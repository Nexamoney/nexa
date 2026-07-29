// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation/dag.h"

#include "blockstorage/blockcache.h"
#include "daa.h"
#include "main.h"
#include "pow.h"
#include "test/test_nexa.h"
#include "validation/tailstorm.h"

#include <boost/test/unit_test.hpp>

using namespace std;

class CTailstormForestTest
{
public:
    static void AddGroveLookup(
        CTailstormForest &forest, const uint256 &hash, const CTailstormGroveRef &grove)
    {
        LOCK(forest.cs_forest);
        forest.mapAllGrovesByNode.emplace(hash, grove);
    }

    static void Reset(CTailstormForest &forest)
    {
        LOCK(forest.cs_forest);

        for (auto &[hash, node] : forest.mapAllNodes)
        {
            node->setAncestors.clear();
            node->setDescendants.clear();
        }

        std::atomic_store(&forest.pDagActiveTip, CTreeNodeRef{});
        forest.bestGrove.reset();
        forest.mapAllGrovesByNode.clear();
        forest.mapAllNodes.clear();
        forest.mapNodesUnlinked.clear();
        forest.mapSummaryBlocksUnlinked.clear();
        forest._pcoinsTip = nullptr;
        forest.processingOrphans = false;
    }
};

namespace
{
class TestTailstormTree : public CTailstormTree
{
public:
    void SetSummaryRoot(CBlockIndex *summaryRoot) { pindexSummaryRoot = summaryRoot; }
    void AddNode(const CTreeNodeRef &node) { dag.emplace(node->hash, node); }
    CTreeNodeRef InsertNode(CTreeNodeRef node) { return Insert(node); }
    size_t Size() const { return dag.size(); }
};

class ScopedChainTip
{
    CBlockIndex *originalTip;

public:
    explicit ScopedChainTip(CBlockIndex *tip) : originalTip(chainActive.Tip()) { chainActive.SetTip(tip); }
    ~ScopedChainTip() { chainActive.SetTip(originalTip); }
};

CTreeNodeRef MakeTestTreeNode(const unsigned char nonce)
{
    CBlockRef block = MakeBlockRef();
    block->nonce = {nonce};
    block->UpdateHeader();
    return MakeTreeNodeRef(ConstCBlockRef(block));
}

class LookupOnlyTailstormGrove : public CTailstormGrove
{
public:
    explicit LookupOnlyTailstormGrove(CCoinsViewCache *coinsCache) : CTailstormGrove(coinsCache) {}
    ~LookupOnlyTailstormGrove() { tree.reset(); }
};

class ScopedBlockIndexEntry
{
    uint256 hash;
    CBlockIndex *index;

public:
    ScopedBlockIndexEntry(const uint256 &_hash, CBlockIndex *_index) : hash(_hash), index(_index)
    {
        WRITELOCK(cs_mapBlockIndex);
        auto [iter, inserted] = mapBlockIndex.emplace(hash, index);
        assert(inserted);
        index->phashBlock = &iter->first;
    }

    ~ScopedBlockIndexEntry()
    {
        WRITELOCK(cs_mapBlockIndex);
        auto iter = mapBlockIndex.find(hash);
        if (iter != mapBlockIndex.end() && iter->second == index)
        {
            mapBlockIndex.erase(iter);
        }
        index->phashBlock = nullptr;
    }
};

class ScopedBlockCacheEntry
{
    uint256 hash;

public:
    ScopedBlockCacheEntry(const ConstCBlockRef &block, const uint64_t height) : hash(block->GetHash())
    {
        blockcache.Init();
        blockcache.AddBlock(block, height);
    }

    ~ScopedBlockCacheEntry() { blockcache.EraseBlock(hash); }
};

struct TailstormForestTestingSetup : TestingSetup
{
    CCoinsView coins;
    CCoinsViewCache coinsCache;

    TailstormForestTestingSetup() : TestingSetup(CBaseChainParams::REGTEST), coinsCache(&coins)
    {
        CTailstormForestTest::Reset(tailstormForest);
        tailstormForest.SetBackend(&coinsCache);
    }

    ~TailstormForestTestingSetup() { CTailstormForestTest::Reset(tailstormForest); }
};

CBlockHeader MakeTestSummaryHeader(
    const uint256 &prevHash,
    const uint32_t height,
    const arith_uint256 &prevWork,
    const unsigned char nonce,
    const std::vector<uint8_t> &minerData = {})
{
    CBlock block;
    block.hashPrevBlock = prevHash;
    block.height = height;
    block.nBits = Params().GenesisBlock().nBits;
    block.chainWork = ArithToUint256(prevWork + GetWorkForDifficultyBits(block.nBits));
    block.nTime = height + 1;
    block.minerData = minerData;
    block.nonce = {nonce};
    block.UpdateHeader();
    return block.GetBlockHeader();
}

class PreviousEpochTestChain
{
public:
    CBlockHeader olderHeader;
    uint256 olderHash;
    CBlockIndex olderSummary;
    CBlockHeader previousHeader;
    uint256 previousHash;
    CBlockIndex previousSummary;
    ScopedBlockIndexEntry previousEntry;
    ConstCBlockRef previousBlock;
    ScopedBlockCacheEntry previousCacheEntry;
    std::shared_ptr<LookupOnlyTailstormGrove> predecessorGrove;

    PreviousEpochTestChain(
        CCoinsViewCache *coinsCache, const unsigned char olderNonce, const unsigned char previousNonce)
        : olderHeader(MakeTestSummaryHeader(uint256(), 0, 0, olderNonce)),
          olderHash(olderHeader.GetHash()),
          olderSummary(olderHeader),
          previousHeader(MakeTestSummaryHeader(olderHash, 1, olderSummary.chainWork(), previousNonce)),
          previousHash(previousHeader.GetHash()),
          previousSummary(previousHeader),
          previousEntry(previousHash, &previousSummary),
          previousBlock(std::make_shared<const CBlock>(previousHeader)),
          previousCacheEntry(previousBlock, previousSummary.height()),
          predecessorGrove(std::make_shared<LookupOnlyTailstormGrove>(coinsCache))
    {
        olderSummary.phashBlock = &olderHash;
        olderSummary.nStatus |= BLOCK_LINKED;
        previousSummary.pprev = &olderSummary;
        previousSummary.nStatus |= BLOCK_LINKED;
        previousSummary.nNextMaxBlockSize = Params().GetConsensus().nNextMaxBlockSize;
        CTailstormForestTest::AddGroveLookup(tailstormForest, olderHash, predecessorGrove);
    }
};

ConstCBlockRef MakeTestSubblock(
    const CBlockIndex &summaryRoot, const std::set<CTreeNodeRef> &parents, const unsigned char nonce)
{
    CBlockRef block = MakeBlockRef();
    block->hashPrevBlock = summaryRoot.GetBlockHash();
    block->height = summaryRoot.height() + 1;
    block->nTime = summaryRoot.GetBlockTime() + 1;
    block->minerData =
        GenerateMinerData(Params().GetConsensus().tailstorm_k, parents, summaryRoot.pprev->GetBlockHash());
    block->nBits = GetNextWorkRequired(&summaryRoot, block.get(), Params().GetConsensus());
    block->chainWork =
        ArithToUint256(summaryRoot.chainWork() + GetWorkForDifficultyBits(block->nBits));
    block->nonce = {nonce};
    CMutableTransaction coinbase;
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << block->height);
    block->vtx.push_back(MakeTransactionRef(coinbase));
    block->UpdateHeader();
    return ConstCBlockRef(block);
}

CTreeNodeRef FindTestNode(const std::set<CTreeNodeRef> &dag, const uint256 &hash)
{
    auto iter =
        std::find_if(dag.begin(), dag.end(), [&hash](const CTreeNodeRef &node) { return node->hash == hash; });
    return iter == dag.end() ? CTreeNodeRef{} : *iter;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(tailstorm_dag_tests, TailstormForestTestingSetup)

BOOST_AUTO_TEST_CASE(coinbase_rewards)
{
    // set up a set of nodes and put them in a dag. The nodes must have
    // a correct set of ancestors so we can calculate scores. 
    //
    // The following dags are show in vertical going from top to bottom
    // Each dag show the summary block "block" at each end.  The score
    // for each subblock is show as a number in the center of the subblock
    //
    // The final block is itself a subblock so that's why, in the first example,
    // the score is 2, when you only see on subblock. But it's actually one
    // subblock "plus" the summary blocks' subbock which makes 2.


    /*
    Dag (k=2) with 1 subblock and the summary's subblock

    =======
    block 1
    =======
       |
     -----
     | 1 |
     -----
       |
    =======
    block 2
      (1)
    =======

    */

    std::set<CTreeNodeRef> setBestDag;
    std::map<uint256, uint32_t> mapExpectedScores;

    CTreeNode node;
    node.hash = InsecureRand256();
    node.dagHeight = 1;
    CTreeNodeRef noderef = MakeTreeNodeRef(node);

    setBestDag.insert(noderef);
    mapExpectedScores.emplace(node.hash, 1);

    auto mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }


    /*
    Dag (k=3) with 2 subblock and the summary's subblock

    =======
    block 1
    =======
       |
     -----
     | 2 |
     -----
       |
     -----
     | 2 |
     -----
       |
    =======
    block 2
      (2)
    =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    CTreeNodeRef noderef1 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.insert(noderef1);
    CTreeNodeRef noderef2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(node.hash, 2);

    // Add the descendants
    noderef1->setDescendants.insert(noderef2);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=4) with 3 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 2 |  | 2 |
    -----  -----
       \   /
        | |
       -----
       | 3 |
       -----
         |
      =======
      block 2
        (3)
      =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    CTreeNodeRef noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    CTreeNodeRef noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    node.setAncestors.insert(noderef1b);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(node.hash, 3);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2);
    noderef1b->setDescendants.insert(noderef2);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=4) with 3 subblocks and the summary's subblock

       =======
       block 1
       =======
       /     \
    -----    -----
    | 2 |    | 1 | * low score from a skipped dagheight link.
    -----    -----
      |        /
      |       /
    -----    /
    | 2 |   /
    -----  /
       \  /
      =======
      block 2
        (3)
      =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(node.hash, 2);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=8) with 3 subblocks and the summary's subblock

       =======
       block 1
       =======
       /     \
    -----    -----
    | 6 |    | 5 |
    -----    -----
      |        /
      |       /
    -----    /
    | 6 |   /
    -----  /
      |   /
    -----  
    | 7 |   
    -----    
      |   \
      |    \
      |     \
    -----    -----
    | 6 |    | 5 |
    -----    -----
      |        /
      |       /
    -----    /
    | 6 |   /
    -----  /
       \  /
      =======
      block 2
        (7)
      =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(node.hash, 6);


    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2);
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 7);


    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3);
    CTreeNodeRef noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3);
    CTreeNodeRef noderef4b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4b);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 5;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef4);
    CTreeNodeRef noderef5 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef5);
    mapExpectedScores.emplace(node.hash, 6);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2);
    noderef1b->setDescendants.insert(noderef3);
    noderef2->setDescendants.insert(noderef3);
    noderef3->setDescendants.insert(noderef4);
    noderef3->setDescendants.insert(noderef4b);
    noderef4->setDescendants.insert(noderef5);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=5) with 4 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 2 |  | 2 |
    -----  -----
      |      |
      |      |
    -----  -----
    | 2 |  | 2 |
    -----  -----
       \   /
      =======
      block 2
        (4)
      =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    CTreeNodeRef noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 2);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=6) with 5 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 2 |  | 3 |
    -----  -----
      |      |  \
      |      |   \
    -----  -----  -----
    | 2 |  | 2 |  | 2 |
    -----  -----  -----
      \    |     /
        =======
        block 2
          (5)
        =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 2);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=7) with 6 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 3 |  | 4 |
    -----  -----
      |      |  \
      |      |   \
    -----  -----  -----
    | 3 |  | 3 |  | 3 |
    -----  -----  -----
        \    |    /
         \   |   /
          \  |  /
           -----
           | 6 |
           -----
             |
          =======
          block 2
            (6)
          =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    CTreeNodeRef noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 6);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef2a->setDescendants.insert(noderef3a);
    noderef2b->setDescendants.insert(noderef3a);
    noderef2c->setDescendants.insert(noderef3a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=6) with 5 subblocks and the summary's subblock

          =======
          block 1
          =======
             |
           -----
           | 5 |
           -----
          /  |  \
         /   |   \
    -----  -----  -----
    | 3 |  | 3 |  | 3 |
    -----  -----  -----
        \    |    /
         \   |   /
          \  |  /
           -----
           | 5 |
           -----
             |
          =======
          block 2
            (5)
          =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 5);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1a->setDescendants.insert(noderef2b);
    noderef1a->setDescendants.insert(noderef2c);
    noderef2a->setDescendants.insert(noderef3a);
    noderef2b->setDescendants.insert(noderef3a);
    noderef2c->setDescendants.insert(noderef3a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=4) with 3 subblocks and the summary's subblock

          =======
          block 1
          =======
          /  |  \
         /   |   \
    -----  -----  -----
    | 1 |  | 1 |  | 1 |
    -----  -----  -----
        \    |    /
         \   |   /
          \  |  /
          =======
          block 2
            (3)
          =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();


    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 1);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=5) with 4 subblocks and the summary's subblock

      =======
      block 1
      =======
       /   \
    -----  -----
    | 3 |  | 1 | * low score skipped dagheight link
    -----  -----
      |      |
      |      |
    -----    |
    | 3 |    |
    -----    |
      |      |
      |      |
      |      |
    -----    |
    | 3 |    |
    -----    |
        \    |
        =======
        block 2
          (4)
        =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 3);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef2a->setDescendants.insert(noderef3a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }


    /*
    Wider dag (k=9) with 8 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======
      block 1
      =======
       /   \
    -----  -----
    | 4 |  | 6 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 4 |  | 4 |  | 4 |  | 3 |
    -----  -----  -----  -----
        \    |    /     /
         \   |   /     /
          \  |  /     /
           -----     /
           | 7 |    /
           -----   /
             |    /
             |   /
           ----- 
           | 8 |
           -----
             |
          =======
          block 2
            (8)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    // Special case in that we need to add the children so we can
    // properly caclulate scores for the skipped level
    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3a);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 8);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3a);
    noderef2b->setDescendants.insert(noderef3a);
    noderef2c->setDescendants.insert(noderef3a);
    noderef2d->setDescendants.insert(noderef4);
    noderef3a->setDescendants.insert(noderef4);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=11) with 10 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======
      block 1
      =======
       /   \
    -----  -----
    | 4 |  | 8 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 4 |  | 4 |  | 4 |  | 5 |
    -----  -----  -----  -----
        \    |    /     /  |
         \   |   /     /   |
          \  |  /     /    |
           -----     /   -----
           | 7 |    /    | 4 |
           -----   /     -----
             |    /        |
             |   /         |
           -----         -----
           | 8 |         | 4 |
           -----         -----
             |             |
          =======          |
          block 2  ________|
            (10)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3a);
    CTreeNodeRef noderef4a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 8);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3);
    noderef2b->setDescendants.insert(noderef3);
    noderef2c->setDescendants.insert(noderef3);
    noderef2d->setDescendants.insert(noderef4);
    noderef2d->setDescendants.insert(noderef3a);
    noderef3->setDescendants.insert(noderef4);
    noderef3a->setDescendants.insert(noderef4a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=10) with 9 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======
      block 1
      =======
       /   \
    -----  -----
    | 5 |  | 7 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 5 |  | 5 |  | 5 |  | 4 |
    -----  -----  -----  -----
        \    |    /     /  |
         \   |   /     /   |
          \  |  /     /    |
           -----     /     |
           | 8 |\   /      |
           ----- \ /       |
             |    /        |
             |   / \       |
           -----    \    -----
           | 8 |     \__ | 8 |
           -----         -----
             |             |
          =======          |
          block 2  ________|
            (9)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4a);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 8);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3);
    noderef2b->setDescendants.insert(noderef3);
    noderef2c->setDescendants.insert(noderef3);
    noderef2d->setDescendants.insert(noderef4);
    noderef2d->setDescendants.insert(noderef4a);
    noderef3->setDescendants.insert(noderef4);
    noderef3->setDescendants.insert(noderef4a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=10) with 9 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======
      block 1
      =======
       /   \
    -----  -----
    | 4 |  | 7 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 4 |  | 4 |  | 4 |  | 4 | * has both skipped and non skipped dagheight links.
    -----  -----  -----  -----
        \    |    /     /  |
         \   |   /     /   |
          \  |  /     /    |
           -----     /   -----
           | 7 |    /    | 3 | * has a skipped dagheight link 
           -----   /     -----
             |    /      /
             |   /      /
           -----       / 
           | 8 |      /  
           -----     /    
             |      /
          =======  /
          block 2  
            (9)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 8);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3);
    noderef2b->setDescendants.insert(noderef3);
    noderef2c->setDescendants.insert(noderef3);
    noderef2d->setDescendants.insert(noderef4);
    noderef2d->setDescendants.insert(noderef3a);
    noderef3->setDescendants.insert(noderef4);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*  Prove that adding exta an unnecessary links to past blocks does not effect the score
    Wider dag (k=7) with 6 subblocks and the summary's subblock

           =======
           block 1
           =======
            /   \
         -----  -----
    ____ | 3 |  | 4 |_________
   |     -----  -----         |
   |       |      |  \        |
   |       |      |   \       |
   |     -----  -----  -----  |
   |     | 3 |  | 3 |  | 3 |  |
   |     -----  -----  -----  |
   |         \    |    /      |
   |          \   |   /       |
   |           \  |  /        |
   |            -----         |
   |___________ | 6 |_________|
                -----
                  |
               =======
               block 2
                 (6)
              =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    node.setAncestors.insert(noderef1b);
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 6);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1a->setDescendants.insert(noderef3a);
    noderef1b->setDescendants.insert(noderef3a);
    noderef2a->setDescendants.insert(noderef3a);
    noderef2b->setDescendants.insert(noderef3a);
    noderef2c->setDescendants.insert(noderef3a);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }


    /*** The following tests are with dags that also have Uncle blocks in them ***/

    /*
    Dag (k=4) with 1 uncle, 2 subblocks and the summary's subblock

    =======    -----
    block 1    | 1 |  Uncle block
    =======    -----
       |
     -----
     | 3 |
     -----
       |
     -----
     | 3 |
     -----
       |
    =======
    block 2
      (3)
    =======

    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    noderef1->dagHeight = 1;
    noderef1->setAncestors.clear();
    noderef1->setDescendants.clear();
    setBestDag.insert(noderef1);
    mapExpectedScores.emplace(noderef1->hash, 3);

    noderef2->dagHeight = 2;
    noderef2->setAncestors.clear();
    noderef2->setDescendants.clear();
    noderef2->setAncestors.insert(noderef1);
    setBestDag.insert(noderef2);
    mapExpectedScores.emplace(noderef2->hash, 3);

    // Add the descendants
    noderef1->setDescendants.insert(noderef2);

    // Add Uncles
    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.fUncle = true;
    CTreeNodeRef noderefUncle1 = MakeTreeNodeRef(node);
    setBestDag.insert(noderefUncle1);
    mapExpectedScores.emplace(noderefUncle1->hash, 1);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

    /*
    Wider dag (k=13) with 2 uncles, 10 subblocks and the summary's subblock. This also tests where
    the linkage between some subblocks skips back more than one dagheight, and is what
    we'd see with a selfish miner. (When we skip a dagheight we do not add any scores.)

      =======    -----  -----
      block 1    | 8 |  | 8 |  Uncle blocks
      =======    -----  -----
       /   \
    -----  -----
    | 6 |  | 10 | _____    
    -----  -----      \
      |      |  \      \
      |      |   \      \
    -----  -----  -----  -----
    | 6 |  | 6 |  | 6 |  | 7 |
    -----  -----  -----  -----
        \    |    /     /  |
         \   |   /     /   |
          \  |  /     /    |
           -----     /   -----
           | 9 |    /    | 6 |
           -----   /     -----
             |    /        |
             |   /         |
           -----         -----
           | 10 |         | 6 |
           -----         -----
             |             |
          =======          |
          block 2  ________|
            (12)
          =======
    */

    setBestDag.clear();
    mapExpectedScores.clear();
    mapScores.clear();

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef1b);
    mapExpectedScores.emplace(node.hash, 10);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2b);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2c);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.insert(noderef2d);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3);
    mapExpectedScores.emplace(node.hash, 9);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef3a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3a);
    noderef4a = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.insert(noderef4);
    mapExpectedScores.emplace(node.hash, 10);

    // Add the descendants
    noderef1a->setDescendants.insert(noderef2a);
    noderef1b->setDescendants.insert(noderef2b);
    noderef1b->setDescendants.insert(noderef2c);
    noderef1b->setDescendants.insert(noderef2d);
    noderef2a->setDescendants.insert(noderef3);
    noderef2b->setDescendants.insert(noderef3);
    noderef2c->setDescendants.insert(noderef3);
    noderef2d->setDescendants.insert(noderef4);
    noderef2d->setDescendants.insert(noderef3a);
    noderef3->setDescendants.insert(noderef4);
    noderef3a->setDescendants.insert(noderef4a);

    // Add Uncles
    noderefUncle1->dagHeight = 1;
    noderefUncle1->setAncestors.clear();
    noderefUncle1->setDescendants.clear();
    noderefUncle1->fUncle = true;
    setBestDag.insert(noderefUncle1);
    mapExpectedScores.emplace(noderefUncle1->hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.fUncle = true;
    CTreeNodeRef noderefUncle2 = MakeTreeNodeRef(node);
    setBestDag.insert(noderefUncle2);
    mapExpectedScores.emplace(noderefUncle2->hash, 8);

    mapScores = GetDagScores(setBestDag);
    for (auto &mi : mapScores)
    {
        BOOST_CHECK_EQUAL(mapExpectedScores[mi.first->hash], mi.second);
    }

}

BOOST_AUTO_TEST_CASE(late_orphan_replay)
{
    // Verify that a previous-epoch child arriving before its parent is replayed
    // into that epoch's DAG once the missing parent arrives.
    PreviousEpochTestChain chain(&coinsCache, 10, 11);
    BOOST_REQUIRE(blockcache.GetBlock(chain.previousHash));

    CBlockHeader currentHeader =
        MakeTestSummaryHeader(chain.previousHash, 2, chain.previousSummary.chainWork(), 12);
    CBlockIndex currentSummary(currentHeader);
    currentSummary.pprev = &chain.previousSummary;
    const uint256 currentHash = currentHeader.GetHash();
    currentSummary.phashBlock = &currentHash;
    ScopedChainTip scopedChainTip(&currentSummary);

    ConstCBlockRef parent = MakeTestSubblock(chain.previousSummary, {}, 20);
    CTreeNodeRef parentNode = MakeTreeNodeRef(parent);
    ConstCBlockRef child = MakeTestSubblock(chain.previousSummary, {parentNode}, 21);

    // The child arrives first and is orphaned because its subblock parent is missing.
    BOOST_CHECK(!tailstormForest.Insert(child));
    BOOST_CHECK_EQUAL(tailstormForest.GetUnlinkedSubblocks(), 1);

    // Its parent then arrives after the next summary block is already the active tip.
    // It is parked, unprocessed, in the previous epoch's DAG.
    BOOST_REQUIRE(tailstormForest.Insert(parent));

    std::set<CTreeNodeRef> previousDag;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(chain.previousHash, previousDag));
    CTreeNodeRef parentNodeInDag = FindTestNode(previousDag, parent->GetHash());
    BOOST_REQUIRE(parentNodeInDag);
    BOOST_CHECK(!parentNodeInDag->fProcessed);

    std::set<uint256> linked;
    {
        LOCK(tailstormForest.cs_forest);
        linked = tailstormForest.ProcessOrphans();
    }

    BOOST_CHECK_EQUAL(linked.count(child->GetHash()), 1);
    BOOST_CHECK_EQUAL(tailstormForest.GetUnlinkedSubblocks(), 0);

    previousDag.clear();
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(chain.previousHash, previousDag));
    CTreeNodeRef childNodeInDag = FindTestNode(previousDag, child->GetHash());
    BOOST_REQUIRE(childNodeInDag);
    BOOST_CHECK(!childNodeInDag->fProcessed);

    CTailstormGroveRef childGrove;
    BOOST_REQUIRE(tailstormForest.GetGrove(child->GetHash(), childGrove));
    BOOST_CHECK_EQUAL(childGrove->id(), chain.previousHash);
}

BOOST_AUTO_TEST_CASE(late_uncle_inclusion)
{
    // Verify that a late previous-epoch orphan completing a k-node DAG remains
    // available and is selected as an uncle by the current epoch.
    const uint32_t tailstormK = Params().GetConsensus().tailstorm_k;
    BOOST_REQUIRE(tailstormK >= 3);

    PreviousEpochTestChain chain(&coinsCache, 30, 31);
    BOOST_REQUIRE(blockcache.GetBlock(chain.previousHash));

    std::vector<ConstCBlockRef> existingSubblocks;
    std::set<CTreeNodeRef> summarySubblocks;
    for (uint32_t i = 0; i < tailstormK - 2; ++i)
    {
        ConstCBlockRef subblock =
            MakeTestSubblock(chain.previousSummary, {}, static_cast<unsigned char>(40 + i));
        existingSubblocks.push_back(subblock);
        summarySubblocks.insert(MakeTreeNodeRef(subblock));
    }

    ConstCBlockRef parent = MakeTestSubblock(chain.previousSummary, {}, 60);
    CTreeNodeRef parentNode = MakeTreeNodeRef(parent);
    summarySubblocks.insert(parentNode);
    BOOST_REQUIRE_EQUAL(summarySubblocks.size(), tailstormK - 1);
    ConstCBlockRef child = MakeTestSubblock(chain.previousSummary, {parentNode}, 61);

    std::vector<uint8_t> currentMinerData =
        GenerateMinerData(tailstormK, summarySubblocks, chain.olderHash);
    CBlockHeader currentHeader =
        MakeTestSummaryHeader(chain.previousHash, 2, chain.previousSummary.chainWork(), 32, currentMinerData);
    CBlockIndex currentSummary(currentHeader);
    currentSummary.pprev = &chain.previousSummary;
    currentSummary.nStatus |= BLOCK_LINKED;
    currentSummary.nNextMaxBlockSize = Params().GetConsensus().nNextMaxBlockSize;
    const uint256 currentHash = currentHeader.GetHash();
    ScopedBlockIndexEntry currentEntry(currentHash, &currentSummary);
    ConstCBlockRef currentBlock = std::make_shared<const CBlock>(currentHeader);
    ScopedBlockCacheEntry currentCacheEntry(currentBlock, currentSummary.height());
    BOOST_REQUIRE(blockcache.GetBlock(currentHash));
    ScopedChainTip scopedChainTip(&currentSummary);

    for (const ConstCBlockRef &subblock : existingSubblocks)
    {
        BOOST_REQUIRE(tailstormForest.Insert(subblock));
    }

    // The child arrives first. Its parent will become node k-1, while replaying
    // the child will make it the omitted kth node eligible for uncle adoption.
    BOOST_CHECK(!tailstormForest.Insert(child));
    BOOST_CHECK_EQUAL(tailstormForest.GetUnlinkedSubblocks(), 1);
    BOOST_REQUIRE(tailstormForest.Insert(parent));

    std::set<CTreeNodeRef> previousDag;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(chain.previousHash, previousDag));
    BOOST_REQUIRE_EQUAL(previousDag.size(), tailstormK - 1);
    CTreeNodeRef parentNodeInDag = FindTestNode(previousDag, parent->GetHash());
    BOOST_REQUIRE(parentNodeInDag);
    BOOST_CHECK(!parentNodeInDag->fProcessed);

    std::set<uint256> linked;
    {
        LOCK(tailstormForest.cs_forest);
        linked = tailstormForest.ProcessOrphans();
    }

    BOOST_CHECK_EQUAL(linked.count(child->GetHash()), 1);
    BOOST_CHECK_EQUAL(tailstormForest.GetUnlinkedSubblocks(), 0);
    previousDag.clear();
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(chain.previousHash, previousDag));
    BOOST_REQUIRE_EQUAL(previousDag.size(), tailstormK);
    CTreeNodeRef childNodeInPreviousDag = FindTestNode(previousDag, child->GetHash());
    BOOST_REQUIRE(childNodeInPreviousDag);
    BOOST_CHECK(!childNodeInPreviousDag->fProcessed);
    BOOST_CHECK(!childNodeInPreviousDag->fUncle);

    ConstCBlockRef currentSubblock = MakeTestSubblock(currentSummary, {}, 70);
    BOOST_REQUIRE(tailstormForest.Insert(currentSubblock));

    std::set<CTreeNodeRef> currentDag;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(currentHash, currentDag));
    CTreeNodeRef childUncle = FindTestNode(currentDag, child->GetHash());
    BOOST_REQUIRE(childUncle);
    BOOST_CHECK(childUncle->fUncle);
    BOOST_CHECK_EQUAL(childUncle->roothash, currentHash);

    std::set<CTreeNodeRef> bestDag;
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(currentHash, bestDag));
    CTreeNodeRef selectedChildUncle = FindTestNode(bestDag, child->GetHash());
    BOOST_REQUIRE(selectedChildUncle);
    BOOST_CHECK(selectedChildUncle->fUncle);
    BOOST_CHECK_EQUAL(selectedChildUncle->roothash, currentHash);
}

BOOST_AUTO_TEST_CASE(unprocessed_ancestor_parks_child_during_reorg_gap)
{
    CBlockIndex summaryRoot;
    summaryRoot.SetBlockHeader(std::make_shared<CBlockHeader>());
    summaryRoot.SetBlockHeaderHeight(0);
    ScopedChainTip scopedChainTip(&summaryRoot);

    LOCK(tailstormForest.cs_forest);

    TestTailstormTree tree;
    tree.SetSummaryRoot(&summaryRoot);

    CTreeNodeRef parent = MakeTestTreeNode(1);
    parent->nSequenceId = 1;
    parent->dagHeight = 1;
    parent->fProcessed = false;
    tree.AddNode(parent);

    CTreeNodeRef child = MakeTestTreeNode(2);
    child->dagHeight = 2;
    child->setAncestors.insert(parent);
    parent->setDescendants.insert(child);

    // Model the reorg gap directly: the grove root is the transient chain tip, but
    // the child's parent was parked while this was a non-tip grove.
    CTreeNodeRef inserted = tree.InsertNode(child);

    BOOST_REQUIRE(inserted != nullptr);
    BOOST_CHECK(inserted == child);
    BOOST_CHECK_EQUAL(tree.Size(), 2);
    BOOST_CHECK_EQUAL(child->nSequenceId, 2);
    BOOST_CHECK(!child->fProcessed);
    BOOST_CHECK(!parent->fProcessed);
}

BOOST_AUTO_TEST_SUITE_END()
