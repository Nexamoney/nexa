// Copyright (c) 2018-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation/dag.h"

#include "blockstorage/blockcache.h"
#include "coins.h"
#include "daa.h"
#include "main.h"
#include "miner.h"
#include "pow.h"
#include "test/test_nexa.h"
#include "txadmission.h"
#include "unlimited.h"
#include "validation/tailstorm.h"
#include "validation/validation.h"

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <thread>

using namespace std;

extern std::atomic<bool> forceTemplateRecalc;

class CTailstormForestTest
{
public:
    static void AddGroveLookup(
        CTailstormForest &forest, const uint256 &hash, const CTailstormGroveRef &grove)
    {
        LOCK(forest.cs_forest);
        forest.mapAllGrovesByNode.emplace(hash, grove);
    }

    static bool RecheckPending(CTailstormForest &forest) { return forest.fRecheckReorg; }

    static bool HasDagTx(const CTailstormTree &tree, const uint256 &txid) { return tree.mapDagTxns.count(txid) != 0; }

    static CCoinsViewCache &CoinsView(CTailstormTree &tree) { return *tree.view; }

    static void SetRecheckPending(CTailstormForest &forest, bool fPending) { forest.fRecheckReorg = fPending; }

    static size_t SummaryOrphanCount(CTailstormForest &forest)
    {
        LOCK(forest.cs_forest);
        return forest.mapSummaryBlocksUnlinked.size();
    }

    static void RemoveGroveLookup(CTailstormForest &forest, const uint256 &hash)
    {
        LOCK(forest.cs_forest);
        forest.mapAllGrovesByNode.erase(hash);
    }

    // Files a subblock as the retry verdict does, for removal at the next regeneration.

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
    void SetSummaryRootCoins(CCoinsViewCache *coins) { _pcoinsSummaryRoot = coins; }
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

CTransactionRef MakeTestTransaction(const COutPoint &spentOutput, const unsigned char tag)
{
    CMutableTransaction tx;
    tx.vin.emplace_back(spentOutput, 1);
    tx.vout.emplace_back(1, CScript() << OP_RETURN << tag);
    return MakeTransactionRef(tx);
}

CTreeNodeRef MakeTestTransactionNode(const CTransactionRef &tx, const unsigned char nonce)
{
    CBlockRef block = MakeBlockRef();
    block->nonce = {nonce};
    block->vtx.push_back(tx);
    block->UpdateHeader();
    return MakeTreeNodeRef(ConstCBlockRef(block));
}

void LinkTestTreeNodes(const CTreeNodeRef &parent, const CTreeNodeRef &child)
{
    child->setAncestors.insert(parent);
    parent->setDescendants.insert(child);
    child->dagHeight = parent->dagHeight + 1;
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
        // Connecting a subblock of the previous epoch reads the size limit from the summary
        // before it.
        olderSummary.nNextMaxBlockSize = Params().GetConsensus().nNextMaxBlockSize;
        previousSummary.pprev = &olderSummary;
        previousSummary.nStatus |= BLOCK_LINKED;
        previousSummary.nNextMaxBlockSize = Params().GetConsensus().nNextMaxBlockSize;
        CTailstormForestTest::AddGroveLookup(tailstormForest, olderHash, predecessorGrove);
    }
};

ConstCBlockRef MakeTestSubblock(const CBlockIndex &summaryRoot,
    const std::vector<CTreeNodeRef> &parents,
    const unsigned char nonce,
    const std::vector<CTransactionRef> &txs = {})
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
    for (const auto &tx : txs)
        block->vtx.push_back(tx);
    block->UpdateHeader();
    return ConstCBlockRef(block);
}

CTreeNodeRef FindTestNode(const std::vector<CTreeNodeRef> &dag, const uint256 &hash)
{
    auto iter =
        std::find_if(dag.begin(), dag.end(), [&hash](const CTreeNodeRef &node) { return node->hash == hash; });
    return iter == dag.end() ? CTreeNodeRef{} : *iter;
}

// The nodes in dag order, as the dag getters return them and GetTxnExclusionSet requires.
std::vector<CTreeNodeRef> SortTestDag(const std::vector<CTreeNodeRef> &nodes)
{
    LOCK(tailstormForest.cs_forest);
    TestTailstormTree tree;
    for (const auto &node : nodes)
        tree.AddNode(node);
    tailstormForest.RenumberDag(tree);
    return tree.SortedDag();
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(tailstorm_dag_tests, TailstormForestTestingSetup)

BOOST_AUTO_TEST_CASE(double_spend_prefers_dag_score)
{
    // Give the higher-hash subblock more DAG support to prove score takes
    // precedence over the deterministic subblock-hash tie-breaker.
    const COutPoint spentOutput(MakeTestTreeNode(20)->hash);
    const CTransactionRef txA = MakeTestTransaction(spentOutput, 1);
    const CTransactionRef txB = MakeTestTransaction(spentOutput, 2);
    const CTreeNodeRef nodeA = MakeTestTransactionNode(txA, 1);
    const CTreeNodeRef nodeB = MakeTestTransactionNode(txB, 2);
    const CTreeNodeRef scoreWinner = nodeA->hash > nodeB->hash ? nodeA : nodeB;
    const CTreeNodeRef scoreLoser = scoreWinner == nodeA ? nodeB : nodeA;
    const CTransactionRef winnerTx = scoreWinner == nodeA ? txA : txB;
    const CTransactionRef loserTx = scoreWinner == nodeA ? txB : txA;
    const CTreeNodeRef child = MakeTestTreeNode(3);

    scoreWinner->dagHeight = 1;
    scoreLoser->dagHeight = 1;
    LinkTestTreeNodes(scoreWinner, child);
    const std::vector<CTreeNodeRef> dag{scoreWinner, scoreLoser, child};
    const auto scores = GetDagScores(dag);
    BOOST_REQUIRE(scoreWinner->hash > scoreLoser->hash);
    BOOST_REQUIRE(scores.at(scoreWinner) > scores.at(scoreLoser));

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(scoreWinner, true));
    BOOST_CHECK(!registry.ScanSpends(scoreLoser, true));
    std::set<uint256> losers;
    const std::set<uint256> exclusions = GetTxnExclusionSet(SortTestDag(dag), nullptr, &losers);

    BOOST_CHECK_EQUAL(losers.count(winnerTx->GetId()), 0);
    BOOST_CHECK_EQUAL(losers.count(loserTx->GetId()), 1);
    BOOST_CHECK_EQUAL(exclusions.count(winnerTx->GetId()), 0);
    BOOST_CHECK_EQUAL(exclusions.count(loserTx->GetId()), 1);
}

BOOST_AUTO_TEST_CASE(double_spend_changes_after_join)
{
    // A common descendant does not freeze the winner: extending only the
    // losing branch can give it a higher score.
    // See winner_flip_evicts_pool_dependents_at_regeneration for a score-driven flip without a join,
    // and first_regeneration_of_a_group_evicts_pool_dependents for displacement by a lower-hash rival.
    const COutPoint spentOutput(MakeTestTreeNode(20)->hash);
    const CTransactionRef txA = MakeTestTransaction(spentOutput, 1);
    const CTransactionRef txB = MakeTestTransaction(spentOutput, 2);
    const CTreeNodeRef nodeA = MakeTestTransactionNode(txA, 1);
    const CTreeNodeRef nodeB = MakeTestTransactionNode(txB, 2);
    const CTreeNodeRef initialWinner = nodeA->hash < nodeB->hash ? nodeA : nodeB;
    const CTreeNodeRef initialLoser = initialWinner == nodeA ? nodeB : nodeA;
    const CTransactionRef winnerTx = initialWinner == nodeA ? txA : txB;
    const CTransactionRef loserTx = initialWinner == nodeA ? txB : txA;
    const CTreeNodeRef join = MakeTestTreeNode(3);
    const CTreeNodeRef side = MakeTestTreeNode(4);
    BOOST_SCOPE_EXIT_ALL(&)
    {
        for (const auto &node : {nodeA, nodeB, join, side})
        {
            node->setAncestors.clear();
            node->setDescendants.clear();
        }
    };

    nodeA->dagHeight = 1;
    nodeB->dagHeight = 1;
    LinkTestTreeNodes(nodeA, join);
    LinkTestTreeNodes(nodeB, join);
    std::vector<CTreeNodeRef> dag{nodeA, nodeB, join};
    const auto before = GetDagScores(dag);
    BOOST_REQUIRE_EQUAL(before.at(initialWinner), 2);
    BOOST_REQUIRE_EQUAL(before.at(initialLoser), 2);

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(nodeA, true));
    BOOST_CHECK(!registry.ScanSpends(nodeB, true));
    const auto initialExclusions = GetTxnExclusionSet(SortTestDag(dag));
    BOOST_CHECK_EQUAL(initialExclusions.size(), 1);
    BOOST_CHECK_EQUAL(initialExclusions.count(winnerTx->GetId()), 0);
    BOOST_CHECK_EQUAL(initialExclusions.count(loserTx->GetId()), 1);

    LinkTestTreeNodes(initialLoser, side);
    dag.push_back(side);
    const auto after = GetDagScores(dag);
    BOOST_REQUIRE_EQUAL(after.at(initialWinner), 2);
    BOOST_REQUIRE_EQUAL(after.at(initialLoser), 3);
    const auto finalExclusions = GetTxnExclusionSet(SortTestDag(dag));
    BOOST_CHECK_EQUAL(finalExclusions.size(), 1);
    BOOST_CHECK_EQUAL(finalExclusions.count(winnerTx->GetId()), 1);
    BOOST_CHECK_EQUAL(finalExclusions.count(loserTx->GetId()), 0);
}

BOOST_AUTO_TEST_CASE(double_spend_uses_hash_tiebreak)
{
    // With equal DAG scores, the transaction carried by the lower-hash
    // subblock must win independently of transaction ordering.
    const COutPoint spentOutput(MakeTestTreeNode(21)->hash);
    const CTransactionRef txA = MakeTestTransaction(spentOutput, 4);
    const CTransactionRef txB = MakeTestTransaction(spentOutput, 5);
    const CTreeNodeRef nodeA = MakeTestTransactionNode(txA, 4);
    const CTreeNodeRef nodeB = MakeTestTransactionNode(txB, 5);
    nodeA->dagHeight = 1;
    nodeB->dagHeight = 1;

    const CTreeNodeRef winner = nodeA->hash < nodeB->hash ? nodeA : nodeB;
    const CTreeNodeRef loser = winner == nodeA ? nodeB : nodeA;
    const CTransactionRef winnerTx = winner == nodeA ? txA : txB;
    const CTransactionRef loserTx = winner == nodeA ? txB : txA;
    const std::vector<CTreeNodeRef> dag{nodeA, nodeB};
    const auto scores = GetDagScores(dag);
    BOOST_REQUIRE_EQUAL(scores.at(nodeA), scores.at(nodeB));

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(winner, true));
    BOOST_CHECK(!registry.ScanSpends(loser, true));
    std::set<uint256> losers;
    const std::set<uint256> exclusions = GetTxnExclusionSet(SortTestDag(dag), nullptr, &losers);

    BOOST_CHECK_EQUAL(losers.count(winnerTx->GetId()), 0);
    BOOST_CHECK_EQUAL(losers.count(loserTx->GetId()), 1);
    BOOST_CHECK_EQUAL(exclusions.count(winnerTx->GetId()), 0);
    BOOST_CHECK_EQUAL(exclusions.count(loserTx->GetId()), 1);
}

BOOST_AUTO_TEST_CASE(double_spend_uses_max_subblock_score)
{
    // A transaction may appear in multiple subblocks. Exercise both traversal
    // orders and require its highest-scoring subblock to decide.
    const COutPoint spentOutput(MakeTestTreeNode(22)->hash);
    const CTransactionRef repeatedTx = MakeTestTransaction(spentOutput, 6);
    const CTransactionRef competingTx = MakeTestTransaction(spentOutput, 7);
    const CTreeNodeRef repeatedTxNodeA = MakeTestTransactionNode(repeatedTx, 6);
    const CTreeNodeRef repeatedTxNodeB = MakeTestTransactionNode(repeatedTx, 7);
    const CTreeNodeRef repeatedTxChild = MakeTestTreeNode(8);
    const CTreeNodeRef repeatedTxGrandchild = MakeTestTreeNode(9);
    const CTreeNodeRef competingTxNode = MakeTestTransactionNode(competingTx, 10);
    const CTreeNodeRef competingTxChild = MakeTestTreeNode(11);
    const std::vector<CTreeNodeRef> dag{repeatedTxNodeA, repeatedTxNodeB, repeatedTxChild, repeatedTxGrandchild,
        competingTxNode, competingTxChild};
    const std::set<CTreeNodeRef> repeatedTxNodes{repeatedTxNodeA, repeatedTxNodeB};
    const CTreeNodeRef firstRepeatedTxNode = *repeatedTxNodes.begin();
    const CTreeNodeRef secondRepeatedTxNode = *std::next(repeatedTxNodes.begin());

    const auto checkMaxSubblockScoreWins = [&](const CTreeNodeRef &highScoreRepeatedTxNode) {
        for (const CTreeNodeRef &node : dag)
        {
            node->dagHeight = 1;
            node->setAncestors.clear();
            node->setDescendants.clear();
        }

        LinkTestTreeNodes(highScoreRepeatedTxNode, repeatedTxChild);
        LinkTestTreeNodes(repeatedTxChild, repeatedTxGrandchild);
        LinkTestTreeNodes(competingTxNode, competingTxChild);

        const CTreeNodeRef lowScoreRepeatedTxNode =
            highScoreRepeatedTxNode == repeatedTxNodeA ? repeatedTxNodeB : repeatedTxNodeA;
        const auto scores = GetDagScores(dag);
        BOOST_REQUIRE(scores.at(highScoreRepeatedTxNode) > scores.at(competingTxNode));
        BOOST_REQUIRE(scores.at(competingTxNode) > scores.at(lowScoreRepeatedTxNode));

        LOCK(tailstormForest.cs_forest);
        CDagConflictRegistry registry;
        BOOST_CHECK(!registry.ScanSpends(repeatedTxNodeA, true));
        BOOST_CHECK(!registry.ScanSpends(repeatedTxNodeB, true));
        BOOST_CHECK(!registry.ScanSpends(competingTxNode, true));
        std::set<uint256> losers;
        const std::set<uint256> exclusions = GetTxnExclusionSet(SortTestDag(dag), nullptr, &losers);

        BOOST_CHECK_EQUAL(losers.count(repeatedTx->GetId()), 0);
        BOOST_CHECK_EQUAL(losers.count(competingTx->GetId()), 1);
        BOOST_CHECK_EQUAL(exclusions.count(repeatedTx->GetId()), 0);
        BOOST_CHECK_EQUAL(exclusions.count(competingTx->GetId()), 1);
    };

    checkMaxSubblockScoreWins(secondRepeatedTxNode);
    checkMaxSubblockScoreWins(firstRepeatedTxNode);
}

BOOST_AUTO_TEST_CASE(exclusion_set_excludes_loser_descendants)
{
    // A conflict loser is excluded, and so is anything spending its outputs.
    const COutPoint contested(MakeTestTreeNode(50)->hash, 0);
    const CTransactionRef txWin = MakeTestTransaction(contested, 1);
    const CTransactionRef txLose = MakeTestTransaction(contested, 2);
    const CTransactionRef txWinChild = MakeTestTransaction(txWin->OutpointAt(0), 3);
    const CTransactionRef txLoseChild = MakeTestTransaction(txLose->OutpointAt(0), 4);
    const CTreeNodeRef nodeWin = MakeTestTransactionNode(txWin, 1);
    const CTreeNodeRef nodeLose = MakeTestTransactionNode(txLose, 2);
    const CTreeNodeRef nodeWinChild = MakeTestTransactionNode(txWinChild, 3);
    const CTreeNodeRef nodeLoseChild = MakeTestTransactionNode(txLoseChild, 4);

    // The winner's subblock has a descendant, so it outscores the loser's subblock.
    nodeWin->dagHeight = 1;
    nodeLose->dagHeight = 1;
    nodeLoseChild->dagHeight = 1;
    LinkTestTreeNodes(nodeWin, nodeWinChild);
    const std::vector<CTreeNodeRef> dag{nodeWin, nodeLose, nodeWinChild, nodeLoseChild};
    const auto scores = GetDagScores(dag);
    BOOST_REQUIRE(scores.at(nodeWin) > scores.at(nodeLose));

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(nodeWin, true));
    BOOST_CHECK(!registry.ScanSpends(nodeLose, true));
    BOOST_CHECK(!registry.ScanSpends(nodeWinChild, true));
    BOOST_CHECK(!registry.ScanSpends(nodeLoseChild, true));
    std::set<uint256> losers;
    const std::set<uint256> exclusions = GetTxnExclusionSet(SortTestDag(dag), nullptr, &losers);

    BOOST_CHECK_EQUAL(losers.size(), 1);
    BOOST_CHECK_EQUAL(losers.count(txLose->GetId()), 1);
    BOOST_CHECK_EQUAL(exclusions.size(), 2);
    BOOST_CHECK_EQUAL(exclusions.count(txLose->GetId()), 1);
    BOOST_CHECK_EQUAL(exclusions.count(txLoseChild->GetId()), 1);
    BOOST_CHECK_EQUAL(exclusions.count(txWin->GetId()), 0);
    BOOST_CHECK_EQUAL(exclusions.count(txWinChild->GetId()), 0);
}

BOOST_AUTO_TEST_CASE(exclusion_set_ignores_sequence_order)
{
    // A transaction whose parent is included is sourced even when its subblock is sequenced
    // ahead of the parent's.
    const CTransactionRef txParent = MakeTestTransaction(COutPoint(MakeTestTreeNode(55)->hash, 0), 1);
    const CTransactionRef txChild = MakeTestTransaction(txParent->OutpointAt(0), 2);
    const CTreeNodeRef nodeParent = MakeTestTransactionNode(txParent, 1);
    const CTreeNodeRef nodeChild = MakeTestTransactionNode(txChild, 2);
    nodeParent->dagHeight = 1;
    nodeChild->dagHeight = 1;
    nodeChild->nSequenceId = 1;
    nodeParent->nSequenceId = 2;
    const std::vector<CTreeNodeRef> dag{nodeParent, nodeChild};

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(nodeParent, true));
    BOOST_CHECK(!registry.ScanSpends(nodeChild, true));
    std::set<uint256> losers;
    const std::set<uint256> exclusions = GetTxnExclusionSet(SortTestDag(dag), nullptr, &losers);

    BOOST_CHECK(losers.empty());
    BOOST_CHECK(exclusions.empty());
}

BOOST_AUTO_TEST_CASE(regeneration_renumbers_after_bad_subblock_removal)
{
    // k+1 subblocks against k-1 slots: the first k-1 are processed, the last two are held past
    // the cap. Removing a bad subblock, and the regeneration that follows, must leave the remaining
    // sequence ids dense across processed and held nodes alike, which Check() asserts.
    const uint32_t tailstormK = Params().GetConsensus().tailstorm_k;
    BOOST_REQUIRE(tailstormK >= 3);
    PreviousEpochTestChain chain(&coinsCache, 90, 91);
    ScopedChainTip scopedChainTip(&chain.previousSummary);

    std::vector<ConstCBlockRef> subblocks;
    for (uint32_t i = 0; i < tailstormK + 1; ++i)
    {
        subblocks.push_back(MakeTestSubblock(chain.previousSummary, {}, static_cast<unsigned char>(100 + i)));
        BOOST_REQUIRE(tailstormForest.Insert(subblocks.back()));
    }

    std::vector<CTreeNodeRef> bestDag;
    CTailstormTreeRef tree;
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(chain.previousHash, bestDag, &tree));
    BOOST_REQUIRE(tree);
    BOOST_REQUIRE_EQUAL(bestDag.size(), tailstormK - 1);
    std::vector<CTreeNodeRef> fullDag;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(chain.previousHash, fullDag));
    BOOST_REQUIRE_EQUAL(fullDag.size(), tailstormK + 1);

    CTailstormGroveRef grove;
    BOOST_REQUIRE(tailstormForest.GetGrove(subblocks[0]->GetHash(), grove));
    // A subblock found bad is removed from the grove, and the dag regenerated.
    {
        LOCK(tailstormForest.cs_forest);
        TxAdmissionPause pause;
        uint256 badHash = subblocks[0]->GetHash();
        BOOST_REQUIRE(tailstormForest.Remove(badHash));
        tailstormForest.ReGenerateDagData(grove);
    }

    fullDag.clear();
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(chain.previousHash, fullDag));
    BOOST_CHECK_EQUAL(fullDag.size(), tailstormK);
    BOOST_CHECK(!FindTestNode(fullDag, subblocks[0]->GetHash()));

    // The full dag comes back in nSequenceId order. None of these subblocks has a parent or child,
    // so they score the same and dag order is hash order; the first tailstorm_k - 1 are processed.
    const std::vector<CTreeNodeRef> &bySequence = fullDag;
    for (size_t i = 0; i < bySequence.size(); ++i)
    {
        BOOST_CHECK_EQUAL(bySequence[i]->nSequenceId, i + 1);
        BOOST_CHECK_EQUAL(bySequence[i]->fProcessed, i < tailstormK - 1);
        if (i > 0)
            BOOST_CHECK(bySequence[i - 1]->hash < bySequence[i]->hash);
    }

    // The predecessor lookup has no grove behind it; Check() walks real groves only.
    CTailstormForestTest::RemoveGroveLookup(tailstormForest, chain.olderHash);
    tailstormForest.setSanityCheck(1.0);
    tailstormForest.Check();
    tailstormForest.setSanityCheck(0.0);
}

// A bare script that OP_0 satisfies keeps test spends free of signatures.
static const CScript testSpendable = CScript() << 2 << OP_ADD << 0 << OP_GREATERTHAN;

// One coin at the summary tip for double spend tests, plus a spender of any output.
struct DoubleSpendTestCoin
{
    PreviousEpochTestChain chain;
    ScopedChainTip scopedChainTip;
    const int height;
    CTransactionRef parentTx;

    explicit DoubleSpendTestCoin(CCoinsViewCache &coinsCache)
        : chain(&coinsCache, 92, 93), scopedChainTip(&chain.previousSummary),
          height(chain.previousSummary.height() + 1)
    {
        BOOST_REQUIRE(Params().GetConsensus().tailstorm_k >= 4);
        mempool.clear();
        CMutableTransaction parent;
        parent.vin.emplace_back(COutPoint(MakeTestTreeNode(94)->hash, 0), 2000);
        parent.vout.emplace_back(1000, testSpendable);
        parentTx = MakeTransactionRef(parent);
        AddCoins(coinsCache, *parentTx, height);
    }
    ~DoubleSpendTestCoin() { mempool.clear(); }

    CTransactionRef Spend(const COutPoint &out, CAmount amount, CAmount value) const
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(out, amount);
        tx.vin.back().scriptSig = CScript() << OP_0;
        tx.vout.emplace_back(value, testSpendable);
        return MakeTransactionRef(tx);
    }
    CTransactionRef SpendCoin(CAmount value) const { return Spend(parentTx->OutpointAt(0), 1000, value); }

    void Pool(const CTransactionRef &tx) const
    {
        TestMemPoolEntryHelper entry;
        mempool.addUnchecked(entry.Height(height).FromTx(*tx));
        BOOST_REQUIRE(mempool.exists(tx->GetId()));
    }
};

// A subblock carrying txs whose hash is below that of rival, so it wins a tie on score.
static ConstCBlockRef MakeLowerHashSubblock(
    const CBlockIndex &summaryRoot, const ConstCBlockRef &rival, const std::vector<CTransactionRef> &txs)
{
    for (unsigned nonce = 96; nonce < 256; nonce++)
    {
        ConstCBlockRef block = MakeTestSubblock(summaryRoot, {}, (unsigned char)nonce, txs);
        if (block->GetHash() < rival->GetHash())
            return block;
    }
    BOOST_FAIL("no nonce gives a lower hash");
    return nullptr;
}

// A subblock carrying txs whose hash is above that of rival, so it loses a tie on score.
static ConstCBlockRef MakeHigherHashSubblock(
    const CBlockIndex &summaryRoot, const ConstCBlockRef &rival, const std::vector<CTransactionRef> &txs)
{
    for (unsigned nonce = 96; nonce < 256; nonce++)
    {
        ConstCBlockRef block = MakeTestSubblock(summaryRoot, {}, (unsigned char)nonce, txs);
        if (rival->GetHash() < block->GetHash())
            return block;
    }
    BOOST_FAIL("no nonce gives a higher hash");
    return nullptr;
}

BOOST_AUTO_TEST_CASE(regeneration_retries_cross_branch_spend)
{
    // Subblock ancestry (parent -> child):
    //             +--> A[p]
    // Summary ----+
    //             +--> B[c]
    // Uppercase names are subblocks; lowercase names in brackets are transactions.
    //
    // A carries p, which spends a summary-root coin. B carries c, which spends p's
    // output, but B does not reference A. Seed both sequence orders before rebuilding.
    // Regeneration must restore hash order and apply both transactions, leaving only the output of c.
    DoubleSpendTestCoin coin(coinsCache);
    const CBlockIndex &summary = coin.chain.previousSummary;
    const CTransactionRef provider = coin.SpendCoin(800);
    const CTransactionRef spender = coin.Spend(provider->OutpointAt(0), 800, 400);
    const ConstCBlockRef providerBlock = MakeTestSubblock(summary, {}, 95, {provider});
    const ConstCBlockRef spenderBlock = MakeTestSubblock(summary, {}, 96, {spender});

    // Accept the spender's subblock before its input exists; the transaction must wait.
    BOOST_REQUIRE(tailstormForest.Insert(spenderBlock));
    std::vector<CTreeNodeRef> bestDag;
    CTailstormTreeRef tree;
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(coin.chain.previousHash, bestDag, &tree));
    {
        LOCK(tailstormForest.cs_forest);
        BOOST_CHECK(!CTailstormForestTest::HasDagTx(*tree, spender->GetId()));
    }
    BOOST_REQUIRE(tailstormForest.Insert(providerBlock));

    std::vector<CTreeNodeRef> fullDag;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(coin.chain.previousHash, fullDag));
    BOOST_REQUIRE_EQUAL(fullDag.size(), 2u);
    const CTreeNodeRef providerNode = FindTestNode(fullDag, providerBlock->GetHash());
    const CTreeNodeRef spenderNode = FindTestNode(fullDag, spenderBlock->GetHash());
    BOOST_REQUIRE(providerNode);
    BOOST_REQUIRE(spenderNode);
    CTailstormGroveRef grove;
    BOOST_REQUIRE(tailstormForest.GetGrove(coin.chain.previousHash, grove));

    LOCK(tailstormForest.cs_forest);
    TxAdmissionPause pause;
    // The dependency is between transactions, not between subblock headers.
    BOOST_CHECK(providerNode->setAncestors.empty());
    BOOST_CHECK(spenderNode->setAncestors.empty());
    BOOST_CHECK_EQUAL(providerNode->dagHeight, 1u);
    BOOST_CHECK_EQUAL(spenderNode->dagHeight, 1u);
    BOOST_CHECK(CTailstormForestTest::HasDagTx(*tree, provider->GetId()));
    BOOST_CHECK(CTailstormForestTest::HasDagTx(*tree, spender->GetId()));

    // These unrelated sub-blocks both score one, so the lower hash must come first.
    const uint32_t expectedProviderId = providerNode->hash < spenderNode->hash ? 1u : 2u;
    // Regeneration clears the DAG view, so neither order can reuse the insertion result.
    Coin parentFirstCoin;
    for (const bool childFirst : {false, true})
    {
        BOOST_TEST_CONTEXT("initial child first=" << childFirst)
        {
            providerNode->nSequenceId = childFirst ? 2 : 1;
            spenderNode->nSequenceId = childFirst ? 1 : 2;
            tailstormForest.ReGenerateDagData(grove);

            BOOST_CHECK(providerNode->fProcessed);
            BOOST_CHECK(spenderNode->fProcessed);
            BOOST_CHECK_EQUAL(providerNode->nSequenceId, expectedProviderId);
            BOOST_CHECK_EQUAL(spenderNode->nSequenceId, 3u - expectedProviderId);
            BOOST_CHECK(CTailstormForestTest::HasDagTx(*tree, provider->GetId()));
            BOOST_CHECK(CTailstormForestTest::HasDagTx(*tree, spender->GetId()));
            // Both inputs must be spent; only the spender's output should remain.
            CCoinsViewCache &view = CTailstormForestTest::CoinsView(*tree);
            BOOST_CHECK(!view.HaveCoin(coin.parentTx->OutpointAt(0)));
            BOOST_CHECK(!view.HaveCoin(provider->OutpointAt(0)));
            Coin result;
            BOOST_REQUIRE(view.GetCoin(spender->OutpointAt(0), result));
            BOOST_CHECK(result.out == spender->vout[0]);
            BOOST_CHECK_EQUAL(result.height(), coin.height);
            if (!childFirst)
                parentFirstCoin = result;
            else
            {
                BOOST_CHECK(result.out == parentFirstCoin.out);
                BOOST_CHECK_EQUAL(result.height(), parentFirstCoin.height());
            }
            // Applying DAG transactions must not change the summary-root coins.
            BOOST_CHECK(coinsCache.HaveCoin(coin.parentTx->OutpointAt(0)));
            BOOST_CHECK(!coinsCache.HaveCoin(provider->OutpointAt(0)));
            BOOST_CHECK(!coinsCache.HaveCoin(spender->OutpointAt(0)));
        }
    }
}

static void CheckCrossBranchRegeneration(CCoinsViewCache &coinsCache, size_t spenderBranchLength)
{
    // Temporarily set K=8 so both cases fit; the unequal branches fill all seven slots.
    // The destructor restores the saved value on scope exit, including test failures.
    struct ScopedTailstormK
    {
        uint32_t &value = ModifiableParams().GetModifiableConsensus().tailstorm_k;
        const uint32_t saved = value;
        ScopedTailstormK() { value = 8; }
        ~ScopedTailstormK() { value = saved; }
    } tailstormK;
    DoubleSpendTestCoin coin(coinsCache);
    // p spends a summary-root coin, c spends p's output, and d spends c's.
    // A2 carries p; B2 carries c; the last subblock on branch B carries d.
    const CTransactionRef provider = coin.SpendCoin(800);
    const CTransactionRef child = coin.Spend(provider->OutpointAt(0), 800, 600);
    const CTransactionRef grandchild = coin.Spend(child->OutpointAt(0), 600, 400);
    const auto insert = [&](const std::vector<CTreeNodeRef> &parents, unsigned char nonce,
                            const std::vector<CTransactionRef> &txs) {
        const ConstCBlockRef block = MakeTestSubblock(coin.chain.previousSummary, parents, nonce, txs);
        BOOST_REQUIRE(tailstormForest.Insert(block));
        std::vector<CTreeNodeRef> dag;
        BOOST_REQUIRE(tailstormForest.GetFullDagFor(coin.chain.previousHash, dag));
        const CTreeNodeRef node = FindTestNode(dag, block->GetHash());
        BOOST_REQUIRE(node);
        return node;
    };

    // Insert the subblocks carrying c and d before p's, exercising chained missing-input retries.
    unsigned char nonce = 95;
    std::vector<CTreeNodeRef> branchB;
    for (size_t i = 0; i < spenderBranchLength; ++i)
    {
        std::vector<CTreeNodeRef> parents;
        if (!branchB.empty())
            parents.push_back(branchB.back());
        std::vector<CTransactionRef> txs;
        if (i == 1)
            txs.push_back(child);
        // Put d at the branch tip so the unequal case spans an extra subblock.
        if (i + 1 == spenderBranchLength)
            txs.push_back(grandchild);
        branchB.push_back(insert(parents, nonce++, txs));
    }
    const CTreeNodeRef a1 = insert({}, nonce++, {});
    const CTreeNodeRef a2 = insert({a1}, nonce++, {provider});
    const CTreeNodeRef a3 = insert({a2}, nonce++, {});
    const std::vector<CTreeNodeRef> branchA{a1, a2, a3};
    CTailstormGroveRef grove;
    BOOST_REQUIRE(tailstormForest.GetGrove(coin.chain.previousHash, grove));
    std::vector<CTreeNodeRef> dag;
    CTailstormTreeRef tree;
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(coin.chain.previousHash, dag, &tree));
    BOOST_REQUIRE_EQUAL(dag.size(), branchA.size() + branchB.size());

    LOCK(tailstormForest.cs_forest);
    TxAdmissionPause pause;
    // Each node names only its direct parent; the two branches must stay separate.
    for (const auto &branch : {branchA, branchB})
    {
        for (size_t i = 0; i < branch.size(); ++i)
        {
            BOOST_CHECK_EQUAL(branch[i]->dagHeight, i + 1);
            BOOST_CHECK_EQUAL(branch[i]->setAncestors.size(), i == 0 ? 0u : 1u);
            if (i > 0)
                BOOST_CHECK(branch[i]->setAncestors.count(branch[i - 1]));
        }
    }
    for (const auto &tx : {provider, child, grandchild})
        BOOST_CHECK(CTailstormForestTest::HasDagTx(*tree, tx->GetId()));

    std::vector<CTreeNodeRef> expectedOrder;
    if (branchA.size() == branchB.size())
    {
        // Equal chains have equal scores; longer remaining descendant lists rank first.
        // This places both roots before their children, with lower hash first at each depth.
        for (size_t i = 0; i < branchA.size(); ++i)
        {
            CTreeNodeRef first = branchA[i];
            CTreeNodeRef second = branchB[i];
            if (second->hash < first->hash)
                std::swap(first, second);
            expectedOrder.insert(expectedOrder.end(), {first, second});
        }
    }
    else
    {
        // Every sub-block in the four-node chain scores four, ahead of the three-node chain.
        expectedOrder = branchB;
        expectedOrder.insert(expectedOrder.end(), branchA.begin(), branchA.end());
    }

    // Seed different sequence ids; each rebuild must restore the same canonical order.
    std::vector<std::vector<CTreeNodeRef> > orders{branchA, branchB, {}};
    orders[0].insert(orders[0].end(), branchB.begin(), branchB.end());
    orders[1].insert(orders[1].end(), branchA.begin(), branchA.end());
    // Alternate branches, then finish the longer one without dropping its final node.
    for (size_t i = 0; i < std::max(branchA.size(), branchB.size()); ++i)
    {
        if (i < branchB.size())
            orders[2].push_back(branchB[i]);
        if (i < branchA.size())
            orders[2].push_back(branchA[i]);
    }
    Coin providerFirstCoin;
    for (size_t order = 0; order < orders.size(); ++order)
    {
        BOOST_TEST_CONTEXT("initial sequence order=" << order)
        {
            const auto &nodes = orders[order];
            for (size_t i = 0; i < nodes.size(); ++i)
                nodes[i]->nSequenceId = i + 1;
            // Rebuild from summary-root coins rather than reusing the insertion view.
            tailstormForest.ReGenerateDagData(grove);

            for (size_t i = 0; i < expectedOrder.size(); ++i)
            {
                BOOST_CHECK(expectedOrder[i]->fProcessed);
                BOOST_CHECK_EQUAL(expectedOrder[i]->nSequenceId, i + 1);
            }
            for (const auto &tx : {provider, child, grandchild})
                BOOST_CHECK(CTailstormForestTest::HasDagTx(*tree, tx->GetId()));
            // Only d's output survives once p, c and d have all been applied.
            CCoinsViewCache &view = CTailstormForestTest::CoinsView(*tree);
            for (const auto &tx : {coin.parentTx, provider, child})
                BOOST_CHECK(!view.HaveCoin(tx->OutpointAt(0)));
            Coin result;
            BOOST_REQUIRE(view.GetCoin(grandchild->OutpointAt(0), result));
            BOOST_CHECK(result.out == grandchild->vout[0]);
            BOOST_CHECK_EQUAL(result.height(), coin.height);
            if (order == 0)
                providerFirstCoin = result;
            else
            {
                BOOST_CHECK(result.out == providerFirstCoin.out);
                BOOST_CHECK_EQUAL(result.height(), providerFirstCoin.height());
            }
            // The rebuilt DAG must not spend coins in its summary-root backend.
            BOOST_CHECK(coinsCache.HaveCoin(coin.parentTx->OutpointAt(0)));
            for (const auto &tx : {provider, child, grandchild})
                BOOST_CHECK(!coinsCache.HaveCoin(tx->OutpointAt(0)));
        }
    }
}

BOOST_AUTO_TEST_CASE(regeneration_retries_longer_branches)
{
    // Subblock ancestry (parent -> child):
    //             +--> A1 --> A2[p] --> A3
    // Summary ----+
    //             +--> B1 --> B2[c] --> B3[d]
    // Uppercase names are subblocks; lowercase names in brackets are transactions.
    //
    // p spends a summary-root coin; c spends p's output; d spends c's output.
    // The branches have no subblock ancestry link. Insert branch B before A,
    // then seed A-first, B-first and interleaved sequence ids before rebuilding.
    // Each rebuild must restore canonical order, apply all three transactions and leave only the output of d.
    CheckCrossBranchRegeneration(coinsCache, 3);
}

BOOST_AUTO_TEST_CASE(regeneration_retries_unequal_branches)
{
    // Subblock ancestry (parent -> child):
    //             +--> A1 --> A2[p] --> A3
    // Summary ----+
    //             +--> B1 --> B2[c] --> B3 --> B4[d]
    // Uppercase names are subblocks; lowercase names in brackets are transactions.
    //
    // p spends a summary-root coin; c spends p's output; d spends c's output.
    // The branches have no subblock ancestry link, and B3 adds a step between
    // the sub-blocks carrying c and d. Insert B before A, then seed A-first, B-first
    // and interleaved sequence ids before rebuilding. All seven sub-blocks must remain
    // selected in canonical order, with p, c and d applied and only the output of d left.
    CheckCrossBranchRegeneration(coinsCache, 4);
}

BOOST_AUTO_TEST_CASE(winner_flip_evicts_pool_dependents_at_regeneration)
{
    // Two subblocks spend the same coin. With equal scores the lower-hash subblock wins and its
    // transaction is applied, so a pool child of it is admissible. A third subblock extending the
    // losing subblock raises that side's score, the winner flips at regeneration, and the old
    // winner's outputs leave the view. The old winner and its child must leave the pool with them.
    DoubleSpendTestCoin coin(coinsCache);
    const CBlockIndex &summary = coin.chain.previousSummary;
    // Different output values keep the two spends distinct.
    CTransactionRef winnerTx = coin.SpendCoin(500);
    CTransactionRef loserTx = coin.SpendCoin(400);
    ConstCBlockRef winnerBlock = MakeTestSubblock(summary, {}, 95, {winnerTx});
    ConstCBlockRef loserBlock = MakeTestSubblock(summary, {}, 96, {loserTx});
    if (loserBlock->GetHash() < winnerBlock->GetHash())
    {
        std::swap(winnerBlock, loserBlock);
        std::swap(winnerTx, loserTx);
    }
    BOOST_REQUIRE(tailstormForest.Insert(winnerBlock));
    BOOST_REQUIRE(tailstormForest.Insert(loserBlock));

    const CTransactionRef childTx = coin.Spend(winnerTx->OutpointAt(0), winnerTx->vout[0].nValue, 100);
    coin.Pool(winnerTx);
    coin.Pool(childTx);

    // A subblock on the losing side gives it the higher score; inserting it regenerates the dag.
    ConstCBlockRef flip = MakeTestSubblock(summary, {MakeTreeNodeRef(loserBlock)}, 97);
    BOOST_REQUIRE(tailstormForest.Insert(flip));

    BOOST_CHECK(!mempool.exists(winnerTx->GetId()));
    BOOST_CHECK(!mempool.exists(childTx->GetId()));
}

BOOST_AUTO_TEST_CASE(first_regeneration_of_a_group_evicts_pool_dependents)
{
    // The first subblock to spend the coin is applied on arrival and a pool child of its spend is
    // admissible. A lower-hash subblock spending the same coin then creates the conflict group and
    // wins the tie, so the group's first regeneration runs before any winner is recorded for it.
    // The child must leave the pool with the displaced spend.
    DoubleSpendTestCoin coin(coinsCache);
    const CBlockIndex &summary = coin.chain.previousSummary;
    const CTransactionRef firstTx = coin.SpendCoin(500);
    const ConstCBlockRef firstBlock = MakeTestSubblock(summary, {}, 95, {firstTx});
    BOOST_REQUIRE(tailstormForest.Insert(firstBlock));

    const CTransactionRef childTx = coin.Spend(firstTx->OutpointAt(0), firstTx->vout[0].nValue, 100);
    coin.Pool(childTx);

    const ConstCBlockRef winnerBlock = MakeLowerHashSubblock(summary, firstBlock, {coin.SpendCoin(400)});
    BOOST_REQUIRE(tailstormForest.Insert(winnerBlock));

    BOOST_CHECK(!mempool.exists(childTx->GetId()));
}

BOOST_AUTO_TEST_CASE(loser_descendant_chain_evicts_pool_dependents)
{
    // Two applied subblocks carry L and then T spending L, neither of them pooled. A pool child C
    // spends T. A lower-hash subblock spending L's coin wins, so both L and T leave the view. C
    // must leave the pool although its parent T was never there.
    DoubleSpendTestCoin coin(coinsCache);
    const CBlockIndex &summary = coin.chain.previousSummary;
    const CTransactionRef losingTx = coin.SpendCoin(500);
    const ConstCBlockRef losingBlock = MakeTestSubblock(summary, {}, 95, {losingTx});
    BOOST_REQUIRE(tailstormForest.Insert(losingBlock));
    const CTransactionRef middleTx = coin.Spend(losingTx->OutpointAt(0), losingTx->vout[0].nValue, 300);
    // A sibling, not a descendant, keeps the scores level so the hash decides the winner.
    const ConstCBlockRef middleBlock = MakeTestSubblock(summary, {}, 96, {middleTx});
    BOOST_REQUIRE(tailstormForest.Insert(middleBlock));

    const CTransactionRef childTx = coin.Spend(middleTx->OutpointAt(0), middleTx->vout[0].nValue, 100);
    coin.Pool(childTx);

    const ConstCBlockRef winnerBlock = MakeLowerHashSubblock(summary, losingBlock, {coin.SpendCoin(400)});
    BOOST_REQUIRE(tailstormForest.Insert(winnerBlock));

    BOOST_CHECK(!mempool.exists(childTx->GetId()));
}

BOOST_AUTO_TEST_CASE(applied_rival_evicts_pool_dependents_of_a_displaced_transaction)
{
    // Two sibling subblocks spend the same coin and the lower-hash one wins, so its transaction L
    // is applied and a pool child C of L is admissible. A third sibling F sorts last. A late
    // previous-epoch subblock then becomes an uncle, and the insert that adopts it is a child of W,
    // which moves W ahead of L in dag order. Uncles take the summary slots first, so F and L leave
    // the selection and W is applied. L cannot be applied while W spends its input, so C has lost
    // its input and must leave the pool.
    const uint32_t tailstormK = Params().GetConsensus().tailstorm_k;
    BOOST_REQUIRE_EQUAL(tailstormK, 4u);
    PreviousEpochTestChain chain(&coinsCache, 30, 31);
    mempool.clear();

    // Previous epoch: k-1 committed subblocks and a late child of one of them.
    std::vector<ConstCBlockRef> existingSubblocks;
    std::vector<CTreeNodeRef> summarySubblocks;
    for (uint32_t i = 0; i < tailstormK - 2; ++i)
    {
        ConstCBlockRef subblock = MakeTestSubblock(chain.previousSummary, {}, static_cast<unsigned char>(40 + i));
        existingSubblocks.push_back(subblock);
        summarySubblocks.push_back(MakeTreeNodeRef(subblock));
    }
    ConstCBlockRef parent = MakeTestSubblock(chain.previousSummary, {}, 60);
    CTreeNodeRef parentNode = MakeTreeNodeRef(parent);
    summarySubblocks.push_back(parentNode);
    ConstCBlockRef lateChild = MakeTestSubblock(chain.previousSummary, {parentNode}, 61);

    std::vector<uint8_t> currentMinerData = GenerateMinerData(tailstormK, summarySubblocks, chain.olderHash);
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
    ScopedChainTip scopedChainTip(&currentSummary);

    for (const ConstCBlockRef &subblock : existingSubblocks)
        BOOST_REQUIRE(tailstormForest.Insert(subblock));
    BOOST_CHECK(!tailstormForest.Insert(lateChild)); // parent not yet held: orphaned
    BOOST_REQUIRE(tailstormForest.Insert(parent));

    // One coin at the current tip, and the two rival spends of it.
    const int height = currentSummary.height() + 1;
    CMutableTransaction coinTx;
    coinTx.vin.emplace_back(COutPoint(MakeTestTreeNode(94)->hash, 0), 2000);
    coinTx.vout.emplace_back(1000, testSpendable);
    const CTransactionRef parentTx = MakeTransactionRef(coinTx);
    AddCoins(coinsCache, *parentTx, height);
    auto spend = [&](const COutPoint &out, CAmount amount, CAmount value)
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(out, amount);
        tx.vin.back().scriptSig = CScript() << OP_0;
        tx.vout.emplace_back(value, testSpendable);
        return MakeTransactionRef(tx);
    };
    const CTransactionRef txW = spend(parentTx->OutpointAt(0), 1000, 500);
    const CTransactionRef txL = spend(parentTx->OutpointAt(0), 1000, 400);

    // An unrelated coin and a dummy spend of it, so F carries a tx of its own that conflicts with nothing.
    CMutableTransaction dummyCoinTx;
    dummyCoinTx.vin.emplace_back(COutPoint(MakeTestTreeNode(95)->hash, 0), 2000);
    dummyCoinTx.vout.emplace_back(1000, testSpendable);
    const CTransactionRef dummyParentTx = MakeTransactionRef(dummyCoinTx);
    AddCoins(coinsCache, *dummyParentTx, height);
    const CTransactionRef txF = spend(dummyParentTx->OutpointAt(0), 1000, 300);

    // Three sibling roots of equal score, so dag order is hash order: L < W < F. All three fit in the
    // k - 1 places, L comes before W and so wins the double spend, and F is the last selected.
    const ConstCBlockRef blockW = MakeTestSubblock(currentSummary, {}, 71, {txW});
    const ConstCBlockRef blockL = MakeLowerHashSubblock(currentSummary, blockW, {txL});
    const ConstCBlockRef blockF = MakeHigherHashSubblock(currentSummary, blockW, {txF});
    BOOST_REQUIRE(tailstormForest.Insert(blockF));
    BOOST_REQUIRE(tailstormForest.Insert(blockW));
    BOOST_REQUIRE(tailstormForest.Insert(blockL));

    std::vector<CTreeNodeRef> bestDag;
    CTailstormTreeRef tree;
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(currentHash, bestDag, &tree));
    BOOST_REQUIRE_EQUAL(bestDag.size(), tailstormK - 1);
    BOOST_CHECK(bestDag[0]->hash == blockL->GetHash());
    BOOST_CHECK(bestDag[1]->hash == blockW->GetHash());
    // The best dag is in sorted order, so its last element is the lowest sorted selected subblock.
    const CTreeNodeRef lowestSortedBlock = bestDag.back();
    BOOST_CHECK(lowestSortedBlock->hash == blockF->GetHash());
    BOOST_REQUIRE(tree);
    // W comes after L, so its double spend is skipped.
    BOOST_REQUIRE(CTailstormForestTest::HasDagTx(*tree, txL->GetId()));
    BOOST_REQUIRE(!CTailstormForestTest::HasDagTx(*tree, txW->GetId()));
    BOOST_REQUIRE(CTailstormForestTest::HasDagTx(*tree, txF->GetId()));

    // C spends L's output and is pooled while L is applied.
    const CTransactionRef txC = spend(txL->OutpointAt(0), txL->vout[0].nValue, 100);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(entry.Height(height).FromTx(*txC));
    BOOST_REQUIRE(mempool.exists(txC->GetId()));

    {
        LOCK(tailstormForest.cs_forest);
        const std::set<uint256> linked = tailstormForest.ProcessOrphans();
        BOOST_REQUIRE_EQUAL(linked.count(lateChild->GetHash()), 1u);
    }

    // With the dependency-score-hash sort order, we cannot adjust the subblock order via arrival.  The
    // only way to adjust it is to change the score by adding a child below the block we want to be the
    // winner, to increase its score.
    const ConstCBlockRef childOfW = MakeTestSubblock(currentSummary, {MakeTreeNodeRef(blockW)}, 72);
    BOOST_REQUIRE(tailstormForest.Insert(childOfW));

    // The selection was already full, so the insert only appends the child, unprocessed, without reordering.
    // The uncle is adopted after it and shrinks the selection. Force the rebuild that a later event would
    // trigger: it reorders the dag, and the child raises W's score above L's.
    CTailstormGroveRef grove;
    BOOST_REQUIRE(tailstormForest.GetGrove(blockW->GetHash(), grove));
    {
        LOCK(tailstormForest.cs_forest);
        TxAdmissionPause pause;
        tailstormForest.ReGenerateDagData(grove);
    }
    bestDag.clear();
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(currentHash, bestDag));
    BOOST_REQUIRE_EQUAL(bestDag.size(), tailstormK - 1);
    BOOST_REQUIRE(FindTestNode(bestDag, lateChild->GetHash()));
    BOOST_REQUIRE(FindTestNode(bestDag, blockW->GetHash()));
    BOOST_REQUIRE(FindTestNode(bestDag, childOfW->GetHash()));
    BOOST_REQUIRE(!FindTestNode(bestDag, lowestSortedBlock->hash));
    BOOST_REQUIRE(!FindTestNode(bestDag, blockL->GetHash()));
    BOOST_CHECK(CTailstormForestTest::HasDagTx(*tree, txW->GetId()));
    BOOST_CHECK(!CTailstormForestTest::HasDagTx(*tree, txL->GetId()));
    BOOST_CHECK(!mempool.exists(txC->GetId()));
    mempool.clear();
}

// A summary over subblocks of a DoubleSpendTestCoin's epoch, connected through ConnectBlock as a
// peer's summary would be. The coins view is at the summary root for the life of the case.
class SummaryValidationCase
{
    CCoinsViewCache &parent;
    const bool wasSynced;
    const bool checkpoints;

public:
    DoubleSpendTestCoin coin;

    explicit SummaryValidationCase(CCoinsViewCache &coins)
        : parent(coins), wasSynced(IsInitialSyncComplete()), checkpoints(fCheckpointsEnabled), coin(coins)
    {
        BOOST_REQUIRE_EQUAL(Params().GetConsensus().tailstorm_k, 4u);
        bool synced = true;
        IsInitialSyncCompleteInit(&synced);
        fCheckpointsEnabled = false;
        parent.SetBestBlock(coin.chain.previousHash);
    }

    ~SummaryValidationCase()
    {
        bool synced = wasSynced;
        IsInitialSyncCompleteInit(&synced);
        fCheckpointsEnabled = checkpoints;
    }

    // Insert a subblock into the forest and return its live node.
    CTreeNodeRef Insert(const ConstCBlockRef &block)
    {
        BOOST_REQUIRE(tailstormForest.Insert(block));
        std::vector<CTreeNodeRef> dag;
        BOOST_REQUIRE(tailstormForest.GetFullDagFor(coin.chain.previousHash, dag));
        CTreeNodeRef node = FindTestNode(dag, block->GetHash());
        BOOST_REQUIRE(node);
        return node;
    }

    // The declared nodes in the order a summary must list them: uncles first, then the subblocks as
    // AnalyzeSummaryDag orders them.
    std::vector<CTreeNodeRef> Declaration(const std::vector<CTreeNodeRef> &declared) const
    {
        std::vector<CTreeNodeRef> ordered;
        std::vector<ConstCBlockRef> subblocks;
        std::map<uint256, CTreeNodeRef> byHash;
        for (const CTreeNodeRef &node : declared)
        {
            if (node->fUncle)
                ordered.push_back(node);
            else
            {
                subblocks.push_back(node->subblock);
                byHash[node->hash] = node;
            }
        }
        std::vector<ConstCBlockRef> analyzed;
        std::set<uint256> excluded;
        std::string reject;
        BOOST_REQUIRE_MESSAGE(
            AnalyzeSummaryDag(coin.chain.previousHash, subblocks, parent, analyzed, excluded, reject), reject);
        for (const ConstCBlockRef &block : analyzed)
            ordered.push_back(byHash.at(block->GetHash()));
        return ordered;
    }

    // A summary declaring the given nodes and carrying txs, which pay fees on top of the subsidy. The
    // coinbase pays the dag as validation computes it, from the forest's nodes for the declared proofs;
    // payout names those nodes when they differ from declared.
    CBlockRef Summary(const std::vector<CTreeNodeRef> &declared,
        const std::vector<CTransactionRef> &txs,
        CAmount fees,
        const std::vector<CTreeNodeRef> *payout = nullptr)
    {
        const auto &chain = coin.chain;
        const std::vector<CTreeNodeRef> ordered = Declaration(declared);
        const auto minerData = GenerateMinerData(Params().GetConsensus().tailstorm_k, ordered, chain.olderHash);
        CBlockRef summary = MakeBlockRef(MakeTestSummaryHeader(
            chain.previousHash, chain.previousSummary.height() + 1, chain.previousSummary.chainWork(), 32, minerData));
        const CAmount reward = GetBlockSubsidy(summary->height, Params().GetConsensus()) + fees;
        const std::vector<CTreeNodeRef> &paid = payout ? *payout : declared;
        const auto scores = GetDagScores(paid);
        uint64_t totalScore = paid.size();
        for (const auto &entry : scores)
            totalScore += entry.second;
        CAmount dagReward = 0;
        for (const auto &entry : scores)
            dagReward += reward * entry.second / totalScore;
        CMutableTransaction cb;
        cb.vout.emplace_back(dagReward, paid[0]->subblock->vtx[0]->vout[0].scriptPubKey);
        cb.vout.emplace_back(reward - dagReward, testSpendable);
        cb.vout.emplace_back(0, CScript() << OP_RETURN << summary->height << std::vector<uint8_t>(MIN_TX_SIZE));
        summary->vtx = {MakeTransactionRef(cb)};
        summary->vtx.insert(summary->vtx.end(), txs.begin(), txs.end());
        std::sort(summary->vtx.begin() + 1, summary->vtx.end(), NumericallyLessTxHashComparator());
        summary->UpdateHeader();
        BOOST_REQUIRE(summary->IsTailstormSummaryBlock());
        return summary;
    }

    bool Connect(const CBlockRef &summary, CValidationState &state)
    {
        BOOST_REQUIRE_MESSAGE(CheckBlock(Params().GetConsensus(), summary, state, false, true), state.GetLogString());
        CBlockIndex index(*summary);
        index.pprev = &coin.chain.previousSummary;
        CCoinsViewCache view(&parent);
        std::map<CGroupTokenID, CAmount> mintages;
        std::map<CGroupTokenID, CAuth> authorities;
        const bool connected =
            ConnectBlock(summary, state, &index, view, parent, Params(), mintages, authorities, true);
        BOOST_TEST_MESSAGE("summary result: " << connected << " " << state.GetLogString());
        BOOST_CHECK_EQUAL(chainActive.Tip()->GetBlockHash(), coin.chain.previousHash);
        BOOST_CHECK(parent.HaveCoin(coin.parentTx->OutpointAt(0)));
        return connected;
    }
};

BOOST_AUTO_TEST_CASE(summary_accepts_child_before_parent)
{
    // An early input check must preserve CTOR: a transaction's parent may occur later.
    LOCK(cs_main);
    SummaryValidationCase test(coinsCache);
    const auto &root = test.coin.chain.previousSummary;
    const std::vector<CTreeNodeRef> declared{test.Insert(MakeTestSubblock(root, {}, 95)),
        test.Insert(MakeTestSubblock(root, {}, 96)), test.Insert(MakeTestSubblock(root, {}, 97))};
    const CTransactionRef parent = test.coin.SpendCoin(500);
    CTransactionRef child;
    for (CAmount value = 1; value < 500; ++value)
    {
        child = test.coin.Spend(parent->OutpointAt(0), 500, value);
        if (NumericallyLessTxHashComparator()(child, parent))
            break;
    }
    BOOST_REQUIRE(NumericallyLessTxHashComparator()(child, parent));
    const auto summary = test.Summary(declared, {parent, child}, 1000 - child->vout[0].nValue);
    BOOST_REQUIRE_EQUAL(summary->vtx[1]->GetId(), child->GetId());
    CValidationState state;
    BOOST_CHECK_MESSAGE(test.Connect(summary, state), state.GetLogString());
}

BOOST_AUTO_TEST_CASE(summary_dag_is_rebuilt_from_the_declaration)
{
    // Three chained subblocks. The dag analyzed for a summary is rebuilt from their headers alone, so
    // it comes back in chain order whatever the declaration order, and the forest need not hold them.
    BOOST_REQUIRE_EQUAL(Params().GetConsensus().tailstorm_k, 4u);
    PreviousEpochTestChain chain(&coinsCache, 92, 93);
    const ConstCBlockRef a = MakeTestSubblock(chain.previousSummary, {}, 95);
    const ConstCBlockRef b = MakeTestSubblock(chain.previousSummary, {MakeTreeNodeRef(a)}, 96);
    const ConstCBlockRef c = MakeTestSubblock(chain.previousSummary, {MakeTreeNodeRef(b)}, 97);

    const std::vector<std::vector<ConstCBlockRef> > declarations{{c, a, b}, {b, c, a}, {a, b, c}};
    for (const std::vector<ConstCBlockRef> &declared : declarations)
    {
        std::vector<ConstCBlockRef> ordered;
        std::set<uint256> excluded;
        std::string reject;
        BOOST_REQUIRE_MESSAGE(
            AnalyzeSummaryDag(chain.previousHash, declared, coinsCache, ordered, excluded, reject), reject);
        BOOST_REQUIRE_EQUAL(ordered.size(), 3u);
        BOOST_CHECK_EQUAL(ordered[0]->GetHash(), a->GetHash());
        BOOST_CHECK_EQUAL(ordered[1]->GetHash(), b->GetHash());
        BOOST_CHECK_EQUAL(ordered[2]->GetHash(), c->GetHash());
        BOOST_CHECK(excluded.empty());
    }
}

BOOST_AUTO_TEST_CASE(summary_exclusions_drop_unsourced_declared_transactions)
{
    // A declared transaction sources from the coins at the summary root or from another declared
    // transaction. One that does neither is excluded, and it is not a double spend loser.
    DoubleSpendTestCoin coin(coinsCache);
    const CBlockIndex &summaryRoot = coin.chain.previousSummary;
    const CTransactionRef txA = coin.SpendCoin(500);
    const CTransactionRef txB = coin.Spend(txA->OutpointAt(0), txA->vout[0].nValue, 300);
    const CTransactionRef txC = coin.Spend(COutPoint(MakeTestTreeNode(99)->hash, 0), 1000, 100);
    const CTreeNodeRef a = MakeTreeNodeRef(MakeTestSubblock(summaryRoot, {}, 95, {txA}));
    const CTreeNodeRef b = MakeTreeNodeRef(MakeTestSubblock(summaryRoot, {a}, 96, {txB}));
    const CTreeNodeRef c = MakeTreeNodeRef(MakeTestSubblock(summaryRoot, {}, 98, {txC}));

    std::vector<ConstCBlockRef> ordered;
    std::set<uint256> excluded;
    std::string reject;
    BOOST_REQUIRE_MESSAGE(AnalyzeSummaryDag(coin.chain.previousHash, {a->subblock, b->subblock, c->subblock},
                              coinsCache, ordered, excluded, reject),
        reject);
    BOOST_CHECK_EQUAL(excluded.size(), 1u);
    BOOST_CHECK_EQUAL(excluded.count(txC->GetId()), 1u);

    // The same dag through the exclusion set alone, which also reports the losers: there are none.
    LOCK(tailstormForest.cs_forest);
    LinkTestTreeNodes(a, b);
    std::set<uint256> losers;
    const std::set<uint256> direct = GetTxnExclusionSet(OrderDag({a, b, c}), &coinsCache, &losers);
    BOOST_CHECK(losers.empty());
    BOOST_CHECK(direct == excluded);
}

BOOST_AUTO_TEST_CASE(summary_validation_isolated_from_live_dag)
{
    // Connect the same summary while the forest's view of its dag changes: after a fault in the live
    // sequence ids, and after a late arrival that reorders the live dag and flips its double spend
    // winner. Missing transactions and incorrect payouts must still fail through the full connection path.
    LOCK(cs_main);
    SummaryValidationCase test(coinsCache);
    const CBlockIndex &root = test.coin.chain.previousSummary;
    const CTransactionRef winner = test.coin.SpendCoin(700);
    const CTransactionRef loser = test.coin.SpendCoin(600);
    const CTransactionRef childTx = test.coin.Spend(winner->OutpointAt(0), 700, 500);
    const ConstCBlockRef a = MakeTestSubblock(root, {}, 95, {winner});
    const ConstCBlockRef b = MakeLowerHashSubblock(root, a, {loser});
    BOOST_REQUIRE(b->GetHash() < a->GetHash());
    const CTreeNodeRef liveA = test.Insert(a);
    const CTreeNodeRef liveC = test.Insert(MakeTestSubblock(root, {MakeTreeNodeRef(a)}, 97, {childTx}));
    const CTreeNodeRef liveB = test.Insert(b);

    // a and c score two each and b one, so a leads the dag order and winner is the first spend.
    const CBlockRef summary = test.Summary({liveA, liveB, liveC}, {winner, childTx}, 500);
    const uint256 summaryHash = summary->GetHash();

    auto check = [&](const CBlockRef &block, const std::string &expectedReject)
    {
        CValidationState state;
        const bool connected = test.Connect(block, state);
        BOOST_CHECK_MESSAGE(connected == expectedReject.empty(), state.GetLogString());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), expectedReject);
    };
    auto checkSummary = [&]()
    {
        check(summary, "");

        CBlockRef missingTx = MakeBlockRef(*summary);
        missingTx->vtx.erase(std::find(missingTx->vtx.begin(), missingTx->vtx.end(), childTx));
        missingTx->UpdateHeader();
        check(missingTx, "bad-blk-missing-txn");

        CBlockRef wrongPayout = MakeBlockRef(*summary);
        CMutableTransaction wrongCoinbase(*summary->vtx[0]);
        --wrongCoinbase.vout[0].nValue;
        wrongPayout->vtx[0] = MakeTransactionRef(wrongCoinbase);
        wrongPayout->UpdateHeader();
        check(wrongPayout, "bad-cb-no-dag-match");
    };
    // The declared dag as the forest holds it, in its live order, and the exclusions that order gives.
    auto liveExclusions = [&](std::vector<CTreeNodeRef> &declared)
    {
        ConstCBlockRef declaredSummary = summary;
        CTailstormTreeRef tree;
        BOOST_REQUIRE(tailstormForest.GetDagForBlock(declaredSummary, declared, &tree));
        BOOST_REQUIRE(tree);
        BOOST_REQUIRE_EQUAL(declared.size(), 3u);
        return GetTxnExclusionSet(declared, *tree);
    };

    LOCK(tailstormForest.cs_forest);
    std::vector<CTreeNodeRef> declared;
    BOOST_CHECK_EQUAL(liveExclusions(declared).count(winner->GetId()), 0u);
    checkSummary();

    // Fault injection: swap the live sequence ids of a and b. The forest now orders the declared dag
    // b, c, a and takes loser as the first spend; validation must not read the ids.
    {
        const uint32_t idA = liveA->nSequenceId;
        const uint32_t idB = liveB->nSequenceId;
        BOOST_SCOPE_EXIT(&liveA, &liveB, idA, idB)
        {
            liveA->nSequenceId = idA;
            liveB->nSequenceId = idB;
        }
        BOOST_SCOPE_EXIT_END
        liveA->nSequenceId = idB;
        liveB->nSequenceId = idA;
        const std::set<uint256> faulted = liveExclusions(declared);
        BOOST_CHECK_EQUAL(faulted.count(winner->GetId()), 1u);
        BOOST_CHECK_EQUAL(faulted.count(loser->GetId()), 0u);
        checkSummary();
    }

    // A late child of b lifts b's rank to a's, and b's lower hash then places it first: the forest
    // reorders the live dag to b, a, c and its winner flips to loser, while the summary stays valid.
    // The selection is already full, so the insert only appends late; renumber as a later event
    // (ReGenerateDagData) would, to apply the reorder.
    const ConstCBlockRef late = MakeTestSubblock(root, {MakeTreeNodeRef(b)}, 98);
    BOOST_REQUIRE(tailstormForest.Insert(late));
    {
        ConstCBlockRef declaredSummary = summary;
        std::vector<CTreeNodeRef> dag;
        CTailstormTreeRef tree;
        BOOST_REQUIRE(tailstormForest.GetDagForBlock(declaredSummary, dag, &tree));
        BOOST_REQUIRE(tree);
        tailstormForest.RenumberDag(*tree);
    }
    const std::set<uint256> flipped = liveExclusions(declared);
    BOOST_REQUIRE(!FindTestNode(declared, late->GetHash()));
    BOOST_CHECK_EQUAL(flipped.count(winner->GetId()), 1u);
    BOOST_CHECK_EQUAL(flipped.count(loser->GetId()), 0u);
    checkSummary();
    BOOST_CHECK_EQUAL(summary->GetHash(), summaryHash);
}

// A subblock built on any root, for declarations the forest would never produce.
static ConstCBlockRef MakeTestSubblockWithRoot(const uint256 &hashPrev,
    const std::vector<CTreeNodeRef> &parents,
    const uint32_t nBits,
    const unsigned char nonce)
{
    CBlockRef block = MakeBlockRef();
    block->hashPrevBlock = hashPrev;
    block->height = 2;
    block->nTime = 3;
    block->minerData = GenerateMinerData(Params().GetConsensus().tailstorm_k, parents, uint256());
    block->nBits = nBits;
    block->nonce = {nonce};
    CMutableTransaction coinbase;
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << block->height);
    block->vtx.push_back(MakeTransactionRef(coinbase));
    block->UpdateHeader();
    return ConstCBlockRef(block);
}

// Analyzed as this epoch's subblocks of chain, these do not form a complete dag, and nothing is returned.
static void CheckSummaryDagIncomplete(const PreviousEpochTestChain &chain,
    const std::vector<ConstCBlockRef> &subblocks,
    const CCoinsViewCache &coins)
{
    std::vector<ConstCBlockRef> ordered;
    std::set<uint256> excluded;
    std::string reject;
    BOOST_CHECK(!AnalyzeSummaryDag(chain.previousHash, subblocks, coins, ordered, excluded, reject));
    BOOST_CHECK_EQUAL(reject, "bad-summary-dag-incomplete");
    BOOST_CHECK(ordered.empty());
    BOOST_CHECK(excluded.empty());
}

BOOST_AUTO_TEST_CASE(summary_rejects_a_subblock_whose_parent_it_does_not_commit)
{
    // b builds on a; the summary declares b, c and d but not a.
    BOOST_REQUIRE_EQUAL(Params().GetConsensus().tailstorm_k, 4u);
    PreviousEpochTestChain chain(&coinsCache, 220, 221);
    const ConstCBlockRef a = MakeTestSubblock(chain.previousSummary, {}, 222);
    const ConstCBlockRef b = MakeTestSubblock(chain.previousSummary, {MakeTreeNodeRef(a)}, 223);
    const ConstCBlockRef c = MakeTestSubblock(chain.previousSummary, {}, 224);
    const ConstCBlockRef d = MakeTestSubblock(chain.previousSummary, {}, 225);
    CheckSummaryDagIncomplete(chain, {b, c, d}, coinsCache);
}

BOOST_AUTO_TEST_CASE(summary_rejects_a_subblock_whose_parent_is_an_uncle)
{
    // u is from the previous epoch and declared as an uncle, so it is not among the analyzed
    // subblocks; y names it as a parent.
    BOOST_REQUIRE_EQUAL(Params().GetConsensus().tailstorm_k, 4u);
    PreviousEpochTestChain chain(&coinsCache, 226, 227);
    const ConstCBlockRef a = MakeTestSubblock(chain.previousSummary, {}, 230);
    const ConstCBlockRef u = MakeTestSubblockWithRoot(chain.olderHash, {}, a->nBits, 228);
    const ConstCBlockRef y = MakeTestSubblock(chain.previousSummary, {MakeTreeNodeRef(u)}, 229);
    CheckSummaryDagIncomplete(chain, {y, a}, coinsCache);
}

BOOST_AUTO_TEST_CASE(summary_uncle_count_must_match_the_blocks)
{
    // Whether a declared block is an uncle follows from the root it builds on, not from the count the
    // summary states. A previous-epoch block listed among the subblocks is not part of this epoch's
    // dag, and a subblock of this epoch listed as an uncle must not have its transactions passed over.
    LOCK(cs_main);
    SummaryValidationCase test(coinsCache);
    const CBlockIndex &root = test.coin.chain.previousSummary;
    const CTransactionRef tx = test.coin.SpendCoin(500);
    const CTreeNodeRef a = test.Insert(MakeTestSubblock(root, {}, 95, {tx}));
    const CTreeNodeRef b = test.Insert(MakeTestSubblock(root, {}, 96));
    const CTreeNodeRef c = test.Insert(MakeTestSubblock(root, {}, 97));
    const std::vector<CTreeNodeRef> live{a, b, c};

    // Declared as they are, the summary carries tx and connects.
    CValidationState honest;
    BOOST_CHECK_MESSAGE(test.Connect(test.Summary(live, {tx}, 500), honest), honest.GetLogString());

    // u builds on the previous summary. Passed to the analysis as a subblock of this epoch, its parent
    // is neither a declared subblock nor the summary root.
    const ConstCBlockRef u = MakeTestSubblockWithRoot(test.coin.chain.olderHash, {}, a->subblock->nBits, 90);
    CheckSummaryDagIncomplete(test.coin.chain, {u, b->subblock, c->subblock}, coinsCache);

    // a declared as an uncle, with tx left out of the summary. The forest holds a as a subblock of this
    // epoch and the coinbase pays it as one.
    CTreeNodeRef claimedUncle = MakeTreeNodeRef(a->subblock);
    claimedUncle->fUncle = true;
    CValidationState state;
    BOOST_CHECK_MESSAGE(!test.Connect(test.Summary({claimedUncle, b, c}, {}, 0, &live), state), state.GetLogString());
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-summary-uncle");
}

BOOST_AUTO_TEST_CASE(summary_rejects_a_block_on_neither_root)
{
    // x builds on a block that is neither this summary's parent nor the previous summary.
    BOOST_REQUIRE_EQUAL(Params().GetConsensus().tailstorm_k, 4u);
    PreviousEpochTestChain chain(&coinsCache, 236, 237);
    const ConstCBlockRef a = MakeTestSubblock(chain.previousSummary, {}, 240);
    const ConstCBlockRef c = MakeTestSubblock(chain.previousSummary, {}, 241);
    const ConstCBlockRef x = MakeTestSubblockWithRoot(MakeTestTreeNode(238)->hash, {}, a->nBits, 239);
    CheckSummaryDagIncomplete(chain, {x, a, c}, coinsCache);
}

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

    std::vector<CTreeNodeRef> setBestDag;
    std::map<uint256, uint32_t> mapExpectedScores;

    CTreeNode node;
    node.hash = InsecureRand256();
    node.dagHeight = 1;
    CTreeNodeRef noderef = MakeTreeNodeRef(node);

    setBestDag.push_back(noderef);
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
    setBestDag.push_back(noderef1);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.insert(noderef1);
    CTreeNodeRef noderef2 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    CTreeNodeRef noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    node.setAncestors.insert(noderef1b);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2);
    mapExpectedScores.emplace(node.hash, 6);


    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2);
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef3 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3);
    mapExpectedScores.emplace(node.hash, 7);


    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3);
    CTreeNodeRef noderef4 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3);
    CTreeNodeRef noderef4b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4b);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 5;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef4);
    CTreeNodeRef noderef5 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef5);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    CTreeNodeRef noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 2);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    CTreeNodeRef noderef3a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3a);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3a);
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
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 1);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3a);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    // Special case in that we need to add the children so we can
    // properly caclulate scores for the skipped level
    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    CTreeNodeRef noderef2d = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2d);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3a);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3a);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2d);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3a);
    CTreeNodeRef noderef4a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
    mapExpectedScores.emplace(node.hash, 5);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2d);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4a);
    mapExpectedScores.emplace(node.hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2d);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2a);
    node.setAncestors.insert(noderef2b);
    node.setAncestors.insert(noderef2c);
    noderef3 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3);
    mapExpectedScores.emplace(node.hash, 7);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 4);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 3);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
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
    setBestDag.push_back(noderef3a);
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
    setBestDag.push_back(noderef1);
    mapExpectedScores.emplace(noderef1->hash, 3);

    noderef2->dagHeight = 2;
    noderef2->setAncestors.clear();
    noderef2->setDescendants.clear();
    noderef2->setAncestors.insert(noderef1);
    setBestDag.push_back(noderef2);
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
    setBestDag.push_back(noderefUncle1);
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
    setBestDag.push_back(noderef1a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    noderef1b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef1b);
    mapExpectedScores.emplace(node.hash, 10);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1a);
    noderef2a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2b = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2b);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2c = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2c);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 2;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef1b);
    noderef2d = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef2d);
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
    setBestDag.push_back(noderef3);
    mapExpectedScores.emplace(node.hash, 9);

    node.hash = InsecureRand256();
    node.dagHeight = 3;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    noderef3a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef3a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef3a);
    noderef4a = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4a);
    mapExpectedScores.emplace(node.hash, 6);

    node.hash = InsecureRand256();
    node.dagHeight = 4;
    node.fUncle = false;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.setAncestors.insert(noderef2d);
    node.setAncestors.insert(noderef3);
    noderef4 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderef4);
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
    setBestDag.push_back(noderefUncle1);
    mapExpectedScores.emplace(noderefUncle1->hash, 8);

    node.hash = InsecureRand256();
    node.dagHeight = 1;
    node.setAncestors.clear();
    node.setDescendants.clear();
    node.fUncle = true;
    CTreeNodeRef noderefUncle2 = MakeTreeNodeRef(node);
    setBestDag.push_back(noderefUncle2);
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

    std::vector<CTreeNodeRef> previousDag;
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
    std::vector<CTreeNodeRef> summarySubblocks;
    for (uint32_t i = 0; i < tailstormK - 2; ++i)
    {
        ConstCBlockRef subblock =
            MakeTestSubblock(chain.previousSummary, {}, static_cast<unsigned char>(40 + i));
        existingSubblocks.push_back(subblock);
        summarySubblocks.push_back(MakeTreeNodeRef(subblock));
    }

    ConstCBlockRef parent = MakeTestSubblock(chain.previousSummary, {}, 60);
    CTreeNodeRef parentNode = MakeTreeNodeRef(parent);
    summarySubblocks.push_back(parentNode);
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

    std::vector<CTreeNodeRef> previousDag;
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

    std::vector<CTreeNodeRef> currentDag;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(currentHash, currentDag));
    CTreeNodeRef childUncle = FindTestNode(currentDag, child->GetHash());
    BOOST_REQUIRE(childUncle);
    BOOST_CHECK(childUncle->fUncle);
    BOOST_CHECK_EQUAL(childUncle->roothash, currentHash);

    std::vector<CTreeNodeRef> bestDag;
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(currentHash, bestDag));
    CTreeNodeRef selectedChildUncle = FindTestNode(bestDag, child->GetHash());
    BOOST_REQUIRE(selectedChildUncle);
    BOOST_CHECK(selectedChildUncle->fUncle);
    BOOST_CHECK_EQUAL(selectedChildUncle->roothash, currentHash);
}

BOOST_AUTO_TEST_CASE(summary_orphan_survives_descendant_grove)
{
    // A future-epoch subblock can create a grove rooted at a summary block before
    // that summary has all of its own subblocks. The grove must not make the
    // unvalidated summary look connected or it will never be retried.
    const uint32_t tailstormK = Params().GetConsensus().tailstorm_k;
    BOOST_REQUIRE(tailstormK >= 3);

    PreviousEpochTestChain chain(&coinsCache, 80, 81);
    chain.olderSummary.nNextMaxBlockSize = Params().GetConsensus().nNextMaxBlockSize;
    ScopedChainTip scopedChainTip(&chain.previousSummary);

    std::vector<ConstCBlockRef> summarySubblocks;
    std::vector<CTreeNodeRef> summarySubblockNodes;
    for (uint32_t i = 0; i < tailstormK - 1; ++i)
    {
        ConstCBlockRef subblock =
            MakeTestSubblock(chain.previousSummary, {}, static_cast<unsigned char>(90 + i));
        summarySubblocks.push_back(subblock);
        summarySubblockNodes.push_back(MakeTreeNodeRef(subblock));
    }

    std::vector<uint8_t> minerData =
        GenerateMinerData(tailstormK, summarySubblockNodes, chain.olderHash);
    CBlockHeader currentHeader =
        MakeTestSummaryHeader(chain.previousHash, 2, chain.previousSummary.chainWork(), 100, minerData);
    // Make the eventual processing attempt fail CheckBlockHeader() without violating
    // the preconditions of GetHash(), which is needed to register the test block.
    currentHeader.nonce.resize(CBlockHeader::MAX_NONCE_SIZE + 1);
    CBlockIndex currentSummary(currentHeader);
    currentSummary.pprev = &chain.previousSummary;
    currentSummary.nStatus |= BLOCK_PROCESSED | BLOCK_HAVE_DATA | BLOCK_LINKED;
    {
        WRITELOCK(cs_mapBlockIndex);
        currentSummary.RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    }
    currentSummary.nNextMaxBlockSize = Params().GetConsensus().nNextMaxBlockSize;
    const uint256 currentHash = currentHeader.GetHash();
    ScopedBlockIndexEntry currentEntry(currentHash, &currentSummary);
    ConstCBlockRef currentBlock = std::make_shared<const CBlock>(currentHeader);
    ScopedBlockCacheEntry currentCacheEntry(currentBlock, currentSummary.height());

    // One subblock is enough to create the current summary's predecessor grove,
    // but the remaining summary proofs are deliberately absent.
    BOOST_REQUIRE(tailstormForest.Insert(summarySubblocks.front()));
    ConstCBlockRef futureSubblock = MakeTestSubblock(currentSummary, {}, 110);
    BOOST_REQUIRE(tailstormForest.Insert(futureSubblock));

    CTailstormGroveRef descendantGrove;
    BOOST_REQUIRE(tailstormForest.GetGrove(currentHash, descendantGrove));

    tailstormForest.AddSummaryBlockOrphan(currentBlock);
    BOOST_REQUIRE_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 1);
    {
        LOCK(tailstormForest.cs_forest);
        tailstormForest.ProcessOrphans();
    }

    BOOST_CHECK_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 1);

    // Once all committed subblocks arrive, processing is attempted. A
    // definitively invalid summary is removed instead of being retried.
    for (size_t i = 1; i < summarySubblocks.size(); ++i)
        BOOST_REQUIRE(tailstormForest.Insert(summarySubblocks[i]));
    {
        LOCK(tailstormForest.cs_forest);
        tailstormForest.ProcessOrphans();
    }
    BOOST_CHECK_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 0);

    // Independent validation makes the retry entry unnecessary even if this
    // ProcessOrphans() call was not the one that validated the summary.
    CBlockHeader validatedHeader =
        MakeTestSummaryHeader(chain.previousHash, 2, chain.previousSummary.chainWork(), 101, minerData);
    CBlockIndex validatedSummary(validatedHeader);
    validatedSummary.pprev = &chain.previousSummary;
    validatedSummary.nStatus |= BLOCK_PROCESSED | BLOCK_HAVE_DATA | BLOCK_LINKED;
    {
        WRITELOCK(cs_mapBlockIndex);
        BOOST_REQUIRE(validatedSummary.RaiseValidity(BLOCK_VALID_SCRIPTS));
    }
    const uint256 validatedHash = validatedHeader.GetHash();
    ScopedBlockIndexEntry validatedEntry(validatedHash, &validatedSummary);
    ConstCBlockRef validatedBlock = std::make_shared<const CBlock>(validatedHeader);
    tailstormForest.AddSummaryBlockOrphan(validatedBlock);
    BOOST_REQUIRE_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 1);
    {
        LOCK(tailstormForest.cs_forest);
        tailstormForest.ProcessOrphans();
    }
    BOOST_CHECK_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 0);

    // Age-based cleanup remains a backstop for retained entries.
    tailstormForest.AddSummaryBlockOrphan(currentBlock);
    BOOST_REQUIRE_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 1);
    {
        LOCK(tailstormForest.cs_forest);
        tailstormForest.ClearByHeight(currentBlock->height);
    }
    BOOST_CHECK_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 0);
}

BOOST_AUTO_TEST_CASE(summary_orphan_accept_subblock)
{
    // AcceptSubblock must retry a complete summary orphan before checking the forest.
    // The summary is deliberately invalid so the retry has a definite outcome.
    const uint32_t tailstormK = Params().GetConsensus().tailstorm_k;
    BOOST_REQUIRE(tailstormK >= 3);

    PreviousEpochTestChain chain(&coinsCache, 120, 121);
    ScopedChainTip scopedChainTip(&chain.previousSummary);

    std::vector<ConstCBlockRef> subblocks;
    std::vector<CTreeNodeRef> nodes;
    for (uint32_t i = 0; i < tailstormK - 1; ++i)
    {
        subblocks.push_back(MakeTestSubblock(chain.previousSummary, {}, static_cast<unsigned char>(130 + i)));
        nodes.push_back(MakeTreeNodeRef(subblocks.back()));
    }

    const auto minerData = GenerateMinerData(tailstormK, nodes, chain.olderHash);
    CBlockHeader summaryHeader =
        MakeTestSummaryHeader(chain.previousHash, 2, chain.previousSummary.chainWork(), 140, minerData);
    summaryHeader.nonce.resize(CBlockHeader::MAX_NONCE_SIZE + 1);
    CBlockIndex summaryIndex(summaryHeader);
    summaryIndex.pprev = &chain.previousSummary;
    summaryIndex.nStatus |= BLOCK_PROCESSED | BLOCK_HAVE_DATA | BLOCK_LINKED;
    {
        WRITELOCK(cs_mapBlockIndex);
        BOOST_REQUIRE(summaryIndex.RaiseValidity(BLOCK_VALID_TRANSACTIONS));
    }
    summaryIndex.nNextMaxBlockSize = Params().GetConsensus().nNextMaxBlockSize;
    const uint256 summaryHash = summaryHeader.GetHash();
    ScopedBlockIndexEntry summaryEntry(summaryHash, &summaryIndex);
    ConstCBlockRef summary = std::make_shared<const CBlock>(summaryHeader);
    ScopedBlockCacheEntry summaryCacheEntry(summary, summaryIndex.height());

    for (size_t i = 0; i + 1 < subblocks.size(); ++i)
        BOOST_REQUIRE(tailstormForest.Insert(subblocks[i]));
    ConstCBlockRef descendant = MakeTestSubblock(summaryIndex, {}, 150);
    BOOST_REQUIRE(tailstormForest.Insert(descendant));
    tailstormForest.AddSummaryBlockOrphan(summary);

    CTailstormGroveRef descendantGrove;
    BOOST_REQUIRE(tailstormForest.GetGrove(summaryHash, descendantGrove));
    BOOST_REQUIRE_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 1);
    std::vector<CTreeNodeRef> committed;
    BOOST_REQUIRE(!tailstormForest.GetDagForBlock(summary, committed));

    // The predecessor lookup is only fixture scaffolding, not a populated grove.
    CTailstormForestTest::RemoveGroveLookup(tailstormForest, chain.olderHash);
    const bool originalTailstormEnabled = fTailstormEnabled.load();
    const bool originalTemplateRecalc = forceTemplateRecalc.load();
    BOOST_SCOPE_EXIT(originalTailstormEnabled, originalTemplateRecalc)
    {
        tailstormForest.setSanityCheck(0.0);
        fTailstormEnabled.store(originalTailstormEnabled);
        forceTemplateRecalc.store(originalTemplateRecalc);
    }
    BOOST_SCOPE_EXIT_END
    fTailstormEnabled.store(true);
    tailstormForest.setSanityCheck(1.0);
    tailstormForest.Check();

    // Use the production entry point: insertion, orphan processing, reorg check, consistency check.
    AcceptSubblock(subblocks.back());

    BOOST_CHECK_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 0);
    committed.clear();
    BOOST_REQUIRE(tailstormForest.GetDagForBlock(summary, committed));
    BOOST_CHECK_EQUAL(committed.size(), tailstormK - 1);
    BOOST_CHECK(FindTestNode(committed, subblocks.back()->GetHash()));
    BOOST_CHECK(tailstormForest.GetGrove(summaryHash, descendantGrove));
    BOOST_CHECK(chainActive.Tip() == &chain.previousSummary);
    {
        READLOCK(cs_mapBlockIndex);
        BOOST_CHECK(!summaryIndex.IsValid(BLOCK_VALID_SCRIPTS));
    }
}

BOOST_AUTO_TEST_CASE(summary_orphan_late_uncle)
{
    // R closes the epoch rooted at R0, committing A, B and C but omitting U.
    // S waits for U as an uncle alongside D and E; F already references S.
    // Parent references:
    // R0 --> A --> B --> C --> U
    // R  --> D
    // R  --> E
    // S  --> F
    const uint32_t tailstormK = Params().GetConsensus().tailstorm_k;
    BOOST_REQUIRE(tailstormK >= 3);
    const bool originalTailstormEnabled = fTailstormEnabled.load();
    const bool originalTemplateRecalc = forceTemplateRecalc.load();
    const uint64_t originalForkTime = nMiningForkTime;
    bool originalSyncComplete = IsInitialSyncComplete();
    BOOST_SCOPE_EXIT(originalTailstormEnabled, originalTemplateRecalc, originalForkTime, originalSyncComplete)
    {
        tailstormForest.setSanityCheck(0.0);
        fTailstormEnabled.store(originalTailstormEnabled);
        forceTemplateRecalc.store(originalTemplateRecalc);
        nMiningForkTime = originalForkTime;
        IsInitialSyncCompleteInit(&originalSyncComplete);
    }
    BOOST_SCOPE_EXIT_END

    // Use the real chain and coins view so orphan replay can validate and activate S.
    tailstormForest.SetBackend(pcoinsTip);
    fTailstormEnabled.store(false);
    auto initialTemplate = BlockAssembler(Params()).CreateNewBlock(CScript() << OP_RETURN);
    CBlockRef initialBlock = initialTemplate->block;
    initialBlock->nonce.resize(4);
    initialBlock->UpdateHeader();
    BOOST_REQUIRE(MineBlock(*initialBlock, 100000, Params().GetConsensus()));
    CValidationState initialState;
    const bool initialAccepted =
        ProcessSummaryBlock(initialState, Params(), nullptr, initialBlock, true, nullptr, SINGLE_THREADED);
    BOOST_REQUIRE_MESSAGE(initialAccepted, initialState.GetLogString());
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == initialBlock->GetHash());
    CBlockIndex *previousRoot = chainActive.Tip();

    nMiningForkTime = 1;
    fTailstormEnabled.store(true);
    bool synced = true;
    IsInitialSyncCompleteInit(&synced);

    auto makeSubblock = [&](const CBlockIndex &root, const std::vector<CTreeNodeRef> &parents, unsigned char tag)
    {
        CBlockRef block = std::make_shared<CBlock>(*MakeTestSubblock(root, parents, tag));
        CMutableTransaction coinbase(*block->vtx[0]);
        coinbase.vout[0].scriptPubKey << std::vector<uint8_t>(100, tag);
        block->vtx[0] = MakeTransactionRef(coinbase);
        block->nonce = {tag, 0, 0, 0};
        block->UpdateHeader();
        BOOST_REQUIRE(MineBlock(*block, 100000, Params().GetConsensus()));
        CValidationState state;
        BOOST_REQUIRE_MESSAGE(CheckBlock(Params().GetConsensus(), block, state), state.GetLogString());
        return ConstCBlockRef(block);
    };
    auto makeSummary = [&](CBlockIndex &root, std::vector<CTreeNodeRef> nodes, unsigned char tag)
    {
        CBlockRef block = std::make_shared<CBlock>(MakeTestSummaryHeader(root.GetBlockHash(), root.height() + 1,
            root.chainWork(), tag, GenerateMinerData(tailstormK, nodes, root.pprev->GetBlockHash())));
        block->nTime = root.GetBlockTime() + 1;
        block->hashAncestor = root.GetChildsConsensusAncestor()->GetBlockHash();
        block->nBits = GetNextWorkRequired(&root, block.get(), Params().GetConsensus());
        block->chainWork = ArithToUint256(root.chainWork() + block->GetBlockWork());
        const CAmount reward = GetBlockSubsidy(block->height, Params().GetConsensus());
        const auto scores = GetDagScores(nodes);
        uint32_t totalScore = tailstormK - 1;
        for (const auto &entry : scores)
            totalScore += entry.second;
        CMutableTransaction coinbase;
        CAmount paid = 0;
        for (const auto &entry : scores)
        {
            const CAmount amount = reward * entry.second / totalScore;
            coinbase.vout.emplace_back(amount, entry.first->subblock->vtx[0]->vout[0].scriptPubKey);
            paid += amount;
        }
        coinbase.vout.emplace_back(reward - paid, CScript() << OP_RETURN << tag);
        coinbase.vout.emplace_back(0, CScript() << OP_RETURN << block->height << std::vector<uint8_t>(100, tag));
        block->vtx.push_back(MakeTransactionRef(coinbase));
        block->nonce = {tag, 0, 0, 0};
        block->UpdateHeader();
        BOOST_REQUIRE(MineBlock(*block, 100000, Params().GetConsensus()));
        CValidationState state;
        BOOST_REQUIRE_MESSAGE(CheckBlock(Params().GetConsensus(), block, state), state.GetLogString());
        const bool contextual = ContextualCheckBlock(block, state, &root);
        BOOST_REQUIRE_MESSAGE(contextual, state.GetLogString());
        BOOST_REQUIRE(ValidateSummaryBlockCoinbase(reward, block, nodes));
        return ConstCBlockRef(block);
    };

    std::vector<CTreeNodeRef> previousNodes;
    for (uint32_t i = 0; i < tailstormK - 1; ++i)
    {
        const auto parents =
            previousNodes.empty() ? std::vector<CTreeNodeRef>{} : std::vector<CTreeNodeRef>{previousNodes.back()};
        ConstCBlockRef block = makeSubblock(*previousRoot, parents, 170 + i);
        AcceptSubblock(block);
        std::vector<CTreeNodeRef> dag;
        BOOST_REQUIRE(tailstormForest.GetFullDagFor(previousRoot->GetBlockHash(), dag));
        previousNodes.push_back(FindTestNode(dag, block->GetHash()));
        BOOST_REQUIRE(previousNodes.back());
    }
    ConstCBlockRef lateUncle = makeSubblock(*previousRoot, {previousNodes.back()}, 180);
    ConstCBlockRef rootBlock = makeSummary(*previousRoot, previousNodes, 181);
    CValidationState rootState;
    const bool rootAccepted =
        ProcessSummaryBlock(rootState, Params(), nullptr, rootBlock, true, nullptr, SINGLE_THREADED);
    BOOST_REQUIRE_MESSAGE(rootAccepted, rootState.GetLogString());
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == rootBlock->GetHash());
    CBlockIndex *rootIndex = chainActive.Tip();

    // Leave one summary proof for an uncle that is still absent locally.
    std::vector<CTreeNodeRef> summaryNodes;
    CTreeNodeRef uncleNode = MakeTreeNodeRef(lateUncle);
    uncleNode->fUncle = true;
    summaryNodes.push_back(uncleNode);
    for (uint32_t i = 0; i < tailstormK - 2; ++i)
    {
        ConstCBlockRef block = makeSubblock(*rootIndex, {}, 190 + i);
        AcceptSubblock(block);
    }
    std::vector<CTreeNodeRef> currentNodes;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(rootBlock->GetHash(), currentNodes));
    summaryNodes.insert(summaryNodes.end(), currentNodes.begin(), currentNodes.end());
    ConstCBlockRef summary = makeSummary(*rootIndex, summaryNodes, 200);
    // Store S through normal validation; its missing uncle must leave it queued.
    CValidationState summaryState;
    ProcessSummaryBlock(summaryState, Params(), nullptr, summary, true, nullptr, SINGLE_THREADED);
    BOOST_REQUIRE_MESSAGE(summaryState.IsValid(), summaryState.GetLogString());
    BOOST_REQUIRE_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 1);
    BOOST_REQUIRE(chainActive.Tip() == rootIndex);
    CBlockIndex *summaryIndex = LookupBlockIndex(summary->GetHash());
    BOOST_REQUIRE(summaryIndex);
    AcceptSubblock(makeSubblock(*summaryIndex, {}, 210));
    CTailstormGroveRef descendantGrove;
    BOOST_REQUIRE(tailstormForest.GetGrove(summary->GetHash(), descendantGrove));

    CTailstormGroveRef rootGrove;
    BOOST_REQUIRE(tailstormForest.GetGrove(rootBlock->GetHash(), rootGrove));
    std::vector<CTreeNodeRef> currentDag;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(rootBlock->GetHash(), currentDag));
    BOOST_REQUIRE_EQUAL(currentDag.size(), tailstormK - 2);
    std::vector<CTreeNodeRef> committed;
    BOOST_REQUIRE(!tailstormForest.GetDagForBlock(summary, committed));
    tailstormForest.setSanityCheck(1.0);
    tailstormForest.Check();

    // This updates the previous grove, not the cached uncle set of the current one.
    AcceptSubblock(lateUncle);

    BOOST_CHECK(tailstormForest.Contains(lateUncle->GetHash()));
    BOOST_CHECK_EQUAL(CTailstormForestTest::SummaryOrphanCount(tailstormForest), 0);
    BOOST_REQUIRE(tailstormForest.GetDagForBlock(summary, committed));
    BOOST_CHECK_EQUAL(committed.size(), tailstormK - 1);
    const CTreeNodeRef committedUncle = FindTestNode(committed, lateUncle->GetHash());
    BOOST_REQUIRE(committedUncle);
    BOOST_CHECK(committedUncle->fUncle);
    BOOST_CHECK(chainActive.Tip() == summaryIndex);
    {
        READLOCK(cs_mapBlockIndex);
        BOOST_CHECK(summaryIndex->IsValid(BLOCK_VALID_SCRIPTS));
    }
}

BOOST_AUTO_TEST_CASE(unprocessed_ancestor_parks_child_during_reorg_gap)
{
    // An arrival is applied on its own only if every other subblock is processed exactly when it is
    // within the cutoff. Here the parent is within it but unprocessed, so the child is not applied:
    // the tree regenerates instead (a no-op here, as there is no grove to regenerate).
    CBlockIndex summaryRoot;
    summaryRoot.SetBlockHeader(std::make_shared<CBlockHeader>());
    summaryRoot.SetBlockHeaderHeight(0);
    const uint256 summaryRootHash = MakeTestTreeNode(99)->hash;
    summaryRoot.phashBlock = &summaryRootHash;
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

// Requests received while a pass is waiting for the protected state are covered by that pass. The
// request flag must remain pending until the pass acquires the state locks and takes its snapshot.
BOOST_AUTO_TEST_CASE(checkforreorg_consumes_request_at_state_snapshot)
{
    fTailstormEnabled.store(true);

    bool fHolderOwnsReorgLock = false;
    std::thread holder;
    {
        // Hold cs_main so the holder thread blocks inside its first pass while owning cs_reorg.
        LOCK(cs_main);

        CTailstormForestTest::SetRecheckPending(tailstormForest, true);
        holder = std::thread([] { tailstormForest.CheckForReorg(); });

        // Probe cs_reorg without holding cs_main in the probing thread. Once the probe fails, the
        // holder owns cs_reorg and is blocked waiting for the state lock held above.
        std::thread probe([&fHolderOwnsReorgLock] {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (std::chrono::steady_clock::now() < deadline)
            {
                {
                    TRY_LOCK(tailstormForest.cs_reorg, probeLock);
                    if (!probeLock)
                    {
                        fHolderOwnsReorgLock = true;
                        return;
                    }
                }
                MilliSleep(1);
            }
        });
        probe.join();

        // The pass has not observed the protected state yet, so neither the original nor this
        // concurrent request should have been consumed.
        BOOST_CHECK(fHolderOwnsReorgLock);
        BOOST_CHECK(CTailstormForestTest::RecheckPending(tailstormForest));
        if (fHolderOwnsReorgLock)
        {
            tailstormForest.CheckForReorg();
            BOOST_CHECK(CTailstormForestTest::RecheckPending(tailstormForest));
        }
    }
    holder.join();

    // The pass consumed the coalesced requests immediately before taking its state snapshot.
    BOOST_CHECK(!CTailstormForestTest::RecheckPending(tailstormForest));
    fTailstormEnabled.store(false);
}

BOOST_AUTO_TEST_CASE(renumber_dag_orders_by_dependency_score_hash)
{
    // RenumberDag numbers a dag 1..N by dependency (parents before children), then higher score,
    // then lower hash, whatever ids the subblocks held before.
    LOCK(tailstormForest.cs_forest);

    TestTailstormTree tree;

    // Two base subblocks with no children score the same, so the lower hash goes first. Give
    // the higher-hash one a child: its score rises above the other's, and the child (whose
    // score counts its parent) also outranks the childless base subblock.
    CTreeNodeRef nodeA = MakeTestTreeNode(1);
    CTreeNodeRef nodeB = MakeTestTreeNode(2);
    if (nodeA->hash < nodeB->hash)
        std::swap(nodeA, nodeB);
    BOOST_REQUIRE(nodeB->hash < nodeA->hash);
    nodeA->dagHeight = 1;
    nodeB->dagHeight = 1;

    // Gapped and out of order ids, as a removal or an arrival leaves them.
    nodeA->nSequenceId = 5;
    nodeB->nSequenceId = 2;
    tree.AddNode(nodeA);
    tree.AddNode(nodeB);
    tailstormForest.RenumberDag(tree);
    BOOST_CHECK_EQUAL(nodeB->nSequenceId, 1);
    BOOST_CHECK_EQUAL(nodeA->nSequenceId, 2);

    CTreeNodeRef child = MakeTestTreeNode(3);
    LinkTestTreeNodes(nodeA, child);
    tree.AddNode(child);
    tailstormForest.RenumberDag(tree);
    BOOST_CHECK_EQUAL(nodeA->nSequenceId, 1);
    BOOST_CHECK_EQUAL(child->nSequenceId, 2);
    BOOST_CHECK_EQUAL(nodeB->nSequenceId, 3);

    const std::vector<CTreeNodeRef> sorted = tree.SortedDag();
    BOOST_REQUIRE_EQUAL(sorted.size(), 3);
    BOOST_CHECK(sorted[0] == nodeA);
    BOOST_CHECK(sorted[1] == child);
    BOOST_CHECK(sorted[2] == nodeB);

    // Renumbering an unchanged dag leaves every id where it is.
    tailstormForest.RenumberDag(tree);
    BOOST_CHECK_EQUAL(nodeA->nSequenceId, 1);
    BOOST_CHECK_EQUAL(child->nSequenceId, 2);
    BOOST_CHECK_EQUAL(nodeB->nSequenceId, 3);
}

BOOST_AUTO_TEST_CASE(renumber_dag_ranks_by_descendant_score)
{
    // A subblock with several parents scores high while each parent scores low. Ranking a parent by the
    // highest score among it and its descendants places the parents, and so the child, ahead of an
    // unrelated chain whose scores fall between theirs.
    LOCK(tailstormForest.cs_forest);

    TestTailstormTree tree;

    // P1, P2, P3 (score 2 each) are the parents of C (score 4).
    std::vector<CTreeNodeRef> parents;
    CTreeNodeRef child = MakeTestTreeNode(10);
    for (unsigned char nonce = 1; nonce <= 3; nonce++)
    {
        CTreeNodeRef parent = MakeTestTreeNode(nonce);
        parent->dagHeight = 1;
        LinkTestTreeNodes(parent, child);
        parents.push_back(parent);
        tree.AddNode(parent);
    }
    tree.AddNode(child);

    // Q -> Q1 -> Q2 all score 3.
    CTreeNodeRef nodeQ = MakeTestTreeNode(20);
    CTreeNodeRef nodeQ1 = MakeTestTreeNode(21);
    CTreeNodeRef nodeQ2 = MakeTestTreeNode(22);
    nodeQ->dagHeight = 1;
    LinkTestTreeNodes(nodeQ, nodeQ1);
    LinkTestTreeNodes(nodeQ1, nodeQ2);
    tree.AddNode(nodeQ);
    tree.AddNode(nodeQ1);
    tree.AddNode(nodeQ2);

    std::vector<CTreeNodeRef> all = parents;
    all.insert(all.end(), {child, nodeQ, nodeQ1, nodeQ2});
    const auto scores = GetDagScores(all);
    BOOST_REQUIRE_EQUAL(scores.at(parents[0]), 2);
    BOOST_REQUIRE_EQUAL(scores.at(child), 4);
    BOOST_REQUIRE_EQUAL(scores.at(nodeQ), 3);

    tailstormForest.RenumberDag(tree);

    for (const auto &parent : parents)
        BOOST_CHECK(parent->nSequenceId < child->nSequenceId);
    BOOST_CHECK_EQUAL(child->nSequenceId, 4);
    BOOST_CHECK_EQUAL(nodeQ->nSequenceId, 5);
    BOOST_CHECK_EQUAL(nodeQ1->nSequenceId, 6);
    BOOST_CHECK_EQUAL(nodeQ2->nSequenceId, 7);

    for (const auto &node : all)
    {
        node->setAncestors.clear();
        node->setDescendants.clear();
    }
}

BOOST_AUTO_TEST_SUITE_END()
