// Copyright (c) 2018-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation/dag.h"

#include "blockstorage/blockcache.h"
#include "coins.h"
#include "daa.h"
#include "main.h"
#include "pow.h"
#include "test/test_nexa.h"
#include "txadmission.h"
#include "validation/tailstorm.h"

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <thread>

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

    static bool RecheckPending(CTailstormForest &forest) { return forest.fRecheckReorg; }

    static bool HasDagTx(const CTailstormTree &tree, const uint256 &txid) { return tree.mapDagTxns.count(txid) != 0; }

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
    static void MarkSubblockBad(CTailstormTree &tree, const uint256 &hash) { tree.setBadSubblocks.insert(hash); }

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
    void IndexMissing(const CTransactionRef &tx, const uint256 &subblock) { missingInputs.Add(tx, subblock); }
    std::vector<std::pair<CTransactionRef, std::set<uint256> > > TakeWaiting(const COutPoint &outpoint)
    {
        return missingInputs.RemoveFor(outpoint);
    }
    void Retry(const CTransactionRef &tx, CCoinsViewCache &coins)
    {
        ConnectDependentTxs(tx, coins, {});
    }
    const std::set<uint256> &BadSubblocks() const { return setBadSubblocks; }
    bool HasDagTx(const uint256 &txid) const { return mapDagTxns.count(txid) != 0; }
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
    const std::set<CTreeNodeRef> &parents,
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

CTreeNodeRef FindTestNode(const std::set<CTreeNodeRef> &dag, const uint256 &hash)
{
    auto iter =
        std::find_if(dag.begin(), dag.end(), [&hash](const CTreeNodeRef &node) { return node->hash == hash; });
    return iter == dag.end() ? CTreeNodeRef{} : *iter;
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
    const std::set<CTreeNodeRef> dag{scoreWinner, scoreLoser, child};
    const auto scores = GetDagScores(dag);
    BOOST_REQUIRE(scoreWinner->hash > scoreLoser->hash);
    BOOST_REQUIRE(scores.at(scoreWinner) > scores.at(scoreLoser));

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(scoreWinner, true));
    BOOST_CHECK(!registry.ScanSpends(scoreLoser, true));
    BOOST_REQUIRE_EQUAL(registry.GroupCount(), 1);
    std::set<uint256> losers;
    const std::set<uint256> exclusions = GetTxnExclusionSet(dag, registry, nullptr, &losers);

    BOOST_CHECK_EQUAL(losers.count(winnerTx->GetId()), 0);
    BOOST_CHECK_EQUAL(losers.count(loserTx->GetId()), 1);
    BOOST_CHECK_EQUAL(exclusions.count(winnerTx->GetId()), 0);
    BOOST_CHECK_EQUAL(exclusions.count(loserTx->GetId()), 1);
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
    const std::set<CTreeNodeRef> dag{nodeA, nodeB};
    const auto scores = GetDagScores(dag);
    BOOST_REQUIRE_EQUAL(scores.at(nodeA), scores.at(nodeB));

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(winner, true));
    BOOST_CHECK(!registry.ScanSpends(loser, true));
    BOOST_REQUIRE_EQUAL(registry.GroupCount(), 1);
    std::set<uint256> losers;
    const std::set<uint256> exclusions = GetTxnExclusionSet(dag, registry, nullptr, &losers);

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
    const std::set<CTreeNodeRef> dag{repeatedTxNodeA, repeatedTxNodeB, repeatedTxChild, repeatedTxGrandchild,
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
        BOOST_REQUIRE_EQUAL(registry.GroupCount(), 1);
        std::set<uint256> losers;
        const std::set<uint256> exclusions = GetTxnExclusionSet(dag, registry, nullptr, &losers);

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
    const std::set<CTreeNodeRef> dag{nodeWin, nodeLose, nodeWinChild, nodeLoseChild};
    const auto scores = GetDagScores(dag);
    BOOST_REQUIRE(scores.at(nodeWin) > scores.at(nodeLose));

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(nodeWin, true));
    BOOST_CHECK(!registry.ScanSpends(nodeLose, true));
    BOOST_CHECK(!registry.ScanSpends(nodeWinChild, true));
    BOOST_CHECK(!registry.ScanSpends(nodeLoseChild, true));
    BOOST_REQUIRE_EQUAL(registry.GroupCount(), 1);
    std::set<uint256> losers;
    const std::set<uint256> exclusions = GetTxnExclusionSet(dag, registry, nullptr, &losers);

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
    const std::set<CTreeNodeRef> dag{nodeParent, nodeChild};

    LOCK(tailstormForest.cs_forest);
    CDagConflictRegistry registry;
    BOOST_CHECK(!registry.ScanSpends(nodeParent, true));
    BOOST_CHECK(!registry.ScanSpends(nodeChild, true));
    BOOST_REQUIRE_EQUAL(registry.GroupCount(), 0);
    std::set<uint256> losers;
    const std::set<uint256> exclusions = GetTxnExclusionSet(dag, registry, nullptr, &losers);

    BOOST_CHECK(losers.empty());
    BOOST_CHECK(exclusions.empty());
}

BOOST_AUTO_TEST_CASE(retry_verdict_marks_subblocks_bad)
{
    // A transaction omitted at insert for a missing input is validated when that input is
    // applied. An invalid one marks every subblock containing it for removal and leaves the
    // index; a valid one is applied; one still short of another input goes back on the index
    // under its subblock.
    PreviousEpochTestChain chain(&coinsCache, 60, 61);
    TestTailstormTree tree;
    tree.SetSummaryRoot(&chain.previousSummary);
    tree.SetSummaryRootCoins(&coinsCache);
    CCoinsViewCache tcoins(&coinsCache);
    const int height = chain.previousSummary.height() + 1;

    // The parent creates three outputs. A bare script that OP_0 satisfies keeps the valid
    // spend free of signatures.
    const CScript spendable = CScript() << 2 << OP_ADD << 0 << OP_GREATERTHAN;
    CMutableTransaction parent;
    parent.vin.emplace_back(COutPoint(MakeTestTreeNode(62)->hash, 0), 3000);
    for (int i = 0; i < 3; i++)
        parent.vout.emplace_back(1000, spendable);
    const CTransactionRef parentTx = MakeTransactionRef(parent);
    AddCoins(tcoins, *parentTx, height);

    auto makeChild = [&](unsigned int parentOutput, CAmount claimed, unsigned char tag, bool extraInput)
    {
        CMutableTransaction tx;
        tx.vin.emplace_back(parentTx->OutpointAt(parentOutput), claimed);
        tx.vin.back().scriptSig = CScript() << OP_0;
        if (extraInput)
            tx.vin.emplace_back(COutPoint(MakeTestTreeNode(tag)->hash, 0), 1);
        tx.vout.emplace_back(500, CScript() << OP_RETURN << tag);
        return MakeTransactionRef(tx);
    };
    // Claims more than the output holds: input-amount-mismatch, REJECT_INVALID.
    const CTransactionRef invalidTx = makeChild(0, 1001, 70, false);
    const CTransactionRef validTx = makeChild(1, 1000, 71, false);
    const CTransactionRef waitingTx = makeChild(2, 1000, 72, true);

    const uint256 subblockA = MakeTestTreeNode(63)->hash;
    const uint256 subblockB = MakeTestTreeNode(64)->hash;

    LOCK(tailstormForest.cs_forest);
    tree.IndexMissing(invalidTx, subblockA);
    tree.IndexMissing(invalidTx, subblockB);
    tree.IndexMissing(validTx, subblockA);
    tree.IndexMissing(waitingTx, subblockB);

    tree.Retry(parentTx, tcoins);

    // Invalid: both subblocks marked, not applied, not re-indexed, output untouched.
    BOOST_CHECK_EQUAL(tree.BadSubblocks().size(), 2);
    BOOST_CHECK_EQUAL(tree.BadSubblocks().count(subblockA), 1);
    BOOST_CHECK_EQUAL(tree.BadSubblocks().count(subblockB), 1);
    BOOST_CHECK(!tree.HasDagTx(invalidTx->GetId()));
    BOOST_CHECK(tcoins.HaveCoin(parentTx->OutpointAt(0)));
    BOOST_CHECK(tree.TakeWaiting(parentTx->OutpointAt(0)).empty());

    // Valid: applied.
    BOOST_CHECK(tree.HasDagTx(validTx->GetId()));
    BOOST_CHECK(!tcoins.HaveCoin(parentTx->OutpointAt(1)));

    // Waiting: back on the index under its subblock, nothing applied.
    BOOST_CHECK(!tree.HasDagTx(waitingTx->GetId()));
    BOOST_CHECK(tcoins.HaveCoin(parentTx->OutpointAt(2)));
    const auto waiting = tree.TakeWaiting(parentTx->OutpointAt(2));
    BOOST_REQUIRE_EQUAL(waiting.size(), 1);
    BOOST_CHECK(waiting[0].first->GetId() == waitingTx->GetId());
    BOOST_CHECK_EQUAL(waiting[0].second.count(subblockB), 1);
}

BOOST_AUTO_TEST_CASE(regeneration_renumbers_after_bad_subblock_removal)
{
    // k+1 subblocks against k-1 slots: the first k-1 are processed, the last two are held past
    // the cap. Removing a bad subblock at regeneration must leave the remaining sequence ids
    // dense across processed and held nodes alike, which Check() asserts.
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

    std::set<CTreeNodeRef> bestDag;
    CTailstormTreeRef tree;
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(chain.previousHash, bestDag, &tree));
    BOOST_REQUIRE(tree);
    BOOST_REQUIRE_EQUAL(bestDag.size(), tailstormK - 1);
    std::set<CTreeNodeRef> fullDag;
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(chain.previousHash, fullDag));
    BOOST_REQUIRE_EQUAL(fullDag.size(), tailstormK + 1);

    CTailstormGroveRef grove;
    BOOST_REQUIRE(tailstormForest.GetGrove(subblocks[0]->GetHash(), grove));
    CTailstormForestTest::MarkSubblockBad(*tree, subblocks[0]->GetHash());
    {
        LOCK(tailstormForest.cs_forest);
        TxAdmissionPause pause;
        tailstormForest.ReGenerateDagData(grove);
    }

    fullDag.clear();
    BOOST_REQUIRE(tailstormForest.GetFullDagFor(chain.previousHash, fullDag));
    BOOST_CHECK_EQUAL(fullDag.size(), tailstormK);
    BOOST_CHECK(!FindTestNode(fullDag, subblocks[0]->GetHash()));

    std::vector<CTreeNodeRef> bySequence(fullDag.begin(), fullDag.end());
    std::sort(bySequence.begin(), bySequence.end(),
        [](const CTreeNodeRef &a, const CTreeNodeRef &b) { return a->nSequenceId < b->nSequenceId; });
    for (size_t i = 0; i < bySequence.size(); ++i)
    {
        BOOST_CHECK_EQUAL(bySequence[i]->nSequenceId, i + 1);
        BOOST_CHECK_EQUAL(bySequence[i]->fProcessed, i < tailstormK - 1);
    }
    // Arrival order is kept: the node that was held past the cap is now the last processed one.
    BOOST_CHECK(bySequence[tailstormK - 2]->hash == subblocks[tailstormK - 1]->GetHash());

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
    // is applied and a pool child C of L is admissible. A late previous-epoch subblock then
    // becomes an uncle. Uncles take the summary slots first, so the losing-side subblock leaves
    // the selection: at the next regeneration its rival W is the only spender present, no loser is
    // recorded, and W is applied. L cannot be applied while W spends its input, so C has lost its
    // input and must leave the pool.
    const uint32_t tailstormK = Params().GetConsensus().tailstorm_k;
    BOOST_REQUIRE_EQUAL(tailstormK, 4u);
    PreviousEpochTestChain chain(&coinsCache, 30, 31);
    mempool.clear();

    // Previous epoch: k-1 committed subblocks and a late child of one of them.
    std::vector<ConstCBlockRef> existingSubblocks;
    std::set<CTreeNodeRef> summarySubblocks;
    for (uint32_t i = 0; i < tailstormK - 2; ++i)
    {
        ConstCBlockRef subblock = MakeTestSubblock(chain.previousSummary, {}, static_cast<unsigned char>(40 + i));
        existingSubblocks.push_back(subblock);
        summarySubblocks.insert(MakeTreeNodeRef(subblock));
    }
    ConstCBlockRef parent = MakeTestSubblock(chain.previousSummary, {}, 60);
    CTreeNodeRef parentNode = MakeTreeNodeRef(parent);
    summarySubblocks.insert(parentNode);
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

    // Current epoch, in arrival order: F, then B_W, then B_L with the lower hash so L wins.
    const ConstCBlockRef blockF = MakeTestSubblock(currentSummary, {}, 70);
    const ConstCBlockRef blockW = MakeTestSubblock(currentSummary, {}, 71, {txW});
    const ConstCBlockRef blockL = MakeLowerHashSubblock(currentSummary, blockW, {txL});
    BOOST_REQUIRE(tailstormForest.Insert(blockF));
    BOOST_REQUIRE(tailstormForest.Insert(blockW));
    BOOST_REQUIRE(tailstormForest.Insert(blockL));

    std::set<CTreeNodeRef> bestDag;
    CTailstormTreeRef tree;
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(currentHash, bestDag, &tree));
    BOOST_REQUIRE(tree);
    BOOST_REQUIRE(CTailstormForestTest::HasDagTx(*tree, txL->GetId()));
    BOOST_REQUIRE(!CTailstormForestTest::HasDagTx(*tree, txW->GetId()));

    // C spends L's output and is pooled while L is applied.
    const CTransactionRef txC = spend(txL->OutpointAt(0), txL->vout[0].nValue, 100);
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(entry.Height(height).FromTx(*txC));
    BOOST_REQUIRE(mempool.exists(txC->GetId()));

    // The late child links into the previous epoch and, at the next insert into this grove, is
    // adopted as an uncle. It takes a slot ahead of the regular subblocks and B_L is displaced.
    {
        LOCK(tailstormForest.cs_forest);
        const std::set<uint256> linked = tailstormForest.ProcessOrphans();
        BOOST_REQUIRE_EQUAL(linked.count(lateChild->GetHash()), 1u);
    }
    BOOST_REQUIRE(tailstormForest.Insert(MakeTestSubblock(currentSummary, {}, 72)));
    bestDag.clear();
    BOOST_REQUIRE(tailstormForest.GetBestDagFor(currentHash, bestDag));
    BOOST_REQUIRE(FindTestNode(bestDag, lateChild->GetHash()));
    BOOST_REQUIRE(!FindTestNode(bestDag, blockL->GetHash()));
    BOOST_REQUIRE(FindTestNode(bestDag, blockW->GetHash()));

    // Adoption alone leaves the view as it was. The rebuild that a later event triggers is what
    // applies W and drops L; force it here.
    CTailstormGroveRef grove;
    BOOST_REQUIRE(tailstormForest.GetGrove(blockF->GetHash(), grove));
    {
        LOCK(tailstormForest.cs_forest);
        TxAdmissionPause pause;
        tailstormForest.ReGenerateDagData(grove);
    }
    BOOST_CHECK(CTailstormForestTest::HasDagTx(*tree, txW->GetId()));
    BOOST_CHECK(!CTailstormForestTest::HasDagTx(*tree, txL->GetId()));
    BOOST_CHECK(!mempool.exists(txC->GetId()));
    mempool.clear();
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
    std::set<CTreeNodeRef> summarySubblockNodes;
    for (uint32_t i = 0; i < tailstormK - 1; ++i)
    {
        ConstCBlockRef subblock =
            MakeTestSubblock(chain.previousSummary, {}, static_cast<unsigned char>(90 + i));
        summarySubblocks.push_back(subblock);
        summarySubblockNodes.insert(MakeTreeNodeRef(subblock));
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

BOOST_AUTO_TEST_CASE(renumber_dag_closes_sequence_id_gaps)
{
    // RemoveFromGrove takes a subblock out of the dag but leaves its nSequenceId behind as a
    // hole, and Check() asserts every dag is numbered 1..N with nothing missing. Fill a dag
    // with gapped ids and check RenumberDag closes the holes without reordering the subblocks.
    LOCK(tailstormForest.cs_forest);

    TestTailstormTree tree;

    // Two gaps: one where the subblocks numbered 3 and 4 were removed, one where 7 and 8 were.
    const std::vector<uint32_t> vGappedIds = {1, 2, 5, 6, 9};
    std::vector<CTreeNodeRef> vNodesInArrivalOrder;
    unsigned char nonce = 1;
    for (const uint32_t nSequenceId : vGappedIds)
    {
        CTreeNodeRef node = MakeTestTreeNode(nonce++);
        node->nSequenceId = nSequenceId;
        tree.AddNode(node);
        vNodesInArrivalOrder.push_back(node);
    }
    BOOST_REQUIRE_EQUAL(tree.Size(), vGappedIds.size());

    tailstormForest.RenumberDag(tree);

    // The ids are contiguous again, and each subblock holds its place in the arrival order
    // that the old ids recorded.
    for (size_t i = 0; i < vNodesInArrivalOrder.size(); i++)
    {
        BOOST_CHECK_EQUAL(vNodesInArrivalOrder[i]->nSequenceId, static_cast<uint32_t>(i + 1));
    }

    // Renumbering a dag that has no gaps leaves every id where it is.
    tailstormForest.RenumberDag(tree);
    for (size_t i = 0; i < vNodesInArrivalOrder.size(); i++)
    {
        BOOST_CHECK_EQUAL(vNodesInArrivalOrder[i]->nSequenceId, static_cast<uint32_t>(i + 1));
    }
}

BOOST_AUTO_TEST_SUITE_END()
