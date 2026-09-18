// Copyright (c) 2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/* Tailstorm read-only (RO) input tests.
 
  Block validation runs a "read only, then outputs, then inputs" algorithm (see
  ConnectBlockCanonicalOrdering()):
 
    1. every RO input of the block must resolve to an unspent coin,
    2. then every output of every transaction in the block is added to the coins view,
    3. then the consumed (non RO) inputs are checked and finally spent.
 
  Because step 1 runs before step 3, an output that this block spends may still be referenced
  as a RO input by this block.  But because step 1 also runs before step 2, an output that this
  block creates may NOT be referenced as a RO input by this block.
 
  Tailstorm makes both of those rules harder to honour, because a summary block is validated
  flat while its subblocks are validated one at a time, each layered onto the coins view left
  behind by the previous one (CTailstormTree::Insert() and
  CTailstormForest::ReGenerateDagDataForSubblocks() both call ConnectBlockCanonicalOrdering()
  with the DAG's running view).  Resolving RO inputs against that running view would make the
  DAG disagree with the summary block in both directions:
 
    - it would let a subblock read an output an earlier subblock CREATED, building an epoch
      whose summary block can never validate, and
    - it would stop a subblock reading an output an earlier subblock SPENT, even though the
      summary block accepts exactly that.
 
  So RO inputs are resolved against pcoinsTip -- the UTXO set as of the last summary block, and
  the epoch's starting point -- which makes a subblock enforce the same rule the summary block
  will.  These tests pin both directions down, at the subblock level and at the summary block
  level.
 */

#include "chainparams.h"
#include "consensus/validation.h"
#include "daa.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/sighashtype.h"
#include "test/test_nexa.h"
#include "validation/dag.h"
#include "validation/tailstorm.h"
#include "validation/validation.h"

#include <boost/test/unit_test.hpp>

namespace
{
/* Run the block through the shared block connection code, exactly as the tailstorm DAG does
   for a subblock and as ConnectBlock() does for a summary block.  Returns false and fills in
   state if the block does not connect to the passed coins view.
 */
bool ConnectForTest(const ConstCBlockRef &pblock,
    CBlockIndex *pindex,
    CCoinsViewCache &view,
    CValidationState &state,
    const std::map<uint256, CTransactionRef> *mapDagTxns = nullptr)
{
    CAmount nFees = 0;
    CBlockUndo blockundo;
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    std::map<CGroupTokenID, CAmount> accumulatedMintages;
    std::map<CGroupTokenID, CAuth> accumulatedAuthorities;

    return ConnectBlockCanonicalOrdering(pblock, state, pindex, view, *pcoinsTip, Params(), false /* fJustCheck */,
        SINGLE_THREADED, true /* fScriptChecks */, nFees, blockundo, vPos, accumulatedMintages,
        accumulatedAuthorities, mapDagTxns, nullptr);
}

/* Assemble a block on top of pindexPrev holding the passed transactions in canonical (LTOR)
   order.  minerData decides what kind of block this is: version 1 miner data makes it a
   subblock, version 2 makes it a tailstorm summary block.
 */
CBlockRef MakeTestBlock(const CBlockIndex *pindexPrev,
    const std::vector<CMutableTransaction> &txns,
    const uint8_t tag,
    const std::vector<uint8_t> &minerData)
{
    CBlockRef pblock = MakeBlockRef();
    pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    pblock->height = pindexPrev->height() + 1;
    pblock->nTime = pindexPrev->GetBlockTime() + 1;
    pblock->nBits = GetNextWorkRequired(pindexPrev, pblock.get(), Params().GetConsensus());
    pblock->chainWork = ArithToUint256(pindexPrev->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
    pblock->minerData = minerData;
    pblock->nonce = {tag};

    // Every block needs its own coinbase, and they must not be identical or the coins view
    // will reject the second one as a repeated transaction.  The tag makes them unique.
    CMutableTransaction coinbase;
    coinbase.vout.emplace_back(0, CScript() << OP_RETURN << (uint64_t)tag);
    pblock->vtx.push_back(MakeTransactionRef(coinbase));

    for (const CMutableTransaction &tx : txns)
    {
        pblock->vtx.push_back(MakeTransactionRef(tx));
    }
    std::sort(pblock->vtx.begin() + 1, pblock->vtx.end(), NumericallyLessTxHashComparator());

    pblock->UpdateHeader();
    return pblock;
}

/* Make the miner data that marks a block as a subblock referencing the passed parents. */
std::vector<uint8_t> SubblockMinerData(const std::set<CTreeNodeRef> &parents)
{
    return GenerateMinerData(Params().GetConsensus().tailstorm_k, parents, uint256());
}

/* Make the miner data that marks a block as the tailstorm summary block of the passed dag. */
std::vector<uint8_t> SummaryMinerData(const std::set<CTreeNodeRef> &dag, const CBlockIndex *pindexPrev)
{
    return GenerateMinerData(Params().GetConsensus().tailstorm_k, dag, pindexPrev->pprev->GetBlockHash());
}

/** Add every non coinbase transaction of the subblock to the DAG's transaction map, the way
    the DAG does after a subblock successfully connects.
 */
void RecordDagTxns(const ConstCBlockRef &subblock, std::map<uint256, CTransactionRef> &mapDagTxns)
{
    for (const CTransactionRef &ptx : subblock->vtx)
    {
        if (ptx->IsCoinBase())
            continue;
        mapDagTxns.emplace(ptx->GetId(), ptx);
    }
}

struct TailstormReadOnlySetup : public TestChain100Setup
{
    // The fixture leaves the tip at the coinbase maturity height, so only the very first coinbase
    // is spendable.  Mine a few more blocks so the tests have several mature coinbases to use.
    TailstormReadOnlySetup()
    {
        for (int i = 0; i < 10; i++)
        {
            std::vector<CMutableTransaction> noTxns;
            CBlock b = CreateAndProcessBlock(noTxns, coinbaseLockingScript);
            BOOST_CHECK(chainActive.Tip()->GetBlockHash() == b.GetHash());
        }
    }

    // A transaction that consumes coinbaseTxns[cbIdx] output 0.  If roPrevout is given, the
    // transaction also carries it as a read only input.  A transaction may not be made up
    //entirely of read only inputs, hence the consumed input in every case.
    CMutableTransaction MakeSpend(size_t cbIdx, const COutPoint *roPrevout = nullptr)
    {
        CMutableTransaction tx;
        tx.vin.resize(roPrevout ? 2 : 1);
        tx.vin[0] = coinbaseTxns[cbIdx].SpendOutput(0);
        if (roPrevout)
        {
            tx.vin[1] = CTxIn(*roPrevout, 0);
            tx.vin[1].SetReadOnly();
            tx.vin[1].nSequence = 0; // read only inputs must have a zero sequence
            tx.vin[1].amount = 0; // ... and a zero amount, they are not being spent
            tx.vin[1].scriptSig = CScript(); // ... and need no satisfier
        }
        tx.vout.resize(1);
        tx.vout[0] = CTxOut(coinbaseTxns[cbIdx].vout[0].nValue - 1000, coinbaseLockingScript);
        // Sign last: the signature commits to every input, read only ones included.
        tx.vin[0].scriptSig = SignCoinbaseSpend(tx, 0, defaultSigHashType, coinbaseTxns[cbIdx].vout[0].nValue);
        return tx;
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(tailstorm_readonly_tests, TailstormReadOnlySetup)

/* A read only input may not reference an output created earlier in the same epoch.  The
   subblock carrying it is rejected, because the summary block that would have to summarize it
   can never validate.
 */
BOOST_AUTO_TEST_CASE(readonly_input_created_in_epoch_is_rejected)
{
    LOCK(cs_main);
    CBlockIndex *pindexSummaryRoot = chainActive.Tip();

    // tx1 creates the output that will later be read.  It goes into subblock 1.
    CMutableTransaction tx1 = MakeSpend(0);
    // tx2 takes tx1's brand new output as a read only input.  It goes into subblock 2.
    const COutPoint roPrevout = tx1.OutpointAt(0);
    CMutableTransaction tx2 = MakeSpend(1, &roPrevout);

    // Build the epoch: tailstorm_k - 1 subblocks, whose transactions are then summarized by the
    // summary block (which counts as the final subblock of the epoch).
    CBlockRef subblock1 = MakeTestBlock(pindexSummaryRoot, {tx1}, 1, SubblockMinerData({}));
    CTreeNodeRef node1 = MakeTreeNodeRef(ConstCBlockRef(subblock1));

    CBlockRef subblock2 = MakeTestBlock(pindexSummaryRoot, {tx2}, 2, SubblockMinerData({node1}));
    CTreeNodeRef node2 = MakeTreeNodeRef(ConstCBlockRef(subblock2));

    CBlockRef subblock3 = MakeTestBlock(pindexSummaryRoot, {}, 3, SubblockMinerData({node2}));
    CTreeNodeRef node3 = MakeTreeNodeRef(ConstCBlockRef(subblock3));

    BOOST_CHECK(subblock1->IsSubblock());
    BOOST_CHECK(subblock2->IsSubblock());
    BOOST_CHECK(subblock3->IsSubblock());

    // Subblocks: each one connects onto the view left by the previous one.
    // This mirrors CTailstormForest::ReGenerateDagDataForSubblocks(): one coins view for the
    // whole DAG, subblocks layered into it one at a time, and a growing map of transactions
    // that are already in the DAG.
    CCoinsViewCache dagView(pcoinsTip);
    std::map<uint256, CTransactionRef> mapDagTxns;

    CValidationState state1;
    BOOST_CHECK_MESSAGE(ConnectForTest(subblock1, pindexSummaryRoot, dagView, state1, &mapDagTxns),
        "subblock 1 did not connect: " << state1.GetLogString());
    RecordDagTxns(subblock1, mapDagTxns);

    // tx1's output is now in the DAG's running view -- but not in pcoinsTip, which is where read
    // only inputs are resolved -- so subblock 2 is rejected.
    BOOST_CHECK(dagView.HaveCoin(roPrevout));
    BOOST_CHECK(!pcoinsTip->HaveCoin(roPrevout));

    CValidationState state2;
    BOOST_CHECK(!ConnectForTest(subblock2, pindexSummaryRoot, dagView, state2, &mapDagTxns));
    BOOST_CHECK_EQUAL(state2.GetRejectReason(), "bad-txns-read-only-input-created-in-epoch");

    // The read only pre-check is not part of the XVal fast path, so a subblock relayed as a
    // compact block whose transactions were all verified in the txpool is rejected just the same.
    subblock2->fXVal = true;
    CCoinsViewCache dagViewXVal(pcoinsTip);
    std::map<uint256, CTransactionRef> mapDagTxnsXVal;
    CValidationState stateX1;
    BOOST_CHECK(ConnectForTest(subblock1, pindexSummaryRoot, dagViewXVal, stateX1, &mapDagTxnsXVal));
    RecordDagTxns(subblock1, mapDagTxnsXVal);
    CValidationState stateX2;
    BOOST_CHECK(!ConnectForTest(subblock2, pindexSummaryRoot, dagViewXVal, stateX2, &mapDagTxnsXVal));
    BOOST_CHECK_EQUAL(stateX2.GetRejectReason(), "bad-txns-read-only-input-created-in-epoch");

    // This is why the subblock has to be rejected:
    // Had the DAG accepted subblock 2, the epoch's summary block -- which carries the union of
    // the subblocks' transactions and is validated as one flat block -- could never validate.
    std::set<CTreeNodeRef> setBestDag = {node1, node2, node3};
    CBlockRef summaryBlock =
        MakeTestBlock(pindexSummaryRoot, {tx1, tx2}, 4, SummaryMinerData(setBestDag, pindexSummaryRoot));
    BOOST_CHECK(summaryBlock->IsTailstormSummaryBlock());
    BOOST_CHECK_EQUAL(summaryBlock->NumSubblocks(), Params().GetConsensus().tailstorm_k - 1);

    CBlockIndex indexSummary(*summaryBlock);
    indexSummary.pprev = pindexSummaryRoot;

    CCoinsViewCache summaryView(pcoinsTip);
    CValidationState stateSummary;
    BOOST_CHECK_MESSAGE(!ConnectForTest(summaryBlock, &indexSummary, summaryView, stateSummary),
        "summary block connected but tx2 reads an output created by tx1 in this block");
    BOOST_CHECK_EQUAL(stateSummary.GetRejectReason(), "bad-txns-read-only-inputs-missing-or-spent");
    BOOST_CHECK_EQUAL(stateSummary.GetRejectCode(), REJECT_CONFLICT);
}

/* The companion rule, at the summary block level: an output that already exists may be read by
   the very block that spends it, because read only inputs are checked before any input is
   consumed.  Only outputs *created* by the block are off limits.
 */
BOOST_AUTO_TEST_CASE(readonly_input_spent_by_same_summary_block_is_allowed)
{
    LOCK(cs_main);
    CBlockIndex *pindexSummaryRoot = chainActive.Tip();

    // tx3 spends a confirmed coinbase output; tx4 reads that same output.
    CMutableTransaction tx3 = MakeSpend(0);
    const COutPoint roPrevout = coinbaseTxns[0].OutpointAt(0);
    CMutableTransaction tx4 = MakeSpend(1, &roPrevout);
    BOOST_CHECK(tx3.vin[0].prevout == roPrevout);

    CBlockRef subblock1 = MakeTestBlock(pindexSummaryRoot, {tx3}, 1, SubblockMinerData({}));
    CTreeNodeRef node1 = MakeTreeNodeRef(ConstCBlockRef(subblock1));
    CBlockRef subblock2 = MakeTestBlock(pindexSummaryRoot, {tx4}, 2, SubblockMinerData({node1}));
    CTreeNodeRef node2 = MakeTreeNodeRef(ConstCBlockRef(subblock2));
    CBlockRef subblock3 = MakeTestBlock(pindexSummaryRoot, {}, 3, SubblockMinerData({node2}));
    CTreeNodeRef node3 = MakeTreeNodeRef(ConstCBlockRef(subblock3));

    std::set<CTreeNodeRef> setBestDag = {node1, node2, node3};
    CBlockRef summaryBlock =
        MakeTestBlock(pindexSummaryRoot, {tx3, tx4}, 4, SummaryMinerData(setBestDag, pindexSummaryRoot));

    CBlockIndex indexSummary(*summaryBlock);
    indexSummary.pprev = pindexSummaryRoot;

    CCoinsViewCache summaryView(pcoinsTip);
    CValidationState stateSummary;
    BOOST_CHECK_MESSAGE(ConnectForTest(summaryBlock, &indexSummary, summaryView, stateSummary),
        "summary block did not connect: " << stateSummary.GetLogString());
}

/* The same companion rule, at the subblock level: an output spent by an earlier subblock of the
   epoch may still be read by a later one.  The DAG has to allow this, because the summary block
   of that epoch does (see readonly_input_spent_by_same_summary_block_is_allowed) -- rejecting it
   in the DAG would stop honest miners from ever building the block.
 */
BOOST_AUTO_TEST_CASE(readonly_input_spent_by_earlier_subblock_is_allowed)
{
    LOCK(cs_main);
    CBlockIndex *pindexSummaryRoot = chainActive.Tip();

    CMutableTransaction tx5 = MakeSpend(0);
    const COutPoint roPrevout = coinbaseTxns[0].OutpointAt(0);
    CMutableTransaction tx6 = MakeSpend(1, &roPrevout);

    CBlockRef subblock1 = MakeTestBlock(pindexSummaryRoot, {tx5}, 1, SubblockMinerData({}));
    CTreeNodeRef node1 = MakeTreeNodeRef(ConstCBlockRef(subblock1));
    CBlockRef subblock2 = MakeTestBlock(pindexSummaryRoot, {tx6}, 2, SubblockMinerData({node1}));

    CCoinsViewCache dagView(pcoinsTip);
    std::map<uint256, CTransactionRef> mapDagTxns;

    CValidationState state1;
    BOOST_CHECK_MESSAGE(ConnectForTest(subblock1, pindexSummaryRoot, dagView, state1, &mapDagTxns),
        "subblock 1 did not connect: " << state1.GetLogString());
    RecordDagTxns(subblock1, mapDagTxns);

    // The DAG's running view now shows the coin as spent, but pcoinsTip -- the epoch's starting
    // UTXO set, and where read only inputs are resolved -- still has it.
    BOOST_CHECK(!dagView.HaveCoin(roPrevout));
    BOOST_CHECK(pcoinsTip->HaveCoin(roPrevout));

    CValidationState state2;
    BOOST_CHECK_MESSAGE(ConnectForTest(subblock2, pindexSummaryRoot, dagView, state2, &mapDagTxns),
        "subblock 2 did not connect: " << state2.GetLogString());
}

/* A read only input referencing an output that never existed is still rejected, and is still
   reported as a conflict rather than as an epoch violation.
 */
BOOST_AUTO_TEST_CASE(readonly_input_of_unknown_output_is_rejected)
{
    LOCK(cs_main);
    CBlockIndex *pindexSummaryRoot = chainActive.Tip();

    const COutPoint roPrevout(InsecureRand256(), 0);
    CMutableTransaction tx7 = MakeSpend(0, &roPrevout);

    CBlockRef subblock1 = MakeTestBlock(pindexSummaryRoot, {tx7}, 1, SubblockMinerData({}));

    CCoinsViewCache dagView(pcoinsTip);
    std::map<uint256, CTransactionRef> mapDagTxns;
    CValidationState state1;
    BOOST_CHECK(!ConnectForTest(subblock1, pindexSummaryRoot, dagView, state1, &mapDagTxns));
    BOOST_CHECK_EQUAL(state1.GetRejectReason(), "bad-txns-read-only-inputs-missing-or-spent");
    BOOST_CHECK_EQUAL(state1.GetRejectCode(), REJECT_CONFLICT);
}

/* The transactions in a subblock are ultimately confirmed by the summary block that closes the
   epoch, so the outputs they create must carry that summary block's height -- the epoch height,
   which is the DAG root's height plus one.  Getting this wrong makes the DAG's coins disagree
   with the very block that will confirm them, and makes an output created inside the epoch
   indistinguishable from one confirmed by the previous summary block.
 */
BOOST_AUTO_TEST_CASE(subblock_outputs_use_the_epoch_height)
{
    LOCK(cs_main);
    printf("subblock_outputs_use_the_epoch_height\n");
    CBlockIndex *pindexSummaryRoot = chainActive.Tip();
    const int64_t nEpochHeight = pindexSummaryRoot->height() + 1;

    CMutableTransaction tx1 = MakeSpend(0);
    const COutPoint created = tx1.OutpointAt(0);

    CBlockRef subblock1 = MakeTestBlock(pindexSummaryRoot, {tx1}, 1, SubblockMinerData({}));
    CTreeNodeRef node1 = MakeTreeNodeRef(ConstCBlockRef(subblock1));
    CBlockRef subblock2 = MakeTestBlock(pindexSummaryRoot, {}, 2, SubblockMinerData({node1}));
    CTreeNodeRef node2 = MakeTreeNodeRef(ConstCBlockRef(subblock2));
    CBlockRef subblock3 = MakeTestBlock(pindexSummaryRoot, {}, 3, SubblockMinerData({node2}));
    CTreeNodeRef node3 = MakeTreeNodeRef(ConstCBlockRef(subblock3));

    BOOST_CHECK_EQUAL((int64_t)subblock1->height, nEpochHeight);

    // Layer the subblock into the DAG's view the way CTailstormTree::Insert() does: the index it
    // is validated against is the summary block the epoch is being built on, not the subblock.
    CCoinsViewCache dagView(pcoinsTip);
    std::map<uint256, CTransactionRef> mapDagTxns;
    CValidationState state1;
    BOOST_CHECK_MESSAGE(ConnectForTest(subblock1, pindexSummaryRoot, dagView, state1, &mapDagTxns),
        "subblock 1 did not connect: " << state1.GetLogString());

    Coin dagCoin;
    BOOST_CHECK(dagView.GetCoin(created, dagCoin));
    BOOST_CHECK_EQUAL(dagCoin.height(), nEpochHeight);

    // The summary block that confirms the very same transaction must stamp it identically.
    std::set<CTreeNodeRef> setBestDag = {node1, node2, node3};
    CBlockRef summaryBlock =
        MakeTestBlock(pindexSummaryRoot, {tx1}, 4, SummaryMinerData(setBestDag, pindexSummaryRoot));
    BOOST_CHECK_EQUAL((int64_t)summaryBlock->height, nEpochHeight);

    CBlockIndex indexSummary(*summaryBlock);
    indexSummary.pprev = pindexSummaryRoot;

    CCoinsViewCache summaryView(pcoinsTip);
    CValidationState stateSummary;
    BOOST_CHECK_MESSAGE(ConnectForTest(summaryBlock, &indexSummary, summaryView, stateSummary),
        "summary block did not connect: " << stateSummary.GetLogString());

    Coin summaryCoin;
    BOOST_CHECK(summaryView.GetCoin(created, summaryCoin));
    BOOST_CHECK_EQUAL(summaryCoin.height(), nEpochHeight);
    BOOST_CHECK_EQUAL(dagCoin.height(), summaryCoin.height());
}

BOOST_AUTO_TEST_SUITE_END()

