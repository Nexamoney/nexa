// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockrelay/blockrelay_common.h"
#include "blockrelay/compactblock.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "daa.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "protocol.h"
#include "random.h"
#include "validation/parallel.h"

#include "test/test_nexa.h"
#include "test/testutil.h"

#include <boost/test/unit_test.hpp>
#include <chrono>
#include <future>

class HasReason
{
public:
    HasReason(const std::string &reason) : m_reason(reason) {}
    bool operator()(const std::invalid_argument &e) const
    {
        return std::string(e.what()).find(m_reason) != std::string::npos;
    };

private:
    const std::string m_reason;
};

struct RegtestingSetup : public TestingSetup
{
    RegtestingSetup() : TestingSetup(CBaseChainParams::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(compactblocks_tests, RegtestingSetup)

static CBlock TestBlock()
{
    CBlock block;
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig.resize(10);
    tx.vout.resize(1);
    tx.vout[0].nValue = 42;

    block.vtx.resize(3);
    block.vtx[0] = MakeTransactionRef(tx);
    block.hashPrevBlock = InsecureRand256();
    block.nBits = 0x207fffff;

    tx.vin[0].prevout.hash = InsecureRand256();
    block.vtx[1] = MakeTransactionRef(tx);

    tx.vin.resize(10);
    for (size_t i = 0; i < tx.vin.size(); i++)
    {
        tx.vin[i].prevout.hash = InsecureRand256();
    }
    block.vtx[2] = MakeTransactionRef(tx);

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    assert(!mutated);
    block.UpdateHeader(); // make sure the size field is properly calculated
    block.nonce.resize(5);
    bool worked = MineBlock(block, 1UL<<(5*8), Params().GetConsensus());
    assert(worked);
    return block;
}

BOOST_AUTO_TEST_CASE(TransactionsRequestSerializationTest)
{
    CompactReRequest req1;
    req1.blockhash = InsecureRand256();
    req1.indexes.resize(4);
    req1.indexes[0] = 0;
    req1.indexes[1] = 1;
    req1.indexes[2] = 3;
    req1.indexes[3] = 4;

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << req1;

    CompactReRequest req2;
    stream >> req2;

    BOOST_CHECK_EQUAL(req1.blockhash.ToString(), req2.blockhash.ToString());
    BOOST_CHECK_EQUAL(req1.indexes.size(), req2.indexes.size());
    BOOST_CHECK_EQUAL(req1.indexes[0], req2.indexes[0]);
    BOOST_CHECK_EQUAL(req1.indexes[1], req2.indexes[1]);
    BOOST_CHECK_EQUAL(req1.indexes[2], req2.indexes[2]);
    BOOST_CHECK_EQUAL(req1.indexes[3], req2.indexes[3]);
}

BOOST_AUTO_TEST_CASE(validate_compact_block)
{
    CBlock block = TestBlock(); // valid block
    CompactBlock a(block);
    BOOST_CHECK_NO_THROW(validateCompactBlock(std::make_shared<CompactBlock>(a)));

    // invalid header
    CompactBlock b = a;
    b.header.SetNull();
    BOOST_ASSERT(b.header.IsNull());
    BOOST_CHECK_THROW(validateCompactBlock(std::make_shared<CompactBlock>(b)), std::invalid_argument);

    // null tx in prefilled
    CompactBlock c = a;
    c.prefilledtxn.at(0).tx = CTransaction();
    BOOST_CHECK_THROW(validateCompactBlock(std::make_shared<CompactBlock>(c)), std::invalid_argument);

    // overflowing index
    CompactBlock d = a;
    d.prefilledtxn.push_back(d.prefilledtxn[0]);
    assert(d.prefilledtxn.size() == size_t(2));
    d.prefilledtxn.at(0).index = 1;
    d.prefilledtxn.at(1).index = std::numeric_limits<uint32_t>::max();
    BOOST_CHECK_EXCEPTION(validateCompactBlock(std::make_shared<CompactBlock>(d)), std::invalid_argument,
        HasReason("tx index overflows"));

    // too high index
    CompactBlock e = a;
    e.prefilledtxn.at(0).index = std::numeric_limits<uint32_t>::max() / 2;
    BOOST_CHECK_EXCEPTION(validateCompactBlock(std::make_shared<CompactBlock>(e)), std::invalid_argument,
        HasReason("invalid index for tx"));

    // no transactions
    CompactBlock f = a;
    f.shorttxids.clear();
    f.prefilledtxn.clear();
    BOOST_CHECK_THROW(validateCompactBlock(std::make_shared<CompactBlock>(f)), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(reconstruct_state_released_after_handoff)
{
    BOOST_REQUIRE(PV->Enabled());

    CKey key;
    key.MakeNewKey(true);
    CBlockRef block = BlockAssembler(Params()).CreateNewBlock(p2pkh(key.GetPubKey().GetID()))->block;
    block->nonce.resize(3);
    BOOST_REQUIRE(MineBlock(*block, 1 << 23, Params().GetConsensus()));
    const uint256 hash = block->GetHash();
    CompactBlock compact(*block);

    CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c0f2, 10000)), "", true);
    SetConnected(node);
    BOOST_REQUIRE(thinrelay.AddBlockInFlight(&node, hash, NetMsgType::CMPCTBLOCK));
    std::shared_ptr<CBlockThinRelay> handedOff = thinrelay.SetBlockToReconstruct(&node, hash);
    BOOST_REQUIRE(handedOff != nullptr);

    bool firstAccepted = false;
    bool replayAccepted = false;
    bool replayChecked = false;
    bool stillInFlight = false;
    bool sameCompactData = true;
    bool retainedReconstruction = false;
    size_t firstTxCount = 0;
    size_t replayTxCount = 0;
    std::future<void> handling;
    bool handlerCompleted = false;
    {
        // Keep validation behind cs_main while the handler processes the repeat message.
        LOCK(cs_main);
        handling = std::async(std::launch::async, [&]() {
            CDataStream first(SER_NETWORK, PROTOCOL_VERSION);
            first << compact;
            firstAccepted = CompactBlock::HandleMessage(first, 0, &node);
            if (firstAccepted)
            {
                firstTxCount = handedOff->vtx.size();
                replayTxCount = firstTxCount;
                stillInFlight = thinrelay.IsBlockInFlight(&node, NetMsgType::CMPCTBLOCK, hash);
                retainedReconstruction = thinrelay.GetBlockToReconstruct(&node, hash) != nullptr;
                if (!stillInFlight && !retainedReconstruction)
                {
                    const auto originalCompact = handedOff->cmpctblock;
                    CDataStream replay(SER_NETWORK, PROTOCOL_VERSION);
                    replay << compact;
                    replayChecked = true;
                    replayAccepted = CompactBlock::HandleMessage(replay, 0, &node);
                    sameCompactData = handedOff->cmpctblock == originalCompact;
                    replayTxCount = handedOff->vtx.size();
                }
            }
        });
        handlerCompleted = handling.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    }
    handling.get();
    thinrelay.ClearAllBlockData(&node, hash);
    // The detached validation worker holds a node reference before it registers with PV.
    // Wait for that reference so fixture teardown cannot overtake the worker.
    while (node.GetRefCount() != 0)
        MilliSleep(10);

    BOOST_REQUIRE(handlerCompleted);
    BOOST_REQUIRE(firstAccepted);
    BOOST_CHECK_EQUAL(firstTxCount, block->vtx.size());
    BOOST_CHECK(!stillInFlight);
    BOOST_CHECK(!retainedReconstruction);
    BOOST_CHECK(replayChecked);
    BOOST_CHECK(!replayAccepted);
    BOOST_CHECK(sameCompactData);
    BOOST_CHECK_EQUAL(replayTxCount, firstTxCount);
}

BOOST_AUTO_TEST_CASE(wait_covers_unregistered_validation_thread)
{
    BOOST_REQUIRE(PV->Enabled());

    CKey key;
    key.MakeNewKey(true);
    CBlockRef block = BlockAssembler(Params()).CreateNewBlock(p2pkh(key.GetPubKey().GetID()))->block;
    block->nonce.resize(3);
    BOOST_REQUIRE(MineBlock(*block, 1 << 23, Params().GetConsensus()));

    CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c0f3, 10000)), "", true);
    SetConnected(node);

    // The worker may not have registered yet when the wait starts; it holds a node reference until it is done
    PV->HandleBlockMessage(&node, NetMsgType::BLOCK, block);
    PV->WaitForAllValidationThreadsToStop();
    BOOST_CHECK_EQUAL(node.GetRefCount(), 0);

    // Do not let teardown overtake the worker if the wait returned early
    while (node.GetRefCount() != 0)
        MilliSleep(10);
}


BOOST_AUTO_TEST_CASE(getblocktxn_rejects_repeated_indexes)
{
    // A GETBLOCKTXN may name each transaction once. Repeating the index of the largest transaction up to
    // vtx.size() times made the response (built in memory, then copied to the send buffer) vtx.size() times
    // that transaction's size, from a request of 4 bytes per index.
    CBlock block = TestBlock();
    std::vector<uint32_t> repeated(block.vtx.size(), 2);
    BOOST_CHECK_EXCEPTION(CompactReReqResponse(block, repeated), std::invalid_argument, HasReason("index"));

    std::vector<uint32_t> descending = {2, 1};
    BOOST_CHECK_EXCEPTION(CompactReReqResponse(block, descending), std::invalid_argument, HasReason("index"));

    // Honest requests are strictly increasing, and still work.
    CompactReReqResponse ok(block, {0, 1, 2});
    BOOST_CHECK_EQUAL(ok.txn.size(), 3);
}

BOOST_AUTO_TEST_SUITE_END()
