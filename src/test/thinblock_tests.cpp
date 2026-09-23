// Copyright (c) 2016-2023 The Bitcoin Unlimited Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockrelay/blockrelay_common.h"
#include "blockrelay/compactblock.h"
#include "blockrelay/connmgr.h"
#include "blockrelay/expedited.h"
#include "blockrelay/graphene.h"
#include "blockrelay/thinblock.h"
#include "bloom.h"
#include "chainparams.h"
#include "main.h"
#include "primitives/block.h"
#include "random.h"
#include "serialize.h"
#include "streams.h"
#include "txmempool.h"
#include "uint256.h"
#include "unlimited.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation/tailstorm.h"
#include "version.h"

#include "test/test_nexa.h"

#include <boost/test/unit_test.hpp>
#include <sstream>
#include <string.h>


BOOST_FIXTURE_TEST_SUITE(thinblock_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(thinblock_test)
{
    CBloomFilter filter;
    std::vector<uint256> vOrphanHashes;
    CAddress addr1(ipaddress(0xa0b0c001, 10000));
    CNode dummyNode1(INVALID_SOCKET, addr1, "", true);
    CBlock block = TestBlock1();

    // Create 10 random hashes to seed the orphanhash vector.  This way we will create a bloom filter
    // with a size of 10 elements.
    std::string hash = "3fba505b48865fccda4e248cecc39d5dfbc6b8ef7b4adc9cd27242c1193c714";
    for (int i = 0; i < 10; i++)
    {
        std::stringstream ss;
        ss << i;
        hash.append(ss.str());
        uint256 random_hash = uint256S(hash);
        vOrphanHashes.push_back(random_hash);
    }
    BuildSeededBloomFilter(filter, vOrphanHashes, block.GetHash(), &dummyNode1, true);

    /* empty filter */
    CThinBlock thinblock(block, filter);
    CXThinBlock xthinblock(block, &filter);
    BOOST_CHECK_EQUAL(290UL, thinblock.vMissingTx.size());
    BOOST_CHECK_EQUAL(290UL, xthinblock.vMissingTx.size());

    /* insert txid not in block */
    const uint256 random_hash = uint256S("3fba505b48865fccda4e248cecc39d5dfbc6b8ef7b4adc9cd27242c1193c7133");
    filter.insert(random_hash);
    CThinBlock thinblock1(block, filter);
    CXThinBlock xthinblock1(block, &filter);
    BOOST_CHECK_EQUAL(290UL, thinblock1.vMissingTx.size());
    BOOST_CHECK_EQUAL(290UL, xthinblock1.vMissingTx.size());

    /* insert txid in block */
    const uint256 hash_in_block = block.vtx[1]->GetId();
    filter.insert(hash_in_block);
    CThinBlock thinblock2(block, filter);
    CXThinBlock xthinblock2(block, &filter);
    BOOST_CHECK_EQUAL(289UL, thinblock2.vMissingTx.size());
    BOOST_CHECK_EQUAL(289UL, xthinblock2.vMissingTx.size());

    /*collision test*/
    BOOST_CHECK(!xthinblock2.collision);
    block.vtx.push_back(block.vtx[1]); // duplicate tx
    filter.clear();
    CXThinBlock xthinblock3(block, &filter);
    BOOST_CHECK(xthinblock3.collision);


    //  Add tests using a non-deterministic bloom filter which may
    //  or may not yeild a false positive.
    CBloomFilter filter1;
    BuildSeededBloomFilter(filter1, vOrphanHashes, block.GetHash(), &dummyNode1, false);

    /* empty filter */
    CBlock block1 = TestBlock1();
    CThinBlock thinblock4(block1, filter1);
    CXThinBlock xthinblock4(block1, &filter1);
    BOOST_CHECK(thinblock4.vMissingTx.size() >= 288 && thinblock4.vMissingTx.size() <= 290);
    BOOST_CHECK(xthinblock4.vMissingTx.size() >= 288 && xthinblock4.vMissingTx.size() <= 290);

    /* insert txid not in block */
    const uint256 random_hash1 = uint256S("3fba505b48865fccda4e248cecc39d5dfbc6b8ef7b4adc9cd27242c1193c7132");
    filter1.insert(random_hash1);
    CThinBlock thinblock5(block1, filter1);
    CXThinBlock xthinblock5(block1, &filter1);
    BOOST_CHECK(thinblock5.vMissingTx.size() >= 288 && thinblock5.vMissingTx.size() <= 290);
    BOOST_CHECK(xthinblock5.vMissingTx.size() >= 288 && xthinblock5.vMissingTx.size() <= 290);

    /* insert txid in block */
    const uint256 hash_in_block1 = block.vtx[1]->GetId();
    filter1.insert(hash_in_block1);
    CThinBlock thinblock6(block1, filter1);
    CXThinBlock xthinblock6(block1, &filter1);
    BOOST_CHECK(thinblock6.vMissingTx.size() >= 287 && thinblock6.vMissingTx.size() <= 289);
    BOOST_CHECK(xthinblock6.vMissingTx.size() >= 287 && xthinblock6.vMissingTx.size() <= 289);

    /*collision test*/
    BOOST_CHECK(!xthinblock6.collision);
    block.vtx.push_back(block1.vtx[1]); // duplicate tx
    filter1.clear();
    CXThinBlock xthinblock7(block, &filter1);
    BOOST_CHECK(xthinblock7.collision);
}

static bool ReceiveRelayBlock(CNode &node, const CBlock &block, const std::string &command)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    CBloomFilter filter;
    if (command == NetMsgType::CMPCTBLOCK)
    {
        stream << CompactBlock(block);
        return CompactBlock::HandleMessage(stream, 0, &node);
    }
    if (command == NetMsgType::GRAPHENEBLOCK)
    {
        stream << CGrapheneBlock(
            MakeBlockRef(block), 5, 6, node.negotiatedGrapheneVersion, NegotiateFastFilterSupport(&node));
        return CGrapheneBlock::HandleMessage(stream, &node, 0, command, 0);
    }
    if (command == NetMsgType::XTHINBLOCK)
    {
        stream << CXThinBlock(block, &filter);
        return CXThinBlock::HandleMessage(stream, &node, command, 0);
    }
    stream << CThinBlock(block, filter);
    return CThinBlock::HandleMessage(stream, &node);
}

// Unsolicited and late replies must neither retain reconstruction state nor penalize the peer.
BOOST_AUTO_TEST_CASE(unsolicited_relay_blocks)
{
    CAddress address(ipaddress(0xa0b0c001, 10000));
    CNode node(INVALID_SOCKET, address, "", true);
    node.negotiatedGrapheneVersion = 4;
    for (bool subblock : {false, true})
    {
        CBlock block = Params().GenesisBlock();
        if (subblock)
        {
            CDataStream minerData(SER_NETWORK, PROTOCOL_VERSION);
            minerData << uint8_t(DEFAULT_MINER_DATA_SUBBLOCK_VERSION) << std::vector<uint256>();
            block.minerData.assign(minerData.begin(), minerData.end());
        }
        const uint256 hash = block.GetHash();
        for (const auto &command :
            {NetMsgType::CMPCTBLOCK, NetMsgType::GRAPHENEBLOCK, NetMsgType::XTHINBLOCK, NetMsgType::THINBLOCK})
        {
            const std::string thinType = command == NetMsgType::THINBLOCK ? NetMsgType::XTHINBLOCK : command;
            for (bool expired : {false, true})
            {
                if (expired)
                {
                    BOOST_REQUIRE(thinrelay.AddBlockInFlight(&node, hash, thinType));
                    thinrelay.SetBlockToReconstruct(&node, hash);
                    thinrelay.ClearAllBlockData(&node, hash);
                }
                const double score = node.nMisbehavior.load();
                BOOST_CHECK(!ReceiveRelayBlock(node, block, command));
                BOOST_REQUIRE(!thinrelay.GetBlockToReconstruct(&node, hash));
                BOOST_CHECK(!thinrelay.IsBlockInFlight(&node, thinType, hash));
                BOOST_CHECK_EQUAL(node.nMisbehavior.load(), score);
                BOOST_CHECK(!node.IsDisconnecting());
                thinrelay.ClearAllBlockData(&node, hash);
            }
        }
    }
}

// A reply in an unrequested format must not overwrite another format's pending reconstruction.
BOOST_AUTO_TEST_CASE(unrequested_relay_preserves_pending_block)
{
    CAddress address(ipaddress(0xa0b0c002, 10000));
    CNode node(INVALID_SOCKET, address, "", true);
    node.negotiatedGrapheneVersion = 4;
    const CBlock block = Params().GenesisBlock();
    const uint256 hash = block.GetHash();
    for (const auto &command :
        {NetMsgType::CMPCTBLOCK, NetMsgType::GRAPHENEBLOCK, NetMsgType::XTHINBLOCK, NetMsgType::THINBLOCK})
    {
        const std::string requestedType =
            command == NetMsgType::CMPCTBLOCK ? NetMsgType::XTHINBLOCK : NetMsgType::CMPCTBLOCK;
        BOOST_REQUIRE(thinrelay.AddBlockInFlight(&node, hash, requestedType));
        auto pending = thinrelay.SetBlockToReconstruct(&node, hash);
        auto compact = pending->cmpctblock;
        auto graphene = pending->grapheneblock;
        auto xthin = pending->xthinblock;
        auto thin = pending->thinblock;

        BOOST_CHECK(!ReceiveRelayBlock(node, block, command));
        BOOST_CHECK(thinrelay.GetBlockToReconstruct(&node, hash) == pending);
        BOOST_CHECK(thinrelay.IsBlockInFlight(&node, requestedType, hash));
        BOOST_REQUIRE(pending->cmpctblock == compact);
        BOOST_REQUIRE(pending->grapheneblock == graphene);
        BOOST_REQUIRE(pending->xthinblock == xthin);
        BOOST_REQUIRE(pending->thinblock == thin);
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 0);
        thinrelay.ClearAllBlockData(&node, hash);
    }
}

struct ExpeditedTestPeer
{
    CNode node;
    const bool thinBlocksEnabled = IsThinBlocksEnabled();

    ExpeditedTestPeer() : node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c003, 10000)), "", true)
    {
        SetBoolArg("-use-thinblocks", true);
        node.nServices |= NODE_XTHIN;
        node.negotiatedGrapheneVersion = 4;
        BOOST_REQUIRE(connmgr->PushExpeditedRequest(&node, EXPEDITED_BLOCKS));
    }

    ~ExpeditedTestPeer()
    {
        connmgr->RemovedNode(&node);
        SetBoolArg("-use-thinblocks", thinBlocksEnabled);
        // PushExpeditedRequest queues a reference that must not outlive this stack node.
        LOCK(cs_prioritySendQ);
        for (auto it = vPrioritySendQ.begin(); it != vPrioritySendQ.end();)
        {
            if (it->get() == &node)
                it = vPrioritySendQ.erase(it);
            else
                ++it;
        }
    }
};

// Expedited peer status does not authorize unsolicited messages in ordinary relay formats.
BOOST_AUTO_TEST_CASE(expedited_peer_ordinary_relay)
{
    ExpeditedTestPeer peer;
    CNode &node = peer.node;
    BOOST_REQUIRE(connmgr->IsExpeditedUpstream(&node));
    const CBlock block = Params().GenesisBlock();
    const uint256 hash = block.GetHash();
    for (const auto &command :
        {NetMsgType::CMPCTBLOCK, NetMsgType::GRAPHENEBLOCK, NetMsgType::XTHINBLOCK, NetMsgType::THINBLOCK})
    {
        const std::string requestedType =
            command == NetMsgType::CMPCTBLOCK ? NetMsgType::XTHINBLOCK : NetMsgType::CMPCTBLOCK;
        for (bool pendingOtherFormat : {false, true})
        {
            std::shared_ptr<CBlockThinRelay> pending;
            if (pendingOtherFormat)
            {
                BOOST_REQUIRE(thinrelay.AddBlockInFlight(&node, hash, requestedType));
                pending = thinrelay.SetBlockToReconstruct(&node, hash);
            }
            auto compact = pending ? pending->cmpctblock : nullptr;
            auto graphene = pending ? pending->grapheneblock : nullptr;
            auto xthin = pending ? pending->xthinblock : nullptr;
            auto thin = pending ? pending->thinblock : nullptr;
            BOOST_CHECK(!ReceiveRelayBlock(node, block, command));
            BOOST_CHECK(thinrelay.GetBlockToReconstruct(&node, hash) == pending);
            BOOST_CHECK_EQUAL(thinrelay.IsBlockInFlight(&node, requestedType, hash), pendingOtherFormat);
            if (pending)
            {
                BOOST_CHECK(pending->cmpctblock == compact);
                BOOST_CHECK(pending->grapheneblock == graphene);
                BOOST_CHECK(pending->xthinblock == xthin);
                BOOST_CHECK(pending->thinblock == thin);
            }
            BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 0);
            BOOST_CHECK(!node.IsDisconnecting());
            thinrelay.ClearAllBlockData(&node, hash);
        }
    }
}

// Expedited admission depends on the message type and upstream status, not the hop count.
// Zero-hop XPEDITEDBLK cases bypass HandleExpeditedBlock, which normally passes hops + 1.
BOOST_AUTO_TEST_CASE(expedited_xthin_admission)
{
    for (bool upstream : {false, true})
    {
        for (const auto &command : {NetMsgType::XTHINBLOCK, NetMsgType::XPEDITEDBLK})
        {
            for (unsigned hops : {0U, 1U})
            {
                ExpeditedTestPeer peer;
                CNode &node = peer.node;
                if (!upstream)
                    connmgr->RemovedNode(&node);
                CXThinBlock block;
                block.header = Params().GenesisBlock().GetBlockHeader();
                CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
                stream << block; // Missing transactions make the payload invalid after admission.
                BOOST_CHECK(!CXThinBlock::HandleMessage(stream, &node, command, hops));
                const bool expedited = upstream && command == NetMsgType::XPEDITEDBLK;
                BOOST_CHECK_EQUAL(node.nMisbehavior.load(), expedited ? 100 : 0);
                BOOST_CHECK(!thinrelay.GetBlockToReconstruct(&node, block.header.GetHash()));
                BOOST_CHECK(!thinrelay.IsBlockInFlight(&node, NetMsgType::XTHINBLOCK, block.header.GetHash()));
                thinrelay.ClearAllBlockData(&node, block.header.GetHash());
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
