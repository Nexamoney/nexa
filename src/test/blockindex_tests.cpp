// Copyright (c) 2015-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for block index handling

#include "blockstorage/blockstorage.h"
#include "chainparams.h"
#include "daa.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "validation/parallel.h"
#include "validation/validation.h"

#include "test/test_nexa.h"
#include "test/testutil.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <future>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(blockindex_tests, TestingSetup)

// Test that the trimming of headers from the block index,
// and test whether the headers are either present or null.
// Only recent entries in the block index should have headers actually
// stored in RAM, otherwise they should be null and only accessible
// directly from the database.
BOOST_AUTO_TEST_CASE(header_handling)
{
    // Setup index
    const CChainParams &chainparams = Params(CBaseChainParams::REGTEST);
    {
        LOCK(cs_main);
        UnloadBlockIndex();
        chainActive.reset();
        InitBlockIndex(chainparams);
    }

    assert(chainActive.Tip()->GetBlockHash() == chainparams.GetConsensus().hashGenesisBlock);
    CScript scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f"
                                                 "6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
                                     << OP_CHECKSIG;

    LOCK(cs_main);
    bool fBlockDownload = false;
    IsInitialBlockDownloadInit(&fBlockDownload);
    fCheckpointsEnabled = false;

    // Grab initial template:
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    BOOST_CHECK(pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey));

    // Create index entries right up to the flush point which would be 2 times DEFAULT_HEADERS_TO_KEEP_IN_RAM
    // which in this case is 200 entries.
    for (unsigned int i = 0; i < 199; i++)
    {
        CBlockRef pblock = pblocktemplate->block;
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256());
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->UpdateHeader();
        CBlockIndex *pindex = AddToBlockIndex(chainparams, *pblock);

        // Check we have the header when we first create the index value
        BOOST_CHECK(!pindex->IsHeaderNull());
        BOOST_CHECK(pindex->GetBlockHeader().height == pblock->height);
        BOOST_CHECK(pindex->GetBlockHeader().nBits == pblock->nBits);

        chainActive.SetTip(pindex);
    }

    // Flush state to disk and check header status
    // Nothing should have been flushed (everthing should still be in setDirtyBlockIndex)
    // and all headers should still be present in the block index.
    BOOST_CHECK(setHeadersToTrim.size() == 99);
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED);
    {
        // Nothing got flushed
        BOOST_CHECK(setDirtyBlockIndex.size() == 199);

        // Check all headers are present still after flushing
        uint32_t nChainHeight = chainActive.Height();
        for (auto iter : mapBlockIndex)
        {
            if ((nChainHeight - iter.second->nHeight) < (2 * DEFAULT_HEADERS_TO_KEEP_IN_RAM))
            {
                BOOST_CHECK(!iter.second->IsHeaderNull());
            }
            else
            {
                BOOST_CHECK(iter.second->IsHeaderNull());
            }
        }
        BOOST_CHECK(setHeadersToTrim.size() == 99);
    }

    // Add one more index entry and then flush state.
    // Only the most recent 100 index entries should still have headers, all others
    // should be nulled.
    {
        CBlockRef pblock = pblocktemplate->block;
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256());
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->UpdateHeader();
        CBlockIndex *pindex = AddToBlockIndex(chainparams, *pblock);

        // Check we have the header when we first create the index value
        BOOST_CHECK(!pindex->IsHeaderNull());
        BOOST_CHECK(pindex->GetBlockHeader().height == pblock->height);
        BOOST_CHECK(pindex->GetBlockHeader().nBits == pblock->nBits);

        chainActive.SetTip(pindex);
    }
    BOOST_CHECK(setHeadersToTrim.size() == 100);
    FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED);
    {
        // Everthing got flushed
        BOOST_CHECK(setDirtyBlockIndex.size() == 0);

        // Check all headers are present still after flushing
        uint32_t nChainHeight = chainActive.Height();
        for (auto &iter : mapBlockIndex)
        {
            const uint32_t &nHeight = iter.second->nHeight;
            if (nHeight == 0 || (nChainHeight - nHeight) < DEFAULT_HEADERS_TO_KEEP_IN_RAM)
            {
                BOOST_CHECK(!iter.second->IsHeaderNull());
            }
            else
            {
                BOOST_CHECK(iter.second->IsHeaderNull());
            }
        }
        BOOST_CHECK(setHeadersToTrim.size() == 0);
    }

    // Add 5000 more entries before flushing.
    // Only the most recent 100 index entries should still have headers, all others
    // should be nulled.
    for (unsigned int i = 0; i < 5000; ++i)
    {
        CBlockRef pblock = pblocktemplate->block;
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256());
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->UpdateHeader();
        CBlockIndex *pindex = AddToBlockIndex(chainparams, *pblock);

        // Check we have the header when we first create the index value
        BOOST_CHECK(!pindex->IsHeaderNull());
        BOOST_CHECK(pindex->GetBlockHeader().height == pblock->height);
        BOOST_CHECK(pindex->GetBlockHeader().nBits == pblock->nBits);

        chainActive.SetTip(pindex);
    }

    BOOST_CHECK(setHeadersToTrim.size() == 5000);
    FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED);
    {
        // Everthing got flushed
        BOOST_CHECK(setDirtyBlockIndex.size() == 0);

        // Check all headers are present still after flushing
        uint32_t nChainHeight = chainActive.Height();
        for (auto &iter : mapBlockIndex)
        {
            const uint32_t &nHeight = iter.second->nHeight;
            if (nHeight == 0 || (nChainHeight - nHeight) < DEFAULT_HEADERS_TO_KEEP_IN_RAM)
            {
                BOOST_CHECK(!iter.second->IsHeaderNull());
            }
            else
            {
                BOOST_CHECK(iter.second->IsHeaderNull());
            }
        }
        BOOST_CHECK(setHeadersToTrim.size() == 0);
    }

    // Add 1111 more entries before flushing.
    // Only the most recent 100 index entries should still have headers, all others
    // should be nulled.
    for (unsigned int i = 0; i < 1111; ++i)
    {
        CBlockRef pblock = pblocktemplate->block;
        auto tip = chainActive.Tip();
        pblock->nTime = tip->GetMedianTimePast() + 1000;
        pblock->hashPrevBlock = tip->GetBlockHash();
        pblock->hashAncestor = tip->GetChildsConsensusAncestor()->GetBlockHash();
        BOOST_CHECK(pblock->hashAncestor != uint256());
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.nVersion = 0;
        txCoinbase.vout[1].scriptPubKey = CScript() << OP_RETURN << (tip->height() + 1) << OP_0;
        txCoinbase.vout[0].scriptPubKey = CScript();
        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->height = tip->height() + 1;
        pblock->nBits = GetNextWorkRequired(tip, pblock.get(), chainparams.GetConsensus());
        pblock->chainWork = ArithToUint256(tip->chainWork() + GetWorkForDifficultyBits(pblock->nBits));
        pblock->txCount = 1;

        pblock->UpdateHeader();
        CBlockIndex *pindex = AddToBlockIndex(chainparams, *pblock);

        // Check we have the header when we first create the index value
        BOOST_CHECK(!pindex->IsHeaderNull());
        BOOST_CHECK(pindex->GetBlockHeader().height == pblock->height);
        BOOST_CHECK(pindex->GetBlockHeader().nBits == pblock->nBits);

        chainActive.SetTip(pindex);
    }

    BOOST_CHECK(setHeadersToTrim.size() == 1111);
    FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED);
    {
        // Everthing got flushed
        BOOST_CHECK(setDirtyBlockIndex.size() == 0);

        // Check all headers are present still after flushing
        uint32_t nChainHeight = chainActive.Height();
        for (auto &iter : mapBlockIndex)
        {
            const uint32_t &nHeight = iter.second->nHeight;
            if (nHeight == 0 || (nChainHeight - nHeight) < DEFAULT_HEADERS_TO_KEEP_IN_RAM)
            {
                BOOST_CHECK(!iter.second->IsHeaderNull());
            }
            else
            {
                BOOST_CHECK(iter.second->IsHeaderNull());
            }
        }
        BOOST_CHECK(setHeadersToTrim.size() == 0);
    }

    // Try to access headers.
    // Loop through looking for random headers, which may or may not be in the
    // blockindex RAM, however, we should always get a header, whether it came
    // from RAM or disk.
    FastRandomContext ctx;
    const size_t nSkipRange = mapBlockIndex.size(); // spot check the entire index
    for (int i = 0; i <= 100; i++)
    {
        uint64_t nSkipTo = std::max((uint64_t)1, ctx.randrange(nSkipRange));
        auto iter = mapBlockIndex.begin();
        std::advance(iter, nSkipTo);
        CBlockHeader header = iter->second->GetBlockHeader();
        BOOST_CHECK(header.IsNull() != true);
    }

    // Must reset this to "true" or you'll cause a thread to hang in the main test loop.
    fCheckpointsEnabled = true;
}

// GetBlockHeader() copies the header without cs_mapBlockIndex while a flush replaces or trims it. Only a
// ThreadSanitizer build reports the race reliably (NX-44).
BOOST_AUTO_TEST_CASE(header_read_while_replaced)
{
    CBlockHeader header;
    header.nBits = 0x207fffff;
    header.nTime = 1234;
    header.size = 1;
    CBlockIndex index(header);

    std::atomic<bool> fDone{false};
    std::thread writer(
        [&]
        {
            for (int i = 0; i < 20000; i++)
                index.SetBlockHeader(std::make_shared<CBlockHeader>(header));
            fDone = true;
        });
    bool fSame = true;
    while (!fDone)
        fSame &= index.GetBlockHeader().nTime == header.nTime;
    writer.join();
    BOOST_CHECK(fSame);
}

// A block on top of pindexPrev with one more unit of work, so that siblings made by this have equal work
static CBlockRef MakeSiblingBlock(const CBlockIndex *pindexPrev, uint32_t nTime)
{
    CBlockRef block = std::make_shared<CBlock>();
    block->hashPrevBlock = pindexPrev->GetBlockHash();
    block->height = pindexPrev->height() + 1;
    block->nTime = nTime;
    block->SetChainWork(pindexPrev->chainWork() + 1);
    // the hash includes the size, so calculate it before the hash is used
    block->GetBlockSize();
    return block;
}

// Parallel validation swaps the sequence ids of competing blocks so that the winner sorts first. The candidate
// set orders blocks by sequence id, so the swap must keep it sorted, or later erases of those blocks can miss
BOOST_AUTO_TEST_CASE(pv_cleanup_keeps_candidates_sorted)
{
    CBlockIndex *pindexPrev = nullptr;
    {
        LOCK(cs_main);
        pindexPrev = chainActive.Tip();
    }

    // two sibling blocks with equal work: L arrived first, W arrived later but won the validation race
    CBlockRef blockL = MakeSiblingBlock(pindexPrev, 1);
    CBlockRef blockW = MakeSiblingBlock(pindexPrev, 2);
    BOOST_REQUIRE(blockW->IsSummaryBlock());
    CBlockIndex indexL(*blockL);
    CBlockIndex indexW(*blockW);
    indexL.nSequenceId = 5;
    indexW.nSequenceId = 9;
    {
        WRITELOCK(cs_mapBlockIndex);
        indexL.phashBlock = &mapBlockIndex.emplace(blockL->GetHash(), &indexL).first->first;
        indexW.phashBlock = &mapBlockIndex.emplace(blockW->GetHash(), &indexW).first->first;
        setBlockIndexCandidates.insert(&indexL);
        setBlockIndexCandidates.insert(&indexW);
    }

    // register L as a competing validation thread; BeginValidation records its sequence id
    const boost::thread::id otherId; // not any thread, so never this one
    CNode node(INVALID_SOCKET, CAddress(), "", true);
    PV->InitThread(otherId, &node, blockL);
    {
        LOCK(cs_main);
        BOOST_REQUIRE(PV->BeginValidation(otherId, &indexL, true));
        // W won the race
        PV->Cleanup(blockW, &indexW);
    }
    PV->Erase(otherId);

    {
        WRITELOCK(cs_mapBlockIndex);
        // the winner now has the lower sequence id
        BOOST_CHECK_EQUAL(indexW.nSequenceId, 5);
        BOOST_CHECK_EQUAL(indexL.nSequenceId, 9);
        // the set is still ordered, and both blocks can still be found
        BOOST_CHECK(std::is_sorted(
            setBlockIndexCandidates.begin(), setBlockIndexCandidates.end(), setBlockIndexCandidates.value_comp()));
        BOOST_CHECK_EQUAL(setBlockIndexCandidates.count(&indexL), 1);
        BOOST_CHECK_EQUAL(setBlockIndexCandidates.count(&indexW), 1);

        // remove the test blocks by position, which works even if the set is out of order
        for (auto it = setBlockIndexCandidates.begin(); it != setBlockIndexCandidates.end();)
        {
            if (*it == &indexL || *it == &indexW)
                it = setBlockIndexCandidates.erase(it);
            else
                ++it;
        }
        mapBlockIndex.erase(blockL->GetHash());
        mapBlockIndex.erase(blockW->GetHash());
    }
}

// Same as above, but with several competing blocks, so the winner's sequence id changes more than once, and with
// one competing block that is not a candidate, which must stay out of the set
BOOST_AUTO_TEST_CASE(pv_cleanup_keeps_candidates_sorted_many)
{
    CBlockIndex *pindexPrev = nullptr;
    {
        LOCK(cs_main);
        pindexPrev = chainActive.Tip();
    }

    // W won the validation race against three blocks that arrived before it. C5 is not a candidate.
    CBlockRef blockW = MakeSiblingBlock(pindexPrev, 1);
    std::vector<CBlockRef> blocks = {
        MakeSiblingBlock(pindexPrev, 2), MakeSiblingBlock(pindexPrev, 3), MakeSiblingBlock(pindexPrev, 4)};
    CBlockIndex indexW(*blockW);
    CBlockIndex indexC3(*blocks[0]);
    CBlockIndex indexC5(*blocks[1]);
    CBlockIndex indexC7(*blocks[2]);
    std::vector<CBlockIndex *> competitors = {&indexC3, &indexC5, &indexC7};
    indexW.nSequenceId = 9;
    indexC3.nSequenceId = 3;
    indexC5.nSequenceId = 5;
    indexC7.nSequenceId = 7;
    {
        WRITELOCK(cs_mapBlockIndex);
        indexW.phashBlock = &mapBlockIndex.emplace(blockW->GetHash(), &indexW).first->first;
        for (size_t i = 0; i < competitors.size(); i++)
            competitors[i]->phashBlock = &mapBlockIndex.emplace(blocks[i]->GetHash(), competitors[i]).first->first;
        setBlockIndexCandidates.insert(&indexW);
        setBlockIndexCandidates.insert(&indexC3);
        setBlockIndexCandidates.insert(&indexC7);
    }

    // each competing validation needs its own thread id, so start threads that wait until the test is done
    std::promise<void> done;
    std::shared_future<void> fDone = done.get_future().share();
    std::vector<boost::thread> threads;
    for (size_t i = 0; i < competitors.size(); i++)
        threads.emplace_back([fDone] { fDone.wait(); });

    CNode node(INVALID_SOCKET, CAddress(), "", true);
    for (size_t i = 0; i < competitors.size(); i++)
        PV->InitThread(threads[i].get_id(), &node, blocks[i]);
    {
        LOCK(cs_main);
        for (size_t i = 0; i < competitors.size(); i++)
            BOOST_REQUIRE(PV->BeginValidation(threads[i].get_id(), competitors[i], true));
        PV->Cleanup(blockW, &indexW);
    }
    for (auto &t : threads)
        PV->Erase(t.get_id());
    done.set_value();
    for (auto &t : threads)
        t.join();

    {
        WRITELOCK(cs_mapBlockIndex);
        // the winner takes the lowest sequence id and the others keep their order
        BOOST_CHECK_EQUAL(indexW.nSequenceId, 3);
        BOOST_CHECK_EQUAL(indexC3.nSequenceId, 5);
        BOOST_CHECK_EQUAL(indexC5.nSequenceId, 7);
        BOOST_CHECK_EQUAL(indexC7.nSequenceId, 9);
        // the set is still ordered, the candidates can still be found, and C5 was not added
        BOOST_CHECK(std::is_sorted(
            setBlockIndexCandidates.begin(), setBlockIndexCandidates.end(), setBlockIndexCandidates.value_comp()));
        BOOST_CHECK_EQUAL(setBlockIndexCandidates.count(&indexW), 1);
        BOOST_CHECK_EQUAL(setBlockIndexCandidates.count(&indexC3), 1);
        BOOST_CHECK_EQUAL(setBlockIndexCandidates.count(&indexC7), 1);
        BOOST_CHECK(std::find(setBlockIndexCandidates.begin(), setBlockIndexCandidates.end(), &indexC5) ==
                    setBlockIndexCandidates.end());

        // remove the test blocks by position, which works even if the set is out of order
        for (auto it = setBlockIndexCandidates.begin(); it != setBlockIndexCandidates.end();)
        {
            if (*it == &indexW || std::count(competitors.begin(), competitors.end(), *it))
                it = setBlockIndexCandidates.erase(it);
            else
                ++it;
        }
        mapBlockIndex.erase(blockW->GetHash());
        for (auto &block : blocks)
            mapBlockIndex.erase(block->GetHash());
    }
}

BOOST_AUTO_TEST_SUITE_END()
