// Copyright (c) 2018-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockrelay/graphene.h"
#include "blockrelay/graphene_set.h"
#include "blockrelay/mempool_sync.h"
#include "bloom.h"
#include "dosman.h"
#include "fastfilter.h"
#include "hashwrapper.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_nexa.h"
#include "tweak.h"

#include <boost/test/unit_test.hpp>
#include <cassert>
#include <chrono>
#include <cmath>
#include <iostream>
#include <iomanip>

#define MAX_GRAPHENE_SET_VERSION 4

extern CTweak<uint64_t> grapheneFastFilterCompatibility;

size_t ProjectedGrapheneSizeBytes(uint64_t version, uint64_t nBlockTxs, uint64_t nExcessTxs, uint64_t nSymDiff, bool computeOptimized=false)
{
    const int SERIALIZATION_OVERHEAD = 11;
    auto fpr = [nExcessTxs](int a) { return a / float(nExcessTxs); };

    CIblt iblt(nSymDiff, CGrapheneSet::GetCIbltVersion(version));
    size_t ibltBytes = ::GetSerializeSize(iblt, SER_NETWORK, PROTOCOL_VERSION) - SERIALIZATION_OVERHEAD;

    size_t filterBytes;
    if (computeOptimized)
    {
        CVariableFastFilter filter(nBlockTxs, fpr(nSymDiff));
        filterBytes = ::GetSerializeSize(filter, SER_NETWORK, PROTOCOL_VERSION) - SERIALIZATION_OVERHEAD;
    }
    else
    {
        CBloomFilter filter(
            nBlockTxs, fpr(nSymDiff), insecure_rand_ctx.rand32(), BLOOM_UPDATE_ALL, true, std::numeric_limits<uint32_t>::max());
        filterBytes = ::GetSerializeSize(filter, SER_NETWORK, PROTOCOL_VERSION) - SERIALIZATION_OVERHEAD;
    }

    return filterBytes + ibltBytes;
}

// Create a deterministic hash by providing an index
uint256 GetHash(unsigned int nIndex)
{
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(32) << nIndex;
    return uint256S(ss.str());
}

BOOST_FIXTURE_TEST_SUITE(graphene_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(graphene_set_encodes_and_decodes)
{
    uint64_t version = MAX_GRAPHENE_SET_VERSION;
    uint256 senderArr[] = {
        SerializeHash(3), SerializeHash(1), SerializeHash(2), SerializeHash(7), SerializeHash(11), SerializeHash(4)};
    std::vector<uint256> senderItems(senderArr, senderArr + sizeof(senderArr) / sizeof(uint256));
    uint256 receiverArr[] = {
        SerializeHash(7), SerializeHash(2), SerializeHash(4), SerializeHash(-1), SerializeHash(1), SerializeHash(11)};
    std::vector<uint256> receiverItems(receiverArr, receiverArr + sizeof(receiverArr) / sizeof(uint256));

    // unordered graphene sets
    {
        CGrapheneSet senderGrapheneSet(6, 6, senderItems, 0, 0, version, 0, false, false, true);
        std::vector<uint64_t> reconciledCheapHashes = senderGrapheneSet.Reconcile(receiverItems);

        std::vector<uint64_t> senderCheapHashes;
        for (uint256 item : senderItems)
            senderCheapHashes.push_back(senderGrapheneSet.GetShortID(item));

        std::sort(senderCheapHashes.begin(), senderCheapHashes.end(), [](uint64_t i1, uint64_t i2) { return i1 < i2; });
        std::sort(reconciledCheapHashes.begin(), reconciledCheapHashes.end(),
            [](uint64_t i1, uint64_t i2) { return i1 < i2; });

        BOOST_CHECK_EQUAL_COLLECTIONS(reconciledCheapHashes.begin(), reconciledCheapHashes.end(),
            senderCheapHashes.begin(), senderCheapHashes.end());
    }

    // ordered graphene sets
    {
        CGrapheneSet senderGrapheneSet(6, 6, senderItems, 0, 0, version, 0, false, true, true);
        std::vector<uint64_t> reconciledCheapHashes = senderGrapheneSet.Reconcile(receiverItems);

        std::vector<uint64_t> senderCheapHashes;
        for (uint256 item : senderItems)
            senderCheapHashes.push_back(senderGrapheneSet.GetShortID(item));

        BOOST_CHECK_EQUAL_COLLECTIONS(reconciledCheapHashes.begin(), reconciledCheapHashes.end(),
            senderCheapHashes.begin(), senderCheapHashes.end());
    }
}

BOOST_AUTO_TEST_CASE(graphene_set_decodes_multiple_sizes)
{
    size_t nItemList[] = {1, 10, 50, 500, 5000, 10000};
    int nNumHashes = 0;
    uint64_t version = MAX_GRAPHENE_SET_VERSION;
    for (size_t nItems : nItemList)
    {
        std::vector<uint256> senderItems;
        std::vector<uint256> baseReceiverItems;
        for (size_t i = 1; i <= nItems; i++)
        {
            nNumHashes++;
            const uint256 &hash = GetHash(nNumHashes);
            senderItems.push_back(hash);
            baseReceiverItems.push_back(hash);
        }

        // Add 10 more items to receiver mempool
        {
            std::vector<uint256> receiverItems = baseReceiverItems;
            for (size_t j = 1; j < 11; j++)
            {
                nNumHashes++;
                receiverItems.push_back(SerializeHash(GetHash(nNumHashes)));
            }

            CGrapheneSet senderGrapheneSet(
                receiverItems.size(), receiverItems.size(), senderItems, 0, 0, version, 0, false, true, true);
            std::vector<uint64_t> reconciledCheapHashes = senderGrapheneSet.Reconcile(receiverItems);

            std::vector<uint64_t> senderCheapHashes;
            for (auto &hash : senderItems)
                senderCheapHashes.push_back(senderGrapheneSet.GetShortID(hash));

            BOOST_CHECK_EQUAL_COLLECTIONS(reconciledCheapHashes.begin(), reconciledCheapHashes.end(),
                senderCheapHashes.begin(), senderCheapHashes.end());
        }

        // Add 100 more items to receiver mempool
        {
            std::vector<uint256> receiverItems = baseReceiverItems;
            for (size_t j = 1; j < 101; j++)
            {
                nNumHashes++;
                receiverItems.push_back(SerializeHash(GetHash(nNumHashes)));
            }

            CGrapheneSet senderGrapheneSet(
                receiverItems.size(), receiverItems.size(), senderItems, 0, 0, version, 0, false, true, true);
            std::vector<uint64_t> reconciledCheapHashes = senderGrapheneSet.Reconcile(receiverItems);

            std::vector<uint64_t> senderCheapHashes;
            for (auto &hash : senderItems)
                senderCheapHashes.push_back(senderGrapheneSet.GetShortID(hash));

            BOOST_CHECK_EQUAL_COLLECTIONS(reconciledCheapHashes.begin(), reconciledCheapHashes.end(),
                senderCheapHashes.begin(), senderCheapHashes.end());
        }
    }
}

BOOST_AUTO_TEST_CASE(graphene_set_finds_brute_force_opt_for_small_blocks)
{
    uint64_t version = MAX_GRAPHENE_SET_VERSION;
    CGrapheneSet grapheneSet(version);

    uint16_t approx_items_thresh = version >= 4 ? APPROX_ITEMS_THRESH_REDUCE_CHECK : APPROX_ITEMS_THRESH;   
    int n = (int)std::floor(approx_items_thresh / 2);
    int mu = 100;
    int m = (int)std::floor(n / 8) + mu;

    int best_a = 1;
    size_t best_size = std::numeric_limits<size_t>::max();
    int a = 1;
    for (a = 1; a < m - mu; a++)
    {
        size_t totalBytes = ProjectedGrapheneSizeBytes(version, n, m - mu, a);
        size_t totalBytesOpt = ProjectedGrapheneSizeBytes(version, n, m - mu, a, true);

        BOOST_CHECK_EQUAL(totalBytes, totalBytesOpt);

        if (totalBytes < best_size)
        {
            best_size = totalBytes;
            best_a = a;
        }
    }

    BOOST_CHECK_EQUAL(grapheneSet.OptimalSymDiff(version, n, m, m - mu, 1), best_a);
}

BOOST_AUTO_TEST_CASE(graphene_set_finds_brute_force_opt_for_large_mempools)
{
    // The brute force search stops early; it must still find the optimum of the full search
    const uint64_t nBlockTxs = 100;
    const uint8_t nChecksumBits = MAX_CHECKSUM_BITS;
    for (uint64_t nReceiverPoolTx : {1000, 50000, 1000000})
    {
        const uint64_t nReceiverExcessTxs = nReceiverPoolTx - nBlockTxs;
        auto T = [&](uint64_t a)
        {
            float fpr = std::min(a / float(nReceiverExcessTxs), FILTER_FPR_MAX);
            double F = floor(FILTER_CELL_SIZE * (-1 / LN2SQUARED * nBlockTxs * log(fpr) / 8));
            uint8_t n_iblt_hash = CIblt::OptimalNHash(a);
            uint64_t padded_cells = (int)(CIblt::OptimalOverhead(a) * a);
            uint64_t cells = n_iblt_hash * int(ceil(padded_cells / float(n_iblt_hash)));
            return F + (nChecksumBits / 8 + IBLT_FIXED_CELL_SIZE) * cells;
        };

        uint64_t best_a = 1;
        double best_T = std::numeric_limits<double>::max();
        for (uint64_t a = 1; a < nReceiverPoolTx; a++)
        {
            if (T(a) < best_T)
            {
                best_T = T(a);
                best_a = a;
            }
        }

        BOOST_CHECK_EQUAL(
            CGrapheneSet::BruteForceSymDiff(nBlockTxs, nReceiverPoolTx, nReceiverExcessTxs, 1, nChecksumBits), best_a);
    }
}

BOOST_AUTO_TEST_CASE(graphene_set_finds_approx_opt_for_large_blocks)
{
    uint64_t version = MAX_GRAPHENE_SET_VERSION;
    uint16_t approx_items_thresh = version >= 4 ? APPROX_ITEMS_THRESH_REDUCE_CHECK : APPROX_ITEMS_THRESH;   
    int n = 4 * approx_items_thresh;
    int mu = 1000;
    int m = approx_items_thresh + mu;
    CGrapheneSet grapheneSet(version);
    double optSymDiff = grapheneSet.OptimalSymDiff(version, n, m, m - mu, 0);
    double fpr = CGrapheneSet::BloomFalsePositiveRate(optSymDiff, m - mu);
    uint8_t checksumBits = CGrapheneSet::NChecksumBits(n * CIblt::OptimalOverhead(n), CIblt::OptimalNHash(n), m, fpr, UNCHECKED_ERROR_TOL);
    auto approxSymDiff = [n, checksumBits]() {
        return std::max(
            1.0, std::round(FILTER_CELL_SIZE * n / ((checksumBits + 8 * IBLT_FIXED_CELL_SIZE) * IBLT_DEFAULT_OVERHEAD * LN2SQUARED)));
    };

    BOOST_CHECK_EQUAL(approxSymDiff(), optSymDiff);
}

BOOST_AUTO_TEST_CASE(graphene_set_approx_opt_close_to_optimal)
{
    for (uint64_t version=0; version < MAX_GRAPHENE_SET_VERSION; version++)
    {
        int n = version >= 4 ? APPROX_ITEMS_THRESH_REDUCE_CHECK : APPROX_ITEMS_THRESH;
        int mu = 100;
        int m = (int)std::ceil(n / APPROX_EXCESS_RATE) + mu;
        CGrapheneSet grapheneSet(version);

        float totalBytesApprox = (float)ProjectedGrapheneSizeBytes(version, n, m - mu, CGrapheneSet::ApproxOptimalSymDiff(version, n));
        float totalBytesBrute =
            (float)ProjectedGrapheneSizeBytes(version, n, m - mu, grapheneSet.BruteForceSymDiff(n, m, m - mu, MAX_CHECKSUM_BITS));
        float totalBytesBruteOpt =
            (float)ProjectedGrapheneSizeBytes(version, n, m - mu, grapheneSet.BruteForceSymDiff(n, m, m - mu, MAX_CHECKSUM_BITS), true);

        BOOST_CHECK_CLOSE(totalBytesApprox, totalBytesBrute, 15);
        BOOST_CHECK_CLOSE(totalBytesApprox, totalBytesBruteOpt, 15);
    }
}

BOOST_AUTO_TEST_CASE(graphene_set_optimization_params_any_receiver_count)
{
    // The receiver count comes from the peer and used to be truncated to int
    const uint64_t counts[] = {0, 1, 1ULL << 16, (1ULL << 31) - 1, 1ULL << 31, 1ULL << 32, (1ULL << 32) + 5, 1ULL << 63,
        std::numeric_limits<uint64_t>::max()};
    const uint64_t nItemsList[] = {5, 4 * (uint64_t)APPROX_ITEMS_THRESH};
    for (uint64_t nReceiverUniverseItems : counts)
    {
        for (uint64_t nItems : nItemsList)
        {
            for (uint64_t version = 0; version <= MAX_GRAPHENE_SET_VERSION; version++)
            {
                GrapheneSetOptimizationParams params =
                    CGrapheneSet::DetermineGrapheneSetOptimizationParams(nReceiverUniverseItems, 100, nItems, version);
                BOOST_CHECK(params.nReceiverExcessItems <= nReceiverUniverseItems);
                BOOST_CHECK(params.nReceiverMissingItems >= 1 && params.nReceiverMissingItems <= nItems);
            }
        }
    }

    // In range values give the same result as before
    GrapheneSetOptimizationParams params =
        CGrapheneSet::DetermineGrapheneSetOptimizationParams(1000, 100, 5, MAX_GRAPHENE_SET_VERSION);
    BOOST_CHECK_EQUAL(params.nReceiverExcessItems, 995);
    BOOST_CHECK_EQUAL(params.nReceiverMissingItems, 1);
    params = CGrapheneSet::DetermineGrapheneSetOptimizationParams(10, 100, 50, MAX_GRAPHENE_SET_VERSION);
    BOOST_CHECK_EQUAL(params.nReceiverExcessItems, 10);
    BOOST_CHECK_EQUAL(params.nReceiverMissingItems, 50);

    // Building a set and a recovery IBLT for such counts must not abort
    std::vector<uint256> items;
    std::set<uint64_t> cheapHashes;
    for (unsigned int i = 1; i <= 5; i++)
    {
        items.push_back(GetHash(i));
        cheapHashes.insert(GetHash(i).GetCheapHash());
    }
    CGrapheneSet grapheneSet(1ULL << 31, 100, items, 0, 0, MAX_GRAPHENE_SET_VERSION, 0, false, true, true);
    CIblt iblt = grapheneSet.FailureRecoveryIblt(cheapHashes, items.size(), 1ULL << 31, 1000,
        FAILURE_RECOVERY_SUCCESS_RATE, 0.001, CGrapheneBlock::GetGrapheneSetVersion(GRAPHENE_MAX_VERSION_SUPPORTED), 3);
    BOOST_CHECK(iblt.size() > 0);
}

BOOST_AUTO_TEST_CASE(graphene_set_decodes_empty_intersection)
{
    uint64_t version = MAX_GRAPHENE_SET_VERSION;
    uint256 senderArr[] = {SerializeHash(-7), SerializeHash(-2), SerializeHash(-4), SerializeHash(-1),
        SerializeHash(-5), SerializeHash(-11), SerializeHash(3), SerializeHash(1), SerializeHash(2), SerializeHash(7),
        SerializeHash(11), SerializeHash(4)};
    std::vector<uint256> senderItems(senderArr, senderArr + sizeof(senderArr) / sizeof(uint256));

    // includes no transactions from block
    uint256 receiverArr[] = {SerializeHash(-7), SerializeHash(-2), SerializeHash(-4), SerializeHash(-1),
        SerializeHash(-5), SerializeHash(-11)};
    std::vector<uint256> receiverItems(receiverArr, receiverArr + sizeof(receiverArr) / sizeof(uint256));

    CGrapheneSet senderGrapheneSet(6, 12, senderItems, 0, 0, version, 0, false, true, true);
    std::vector<uint64_t> reconciledCheapHashes = senderGrapheneSet.Reconcile(receiverItems);

    std::vector<uint64_t> senderCheapHashes;
    for (uint256 item : senderItems)
        senderCheapHashes.push_back(senderGrapheneSet.GetShortID(item));

    BOOST_CHECK_EQUAL_COLLECTIONS(
        reconciledCheapHashes.begin(), reconciledCheapHashes.end(), senderCheapHashes.begin(), senderCheapHashes.end());
}

BOOST_AUTO_TEST_CASE(graphene_set_can_serde)
{
    uint64_t version = MAX_GRAPHENE_SET_VERSION;
    std::vector<uint256> senderItems;
    CDataStream ss(SER_DISK, 0);

    senderItems.push_back(SerializeHash(3));
    CGrapheneSet sentGrapheneSet(1, 1, senderItems, 0, 0, version, 0, false, false, true);
    CGrapheneSet receivedGrapheneSet(version);

    ss << sentGrapheneSet;
    ss >> receivedGrapheneSet;

    BOOST_CHECK_EQUAL(receivedGrapheneSet.Reconcile(senderItems)[0], sentGrapheneSet.GetShortID(senderItems[0]));
}

BOOST_AUTO_TEST_CASE(graphene_set_version_check)
{
    for (uint64_t version = 0; version <= MAX_GRAPHENE_SET_VERSION; version++)
    {
        std::vector<uint256> senderItems;
        CDataStream ss(SER_DISK, 0);

        senderItems.push_back(SerializeHash(1));
        senderItems.push_back(SerializeHash(2));
        senderItems.push_back(SerializeHash(3));
        CGrapheneSet sentGrapheneSet(3, 3, senderItems, 0, 0, version, false, false, true);
        CGrapheneSet receivedGrapheneSet(version);

        ss << sentGrapheneSet;
        ss >> receivedGrapheneSet;
    }
}

BOOST_AUTO_TEST_CASE(item_rank_encodes_and_decodes)
{
    uint64_t itemArr[4] = {1, 20, 500, 7000};
    std::vector<uint64_t> inputItems(itemArr, itemArr + sizeof(itemArr) / sizeof(uint64_t));
    uint16_t nBits = 13;

    std::vector<unsigned char> encoded = CGrapheneSet::EncodeRank(inputItems, nBits);
    std::vector<uint64_t> outputItems = CGrapheneSet::DecodeRank(encoded, inputItems.size(), nBits);

    BOOST_CHECK_EQUAL_COLLECTIONS(outputItems.begin(), outputItems.end(), inputItems.begin(), inputItems.end());
}

BOOST_AUTO_TEST_CASE(item_rank_padding_is_zero)
{
    // 3 bits in one byte, the 5 padding bits must not carry heap contents
    std::vector<unsigned char> encoded = CGrapheneSet::EncodeRank({5}, 3);
    BOOST_CHECK_EQUAL(encoded.size(), 1);
    BOOST_CHECK_EQUAL(encoded[0], 5);
}

BOOST_AUTO_TEST_CASE(graphene_set_rejects_invalid_item_rank)
{
    uint64_t version = MAX_GRAPHENE_SET_VERSION;
    std::vector<uint256> items;
    for (int i = 0; i < 5; i++)
        items.push_back(SerializeHash(i));
    CGrapheneSet senderGrapheneSet(5, 5, items, 0, 0, version, 0, false, true, true);

    std::set<uint64_t> receiverSet;
    CIblt localIblt(*senderGrapheneSet.GetIblt());
    localIblt.reset();
    std::vector<uint64_t> senderCheapHashes;
    for (const uint256 &item : items)
    {
        uint64_t cheapHash = senderGrapheneSet.GetShortID(item);
        senderCheapHashes.push_back(cheapHash);
        receiverSet.insert(cheapHash);
        localIblt.insert(cheapHash, IBLT_NULL_VALUE);
    }
    auto reconcile = [&](const std::vector<unsigned char> &encodedRank)
    { return CGrapheneSet::Reconcile(receiverSet, localIblt, senderGrapheneSet.GetIblt(), encodedRank, true); };

    std::vector<unsigned char> encodedRank = senderGrapheneSet.GetEncodedRank();
    std::vector<uint64_t> reconciled = reconcile(encodedRank);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        reconciled.begin(), reconciled.end(), senderCheapHashes.begin(), senderCheapHashes.end());

    // 5 items use 3-bit ranks, so ranks 5 to 7 are encodable but out of range
    BOOST_CHECK_THROW(reconcile(CGrapheneSet::EncodeRank({0, 1, 2, 3, 7}, 3)), std::runtime_error);
    BOOST_CHECK_THROW(reconcile(CGrapheneSet::EncodeRank({0, 1, 2, 3, 3}, 3)), std::runtime_error);

    std::vector<unsigned char> shortRank(encodedRank.begin(), encodedRank.end() - 1);
    BOOST_CHECK_THROW(reconcile(shortRank), std::runtime_error);
    BOOST_CHECK_THROW(reconcile(std::vector<unsigned char>()), std::runtime_error);
    std::vector<unsigned char> longRank(encodedRank);
    longRank.push_back(0);
    BOOST_CHECK_THROW(reconcile(longRank), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(item_rank_size_is_exact_for_large_sets)
{
    // 21 * 1048589 bits is not exactly representable as a float, which used to size the
    // encoding one byte short and let decoding read past the end of its bit array.
    const size_t nItems = 1048589;
    const uint16_t nBits = 21;
    std::vector<uint64_t> items(nItems);
    for (size_t i = 0; i < nItems; i++)
        items[i] = nItems - 1 - i;

    std::vector<unsigned char> encoded = CGrapheneSet::EncodeRank(items, nBits);
    BOOST_CHECK_EQUAL(encoded.size(), (nBits * nItems + 7) / 8);
    BOOST_CHECK(CGrapheneSet::DecodeRank(encoded, nItems, nBits) == items);

    encoded.pop_back();
    BOOST_CHECK_THROW(CGrapheneSet::DecodeRank(encoded, nItems, nBits), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(compute_optimized_graphene_set_can_serde)
{
    uint64_t version = MAX_GRAPHENE_SET_VERSION;
    std::vector<uint256> senderItems;
    CDataStream ss(SER_DISK, 0);

    senderItems.push_back(SerializeHash(3));
    CGrapheneSet sentGrapheneSet(1, 1, senderItems, 0, 0, version, 0, true, false, true);
    CGrapheneSet receivedGrapheneSet(version, true);

    ss << sentGrapheneSet;
    ss >> receivedGrapheneSet;

    BOOST_CHECK_EQUAL(receivedGrapheneSet.Reconcile(senderItems)[0], sentGrapheneSet.GetShortID(senderItems[0]));
}

BOOST_AUTO_TEST_CASE(graphene_set_cpu_check)
{
    size_t nItems = 10000;
    int nNumHashes = 0;

    std::vector<uint256> senderItems;
    std::vector<uint64_t> senderCheapHashes;
    std::vector<uint256> baseReceiverItems;
    for (size_t i = 1; i <= nItems; i++)
    {
        nNumHashes++;
        const uint256 &hash = GetHash(nNumHashes);
        senderItems.push_back(hash);
        senderCheapHashes.push_back(hash.GetCheapHash());
        baseReceiverItems.push_back(hash);
    }

    // Add 10000 more items to receiver mempool
    std::vector<uint256> receiverItems = baseReceiverItems;
    for (size_t j = 1; j < 10000; j++)
    {
        nNumHashes++;
        receiverItems.push_back(SerializeHash(GetHash(nNumHashes)));
    }

    auto legacyStart = std::chrono::high_resolution_clock::now();
    CGrapheneSet legacyGrapheneSet(
        receiverItems.size(), receiverItems.size(), senderItems, 0, 0, 0, 0, false, false, true);
    legacyGrapheneSet.Reconcile(receiverItems);
    auto legacyFinish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> legacyElapsed = legacyFinish - legacyStart;
    std::cout << "Legacy elapsed time: " << legacyElapsed.count() << " s\n";

    auto sipStart = std::chrono::high_resolution_clock::now();
    CGrapheneSet sipGrapheneSet(
        receiverItems.size(), receiverItems.size(), senderItems, 0, 0, MAX_GRAPHENE_SET_VERSION, 0, false, false, true);
    sipGrapheneSet.Reconcile(receiverItems);
    auto sipFinish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> sipElapsed = sipFinish - sipStart;
    std::cout << "Sip elapsed time: " << sipElapsed.count() << " s\n";

    auto fastStart = std::chrono::high_resolution_clock::now();
    CGrapheneSet fastGrapheneSet(
        receiverItems.size(), receiverItems.size(), senderItems, 0, 0, MAX_GRAPHENE_SET_VERSION, 0, true, false, true);
    fastGrapheneSet.Reconcile(receiverItems);
    auto fastFinish = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> fastElapsed = fastFinish - fastStart;
    std::cout << "Fast elapsed time: " << fastElapsed.count() << " s\n";
}

BOOST_AUTO_TEST_CASE(graphene_block_can_serde)
{
    uint64_t version = GRAPHENE_MAX_VERSION_SUPPORTED;
    // regular graphene block
    {
        CBlock block;
        CTransaction tx;
        CDataStream stream(
            ParseHex("01000000010b26e9b7735eb6aabdf358bab62f9816a21ba9ebdb719d5299e88607d722c190000000008b4830450220070aca4"
                     "4506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b864"
                     "3ac4cb7cb3c462aced7f14711a0141046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eee"
                     "f87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339ffffffff021bff3d11000000001976a91404943fdd"
                     "508053c75000106d3bc6e2754dbcff1988ac2f15de00000000001976a914a266436d2965547608b9e15d9032a7b9d64fa4318"
                     "8ac00000000"),
            SER_DISK, CLIENT_VERSION);
        stream >> tx;
        const CTransactionRef ptx = MakeTransactionRef(tx);
        block.vtx.push_back(ptx);
        CGrapheneBlock senderGrapheneBlock(MakeBlockRef(block), 5, 6, version, false);
        CGrapheneBlock receiverGrapheneBlock(4);
        CDataStream ss(SER_DISK, 0);

        ss << senderGrapheneBlock;
        ss >> receiverGrapheneBlock;
    }
    
    // compute optimized graphene block
    {
        CBlock block;
        CTransaction tx;
        CDataStream stream(
            ParseHex("01000000010b26e9b7735eb6aabdf358bab62f9816a21ba9ebdb719d5299e88607d722c190000000008b4830450220070aca4"
                     "4506c5cef3a16ed519d7c3c39f8aab192c4e1c90d065f37b8a4af6141022100a8e160b856c2d43d27d8fba71e5aef6405b864"
                     "3ac4cb7cb3c462aced7f14711a0141046d11fee51b0e60666d5049a9101a72741df480b96ee26488a4d3466b95c9a40ac5eee"
                     "f87e10a5cd336c19a84565f80fa6c547957b7700ff4dfbdefe76036c339ffffffff021bff3d11000000001976a91404943fdd"
                     "508053c75000106d3bc6e2754dbcff1988ac2f15de00000000001976a914a266436d2965547608b9e15d9032a7b9d64fa4318"
                     "8ac00000000"),
            SER_DISK, CLIENT_VERSION);
        stream >> tx;
        const CTransactionRef ptx = MakeTransactionRef(tx);
        block.vtx.push_back(ptx);
        CGrapheneBlock senderGrapheneBlock(MakeBlockRef(block), 5, 6, version, true);
        CGrapheneBlock receiverGrapheneBlock(4, true);
        CDataStream ss(SER_DISK, 0);

        ss << senderGrapheneBlock;
        ss >> receiverGrapheneBlock;
    }
}

BOOST_AUTO_TEST_CASE(nchecksumbits_gives_correct_value)
{
    double tol = 1 / std::pow(2, 11); 
    uint8_t bits = CGrapheneSet::NChecksumBits(10, 2, 1, 0.5, tol);

    BOOST_CHECK_EQUAL(bits, 11);
}

BOOST_AUTO_TEST_CASE(graphene_failure_recovery_primitives)
{
    size_t nItems = 100;
    int nNumHashes = 0;
    uint64_t grapheneSetVersion = CGrapheneBlock::GetGrapheneSetVersion(GRAPHENE_MAX_VERSION_SUPPORTED);
    uint32_t ibltSalt = 3;

    std::vector<uint256> senderItems;
    std::set<uint64_t> senderCheapHashes;
    std::vector<uint256> baseReceiverItems;
    for (size_t i = 1; i <= nItems; i++)
    {
        nNumHashes++;
        const uint256 &hash = GetHash(nNumHashes);
        senderItems.push_back(hash);
        senderCheapHashes.insert(hash.GetCheapHash());
        baseReceiverItems.push_back(hash);
    }

    // Add 10000 more items to receiver mempool
    std::vector<uint256> receiverItems = baseReceiverItems;
    for (size_t j = 1; j < 10000; j++)
    {
        nNumHashes++;
        receiverItems.push_back(SerializeHash(GetHash(nNumHashes)));
    }

    CGrapheneSet fastGrapheneSet(
        receiverItems.size(), receiverItems.size(), senderItems, 0, 0, MAX_GRAPHENE_SET_VERSION, 0, true, false, true);
    fastGrapheneSet.Reconcile(receiverItems);

    uint64_t nPassedFilterItems = 12;
    uint64_t nReceiverUniverseItems = 200;
    double fSenderBloomFpr = 1.0;

	CVariableFastFilter receiverFilter = fastGrapheneSet.FailureRecoveryFilter(senderItems, nItems, nPassedFilterItems, nReceiverUniverseItems, FAILURE_RECOVERY_SUCCESS_RATE, fSenderBloomFpr, grapheneSetVersion);
    CIblt recoveryIblt = fastGrapheneSet.FailureRecoveryIblt(senderCheapHashes, nItems, nPassedFilterItems, nReceiverUniverseItems, FAILURE_RECOVERY_SUCCESS_RATE, fSenderBloomFpr, grapheneSetVersion, ibltSalt);
}

BOOST_AUTO_TEST_CASE(graphene_failure_recovery_params_sanity)
{
    // exmple from https://github.com/bissias/graphene-experiments/blob/master/jupyter/graphene_v2_param_estimates.ipynb
    // variable names are from graphene paper https://people.cs.umass.edu/~gbiss/graphene.sigcomm.pdf
    uint64_t z = 10; 
    uint64_t n = 10; 
    uint64_t m = 20; 
    double f_S = 0.1; 
    double beta = 0.9;
    uint64_t x_star_desired = 4;
    uint64_t y_star_desired = 5;

    uint64_t x_star_actual = CGrapheneSet::LowerBoundTruePositives(n, z, m, f_S, beta);
    uint64_t y_star_actual = CGrapheneSet::UpperBoundFalsePositives(n, z, m, f_S, beta);

    BOOST_CHECK_EQUAL(x_star_desired, x_star_actual);
    BOOST_CHECK_EQUAL(y_star_desired, y_star_actual);
}

// A Graphene set whose regular Bloom filter claims nHashFuncs hash functions
static CDataStream GrapheneSetWithFilterHashes(unsigned int nHashFuncs)
{
    std::vector<uint256> senderItems = {SerializeHash(3)};
    CGrapheneSet sentGrapheneSet(1, 1, senderItems, 0, 0, MAX_GRAPHENE_SET_VERSION, 0, false, false, true);
    CDataStream filter(SER_NETWORK, PROTOCOL_VERSION);
    filter << std::vector<unsigned char>(8, 0x55) << nHashFuncs << (unsigned int)0 << (unsigned char)0;
    filter >> *sentGrapheneSet.GetRegularFilter();
    CDataStream ss(SER_DISK, 0);
    ss << sentGrapheneSet;
    return ss;
}

BOOST_AUTO_TEST_CASE(graphene_set_with_too_many_filter_hashes_is_rejected)
{
    CGrapheneSet received(MAX_GRAPHENE_SET_VERSION);
    CDataStream ok = GrapheneSetWithFilterHashes(MAX_HASH_FUNCS);
    BOOST_CHECK_NO_THROW(ok >> received);
    CDataStream tooMany = GrapheneSetWithFilterHashes(MAX_HASH_FUNCS + 1);
    BOOST_CHECK_THROW(tooMany >> received, std::runtime_error);

    // The filter we build for the smallest false positive rate a sender can choose stays within the limit
    for (unsigned int nItems : {1, 2, 3, 10, 1000})
    {
        CBloomFilter filter(
            nItems, 1.0 / LARGE_MEM_POOL_SIZE, 0, BLOOM_UPDATE_ALL, true, std::numeric_limits<uint32_t>::max());
        BOOST_CHECK_LE(filter.NumHashFuncs(), MAX_HASH_FUNCS);
    }
}

BOOST_FIXTURE_TEST_CASE(graphene_recovery_response_must_be_requested, TestingSetup)
{
    CAddress addr(ipaddress(0xa0b0c001, 10000));
    CNode node(INVALID_SOCKET, addr, "", true);
    SetConnected(node);
    node.negotiatedGrapheneVersion = 4;

    const CBlock block = TestBlock1();
    const uint256 hash = block.GetHash();
    auto pblock = thinrelay.SetBlockToReconstruct(&node, hash);
    *((CBlockHeader *)pblock.get()) = block.GetBlockHeader();
    pblock->grapheneblock = std::make_shared<CGrapheneBlock>(MakeBlockRef(CBlock(block)), 1, 1, 4, false);

    CGrapheneReceiverRecover response;
    response.blockhash = hash;
    response.pRevisedIblt = std::make_shared<CIblt>(1, CGrapheneSet::GetCIbltVersion(4));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << response;

    // Nothing was requested: ignored, and the block is still being reconstructed
    CDataStream unrequested(ss);
    BOOST_CHECK(!HandleGrapheneBlockRecoveryResponse(unrequested, &node, Params()));
    BOOST_CHECK(thinrelay.GetBlockToReconstruct(&node, hash) == pblock);

    // A request allows one response. Reconstructing this synthetic block can throw, as ProcessMessage expects.
    pblock->grapheneblock->fRecoveryRequested = true;
    CDataStream requested(ss);
    try
    {
        HandleGrapheneBlockRecoveryResponse(requested, &node, Params());
    }
    catch (const std::exception &)
    {
    }
    BOOST_CHECK(!pblock->grapheneblock->fRecoveryRequested);

    thinrelay.ClearAllBlockData(&node, hash);
}

// Exposes n_hash so a test can build an IBLT no honest sender would
class CIbltWithNHash : public CIblt
{
public:
    CIbltWithNHash(const CIblt &iblt) : CIblt(iblt) {}
    void SetNHash(uint8_t n) { n_hash = n; }
};

static void SetTooManyIbltHashes(CIblt &iblt)
{
    CIbltWithNHash bad(iblt);
    bad.SetNHash(CIblt::MaxNHash() + 1);
    iblt = bad;
}

BOOST_FIXTURE_TEST_CASE(graphene_set_outside_limits_penalises_sender, TestingSetup)
{
    const CBlock block = TestBlock1();
    const uint64_t prevFilterCompatibility = grapheneFastFilterCompatibility.Value();
    grapheneFastFilterCompatibility.Set(UniValue((uint64_t)REGULAR));

    // A Graphene block whose regular Bloom filter has too many hash functions
    {
        CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c002, 10000)), "", true);
        SetConnected(node);
        node.negotiatedGrapheneVersion = 4;
        CGrapheneBlock grapheneBlock(MakeBlockRef(CBlock(block)), 1, 1, 4, false);
        CDataStream filter(SER_NETWORK, PROTOCOL_VERSION);
        filter << std::vector<unsigned char>(8, 0x55) << (unsigned int)(MAX_HASH_FUNCS + 1) << (unsigned int)0
               << (unsigned char)0;
        filter >> *grapheneBlock.pGrapheneSet->GetRegularFilter();
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << grapheneBlock;
        BOOST_CHECK_NO_THROW(CGrapheneBlock::HandleMessage(ss, &node, 0, NetMsgType::GRAPHENEBLOCK, 0));
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 20);
    }

    // A Graphene block whose IBLT has too many hash functions
    {
        CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c003, 10000)), "", true);
        SetConnected(node);
        node.negotiatedGrapheneVersion = 4;
        CGrapheneBlock grapheneBlock(MakeBlockRef(CBlock(block)), 1, 1, 4, false);
        SetTooManyIbltHashes(*grapheneBlock.pGrapheneSet->GetIblt());
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << grapheneBlock;
        BOOST_CHECK_NO_THROW(CGrapheneBlock::HandleMessage(ss, &node, 0, NetMsgType::GRAPHENEBLOCK, 0));
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 20);
    }

    // A recovery response whose revised IBLT has too many hash functions
    {
        CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c004, 10000)), "", true);
        SetConnected(node);
        CGrapheneReceiverRecover response;
        response.blockhash = block.GetHash();
        response.pRevisedIblt = std::make_shared<CIblt>(1, CGrapheneSet::GetCIbltVersion(4));
        SetTooManyIbltHashes(*response.pRevisedIblt);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << response;
        BOOST_CHECK_NO_THROW(HandleGrapheneBlockRecoveryResponse(ss, &node, Params()));
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 20);
    }

    // A mempool sync whose IBLT has too many hash functions
    {
        CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c005, 10000)), "", true);
        SetConnected(node);
        CMempoolSync mempoolSync({SerializeHash(3)}, 1, 1, 0, 0, 0);
        SetTooManyIbltHashes(*mempoolSync.pGrapheneSet->GetIblt());
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << mempoolSync;
        BOOST_CHECK_NO_THROW(CMempoolSync::ReceiveMempoolSync(ss, &node, NetMsgType::MEMPOOLSYNC));
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 20);
    }

    grapheneFastFilterCompatibility.Set(UniValue(prevFilterCompatibility));
    dosMan.ClearBanned();
}

BOOST_FIXTURE_TEST_CASE(fast_filter_outside_limits_penalises_sender, TestingSetup)
{
    const CBlock block = TestBlock1();

    // A Graphene block whose fast filter claims more bits than its data holds
    {
        CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c006, 10000)), "", true);
        SetConnected(node);
        node.negotiatedGrapheneVersion = 4;
        CGrapheneBlock grapheneBlock(MakeBlockRef(CBlock(block)), 1, 1, 4, true);
        auto filter = grapheneBlock.pGrapheneSet->GetFastFilter();
        filter->nFilterBits = 8 * filter->nFilterBytes + 8;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << grapheneBlock;
        BOOST_CHECK_NO_THROW(CGrapheneBlock::HandleMessage(ss, &node, 0, NetMsgType::GRAPHENEBLOCK, 0));
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 20);
    }

    // A recovery request whose fast filter has too many hash functions
    {
        CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c007, 10000)), "", true);
        SetConnected(node);
        CRequestGrapheneReceiverRecover request;
        request.pReceiverFilter = std::make_shared<CVariableFastFilter>(1, 0.1);
        request.pReceiverFilter->nHashFuncs = MAX_N_HASH_FUNC + 1;
        request.nSenderFilterPositives = 1;
        request.blockhash = block.GetHash();
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << request;
        BOOST_CHECK_NO_THROW(HandleGrapheneBlockRecoveryRequest(ss, &node, 0, Params()));
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 20);
    }

    // A mempool sync whose fast filter claims more bits than its data holds
    {
        CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c008, 10000)), "", true);
        SetConnected(node);
        CMempoolSync mempoolSync({SerializeHash(3)}, 1, 1, 0, 0, 0);
        auto filter = mempoolSync.pGrapheneSet->GetFastFilter();
        filter->nFilterBits = 8 * filter->nFilterBytes + 8;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << mempoolSync;
        BOOST_CHECK_NO_THROW(CMempoolSync::ReceiveMempoolSync(ss, &node, NetMsgType::MEMPOOLSYNC));
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 20);
    }

    // A Graphene block cut short, like any other message that fails to deserialize
    {
        CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c009, 10000)), "", true);
        SetConnected(node);
        node.negotiatedGrapheneVersion = 4;
        CGrapheneBlock grapheneBlock(MakeBlockRef(CBlock(block)), 1, 1, 4, true);
        CDataStream full(SER_NETWORK, PROTOCOL_VERSION);
        full << grapheneBlock;
        CDataStream ss(full.begin(), full.begin() + full.size() / 2, SER_NETWORK, PROTOCOL_VERSION);
        BOOST_CHECK_NO_THROW(CGrapheneBlock::HandleMessage(ss, &node, 0, NetMsgType::GRAPHENEBLOCK, 0));
        BOOST_CHECK_EQUAL(node.nMisbehavior.load(), 20);
    }

    dosMan.ClearBanned();
}

BOOST_AUTO_TEST_SUITE_END()
