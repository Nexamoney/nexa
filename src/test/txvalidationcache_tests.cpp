// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockstorage/blockstorage.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "daa.h"
#include "dosman.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "nodestate.h"
#include "pubkey.h"
#include "random.h"
#include "requestManager.h"
#include "script/sighashtype.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_nexa.h"
#include "threadgroup.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "utiltime.h"
#include "validation/forks.h"
#include "validation/parallel.h"
#include "validation/validation.h"

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>

extern CTweak<uint32_t> minRelayFee;
extern void LimitMempoolSize(CTxMemPool &pool, size_t limit, unsigned long age);
extern CRollingFastFilter<32 * 1024 * 1024> filterTransactionKnown;

BOOST_AUTO_TEST_SUITE(txvalidationcache_tests) // BU harmonize suite name with filename

static bool ToMemPool(CMutableTransaction &tx, std::string rejectReason = "")
{
    CValidationState state;
    bool fMissingInputs = false;
    bool ret = false;
    ret = AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx), false, &fMissingInputs, false);

    if (rejectReason != "")
    {
        if (rejectReason != state.GetRejectReason())
        {
            printf("break here to debug\n");
        }
        BOOST_CHECK_EQUAL(rejectReason, state.GetRejectReason());
    }
    return ret;
}

BOOST_FIXTURE_TEST_CASE(tx_mempool_block_doublespend, TestChain100Setup)
{
    // Make sure skipping validation of transctions that were
    // validated going into the memory pool does not allow
    // double-spends in blocks to pass validation when they should not.

    // Create a double-spend of mature coinbase txn:
    std::vector<CMutableTransaction> spends;
    spends.resize(2);
    for (int i = 0; i < 2; i++)
    {
        spends[i].vin.resize(1);
        spends[i].vin[0] = coinbaseTxns[0].SpendOutput(0);
        spends[i].vout.resize(1);
        spends[i].vout[0].nValue = 11 * CENT;
        spends[i].vout[0].scriptPubKey = coinbaseLockingScript; // just any valid output
        spends[i].vin[0].scriptSig =
            SignCoinbaseSpend(spends[i], 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);
    }

    CBlock block;

    // Test 1: block with both of those transactions should be rejected.
    block = CreateAndProcessBlock(spends, coinbaseLockingScript);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());

    // Test 2: ... and should be rejected if spend1 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[0]));
    block = CreateAndProcessBlock(spends, coinbaseLockingScript);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());
    mempool.clear();

    // Test 3: ... and should be rejected if spend2 is in the memory pool
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(spends, coinbaseLockingScript);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != block.GetHash());
    mempool.clear();

    // Final sanity test: first spend in mempool, second in block, that's OK:
    std::vector<CMutableTransaction> oneSpend;
    oneSpend.push_back(spends[0]);
    BOOST_CHECK(ToMemPool(spends[1]));
    block = CreateAndProcessBlock(oneSpend, coinbaseLockingScript);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
    // spends[1] should have been removed from the mempool when the
    // block with spends[0] is accepted:
    BOOST_CHECK_EQUAL(mempool.size(), 0UL);
    mempool.clear();
}

BOOST_FIXTURE_TEST_CASE(cache_configuration, TestChain100Setup)
{
    // check that default values are returned
    CacheConfig cacheConfig1 = DiscoverCacheConfiguration(true);
    BOOST_CHECK(cacheConfig1.nBlockTreeDBCache == 2097152);
    BOOST_CHECK(cacheConfig1.nTxIndexCache == 0);
    BOOST_CHECK(cacheConfig1.nCoinDBCache == 73662464);
    BOOST_CHECK(nCoinCacheMaxSize == 448528384);

    // Check non-default values are returned
    CacheConfig cacheConfig2 = DiscoverCacheConfiguration();
    BOOST_CHECK(cacheConfig2.nBlockTreeDBCache == 655360);
    BOOST_CHECK(cacheConfig2.nTxIndexCache == 0);
    BOOST_CHECK(cacheConfig2.nCoinDBCache == 1146880);
    BOOST_CHECK(nCoinCacheMaxSize == 3440640);

    // check settings when txindex is on
    bool nTemp = fTxIndex;
    fTxIndex = true;
    cacheConfig1 = DiscoverCacheConfiguration(true);
    BOOST_CHECK(cacheConfig1.nBlockTreeDBCache == 2097152);
    BOOST_CHECK(cacheConfig1.nTxIndexCache == 36831232);
    BOOST_CHECK(cacheConfig1.nCoinDBCache == 36831232);
    BOOST_CHECK(nCoinCacheMaxSize == 448528384);

    // Check non-default values are returned
    cacheConfig2 = DiscoverCacheConfiguration();
    BOOST_CHECK(cacheConfig2.nBlockTreeDBCache == 655360);
    BOOST_CHECK(cacheConfig2.nTxIndexCache == 573440);
    BOOST_CHECK(cacheConfig2.nCoinDBCache == 573440);
    BOOST_CHECK(nCoinCacheMaxSize == 3440640);

    // Cleanup
    fTxIndex = nTemp;
}

BOOST_FIXTURE_TEST_CASE(uncache_coins, TestChain100Setup)
{
    int64_t nStartTime = GetTime();
    {
        WRITELOCK(orphanpool.cs_orphanpool);
        orphanpool._SetLastOrphanCheck(nStartTime);
    }
    SetMockTime(nStartTime); // Overrides future calls to GetTime()

    mempool.clear();
    pcoinsTip->Flush();

    bool fSpent = false;

    // Make sure coins are uncached when txns are not accepted into the memory pool
    // and also verify they are uncached when orphans or txns are evicted from either the
    // orphan cache or the transaction memory pool.

    std::vector<CMutableTransaction> spends;

    // Add valid txns to the memory pool.  The coins should be present in the coins cache.
    spends.resize(1);
    spends[0].vin.resize(1);
    spends[0].vin[0] = coinbaseTxns[0].SpendOutput(0);
    spends[0].vout.resize(1);
    spends[0].vout[0].nValue = 11 * CENT;
    spends[0].vout[0].scriptPubKey = coinbaseLockingScript;

    // Sign:
    spends[0].vin[0].scriptSig = SignCoinbaseSpend(spends[0], 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);

    BOOST_CHECK(ToMemPool(spends[0]));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent));
    BOOST_CHECK(fSpent == false);

    // Try to add the same tx to the memory pool. The coins should still be present.
    BOOST_CHECK(!ToMemPool(spends[0], "txn-already-in-mempool"));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent));
    BOOST_CHECK(fSpent == false);

    // Try to add an invalid txn to the memory pool.  The coins for the previous txn should
    // still be present and but the coins from the rejected txn should not be present.
    spends.resize(2);
    spends[1].vin.resize(1);
    spends[1].vin[0] = coinbaseTxns[1].SpendOutput(0);
    spends[1].vout.resize(1);
    spends[1].vout[0].nValue = 11 * CENT;
    spends[1].vout[0].scriptPubKey = coinbaseLockingScript;

    // Sign:
    std::vector<unsigned char> vchSig2;
    uint256 hash2 =
        SignatureHash(coinbaseLockingScript, spends[1], 0, defaultSigHashType, coinbaseTxns[1].vout[0].nValue, 0);
    BOOST_CHECK(hash2 != SIGNATURE_HASH_ERROR);
    BOOST_CHECK(coinbaseKey.SignSchnorr(hash2, vchSig2));
    defaultSigHashType.appendToSig(vchSig2);
    spends[1].vin[0].scriptSig << vchSig2 << ToByteVector(coinbaseKey.GetPubKey());

    BOOST_CHECK(!ToMemPool(spends[1], "bad-txns-premature-spend-of-coinbase"));
    // not uncached because from a previous txn
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent));
    BOOST_CHECK(fSpent == false);
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[1].vin[0].prevout, fSpent));

    // Add an orphan to the orphan cache.  The valid inputs should be present in the coins cache.
    spends.resize(3);
    spends[2].vin.resize(3);
    spends[2].vin[2].prevout.hash = InsecureRand256();
    spends[2].vin[2].amount = 10000000; // Arbitrary amount for this fake input
    spends[2].vin[1].prevout.hash = InsecureRand256();
    spends[2].vin[1].amount = 10000000; // Arbitrary amount for this fake input
    spends[2].vin[0] = coinbaseTxns[2].SpendOutput(0);
    spends[2].vout.resize(1);
    spends[2].vout[0].nValue = 799999999;
    spends[2].vout[0].scriptPubKey = coinbaseLockingScript;

    // Sign:
    std::vector<unsigned char> vchSig3;
    uint256 hash3 =
        SignatureHash(coinbaseLockingScript, spends[2], 0, defaultSigHashType, coinbaseTxns[2].vout[0].nValue, 0);
    BOOST_CHECK(hash3 != SIGNATURE_HASH_ERROR);
    BOOST_CHECK(coinbaseKey.SignSchnorr(hash3, vchSig3));
    defaultSigHashType.appendToSig(vchSig3);
    spends[2].vin[0].scriptSig << vchSig3 << ToByteVector(coinbaseKey.GetPubKey());

    BOOST_CHECK(!ToMemPool(spends[2]));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[2].vin[0].prevout, fSpent)); // the only valid coin from the orphantx
    BOOST_CHECK(fSpent == false);
    {
        WRITELOCK(orphanpool.cs_orphanpool);
        BOOST_CHECK(orphanpool.AddOrphanTx(MakeTransactionRef(spends[2]), 1));
        BOOST_CHECK_EQUAL(orphanpool.mapOrphans.size(), 1UL);
    }
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent)); // valid coin from previous txn
    BOOST_CHECK(fSpent == false);
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[2].vin[2].prevout, fSpent));
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[2].vin[1].prevout, fSpent));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[2].vin[0].prevout, fSpent)); // the only valid coin from the orphantx
    BOOST_CHECK(fSpent == false);

    // Remove valid orphans by time.  The coins should be removed from the coins cache
    {
        SetMockTime(nStartTime + 3600 * DEFAULT_ORPHANPOOL_EXPIRY + 300);
        std::vector<CTransactionRef> vWorkQueue;
        ProcessOrphans(vWorkQueue);

        WRITELOCK(orphanpool.cs_orphanpool);
        BOOST_CHECK_EQUAL(orphanpool.mapOrphans.size(), 0UL);
    }

    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent)); // valid coin from previous txn
    BOOST_CHECK(fSpent == false);
    // the valid coin from orphantx is uncached
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[2].vin[2].prevout, fSpent));

    // Remove valid orphans by size.  The coins should be removed from the coins cache
    BOOST_CHECK(!ToMemPool(spends[2]));
    {
        WRITELOCK(orphanpool.cs_orphanpool);
        BOOST_CHECK(orphanpool.AddOrphanTx(MakeTransactionRef(spends[2]), 1));
    }
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent)); // valid coin from previous txn
    BOOST_CHECK(fSpent == false);
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[2].vin[2].prevout, fSpent));
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[2].vin[1].prevout, fSpent));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[2].vin[0].prevout, fSpent)); // the only valid coin from the orphantx
    BOOST_CHECK(fSpent == false);

    {
        WRITELOCK(orphanpool.cs_orphanpool);
        orphanpool.LimitPoolSize(0, 0);
    }

    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent)); // valid coin from previous txn
    BOOST_CHECK(fSpent == false);
    // the valid coin from orphantx is uncached
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[2].vin[0].prevout, fSpent));

    // Evict the valid previous tx, by time.  The coins should be removed from the coins cache
    SetMockTime(nStartTime + 1 + 72 * 60 * 60); // move to 1 second beyond time to evict
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent)); // valid coin from previous txn
    BOOST_CHECK(fSpent == false);
    LimitMempoolSize(mempool, 100 * 1000 * 1000, 72 * 60 * 60);
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent)); // valid coin from previous txn

    // Add a tx to the memory pool.  The valid inputs should be present in the coins cache.
    spends.resize(4);
    spends[3].vin.resize(1);
    spends[3].vin[0] = coinbaseTxns[0].SpendOutput(0);
    spends[3].vout.resize(1);
    spends[3].vout[0].nValue = 11 * CENT;
    spends[3].vout[0].scriptPubKey = coinbaseLockingScript;

    // Sign:
    std::vector<unsigned char> vchSig4;
    uint256 hash4 =
        SignatureHash(coinbaseLockingScript, spends[3], 0, defaultSigHashType, coinbaseTxns[3].vout[0].nValue, 0);
    BOOST_CHECK(hash4 != SIGNATURE_HASH_ERROR);
    BOOST_CHECK(coinbaseKey.SignSchnorr(hash4, vchSig4));
    defaultSigHashType.appendToSig(vchSig4);
    spends[3].vin[0].scriptSig << vchSig4 << ToByteVector(coinbaseKey.GetPubKey());

    BOOST_CHECK(ToMemPool(spends[3]));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[3].vin[0].prevout, fSpent));

    // Evict a valid tx by size of memory pool.  The coins should be removed from the coins cache
    SetMockTime(nStartTime + 1); // change start time so we are well within the limits
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[3].vin[0].prevout, fSpent)); // valid coin from previous txn
    BOOST_CHECK(fSpent == false);
    LimitMempoolSize(mempool, 0, 72 * 60 * 60); // limit mempool size to zero
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[3].vin[0].prevout, fSpent)); // valid coin from previous txn

    // Test getting a coin that is not in the cache.
    BOOST_CHECK(pcoinsTip->GetCoinFromDB(spends[3].vin[0].prevout));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[3].vin[0].prevout, fSpent)); // valid coin from previous txn
    BOOST_CHECK(fSpent == false);

    // Spend the coin and then check the results from HaveCoinInCached()
    Coin *pcoin = nullptr;
    pcoinsTip->SpendCoin(spends[3].vin[0].prevout, pcoin);
    fSpent = false;
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[3].vin[0].prevout, fSpent)); // valid coin from previous txn
    BOOST_CHECK(fSpent == true);

    /**  Simulate the following scenario:
     *     Add an orphan to the orphan pool
     *     then add the parent to the mempool which causes the orphan to also be pulled into the mempool.
     *     then delete the orphan using EraseOrphanTx(hash).
     *   Result: All coins should still be present in cache.
     */

    // Add an orphan to the orphan cache.  The valid inputs should be present in the coins cache.
    spends.resize(5);
    spends[4].vin.resize(3);
    spends[4].vin[2].prevout.hash = InsecureRand256();
    spends[4].vin[2].amount = 10000000; // Arbitrary amount for this fake input
    spends[4].vin[1].prevout.hash = InsecureRand256();
    spends[4].vin[1].amount = 10000000; // Arbitrary amount for this fake input
    spends[4].vin[0] = coinbaseTxns[5].SpendOutput(0);
    spends[4].vout.resize(1);
    spends[4].vout[0].nValue = 799999999;
    spends[4].vout[0].scriptPubKey = coinbaseLockingScript;

    // Sign:
    std::vector<unsigned char> vchSig5;
    uint256 hash5 =
        SignatureHash(coinbaseLockingScript, spends[2], 0, defaultSigHashType, coinbaseTxns[5].vout[0].nValue, 0);
    BOOST_CHECK(hash5 != SIGNATURE_HASH_ERROR);
    BOOST_CHECK(coinbaseKey.SignSchnorr(hash5, vchSig5));
    defaultSigHashType.appendToSig(vchSig5);
    spends[4].vin[0].scriptSig << vchSig5 << ToByteVector(coinbaseKey.GetPubKey());

    BOOST_CHECK(!ToMemPool(spends[4]));
    {
        WRITELOCK(orphanpool.cs_orphanpool);
        BOOST_CHECK(orphanpool.AddOrphanTx(MakeTransactionRef(spends[4]), 1));
    }
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[4].vin[2].prevout, fSpent));
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[4].vin[1].prevout, fSpent));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[4].vin[0].prevout, fSpent)); // the only valid coin from the orphantx
    BOOST_CHECK(fSpent == false);

    // All we need to do to simluate the above scenario is now erase the orphan tx from the orphan cache as it
    // would be if the orphan was moved into the mempool.
    // Result: All the coins should still be remaining in the coins cache.
    {
        WRITELOCK(orphanpool.cs_orphanpool);
        orphanpool.EraseOrphanTx(spends[4].GetId());
    }
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[4].vin[0].prevout, fSpent));
    BOOST_CHECK(fSpent == false);


    // cleanup
    mempool.clear();
    {
        WRITELOCK(orphanpool.cs_orphanpool);
        orphanpool.mapOrphans.clear();
    }
    pcoinsTip->Flush();
    SetMockTime(0);
}

BOOST_FIXTURE_TEST_CASE(long_unconfirmed_chains, TestChain100Setup)
{
    double nTempFee = minRelayFee.Value();
    minRelayFee.Set(0);

    // Get 1 more spendable coinbase tx
    std::vector<CMutableTransaction> noTxns;
    CBlock b = CreateAndProcessBlock(noTxns, coinbaseLockingScript);
    coinbaseTxns.push_back(*b.vtx[0]);

    auto prevout = coinbaseTxns[0].SpendOutput(0);
    uint256 hash;

    // Create a chain of 50 unconfirmed transactions
    for (int i = 1; i <= 50; i++)
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0] = prevout;
        tx.vout.resize(1);
        tx.vout[0].nValue = 11 * CENT;
        tx.vout[0].scriptPubKey = coinbaseLockingScript;

        // Sign:
        std::vector<unsigned char> vchSig;
        if (i == 1)
        {
            hash = SignatureHash(coinbaseLockingScript, tx, 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue, 0);
        }
        else
        {
            hash = SignatureHash(coinbaseLockingScript, tx, 0, defaultSigHashType, 11 * CENT, 0);
        }
        BOOST_CHECK(hash != SIGNATURE_HASH_ERROR);
        BOOST_CHECK(coinbaseKey.SignSchnorr(hash, vchSig));
        defaultSigHashType.appendToSig(vchSig);
        tx.vin[0].scriptSig << vchSig << ToByteVector(coinbaseKey.GetPubKey());
        BOOST_CHECK(ToMemPool(tx));

        prevout = tx.SpendOutput(0);
    }

    // Add one more which should should work because the limit is now 52
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0] = prevout;
        tx.vout.resize(1);
        tx.vout[0].nValue = 11 * CENT;
        tx.vout[0].scriptPubKey = coinbaseLockingScript;
        tx.vin[0].scriptSig = SignCoinbaseSpend(tx, 0, defaultSigHashType, 11 * CENT);
        BOOST_CHECK(ToMemPool(tx));
        prevout = tx.SpendOutput(0);
    }

    // Now try to add a tx with multiple inputs.  It should pass
    {
        CMutableTransaction tx;
        tx.vin.resize(2);
        tx.vin[0] = prevout;
        tx.vin[1] = coinbaseTxns[1].SpendOutput(0);
        tx.vout.resize(1);
        tx.vout[0].nValue = 11 * CENT;
        tx.vout[0].scriptPubKey = coinbaseLockingScript;

        tx.vin[0].scriptSig = SignCoinbaseSpend(tx, 0, defaultSigHashType, coinbaseTxns[1].vout[0].nValue);
        tx.vin[1].scriptSig = SignCoinbaseSpend(tx, 1, defaultSigHashType, coinbaseTxns[1].vout[0].nValue);

        BOOST_CHECK(ToMemPool(tx));
        prevout = tx.SpendOutput(0);
    }

    // Now try to add a tx with only one input. It should succeed.
    {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0] = prevout;
        tx.vout.resize(1);
        tx.vout[0].nValue = 11 * CENT;
        tx.vout[0].scriptPubKey = coinbaseLockingScript;
        tx.vin[0].scriptSig = SignCoinbaseSpend(tx, 0, defaultSigHashType, 11 * CENT);
        BOOST_CHECK(ToMemPool(tx));

        prevout = tx.SpendOutput(0);
    }

    minRelayFee.Set(nTempFee);
}

BOOST_FIXTURE_TEST_CASE(limitfreerelay, TestChain100Setup)
{
    int64_t nStartTime = GetTime();
    {
        WRITELOCK(orphanpool.cs_orphanpool);
        orphanpool._SetLastOrphanCheck(nStartTime);
    }
    SetMockTime(nStartTime); // Overrides future calls to GetTime()

    mempool.clear();
    pcoinsTip->Flush();

    bool fSpent = false;

    // Make sure coins are uncached when txns are not accepted into the memory pool
    // and also verify they are uncached when orphans or txns are evicted from either the
    // orphan cache or the transaction memory pool.

    std::vector<CMutableTransaction> spends;

    // Try to add a transaction with that is considered free (the fee is less than the minrelaytxfee)
    spends.resize(1);
    spends[0].vin.resize(1);
    spends[0].vin[0] = coinbaseTxns[0].SpendOutput(0);
    spends[0].vout.resize(1);
    spends[0].vout[0].nValue = coinbaseTxns[0].vout[0].nValue;
    spends[0].vout[0].scriptPubKey = coinbaseLockingScript;
    spends[0].vin[0].scriptSig = SignCoinbaseSpend(spends[0], 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);

    BOOST_CHECK(!ToMemPool(spends[0], "mempool min fee not met"));
    BOOST_CHECK(!pcoinsTip->HaveCoinInCache(spends[0].vin[0].prevout, fSpent));
    BOOST_CHECK(fSpent == false);

    // Add a txn, which is not considered free (it has enough fee), to the memory pool.
    // The coins should be present in the coins cache.
    spends.resize(2);
    spends[1].vin.resize(1);
    spends[1].vin[0] = coinbaseTxns[0].SpendOutput(0);
    spends[1].vout.resize(1);
    spends[1].vout[0].nValue = 11 * CENT;
    spends[1].vout[0].scriptPubKey = coinbaseLockingScript;
    spends[1].vin[0].scriptSig = SignCoinbaseSpend(spends[1], 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);

    BOOST_CHECK(ToMemPool(spends[1]));
    BOOST_CHECK(pcoinsTip->HaveCoinInCache(spends[1].vin[0].prevout, fSpent));
    BOOST_CHECK(fSpent == false);

    // Try to accept a free transaction into the mempool when free txns are allowed
    mempool.clear();
    pcoinsTip->Flush();

    spends.resize(3);
    spends[2].vin.resize(1);
    spends[2].vin[0] = coinbaseTxns[0].SpendOutput(0);
    spends[2].vout.resize(1);
    spends[2].vout[0].nValue = coinbaseTxns[0].vout[0].nValue;
    spends[2].vout[0].scriptPubKey = coinbaseLockingScript;
    spends[2].vin[0].scriptSig = SignCoinbaseSpend(spends[2], 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);

    CValidationState state;
    bool fMissingInputs = false;
    bool ret = false;
    bool fFreeTxnsAllowed = true;
    ret = AcceptToMemoryPool(mempool, state, MakeTransactionRef(spends[2]), fFreeTxnsAllowed, &fMissingInputs, false);
    BOOST_CHECK(ret == true);
}

// The tx id hashes the satisfier scripts joined by 0xFF without length prefixes, so the bytes after a 0xFF in one
// scriptSig can be moved to the start of the next one without changing the id. A block body altered this way has
// the same merkle root and header as the honest one but fails its script checks.
struct RecutBlockSetup : public TestChain100Setup
{
    CBlockRef honest;
    CBlockRef altered;

    // With fBadScripts the honest body fails its script checks too
    void MakeBlocks(bool fBadScripts = false)
    {
        const CChainParams &chainparams = Params();
        const uint8_t SEPARATOR = 0xff;
        // One more block so the second coinbase is mature too
        CreateAndProcessBlock({}, coinbaseLockingScript);

        CMutableTransaction tx;
        tx.vin.resize(2);
        tx.vin[0] = coinbaseTxns[0].SpendOutput(0);
        tx.vin[1] = coinbaseTxns[1].SpendOutput(0);
        tx.vout.resize(1);
        tx.vout[0].scriptPubKey = coinbaseLockingScript;
        // Vary the output until the first satisfier contains the separator byte.
        // size_type matches the iterator operator+. Win64 size_t does not.
        CScript::size_type cut = 0;
        for (CAmount extra = 0; cut == 0; extra++)
        {
            tx.vout[0].nValue = 1000 * COIN + extra;
            tx.vin[0].scriptSig = SignCoinbaseSpend(tx, 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);
            tx.vin[1].scriptSig = SignCoinbaseSpend(tx, 1, defaultSigHashType, coinbaseTxns[1].vout[0].nValue);
            const CScript &sig0 = tx.vin[0].scriptSig;
            for (size_t i = 1; i + 1 < sig0.size() && cut == 0; i++)
                if (sig0[i] == SEPARATOR)
                    cut = i;
        }
        if (fBadScripts)
            tx.vout[0].nValue += 1; // invalidates both signatures

        // Move the bytes after the separator from vin[0] to the start of vin[1]
        CMutableTransaction recut(tx);
        const CScript sig0 = tx.vin[0].scriptSig;
        recut.vin[0].scriptSig = CScript(sig0.begin(), sig0.begin() + cut);
        recut.vin[1].scriptSig = CScript(sig0.begin() + cut + 1, sig0.end());
        recut.vin[1].scriptSig.push_back(SEPARATOR);
        recut.vin[1].scriptSig.insert(
            recut.vin[1].scriptSig.end(), tx.vin[1].scriptSig.begin(), tx.vin[1].scriptSig.end());
        const CTransaction honestTx(tx);
        const CTransaction recutTx(recut);
        BOOST_REQUIRE(honestTx.vin[0].scriptSig != recutTx.vin[0].scriptSig);
        BOOST_REQUIRE(honestTx.GetId() == recutTx.GetId());
        BOOST_REQUIRE(honestTx.GetIdem() == recutTx.GetIdem());

        std::unique_ptr<CBlockTemplate> pblocktemplate =
            BlockAssembler(chainparams).CreateNewBlock(coinbaseLockingScript);
        honest = pblocktemplate->block;
        honest->vtx.resize(1);
        honest->vtx.push_back(MakeTransactionRef(honestTx));
        honest->UpdateHeader();
        honest->nonce.resize(3);
        BOOST_REQUIRE(MineBlock(*honest, 1 << 23, chainparams.GetConsensus()));
        altered = MakeBlockRef(*honest);
        altered->vtx[1] = MakeTransactionRef(recutTx);
        BOOST_REQUIRE(altered->GetHash() == honest->GetHash());
        BOOST_REQUIRE(BlockMerkleRoot(*altered) == honest->hashMerkleRoot);
        BOOST_REQUIRE_EQUAL(::GetSerializeSize(*altered, SER_NETWORK, PROTOCOL_VERSION),
            ::GetSerializeSize(*honest, SER_NETWORK, PROTOCOL_VERSION));
    }

    bool BlockFailed(const uint256 &hash)
    {
        CBlockIndex *pindex = LookupBlockIndex(hash);
        return pindex == nullptr || (pindex->nStatus & BLOCK_FAILED_MASK);
    }
};

BOOST_FIXTURE_TEST_CASE(block_body_with_recut_satisfiers, RecutBlockSetup)
{
    // Receiving the altered body first must not stop the honest body from being accepted
    MakeBlocks();
    const uint256 hash = honest->GetHash();
    CValidationState state;
    ProcessSummaryBlock(state, Params(), nullptr, altered, true, nullptr, SINGLE_THREADED);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() != hash);
    BOOST_CHECK_MESSAGE(!BlockFailed(hash), "altered body marked the honest block invalid");
    BOOST_CHECK(suspectBlockBodies.IsSuspect(hash));

    CValidationState state2;
    ProcessSummaryBlock(state2, Params(), nullptr, honest, true, nullptr, SINGLE_THREADED);
    BOOST_CHECK_MESSAGE(chainActive.Tip()->GetBlockHash() == hash, "honest body was not accepted");
    BOOST_CHECK(!suspectBlockBodies.IsSuspect(hash));
}

BOOST_FIXTURE_TEST_CASE(block_body_recut_blames_its_sender, RecutBlockSetup)
{
    // The peer that sent the altered body is penalized, not the one that then sends the honest body
    MakeBlocks();
    CNode nodeA(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c001, 10000)), "", true);
    CNode nodeB(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c002, 10000)), "", true);
    {
        LOCK(cs_vNodes);
        vNodes.push_back(&nodeA);
        vNodes.push_back(&nodeB);
    }
    // B's honest body arrives after A's altered body is stored but before it is validated
    {
        LOCK(cs_main);
        CBlockIndex *pindex = nullptr;
        CValidationState stateA;
        ProcessAcceptBlock(&nodeA, altered, stateA, Params(), &pindex, nullptr);
        CValidationState stateB;
        ProcessAcceptBlock(&nodeB, honest, stateB, Params(), &pindex, nullptr);
    }
    CValidationState state;
    ActivateBestChain(state, Params());
    BOOST_CHECK(nodeA.nMisbehavior.load() > 0);
    BOOST_CHECK_EQUAL(nodeB.nMisbehavior.load(), 0);

    // The body is requested again from B, not from A
    {
        const CInv inv(MSG_BLOCK, honest->GetHash());
        std::map<uint256, CUnknownObj> pending;
        requester.GetBlockRequests(pending);
        pending.clear();
        requester.AskFor(inv, &nodeA, objType::BLOCK);
        requester.GetBlockRequests(pending);
        BOOST_CHECK_EQUAL(pending.count(inv.hash), 0U);
        pending.clear();
        requester.AskFor(inv, &nodeB, objType::BLOCK);
        requester.GetBlockRequests(pending);
        BOOST_CHECK_EQUAL(pending.count(inv.hash), 1U);
    }

    // A body pushed again by A is ignored, so the stored body stays suspect
    {
        LOCK(cs_main);
        CBlockIndex *pindex = nullptr;
        CValidationState stateA;
        BOOST_CHECK(ProcessAcceptBlock(&nodeA, altered, stateA, Params(), &pindex, nullptr));
        BOOST_CHECK(suspectBlockBodies.IsSuspect(honest->GetHash()));
    }

    // B's body is then fetched again and connects
    CValidationState state2;
    ProcessSummaryBlock(state2, Params(), &nodeB, honest, true, nullptr, SINGLE_THREADED);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == honest->GetHash());
    BOOST_CHECK_EQUAL(nodeB.nMisbehavior.load(), 0);
    {
        LOCK(cs_vNodes);
        vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), &nodeA), vNodes.end());
        vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), &nodeB), vNodes.end());
    }
    dosMan.ClearBanned();
}

BOOST_FIXTURE_TEST_CASE(block_body_with_bad_scripts_is_not_connected, RecutBlockSetup)
{
    // Invalid scripts must never connect, even though the body does not prove header invalidity.
    MakeBlocks(true);
    const uint256 hash = honest->GetHash();
    for (int i = 0; i < 12; i++)
    {
        CValidationState state;
        ProcessSummaryBlock(state, Params(), nullptr, honest, true, nullptr, SINGLE_THREADED);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() != hash);
        BOOST_CHECK(suspectBlockBodies.IsSuspect(hash));
        BOOST_CHECK(!BlockFailed(hash));
    }
}

BOOST_FIXTURE_TEST_CASE(block_body_with_repeated_recut_satisfiers, RecutBlockSetup)
{
    MakeBlocks();
    const uint256 hash = honest->GetHash();
    for (int i = 0; i < 12; i++)
    {
        CValidationState state;
        ProcessSummaryBlock(state, Params(), nullptr, altered, true, nullptr, SINGLE_THREADED);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() != hash);
        BOOST_CHECK(!BlockFailed(hash));
        BOOST_CHECK(suspectBlockBodies.IsSuspect(hash));
    }
    CValidationState state;
    ProcessSummaryBlock(state, Params(), nullptr, honest, true, nullptr, SINGLE_THREADED);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == hash);
    BOOST_CHECK(!suspectBlockBodies.IsSuspect(hash));
}

BOOST_FIXTURE_TEST_CASE(block_body_recut_rewinds_download_cursors, RecutBlockSetup)
{
    MakeBlocks();
    const uint256 hash = honest->GetHash();
    CBlockRef descendant = MakeBlockRef(*honest);
    descendant->hashPrevBlock = hash;
    descendant->height++;
    descendant->hashAncestor = chainActive[GetConsensusAncestorHeight(descendant->height)]->GetBlockHash();
    descendant->SetChainWork(honest->aChainWork() + GetWorkForDifficultyBits(descendant->nBits));
    descendant->nTime++;
    descendant->vtx.resize(1);
    CMutableTransaction coinbase(*descendant->vtx[0]);
    coinbase.vout.back().scriptPubKey = CScript()
                                        << OP_RETURN << descendant->height << std::vector<uint8_t>(MIN_TX_SIZE, 0);
    descendant->vtx[0] = MakeTransactionRef(coinbase);
    descendant->fChecked = false;
    descendant->UpdateHeader();
    BOOST_REQUIRE(MineBlock(*descendant, 1 << 23, Params().GetConsensus()));
    CNode peerA(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c010, 10000)), "", true);
    CNode peerB(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c011, 10000)), "", true);
    {
        LOCK(cs_main);
        CBlockIndex *pindex = nullptr;
        CValidationState state;
        BOOST_REQUIRE(ProcessAcceptBlock(nullptr, altered, state, Params(), &pindex, nullptr));
        CBlockIndex *pindexDescendant = nullptr;
        CValidationState descendantState;
        const bool accepted =
            ProcessAcceptBlock(nullptr, descendant, descendantState, Params(), &pindexDescendant, nullptr);
        BOOST_REQUIRE_MESSAGE(accepted, descendantState.GetLogString());
        for (CNode *peer : {&peerA, &peerB})
        {
            const uint256 peerTip = peer == &peerA ? descendant->GetHash() : hash;
            requester.UpdateBlockAvailability(peer->GetId(), peerTip);
            std::vector<CBlockIndex *> next;
            requester.FindNextBlocksToDownload(peer, 128, next);
            BOOST_CHECK(next.empty());
            CNodeStateAccessor nodeState(nodestate, peer->GetId());
            BOOST_CHECK(nodeState->pindexLastCommonBlock->GetBlockHash() == peerTip);
        }
    }
    CValidationState state;
    ActivateBestChain(state, Params());
    BOOST_REQUIRE(suspectBlockBodies.IsSuspect(hash));
    BOOST_CHECK(!AlreadyHaveBlock(CInv(MSG_BLOCK, hash)));
    {
        LOCK(cs_main);
        for (CNode *peer : {&peerA, &peerB})
        {
            std::vector<CBlockIndex *> next;
            requester.FindNextBlocksToDownload(peer, 128, next);
            BOOST_REQUIRE_EQUAL(next.size(), 1U);
            BOOST_CHECK(next[0]->GetBlockHash() == hash);
            CNodeStateAccessor nodeState(nodestate, peer->GetId());
            BOOST_CHECK(nodeState->pindexLastCommonBlock == chainActive.Tip());
        }
    }
    CValidationState honestState;
    ProcessSummaryBlock(honestState, Params(), nullptr, honest, true, nullptr, SINGLE_THREADED);
    BOOST_CHECK(chainActive.Contains(LookupBlockIndex(hash)));
}

BOOST_FIXTURE_TEST_CASE(recut_satisfiers_do_not_poison_reject_cache, RecutBlockSetup)
{
    MakeBlocks();
    const uint256 id = honest->vtx[1]->GetId();
    CValidationState alteredState;
    bool missing = false;
    BOOST_CHECK(!AcceptToMemoryPool(
        mempool, alteredState, altered->vtx[1], false, &missing, false, TransactionClass::STANDARD));
    BOOST_CHECK(!missing);
    BOOST_CHECK_EQUAL(alteredState.GetRejectReason(), "scriptsig-not-pushonly");
    BOOST_CHECK(alteredState.CorruptionPossible());

    CMutableTransaction dust(*honest->vtx[1]);
    dust.vout[0].nValue = 1;
    CValidationState dustState;
    BOOST_CHECK(!AcceptToMemoryPool(
        mempool, dustState, MakeTransactionRef(dust), false, &missing, false, TransactionClass::STANDARD));
    BOOST_CHECK_EQUAL(dustState.GetRejectReason(), "dust");
    BOOST_CHECK(!dustState.CorruptionPossible());

    const CChainParams savedParams = Params();
    const auto admissionThreads = numTxAdmissionThreads.Value();
    const bool previousShutdown = shutdown_threads.load();
    boost::thread worker;
    BOOST_SCOPE_EXIT(&worker, &savedParams, admissionThreads, previousShutdown)
    {
        shutdown_threads.store(true);
        StopTxAdmission();
        if (worker.joinable())
            worker.join();
        shutdown_threads.store(previousShutdown);
        numTxAdmissionThreads.Set(admissionThreads);
        ModifiableParams() = savedParams;
    }
    BOOST_SCOPE_EXIT_END

    BOOST_REQUIRE(ModifiableParams().SetRequireStandard(false));
    BOOST_REQUIRE(Params().RequireStandard());
    numTxAdmissionThreads.Set(1);
    shutdown_threads.store(false);
    BOOST_REQUIRE_EQUAL(TxAlreadyHave(MSG_TX, id), 0U);
    CTxInputData incoming;
    incoming.tx = altered->vtx[1];
    incoming.msgCookie = 0;
    EnqueueTxForAdmission(incoming);
    worker = boost::thread(&ThreadTxAdmission);
    for (int i = 0; i < 500 && !filterTransactionKnown.contains(id); i++)
        MilliSleep(10);

    BOOST_REQUIRE(filterTransactionKnown.contains(id));
    BOOST_CHECK(!recentRejects.contains(id));
    BOOST_CHECK_EQUAL(TxMayAlreadyHave(MSG_TX, id), 0U);
    CValidationState honestState;
    const bool accepted =
        AcceptToMemoryPool(mempool, honestState, honest->vtx[1], false, &missing, false, TransactionClass::STANDARD);
    BOOST_CHECK_MESSAGE(accepted, honestState.GetLogString());
    BOOST_CHECK(mempool.exists(id));
    mempool.clear();
}

BOOST_AUTO_TEST_SUITE_END()
