// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"
#include "coins.h"
#include "policy/policy.h"
#include "wallet/crypter.h"

#include <vector>

// FIXME: Dedup with SetupDummyInputs in test/transaction_tests.cpp.
//
// Helper: create a dummy transaction with two TX_PUBKEYHASH outputs of
// 21 and 22 CENT.
//
static std::vector<CMutableTransaction> SetupDummyInputs(CBasicKeyStore &keystoreRet, CCoinsViewCache &coinsRet)
{
    std::vector<CMutableTransaction> dummyTransactions;
    dummyTransactions.resize(1);

    // Add some keys to the keystore:
    CKey key[2];
    for (int i = 0; i < 2; i++)
    {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 21 * CENT;
    dummyTransactions[0].vout[0].scriptPubKey = GetScriptForDestination(key[0].GetPubKey().GetID());
    dummyTransactions[0].vout[1].nValue = 22 * CENT;
    dummyTransactions[0].vout[1].scriptPubKey = GetScriptForDestination(key[1].GetPubKey().GetID());
    AddCoins(coinsRet, CTransaction(dummyTransactions[0]), 0);

    return dummyTransactions;
}

// Microbenchmark for simple accesses to a CCoinsViewCache database. Note from
// laanwj, "replicating the actual usage patterns of the client is hard though,
// many times micro-benchmarks of the database showed completely different
// characteristics than e.g. reindex timings. But that's not a requirement of
// every benchmark."
// (https://github.com/bitcoin/bitcoin/issues/7883#issuecomment-224807484)
static void CCoinsCaching(benchmark::State &state)
{
    const ECCVerifyHandle verify_handle;
    ECC_Start();

    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CMutableTransaction t1;
    t1.vin.resize(2);
    t1.vin[0].prevout = dummyTransactions[0].OutpointAt(0);
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[1].prevout = dummyTransactions[0].OutpointAt(1);
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 40 * CENT;
    t1.vout[0].scriptPubKey << OP_1;

    // Benchmark
    while (state.KeepRunning())
    {
        bool success = AreInputsStandard(MakeTransactionRef(t1), coins);
        assert(success);
        CAmount value = coins.GetValueIn(t1);
        assert(value == (21 + 22) * CENT);
    }
    ECC_Stop();
}

BENCHMARK(CCoinsCaching, 170 * 1000);
