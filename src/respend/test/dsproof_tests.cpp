// Copyright (c) 2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/validation.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "respend/dsproof.h"
#include "script/scripttemplate.h"
#include "script/sighashtype.h"
#include "script/sign.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_nexa.h"
#include "txadmission.h"
#include "txmempool.h"

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(dsproof_tests)

// tx1 and tx2 double spend each other and must spend different sets of inputs, so the two spenders have
// different hashInAmounts (and hashPrevOutputs).  If they were identical, a serializer that mixed up
// the spenders' fields would go unnoticed.  Puts tx1 into the mempool, then checks that the proof
// validates both as created and after a network serialization round trip.
static void CheckProofRoundTrip(const CMutableTransaction &tx1, const CMutableTransaction &tx2)
{
    // validate() needs a mempool tx spending the doublespent outpoint to get the pubkey from
    CValidationState state;
    bool fMissingInputs = false;
    bool accepted = AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx1), false, &fMissingInputs, false);
    BOOST_REQUIRE_MESSAGE(accepted, "tx1 rejected: " << state.GetRejectReason() << " (" << state.GetDebugMessage()
                                                     << ") missing inputs: " << fMissingInputs);

    {
        WRITELOCK(mempool.cs_txmempool);
        DoubleSpendProof dsp = DoubleSpendProof::create(CTransaction(tx1), CTransaction(tx2), mempool);
        BOOST_REQUIRE(!dsp.isEmpty());
        BOOST_REQUIRE(dsp.spender1().hashInAmounts != dsp.spender2().hashInAmounts);
        BOOST_CHECK_EQUAL(dsp.validate(mempool), DoubleSpendProof::Valid);

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << dsp;
        DoubleSpendProof dsp2;
        ss >> dsp2;
        BOOST_CHECK(ss.empty());

        BOOST_CHECK(dsp2.Outpoint() == dsp.Outpoint());
        BOOST_CHECK(dsp2.spender1() == dsp.spender1());
        BOOST_CHECK(dsp2.spender2() == dsp.spender2());
        BOOST_CHECK(dsp2.spender2().hashInAmounts == dsp.spender2().hashInAmounts);
        BOOST_CHECK_EQUAL(dsp2.validate(mempool), DoubleSpendProof::Valid);
    }
    mempool.clear();
}

BOOST_FIXTURE_TEST_CASE(dsproof_serialization_roundtrip_p2pkh, TestChain100Setup)
{
    // tx1 spends coinbase 0.  tx2 spends coinbase 0 and coinbase 1, so the two spenders have
    // different hashInAmounts (and hashPrevOutputs).  If they were identical, a serializer that mixed up
    // the spenders' fields would go unnoticed.
    CMutableTransaction tx1;
    tx1.vin.resize(1);
    tx1.vin[0] = coinbaseTxns[0].SpendOutput(0);
    tx1.vout.resize(1);
    tx1.vout[0].nValue = 11 * CENT;
    tx1.vout[0].scriptPubKey = coinbaseLockingScript;
    tx1.vin[0].scriptSig = SignCoinbaseSpend(tx1, 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);

    CMutableTransaction tx2;
    tx2.vin.resize(2);
    tx2.vin[0] = coinbaseTxns[0].SpendOutput(0);
    tx2.vin[1] = coinbaseTxns[1].SpendOutput(0);
    tx2.vout.resize(1);
    tx2.vout[0].nValue = 12 * CENT;
    tx2.vout[0].scriptPubKey = coinbaseLockingScript;
    tx2.vin[0].scriptSig = SignCoinbaseSpend(tx2, 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);
    tx2.vin[1].scriptSig = SignCoinbaseSpend(tx2, 1, defaultSigHashType, coinbaseTxns[1].vout[0].nValue);

    CheckProofRoundTrip(tx1, tx2);
}

static void SignP2pktInput(const CKeyStore &keystore, CMutableTransaction &tx, unsigned int nIn, const CScript &prevOut)
{
    CTransaction txToSign(tx);
    TransactionSignatureCreator tsc(&keystore, &txToSign, nIn, defaultSigHashType);
    BOOST_REQUIRE(ProduceSignature(tsc, prevOut, tx.vin[nIn].scriptSig));
}

BOOST_FIXTURE_TEST_CASE(dsproof_serialization_roundtrip_p2pkt, TestChain100Setup)
{
    CBasicKeyStore keystore;
    CKey key;
    key.MakeNewKey(true);
    keystore.AddKey(key);
    CScript p2pktScript = GetScriptForDestination(ScriptTemplateDestination(P2pktOutput(key.GetPubKey())));

    // Mine a tx with two P2PKT outputs for the double spends to spend.  Amounts are a fraction of the coinbase
    // so that every tx pays well over the min relay fee (CENT is only 1 satoshi).
    const CAmount fundAmount = coinbaseTxns[0].vout[0].nValue / 4;
    CMutableTransaction fund;
    fund.vin.resize(1);
    fund.vin[0] = coinbaseTxns[0].SpendOutput(0);
    fund.vout.resize(2);
    for (auto &out : fund.vout)
    {
        out.nValue = fundAmount;
        out.scriptPubKey = p2pktScript;
        out.SetScript(out.scriptPubKey);
    }
    fund.vin[0].scriptSig = SignCoinbaseSpend(fund, 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);
    CTransaction fundTx(fund);
    CBlock block = CreateAndProcessBlock({fund}, coinbaseLockingScript);
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());

    // tx1 spends output 0.  tx2 spends outputs 0 and 1.
    CMutableTransaction tx1;
    tx1.vin.resize(1);
    tx1.vin[0] = fundTx.SpendOutput(0);
    tx1.vout.resize(1);
    tx1.vout[0].nValue = fundAmount / 2;
    tx1.vout[0].scriptPubKey = coinbaseLockingScript;
    SignP2pktInput(keystore, tx1, 0, fundTx.vout[0].scriptPubKey);

    CMutableTransaction tx2;
    tx2.vin.resize(2);
    tx2.vin[0] = fundTx.SpendOutput(0);
    tx2.vin[1] = fundTx.SpendOutput(1);
    tx2.vout.resize(1);
    tx2.vout[0].nValue = fundAmount;
    tx2.vout[0].scriptPubKey = coinbaseLockingScript;
    SignP2pktInput(keystore, tx2, 0, fundTx.vout[0].scriptPubKey);
    SignP2pktInput(keystore, tx2, 1, fundTx.vout[1].scriptPubKey);

    CheckProofRoundTrip(tx1, tx2);
}

BOOST_AUTO_TEST_SUITE_END()
