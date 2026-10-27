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

// tx1 spends coinbase 0.  tx2 spends coinbase 0 and coinbase 1, so the two spenders have
// different hashInAmounts (and hashPrevOutputs).  If they were identical, a serializer that mixed up
// the spenders' fields would go unnoticed.
static void MakeP2pkhDoubleSpends(TestChain100Setup &setup, CMutableTransaction &tx1, CMutableTransaction &tx2)
{
    const auto &coinbaseTxns = setup.coinbaseTxns;
    tx1.vin.resize(1);
    tx1.vin[0] = coinbaseTxns[0].SpendOutput(0);
    tx1.vout.resize(1);
    tx1.vout[0].nValue = 11 * CENT;
    tx1.vout[0].scriptPubKey = setup.coinbaseLockingScript;
    tx1.vin[0].scriptSig = setup.SignCoinbaseSpend(tx1, 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);

    tx2.vin.resize(2);
    tx2.vin[0] = coinbaseTxns[0].SpendOutput(0);
    tx2.vin[1] = coinbaseTxns[1].SpendOutput(0);
    tx2.vout.resize(1);
    tx2.vout[0].nValue = 12 * CENT;
    tx2.vout[0].scriptPubKey = setup.coinbaseLockingScript;
    tx2.vin[0].scriptSig = setup.SignCoinbaseSpend(tx2, 0, defaultSigHashType, coinbaseTxns[0].vout[0].nValue);
    tx2.vin[1].scriptSig = setup.SignCoinbaseSpend(tx2, 1, defaultSigHashType, coinbaseTxns[1].vout[0].nValue);
}

// Builds a proof from arbitrary fields the same way a peer could, by sending it over the network
static DoubleSpendProof MakeProof(const COutPoint &outpoint,
    const DoubleSpendProof::Spender &s1,
    const DoubleSpendProof::Spender &s2)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << outpoint;
    for (const auto *s : {&s1, &s2})
    {
        ss << s->txVersion << s->outSequence << s->lockTime << s->hashPrevOutputs << s->hashSequence
           << s->hashInAmounts << s->hashOutputs << s->pushData;
    }
    DoubleSpendProof dsp;
    ss >> dsp;
    return dsp;
}

BOOST_FIXTURE_TEST_CASE(dsproof_serialization_roundtrip_p2pkh, TestChain100Setup)
{
    CMutableTransaction tx1, tx2;
    MakeP2pkhDoubleSpends(*this, tx1, tx2);
    CheckProofRoundTrip(tx1, tx2);
}

// outSequence is not covered by the signature.  A proof whose spenders differ only there could be made by
// anyone from a single transaction, so it must not validate.
BOOST_FIXTURE_TEST_CASE(dsproof_rejects_unsigned_difference, TestChain100Setup)
{
    CMutableTransaction tx1, tx2;
    MakeP2pkhDoubleSpends(*this, tx1, tx2);

    CValidationState state;
    bool fMissingInputs = false;
    bool accepted = AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx1), false, &fMissingInputs, false);
    BOOST_REQUIRE_MESSAGE(accepted, "tx1 rejected: " << state.GetRejectReason());

    {
        WRITELOCK(mempool.cs_txmempool);
        DoubleSpendProof dsp = DoubleSpendProof::create(CTransaction(tx1), CTransaction(tx2), mempool);

        // A proof rebuilt from the real spenders is valid, so MakeProof() is faithful
        BOOST_CHECK_EQUAL(MakeProof(dsp.Outpoint(), dsp.spender1(), dsp.spender2()).validate(mempool),
            DoubleSpendProof::Valid);

        // Forge a proof from a single spend by changing only outSequence
        for (const auto &spender : {dsp.spender1(), dsp.spender2()})
        {
            DoubleSpendProof::Spender forged = spender;
            forged.outSequence ^= 1;
            BOOST_CHECK(forged != spender);
            BOOST_CHECK_EQUAL(MakeProof(dsp.Outpoint(), spender, forged).validate(mempool), DoubleSpendProof::Invalid);
        }
    }
    mempool.clear();
}

// A signature's sighash type can be re-encoded without breaking it: ALL/ALL verifies with or without an explicit
// 0x00 byte, and ranged output types are not hashed, so their range bytes can be changed.  A proof pairing a spend
// with such a re-encoding of itself could be made by anyone from a single transaction, so it must not validate.
BOOST_FIXTURE_TEST_CASE(dsproof_rejects_reencoded_sighash, TestChain100Setup)
{
    CMutableTransaction tx1, tx2;
    MakeP2pkhDoubleSpends(*this, tx1, tx2);
    // Sign tx2's double spend with ranged outputs: output 0 is covered, output 1 is not
    tx2.vout.resize(2);
    tx2.vout[1].nValue = 1 * CENT;
    tx2.vout[1].scriptPubKey = coinbaseLockingScript;
    const SigHashType ranged = SigHashType().withRangedOutputs(0, 1);
    std::vector<uint8_t> rangedSig;
    uint256 sighash =
        SignatureHash(coinbaseLockingScript, CTransaction(tx2), 0, ranged, coinbaseTxns[0].vout[0].nValue);
    BOOST_REQUIRE(coinbaseKey.SignSchnorr(sighash, rangedSig));
    ranged.appendToSig(rangedSig);
    tx2.vin[0].scriptSig = CScript() << rangedSig << ToByteVector(coinbaseKey.GetPubKey());
    tx2.vin[1].scriptSig = SignCoinbaseSpend(tx2, 1, defaultSigHashType, coinbaseTxns[1].vout[0].nValue);

    CValidationState state;
    bool fMissingInputs = false;
    bool accepted = AcceptToMemoryPool(mempool, state, MakeTransactionRef(tx1), false, &fMissingInputs, false);
    BOOST_REQUIRE_MESSAGE(accepted, "tx1 rejected: " << state.GetRejectReason());

    {
        WRITELOCK(mempool.cs_txmempool);
        DoubleSpendProof dsp = DoubleSpendProof::create(CTransaction(tx1), CTransaction(tx2), mempool);
        BOOST_CHECK_EQUAL(MakeProof(dsp.Outpoint(), dsp.spender1(), dsp.spender2()).validate(mempool),
            DoubleSpendProof::Valid);

        for (const auto &spender : {dsp.spender1(), dsp.spender2()})
        {
            DoubleSpendProof::Spender forged = spender;
            std::vector<uint8_t> &sig = forged.pushData.front();
            if (SigHashType(sig).hasRangedOutputs())
                sig.back() ^= 1; // a different range count
            else
            {
                BOOST_REQUIRE_EQUAL(sig.size(), 64U);
                sig.push_back(0x00); // explicit ALL/ALL
            }
            BOOST_REQUIRE(SigHashType(sig).isDefined());
            BOOST_CHECK_EQUAL(MakeProof(dsp.Outpoint(), spender, forged).validate(mempool), DoubleSpendProof::Invalid);
        }
    }
    mempool.clear();
}

// A proof received from a peer can name any outpoint.  An output that isn't P2PKH or P2PKT must be rejected even
// if the proof's data satisfies its script.
BOOST_FIXTURE_TEST_CASE(dsproof_rejects_unsupported_script_type, TestChain100Setup)
{
    CTxMemPool pool;
    TestMemPoolEntryHelper entry;

    // An output anyone can spend: it ignores the two items the scriptSig pushes
    CMutableTransaction fund;
    fund.vin.resize(1);
    fund.vin[0] = coinbaseTxns[0].SpendOutput(0);
    fund.vout.resize(1);
    fund.vout[0].nValue = coinbaseTxns[0].vout[0].nValue / 2;
    fund.vout[0].SetScript(CScript() << OP_2DROP << OP_TRUE);
    CTransaction fundTx(fund);
    pool.addUnchecked(entry.FromTx(fundTx));

    CMutableTransaction spend;
    spend.vin.resize(1);
    spend.vin[0] = fundTx.SpendOutput(0);
    spend.vin[0].scriptSig = CScript() << std::vector<uint8_t>(65, 1) << std::vector<uint8_t>(33, 2);
    spend.vout.resize(1);
    spend.vout[0].nValue = fund.vout[0].nValue / 2;
    spend.vout[0].scriptPubKey = coinbaseLockingScript;
    pool.addUnchecked(entry.FromTx(spend));

    // Two spenders that sign different data (in ascending hashOutputs order), with junk "signatures" that the
    // output script accepts
    DoubleSpendProof::Spender s1, s2;
    s1.hashOutputs = uint256S("01");
    s2.hashOutputs = uint256S("02");
    s1.pushData.push_back(std::vector<uint8_t>(65, 3));
    s2.pushData.push_back(std::vector<uint8_t>(65, 4));

    READLOCK(pool.cs_txmempool);
    BOOST_CHECK_EQUAL(MakeProof(spend.vin[0].prevout, s1, s2).validate(pool), DoubleSpendProof::Invalid);
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
