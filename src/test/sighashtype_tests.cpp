// Copyright (c) 2018 The Bitcoin developers
// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/sighashtype.h"
#include "test/test_nexa.h"

#include "consensus/tx_verify.h"
#include "core_io.h"
#include "key.h"
#include "keystore.h"
#include "script/sign.h"
#include "txadmission.h"
#include "validation/validation.h"

#include <boost/test/unit_test.hpp>

#include <set>

BOOST_FIXTURE_TEST_SUITE(sighashtype_tests, BasicTestingSetup)

static void CheckTransaction(CMutableTransaction &tx, CCoinsViewCache &coins, bool inputsOk = true)
{
    auto flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    auto params = Params();

    CValidationState state;
    CTransactionRef txref = MakeTransactionRef(CTransaction(tx));
    BOOST_CHECK(CheckTransaction(txref, state));
    BOOST_CHECK(state.IsValid());

    bool result = Consensus::CheckTxInputs(txref, state, coins, coins, params);
    BOOST_CHECK(result);
    BOOST_CHECK(state.IsValid());

    unsigned char sighashType = 0;
    ValidationResourceTracker resourceTracker;
    CValidationDebugger debugger; // if you pass in a debugger, the function returns true to keep going
    result = CheckInputs(
        txref, state, coins, coins, true, flags, true, &resourceTracker, params, nullptr, &sighashType, nullptr);
    BOOST_CHECK(result == inputsOk);
    if (inputsOk)
        BOOST_CHECK(state.IsValid());
}


static void CheckSigHashType(SigHashType t,
    bool isDefined,
    bool isAll,
    bool hasNoInputs = false,
    bool hasNoOutputs = false,
    bool hasAnyoneCanPay = false,
    bool has2Outputs = false,
    bool hasRangedOutputs = false)
{
    BOOST_CHECK_EQUAL(t.isDefined(), isDefined);
    BOOST_CHECK_EQUAL(t.hasAll(), isAll);
    BOOST_CHECK_EQUAL(t.hasNoInputs(), hasNoInputs);
    BOOST_CHECK_EQUAL(t.hasNoOutputs(), hasNoOutputs);
    BOOST_CHECK_EQUAL(t.hasAnyoneCanPay(), hasAnyoneCanPay);
    BOOST_CHECK_EQUAL(t.hasRangedOutputs(), hasRangedOutputs);
    if (has2Outputs)
    {
        std::string s = t.ToString();
        BOOST_CHECK(s.find("1_2_OUT") != std::string::npos); // we hard coded the output indexes for this test
    }
    if (hasRangedOutputs)
    {
        std::string s = t.ToString();
        // we hard coded the output indexes for this test
        BOOST_CHECK(s.find("RANGED_OUT_at_3_to_7") != std::string::npos);
    }
}

//
// Helper: create two dummy transactions, each with
// two outputs.  The first has 11 and 50 CENT outputs
// paid to a TX_PUBKEY, the second 21 and 22 CENT outputs
// paid to a TX_PUBKEYHASH.
//
static std::vector<CMutableTransaction> SetupDummyInputs(CBasicKeyStore &keystoreRet, CCoinsViewCache &coinsRet)
{
    std::vector<CMutableTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    int height = 1000; // any height will do
    dummyTransactions[0].vin.resize(1); // make a fake input so this is not seen as a coinbase
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 100 * CENT;
    dummyTransactions[0].vout[0].scriptPubKey << ToByteVector(key[0].GetPubKey()) << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = 50 * CENT;
    dummyTransactions[0].vout[1].scriptPubKey << ToByteVector(key[1].GetPubKey()) << OP_CHECKSIG;
    AddCoins(coinsRet, dummyTransactions[0], height);

    dummyTransactions[1].vin.resize(1); // make a fake input so this is not seen as a coinbase
    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = 21 * CENT;
    dummyTransactions[1].vout[0].scriptPubKey = GetScriptForDestination(key[2].GetPubKey().GetID());
    dummyTransactions[1].vout[1].nValue = 22 * CENT;
    dummyTransactions[1].vout[1].scriptPubKey = GetScriptForDestination(key[3].GetPubKey().GetID());
    AddCoins(coinsRet, dummyTransactions[1], height);
    return dummyTransactions;
}


BOOST_AUTO_TEST_CASE(sighash_retargetable_tx_test)
{
    auto flags = POST_UPGRADE_MANDATORY_SCRIPT_VERIFY_FLAGS;
    auto params = Params();
    SigHashType range2 = SigHashType().withThisInput().withRangedOutputs(0, 1);


    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(&coinsDummy);
    std::vector<CMutableTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CMutableTransaction t1;
    t1.vin.resize(1);
    t1.vin[0] = dummyTransactions[0].SpendOutput(0);
    // t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vout.resize(2);
    t1.vout[0].nValue = 12 * CENT;
    t1.vout[0].scriptPubKey << OP_NOP;
    t1.vout[1].nValue = 13 * CENT;
    t1.vout[1].scriptPubKey << OP_NOP;
    CTransaction tx1(t1);


    { // Check too many (sighashtype.md#REQ2)
        SigHashType tooMany = SigHashType().withThisInput().withRangedOutputs(0, 2);
        TransactionSignatureCreator tsc(&keystore, &tx1, 0, tooMany);
        const CScript &scriptPubKey = dummyTransactions[0].vout[0].scriptPubKey;
        CScript &scriptSigRes = t1.vin[0].scriptSig;
        bool worked = ProduceSignature(tsc, scriptPubKey, scriptSigRes);
        BOOST_CHECK(!worked);
    }
    { // Check bad start (sighashtype.md#REQ1)
        SigHashType tooFar = SigHashType().withThisInput().withRangedOutputs(2, 0);
        TransactionSignatureCreator tsc(&keystore, &tx1, 0, tooFar);
        const CScript &scriptPubKey = dummyTransactions[0].vout[0].scriptPubKey;
        CScript &scriptSigRes = t1.vin[0].scriptSig;
        bool worked = ProduceSignature(tsc, scriptPubKey, scriptSigRes);
        BOOST_CHECK(!worked);
    }


    { // This is correct
        TransactionSignatureCreator tsc(&keystore, &tx1, 0, range2);
        const CScript &scriptPubKey = dummyTransactions[0].vout[0].scriptPubKey;
        CScript &scriptSigRes = t1.vin[0].scriptSig;
        bool worked = ProduceSignature(tsc, scriptPubKey, scriptSigRes);
        BOOST_CHECK(worked);
    }

    CheckTransaction(t1, coins);

    // Now create another tx with retargetable range outputs
    CMutableTransaction t2;
    t2.vin.resize(1);
    t2.vin[0] = dummyTransactions[0].SpendOutput(1);
    // t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t2.vout.resize(3);
    t2.vout[0].nValue = 5 * CENT;
    t2.vout[0].scriptPubKey << OP_NOP;
    t2.vout[1].nValue = 6 * CENT;
    t2.vout[1].scriptPubKey << OP_NOP;
    t2.vout[2].nValue = 7 * CENT;
    t2.vout[2].scriptPubKey << OP_NOP;

    {
        CTransaction tx2(t2);
        SigHashType range3 = SigHashType().withThisInput().withRangedOutputs(0, 2);
        TransactionSignatureCreator tsc(&keystore, &tx2, 0, range3);
        const CScript &scriptPubKey = dummyTransactions[0].vout[1].scriptPubKey;
        CScript &scriptSigRes = t2.vin[0].scriptSig;
        bool worked = ProduceSignature(tsc, scriptPubKey, scriptSigRes);
        BOOST_CHECK(worked);
    }

    CheckTransaction(t2, coins);

    // t3 will be the combination of t1 and t2 (without resigning)
    CMutableTransaction t3;
    t3.vin.resize(2);
    // Grab the inputs from both tx.
    t3.vin[0] = t1.vin[0];
    t3.vin[1] = t2.vin[0];
    t3.vout.resize(5);
    t3.vout[0] = t1.vout[0];
    t3.vout[1] = t1.vout[1];
    t3.vout[2] = t2.vout[0];
    t3.vout[3] = t2.vout[1];
    t3.vout[4] = t2.vout[2];

    // should be broken because we did not retarget the sighash in the input coming from t2
    {
        // well the basic tx checks will work.
        CValidationState state;
        CTransactionRef txref = MakeTransactionRef(CTransaction(t3));
        bool result = CheckTransaction(txref, state);
        BOOST_CHECK(result);
        BOOST_CHECK(state.IsValid());

        // But the input should fail sig check
        result = Consensus::CheckTxInputs(txref, state, coins, coins, params);
        BOOST_CHECK(result);
        BOOST_CHECK(state.IsValid());

        // But the input should fail sig check
        unsigned char sighashType = 0;
        ValidationResourceTracker resourceTracker;
        CValidationDebugger debugger; // if you pass in a debugger, the function returns true to keep going
        result = CheckInputs(
            txref, state, coins, coins, true, flags, true, &resourceTracker, params, nullptr, &sighashType, nullptr);
        BOOST_CHECK(!result);
        BOOST_CHECK(!state.IsValid());
    }


    // Now retarget the vin from t2 to outputs starting at index 2
    // This tests sighashtype.md:REQ3 because if the sighashtype was part of the sighash then the signatures
    // will not validate because the data they are signing changes.
    // printf("scriptSig: %s\n", ScriptToAsmStr(t3.vin[1].scriptSig, true).c_str());

    // We can cheat a bit since we know we signed it with [sig].  So the sighashtype is the last bytes.
    // So to retarget the 2nd to last byte should be a 0 (index 0) and we need to make it a 2.
    BOOST_CHECK(t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 2] == 0);
    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 2] = 2;
    CheckTransaction(t3, coins);

    // Negative cases

    // drop an output
    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 1] = 1;
    CheckTransaction(t3, coins, false);
    // drop 2 outputs
    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 1] = 0;
    CheckTransaction(t3, coins, false);

    // Wrong outputs, correct quantity of them
    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 2] = 1;
    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 1] = 2;
    CheckTransaction(t3, coins, false);

    // output start is out of range (REQ1)    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 2] = 5;
    CheckTransaction(t3, coins, false);

    // output end is out of range (REQ2)
    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 2] = 2;
    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 1] = 3;
    CheckTransaction(t3, coins, false);

    t3.vin[1].scriptSig[t3.vin[1].scriptSig.size() - 1] = 255;
    CheckTransaction(t3, coins, false);

    // Move both t1 and t2 by inserting an output at index 0, and swapping their relative order both in inputs
    // and outputs.

    CMutableTransaction t4;
    t4.vin.resize(2);
    // Grab the inputs from both tx.
    t4.vin[0] = t2.vin[0];
    t4.vin[1] = t1.vin[0];
    t4.vout.resize(6);
    t4.vout[0].nValue = 3 * CENT;
    t4.vout[0].scriptPubKey << OP_NOP;
    // Place t2 outputs at index 1
    t4.vout[1] = t2.vout[0];
    t4.vout[2] = t2.vout[1];
    t4.vout[3] = t2.vout[2];
    // Place t1 outputs at index 4
    t4.vout[4] = t1.vout[0];
    t4.vout[5] = t1.vout[1];

    // should be broken because we did not retarget the sighash in the inputs
    CheckTransaction(t4, coins, false);

    // Now retarget the vin from t2 to outputs starting at index 2
    // This tests sighashtype.md:REQ3 because if the sighashtype was part of the sighash then the signatures
    // will not validate because the data they are signing changes.
    // printf("scriptSig: %s\n", ScriptToAsmStr(t4.vin[1].scriptSig, true).c_str());

    // We can cheat a bit since we know we signed it with [sig].  So the sighashtype is the last bytes.
    // So to retarget the 2nd to last byte should be a 0 (index 0) and we need to make it a 2.

    // The old t2 outputs were placed at offset 1
    BOOST_CHECK(t4.vin[0].scriptSig[t4.vin[0].scriptSig.size() - 2] == 0);
    t4.vin[0].scriptSig[t4.vin[0].scriptSig.size() - 2] = 1;

    // The old t1 outputs were placed at offset 4
    BOOST_CHECK(t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 2] == 0);
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 2] = 4;

    CheckTransaction(t4, coins);

    // Negative cases

    // drop an output
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 1] = 0;
    CheckTransaction(t4, coins, false);

    // Wrong outputs, correct quantity of them
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 2] = 1;
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 1] = 1;
    CheckTransaction(t4, coins, false);

    // output start is out of range (REQ1)
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 2] = 255;
    CheckTransaction(t4, coins, false);

    // output end is out of range (REQ2)
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 2] = 2;
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 1] = 3;
    CheckTransaction(t4, coins, false);

    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 1] = 255;
    CheckTransaction(t4, coins, false);

    // Try making a completely different output
    t4.vout.resize(1);
    t4.vout[0].nValue = 50 * CENT;
    t4.vout[0].scriptPubKey << OP_NOP;

    // Retarget the inputs to this one output (won't work)
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 2] = 0;
    t4.vin[1].scriptSig[t4.vin[1].scriptSig.size() - 1] = 0;
    t4.vin[0].scriptSig[t4.vin[0].scriptSig.size() - 2] = 0;
    t4.vin[0].scriptSig[t4.vin[0].scriptSig.size() - 1] = 0;
    CheckTransaction(t4, coins, false);
}


BOOST_AUTO_TEST_CASE(sighash_construction_test)
{
    // Check default values.
    CheckSigHashType(SigHashType(), true, true);

    // Check all possible permutations.
    // std::set<SigHashType::Input> inpTypes{};

    for (SigHashType::Input inp = SigHashType::Input::ALL; inp <= SigHashType::Input::LAST_VALID; ++inp)
    {
        for (SigHashType::Output out = SigHashType::Output::ALL; out <= SigHashType::Output::LAST_VALID; ++out)
        {
            bool hasNoInputs = false;
            bool hasNoOutputs = false;
            bool anyoneCanPay = false;
            bool has2Outputs = false;
            bool hasRangedOutputs = false;
            bool hasAll = false;
            SigHashType t;
            if ((inp == SigHashType::Input::ALL) && (out == SigHashType::Output::ALL))
            {
                t.setAll();
                hasAll = true;
            }
            else
            {
                switch (inp)
                {
                case SigHashType::Input::ALL:
                    break;
                case SigHashType::Input::FIRSTN:
                    t.setFirstNIn(0); // Test the specific 0 inputs case because we have a hasXX api for that
                    hasNoInputs = true;
                    break;
                case SigHashType::Input::THISIN:
                    t.withThisInput();
                    anyoneCanPay = true;
                    break;
                }
                switch (out)
                {
                case SigHashType::Output::ALL:
                    break;
                case SigHashType::Output::FIRSTN:
                    t.setFirstNOut(0); // Test the specific 0 outputs case because we have a hasXX api for that
                    hasNoOutputs = true;
                    break;
                case SigHashType::Output::TWO:
                    t.set2Outs(1, 2);
                    has2Outputs = true;
                    break;
                case SigHashType::Output::RETARGETABLE_RANGE:
                    t.withRangedOutputs(3, 4);
                    hasRangedOutputs = true;
                    break;
                }
            }
            CheckSigHashType(t, true, hasAll, hasNoInputs, hasNoOutputs, anyoneCanPay, has2Outputs, hasRangedOutputs);
        }
    }
}


BOOST_AUTO_TEST_CASE(sighash_serialization_test)
{
    std::vector<unsigned char> v;
    v.reserve(64 + 4);
    for (unsigned int i = 0; i < 256; i++)
    {
        for (unsigned int j = 1; j < 4; j++)
        {
            // create a fake signature and append many different sighashtype combinations
            // we try every sighashtype byte and then append different length sighash data afterwards.
            // since the data has no illegal values (outside of the context of a specific transaction), we just use 0
            v.resize(64 + j);
            v[64] = i;
            for (unsigned int k = 1; k < j; k++)
                v[k] = 0; // fill with dummy values

            SigHashType t(v);

            if (t.isDefined())
            {
                uint8_t up = i >> 4;
                uint8_t lo = i & 0xf;
                BOOST_CHECK(up <= static_cast<uint8_t>(SigHashType::Input::LAST_VALID));
                BOOST_CHECK(lo <= static_cast<uint8_t>(SigHashType::Output::LAST_VALID));

                SigHashType::Input inp = static_cast<SigHashType::Input>(up);
                SigHashType::Output out = static_cast<SigHashType::Output>(lo);
                unsigned int sz = 1; // 1 sighashtype byte
                if (inp == SigHashType::Input::FIRSTN)
                    sz++; // 1 byte, N
                if (out == SigHashType::Output::FIRSTN)
                    sz++; // 1 byte, N
                if (out == SigHashType::Output::TWO)
                    sz += 2; // 2 bytes, A and B
                if (out == SigHashType::Output::RETARGETABLE_RANGE)
                    sz += 2; // 2 bytes, A and B
                BOOST_CHECK(j == sz); // Check that any defined sighashtype has the right number of extra bytes
            }
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
