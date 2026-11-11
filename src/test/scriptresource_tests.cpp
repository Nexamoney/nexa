// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/tx_verify.h"
#include "core_io.h"
#include "key.h"
#include "policy/policy.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "script/standard.h"
#include "test/test_nexa.h"
#include "uint256.h"
#include "unlimited.h"
#include "utiltime.h"

#include <functional>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std;

// Helpers:
#define _STR(x) #x
#define STR(x) _STR(x)

#define FILE_LINE __FILE__ ":" STR(__LINE__)

static std::vector<unsigned char> Serialize(const CScript &s)
{
    std::vector<unsigned char> sSerialized(s.begin(), s.end());
    return sSerialized;
}

BOOST_FIXTURE_TEST_SUITE(scriptresource_tests, BasicTestingSetup)


void CheckScriptResources(const CScript &script, unsigned int expectedMaxStack, const std::string &errLog)
{
    const uint32_t flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis;
    ScriptMachine sm(flags, sis, std::numeric_limits<unsigned int>::max(), std::numeric_limits<unsigned int>::max());
    sm.maxScriptSize = MAX_SCRIPT_TEMPLATE_SIZE;
    sm.Eval(script);
    BOOST_CHECK(sm.getError() == SCRIPT_ERR_OK);
    auto &stats = sm.getStats();
    std::stringstream expected;
    expected << ".  Got: " << stats.maxStackBytes << " Expected: " << expectedMaxStack;
    BOOST_CHECK_MESSAGE(stats.maxStackBytes == expectedMaxStack, errLog + expected.str());
}

#define CHECK(script, expectedMaxStack) \
    CheckScriptResources(script, expectedMaxStack, std::string("Actual error at: " FILE_LINE))

BOOST_AUTO_TEST_CASE(TestScriptResources)
{
    uint160 dummy;
    const CScript s1 = CScript() << OP_1 << ToByteVector(dummy) << ToByteVector(dummy) << OP_2;
    CHECK(s1, 1 + 20 + 20 + 1);

    // true takes the if side
    const CScript s2 = CScript() << OP_1 << OP_IF << OP_1 << OP_1 << OP_ELSE << OP_1 << OP_1 << OP_1 << OP_ENDIF;
    CHECK(s2, 2);

    // since its false it should take the else side
    const CScript s3 = CScript() << OP_0 << OP_IF << OP_1 << OP_1 << OP_ELSE << OP_1 << OP_1 << OP_1 << OP_ENDIF;
    CHECK(s3, 3);

    // Check all the push opcodes
    for (unsigned int i = 0; i < 70001; i += 250)
    {
        VchType v(i, 0xa5);
        const CScript s = CScript() << v;
        BOOST_CHECK(s.size() > i);
        CHECK(s, i);

        // Check dup and dup2 with large sized pushes
        const CScript sdup = CScript() << v << OP_DUP;
        CHECK(sdup, 2 * i);

        const CScript sdup2 = CScript() << v << OP_DUP << OP_2DUP;
        CHECK(sdup2, 4 * i);
    }

    CScript exec1 = CScript() << OP_DUP << OP_DUP; // just code that extends the stack
    CScript execAlt = CScript() << OP_DUP << OP_TOALTSTACK << OP_DUP; // just code that extends the stack
    CScript execExec = CScript() << OP_9 << OP_9 << OP_2SWAP << OP_1 << OP_0 << OP_EXEC;

    std::vector<std::pair<int, CScript> > tests = {
        {0, CScript() << OP_0 << OP_0}, // OP_0 is actually represented by nothing
        {2, CScript() << OP_2 << OP_1 << OP_DROP}, // Verify high-water mark
        {2, CScript() << OP_2 << OP_1 << OP_DROP << OP_DROP << OP_3},

        {6, CScript() << OP_1 << VchType(4, 0xa5) << OP_OVER}, {9, CScript() << VchType(4, 0xa5) << OP_1 << OP_OVER},

        {20, CScript() << VchType(10, 0xa5) << OP_DUP << OP_CAT}, // Verify CAT (does not change size)

        {5, CScript() << OP_2 << VchType(4, 0xa5) << OP_SWAP}, // Verify swap
        {13, CScript() << OP_2 << VchType(5, 0xa5) << OP_1 << VchType(6, 0xa5) << OP_2SWAP}, // Verify swap2

        // verify altstack is counted.
        {15, CScript() << VchType(5, 0xa5) << OP_DUP << OP_TOALTSTACK << OP_DUP},

        // verify bignum
        // convert the biggest 2 byte number into a bignum squared makes 2 bytes + 1 sign byte
        {3, CScript() << 0xFFFF << OP_BIN2BIGNUM},
        // convert the biggest 2 byte number into a bignum squared makes 4 bytes + 1 sign byte, again makes
        // 8 bytes + 1 sign byte
        //                  2           3             6         5         10        9
        {10, CScript() << 0xFFFF << OP_BIN2BIGNUM << OP_DUP << OP_MUL << OP_DUP << OP_MUL},

        // verify opexec
        {30, CScript() << Serialize(exec1) << VchType(10, 0xa5) << OP_1 << OP_0 << OP_EXEC},
        // verify opexec that uses its own altstack
        {30, CScript() << Serialize(execAlt) << VchType(10, 0xa5) << OP_1 << OP_0 << OP_EXEC},
        // Something on the parent stack is added in
        {31, CScript() << OP_1 << Serialize(exec1) << VchType(10, 0xa5) << OP_1 << OP_0 << OP_EXEC},
        // All 3 OP_9s are extra bytes on parent execution stacks (which count) and the innermost double OP_DUP
        // creates 3 copies of the 10 byte object resulting in 33 bytes.
        {33, CScript() << OP_9 << Serialize(execExec) << VchType(10, 0xa5) << Serialize(exec1) << OP_2 << OP_0
                       << OP_EXEC}};

    for (const auto &t : tests)
    {
        CHECK(t.second, t.first);
    }
}

// Replacing a stack item with a shorter one must shrink the tracked stack size.  If the shrink were not
// accounted for, later pushes would be measured against a stale (too large) total.
BOOST_AUTO_TEST_CASE(TestStackItemReplacementShrinks)
{
    // Script level: OP_PLACE overwrites the 60 byte item with a copy of the 1 byte item (61 -> 2 bytes),
    // so after pushing 100 more bytes the high-water mark is exactly 102 (it would be 161 without the shrink).
    CHECK(CScript() << VchType(60, 0xa5) << OP_1 << OP_1 << OP_PLACE << VchType(100, 0xa5), 102);
    // OP_SPLIT replaces the 60 byte data with a 10 byte piece (shrink) and the 1 byte split position with the
    // 50 byte remainder (grow), so the total stays 60 and the 100 byte push brings it to exactly 160.
    CHECK(CScript() << VchType(60, 0xa5) << 10 << OP_SPLIT << VchType(100, 0xa5), 160);

    const uint32_t flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis;

    // Main stack, via the setStackItem API
    {
        ScriptMachine sm(
            flags, sis, std::numeric_limits<unsigned int>::max(), std::numeric_limits<unsigned int>::max());
        sm.maxStackUse = 100;
        sm.PushStack(VchType(60, 0xa5));
        sm.PushStack(VchType(30, 0x5a)); // total 90
        // Replace the bottom 60 byte item with a 10 byte item: total drops to 40
        sm.setStackItem(1, VchType(10, 0x11));
        BOOST_CHECK_EQUAL(sm.getStack().size(), 2U);
        BOOST_CHECK_EQUAL(sm.getStack()[0].size(), 10U);
        // 40 + 60 == 100 fits exactly, but only if the replacement freed 50 bytes
        BOOST_CHECK_NO_THROW(sm.PushStack(VchType(60, 0x22)));
        BOOST_CHECK_EQUAL(sm.getStats().maxStackBytes, 100U);
        // The stack is now exactly at its limit, so a single additional byte must be rejected
        BOOST_CHECK_THROW(sm.PushStack(VchType(1, 0x33)), script_error);
    }

    // Altstack, via the setAltStackItem API
    {
        ScriptMachine sm(
            flags, sis, std::numeric_limits<unsigned int>::max(), std::numeric_limits<unsigned int>::max());
        sm.maxStackUse = 100;
        sm.PushAltStack(VchType(60, 0xa5));
        sm.PushAltStack(VchType(30, 0x5a)); // total 90
        // Replace the bottom 60 byte altstack item with a 10 byte item: total drops to 40
        sm.setAltStackItem(1, VchType(10, 0x11));
        BOOST_CHECK_EQUAL(sm.getAltStack().size(), 2U);
        BOOST_CHECK_EQUAL(sm.getAltStack()[0].size(), 10U);
        BOOST_CHECK_NO_THROW(sm.PushAltStack(VchType(60, 0x22)));
        BOOST_CHECK_EQUAL(sm.getStats().maxStackBytes, 100U);
        BOOST_CHECK_THROW(sm.PushAltStack(VchType(1, 0x33)), script_error);
    }
}

// Evaluate script with a deliberately small stack byte budget and check the outcome
static void CheckStackBudget(const CScript &script,
    int64_t maxStackUse,
    ScriptError expectedError,
    unsigned int expectedMaxStack,
    const std::string &errLog)
{
    const uint32_t flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
    ScriptImportedState sis;
    ScriptMachine sm(flags, sis, std::numeric_limits<unsigned int>::max(), std::numeric_limits<unsigned int>::max());
    sm.maxScriptSize = MAX_SCRIPT_TEMPLATE_SIZE;
    sm.maxStackUse = maxStackUse;
    bool ok = sm.Eval(script);
    BOOST_CHECK_MESSAGE(ok == (expectedError == SCRIPT_ERR_OK), errLog + ": unexpected Eval result");
    BOOST_CHECK_MESSAGE(sm.getError() == expectedError,
        errLog + ": got error " + ScriptErrorString(sm.getError()) + " expected " + ScriptErrorString(expectedError));
    if (expectedError == SCRIPT_ERR_OK)
    {
        std::stringstream s;
        s << ": maxStackBytes got " << sm.getStats().maxStackBytes << " expected " << expectedMaxStack;
        BOOST_CHECK_MESSAGE(sm.getStats().maxStackBytes == expectedMaxStack, errLog + s.str());
    }
}

#define CHECK_BUDGET(script, limit, err, expectedMaxStack) \
    CheckStackBudget(script, limit, err, expectedMaxStack, std::string("at: " FILE_LINE))

// OP_EXEC children get the parent's byte budget minus what the parent is currently using, so the combined
// bytes held by the parent and all of its (nested) children can never exceed the parent's maxStackUse.
BOOST_AUTO_TEST_CASE(TestOpExecSharedStackBudget)
{
    const int64_t limit = 100;

    // Child code that grows its stack to exactly 80 bytes (4 copies of a 20 byte item).
    // Its serialized code is only 24 bytes, so the parent can hold it alongside its own data.
    const CScript child80 = CScript() << VchType(20, 0xa5) << OP_DUP << OP_DUP << OP_DUP;

    // Parent keeps 20 bytes while the child runs: 20 + 80 == 100, exactly at the limit.
    // (code, paramQty and returnedParamQty are popped before the child starts; OP_0 is 0 bytes anyway)
    CHECK_BUDGET(CScript() << VchType(20, 0x11) << Serialize(child80) << 0 << 0 << OP_EXEC, limit, SCRIPT_ERR_OK, 100);
    // One more parent byte leaves the child only 79 bytes, so the child's 4th 20 byte item fails
    CHECK_BUDGET(
        CScript() << VchType(21, 0x11) << Serialize(child80) << 0 << 0 << OP_EXEC, limit, SCRIPT_ERR_STACK_BYTES, 0);

    // Parameters move from the parent to the child, so they stop counting against the parent and start
    // counting against the child: parent keeps 20, child holds the 20 byte param plus 3 copies == 80.
    const CScript dup3 = CScript() << OP_DUP << OP_DUP << OP_DUP;
    CHECK_BUDGET(CScript() << VchType(20, 0x11) << Serialize(dup3) << VchType(20, 0x22) << 1 << 0 << OP_EXEC, limit,
        SCRIPT_ERR_OK, 100);
    CHECK_BUDGET(CScript() << VchType(21, 0x11) << Serialize(dup3) << VchType(20, 0x22) << 1 << 0 << OP_EXEC, limit,
        SCRIPT_ERR_STACK_BYTES, 0);

    // Returned items are pushed back onto the parent once the child exits, and count against the parent:
    // parent 20 + one returned 20 byte item == 40, then 3 more copies reaches exactly 100, a 4th exceeds it.
    CHECK_BUDGET(
        CScript() << VchType(20, 0x11) << Serialize(child80) << 0 << 1 << OP_EXEC << OP_DUP << OP_DUP << OP_DUP, limit,
        SCRIPT_ERR_OK, 100);
    CHECK_BUDGET(CScript() << VchType(20, 0x11) << Serialize(child80) << 0 << 1 << OP_EXEC << OP_DUP << OP_DUP << OP_DUP
                           << OP_DUP,
        limit, SCRIPT_ERR_STACK_BYTES, 0);

    // Nested OP_EXEC: the parent keeps 10 bytes and the child keeps 10 bytes while the grandchild uses 80.
    // 10 + 10 + 80 == 100 fits exactly.
    {
        const CScript child = CScript() << VchType(10, 0x33) << Serialize(child80) << 0 << 0
                                        << OP_EXEC; // child holds 10 bytes
        CHECK_BUDGET(
            CScript() << VchType(10, 0x11) << Serialize(child) << 0 << 0 << OP_EXEC, limit, SCRIPT_ERR_OK, 100);
        // One extra byte in the parent leaves the grandchild 79 bytes
        CHECK_BUDGET(
            CScript() << VchType(11, 0x11) << Serialize(child) << 0 << 0 << OP_EXEC, limit, SCRIPT_ERR_STACK_BYTES, 0);
    }
    {
        // One extra byte in the middle (child) machine also leaves the grandchild 79 bytes
        const CScript child11 = CScript() << VchType(11, 0x33) << Serialize(child80) << 0 << 0 << OP_EXEC;
        CHECK_BUDGET(CScript() << VchType(10, 0x11) << Serialize(child11) << 0 << 0 << OP_EXEC, limit,
            SCRIPT_ERR_STACK_BYTES, 0);
    }

    // The parent's altstack counts against the child's budget too
    CHECK_BUDGET(CScript() << VchType(20, 0x11) << OP_TOALTSTACK << Serialize(child80) << 0 << 0 << OP_EXEC, limit,
        SCRIPT_ERR_OK, 100);
    CHECK_BUDGET(CScript() << VchType(21, 0x11) << OP_TOALTSTACK << Serialize(child80) << 0 << 0 << OP_EXEC, limit,
        SCRIPT_ERR_STACK_BYTES, 0);
}


static const uint32_t limitedFlags[] = {STANDARD_SCRIPT_VERIFY_FLAGS, POST_UPGRADE2_MANDATORY_SCRIPT_VERIFY_FLAGS};

static ScriptError EvalError(const CScript &script, uint32_t flags, const ScriptImportedState &sis)
{
    ScriptMachine sm(flags, sis, MAX_OPS_PER_SCRIPT_TEMPLATE, 0xffffffff);
    sm.maxScriptSize = MAX_SCRIPT_TEMPLATE_SIZE;
    sm.Eval(script);
    return sm.getError();
}

static ScriptError EvalError(const CScript &script, uint32_t flags)
{
    return EvalError(script, flags, ScriptImportedState());
}

// Runs op on a 500 byte item count times
static CScript RepeatOnItem(opcodetype op, int count)
{
    CScript script = CScript() << VchType(500, 0xa5);
    for (int i = 0; i < count; i++)
        script << OP_DUP << op << OP_DROP;
    return script << OP_DROP;
}

// Hashing a near-1 MiB stack item costs the same single op as hashing 1 byte, so one template input
// can hash about 8 GB within MAX_OPS_PER_SCRIPT_TEMPLATE. Policy, and consensus from upgrade2, must reject it.
BOOST_AUTO_TEST_CASE(TestHashOpCostScalesWithItemSize)
{
    CScript script = CScript() << VchType(500, 0xa5);
    for (int i = 0; i < 10; i++) // 500 << 10 = 512000 bytes; two copies still fit in MAX_SCRIPT_STACK_SIZE
        script << OP_DUP << OP_CAT;
    for (int i = 0; i < 16000; i++)
        script << OP_DUP << OP_SHA256 << OP_DROP;
    script << OP_DROP;
    BOOST_CHECK(script.size() <= MAX_SCRIPT_TEMPLATE_SIZE);

    for (uint32_t flags : limitedFlags)
    {
        int64_t start = GetTimeMicros();
        ScriptError err = EvalError(script, flags);
        int64_t elapsed = GetTimeMicros() - start;
        BOOST_CHECK_MESSAGE(
            err != SCRIPT_ERR_OK, "script hashing 16000 x 512000 bytes was accepted after " << elapsed / 1000 << " ms");
    }
}

// An input may hash 4096 bytes plus twice the length of its scriptSig
BOOST_AUTO_TEST_CASE(TestHashedBytesLimit)
{
    for (opcodetype op : {OP_SHA256, OP_HASH256, OP_HASH160, OP_RIPEMD160, OP_SHA1})
    {
        for (uint32_t flags : limitedFlags)
        {
            BOOST_CHECK_MESSAGE(EvalError(RepeatOnItem(op, 8), flags) == SCRIPT_ERR_OK, GetOpName(op));
            BOOST_CHECK_MESSAGE(EvalError(RepeatOnItem(op, 9), flags) != SCRIPT_ERR_OK, GetOpName(op));
        }
        // Not a consensus rule before upgrade2
        BOOST_CHECK_MESSAGE(
            EvalError(RepeatOnItem(op, 9), MANDATORY_SCRIPT_VERIFY_FLAGS) == SCRIPT_ERR_OK, GetOpName(op));
    }

    // A 1003 byte scriptSig allows 2006 more bytes
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << VchType(1000, 0);
    ScriptImportedState sis;
    sis.tx = MakeTransactionRef(tx);
    sis.nIn = 0;
    for (uint32_t flags : limitedFlags)
    {
        BOOST_CHECK(EvalError(RepeatOnItem(OP_SHA256, 12), flags, sis) == SCRIPT_ERR_OK);
        BOOST_CHECK(EvalError(RepeatOnItem(OP_SHA256, 13), flags, sis) != SCRIPT_ERR_OK);
    }

    // Scripts run by OP_EXEC share the allowance of the input
    const CScript code = RepeatOnItem(OP_SHA256, 5);
    CScript once = CScript() << Serialize(code) << OP_0 << OP_0 << OP_EXEC;
    CScript twice = once;
    twice << Serialize(code) << OP_0 << OP_0 << OP_EXEC;
    for (uint32_t flags : limitedFlags)
    {
        BOOST_CHECK(EvalError(once, flags) == SCRIPT_ERR_OK);
        BOOST_CHECK(EvalError(twice, flags) != SCRIPT_ERR_OK);
    }
    BOOST_CHECK(EvalError(twice, MANDATORY_SCRIPT_VERIFY_FLAGS) == SCRIPT_ERR_OK);
}

// Pushes a 500 byte item, then copies it count times
static CScript CopyItem(int count)
{
    CScript script = CScript() << VchType(500, 0xa5);
    for (int i = 0; i < count; i++)
        script << OP_DUP << OP_DROP;
    return script;
}

// Copying a near-1 MiB stack item costs the same single op as copying 1 byte, so one template input can copy
// about 8 GB within MAX_OPS_PER_SCRIPT_TEMPLATE. Policy, and consensus from upgrade2, must reject it.
BOOST_AUTO_TEST_CASE(TestCopyOpCostScalesWithItemSize)
{
    CScript script = CScript() << VchType(500, 0xa5);
    for (int i = 0; i < 10; i++) // 512000 bytes
        script << OP_DUP << OP_CAT;
    for (int i = 0; i < 16000; i++)
        script << OP_DUP << OP_DROP;
    for (uint32_t flags : limitedFlags)
        BOOST_CHECK(EvalError(script, flags) != SCRIPT_ERR_OK);
}

// An input may copy 2 MiB plus 16 times the length of its scriptSig
BOOST_AUTO_TEST_CASE(TestCopiedBytesLimit)
{
    // 500 + 4193 * 500 = 2097000 bytes
    for (uint32_t flags : limitedFlags)
    {
        BOOST_CHECK(EvalError(CopyItem(4193), flags) == SCRIPT_ERR_OK);
        BOOST_CHECK(EvalError(CopyItem(4194), flags) != SCRIPT_ERR_OK);
    }
    // Not a consensus rule before upgrade2
    BOOST_CHECK(EvalError(CopyItem(4194), MANDATORY_SCRIPT_VERIFY_FLAGS) == SCRIPT_ERR_OK);

    // A 1003 byte scriptSig allows 16048 more bytes
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << VchType(1000, 0);
    ScriptImportedState sis;
    sis.tx = MakeTransactionRef(tx);
    sis.nIn = 0;
    for (uint32_t flags : limitedFlags)
    {
        BOOST_CHECK(EvalError(CopyItem(4225), flags, sis) == SCRIPT_ERR_OK);
        BOOST_CHECK(EvalError(CopyItem(4226), flags, sis) != SCRIPT_ERR_OK);
    }

    // Scripts run by OP_EXEC share the allowance of the input
    const CScript code = CopyItem(2097) << OP_DROP;
    CScript once = CScript() << Serialize(code) << OP_0 << OP_0 << OP_EXEC;
    CScript twice = once;
    twice << Serialize(code) << OP_0 << OP_0 << OP_EXEC;
    for (uint32_t flags : limitedFlags)
    {
        BOOST_CHECK(EvalError(once, flags) == SCRIPT_ERR_OK);
        BOOST_CHECK(EvalError(twice, flags) != SCRIPT_ERR_OK);
    }
    BOOST_CHECK(EvalError(twice, MANDATORY_SCRIPT_VERIFY_FLAGS) == SCRIPT_ERR_OK);
}

// A byte array converts to a BigNum when the number it holds is at most 8192 bits wide
BOOST_AUTO_TEST_CASE(TestBigNumConversionLimit)
{
    // little-endian sign-magnitude: the last byte carries the sign
    VchType widest(1024, 0xff);
    widest.push_back(0);
    VchType tooWide(1024, 0);
    tooWide.push_back(1);
    tooWide.push_back(0);
    VchType padded(2048, 0); // a longer item holding a small number
    padded[0] = 1;

    const std::function<CScript(const VchType &)> conversions[] = {[](const VchType &item)
        { return CScript() << item << OP_BIN2BIGNUM; },
        [](const VchType &item) { return CScript() << OP_1 << OP_BIN2BIGNUM << item << OP_ADD; }};
    for (const auto &convert : conversions)
    {
        for (uint32_t flags : limitedFlags)
        {
            BOOST_CHECK(EvalError(convert(widest), flags) == SCRIPT_ERR_OK);
            BOOST_CHECK(EvalError(convert(padded), flags) == SCRIPT_ERR_OK);
            BOOST_CHECK(EvalError(convert(tooWide), flags) != SCRIPT_ERR_OK);
        }
        // Not a consensus rule before upgrade2
        BOOST_CHECK(EvalError(convert(tooWide), MANDATORY_SCRIPT_VERIFY_FLAGS) == SCRIPT_ERR_OK);
    }
}

// Bytes a script counts as copied, with no limit enforced
static uint64_t CopiedBytes(const CScript &script)
{
    ScriptMachine sm(MANDATORY_SCRIPT_VERIFY_FLAGS, ScriptImportedState(), MAX_OPS_PER_SCRIPT_TEMPLATE, 0xffffffff);
    sm.maxScriptSize = MAX_SCRIPT_TEMPLATE_SIZE;
    sm.Eval(script);
    BOOST_CHECK(sm.getError() == SCRIPT_ERR_OK);
    return sm.getStats().copiedBytes;
}

// Every byte of a stack item that an opcode pushes, copies, moves, rewrites or compares is counted
BOOST_AUTO_TEST_CASE(TestCopiedBytesCount)
{
    const VchType item(500, 0xa5);
    const VchType zeros(500, 0);
    const uint64_t base = CopiedBytes(CScript() << item);
    BOOST_CHECK_EQUAL(base, 500);

    const std::vector<std::pair<CScript, uint64_t> > tests = {
        {CScript() << OP_DROP, 0},
        {CScript() << OP_SIZE, 2},
        {CScript() << OP_DUP, 500},
        {CScript() << OP_DUP << OP_2DUP, 500 + 1000},
        {CScript() << OP_DUP << OP_DUP << OP_3DUP, 1000 + 1500},
        {CScript() << OP_DUP << OP_OVER, 500 + 500},
        {CScript() << OP_DUP << OP_TUCK, 500 + 500},
        {CScript() << OP_DUP << OP_2DUP << OP_2OVER, 1500 + 1000},
        {CScript() << OP_1 << OP_1 << OP_PICK, 2 + 500},
        {CScript() << OP_1 << OP_1 << OP_ROLL, 2 + 500},
        {CScript() << OP_1 << OP_SWAP << OP_1NEGATE << OP_PICK, 2 + 500},
        {CScript() << OP_1 << OP_SWAP << OP_2 << OP_NEGATE << OP_ROLL, 3 + 500},
        {CScript() << OP_1 << OP_1 << OP_1 << OP_1 << OP_1 << OP_2ROT, 5 + 501},
        {CScript() << OP_1 << OP_SWAP, 1},
        {CScript() << OP_1 << OP_1 << OP_ROT, 2},
        {CScript() << OP_TOALTSTACK, 500},
        {CScript() << OP_TOALTSTACK << OP_FROMALTSTACK, 1000},
        {CScript() << OP_IFDUP, 500 + 500},
        {CScript() << OP_DROP << zeros << OP_IFDUP, 500 + 500},
        {CScript() << OP_DUP << OP_CAT, 500 + 1000},
        {CScript() << 100 << OP_SPLIT, 1 + 500},
        {CScript() << OP_DUP << OP_AND, 500 + 500},
        {CScript() << OP_DUP << OP_EQUAL, 500 + 500 + 1},
        {CScript() << OP_1 << OP_EQUAL, 1}, // different sizes are not compared
        {CScript() << OP_REVERSEBYTES, 500},
        {CScript() << OP_0 << OP_STORE, 500},
        {CScript() << OP_0 << OP_STORE << OP_0 << OP_LOAD, 500 + 500},
        {CScript() << OP_DUP << OP_1 << OP_PLACE, 500 + 1 + 500},
        {CScript() << OP_DROP << OP_1 << 500 << OP_NUM2BIN, 1 + 2 + 1 + 500},
        {CScript() << OP_DROP << zeros << OP_BIN2NUM, 500 + 500},
        {CScript() << OP_SHA256, 32},
    };
    for (const auto &[ops, expected] : tests)
    {
        const uint64_t counted = CopiedBytes((CScript() << item) + ops) - base;
        BOOST_CHECK_MESSAGE(counted == expected, ScriptToAsmStr(ops) << " counted " << counted);
    }
}

BOOST_AUTO_TEST_SUITE_END()
