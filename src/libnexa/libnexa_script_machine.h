// Copyright (c) 2015-2025 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LIBNEXA_SCRIPTMACHINE_H
#define LIBNEXA_SCRIPTMACHINE_H

#include "libnexa_common.h"

#ifndef NO_SCRIPT_MACHINE // The script interpreter is not available if built without libgmp

/*
Since the ScriptMachine is often going to be initialized, called and destructed within a single stack frame, it
does not make copies of the data it is using.  But higher-level language and debugging interaction use the
ScriptMachine across stack frames.  Therefore it is necessary to create a class to hold all of this data on behalf
of the ScriptMachine.
 */
class ScriptMachineData
{
public:
    ScriptMachineData() : sm(nullptr), tx(nullptr), sis(nullptr), script(nullptr) {}
    ScriptMachine *sm;

    CTransactionRef tx;
    std::shared_ptr<BaseSignatureChecker> checker;
    std::shared_ptr<ScriptImportedState> sis;
    std::shared_ptr<CScript> script;

    ~ScriptMachineData()
    {
        if (sm)
        {
            delete sm;
            sm = nullptr;
        }
    }
};

// Create a ScriptMachine with no transaction context -- useful for tests and debugging
// This ScriptMachine can't CHECKSIG or CHECKSIGVERIFY
SLAPI void *CreateNoContextScriptMachine(unsigned int flags);

// Create a ScriptMachine operating in the context of a particular transaction and input.
// The transaction, input index, and input amount are used in CHECKSIG and CHECKSIGVERIFY to generate the hash that
// the signature validates.
void *CreateScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    unsigned char *txData,
    int txbuflen,
    unsigned char *coinData,
    int coinbuflen,
    std::string *errorDetails);

// Create a ScriptMachine operating in the context of a particular transaction and input.
// The transaction, input index, and input amount are used in CHECKSIG and CHECKSIGVERIFY to generate the hash that
// the signature validates.
SLAPI void *CreateScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    unsigned char *txData,
    int txbuflen,
    unsigned char *coinData,
    int coinbuflen);

// Release a ScriptMachine context
SLAPI void SmRelease(void *smId);

// Copy the provided ScriptMachine, returning a new ScriptMachine id that exactly matches the current one
SLAPI void *SmClone(void *smId);

// Evaluate a script within the context of this script machine
SLAPI bool SmEval(void *smId, unsigned char *scriptBuf, unsigned int scriptLen);

// Step-by-step interface: start evaluating a script within the context of this script machine
SLAPI bool SmBeginStep(void *smId, unsigned char *scriptBuf, unsigned int scriptLen);

// Step-by-step interface: execute the next instruction in the script
SLAPI unsigned int SmStep(void *smId);

// Step-by-step interface: get the current position in this script, specified in bytes offset from the script start
SLAPI int SmPos(void *smId);

// Step-by-step interface: End script evaluation
SLAPI bool SmEndStep(void *smId);

// Revert the script machine to initial conditions
SLAPI void SmReset(void *smId);

// Get a stack item, 0 = stack, 1 = altstack,  pass a buffer at least 520 bytes in size
// returns length of the item or -1 if no item.  0 is the stack top
SLAPI void SmSetStackItem(void *smId,
    unsigned int stack,
    int index,
    StackElementType t,
    const unsigned char *value,
    unsigned int valsize);

// Get a stack item, 0 = stack, 1 = altstack,  pass a buffer at least 520 bytes in size
// returns length of the item or -1 if no item.  0 is the stack top
SLAPI int SmGetStackItem(void *smId,
    unsigned int stack,
    unsigned int index,
    StackElementType *t,
    unsigned char *result);

// Returns the last error generated during script evaluation (if any)
SLAPI unsigned int SmGetError(void *smId);

/*
The functions below give C callers (Kotlin/Native on iOS, MacOS and Linux) the same script machine access that
the JVM and Android get via JNI (Java_org_nexa_libnexakotlin_ScriptMachine_* in libnexa_jvm.cpp).  Both use the
C++ helpers declared below so that they behave identically.

Text returning functions write a NUL terminated string into result (resultLen bytes, including the NUL) and return the
string's full length (excluding the NUL).  If the return value >= resultLen, the text was truncated: call again with a
larger buffer.  On error they return -1 and, if resultLen allows, write the error message into result.
*/

// Returns libnexa's STANDARD_SCRIPT_VERIFY_FLAGS (the JNI functions substitute these when passed flags == -1)
SLAPI unsigned int SmStandardScriptVerifyFlags();

// Like CreateScriptMachine, but returns the reason for failure (as text, see above) if it fails (returns null)
SLAPI void *SmCreate(unsigned int flags,
    unsigned int inputIdx,
    const unsigned char *txData,
    int txbuflen,
    const unsigned char *coinData,
    int coinbuflen,
    char *errorResult,
    unsigned int errorResultLen);

// Create a ScriptMachine in a transaction context whose main stack is the result of executing the (push only)
// satisfier and alt stack is the result of executing the (push only) constraint script.  Returns null on failure, and
// the reason (as text, see above).
SLAPI void *SmCreateTemplateContext(unsigned int flags,
    unsigned int inputIdx,
    const unsigned char *txData,
    int txbuflen,
    const unsigned char *coinData,
    int coinbuflen,
    const unsigned char *satisfier,
    unsigned int satisfierLen,
    const unsigned char *constraint,
    unsigned int constraintLen,
    char *errorResult,
    unsigned int errorResultLen);

// Returns 1 if there are more instructions to execute in the script being stepped, 0 if not, -1 if no machine
SLAPI int SmIsMoreSteps(void *smId);

// Step-by-step interface: execute until the script is complete or fails.  Returns false on failure
SLAPI bool SmContinue(void *smId);

// Step-by-step interface: set the current position in the script (in bytes from the beginning).
// Returns the new position, or -1 on error.
SLAPI int SmSetPos(void *smId, int pos);

// Swap the main and alt stacks
SLAPI void SmSwapStacks(void *smId);

// Clear the current error condition
SLAPI void SmClearError(void *smId);

// The last error as text "<error message>(<error number>)".  See above for the text return convention
SLAPI int SmGetErrorText(void *smId, char *result, unsigned int resultLen);

// Get the bignum modulo divisor as hex text
SLAPI int SmGetBMD(void *smId, char *result, unsigned int resultLen);

// Set the bignum modulo divisor from hex text, and return it (after being set) as hex text
SLAPI int SmSetBMD(void *smId, const char *bmdHex, char *result, unsigned int resultLen);

// Overwrite the script being executed, starting at offset.  Returns false on failure
SLAPI bool SmModify(void *smId, int offset, const unsigned char *data, unsigned int dataLen);

// A stack item as "TYPE SIZE HEXh DECIMAL" text (the same as the JNI getStackItemText), or "" if there is no such item.
// stack: 0 = main stack, 1 = alt stack.  index 0 is the stack top.
SLAPI int SmGetStackItemText(void *smId, unsigned int stack, unsigned int index, char *result, unsigned int resultLen);

// A register's value in the same text format as SmGetStackItemText
SLAPI int SmGetRegisterText(void *smId, int regNum, char *result, unsigned int resultLen);

// Set a register.  itemType is "BYTES" (value is hex), "BIGNUM" (value is hex magnitude followed by a sign byte: 00 is
// positive, 80 negative), "BIGNUM(DEC)" or "INTEGER(DEC)" (value is decimal).
// Returns the register's new value in the same text format as SmGetStackItemText
SLAPI int SmSetRegisterText(void *smId,
    int regNum,
    const char *itemType,
    const char *value,
    char *result,
    unsigned int resultLen);

// Clear the resource use statistics
SLAPI void SmResetResourceUse(void *smId);

// Set resource limits.  Pass -1 to leave a limit unchanged
SLAPI void SmSetResourceLimits(void *smId,
    int64_t maxScriptSize,
    int64_t maxOps,
    int64_t maxSignatureChecks,
    int64_t maxStackUse,
    int64_t maxStackItems,
    int64_t maxOpExec,
    int64_t maxOpExecDepth);

// Get the resource use statistics. result must have room for 6 values: signatures checked, instructions executed,
// max stack bytes, max stack items, op_execs executed, op_exec recursion depth
SLAPI void SmGetResourceUse(void *smId, int64_t *result);

// C++ helpers shared by the C and JNI interfaces

// A stack item as "TYPE SIZE HEXh DECIMAL" text
std::string stackItem2String(const StackItem &item);

// See SmCreateTemplateContext.  Returns null and fills error on failure
void *CreateTemplateContextScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    const unsigned char *txData,
    int txbuflen,
    const unsigned char *coinData,
    int coinbuflen,
    const CScript &satisfier,
    const CScript &constraint,
    std::string &error);

// See SmSetRegisterText.  Returns false and fills error on failure, otherwise fills result
bool SetRegisterFromText(ScriptMachineData *smd,
    int regNum,
    const std::string &type,
    const std::string &value,
    std::string &result,
    std::string &error);

// See SmSetResourceLimits
void SetResourceLimits(ScriptMachineData *smd,
    int64_t maxScriptSize,
    int64_t maxOps,
    int64_t maxSignatureChecks,
    int64_t maxStackUse,
    int64_t maxStackItems,
    int64_t maxOpExec,
    int64_t maxOpExecDepth);

#endif // NO_SCRIPT_MACHINE

#endif // LIBNEXA_SCRIPTMACHINE_H
