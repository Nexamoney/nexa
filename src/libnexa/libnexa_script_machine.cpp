// Copyright (c) 2015-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "libnexa_script_machine.h"

#ifndef NO_SCRIPT_MACHINE

// Create a ScriptMachine with no transaction context -- useful for tests and debugging
// This ScriptMachine can't CHECKSIG or CHECKSIGVERIFY
SLAPI void *CreateNoContextScriptMachine(unsigned int flags)
{
    ScriptMachineData *smd = new ScriptMachineData();
    smd->sis = std::make_shared<ScriptImportedState>();
    smd->sm = new ScriptMachine(flags, *smd->sis, 0xffffffff, 0xffffffff);
    return (void *)smd;
}

// Create a ScriptMachine operating in the context of a particular transaction and input.
// The transaction, input index, and input amount are used in CHECKSIG and CHECKSIGVERIFY to generate the hash that
// the signature validates.
void *CreateScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    unsigned char *txData,
    int txbuflen,
    unsigned char *coinData,
    int coinbuflen,
    std::string *errorDetails)
{
    checkSigInit();

    ScriptMachineData *smd = new ScriptMachineData();
    std::shared_ptr<CTransaction> txref = std::make_shared<CTransaction>();
    std::vector<CTxOut> coins;

    {
        CDataStream ssData((char *)txData, (char *)txData + txbuflen, SER_NETWORK, PROTOCOL_VERSION);
        try
        {
            ssData >> *txref;
        }
        catch (const std::exception &)
        {
            if (errorDetails)
            {
                *errorDetails = "Error deserializing transaction";
            }
            delete smd;
            return 0;
        }
    }

    {
        CDataStream ssData((char *)coinData, (char *)coinData + coinbuflen, SER_NETWORK, PROTOCOL_VERSION);
        try
        {
            ssData >> coins;
        }
        catch (const std::exception &)
        {
            if (errorDetails)
            {
                *errorDetails = "Error deserializing UTXO list";
            }
            delete smd;
            return 0;
        }
    }

    // The passed coins vector needs to be the txout for each vin, so the sizes must be the same
    if (coins.size() != txref->vin.size())
    {
        if (errorDetails)
        {
            *errorDetails = "Error: UTXO list length does not match tx vin length";
        }
        delete smd;
        return 0;
    }
    if (inputIdx >= txref->vin.size())
    {
        if (errorDetails)
        {
            *errorDetails = "Error: Selected input index is out of bounds";
        }
        delete smd;
        return 0;
    }

    CValidationState state;
    {
        // Fill the validation state with derived data about this transaction
        /* This pulls in too much stuff (in particular it needs to determine input coin height,
           to check coinbase spendability, which requires knowing the tip height).
           Think about refactoring CheckTxInputs to take the tip height as a parameter for functional isolation
           For now, calculate the needed data directly.
           Leaving this "canonical" code in for reference purposes
        if (!Consensus::CheckTxInputs(txref, state, prevouts))
        {
            delete smd;
            return 0;
        }
        */
        CAmount amountIn = 0;
        for (size_t i = 0; i < txref->vin.size(); i++)
        {
            amountIn += txref->vin[i].amount;
        }
        CAmount amountOut = 0;
        for (size_t i = 0; i < txref->vout.size(); i++)
        {
            amountOut += txref->vout[i].nValue;
        }
        state.inAmount = amountIn;
        state.outAmount = amountOut;
        state.fee = amountIn - amountOut;
        // coins[i] is the output spent by input i (checked above), which is what CheckGroupTokens wants.
        // This deliberately avoids CCoinsViewCache (the UTXO machinery) so that the script machine has no UTXO
        // dependency and can be built into light libraries.
        if (!CheckGroupTokens(*txref, state, coins, flags & SCRIPT_GROUP_GENESIS_SPENDS_INPUT))
        {
            if (errorDetails)
            {
                *errorDetails = std::string("Error: ") + state.GetRejectReason() + " " + state.GetDebugMessage();
            }
            delete smd;
            return 0;
        }
    }

    smd->tx = txref;
    // Its ok to get the bare tx pointer: the life of the CTransaction is the same as TransactionSignatureChecker
    // -1 is the inputAmount -- no longer used
    smd->checker = std::make_shared<TransactionSignatureChecker>(smd->tx.get(), inputIdx, flags);
    smd->sis = std::make_shared<ScriptImportedState>(&(*smd->checker), smd->tx, state, coins, inputIdx);
    // max ops and max sigchecks are set to the maximum value with the intention that the caller will check these if
    // needed because many uses of the script machine are for debugging and experimental scripts.
    smd->sm = new ScriptMachine(flags, *smd->sis, 0xffffffff, 0xffffffff);
    return (void *)smd;
}

// Create a ScriptMachine operating in the context of a particular transaction and input.
// The transaction, input index, and input amount are used in CHECKSIG and CHECKSIGVERIFY to generate the hash that
// the signature validates.
SLAPI void *CreateScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    unsigned char *txData,
    int txbuflen,
    unsigned char *coinData,
    int coinbuflen)
{
    return CreateScriptMachine(flags, inputIdx, txData, txbuflen, coinData, coinbuflen, nullptr);
}


// Release a ScriptMachine context
SLAPI void SmRelease(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    if (!smd)
    {
        return;
    }
    delete smd;
}

// Copy the provided ScriptMachine, returning a new ScriptMachine id that exactly matches the current one
SLAPI void *SmClone(void *smId)
{
    ScriptMachineData *from = (ScriptMachineData *)smId;
    ScriptMachineData *to = new ScriptMachineData();
    to->script = from->script;
    to->sis = from->sis;
    to->tx = from->tx;
    to->sis->tx = to->tx; // Get it pointing to the right object even though they are currently the same
    to->sm = new ScriptMachine(*from->sm);
    return (void *)to;
}

// Evaluate a script within the context of this script machine
SLAPI bool SmEval(void *smId, unsigned char *scriptBuf, unsigned int scriptLen)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;

    CScript script(scriptBuf, scriptBuf + scriptLen);
    bool ret = smd->sm->Eval(script);
    return ret;
}

// Step-by-step interface: start evaluating a script within the context of this script machine
SLAPI bool SmBeginStep(void *smId, unsigned char *scriptBuf, unsigned int scriptLen)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    // shared_ptr will auto-release the old one
    smd->script = std::make_shared<CScript>(scriptBuf, scriptBuf + scriptLen);
    bool ret = smd->sm->BeginStep(*smd->script);
    return ret;
}

// Step-by-step interface: execute the next instruction in the script
SLAPI unsigned int SmStep(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    unsigned int ret = smd->sm->Step();
    return ret;
}

// Step-by-step interface: get the current position in this script, specified in bytes offset from the script start
SLAPI int SmPos(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    return smd->sm->getPos();
}


// Step-by-step interface: End script evaluation
SLAPI bool SmEndStep(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    bool ret = smd->sm->EndStep();
    return ret;
}

// Revert the script machine to initial conditions
SLAPI void SmReset(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    smd->sm->Reset();
}

// Get a stack item, 0 = stack, 1 = altstack,  pass a buffer at least 520 bytes in size
// returns length of the item or -1 if no item.  0 is the stack top
SLAPI void SmSetStackItem(void *smId,
    unsigned int stack,
    int index,
    StackElementType t,
    const unsigned char *value,
    unsigned int valsize)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;

    const std::vector<StackItem> &stk = (stack == 0) ? smd->sm->getStack() : smd->sm->getAltStack();
    if (((int)stk.size()) <= index)
    {
        return;
    }
    StackItem si;
    if (t == StackElementType::VCH)
    {
        si = StackItem(value, value + valsize);
    }
    else if (t == StackElementType::BIGNUM)
    {
        BigNum bn;
        bn.deserialize(value, valsize);
        si = StackItem(bn);
    }
    else
    {
        return;
    }

    if (stack == 0)
    {
        smd->sm->setStackItem(index, si);
    }
    else if (stack == 1)
    {
        smd->sm->setAltStackItem(index, si);
    }
}

// Get a stack item, 0 = stack, 1 = altstack,  pass a buffer at least 520 bytes in size
// returns length of the item or -1 if no item.  0 is the stack top
SLAPI int SmGetStackItem(void *smId, unsigned int stack, unsigned int index, StackElementType *t, unsigned char *result)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;

    const std::vector<StackItem> &stk = (stack == 0) ? smd->sm->getStack() : smd->sm->getAltStack();
    if (stk.size() <= index)
    {
        return -1;
    }
    index = stk.size() - index - 1; // reverse it so 0 is stack top

    const StackItem &item = stk[index];

    *t = item.type;
    if (item.type == StackElementType::VCH)
    {
        int sz = item.size();
        memcpy(result, item.data().data(), sz);
        return sz;
    }
    else if (item.type == StackElementType::BIGNUM)
    {
        int sz = item.num().serialize(result, 512);
        return (sz);
    }
    else
    {
        return 0;
    }
}

// Returns the last error generated during script evaluation (if any)
SLAPI unsigned int SmGetError(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    return (unsigned int)smd->sm->getError();
}

// Copy text into a C caller's buffer, see the text return convention in libnexa_script_machine.h
static int returnText(const std::string &text, char *result, unsigned int resultLen)
{
    if (result && resultLen > 0)
    {
        size_t n = std::min<size_t>(text.size(), resultLen - 1);
        memcpy(result, text.data(), n);
        result[n] = 0;
    }
    return (int)text.size();
}

static int returnError(const std::string &error, char *result, unsigned int resultLen)
{
    returnText(error, result, resultLen);
    return -1;
}

static ScriptMachineData *getSmd(void *smId)
{
    ScriptMachineData *smd = (ScriptMachineData *)smId;
    if ((!smd) || (!smd->sm))
        return nullptr;
    return smd;
}

static const char *NO_SCRIPT_MACHINE_ERROR = "internal error: no script machine";

std::string stackItem2String(const StackItem &item)
{
    std::string ret;
    ret.reserve(256);
    // return TYPE SIZE string(hex or false) DECIMAL
    if (item.type == StackElementType::VCH)
    {
        size_t sz = item.size();
        // special case for false stack item because insanity of interpreter
        if (sz == 0)
            return std::string(ret + "BYTES 0 false 0");
        ret += "BYTES " + std::to_string(sz) + " " + item.hex() + "h";
        try
        {
            int64_t t = item.asInt64(false); // TODO report minimal encoding
            ret += " " + std::to_string(t);
        }
        catch (script_error &e)
        {
            ret += " NaN";
        }
        catch (BadOpOnType &e)
        {
            ret += " NaN";
        }
    }
    else if (item.type == StackElementType::BIGNUM)
    {
        const BigNum &num = item.num();
        size_t sz = num.magSize();
        ret += "BIGNUM ";
        ret += std::to_string(sz);
        ret += " ";
        ret += item.hex();
        ret += "h ";
        ret += num.str();
    }
    else
    {
        ret += "UNKNOWN"; // this sw needs to be updated for the newly added type
    }
    return ret;
}

void *CreateTemplateContextScriptMachine(unsigned int flags,
    unsigned int inputIdx,
    const unsigned char *txData,
    int txbuflen,
    const unsigned char *coinData,
    int coinbuflen,
    const CScript &satisfier,
    const CScript &constraint,
    std::string &error)
{
    if (!satisfier.IsPushOnly())
    {
        error = "satisfier is not push-only";
        return nullptr;
    }
    if (!constraint.IsPushOnly())
    {
        error = "constraint is not push-only";
        return nullptr;
    }

    const unsigned int maxOps = 0xffffffff;
    ScriptImportedState noSis;
    ScriptMachine ssm(flags, noSis, maxOps, 0);
    if (!ssm.Eval(satisfier))
    {
        error = ScriptErrorString(ssm.getError());
        return nullptr;
    }
    ScriptMachine csm(flags, noSis, maxOps, 0);
    if (!csm.Eval(constraint))
    {
        error = ScriptErrorString(csm.getError());
        return nullptr;
    }

    void *smh = CreateScriptMachine(
        flags, inputIdx, (unsigned char *)txData, txbuflen, (unsigned char *)coinData, coinbuflen, &error);
    if (smh)
    {
        // copy over the stacks that were created by running the constraint and satisfier
        ScriptMachineData *smd = (ScriptMachineData *)smh;
        smd->sm->setAltStack(csm.getStack());
        smd->sm->setStack(ssm.getStack());
    }
    return smh;
}

bool SetRegisterFromText(ScriptMachineData *smd,
    int regNum,
    const std::string &type,
    const std::string &value,
    std::string &result,
    std::string &error)
{
    if (regNum >= NUM_SCRIPT_REGISTERS)
    {
        error = "register number is too large";
        return false;
    }
    if (regNum < 0)
    {
        error = "register number is negative";
        return false;
    }

    StackItem item;
    if ((type == "BYTES") || (type == "BIGNUM"))
    {
        const std::string &hex = value;
        if (!IsHex(hex))
        {
            error = "value is not hex";
            return false;
        }

        if (type == "BYTES")
        {
            auto data = ParseHex(hex);
            item = StackItem(data);
        }
        else // bignum
        {
            if (hex.size() == 0)
            {
                item = StackItem(BigNum());
            }
            else
            {
                std::string sign = hex.substr(hex.length() - 2);
                bool neg = false;
                if (sign == "80")
                    neg = true;
                else if (sign != "00")
                {
                    error = "bignum hex must end in the number's sign: 00 for +, 80 for negative";
                    return false;
                }
                std::string mag = hex.substr(0, hex.length() - 2);
                BigNum bn;
                if (!mag.empty())
                {
                    try
                    {
                        bn = BigNum(mag, 16);
                    }
                    catch (const OutOfBounds &e)
                    {
                        error = std::string("bignum value is not a hex number: ") + e.what();
                        return false;
                    }
                }
                if (neg)
                    bn.negate();
                item = StackItem(bn);
            }
        }
    }
    else if (type == "BIGNUM(DEC)")
    {
        try
        {
            BigNum bn = BigNum(value, 10);
            item = StackItem(bn);
        }
        catch (const OutOfBounds &e)
        {
            error = std::string("value is not a decimal number: ") + e.what();
            return false;
        }
    }
    else if (type == "INTEGER(DEC)")
    {
        try
        {
            CScriptNum sn = CScriptNum::fromIntUnchecked(std::stoll(value));
            item = sn.vchStackItem();
        }
        catch (const std::exception &)
        {
            error = "value is not a 64 bit decimal integer";
            return false;
        }
    }
    else
    {
        error = "unknown data type";
        return false;
    }

    smd->sm->arrRegisters[regNum] = item;
    result = stackItem2String(item);
    return true;
}

void SetResourceLimits(ScriptMachineData *smd,
    int64_t maxScriptSize,
    int64_t maxOps,
    int64_t maxSignatureChecks,
    int64_t maxStackUse,
    int64_t maxStackItems,
    int64_t maxOpExec,
    int64_t maxOpExecDepth)
{
    if (maxScriptSize >= 0)
        smd->sm->maxScriptSize = maxScriptSize;
    if (maxOps >= 0)
        smd->sm->maxOps = maxOps;
    if (maxSignatureChecks >= 0)
        smd->sm->maxConsensusSigOps = maxSignatureChecks;
    if (maxStackUse >= 0)
    {
        // Stack accounting assumes the limit fits in 32 bits (stats.maxStackBytes is unsigned int)
        smd->sm->maxStackUse = std::min<int64_t>(maxStackUse, std::numeric_limits<unsigned int>::max());
    }
    if (maxStackItems >= 0)
        smd->sm->maxStackItems = maxStackItems;
    if (maxOpExec >= 0)
        smd->sm->maxOpExec = maxOpExec;
    if (maxOpExecDepth >= 0)
        smd->sm->maxOpExecDepth = maxOpExecDepth;
}

SLAPI unsigned int SmStandardScriptVerifyFlags() { return STANDARD_SCRIPT_VERIFY_FLAGS; }

SLAPI void *SmCreate(unsigned int flags,
    unsigned int inputIdx,
    const unsigned char *txData,
    int txbuflen,
    const unsigned char *coinData,
    int coinbuflen,
    char *errorResult,
    unsigned int errorResultLen)
{
    std::string error;
    void *ret = CreateScriptMachine(
        flags, inputIdx, (unsigned char *)txData, txbuflen, (unsigned char *)coinData, coinbuflen, &error);
    if (ret == nullptr)
        returnError(error, errorResult, errorResultLen);
    return ret;
}

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
    unsigned int errorResultLen)
{
    std::string error;
    CScript sat(satisfier, satisfier + satisfierLen);
    CScript con(constraint, constraint + constraintLen);
    void *ret =
        CreateTemplateContextScriptMachine(flags, inputIdx, txData, txbuflen, coinData, coinbuflen, sat, con, error);
    if (ret == nullptr)
        returnError(error, errorResult, errorResultLen);
    return ret;
}

SLAPI int SmIsMoreSteps(void *smId)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return -1;
    return smd->sm->isMoreSteps() ? 1 : 0;
}

SLAPI bool SmContinue(void *smId)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return false;
    return smd->sm->Continue();
}

SLAPI int SmSetPos(void *smId, int pos)
{
    ScriptMachineData *smd = getSmd(smId);
    if ((!smd) || (pos < 0))
        return -1;
    return smd->sm->setPos(pos);
}

SLAPI void SmSwapStacks(void *smId)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return;
    Stack tmp = smd->sm->getStack();
    smd->sm->setStack(smd->sm->getAltStack());
    smd->sm->setAltStack(tmp);
}

SLAPI void SmClearError(void *smId)
{
    ScriptMachineData *smd = getSmd(smId);
    if (smd)
        smd->sm->clearError();
}

SLAPI int SmGetErrorText(void *smId, char *result, unsigned int resultLen)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return returnError(NO_SCRIPT_MACHINE_ERROR, result, resultLen);
    auto err = smd->sm->getError();
    std::string ret(ScriptErrorString(err));
    ret += "(" + std::to_string(err) + ")";
    return returnText(ret, result, resultLen);
}

SLAPI int SmGetBMD(void *smId, char *result, unsigned int resultLen)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return returnError(NO_SCRIPT_MACHINE_ERROR, result, resultLen);
    return returnText(smd->sm->bigNumModulo.str(16), result, resultLen);
}

SLAPI int SmSetBMD(void *smId, const char *bmdHex, char *result, unsigned int resultLen)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return returnError(NO_SCRIPT_MACHINE_ERROR, result, resultLen);
    if (!bmdHex)
        return returnError("BMD is null", result, resultLen);
    try
    {
        smd->sm->bigNumModulo = BigNum(bmdHex, 16);
    }
    catch (const OutOfBounds &e)
    {
        return returnError(std::string("BMD is not a hex number: ") + e.what(), result, resultLen);
    }
    return returnText(smd->sm->bigNumModulo.str(16), result, resultLen);
}

SLAPI bool SmModify(void *smId, int offset, const unsigned char *data, unsigned int dataLen)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return false;
    return smd->sm->ModifyScript(offset, (uint8_t *)data, dataLen);
}

SLAPI int SmGetStackItemText(void *smId, unsigned int stack, unsigned int index, char *result, unsigned int resultLen)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return returnError(NO_SCRIPT_MACHINE_ERROR, result, resultLen);
    const std::vector<StackItem> &stk = (stack == 0) ? smd->sm->getStack() : smd->sm->getAltStack();
    if (stk.size() <= index)
        return returnText("", result, resultLen);
    return returnText(stackItem2String(stk[stk.size() - index - 1]), result, resultLen);
}

SLAPI int SmGetRegisterText(void *smId, int regNum, char *result, unsigned int resultLen)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return returnError(NO_SCRIPT_MACHINE_ERROR, result, resultLen);
    if (regNum >= NUM_SCRIPT_REGISTERS)
        return returnError("register number is too large", result, resultLen);
    if (regNum < 0)
        return returnError("register number is negative", result, resultLen);
    return returnText(stackItem2String(smd->sm->arrRegisters[regNum]), result, resultLen);
}

SLAPI int SmSetRegisterText(void *smId,
    int regNum,
    const char *itemType,
    const char *value,
    char *result,
    unsigned int resultLen)
{
    ScriptMachineData *smd = getSmd(smId);
    if (!smd)
        return returnError(NO_SCRIPT_MACHINE_ERROR, result, resultLen);
    if (!itemType || !value)
        return returnError("item type or value is null", result, resultLen);
    std::string ret;
    std::string error;
    if (!SetRegisterFromText(smd, regNum, std::string(itemType), std::string(value), ret, error))
        return returnError(error, result, resultLen);
    return returnText(ret, result, resultLen);
}

SLAPI void SmResetResourceUse(void *smId)
{
    ScriptMachineData *smd = getSmd(smId);
    if (smd)
        smd->sm->ResetResourceUseStats();
}

SLAPI void SmSetResourceLimits(void *smId,
    int64_t maxScriptSize,
    int64_t maxOps,
    int64_t maxSignatureChecks,
    int64_t maxStackUse,
    int64_t maxStackItems,
    int64_t maxOpExec,
    int64_t maxOpExecDepth)
{
    ScriptMachineData *smd = getSmd(smId);
    if (smd)
        SetResourceLimits(
            smd, maxScriptSize, maxOps, maxSignatureChecks, maxStackUse, maxStackItems, maxOpExec, maxOpExecDepth);
}

SLAPI void SmGetResourceUse(void *smId, int64_t *result)
{
    ScriptMachineData *smd = getSmd(smId);
    if ((!smd) || (!result))
        return;
    const auto &stats = smd->sm->getStats();
    result[0] = stats.consensusSigCheckCount;
    result[1] = stats.nOpCount;
    result[2] = stats.maxStackBytes;
    result[3] = stats.maxStackItems;
    result[4] = stats.nOpExec;
    result[5] = stats.nOpExecDepth;
}

#endif // NO_SCRIPT_MACHINE
