// Copyright (c) 2019 Andrew Stone Consulting
// Copyright (c) 2024 Bitcoin Unlimited
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "capd.h"
#include "clientversion.h"
#include "hashwrapper.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"

const long int YEAR_OF_SECONDS = 31536000;

// Local message difficulty must be less than forwarded message difficulty
arith_uint256 MIN_FORWARD_MSG_DIFFICULTY("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
arith_uint256 MIN_LOCAL_MSG_DIFFICULTY("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

uint64_t MSG_LIFETIME_SEC = 60 * 10; // expected message halflife in seconds
uint64_t MSG_MAX_FUTURE_SEC = 60; // clock skew beyond which a peer relaying a future message is penalised
uint64_t NOMINAL_MSG_SIZE = 100; // A message of this size or less has no penalty

PriorityType MIN_RELAY_PRIORITY = Priority(MIN_FORWARD_MSG_DIFFICULTY, NOMINAL_MSG_SIZE, 0);
PriorityType MIN_LOCAL_PRIORITY = Priority(MIN_LOCAL_MSG_DIFFICULTY, NOMINAL_MSG_SIZE, 0);

arith_uint256 MAX_UINT256 = ~arith_uint256();

/* When converting a double to a uint256, precision will be lost.  This is how much to keep.
   Basically, doubles are multiplied by this amount before being converted to a uint256.
   This means that this precision is often lost in related uint256 values because the algorithm
   looks something like this to avoid overflow:

   uintVal/CONVERSION_FRAC * (uint256) ((uint64_t) (doubleVal * CONVERSION_FRAC))
 */
const unsigned long int PRIORITY_CONVERSION_FRAC = 0x100000;

PriorityType Priority(uint32_t difficultyBits, size_t msgContentSize, uint64_t age)
{
    arith_uint256 difficulty;
    difficulty.SetCompact(difficultyBits);
    return Priority(difficulty, msgContentSize, age);
}

PriorityType Priority(arith_uint256 hashTarget, size_t msgContentSize, uint64_t age)
{
    double ret = MIN_LOCAL_MSG_DIFFICULTY.getdouble() / hashTarget.getdouble();

    // Calculate the size based penalty
    if (msgContentSize > NOMINAL_MSG_SIZE)
    {
        ret = (ret / msgContentSize) * NOMINAL_MSG_SIZE;
    }

    // Priority is log2 based, so it falls by 1 (halves) every MSG_LIFETIME_SEC.  Every message falls at the same rate,
    // so relative order never changes, and a > MSG_LIFETIME_SEC old relay-minimum msg is below a new local-minimum msg.
    return std::log2(ret) - (double)age / MSG_LIFETIME_SEC;
}

arith_uint256 aPriorityToPowTarget(PriorityType priority, size_t msgContentSize)
{
    priority = std::exp2(priority);
    if (msgContentSize > NOMINAL_MSG_SIZE)
    {
        priority = (priority * msgContentSize) / NOMINAL_MSG_SIZE;
    }

    arith_uint256 ret;
    if (priority < 1.0)
    {
        PriorityType priInv = (((PriorityType)1) / priority) * PRIORITY_CONVERSION_FRAC;
        ret = (MIN_LOCAL_MSG_DIFFICULTY / arith_uint256(PRIORITY_CONVERSION_FRAC)) * arith_uint256((uint64_t)priInv);
    }
    else
    {
        arith_uint256 v;
        v.setdouble(priority * PRIORITY_CONVERSION_FRAC);
        ret = (MIN_LOCAL_MSG_DIFFICULTY / v) * ((uint64_t)PRIORITY_CONVERSION_FRAC);
    }

    return ret;
}


uint256 CapdMsg::CalcHash() const
{
    CDataStream serialized(SER_GETHASH, CLIENT_VERSION);
    serialized << *this;

    CSHA256 sha;
    sha.Write((unsigned char *)serialized.data(), serialized.size());
    unsigned char stage1[CSHA256::OUTPUT_SIZE];
    sha.Finalize(stage1);
    uint256 hash;
    CHash256 sha2;
    sha2.Write(stage1, sizeof(stage1));
    sha2.Write(nonce.data(), nonce.size());
    sha2.Finalize(hash.begin());
    cachedHash = hash;
    return hash;
}

PriorityType CapdMsg::Priority() const
{
    // A negative age ranks a message created ahead of our clock slightly above its initial priority, as the index does
    return InitialPriority() - ((double)GetTime() - (double)createTime) / MSG_LIFETIME_SEC;
}
PriorityType CapdMsg::InitialPriority() const
{
    if (std::isnan(cachedInitialPriority))
        cachedInitialPriority = ::Priority(difficultyBits, data.size(), 0);
    return cachedInitialPriority;
}
bool CapdMsg::DoesPowMeetTarget() const
{
    if (!IsNonceSizeValid())
        return false;
    return GetPowTarget() > GetHash();
}
std::string CapdMsg::EncodeHex()
{
    CDataStream strmdata(SER_NETWORK, PROTOCOL_VERSION);
    strmdata << *this;
    return HexStr(strmdata.begin(), strmdata.end());
}


bool CapdMsg::checkNonce(unsigned char *stage1, const arith_uint256 &hashTarget)
{
    uint256 hash;
    CHash256 sha2;
    sha2.Write(stage1, CSHA256::OUTPUT_SIZE);
    sha2.Write(nonce.data(), nonce.size());
    sha2.Finalize(hash.begin());

    if (hashTarget > UintToArith256(hash))
        return true;
    return false;
}

bool CapdMsg::Solve(long int time)
{
    cachedHash = uint256(); // Clear the hash because we are changing the message
    cachedInitialPriority = std::numeric_limits<PriorityType>::quiet_NaN();
    if (time < YEAR_OF_SECONDS)
        createTime = GetTime() - time;
    else
        createTime = time;

    CDataStream serialized(SER_GETHASH, CLIENT_VERSION);
    serialized << *this;

    CSHA256 sha;
    sha.Write((unsigned char *)serialized.data(), serialized.size());
    unsigned char stage1[CSHA256::OUTPUT_SIZE];
    sha.Finalize(stage1);

    arith_uint256 hashTarget = arith_uint256().SetCompact(difficultyBits);

    bool solved = false;

    do
    {
        // Looking for the shortest solution means searching all possibilities of different nonce lengths.
        nonce.resize(1);
        uint64_t count = 0;
        while (count < 256)
        {
            nonce[0] = count & 255;
            if (checkNonce(stage1, hashTarget))
            {
                solved = true;
                break;
            }
            count++;
        }
        if (solved)
            break;

        count = 0;
        nonce.resize(2);
        while (count < 256 * 256)
        {
            nonce[0] = count & 255;
            nonce[1] = count >> 8;
            if (checkNonce(stage1, hashTarget))
            {
                solved = true;
                break;
            }
            count++;
        }
        if (solved)
            break;

        count = 0;
        nonce.resize(3);
        while (count < 256 * 256 * 256)
        {
            nonce[0] = count & 255;
            nonce[1] = count >> 8;
            nonce[2] = count >> 16;
            if (checkNonce(stage1, hashTarget))
            {
                solved = true;
                break;
            }
            count++;
        }

        count = 0;
        nonce.resize(4);
        while (count < 256UL * 256UL * 256UL * 256UL)
        {
            nonce[0] = count & 255;
            nonce[1] = count >> 8;
            nonce[2] = count >> 16;
            nonce[3] = count >> 24;
            if (checkNonce(stage1, hashTarget))
            {
                solved = true;
                break;
            }
            count++;
        }
    } while (0);

    return solved;
}

void CapdMsg::SetPowTargetHarderThan(uint256 target)
{
    // Make the target slightly smaller by subtracting from the mantissa of its compact form.  Working in the
    // compact form guarantees the change is not rounded away when the target is stored as difficultyBits.
    // The reduction is random (so solvers do not all pick the same target) but proportional to the mantissa,
    // at most 1/256 of it, so the target is never more than ~0.4% harder (+0.006 priority) than asked.
    // A fixed-size reduction made targets with a small mantissa, such as every exact integer priority, many
    // times harder than requested.
    uint32_t cInt = UintToArith256(target).GetCompact();
    const uint32_t mantissaBits = ((1 << 23) - 1);
    uint32_t mantissa = (cInt & mantissaBits);
    // GetCompact normalizes the mantissa to at least 0x8000 for any nonzero target, so (mantissa >> 8) >= 0x80
    // and the subtraction below cannot underflow.  The result may be unnormalized, which SetCompact accepts.
    uint32_t maxReduction = mantissa >> 8;
    if (maxReduction == 0) // zero target: nothing can be harder, so leave it as is
    {
        SetPowTarget(target);
        return;
    }
    uint32_t randomReduction = 1 + (uint32_t)(std::rand() % maxReduction);
    cInt -= randomReduction;

    arith_uint256 num;
    SetPowTarget(num.SetCompact(cInt));
    // LOG(CAPD, "Capd: target %s > %s\n", target.GetHex(), num.GetHex());
}

void CapdMsg::SetPowTargetHarderThanPriority(PriorityType priority)
{
    SetPowTargetHarderThan(PriorityToPowTarget(priority, data.size()));
}
