// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "daa.h"

#include "arith_uint256.h"
#include "chain.h"
#include "pow.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"
#include "validation/forks.h"
#include "validation/tailstorm.h"

extern std::atomic<bool> fTailstormEnabled;

static std::atomic<const CBlockIndex *> cachedAnchor{nullptr};

arith_uint256 GetTargetForRequiredWork(arith_uint256 requiredWork) noexcept
{
    if (requiredWork == 0)
        return arith_uint256(1);

    // Inverse of GetWorkForTarget(): target = floor((2**256 / work) - 1).
    arith_uint256 target = ~requiredWork / requiredWork;
    if (target == 0)
        target = arith_uint256(1);
    return target;
}

uint32_t GetNextHarderCompactBits(uint32_t nBits) noexcept
{
    uint32_t nSize = nBits >> 24;
    uint32_t nWord = nBits & 0x007fffff;
    assert(nWord != 0);

    // The caller contract is a canonical positive compact encoding, as produced
    // by arith_uint256::GetCompact() or by this function. For such inputs the
    // mantissa's high byte carries the sign-bit-avoiding 0x8000 bit set.
    //
    // Decrement first, then re-canonicalize. When the decrement drops the
    // mantissa below 0x008000 we fold one byte of exponent into the mantissa
    // and fill the low byte with 0xff, giving the largest canonical encoding
    // that is still strictly smaller than the input. The loop iterates only
    // if the input was already non-canonical (e.g. a test-supplied mantissa
    // of 1); a canonical input needs at most one fold.
    --nWord;
    while (nWord < 0x00008000 && nSize > 1)
    {
        nWord = (nWord << 8) | 0xff;
        --nSize;
    }

    // For nSize < 3 the canonical form has the low 8*(3-nSize) bits of the
    // mantissa zero, because GetCompact() left-shifts the value into the top
    // of the 3-byte field. SetCompact() then drops those bits again on decode,
    // so masking them here preserves the decoded target and yields the unique
    // encoding GetCompact() would have produced. Without this step the output
    // would be a valid-but-non-canonical representation of the same target,
    // breaking the "walks an ordered set of canonical targets" invariant.
    if (nSize < 3)
        nWord &= ~((1u << (8 * (3 - nSize))) - 1);

    assert(nWord > 1);
    return (nSize << 24) | nWord;
}

uint32_t GetCompactBitsForRequiredWork(arith_uint256 requiredWork) noexcept
{
    uint32_t nBits = GetTargetForRequiredWork(requiredWork).GetCompact();
    while (GetWorkForDifficultyBits(nBits) < requiredWork)
        nBits = GetNextHarderCompactBits(nBits);
    return nBits;
}

void ResetASERTAnchorBlockCache() noexcept { cachedAnchor = nullptr; }
const CBlockIndex *GetASERTAnchorBlockCache() noexcept { return cachedAnchor.load(); }
/**
 * Returns a pointer to the anchor block used for ASERT.
 * As anchor we use the first block for which IsNov2020Activated() returns true.
 * This block happens to be the last block which was mined under the old DAA
 * rules.
 *
 * This function is meant to be removed some time after the upgrade, once
 * the anchor block is deeply buried, and behind a hard-coded checkpoint.
 *
 * Preconditions: - pindex must not be nullptr
 *                - pindex must satisfy: IsNov2020Activated(params, pindex) == true
 * Postcondition: Returns a pointer to the first (lowest) block for which
 *                IsNov2020Activated is true, and for which IsNov2020ACtivated(pprev)
 *                is false (or for which pprev is nullptr). The return value may
 *                be pindex itself.
 */
static const CBlockIndex *GetASERTAnchorBlock(const CBlockIndex *const pindex, const Consensus::Params &params)
{
    assert(pindex);
    // if the tip is below the desired anchor block, just return it.
    // This is a workaround for the first few blocks in test networks.
    if (pindex->nHeight < params.nASERTAnchorAt)
        return pindex;

    // - We check if we have a cached result, and if we do and it is really the
    //   ancestor of pindex, then we return it.
    //
    // - If we do not or if the cached result is not the ancestor of pindex,
    //   then we proceed with the more expensive walk back to find the ASERT
    //   anchor block.
    //
    // CBlockIndex::GetAncestor() is reasonably efficient; it uses CBlockIndex::pskip
    // Note that if pindex == cachedAnchor, GetAncestor() here will return cachedAnchor,
    // which is what we want.
    const CBlockIndex *lastCached = cachedAnchor.load();
    if (lastCached && pindex->GetAncestor(lastCached->height()) == lastCached)
    {
        return lastCached;
    }
    // Slow path: walk back to genesis, and then use it as our anchor block.
    const CBlockIndex *anchor = pindex;
    while (anchor->pprev)
    {
        // first, skip backwards
        // The below code leverages CBlockIndex::pskip to walk back efficiently.
        if ((anchor->pskip != nullptr))
        {
            // skip backward if we are looking for the genesis block, or
            // if we aren't past block 1
            if (anchor->pskip->nHeight >= params.nASERTAnchorAt)
            {
                anchor = anchor->pskip;
                continue; // continue skipping
            }
        }
        // If in regtest or stormtest, use block 1 as the anchor, so that we can reuse the genesis block
        // when the chain is reset, but still have a recent anchor block time.
        if (params.nASERTAnchorAt)
        {
            if (anchor->nHeight == params.nASERTAnchorAt)
                break;
        }
        anchor = anchor->pprev;
    }

    // Overwrite the cache with the anchor we found. More likely than not, the next
    // time we are asked to validate a header it will be part of same / similar chain, not
    // some other unrelated chain with a totally different anchor.
    cachedAnchor = anchor;
    return anchor;
}


/**
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block every 120 seconds), and we calculate the
 * difficulty based on how far the most recent block's timestamp is ahead of or behind that schedule.
 * We set our targets (difficulty) exponentially. For every [nHalfLife] seconds ahead of or behind schedule we get, we
 * double or halve the difficulty.
 */
uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
    const CBlockHeader *pblock,
    const Consensus::Params &params,
    const CBlockIndex *pindexAnchorBlock,
    bool tailstorm) noexcept
{
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev != nullptr);

    // Anchor block is the block on which all ASERT scheduling calculations are based.
    // It too must exist, and it must have a valid parent.
    assert(pindexAnchorBlock != nullptr);

    // We make no further assumptions other than the height of the prev block must be >= that of the anchor block.
    assert(pindexPrev->height() >= pindexAnchorBlock->height());

    const arith_uint256 powLimit = UintToArith256(params.powLimit);

    // Special difficulty rule for testnet
    // If the new block's timestamp is more than 2* 10 minutes then allow
    // mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        (pblock->GetBlockTime() > pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing))
    {
        return powLimit.GetCompact();
    }

    // For nTimeDiff calculation, the timestamp of the parent to the anchor block is used,
    // as per the absolute formulation of ASERT.
    // This is somewhat counterintuitive since it is referred to as the anchor timestamp, but
    // as per the formula the timestamp of block M-1 must be used if the anchor is M.
    if (pindexPrev->pprev == nullptr)
        return powLimit.GetCompact(); // Start at very low difficulty
    assert(pindexPrev->pprev != nullptr);
    // Note: time difference is to parent of anchor block (or to anchor block itself iff anchor is genesis).
    //       (according to absolute formulation of ASERT)
    const auto anchorTime =
        pindexAnchorBlock->pprev ? pindexAnchorBlock->pprev->GetBlockTime() : pindexAnchorBlock->GetBlockTime();
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - anchorTime;
    // Height difference is from current block to anchor block
    const int64_t nHeightDiff = pindexPrev->height() - pindexAnchorBlock->height();
    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(pindexAnchorBlock->tgtBits());
    // Do the actual target adaptation calculation in separate
    // CalculateASERT() function

    arith_uint256 nextTarget;

    // make the target K times easier to produce K subblocks per block (if we are doing tailstorm)
    if (tailstorm && (params.tailstorm_k != 0))
    {
        nextTarget = CalculateASERT(
            refBlockTarget, params.nPowTargetSpacing, nTimeDiff, nHeightDiff, powLimit, params.nASERTHalfLife);

        // Tailstorm solves K PoW subblocks per summary block, so the subblock baseline target
        // is K times easier than the non-tailstorm ASERT target.
        arith_uint256 defaultTarget = nextTarget * params.tailstorm_k;
        arith_uint320 kTarget = nextTarget;
        kTarget *= params.tailstorm_k;
        if (kTarget > arith_uint320(powLimit))
        {
            // LOGA("Warning: tailstorm target difficulty is too easy! %s > %s clamping to POW limit",
            //     defaultTarget.ToString(), powLimit.ToString());
            defaultTarget = powLimit; // We can't get any easier than this
        }
        else
        {
            defaultTarget = kTarget.reduceTo256();
        }

        // For a normal subblock, use the default target directly.
        //
        // For a summary block, count the exact work already contributed by its referenced
        // uncles/subblocks and then require the summary block to contribute any remaining work
        // needed to reach the expected summary block total work. All arithmetic here stays in work units;
        // we convert back to a target only at the end.
        if (IsTailstormSummaryBlock(*pblock))
        {
            auto ret = ParseSummaryBlockMinerData(pblock->minerData);
            const arith_uint256 defaultWork = GetWorkForTarget(defaultTarget);
            const arith_uint256 expectedBlockWork = defaultWork * params.tailstorm_k;

            // add up the work from all the uncle blocks and subblocks.
            arith_uint256 nCurrentWorkInBlock = 0;
            {
                nCurrentWorkInBlock += (arith_uint256(ret.nUncles) * GetWorkForDifficultyBits(ret.nBitsUncle));
                nCurrentWorkInBlock += (arith_uint256(ret.nSubblocks) * GetWorkForDifficultyBits(ret.nBitsSubblock));
            }

            // The summary block is itself a Tailstorm subblock, so it should never be easier than
            // the default subblock target. If prior included work is short, harden the summary
            // target enough to make up the deficit.
            arith_uint256 requiredSummaryWork = defaultWork;
            if (nCurrentWorkInBlock < expectedBlockWork)
            {
                arith_uint256 remainingWork = expectedBlockWork - nCurrentWorkInBlock;
                if (remainingWork > requiredSummaryWork)
                    requiredSummaryWork = remainingWork;
            }

            nextTarget.SetCompact(GetCompactBitsForRequiredWork(requiredSummaryWork));
        }
        else
        {
            nextTarget = defaultTarget;
        }
    }
    else
    {
        nextTarget = CalculateASERT(
            refBlockTarget, params.nPowTargetSpacing, nTimeDiff, nHeightDiff, powLimit, params.nASERTHalfLife);
    }

    // If the next target is near our powLimit, the work in subblocks can easily cause the summary block target
    // to be easier than the powLimit.  But in that (or any other) case, clamp to the powLimit.
    // No subblock or summary block is allowed to be easier to solve than powLimit!
    if (nextTarget > powLimit)
        nextTarget = powLimit;
    return nextTarget.GetCompact();
}

// ASERT calculation function.
// Clamps to powLimit.
arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
    const int64_t nPowTargetSpacing,
    const int64_t nTimeDiff,
    const int64_t nHeightDiff,
    const arith_uint256 &powLimit,
    const int64_t nHalfLife) noexcept
{
    // Input target must never be zero nor exceed powLimit.
    assert(refTarget > arith_uint256((uint64_t)0));
    assert(refTarget <= powLimit);

    // This is left commented out here as an option, but we have increased the available bits for ASERT to use,
    // allowing it to accurately calculate extremely easy targets.  This is very useful for testing.
    // If we do not have the bits for ASERT, fall back to a simple algorithm.
    /*
    if (!((refTarget >> 238) == 0))
    {
        LOGA("ASERT: target is too large, not enough precision.  Using a simple proportional algorithm");
        if ((nTimeDiff == 0)||(nHeightDiff == 0)) return powLimit;
        int64_t secPerBlock16 = nTimeDiff*16/nHeightDiff;  // we * by 16 to get some (fixed point) decimal precision
        int64_t factor = secPerBlock16/nPowTargetSpacing;  // desired/actual, so if < 16 we need to speed up
        if (factor < 12) factor = 12;  // clamp to 25% moves
        if (factor > 20) factor = 20;  // clamp to 25% moves
        arith_uint256 ret = refTarget*arith_uint256(factor);
        if (ret < refTarget) return powLimit;  // overflow with just 4 bits decimal precision extra, give up
        ret/=arith_uint256(16); // Remove the decimal precision we put in right in the beginning
        return powLimit;
    }
    */

    // Height diff should NOT be negative.
    assert(nHeightDiff >= 0);

    // It will be helpful when reading what follows, to remember that
    // nextTarget is adapted from anchor block target value.

    // Ultimately, we want to approximate the following ASERT formula, using only integer (fixed-point) math:
    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME * (height_diff + 1)) / nHalfLife)

    // First, we'll calculate the exponent:
    assert(llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)));
    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
    // The truncated exponent tells us how many shifts we need to do
    // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
    //        whereas integer division in C++ rounds towards zero (truncated division).
    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
    //        is unpecified but very common behavior for C++ compilers before
    //        C++20, and standard with C++20. We must check this behavior e.g.
    //        using static_assert.
    static_assert(int64_t(-1) >> 1 == int64_t(-1), "ASERT algorithm needs arithmetic shift support");

    // Now we compute an approximated target * 2^(exponent/65536.0)

    // First decompose exponent into 'integer' and 'fractional' parts:
    int64_t shifts = exponent >> 16;
    const uint64_t frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + (int64_t)frac);

    // multiply target by 65536 * 2^(fractional part)
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
    // Error versus actual 2^x is less than 0.013%.
    const uint32_t factor =
        65536 +
        ((+195766423245049ull * frac + 971821376ull * frac * frac + 5127ull * frac * frac * frac + (1ull << 47)) >> 48);
    // this is always < 2^241 since refTarget < 2^224
    arith_uint320 nextTarget = refTarget;
    nextTarget *= factor;

    // multiply by 2^(integer part) / 65536
    shifts -= 16;
    if (shifts <= 0)
    {
        nextTarget >>= -shifts;
    }
    else
    {
        // Detect overflow that would discard high bits
        const auto nextTargetShifted = nextTarget << shifts;
        if ((nextTargetShifted >> shifts) != nextTarget)
        {
            // If we had wider integers, the final value of nextTarget would
            // be >= 2^256 so it would have just ended up as powLimit anyway.
            return powLimit;
        }
        else
        {
            // Shifting produced no overflow, can assign value
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == 0)
    {
        // 0 is not a valid target, but 1 is.
        return arith_uint256(1);
    }
    // since powLimit must be < arith_uint256.MAXINT, this also detects 256 bit overflows
    else if (nextTarget > arith_uint320(powLimit))
    {
        return powLimit;
    }
    auto ret = nextTarget.reduceTo256();
    // LOGA("ASERT: next: %s  prior: %s dTime: %d idealTime: %d  dHeight: %d exponent: %d  ", ret.ToString(),
    //     refTarget.ToString(), nTimeDiff, (nPowTargetSpacing * (nHeightDiff + 1)), nHeightDiff, exponent);
    return ret;
}

uint32_t GetNextWorkRequired(const CBlockIndex *pindexPrev, const CBlockHeader *pblock, const Consensus::Params &params)
{
    // Genesis block
    if (pindexPrev == nullptr)
    {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting)
    {
        return pindexPrev->tgtBits();
    }

    const CBlockIndex *panchorBlock = GetASERTAnchorBlock(pindexPrev, params);
    return GetNextASERTWorkRequired(pindexPrev, pblock, params, panchorBlock, true);
}

uint32_t GetNextNonTailstormWorkRequired(const CBlockIndex *pindexPrev,
    const CBlockHeader *pblock,
    const Consensus::Params &params)
{
    // Genesis block
    if (pindexPrev == nullptr)
    {
        return UintToArith256(params.powLimit).GetCompact();
    }

    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting)
    {
        return pindexPrev->tgtBits();
    }

    const CBlockIndex *panchorBlock = GetASERTAnchorBlock(pindexPrev, params);
    return GetNextASERTWorkRequired(pindexPrev, pblock, params, panchorBlock, false);
}


arith_uint256 GetNextNonTailstormBlockTarget(const CBlockIndex *pindexPrev,
    const CBlockHeader *pblock,
    const Consensus::Params &params)
{
    // Genesis block
    if (pindexPrev == nullptr)
    {
        return UintToArith256(params.powLimit);
    }

    // Special rule for regtest: we never retarget.
    if (params.fPowNoRetargeting)
    {
        arith_uint256 tmp;
        tmp.SetCompact(pindexPrev->tgtBits());
        return tmp;
    }

    arith_uint256 tmp;
    const CBlockIndex *panchorBlock = GetASERTAnchorBlock(pindexPrev, params);
    uint32_t bits = GetNextASERTWorkRequired(pindexPrev, pblock, params, panchorBlock, false);
    tmp.SetCompact(bits);
    return tmp;
}

bool MineBlock(CBlockHeader &blockHeader, unsigned long int tries, const Consensus::Params &cparams)
{
    assert(blockHeader.size != 0); // Size must be properly calculated before we can figure out the hash
    unsigned long int count = 0;
    for (unsigned int x = 0; x < 8; x++)
        if (x < blockHeader.nonce.size())
            count = count | (blockHeader.nonce[x] << (x * 8));

    uint256 headerCommitment = blockHeader.GetMiningHeaderCommitment();
    uint256 prevhash;
    if (fTailstormEnabled)
        prevhash = blockHeader.hashPrevBlock;

    while (tries > 0)
    {
        uint256 mhash = ::GetMiningHash(headerCommitment, blockHeader.nonce);
        if (CheckProofOfWork(mhash, prevhash, blockHeader.nBits, cparams))
        {
            // printf("pow hash: %s\n", mhash.GetHex().c_str());
            return true;
        }
        ++count;
        for (unsigned int x = 0; x < 8; x++)
            if (x < blockHeader.nonce.size())
                blockHeader.nonce[x] = (count >> (x * 8)) & 255;
        tries--;
    }
    return false;
}
