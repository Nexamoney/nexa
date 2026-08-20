// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_DAA_H
#define NEXA_DAA_H

#include "consensus/params.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class arith_uint256;

/* Solve this block.  Not for performance use. The function modifies the nonce but does not change its size.
   NOTE: if nonce size is 0 or small, there may be no solution ever found!
 */
bool MineBlock(CBlockHeader &blockHeader, unsigned long int tries, const Consensus::Params &cparams);

/**
 * Return the largest target whose idealized work is at least the requested work.
 * This is the inverse of the usual target-to-work conversion, before compact rounding.
 */
arith_uint256 GetTargetForRequiredWork(arith_uint256 requiredWork) noexcept;

/**
 * Return the next harder compact target encoding.
 * This is used when compact rounding would otherwise make the encoded target too easy.
 */
uint32_t GetNextHarderCompactBits(uint32_t nBits) noexcept;

/**
 * Return a compact target encoding that guarantees at least the requested work
 * after compact-format rounding has been applied.
 */
uint32_t GetCompactBitsForRequiredWork(arith_uint256 requiredWork) noexcept;

arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
    const int64_t nPowTargetSpacing,
    const int64_t nTimeDiff,
    const int64_t nHeightDiff,
    const arith_uint256 &powLimit,
    const int64_t nHalfLife) noexcept;

/** Minimum work for a deferred subblock to use the primary header cache. */
arith_uint256 GetDeferredSubblockWorkThreshold(const CBlockIndex *pindexTip,
    int64_t maximumSummaryTime,
    const Consensus::Params &params);

uint32_t GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
    const CBlockHeader *pblock,
    const Consensus::Params &params,
    const CBlockIndex *pindexReferenceBlock,
    bool tailstorm = false) noexcept;

/**
 * ASERT caches a special block index for efficiency. If block indices are
 * freed then this needs to be called to ensure no dangling pointer when a new
 * block tree is created.
 * (this is temporary and will be removed after the ASERT constants are fixed)
 */
void ResetASERTAnchorBlockCache() noexcept;

/**
 * For testing purposes - get the current ASERT cache block.
 */
const CBlockIndex *GetASERTAnchorBlockCache() noexcept;

unsigned int GetNextWorkRequired(const CBlockIndex *pindexLast, const CBlockHeader *pblock, const Consensus::Params &);

uint32_t GetNextNonTailstormWorkRequired(const CBlockIndex *pindexPrev,
    const CBlockHeader *pblock,
    const Consensus::Params &params);

arith_uint256 GetNextNonTailstormBlockTarget(const CBlockIndex *pindexPrev,
    const CBlockHeader *pblock,
    const Consensus::Params &params);

#endif // NEXA_DAA_H
