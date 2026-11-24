// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2015-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_CONSENSUS_PARAMS_H
#define NEXA_CONSENSUS_PARAMS_H

#include "amount.h"
#include "clientversion.h"
#include "uint256.h"

#include <map>
#include <string>

namespace Consensus
{
/**
 * Parameters that influence chain consensus.
 */
struct Params
{
    /** what pow algorithm to use (Nexa = 1 or BTC/BCH = 0) */
    unsigned int powAlgorithm = 1;
    /** Initial subsidy */
    CAmount initialSubsidy;
    /** Coinbase maturity */
    int coinbaseMaturity = 0;

    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;

    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
    // difficulty is cut in half. Doubled if blocks are ahead of schedule.
    int64_t nASERTHalfLife;
    // Set the ASERT anchor block to a specific block by height.
    // Useful for test networks to avoid recreating the genesis block to ensure a recent anchor time.
    // It is recommended on test networks to anchor at block 2 because ASERT uses time of the anchor's parent.
    uint64_t nASERTAnchorAt = 0;

    /** Fork activation time */
    uint64_t nextForkActivationTime;

    /** Adaptive Block Size settings */
    uint64_t nShortBlockWindow;
    uint64_t nLongBlockWindow;
    uint64_t nBlockSizeMultiplier;
    uint64_t nNextMaxBlockSize;

    /** Fork1 activation height */
    uint64_t fork1Height;

    /** Number of tailstorm subblocks needed to make up a block.
     *  This *includes* the current block so the actual number of subblocks a summary block needs to reference is
     *  this amount - 1.
     */
    uint32_t tailstorm_k;

    /** Enforce subblock correctness this deep from the chain tip */
    uint32_t tailstormEnforceDepth;
};
} // namespace Consensus

#endif // NEXA_CONSENSUS_PARAMS_H
