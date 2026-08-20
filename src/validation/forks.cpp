// Copyright (c) 2018-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "forks.h"

#include "unlimited.h"

/** Fork1 time MTP >= 12:00:00 PM, March 31st 2025, GMT */
const uint64_t FORK1_ACTIVATION_TIME = 1743422400;

// Fork1 on March 31st 2025 for mainnet, Feb 12th 2025 for testnet
// Activation block: mainnet 766083, testnet 747031
// First Fork1 block: mainnet 766084, testnet 747032
bool IsFork1Activated(const Consensus::Params &consensusparams, const CBlockIndex *pindexTip)
{
    if ((pindexTip == nullptr) || (pindexTip->pprev == nullptr))
    {
        return false;
    }
    // Fork1 enables in the block AFTER the activation.  This gives us time to clean out the txpool.
    // The below condition is true only if for current tip the fork1 rule are active for blocks
    // not just mempool, ie thi condition would be false for the first block with GTP > fork time
    // fork1Height: height of the 1st block with GTP > forktime
    return pindexTip->pprev->nHeight >= (int64_t)consensusparams.fork1Height;
}

// Fork1 on March 31st 2025
bool IsFork1Pending(const Consensus::Params &consensusparams, const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }
    return !IsFork1Activated(consensusparams, pindexTip) &&
           (pindexTip->nHeight >= (int64_t)consensusparams.fork1Height);
}

bool IsUpgrade2Activated(const CBlockIndex *pindexTip)
{
    if ((pindexTip == nullptr) || (pindexTip->pprev == nullptr))
    {
        return false;
    }

    if (Params().NetworkIDString() == CBaseChainParams::STORMTEST && pindexTip->height() > 2)
    {
        return true;
    }
    if (pindexTip->pprev->GetMedianTimePast() >= (int64_t)miningForkTime.Value())
    {
        return true;
    }

    return false;
}

bool IsUpgrade2Pending(const CBlockIndex *pindexTip)
{
    if (pindexTip == nullptr)
    {
        return false;
    }

    if (Params().NetworkIDString() == CBaseChainParams::STORMTEST && pindexTip->height() == 2)
    {
        return true;
    }
    if (!IsUpgrade2Activated(pindexTip) && (pindexTip->GetMedianTimePast() >= (int64_t)miningForkTime.Value()))
    {
        return true;
    }

    return false;
}
