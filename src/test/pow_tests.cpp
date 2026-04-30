// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2022 The Bitcoin Unlimited developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "daa.h"
#include "datastream.h"
#include "pow.h"
#include "random.h"
#include "test/test_nexa.h"
#include "util.h"
#include "validation/tailstorm.h"

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(GetBlockWorkEquivalentTime_test)
{
    SelectParams(CBaseChainParams::LEGACY_UNIT_TESTS);
    const Consensus::Params &params = Params().GetConsensus();

    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++)
    {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].SetBlockHeaderHeight(i);
        blocks[i].SetBlockHeaderTime(1269211443 + i * params.nPowTargetSpacing);
        blocks[i].SetBlockHeaderBits(0x207fffff); /* target 0x7fffff000... */
        blocks[i].SetBlockHeaderChainWork(ArithToUint256(
            i ? blocks[i - 1].GetBlockHeader().aChainWork() + blocks[i - 1].GetBlockWork() : arith_uint256(0)));
    }

    for (int j = 0; j < 1000; j++)
    {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockWorkEquivalentTime(*p1, *p2, *p3, params);
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

static CBlockIndex GetBlockIndex(CBlockIndex *pindexPrev, int64_t nTimeInterval, uint32_t nBits)
{
    CBlockIndex block;
    block.pprev = pindexPrev;
    block.SetBlockHeaderHeight(pindexPrev->height() + 1);
    block.SetBlockHeaderTime(pindexPrev->GetBlockTime() + nTimeInterval);
    block.SetBlockHeaderBits(nBits);
    block.SetBlockHeaderChainWork(ArithToUint256(pindexPrev->chainWork() + block.GetBlockWork()));
    block.BuildSkip();
    return block;
}

static std::vector<unsigned char> MakeTailstormSummaryMinerData(uint8_t nUncles,
    uint32_t nBitsUncle,
    uint8_t nSubblocks,
    uint32_t nBitsSubblock)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    std::vector<std::pair<uint256, std::vector<uint8_t> > > vSubblockProofs;
    ds << DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION << uint256() << nUncles << nBitsUncle << nSubblocks << nBitsSubblock
       << vSubblockProofs;
    return std::vector<unsigned char>(ds.begin(), ds.end());
}

// Return the first compact nBits value that encodes an easier target than the input.
// This walks upward in target space until compact rounding produces a distinct, easier
// encoded difficulty.
static uint32_t GetNextEasierCompactBitsForTest(uint32_t nBits, const arith_uint256 &powLimit)
{
    const arith_uint256 currentTarget = arith_uint256().SetCompact(nBits);
    arith_uint256 step = currentTarget >> 4;
    if (step == 0)
        step = arith_uint256(1);

    arith_uint256 candidateTarget = currentTarget;
    uint32_t candidateBits = nBits;
    while (candidateBits == nBits)
    {
        BOOST_REQUIRE(candidateTarget < powLimit);
        candidateTarget += step;
        if (candidateTarget > powLimit)
            candidateTarget = powLimit;
        candidateBits = candidateTarget.GetCompact();
    }

    BOOST_REQUIRE(GetWorkForDifficultyBits(candidateBits) < GetWorkForDifficultyBits(nBits));
    return candidateBits;
}

// clang-format off
double TargetFromBits(const uint32_t nBits) { return (nBits & 0xff'ff'ff) * pow(256, (nBits >> 24) - 3); }
// clang-format-on

double GetASERTApproximationError(const CBlockIndex *pindexPrev,
    const uint32_t finalBits,
    const CBlockIndex *pindexAnchorBlock)
{
    const int64_t nHeightDiff = pindexPrev->height() - pindexAnchorBlock->height();
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - pindexAnchorBlock->pprev->GetBlockTime();
    const uint32_t initialBits = pindexAnchorBlock->tgtBits();

    BOOST_CHECK(nHeightDiff >= 0);
    double dInitialPow = TargetFromBits(initialBits);
    double dFinalPow = TargetFromBits(finalBits);

    double dExponent = double(nTimeDiff - (nHeightDiff + 1) * 600) / double(2 * 24 * 3600);
    double dTarget = dInitialPow * pow(2, dExponent);

    return (dFinalPow - dTarget) / dTarget;
}

BOOST_AUTO_TEST_CASE(asert_difficulty_test)
{
    SelectParams(CBaseChainParams::LEGACY_UNIT_TESTS);
    const Consensus::Params &params = Params().GetConsensus();

    std::vector<CBlockIndex> blocks(3000 + 2 * 24 * 3600);
    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    arith_uint256 currentPow = powLimit >> 3;
    uint32_t initialBits = currentPow.GetCompact();
    double dMaxErr = 0.0001166792656486;

    // Genesis block, and parent of ASERT anchor block in this test case.
    blocks[0] = CBlockIndex();
    blocks[0].SetBlockHeaderHeight(0);
    blocks[0].SetBlockHeaderTime(1269211443);
    // The pre-anchor block's nBits should never be used, so we set it to a nonsense value in order to
    // trigger an error if it is ever accessed
    blocks[0].SetBlockHeaderBits(0x0dedbeef);
    blocks[0].SetBlockHeaderChainWork(ArithToUint256(blocks[0].GetBlockWork()));

    // Block counter.
    size_t i = 1;

    // ASERT anchor block. We give this one a solvetime of 150 seconds to ensure that
    // the solvetime between the pre-anchor and the anchor blocks is actually used.
    blocks[1] = GetBlockIndex(&blocks[0], 150, initialBits);
    // The nBits for the next block should not be equal to the anchor block's nBits
    CBlockHeader blkHeaderDummy;
    uint32_t nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr);
    BOOST_CHECK(nBits != initialBits);

    // If we add another block at 1050 seconds, we should return to the anchor block's nBits
    blocks[i] = GetBlockIndex(&blocks[i - 1], 1050, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(nBits == initialBits);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr);

    currentPow = arith_uint256().SetCompact(nBits);
    // Before we do anything else, check that timestamps *before* the anchor block work fine.
    // Jumping 2 days into the past will give a timestamp before the anchor, and should halve the target
    blocks[i] = GetBlockIndex(&blocks[i - 1], 600 - 172800, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    currentPow = arith_uint256().SetCompact(nBits);
    // Because nBits truncates target, we don't end up with exactly 1/2 the target
    BOOST_CHECK(currentPow <= arith_uint256().SetCompact(initialBits) / 2);
    BOOST_CHECK(currentPow >= arith_uint256().SetCompact(initialBits - 1) / 2);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr);

    // Jumping forward 2 days should return the target to the initial value
    blocks[i] = GetBlockIndex(&blocks[i - 1], 600 + 172800, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    currentPow = arith_uint256().SetCompact(nBits);
    BOOST_CHECK(nBits == initialBits);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr);

    // Pile up some blocks every 10 mins to establish some history.
    for (; i < 150; i++)
    {
        blocks[i] = GetBlockIndex(&blocks[i - 1], 600, nBits);
        BOOST_CHECK_EQUAL(blocks[i].tgtBits(), nBits);
    }

    nBits = GetNextASERTWorkRequired(&blocks[i - 1], &blkHeaderDummy, params, &blocks[1]);

    BOOST_CHECK_EQUAL(nBits, initialBits);

    // Difficulty stays the same as long as we produce a block every 10 mins.
    for (size_t j = 0; j < 10; i++, j++)
    {
        blocks[i] = GetBlockIndex(&blocks[i - 1], 600, nBits);
        BOOST_CHECK_EQUAL(GetNextASERTWorkRequired(&blocks[i], &blkHeaderDummy, params, &blocks[1]), nBits);
    }

    // If we add a two blocks whose solvetimes together add up to 1200s,
    // then the next block's target should be the same as the one before these blocks
    // (at this point, equal to initialBits).
    blocks[i] = GetBlockIndex(&blocks[i - 1], 300, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    blocks[i] = GetBlockIndex(&blocks[i - 1], 900, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr); // absolute
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    BOOST_CHECK_EQUAL(nBits, initialBits);
    BOOST_CHECK(nBits != blocks[i - 1].tgtBits());

    // Same in reverse - this time slower block first, followed by faster block.
    blocks[i] = GetBlockIndex(&blocks[i - 1], 900, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr); // absolute
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    blocks[i] = GetBlockIndex(&blocks[i - 1], 300, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr); // absolute
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    BOOST_CHECK_EQUAL(nBits, initialBits);
    BOOST_CHECK(nBits != blocks[i - 1].tgtBits());

    // Jumping forward 2 days should double the target (halve the difficulty)
    blocks[i] = GetBlockIndex(&blocks[i - 1], 600 + 2 * 24 * 3600, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr); // absolute
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    currentPow = arith_uint256().SetCompact(nBits) / 2;
    BOOST_CHECK_EQUAL(currentPow.GetCompact(), initialBits);

    // Jumping backward 2 days should bring target back to where we started
    blocks[i] = GetBlockIndex(&blocks[i - 1], 600 - 2 * 24 * 3600, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr); // absolute
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    BOOST_CHECK_EQUAL(nBits, initialBits);

    // Jumping backward 2 days should halve the target (double the difficulty)
    blocks[i] = GetBlockIndex(&blocks[i - 1], 600 - 2 * 24 * 3600, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr); // absolute
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    currentPow = arith_uint256().SetCompact(nBits);
    // Because nBits truncates target, we don't end up with exactly 1/2 the target
    BOOST_CHECK(currentPow <= arith_uint256().SetCompact(initialBits) / 2);
    BOOST_CHECK(currentPow >= arith_uint256().SetCompact(initialBits - 1) / 2);

    // And forward again
    blocks[i] = GetBlockIndex(&blocks[i - 1], 600 + 2 * 24 * 3600, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr); // absolute
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    BOOST_CHECK_EQUAL(nBits, initialBits);
    blocks[i] = GetBlockIndex(&blocks[i - 1], 600 + 2 * 24 * 3600, nBits);
    nBits = GetNextASERTWorkRequired(&blocks[i++], &blkHeaderDummy, params, &blocks[1]);
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[1])) < dMaxErr); // absolute
    BOOST_CHECK(fabs(GetASERTApproximationError(&blocks[i - 1], nBits, &blocks[i - 2])) < dMaxErr); // relative
    currentPow = arith_uint256().SetCompact(nBits) / 2;
    BOOST_CHECK_EQUAL(currentPow.GetCompact(), initialBits);

    // Iterate over the entire -2*24*3600..+2*24*3600 range to check that our integer approximation:
    //   1. Should be monotonic
    //   2. Should change target at least once every 8 seconds (worst-case: 15-bit precision on nBits)
    //   3. Should never change target by more than XXXX per 1-second step
    //   4. Never exceeds dMaxError in absolute error vs a double float calculation
    //   5. Has almost exactly the dMax and dMin errors we expect for the formula
    double dMin = 0;
    double dMax = 0;
    double dErr;
    double dRelMin = 0;
    double dRelMax = 0;
    double dRelErr;
    double dMaxStep = 0;
    uint32_t nBitsRingBuffer[8];
    double dStep = 0;
    blocks[i] = GetBlockIndex(&blocks[i - 1], -2 * 24 * 3600 - 30, nBits);
    for (size_t j = 0; j < 4 * 24 * 3600 + 660; j++)
    {
        uint32_t _nTime = blocks[i].GetBlockHeader().nTime + 1;
        blocks[i].SetBlockHeaderTime(_nTime);
        nBits = GetNextASERTWorkRequired(&blocks[i], &blkHeaderDummy, params, &blocks[1]);

        if (j > 8)
        {
            // 1: Monotonic
            BOOST_CHECK(arith_uint256().SetCompact(nBits) >= arith_uint256().SetCompact(nBitsRingBuffer[(j - 1) % 8]));
            // 2: Changes at least once every 8 seconds (worst case: nBits = 1d008000 to 1d008001)
            BOOST_CHECK(arith_uint256().SetCompact(nBits) > arith_uint256().SetCompact(nBitsRingBuffer[j % 8]));
            // 3: Check 1-sec step size
            dStep = (TargetFromBits(nBits) - TargetFromBits(nBitsRingBuffer[(j - 1) % 8])) / TargetFromBits(nBits);
            if (dStep > dMaxStep)
                dMaxStep = dStep;
            BOOST_CHECK(dStep < 0.0000314812106363); // from nBits = 1d008000 to 1d008001
        }
        nBitsRingBuffer[j % 8] = nBits;

        // 4 and 5: check error vs double precision float calculation
        dErr = GetASERTApproximationError(&blocks[i], nBits, &blocks[1]);
        dRelErr = GetASERTApproximationError(&blocks[i], nBits, &blocks[i - 1]);
        if (dErr < dMin)
            dMin = dErr;
        if (dErr > dMax)
            dMax = dErr;
        if (dRelErr < dRelMin)
            dRelMin = dRelErr;
        if (dRelErr > dRelMax)
            dRelMax = dRelErr;
        BOOST_CHECK_MESSAGE(
            fabs(dErr) < dMaxErr, strprintf("solveTime: %d\tStep size: %.8f%%\tdErr: %.8f%%\tnBits: %0x\n",
                                      int64_t(blocks[i].GetBlockTime()) - blocks[i - 1].GetBlockTime(), dStep * 100, dErr * 100, nBits));
        BOOST_CHECK_MESSAGE(fabs(dRelErr) < dMaxErr,
            strprintf("solveTime: %d\tStep size: %.8f%%\tdRelErr: %.8f%%\tnBits: %0x\n",
                                int64_t(blocks[i].GetBlockTime()) - blocks[i - 1].GetBlockTime(), dStep * 100, dRelErr * 100, nBits));
    }
    auto failMsg = strprintf(
        "Min error: %16.14f%%\tMax error: %16.14f%%\tMax step: %16.14f%%\n", dMin * 100, dMax * 100, dMaxStep * 100);
    BOOST_CHECK_MESSAGE(dMin < -0.0001013168981059 && dMin > -0.0001013168981060 && dMax > 0.0001166792656485 &&
                            dMax < 0.0001166792656486,
        failMsg);
    failMsg = strprintf("Min relError: %16.14f%%\tMax relError: %16.14f%%\n", dRelMin * 100, dRelMax * 100);
    BOOST_CHECK_MESSAGE(dRelMin < -0.0001013168981059 && dRelMin > -0.0001013168981060 &&
                            dRelMax > 0.0001166792656485 && dRelMax < 0.0001166792656486,
        failMsg);

    // Difficulty increases as long as we produce fast blocks
    for (size_t j = 0; j < 100; i++, j++)
    {
        uint32_t nextBits;
        arith_uint256 currentTarget;
        currentTarget.SetCompact(nBits);

        blocks[i] = GetBlockIndex(&blocks[i - 1], 500, nBits);
        nextBits = GetNextASERTWorkRequired(&blocks[i], &blkHeaderDummy, params, &blocks[1]);
        arith_uint256 nextTarget;
        nextTarget.SetCompact(nextBits);

        // Make sure that target is decreased
        BOOST_CHECK(nextTarget <= currentTarget);

        nBits = nextBits;
    }
}

std::string StrPrintCalcArgs(const arith_uint256 refTarget,
    const int64_t targetSpacing,
    const int64_t timeDiff,
    const int64_t heightDiff,
    const arith_uint256 expectedTarget,
    const uint32_t expectednBits)
{
    return strprintf("\n"
                     "ref=         %s\n"
                     "spacing=     %d\n"
                     "timeDiff=    %d\n"
                     "heightDiff=  %d\n"
                     "expTarget=   %s\n"
                     "exp nBits=   0x%08x\n",
        refTarget.ToString(), targetSpacing, timeDiff, heightDiff, expectedTarget.ToString(), expectednBits);
}


// Tests of the CalculateASERT function.
BOOST_AUTO_TEST_CASE(calculate_asert_test)
{
    SelectParams(CBaseChainParams::LEGACY_UNIT_TESTS);
    const Consensus::Params &params = Params().GetConsensus();
    const int64_t nHalfLife = params.nASERTHalfLife;

    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    arith_uint256 initialTarget = powLimit >> 4;
    int64_t height = 0;

    // The CalculateASERT function uses the absolute ASERT formulation
    // and adds +1 to the height difference that it receives.
    // The time difference passed to it must factor in the difference
    // to the *parent* of the reference block.
    // We assume the parent is ideally spaced in time before the reference block.
    static const int64_t parent_time_diff = 600;

    // Steady
    arith_uint256 nextTarget = CalculateASERT(
        initialTarget, params.nPowTargetSpacing, parent_time_diff + 600 /* nTimeDiff */, ++height, powLimit, nHalfLife);
    BOOST_CHECK(nextTarget == initialTarget);

    // A block that arrives in half the expected time
    nextTarget = CalculateASERT(
        initialTarget, params.nPowTargetSpacing, parent_time_diff + 600 + 300, ++height, powLimit, nHalfLife);
    BOOST_CHECK(nextTarget < initialTarget);

    // A block that makes up for the shortfall of the previous one, restores the target to initial
    arith_uint256 prevTarget = nextTarget;
    nextTarget = CalculateASERT(
        initialTarget, params.nPowTargetSpacing, parent_time_diff + 600 + 300 + 900, ++height, powLimit, nHalfLife);
    BOOST_CHECK(nextTarget > prevTarget);
    BOOST_CHECK(nextTarget == initialTarget);

    // Two days ahead of schedule should double the target (halve the difficulty)
    prevTarget = nextTarget;
    nextTarget =
        CalculateASERT(prevTarget, params.nPowTargetSpacing, parent_time_diff + 288 * 1200, 288, powLimit, nHalfLife);
    BOOST_CHECK(nextTarget == prevTarget * 2);

    // Two days behind schedule should halve the target (double the difficulty)
    prevTarget = nextTarget;
    nextTarget =
        CalculateASERT(prevTarget, params.nPowTargetSpacing, parent_time_diff + 288 * 0, 288, powLimit, nHalfLife);
    BOOST_CHECK(nextTarget == prevTarget / 2);
    BOOST_CHECK(nextTarget == initialTarget);

    // Ramp up from initialTarget to PowLimit - should only take 4 doublings...
    uint32_t powLimit_nBits = powLimit.GetCompact();
    uint32_t next_nBits;
    for (size_t k = 0; k < 3; k++)
    {
        prevTarget = nextTarget;
        nextTarget = CalculateASERT(
            prevTarget, params.nPowTargetSpacing, parent_time_diff + 288 * 1200, 288, powLimit, nHalfLife);
        BOOST_CHECK(nextTarget == prevTarget * 2);
        BOOST_CHECK(nextTarget < powLimit);
        next_nBits = nextTarget.GetCompact();
        BOOST_CHECK(next_nBits != powLimit_nBits);
    }

    prevTarget = nextTarget;
    nextTarget =
        CalculateASERT(prevTarget, params.nPowTargetSpacing, parent_time_diff + 288 * 1200, 288, powLimit, nHalfLife);
    next_nBits = nextTarget.GetCompact();
    BOOST_CHECK(nextTarget == prevTarget * 2);
    BOOST_CHECK(next_nBits == powLimit_nBits);

    // Fast periods now cannot increase target beyond POW limit, even if we try to overflow nextTarget.
    // prevTarget is a uint256, so 256*2 = 512 days would overflow nextTarget unless CalculateASERT
    // correctly detects this error
    nextTarget = CalculateASERT(
        prevTarget, params.nPowTargetSpacing, parent_time_diff + 512 * 144 * 600, 0, powLimit, nHalfLife);
    next_nBits = nextTarget.GetCompact();
    BOOST_CHECK(next_nBits == powLimit_nBits);

    // We also need to watch for underflows on nextTarget. We need to withstand an extra ~446 days worth of blocks.
    // This should bring down a powLimit target to the a minimum target of 1.
    nextTarget = CalculateASERT(powLimit, params.nPowTargetSpacing, 0, 2 * (256 - 33) * 144, powLimit, nHalfLife);
    next_nBits = nextTarget.GetCompact();
    BOOST_CHECK_EQUAL(next_nBits, arith_uint256(1).GetCompact());

    // Define a structure holding parameters to pass to CalculateASERT.
    // We are going to check some expected results  against a vector of
    // possible arguments.
    struct calc_params
    {
        arith_uint256 refTarget;
        int64_t targetSpacing;
        int64_t timeDiff;
        int64_t heightDiff;
        arith_uint256 expectedTarget;
        uint32_t expectednBits;
    };

    // Define some named input argument values
    const arith_uint256 SINGLE_300_TARGET{"00000000ffb1ffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    const arith_uint256 FUNNY_REF_TARGET{"000000008000000000000000000fffffffffffffffffffffffffffffffffffff"};

    // Define our expected input and output values.
    // The timeDiff entries exclude the `parent_time_diff` - this is
    // added in the call to CalculateASERT in the test loop.
    const std::vector<calc_params> calculate_args = {

        /* refTarget, targetSpacing, timeDiff, heightDiff, expectedTarget, expectednBits */

        {powLimit, 600, 0, 2 * 144, powLimit >> 1, 0x1c7fffff}, {powLimit, 600, 0, 4 * 144, powLimit >> 2, 0x1c3fffff},
        {powLimit >> 1, 600, 0, 2 * 144, powLimit >> 2, 0x1c3fffff},
        {powLimit >> 2, 600, 0, 2 * 144, powLimit >> 3, 0x1c1fffff},
        {powLimit >> 3, 600, 0, 2 * 144, powLimit >> 4, 0x1c0fffff},
        {powLimit, 600, 0, 2 * (256 - 34) * 144, 3, 0x01030000},
        {powLimit, 600, 0, 2 * (256 - 34) * 144 + 119, 3, 0x01030000},
        {powLimit, 600, 0, 2 * (256 - 34) * 144 + 120, 2, 0x01020000},
        {powLimit, 600, 0, 2 * (256 - 33) * 144 - 1, 2, 0x01020000},
        {powLimit, 600, 0, 2 * (256 - 33) * 144, 1, 0x01010000}, // 1 bit less since we do not need to shift to 0
        {powLimit, 600, 0, 2 * (256 - 32) * 144, 1, 0x01010000}, // more will not decrease below 1
        {1, 600, 0, 2 * (256 - 32) * 144, 1, 0x01010000},
        {powLimit, 600, 2 * (512 - 32) * 144, 0, powLimit, powLimit_nBits},
        {1, 600, (512 - 64) * 144 * 600, 0, powLimit, powLimit_nBits},
        {powLimit, 600, 300, 1, SINGLE_300_TARGET, 0x1d00ffb1}, // clamps to powLimit
        // confuses any attempt to detect overflow by inspecting result
        {FUNNY_REF_TARGET, 600, 600 * 2 * 33 * 144, 0, powLimit, powLimit_nBits},
        {1, 600, 600 * 2 * 256 * 144, 0, powLimit, powLimit_nBits}, // overflow to exactly 2^256
        // just under powlimit (not clamped) yet over powlimit_nbits
        {1, 600, 600 * 2 * 224 * 144 - 1, 0, arith_uint256(0xffff8) << 204, powLimit_nBits},
    };

    for (auto &v : calculate_args)
    {
        nextTarget = CalculateASERT(
            v.refTarget, v.targetSpacing, parent_time_diff + v.timeDiff, v.heightDiff, powLimit, nHalfLife);
        next_nBits = nextTarget.GetCompact();
        const auto failMsg = StrPrintCalcArgs(v.refTarget, v.targetSpacing, parent_time_diff + v.timeDiff, v.heightDiff,
                                 v.expectedTarget, v.expectednBits) +
                             strprintf("nextTarget=  %s\nnext nBits=  0x%08x\n", nextTarget.ToString(), next_nBits);
        BOOST_CHECK_MESSAGE(nextTarget == v.expectedTarget && next_nBits == v.expectednBits, failMsg);
    }
}

// Verify the summary-block DAA adjustment without uncles: a fully populated summary should
// keep the default nBits, while an under-filled summary should harden its own
// subblock nBits enough to make up the missing referenced work.
BOOST_AUTO_TEST_CASE(tailstorm_summary_work_adjustment_test)
{
    // These Tailstorm DAA tests use the legacy unit-test chain because it keeps Tailstorm enabled
    // and also satisfies CalculateASERT()'s preconditions. In particular, CalculateASERT() asserts
    // that powLimit has enough leading zero bits for its shift-based math ((powLimit >> 238) == 0),
    // and the regtest/stormtest-style max targets do not satisfy that requirement.
    SelectParams(CBaseChainParams::LEGACY_UNIT_TESTS);
    const Consensus::Params &params = Params().GetConsensus();
    BOOST_REQUIRE(params.tailstorm_k > 1);

    std::vector<CBlockIndex> blocks(2);
    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    const arith_uint256 initialTarget = powLimit >> 4;
    const uint32_t initialBits = initialTarget.GetCompact();

    blocks[0] = CBlockIndex();
    blocks[0].SetBlockHeaderHeight(0);
    blocks[0].SetBlockHeaderTime(1269211443);
    blocks[0].SetBlockHeaderBits(0x0dedbeef);
    blocks[0].SetBlockHeaderChainWork(ArithToUint256(blocks[0].GetBlockWork()));

    blocks[1] = GetBlockIndex(&blocks[0], params.nPowTargetSpacing, initialBits);

    const int64_t anchorTime = blocks[1].pprev ? blocks[1].pprev->GetBlockTime() : blocks[1].GetBlockTime();
    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(blocks[1].tgtBits());
    arith_uint256 rawDefaultTarget = CalculateASERT(refBlockTarget,
        params.nPowTargetSpacing,
        blocks[1].GetBlockTime() - anchorTime,
        blocks[1].height() - blocks[1].height(),
        powLimit,
        params.nASERTHalfLife) *
        params.tailstorm_k;
    if (rawDefaultTarget > powLimit)
        rawDefaultTarget = powLimit;
    const arith_uint256 rawDefaultWork = GetWorkForTarget(rawDefaultTarget);

    CBlockHeader subblockHeader;
    const uint32_t defaultBits = GetNextASERTWorkRequired(&blocks[1], &subblockHeader, params, &blocks[1], true);
    const arith_uint256 defaultTarget = arith_uint256().SetCompact(defaultBits);

    CBlockHeader fullSummaryHeader;
    fullSummaryHeader.minerData =
        MakeTailstormSummaryMinerData(0, defaultBits, params.tailstorm_k - 1, defaultBits);
    const uint32_t fullSummaryBits =
        GetNextASERTWorkRequired(&blocks[1], &fullSummaryHeader, params, &blocks[1], true);
    BOOST_CHECK_EQUAL(fullSummaryBits, defaultBits);

    const uint8_t nIncludedSubblocks = 1;
    CBlockHeader deficitSummaryHeader;
    deficitSummaryHeader.minerData =
        MakeTailstormSummaryMinerData(0, defaultBits, nIncludedSubblocks, defaultBits);
    const uint32_t deficitSummaryBits =
        GetNextASERTWorkRequired(&blocks[1], &deficitSummaryHeader, params, &blocks[1], true);
    const arith_uint256 deficitSummaryTarget = arith_uint256().SetCompact(deficitSummaryBits);
    const arith_uint256 deficitSummaryWork = GetWorkForDifficultyBits(deficitSummaryBits);

    const arith_uint256 expectedBlockWork = rawDefaultWork * params.tailstorm_k;
    const arith_uint256 currentIncludedWork = GetWorkForDifficultyBits(defaultBits) * nIncludedSubblocks;
    const arith_uint256 remainingWork = expectedBlockWork - currentIncludedWork;
    const uint32_t expectedDeficitBits = GetCompactBitsForRequiredWork(remainingWork);

    BOOST_CHECK_EQUAL(deficitSummaryBits, expectedDeficitBits);
    BOOST_CHECK(deficitSummaryTarget < defaultTarget);
    BOOST_CHECK(deficitSummaryWork >= remainingWork);
}

// Verify the summary-block DAA adjustment with included uncles: easier uncles should force the
// summary subblock nBits to harden, while harder or equal-difficulty uncles should leave the
// summary subblock at the default nBits.
BOOST_AUTO_TEST_CASE(tailstorm_summary_work_adjustment_with_uncles_test)
{
    SelectParams(CBaseChainParams::LEGACY_UNIT_TESTS);
    const Consensus::Params &params = Params().GetConsensus();
    BOOST_REQUIRE(params.tailstorm_k >= 4); // needed for the 3-uncles, K-4-subblocks scenario

    std::vector<CBlockIndex> blocks(2);
    const arith_uint256 powLimit = UintToArith256(params.powLimit);
    // Use a harder baseline than powLimit >> 4 so Tailstorm's subblock target does not clamp to
    // powLimit after multiplying by tailstorm_k. That leaves room to model easier uncle targets.
    const arith_uint256 initialTarget = powLimit >> 10;
    const uint32_t initialBits = initialTarget.GetCompact();

    blocks[0] = CBlockIndex();
    blocks[0].SetBlockHeaderHeight(0);
    blocks[0].SetBlockHeaderTime(1269211443);
    blocks[0].SetBlockHeaderBits(0x0dedbeef);
    blocks[0].SetBlockHeaderChainWork(ArithToUint256(blocks[0].GetBlockWork()));

    blocks[1] = GetBlockIndex(&blocks[0], params.nPowTargetSpacing, initialBits);

    const int64_t anchorTime = blocks[1].pprev ? blocks[1].pprev->GetBlockTime() : blocks[1].GetBlockTime();
    const arith_uint256 refBlockTarget = arith_uint256().SetCompact(blocks[1].tgtBits());
    arith_uint256 rawDefaultTarget = CalculateASERT(refBlockTarget,
        params.nPowTargetSpacing,
        blocks[1].GetBlockTime() - anchorTime,
        blocks[1].height() - blocks[1].height(),
        powLimit,
        params.nASERTHalfLife) *
        params.tailstorm_k;
    if (rawDefaultTarget > powLimit)
        rawDefaultTarget = powLimit;
    const arith_uint256 rawDefaultWork = GetWorkForTarget(rawDefaultTarget);

    CBlockHeader subblockHeader;
    const uint32_t defaultBits = GetNextASERTWorkRequired(&blocks[1], &subblockHeader, params, &blocks[1], true);
    const arith_uint256 defaultTarget = arith_uint256().SetCompact(defaultBits);
    const arith_uint256 defaultWork = GetWorkForDifficultyBits(defaultBits);
    const arith_uint256 halfDefaultWork = defaultWork / arith_uint256(2);
    const arith_uint256 doubleDefaultWork = defaultWork * 2;

    uint32_t harderUncleBits = defaultBits;
    while (GetWorkForDifficultyBits(harderUncleBits) < doubleDefaultWork)
        harderUncleBits = GetNextHarderCompactBits(harderUncleBits);

    uint32_t easierUncleBits = defaultBits;
    while (GetWorkForDifficultyBits(easierUncleBits) > halfDefaultWork)
        easierUncleBits = GetNextEasierCompactBitsForTest(easierUncleBits, powLimit);

    struct Scenario
    {
        const char *name;
        uint8_t nUncles;
        uint32_t nBitsUncle;
        uint8_t nSubblocks;
        bool expectHarderThanDefault;
    };

    // Cover the three interesting uncle-work cases for summary adjustment:
    // 1. easier uncles contribute less work than default subblocks and should harden summary nBits
    // 2. harder uncles contribute enough extra work that summary nBits should stay at the default
    // 3. equal-difficulty uncles behave like subblocks and should also leave summary nBits unchanged
    const Scenario scenarios[] = {
        {"difficulty_adjust_up_with_uncles", 1, easierUncleBits, static_cast<uint8_t>(params.tailstorm_k - 2), true},
        {"difficulty_adjust_down_with_uncles", 2, harderUncleBits, static_cast<uint8_t>(params.tailstorm_k - 3), false},
        {"no_difficulty_change_with_uncles", 3, defaultBits, static_cast<uint8_t>(params.tailstorm_k - 4), false},
    };

    for (const auto &scenario : scenarios)
    {
        CBlockHeader summaryHeader;
        summaryHeader.minerData =
            MakeTailstormSummaryMinerData(scenario.nUncles, scenario.nBitsUncle, scenario.nSubblocks, defaultBits);
        const uint32_t actualSummaryBits =
            GetNextASERTWorkRequired(&blocks[1], &summaryHeader, params, &blocks[1], true);
        const arith_uint256 actualSummaryTarget = arith_uint256().SetCompact(actualSummaryBits);

        const arith_uint256 currentIncludedWork =
            (scenario.nUncles * GetWorkForDifficultyBits(scenario.nBitsUncle)) +
            (scenario.nSubblocks * defaultWork);
        arith_uint256 requiredSummaryWork = rawDefaultWork;
        const arith_uint256 expectedBlockWork = rawDefaultWork * params.tailstorm_k;
        if (currentIncludedWork < expectedBlockWork)
        {
            const arith_uint256 remainingWork = expectedBlockWork - currentIncludedWork;
            if (remainingWork > requiredSummaryWork)
                requiredSummaryWork = remainingWork;
        }

        const uint32_t expectedSummaryBits = GetCompactBitsForRequiredWork(requiredSummaryWork);
        BOOST_CHECK_EQUAL(actualSummaryBits, expectedSummaryBits);

        if (scenario.expectHarderThanDefault)
        {
            BOOST_CHECK(actualSummaryTarget < defaultTarget);
        }
        else
        {
            BOOST_CHECK_EQUAL(actualSummaryBits, defaultBits);
        }
    }
}

// Direct coverage for GetNextHarderCompactBits. The function must always return
// an encoding whose decoded target is strictly smaller than the input's (i.e.
// harder), including the previously-broken "mantissa == 1" borrow case.
BOOST_AUTO_TEST_CASE(get_next_harder_compact_bits_test)
{
    // Simple in-range decrement: mantissa already packed, borrow not exercised.
    {
        const uint32_t nBits = 0x1d00ffff;
        const uint32_t harder = GetNextHarderCompactBits(nBits);
        BOOST_CHECK_EQUAL(harder, 0x1d00fffeu);
        BOOST_CHECK(arith_uint256().SetCompact(harder) < arith_uint256().SetCompact(nBits));
    }

    // Borrow case: the old implementation returned ((nSize-1) << 24) | 0x007fffff
    // which decodes to a *larger* (easier) target. The result must be strictly
    // harder and the encoded work must strictly increase.
    {
        const uint32_t nBits = 0x05000001; // value = 1 * 256^2 = 0x10000
        const uint32_t harder = GetNextHarderCompactBits(nBits);
        const arith_uint256 inputTarget = arith_uint256().SetCompact(nBits);
        const arith_uint256 harderTarget = arith_uint256().SetCompact(harder);
        BOOST_CHECK(harderTarget < inputTarget);
        BOOST_CHECK(GetWorkForDifficultyBits(harder) > GetWorkForDifficultyBits(nBits));
    }

    // Denormalized input: the 23-bit mantissa has an empty top byte and enough
    // headroom to be shifted up without colliding with the sign bit (0x00800000).
    // Normalization should pack it up by one byte, so the decrement takes the
    // finer 256^(nSize-4) step instead of the coarser 256^(nSize-3) step.
    {
        const uint32_t nBits = 0x1d000100;
        const uint32_t harder = GetNextHarderCompactBits(nBits);
        BOOST_CHECK_EQUAL(harder, 0x1c00ffffu);
        BOOST_CHECK(arith_uint256().SetCompact(harder) < arith_uint256().SetCompact(nBits));
    }

    // Canonical lower boundary: input mantissa is exactly 0x008000, the smallest
    // canonical value (set by arith_uint256::GetCompact() after a sign-bit bump).
    // A plain decrement yields (nSize, 0x007fff), which is valid but not canonical
    // and lands 256^(nSize-3) below the input. Re-canonicalizing folds a byte of
    // exponent into the mantissa, giving (nSize-1, 0x7fffff): the finest possible
    // step, one unit of 256^(nSize-4) below the input.
    {
        const uint32_t nBits = 0x1d008000;
        const uint32_t harder = GetNextHarderCompactBits(nBits);
        BOOST_CHECK_EQUAL(harder, 0x1c7fffffu);
        BOOST_CHECK(arith_uint256().SetCompact(harder) < arith_uint256().SetCompact(nBits));
    }

    // Small-nSize canonical step: fold lands at nSize < 3, where canonical form
    // requires the structurally-zero low bytes of the mantissa to actually be
    // zero (GetCompact left-shifts the value into the high bytes). Masking the
    // low byte after the fold keeps the decoded target unchanged while producing
    // the exact bit pattern GetCompact would. Round-trip through GetCompact must
    // return the same nBits, confirming canonicity.
    {
        const uint32_t nBits = 0x03008000;
        const uint32_t harder = GetNextHarderCompactBits(nBits);
        BOOST_CHECK_EQUAL(harder, 0x027fff00u);
        const arith_uint256 target = arith_uint256().SetCompact(harder);
        BOOST_CHECK_EQUAL(target.GetCompact(), harder);
        BOOST_CHECK(target < arith_uint256().SetCompact(nBits));
    }

    // Iterating must produce a strictly decreasing target, never flipping back
    // to an easier encoding the way the old borrow branch did. Start from a
    // realistic nSize so nothing is lost to compact-format truncation.
    {
        uint32_t nBits = 0x1e000005;
        arith_uint256 prevTarget = arith_uint256().SetCompact(nBits);
        for (int i = 0; i < 16; ++i)
        {
            nBits = GetNextHarderCompactBits(nBits);
            const arith_uint256 target = arith_uint256().SetCompact(nBits);
            BOOST_CHECK(target < prevTarget);
            prevTarget = target;
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
