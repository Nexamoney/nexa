// Copyright (c) 2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "crypto/common.h"
#include "datastream.h"
#include "pow.h"
#include "test/test_nexa.h"
#include "validation/headervalidation.h"
#include "validation/tailstorm.h"

#include <boost/test/unit_test.hpp>

namespace
{
struct SummaryPowTestingSetup : BasicTestingSetup
{
    const Consensus::Params &params;
    CBlockHeader header;
    CSummaryBlockMinerData data;

    SummaryPowTestingSetup() : BasicTestingSetup(CBaseChainParams::REGTEST), params(Params().GetConsensus())
    {
        header.hashPrevBlock = uint256S("01");
        header.height = 2;
        header.size = 1000;
        header.nBits = UintToArith256(params.powLimit).GetCompact();
        data.prevOfprevhash = uint256S("02");
        data.nBitsSubblock = header.nBits;
        const arith_uint256 uncleTarget = UintToArith256(params.powLimit) >> 1;
        data.nBitsUncle = uncleTarget.GetCompact();
        SetProofs(0);
    }

    std::vector<uint8_t> FindNonce(const uint256 &commitment,
        const uint256 &parent,
        uint32_t bits,
        bool valid = true,
        uint32_t start = 0)
    {
        std::vector<uint8_t> nonce(4);
        for (uint32_t i = start; i < start + 4096; ++i)
        {
            WriteLE32(nonce.data(), i);
            if (CheckProofOfWork(GetMiningHash(commitment, nonce), parent, bits, params) == valid)
                return nonce;
        }
        BOOST_FAIL("Could not find a nonce with the requested PoW result");
        return {};
    }

    void SetProofs(uint8_t uncles)
    {
        data.nUncles = uncles;
        data.nSubblocks = params.tailstorm_k - 1 - uncles;
        data.vSubblockProofs.clear();
        for (uint32_t i = 0; i < params.tailstorm_k - 1; ++i)
        {
            const uint256 commitment = ArithToUint256(arith_uint256(i + 10));
            const bool uncle = i < uncles;
            data.vSubblockProofs.emplace_back(
                commitment, FindNonce(commitment, uncle ? data.prevOfprevhash : header.hashPrevBlock,
                                uncle ? data.nBitsUncle : data.nBitsSubblock));
        }
    }

    CBlockHeader Summary(bool validPow = true)
    {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION << data.prevOfprevhash << data.nUncles << data.nBitsUncle
               << data.nSubblocks << data.nBitsSubblock << data.vSubblockProofs;
        header.minerData.assign(stream.begin(), stream.end());
        // Miner data is part of the commitment, so solve the summary again after every edit.
        header.nonce = FindNonce(header.GetMiningHeaderCommitment(), header.hashPrevBlock, header.nBits, validPow);
        return header;
    }

    void CheckAccepted()
    {
        CValidationState state;
        BOOST_CHECK(CheckTailstormSummaryBlockProofOfWork(params, Summary(), state));
        BOOST_CHECK(state.IsValid());
    }

    void CheckRejected(const CBlockHeader &summary, const std::string &reason, int dos = 50)
    {
        CValidationState state;
        BOOST_CHECK(!CheckTailstormSummaryBlockProofOfWork(params, summary, state));
        int score = 0;
        BOOST_CHECK(state.IsInvalid(score));
        BOOST_CHECK_EQUAL(score, dos);
        BOOST_CHECK_EQUAL(state.GetRejectCode(), REJECT_INVALID);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), reason);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(headervalidation_tests, SummaryPowTestingSetup)

BOOST_AUTO_TEST_CASE(summary_valid_proofs)
{
    // Cover both sides of the uncle/subblock boundary, including either group being empty.
    for (uint8_t uncles = 0; uncles < params.tailstorm_k; ++uncles)
    {
        BOOST_TEST_CONTEXT("uncles=" << unsigned(uncles))
        {
            SetProofs(uncles);
            CheckAccepted();
        }
    }
}

BOOST_AUTO_TEST_CASE(summary_duplicate_proof)
{
    // Valid PoW must not let the same proof count twice, for either type of subblock.
    for (uint8_t uncles : {uint8_t(0), uint8_t(params.tailstorm_k - 1)})
    {
        SetProofs(uncles);
        CheckAccepted();
        data.vSubblockProofs[1] = data.vSubblockProofs[0];
        CheckRejected(Summary(), "bad-blk-duplicate-mining-hash");
    }
}

BOOST_AUTO_TEST_CASE(summary_distinct_nonces)
{
    // Two solutions to one header commitment are distinct proofs, not duplicates.
    for (uint8_t uncles : {uint8_t(0), uint8_t(params.tailstorm_k - 1)})
    {
        SetProofs(uncles);
        const auto &first = data.vSubblockProofs[0];
        auto &second = data.vSubblockProofs[1];
        second.first = first.first;
        second.second = FindNonce(first.first, uncles ? data.prevOfprevhash : header.hashPrevBlock,
            uncles ? data.nBitsUncle : data.nBitsSubblock, true, ReadLE32(first.second.data()) + 1);
        BOOST_REQUIRE(first.second != second.second);
        BOOST_REQUIRE(GetMiningHash(first.first, first.second) != GetMiningHash(second.first, second.second));
        CheckAccepted();
    }
}

BOOST_AUTO_TEST_CASE(summary_duplicate_across_epochs)
{
    // A proof valid against both parents still cannot count as both an uncle and a subblock.
    SetProofs(1);
    auto &uncle = data.vSubblockProofs[0];
    bool found = false;
    for (uint32_t i = 0; i < 4096; ++i)
    {
        WriteLE32(uncle.second.data(), i);
        const uint256 hash = GetMiningHash(uncle.first, uncle.second);
        if (CheckProofOfWork(hash, data.prevOfprevhash, data.nBitsUncle, params) &&
            CheckProofOfWork(hash, header.hashPrevBlock, data.nBitsSubblock, params))
        {
            found = true;
            break;
        }
    }
    BOOST_REQUIRE(found);
    CheckAccepted();
    data.vSubblockProofs[1] = uncle;
    CheckRejected(Summary(), "bad-blk-duplicate-mining-hash");
}

BOOST_AUTO_TEST_CASE(summary_wrong_proof_count)
{
    // The proof vector disagrees with both k-1 and the declared uncle/subblock counts.
    const auto proofs = data.vSubblockProofs;
    for (size_t count : {size_t(0), size_t(params.tailstorm_k - 2), size_t(params.tailstorm_k)})
    {
        data.vSubblockProofs = proofs;
        data.vSubblockProofs.resize(count, proofs.front());
        CheckRejected(Summary(), "bad-blk-wrong-number-of-subblocks", 100);
    }
}

BOOST_AUTO_TEST_CASE(summary_high_hash)
{
    // Only the summary's own proof is invalid; all referenced proofs remain valid.
    CheckAccepted();
    CheckRejected(Summary(false), "bad-blk-subblock-high-hash");
}

BOOST_AUTO_TEST_CASE(summary_subblock_high_hash)
{
    // A valid summary proof must not hide an invalid referenced subblock proof.
    SetProofs(1);
    CheckAccepted();
    auto &proof = data.vSubblockProofs.back();
    proof.second = FindNonce(proof.first, header.hashPrevBlock, data.nBitsSubblock, false);
    CheckRejected(Summary(), "bad-blk-subblock-high-hash");
}

BOOST_AUTO_TEST_CASE(summary_uncle_high_hash)
{
    // Uncle PoW uses the previous epoch's parent and target.
    SetProofs(1);
    CheckAccepted();
    auto &proof = data.vSubblockProofs.front();
    proof.second = FindNonce(proof.first, data.prevOfprevhash, data.nBitsUncle, false);
    CheckRejected(Summary(), "bad-blk-subblock-high-hash");
}

BOOST_AUTO_TEST_CASE(summary_null_uncle_parent)
{
    // Solve the uncle against the null parent so rejection reaches the parent check.
    data.prevOfprevhash.SetNull();
    SetProofs(1);
    CheckRejected(Summary(), "bad-blk-invalid-uncle-parent");
    SetProofs(0);
    CheckAccepted();
}

BOOST_AUTO_TEST_SUITE_END()
