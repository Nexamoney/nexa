// Copyright (c) 2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "crypto/common.h"
#include "daa.h"
#include "datastream.h"
#include "main.h"
#include "pow.h"
#include "test/test_nexa.h"
#include "validation/headervalidation.h"
#include "validation/tailstorm.h"
#include "validation/validation.h"

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

// A Tailstorm summary header on genesis with K-1 valid sub-block proofs, accepted through the
// real header path. Genesis is made fork pending so summary miner data is allowed.
struct SummaryHeaderTestingSetup : TestingSetup
{
    const Consensus::Params &params;
    const uint64_t forkTime;
    uint32_t nProofs; // sub-block proofs carried by Summary()

    SummaryHeaderTestingSetup()
        : TestingSetup(CBaseChainParams::REGTEST), params(Params().GetConsensus()), forkTime(nMiningForkTime),
          nProofs(params.tailstorm_k - 1)
    {
        nMiningForkTime = chainActive.Genesis()->GetMedianTimePast();
    }
    ~SummaryHeaderTestingSetup() { nMiningForkTime = forkTime; }

    std::vector<uint8_t> Solve(const uint256 &commitment, const uint256 &parent, uint32_t bits)
    {
        std::vector<uint8_t> nonce(4);
        for (uint32_t i = 0; i < 100000; ++i)
        {
            WriteLE32(nonce.data(), i);
            if (CheckProofOfWork(GetMiningHash(commitment, nonce), parent, bits, params))
                return nonce;
        }
        BOOST_FAIL("Could not solve");
        return {};
    }

    // nDeclared is the sub-block count written in the miner data; nProofs proofs are carried.
    CBlockHeader Summary(uint8_t nDeclared, uint32_t salt)
    {
        const CBlockIndex *genesis = chainActive.Genesis();
        CBlockHeader header;
        header.hashPrevBlock = genesis->GetBlockHash();
        header.hashAncestor = genesis->GetBlockHash();
        header.height = 1;
        header.nTime = genesis->GetBlockTime() + 1;
        header.size = 1000;
        header.txCount = 1;
        header.minerData = {DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION};
        header.nBits = GetNextWorkRequired(genesis, &header, params);

        CSummaryBlockMinerData data;
        data.nSubblocks = nDeclared;
        data.nBitsSubblock = header.nBits;
        for (uint32_t i = 0; i < nProofs; ++i)
        {
            const uint256 commitment = ArithToUint256(arith_uint256(salt + i));
            data.vSubblockProofs.emplace_back(commitment, Solve(commitment, header.hashPrevBlock, data.nBitsSubblock));
        }
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION << data.prevOfprevhash << data.nUncles << data.nBitsUncle
               << data.nSubblocks << data.nBitsSubblock << data.vSubblockProofs;
        header.minerData.assign(stream.begin(), stream.end());

        // ContextualCheckBlockHeader requires the chain work implied by the declared counts
        header.chainWork = ArithToUint256(genesis->chainWork() +
                                          arith_uint256(nDeclared) * GetWorkForDifficultyBits(data.nBitsSubblock) +
                                          GetWorkForDifficultyBits(header.nBits));
        header.nonce = Solve(header.GetMiningHeaderCommitment(), header.hashPrevBlock, header.nBits);
        return header;
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

BOOST_AUTO_TEST_CASE(summary_declared_counts_must_match_proofs)
{
    // K-1 proofs satisfy "size == K-1", so the declared sub-block count is never checked
    // against the proofs. Declaring 255 sub-blocks claims work for 255 with K-1 proofs.
    SetProofs(0);
    CheckAccepted();
    data.nSubblocks = 255;
    CValidationState state;
    BOOST_CHECK_MESSAGE(!CheckTailstormSummaryBlockProofOfWork(params, Summary(), state),
        "summary with " << params.tailstorm_k - 1 << " proofs but nSubblocks=255 was accepted");

    // Fewer than K-1 proofs is invalid even when the declared counts match them
    SetProofs(0);
    data.vSubblockProofs.pop_back();
    data.nSubblocks = data.vSubblockProofs.size();
    CheckRejected(Summary(), "bad-blk-wrong-number-of-subblocks", 100);
}

BOOST_FIXTURE_TEST_CASE(summary_header_chainwork_must_be_backed_by_proofs, SummaryHeaderTestingSetup)
{
    // Both headers carry K-1 sub-block proofs on genesis. The honest one declares K-1 and
    // claims K blocks of work. The inflated one declares 255 and, if accepted, claims 256
    // blocks of work and becomes the best header without any additional proof of work.
    const uint8_t honestCount = params.tailstorm_k - 1;
    LOCK(cs_main);

    CValidationState state;
    CBlockIndex *honest = nullptr;
    BOOST_REQUIRE_MESSAGE(AcceptBlockHeader(Summary(honestCount, 1000), state, Params(), &honest),
        "honest summary rejected: " << state.GetRejectReason());
    BOOST_REQUIRE(honest != nullptr);
    BOOST_CHECK(pindexBestHeader == honest);

    state = CValidationState();
    CBlockIndex *inflated = nullptr;
    const bool accepted = AcceptBlockHeader(Summary(255, 2000), state, Params(), &inflated);
    const arith_uint256 blockWork = GetWorkForDifficultyBits(chainActive.Genesis()->nBits);
    BOOST_TEST_MESSAGE(
        "honest summary work: " << ((honest->chainWork() - chainActive.Genesis()->chainWork()) / blockWork).GetLow64()
                                << " blocks");
    if (inflated)
        BOOST_TEST_MESSAGE("inflated summary work: "
                           << ((inflated->chainWork() - chainActive.Genesis()->chainWork()) / blockWork).GetLow64()
                           << " blocks, best header is inflated: " << (pindexBestHeader == inflated));

    BOOST_CHECK_MESSAGE(
        !accepted, "summary declaring 255 sub-blocks with " << unsigned(honestCount) << " proofs was accepted");
    BOOST_CHECK_MESSAGE(pindexBestHeader == honest, "best header moved to the inflated summary");
}

BOOST_FIXTURE_TEST_CASE(summary_header_without_proofs_is_rejected, SummaryHeaderTestingSetup)
{
    // A summary with no proofs and no declared uncles or sub-blocks used to pass the header rules: synced nodes
    // deferred it forever while syncing nodes connected it. It must be rejected the same way before and after the
    // fork, whether or not the initial sync is complete.
    nProofs = 0;
    LOCK(cs_main);
    bool originalSyncComplete = IsInitialSyncComplete();
    for (bool forkPending : {false, true})
    {
        for (bool syncComplete : {false, true})
        {
            nMiningForkTime = forkPending ? chainActive.Genesis()->GetMedianTimePast() : forkTime;
            IsInitialSyncCompleteInit(&syncComplete);
            CValidationState state;
            CBlockIndex *pindex = nullptr;
            BOOST_CHECK(!AcceptBlockHeader(Summary(0, 3000), state, Params(), &pindex));
            BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-blk-wrong-number-of-subblocks");
            BOOST_CHECK(pindex == nullptr);
        }
    }
    IsInitialSyncCompleteInit(&originalSyncComplete);
}

BOOST_AUTO_TEST_SUITE_END()
