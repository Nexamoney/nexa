// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NEXA_DOUBLESPENDPROOFSTORAGE_H
#define NEXA_DOUBLESPENDPROOFSTORAGE_H

#include "bloom.h"
#include "net.h"
#include "respend/dsproof.h"

#include <boost/asio.hpp>

#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <unordered_map>
#include <utility>

class COutPoint;

//! MAX total serialized size of the orphan proofs held at one time
static constexpr size_t MAX_ORPHAN_DSPROOF_BYTES = 1000 * 1000;
//! MAX number of orphan proofs held from one peer
static constexpr size_t MAX_ORPHAN_DSPROOFS_PER_PEER = 20;
//! MAX serialized size of one orphan proof
//! (real proofs are only hundreds of bytes, so this gives plenty of space)
static constexpr size_t MAX_ORPHAN_DSPROOF_SIZE = 4 * 1000;

class DoubleSpendProofStorage
{
public:
    DoubleSpendProofStorage();
    ~DoubleSpendProofStorage();

    /// returns a double spend proof based on proof-id
    DoubleSpendProof proof(int proof) const;
    /// Adds a proof, returns a pair of {fAdded, proofId}
    /// proofId is an internal id that the proof is known under.
    /// Note that if the proof (by hash) was known, the known id is returned instead,
    /// and fAdded will be false.
    std::pair<bool, int32_t> add(const DoubleSpendProof &proof);
    /// remove by proof-id
    void remove(int proof);

    /// this add()s and additionally registers this is an orphan.
    /// you can fetch those upto 90s using 'claim()'.
    /// the oldest orphans are evicted to stay within MAX_ORPHAN_DSPROOF_BYTES and MAX_ORPHAN_DSPROOFS_PER_PEER.
    void addOrphan(const DoubleSpendProof &proof, NodeId peerId);
    /// Returns all (not yet verified) orphans matching prevOut.
    /// Each item is a pair of a proofId and the nodeId that send the proof to us
    std::list<std::pair<int, NodeId> > findOrphans(const COutPoint &prevOut);

    //! Returns how many orphans have this proof id
    int orphanCount(int proofId);

    //! Returns how many proof ids the orphan outpoint lookup table holds
    size_t orphanLookupCount() const;

    //! Returns the total serialized size of the orphan proofs
    size_t orphanBytes() const;

    //! Returns how many orphan proofs are held from this peer
    size_t peerOrphanCount(NodeId peerId) const;

    //! Stops an orphan from expiring or being evicted.
    //! Returns false if proofId is no longer an orphan (after eviction or expiry)
    bool claimOrphan(int proofId);

    DoubleSpendProof lookup(const uint256 &proofId) const;
    bool exists(const uint256 &proofId) const;

    // called every minute
    void periodicCleanup(const boost::system::error_code &error);

    bool isRecentlyRejectedProof(const uint256 &proofHash) const;
    void markProofRejected(const uint256 &proofHash);
    void newBlockFound();

private:
    // dsproofStorageLock guards all the following data structures
    mutable CCriticalSection dsproofStorageLock;

    std::map<int32_t, DoubleSpendProof> m_proofs;
    int m_nextId = 1;
    std::map<int, std::pair<NodeId, int64_t> > m_orphans;
    //! Total serialized size of the proofs in m_orphans
    size_t m_orphanBytes = 0;
    //! The ids in m_orphans, by the peer that sent them
    std::map<NodeId, std::set<int> > m_orphansByPeer;

    //! Erases an orphan from m_orphans and from the totals above
    void eraseOrphan(int proofId);

    //! A salted hasher for use with the uint256 type in the LookupTable below.
    //! This code is inspired by txmempool.h's SaltedTxidHasher
    class SaltedHasher
    {
        const uint64_t k0, k1; //! Salt
    public:
        SaltedHasher();
        size_t operator()(const uint256 &hash) const;
    };

    using LookupTable = std::unordered_map<uint256, int32_t, SaltedHasher>;

    LookupTable m_dspIdLookupTable;
    std::map<uint64_t, std::deque<int> > m_prevTxIdLookupTable;

    CRollingBloomFilter m_recentRejects;

    // initialize timer
    boost::asio::deadline_timer m_timer;
};

#endif
