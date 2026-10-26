// Copyright (c) 2018 The Bitcoin developers
// Copyright (c) 2018-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NEXA_RESPEND_RESPENDDETECTOR_H
#define NEXA_RESPEND_RESPENDDETECTOR_H

#include "respend/dsproof.h"
#include "respend/respendaction.h"

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>

class CRollingBloomFilter;
class DoubleSpendProofStorage;

namespace respend
{
std::vector<RespendActionPtr> CreateDefaultActions();

//! Validates the orphan proofs for outpoint, claims the first valid one and removes the rest
//! Returns the claimed proof id and sets proofHash, or returns -1 if no proof was claimed
int ClaimOrphanProof(DoubleSpendProofStorage &storage,
    const COutPoint &outpoint,
    uint256 &proofHash,
    const std::function<DoubleSpendProof::Validity(const DoubleSpendProof &)> &validate);

// Detects if a transaction is in conflict with mempool, and feeds various
// actions with data about the respend. Finally triggers the actions.
class RespendDetector
{
public:
    RespendDetector(const CTxMemPool &pool,
        const CTransactionRef ptx,
        std::vector<RespendActionPtr> = CreateDefaultActions());

    ~RespendDetector();
    void CheckForRespend(const CTxMemPool &pool, const CTransactionRef ptx);
    void SetValid(bool valid);
    bool IsRespend() const;
    int GetDsproof() const;

    const std::vector<COutPoint> &getConflicts() const;

    // Respend is interesting enough to trigger full tx validation.
    bool IsInteresting() const;

private:
    std::vector<COutPoint> conflictingOutpoints;

    // Outputs we've already seen in valid double spending transactions
    static std::unique_ptr<CRollingBloomFilter> respentBefore;
    static std::mutex respentBeforeMutex;
    std::vector<RespendActionPtr> actions;

    // Does this tx have a dsproof associated with it
    int dsproof = -1;
};

} // namespace respend

#endif
