// Copyright (c) 2020-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dag.h"

#include "blockstorage/blockstorage.h"
#include "consensus/consensus.h"
#include "daa.h"
#include "requestManager.h"
#include "txadmission.h"
#include "txmempool.h"
#include "txorphanpool.h"
#include "ui_interface.h"
#include "validation/tailstorm.h"
#include "validation/validation.h"

#include <algorithm>

extern bool IsInitialBlockDownload();
extern CCriticalSection cs_main;
extern std::atomic<bool> forceTemplateRecalc;

class CValidationState;

CBlockIndex *LookupBlockIndex(const uint256 &hash);

std::set<uint256> GetPrevHashes(const CBlockHeader &header);

// Find the hash of the tip of the dag which has the best dag height
static CTreeNodeRef FindDagTipNode(std::set<CTreeNodeRef> &dag)
{
    CTreeNodeRef activetip = nullptr;
    unsigned int bestHeight = 0;
    for (auto &node : dag)
    {
        if (!node)
        {
            DbgAssert(node != nullptr, );
            continue;
        }

        if (node->fUncle)
            continue;

        if (node->IsTip())
        {
            // If the dagheight has increased and we're within the tailstorm_k range then set the new active tip.
            if ((node->dagHeight > bestHeight) && (node->nSequenceId < Params().GetConsensus().tailstorm_k))
            {
                activetip = node;
                bestHeight = node->dagHeight;
            }

            // Adjust for when we have multiple subblocks at the same height. We always make
            // the first one we saw the activetip.
            if (activetip && (node->nSequenceId < activetip->nSequenceId) && (node->dagHeight == activetip->dagHeight))
            {
                activetip = node;
            }
        }
    }
    return activetip;
}

// Find the hash of the tip of the dag which has the best dag height
static uint256 FindDagTip(std::set<CTreeNodeRef> &dag)
{
    CTreeNodeRef ref = FindDagTipNode(dag);
    if (ref)
        return ref->hash;
    else
        return {};
}

// Find all the ancestor nodes for this node
static std::set<CTreeNodeRef> CalculateAncestors(const CTreeNodeRef &node)
{
    std::set<CTreeNodeRef> setAncestors;
    if (!node)
        return setAncestors;
    setAncestors.insert(node->setAncestors.begin(), node->setAncestors.end());

    std::set<CTreeNodeRef> setLastAncestors = node->setAncestors;
    std::set<CTreeNodeRef> setNextAncestors;
    while (!setLastAncestors.empty())
    {
        for (auto ancestor : setLastAncestors)
        {
            setNextAncestors.insert(ancestor->setAncestors.begin(), ancestor->setAncestors.end());
        }
        setAncestors.insert(setNextAncestors.begin(), setNextAncestors.end());
        setLastAncestors = setNextAncestors;
        setNextAncestors.clear();
    }

    return setAncestors;
}

// Create or extend the conflict group for this outpoint with two competing spends.
void CDagConflictRegistry::AddGroup(const COutPoint &outpoint,
    const uint256 &txidA,
    const CTreeNodeRef &subblockA,
    const uint256 &txidB,
    const CTreeNodeRef &subblockB)
{
    auto &group = groups[outpoint];
    if (group.id == 0)
    {
        group.id = nextId++;
        group.outpoint = outpoint;
    }
    group.spenders.emplace(txidA, subblockA);
    group.spenders.emplace(txidB, subblockB);
}

// Rebuild the group from spendIndex after Unlink removes the spends that one
// subblock contributed. Drop it if fewer than two distinct txids remain.
void CDagConflictRegistry::UpdateGroup(const COutPoint &outpoint)
{
    auto itSpends = spendIndex.find(outpoint);
    std::map<uint256, CTreeNodeRef> spenders;
    if (itSpends != spendIndex.end())
    {
        for (const auto &entry : itSpends->second)
            spenders.emplace(entry.txid, entry.subblock);
    }

    if (spenders.size() < 2)
    {
        groups.erase(outpoint);
        return;
    }

    auto &group = groups[outpoint];
    if (group.id == 0)
    {
        group.id = nextId++;
        group.outpoint = outpoint;
    }
    group.spenders = std::move(spenders);
}

// Compare newNode's inputs to the spend index. True if any spend hits this
// subblock's ancestry. commit writes the index and records conflict groups.
bool CDagConflictRegistry::ScanSpends(const CTreeNodeRef &newNode, bool commit)
{
    AssertLockHeld(tailstormForest.cs_forest);
    if (!newNode || !newNode->subblock)
        return false;
    if (commit && indexed.count(newNode->hash))
        return false;

    const auto setAncestors = CalculateAncestors(newNode);
    bool hasConflict = false;

    // Spends already visited in this subblock, so a later transaction sees an earlier
    // one even on a lookup-only scan that does not write the index.
    std::map<COutPoint, std::vector<CDagSpend> > localSpends;

    for (const CTransactionRef &ptx : newNode->subblock->vtx)
    {
        if (ptx->IsCoinBase())
            continue;

        const uint256 txid = ptx->GetId();
        for (const auto &input : ptx->vin)
        {
            if (input.IsReadOnly())
                continue;
            std::vector<CDagSpend> existing;
            auto itIdx = spendIndex.find(input.prevout);
            if (itIdx != spendIndex.end())
                existing.insert(existing.end(), itIdx->second.begin(), itIdx->second.end());
            auto itLocal = localSpends.find(input.prevout);
            if (itLocal != localSpends.end())
                existing.insert(existing.end(), itLocal->second.begin(), itLocal->second.end());

            for (const auto &prior : existing)
            {
                // The same txid recorded against another subblock is one transaction
                // carried by both of them, not a competing spend.
                if (prior.txid == txid)
                    continue;

                const bool ownAncestry = (prior.subblock == newNode) || (setAncestors.count(prior.subblock) != 0);
                if (ownAncestry)
                    hasConflict = true;
                else if (commit)
                {
                    AddGroup(input.prevout, prior.txid, prior.subblock, txid, newNode);
                    LOG(DAG, "%s: recorded conflict %s vs %s outpoint %s", __func__, txid.ToString(),
                        prior.txid.ToString(), input.prevout.ToString());
                }
            }
        }

        for (const auto &input : ptx->vin)
        {
            if (!input.IsReadOnly())
                localSpends[input.prevout].push_back({txid, newNode});
        }
    }

    if (commit)
    {
        for (const auto &kv : localSpends)
        {
            auto &vec = spendIndex[kv.first];
            vec.insert(vec.end(), kv.second.begin(), kv.second.end());
            for (size_t i = 0; i < kv.second.size(); i++)
                spendsBySubblock[newNode->hash].push_back(kv.first);
        }
        indexed.insert(newNode->hash);
    }

    return hasConflict;
}

// Remove this subblock's spends from the index and update the groups they touched.
void CDagConflictRegistry::Unlink(const CTreeNodeRef &node)
{
    AssertLockHeld(tailstormForest.cs_forest);
    if (!node)
        return;
    if (!indexed.count(node->hash))
        return;

    auto itOuts = spendsBySubblock.find(node->hash);
    if (itOuts != spendsBySubblock.end())
    {
        std::set<COutPoint> touched(itOuts->second.begin(), itOuts->second.end());
        for (const auto &outpoint : touched)
        {
            auto it = spendIndex.find(outpoint);
            if (it == spendIndex.end())
                continue;
            auto &vec = it->second;
            vec.erase(std::remove_if(vec.begin(), vec.end(),
                          [&](const CDagSpend &e) { return e.subblock && e.subblock->hash == node->hash; }),
                vec.end());
            if (vec.empty())
                spendIndex.erase(it);
            UpdateGroup(outpoint);
        }
        spendsBySubblock.erase(itOuts);
    }
    indexed.erase(node->hash);
}

void CDagConflictRegistry::SetLastWinner(uint64_t id, const uint256 &txid)
{
    AssertLockHeld(tailstormForest.cs_forest);
    lastWinner[id] = txid;
}

void CDagConflictRegistry::clear()
{
    AssertLockHeld(tailstormForest.cs_forest);
    nextId = 1;
    spendIndex.clear();
    spendsBySubblock.clear();
    indexed.clear();
    groups.clear();
    lastWinner.clear();
}

bool CTailstormTree::HasAncestryDoubleSpend(const CTreeNodeRef &newNode)
{
    if (!newNode)
        return false;
    return conflictRegistry.ScanSpends(newNode, false);
}

void CTailstormTree::IndexSpends(const CTreeNodeRef &newNode)
{
    if (newNode)
        conflictRegistry.ScanSpends(newNode, true);
}

// Admit a subblock to the dag: ancestry check, insert, index its spends, then recompute
// what the dag must omit and queue this subblock's unsourced transactions for retry.
bool CTailstormTree::checkUpdateAncestryInsertIntoDag(const CTreeNodeRef &newNode,
    std::set<uint256> &excluded,
    std::set<uint256> &losers)
{
    if (HasAncestryDoubleSpend(newNode))
    {
        LOG(DAG, "%s: Rejected - subblock %s has a double spend in its ancestor tree", __func__,
            newNode->hash.ToString());
        return false;
    }

    newNode->nSequenceId = dag.size() + 1;
    DbgAssert(newNode->nSequenceId > 0, );
    newNode->fProcessed = false;
    dag.emplace(newNode->hash, newNode);

    // Record spends and conflict groups before any omit: a new double spend must open a
    // group even if this connect goes on to omit it.
    IndexSpends(newNode);

    // GetTxnExclusionSet treats the subblocks it is given as the dag: their transactions are the
    // double spend candidates and their outputs the available sources. Give it the processed
    // subblocks plus this one, not yet marked processed - the set a summary commits - so a parked
    // or overflow subblock neither wins a group nor sources a transaction here.
    std::vector<CTreeNodeRef> viewDag;
    viewDag.reserve(dag.size());
    for (const auto &mi : dag)
    {
        if (mi.second->fProcessed || mi.second == newNode)
            viewDag.push_back(mi.second);
    }
    excluded = GetTxnExclusionSet(std::move(viewDag), conflictRegistry, _pcoinsSummaryRoot, &losers);
    missingInputs.Add(newNode, excluded, losers);
    return true;
}

// Index this excluded tx against the outpoints it spends. subblock is the hash of
// a subblock containing ptx.
void CDagMissingInputIndex::Add(const CTransactionRef &ptx, const uint256 &subblock)
{
    AssertLockHeld(tailstormForest.cs_forest);
    if (!ptx || ptx->IsCoinBase())
        return;
    const uint256 txid = ptx->GetId();
    subblockByTx[txid].insert(subblock);
    if (txById.count(txid))
        return; // already indexed by another subblock; the watches are per transaction
    txById[txid] = ptx;
    for (const auto &input : ptx->vin)
    {
        waiting[input.prevout].insert(txid);
        watchedByTx[txid].push_back(input.prevout);
    }
}

// Drop one subblock of txid; the transaction leaves the index only when no subblock remains.
void CDagMissingInputIndex::Remove(const uint256 &txid, const uint256 &subblock)
{
    AssertLockHeld(tailstormForest.cs_forest);
    auto it = subblockByTx.find(txid);
    if (it == subblockByTx.end())
        return;
    it->second.erase(subblock);
    if (it->second.empty())
        Remove(txid);
}

// Drop one tx from the missing-input index.
void CDagMissingInputIndex::Remove(const uint256 &txid)
{
    AssertLockHeld(tailstormForest.cs_forest);
    auto it = watchedByTx.find(txid);
    if (it != watchedByTx.end())
    {
        for (const auto &op : it->second)
        {
            auto wit = waiting.find(op);
            if (wit == waiting.end())
                continue;
            wit->second.erase(txid);
            if (wit->second.empty())
                waiting.erase(wit);
        }
        watchedByTx.erase(it);
    }
    txById.erase(txid);
    subblockByTx.erase(txid);
}

void CDagMissingInputIndex::clear()
{
    AssertLockHeld(tailstormForest.cs_forest);
    waiting.clear();
    watchedByTx.clear();
    txById.clear();
    subblockByTx.clear();
}

// Take every tx waiting on this outpoint off the index and return them, each paired
// with the hashes of the subblocks containing it.
std::vector<std::pair<CTransactionRef, std::set<uint256> > > CDagMissingInputIndex::RemoveFor(const COutPoint &outpoint)
{
    AssertLockHeld(tailstormForest.cs_forest);
    std::vector<std::pair<CTransactionRef, std::set<uint256> > > out;
    auto it = waiting.find(outpoint);
    if (it == waiting.end())
        return out;
    std::set<uint256> ids = it->second;
    for (const auto &txid : ids)
    {
        CTransactionRef ptx;
        std::set<uint256> subblocks;
        auto txit = txById.find(txid);
        if (txit != txById.end())
            ptx = txit->second;
        auto cit = subblockByTx.find(txid);
        if (cit != subblockByTx.end())
            subblocks = cit->second;
        Remove(txid);
        if (ptx)
            out.emplace_back(ptx, std::move(subblocks));
    }
    return out;
}

// Index this node's excluded non-loser txs: they spend an input that is not included.
void CDagMissingInputIndex::Add(const CTreeNodeRef &node,
    const std::set<uint256> &excluded,
    const std::set<uint256> &dsLosers)
{
    AssertLockHeld(tailstormForest.cs_forest);
    if (!node || !node->subblock)
        return;
    for (const auto &ptx : node->subblock->vtx)
    {
        if (ptx->IsCoinBase())
            continue;
        const uint256 txid = ptx->GetId();
        // Losers stay out: a later winner flip rebuilds coins via regen.
        if (!excluded.count(txid) || dsLosers.count(txid))
            continue;
        Add(ptx, node->hash);
    }
}

// ptx is now in the coins cache. Include missing-input txs that spend its
// outputs when every input is present and they are not current losers.
void CTailstormTree::ConnectDependentTxs(const CTransactionRef &ptx,
    CCoinsViewCache &coins,
    int height,
    const std::set<uint256> &losers)
{
    if (!ptx)
        return;
    for (size_t j = 0; j < ptx->vout.size(); j++)
    {
        auto deps = missingInputs.RemoveFor(ptx->OutpointAt(j));
        for (const auto &item : deps)
        {
            const CTransactionRef &wtx = item.first;
            // The subblocks containing wtx, carried so wtx can be put back on the
            // missing-input index unchanged if it still cannot be applied.
            const std::set<uint256> &subblocks = item.second;
            if (!wtx || losers.count(wtx->GetId()))
            {
                if (wtx)
                {
                    for (const auto &subblock : subblocks)
                        missingInputs.Add(wtx, subblock);
                }
                continue;
            }
            bool ready = true;
            for (const auto &input : wtx->vin)
            {
                if (input.IsReadOnly())
                    continue;
                CoinAccessor coin(coins, input.prevout);
                if (!coin || coin->IsSpent())
                {
                    ready = false;
                    break;
                }
            }
            if (!ready)
            {
                for (const auto &subblock : subblocks)
                    missingInputs.Add(wtx, subblock);
                continue;
            }
            // ConnectBlock skips mapDagTxns, so admit uses the same checks
            // connect uses for a tx that was omitted as unsourced.
            if (!pindexSummaryRoot || !_pcoinsSummaryRoot)
            {
                LOG(DAG, "%s: dependent tx %s failed validation, not including it: missing index or coins", __func__,
                    wtx->GetId().ToString());
                continue;
            }
            {
                CValidationState depState;
                if (!CheckTxFinalAndInputs(
                        wtx, depState, coins, *_pcoinsSummaryRoot, *pindexSummaryRoot, Params(), true, true, false))
                {
                    LOG(DAG, "%s: dependent tx %s failed validation, not including it: %s", __func__,
                        wtx->GetId().ToString(), depState.GetLogString());
                    if (depState.GetRejectCode() == REJECT_CONFLICT)
                    {
                        // An input went missing or was spent since the readiness check. That is not
                        // a verdict on the transaction, so keep it waiting.
                        for (const auto &subblock : subblocks)
                            missingInputs.Add(wtx, subblock);
                        continue;
                    }
                    // Connect rejects a subblock carrying an invalid transaction at insert. This
                    // transaction escaped that check only because its input was missing then, so
                    // apply the same verdict now, for consistency with nodes that held the input at
                    // insert: mark every subblock carrying it for removal at the next regeneration.
                    //
                    // TODO: the preferred fix is to exclude the invalid transaction and keep the
                    // subblock, at insert, at regeneration and here alike, so a subblock is never
                    // rejected for its contents.
                    setBadSubblocks.insert(subblocks.begin(), subblocks.end());
                    continue;
                }
            }
            try
            {
                UpdateCoins(*wtx, coins, height);
            }
            catch (const std::logic_error &)
            {
                continue;
            }
            mapDagTxns.emplace(wtx->GetId(), wtx);
            {
                std::list<CTransactionRef> txConflicted;
                WRITELOCK(mempool.cs_txmempool);
                mempool._removeConflicts(*wtx, txConflicted);
            }
            LOG(DAG, "%s: included dependent tx %s", __func__, wtx->GetId().ToString());
            ConnectDependentTxs(wtx, coins, height, losers);
        }
    }
}

void CTailstormTree::OmitUnapplyableTxs(const CTreeNodeRef &node, const CCoinsViewCache &coins, std::set<uint256> &omit)
{
    DbgAssert(node && node->subblock, return);

    // Transactions are in canonical (id) order, not dependency order, so a child can precede its
    // parent in vtx. Accept transactions until no more can be sourced, then classify the rest.
    std::set<COutPoint> appliedOutputs;
    std::set<uint256> accepted;
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const auto &ptx : node->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;
            const uint256 txid = ptx->GetId();
            if (omit.count(txid) || accepted.count(txid))
                continue;
            // This txid was already applied from another subblock containing it.
            // Connect skips via mapDagTxns; the inputs look spent because this
            // transaction is what spent them.
            if (mapDagTxns.count(txid))
                continue;

            bool sourced = true;
            for (const auto &input : ptx->vin)
            {
                if (appliedOutputs.count(input.prevout))
                    continue;
                Coin coin;
                if (!coins.GetCoin(input.prevout, coin) || coin.IsSpent())
                {
                    sourced = false;
                    break;
                }
            }
            if (!sourced)
                continue;
            accepted.insert(txid);
            for (size_t j = 0; j < ptx->vout.size(); j++)
                appliedOutputs.insert(ptx->OutpointAt(j));
            changed = true;
        }
    }

    // Whatever remains cannot source from the view. An input that is absent may arrive later, so
    // the transaction is filed for retry; an input already spent will not.
    for (const auto &ptx : node->subblock->vtx)
    {
        if (ptx->IsCoinBase())
            continue;
        const uint256 txid = ptx->GetId();
        if (omit.count(txid) || accepted.count(txid) || mapDagTxns.count(txid))
            continue;

        bool missing = false;
        bool spent = false;
        for (const auto &input : ptx->vin)
        {
            if (appliedOutputs.count(input.prevout))
                continue;
            Coin coin;
            if (coins.GetCoin(input.prevout, coin))
            {
                if (coin.IsSpent())
                    spent = true;
            }
            else
                missing = true;
        }
        if (missing)
        {
            omit.insert(txid);
            missingInputs.Add(ptx, node->hash);
            LOG(DAG, "%s: omitting %s of %s: input not in view", __func__, txid.ToString(), node->hash.ToString());
        }
        else if (spent)
        {
            omit.insert(txid);
            LOG(DAG, "%s: omitting %s of %s: input already spent", __func__, txid.ToString(), node->hash.ToString());
        }
    }
}

std::map<CTreeNodeRef, uint32_t> GetDagScores(const std::set<CTreeNodeRef> &dagNodes)
{
    return GetDagScores(std::vector<CTreeNodeRef>(dagNodes.begin(), dagNodes.end()));
}

std::map<CTreeNodeRef, uint32_t> GetDagScores(const std::vector<CTreeNodeRef> &dagNodes)
{
    // Set the uncle score to a contant which is slightly less that the maximum
    // dag score possible. The idea here is that we want to punish uncles enough
    // to disourage miners from continuing to mine on the previous epoch, but
    // not reduce it so much that it would be beneficial for potential selfish miners.
    uint32_t nUncleScore = 1;
    if (dagNodes.size() > DEFAULT_UNCLE_SCORE_ADJUSTMENT)
        nUncleScore = dagNodes.size() - DEFAULT_UNCLE_SCORE_ADJUSTMENT;

    // Count up how many uncles there are in the dag. We'll need this to initialize
    // the scoring below.
    uint32_t nUncles = 0;
    for (const auto &node : dagNodes)
    {
        if (node->fUncle)
            nUncles++;
    }

    std::map<CTreeNodeRef, uint32_t> mapBestDagScores;
    for (const auto &node : dagNodes)
    {
        // Initialize the map entry if it doesn't already exist.
        if (node->fUncle)
        {
            mapBestDagScores.emplace(node, nUncleScore);
            continue;
        }
        else
        {
            mapBestDagScores.emplace(node, nUncles);
        }

        // Get all ancestors of this node
        std::set<CTreeNodeRef> setAllAncestors = CalculateAncestors(node);

        // initialize the new node with its initial score
        mapBestDagScores[node] += (setAllAncestors.size() + 1);

        // Now search through all the ancestors and add "1" to the score
        // of any valid ancestor.
        for (const auto &ancestor : setAllAncestors)
        {
            // Initialize the map entry if it doesn't already exist.
            mapBestDagScores.emplace(ancestor, nUncles);

            // Add the score
            mapBestDagScores[ancestor] += 1;
        }
    }

    return mapBestDagScores;
}

// Get the current best dag tip for mining on top of
uint256 GetActiveDagTip(std::set<CTreeNodeRef> &dag)
{
    uint256 activetip = FindDagTip(dag);
    if (activetip.IsNull())
    {
        return chainActive.Tip()->GetBlockHash();
    }

    return activetip;
}

// Transactions in dag that must be omitted: conflict losers and txs that
// cannot source from the chain, an included dag tx, or an included earlier
// tx in the same subblock.
std::set<uint256> GetTxnExclusionSet(const std::set<CTreeNodeRef> &dagNodes,
    const CDagConflictRegistry &registry,
    const CCoinsViewCache *pcoins,
    std::set<uint256> *pLosers)
{
    return GetTxnExclusionSet(std::vector<CTreeNodeRef>(dagNodes.begin(), dagNodes.end()), registry, pcoins, pLosers);
}

std::set<uint256> GetTxnExclusionSet(std::vector<CTreeNodeRef> nodes,
    const CDagConflictRegistry &registry,
    const CCoinsViewCache *pcoins,
    std::set<uint256> *pLosers)
{
    std::set<uint256> excluded;
    if (nodes.empty())
        return excluded;

    auto mapScores = GetDagScores(nodes);
    std::map<uint256, std::pair<uint32_t, uint256> > mapScoresByTxId;
    std::map<uint256, CTransactionRef> mapTx;
    std::map<COutPoint, uint256> createdBy;

    // Upper bound on the distinct transactions: every subblock's vtx, minus coinbases.
    std::vector<uint256> order;
    size_t nMaxTxns = 0;
    for (const auto &node : nodes)
    {
        if (node && node->subblock && !node->subblock->vtx.empty())
            nMaxTxns += node->subblock->vtx.size() - 1;
    }
    order.reserve(nMaxTxns);

    std::sort(nodes.begin(), nodes.end(),
        [](const CTreeNodeRef &a, const CTreeNodeRef &b)
        {
            if (a->nSequenceId != b->nSequenceId)
                return a->nSequenceId < b->nSequenceId;
            return a->hash < b->hash;
        });

    for (const auto &node : nodes)
    {
        // Uncles keep the parent-epoch hash; they are not in this grove's index.
        if (!node || !node->subblock || node->fUncle)
            continue;
        auto itScore = mapScores.find(node);
        if (itScore == mapScores.end())
            continue;
        const uint32_t nNodeScore = itScore->second;
        for (size_t i = 0; i < node->subblock->vtx.size(); i++)
        {
            const CTransactionRef &ptx = node->subblock->vtx[i];
            if (ptx->IsCoinBase())
                continue;
            const uint256 txid = ptx->GetId();
            auto res = mapScoresByTxId.emplace(txid, std::make_pair(nNodeScore, node->hash));
            if (!res.second)
            {
                if (nNodeScore > res.first->second.first)
                    res.first->second = std::make_pair(nNodeScore, node->hash);
                else if ((nNodeScore == res.first->second.first) && (node->hash < res.first->second.second))
                    res.first->second.second = node->hash;
            }
            if (mapTx.emplace(txid, ptx).second)
            {
                order.push_back(txid);
                for (size_t j = 0; j < ptx->vout.size(); j++)
                    createdBy.emplace(ptx->OutpointAt(j), txid);
            }
        }
    }

    std::set<uint256> losers;
    for (const auto &kv : registry.Groups())
    {
        const auto &group = kv.second;
        uint256 hashWinner;
        uint256 subblockHashWinner;
        uint32_t nWinnerScore = 0;
        uint32_t nCandidates = 0;
        for (const auto &sp : group.spenders)
        {
            auto it = mapScoresByTxId.find(sp.first);
            if (it == mapScoresByTxId.end())
                continue;
            nCandidates++;
            const uint32_t nScore = it->second.first;
            const uint256 &subblockHash = it->second.second;
            if (nScore > nWinnerScore)
            {
                nWinnerScore = nScore;
                hashWinner = sp.first;
                subblockHashWinner = subblockHash;
            }
            else if ((nScore == nWinnerScore) && (subblockHash < subblockHashWinner))
            {
                hashWinner = sp.first;
                subblockHashWinner = subblockHash;
            }
        }
        // Only one side of the group is in this dag set: no doublespend conflict here.
        if (nCandidates < 2 || hashWinner.IsNull())
            continue;

        for (const auto &sp : group.spenders)
        {
            if ((sp.first != hashWinner) && mapScoresByTxId.count(sp.first))
                losers.insert(sp.first);
        }
    }

    /*
      Why do we need to loop every time there is a change?

      At the subblock level, consider committing a tx B that spends an output before you commit its creation tx A.
      That is tx B appears in a lower score subblock than A.  The fundamental simplification here
      (which has many ramifications) is using score (which depends on subsequent events) rather than using dag
      ancestors only when the coins view is constructed.

      If we set B to be invalid because it is missing inputs (since they arrive later), then we will create a
      coins cache view that does not have B's outputs (and didn't spend its inputs).

      Newly arrived subblocks layer on top of this coins cache.  However, if a node recalculates the entire DAG
      including these newly arrived subblocks, it may end up with a different subblock ordering due to changing score,
      and if A's subblock scores before B's,  B becomes valid.

      The answer is to make transaction processing order independent of subblock order, since that is how the
      transactions will be evaluated in the final summary block anyway.

      The only effect subblock order therefore has is the resolution of doublespends and their descendants (DS), and we
      recognise that the DS that is considered valid may theoretically change so hold them provisionally.
    */
    std::set<uint256> included;
    bool changed = true;
    while (changed)
    {
        changed = false;
        for (const uint256 &txid : order)
        {
            if (losers.count(txid) || included.count(txid))
                continue;
            bool sourced = true;
            const CTransactionRef &ptx = mapTx[txid];
            for (const auto &input : ptx->vin)
            {
                auto it = createdBy.find(input.prevout);
                if (it == createdBy.end())
                {
                    // Not created in this dag: sourced only if the grove's base
                    // coins (chain at the root) still hold the outpoint.
                    if (pcoins)
                    {
                        CoinAccessor coin(*pcoins, input.prevout);
                        if (!coin || coin->IsSpent())
                            sourced = false;
                    }
                    continue;
                }
                if (!included.count(it->second))
                {
                    sourced = false;
                    break;
                }
            }
            if (sourced)
            {
                included.insert(txid);
                changed = true;
            }
        }
    }

    for (const uint256 &txid : order)
    {
        if (!included.count(txid))
            excluded.insert(txid);
    }
    if (pLosers)
        *pLosers = std::move(losers);
    return excluded;
}

// Winner per registry group over this dag: max GetDagScores, and on a tie the lowest
// hash among the subblocks containing the transaction.
static std::map<uint64_t, uint256> ComputeGroupWinners(const std::vector<CTreeNodeRef> &dagNodes,
    const CDagConflictRegistry &registry)
{
    std::map<uint64_t, uint256> winners;
    if (dagNodes.empty())
        return winners;

    auto mapScores = GetDagScores(dagNodes);
    std::map<uint256, std::pair<uint32_t, uint256> > mapScoresByTxId;
    for (const auto &node : dagNodes)
    {
        if (!node || !node->subblock || node->fUncle)
            continue;
        auto itScore = mapScores.find(node);
        if (itScore == mapScores.end())
            continue;
        const uint32_t nNodeScore = itScore->second;
        for (const auto &ptx : node->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;
            const uint256 txid = ptx->GetId();
            auto res = mapScoresByTxId.emplace(txid, std::make_pair(nNodeScore, node->hash));
            if (!res.second)
            {
                if (nNodeScore > res.first->second.first)
                    res.first->second = std::make_pair(nNodeScore, node->hash);
                else if ((nNodeScore == res.first->second.first) && (node->hash < res.first->second.second))
                    res.first->second.second = node->hash;
            }
        }
    }

    for (const auto &kv : registry.Groups())
    {
        const auto &group = kv.second;
        uint256 hashWinner;
        uint256 subblockHashWinner;
        uint32_t nWinnerScore = 0;
        uint32_t nCandidates = 0;
        for (const auto &sp : group.spenders)
        {
            auto it = mapScoresByTxId.find(sp.first);
            if (it == mapScoresByTxId.end())
                continue;
            nCandidates++;
            const uint32_t nScore = it->second.first;
            const uint256 &subblockHash = it->second.second;
            if (nScore > nWinnerScore)
            {
                nWinnerScore = nScore;
                hashWinner = sp.first;
                subblockHashWinner = subblockHash;
            }
            else if ((nScore == nWinnerScore) && (subblockHash < subblockHashWinner))
            {
                hashWinner = sp.first;
                subblockHashWinner = subblockHash;
            }
        }
        if (nCandidates >= 2 && !hashWinner.IsNull())
            winners[group.id] = hashWinner;
    }
    return winners;
}

// Same omit set, taking the tree that produced the dag rather than searching for it.
std::set<uint256> GetTxnExclusionSet(std::vector<CTreeNodeRef> dagNodes,
    const CTailstormTree &tree,
    std::set<uint256> *losers)
{
    return GetTxnExclusionSet(std::move(dagNodes), tree.conflictRegistry, tree._pcoinsSummaryRoot, losers);
}

std::set<uint256> GetTxnExclusionSet(const std::set<CTreeNodeRef> &dagNodes,
    const CTailstormTree &tree,
    std::set<uint256> *losers)
{
    return GetTxnExclusionSet(std::vector<CTreeNodeRef>(dagNodes.begin(), dagNodes.end()), tree, losers);
}

bool IsTailstormDagActivated() { return fTailstormEnabled && IsInitialSyncComplete(); }


// Tailstorm Tree

CTailstormTree::~CTailstormTree()
{
    if (view)
    {
        delete view;
        view = nullptr;
    }
}

CTreeNodeRef CTailstormTree::Insert(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    DbgAssert(newNode->subblock != nullptr, );
    if (!newNode->subblock)
        return {};

    // Add to the tree
    auto element = dag.find(newNode->hash);
    if (element == dag.end()) // We need to add it if it does not already exist
    {
        // Check if we're working on the current chaintip. If not then add to the
        // dag directly and indicate this subblock was not processed.
        auto chainTip = chainActive.Tip();
        if (pindexSummaryRoot && (chainTip != pindexSummaryRoot))
        {
            // Update the sequence id
            newNode->nSequenceId = dag.size() + 1;
            DbgAssert(newNode->nSequenceId > 0, );

            newNode->fProcessed = false;
            // A summary can reference a subblock only at its own height (a regular subblock) or one below it
            // (an uncle; uncle depth is 1). So a subblock stays usable while its grove root is within two
            // summaries of the tip - gap 1 is the tip's own epoch, gap 2 an uncle of it. Park anything older.
            const int64_t gap = (int64_t)chainTip->height() - (int64_t)pindexSummaryRoot->height();
            if (gap <= 2)
            {
                if (!checkUpdateAncestryInsertIntoDag(newNode))
                    return {};
                return newNode;
            }
            else
            {
                tailstormForest.AddSubblockOrphan(newNode);
                return {};
            }
        }

        // if we already have a full dag then don't process anymore but
        // we can add it to the dag as uprocessed so it can be used as an uncle.
        if ((dag.size() + mapUncles.size()) >= Params().GetConsensus().tailstorm_k - 1)
        {
            if (!checkUpdateAncestryInsertIntoDag(newNode))
                return {};
            return newNode;
        }

        // If any ancestor of this subblock is still unprocessed (parked as an uncle for a
        // non-tip grove) then we must not process this subblock either: doing so would
        // evaluate it against a coins cache that does not reflect the unprocessed ancestor's
        // spends (compromising double spend detection) and would create a processed node above
        // an unprocessed ancestor, the exact state Check() asserts on. This can happen when a
        // subblock arrives while a reorg is in flight and the chain tip transiently sits on
        // this grove's root. Park it unprocessed instead; it stays in the dag and, like any
        // other parked subblock, remains eligible to be adopted as an uncle.
        for (auto &ancestor : newNode->setAncestors)
        {
            if (!ancestor->fProcessed)
            {
                if (!checkUpdateAncestryInsertIntoDag(newNode))
                    return {};
                LOG(DAG, "%s(): parked subblock %s because ancestor %s is unprocessed\n", __func__,
                    newNode->hash.ToString(), ancestor->hash.ToString());
                return newNode;
            }
        }

        TxAdmissionPause txlock;

        std::set<uint256> losers;
        std::set<uint256> viewExcl;
        if (!checkUpdateAncestryInsertIntoDag(newNode, viewExcl, losers))
            return {};

        if (view)
            OmitUnapplyableTxs(newNode, *view, viewExcl);
        unsigned nOmitted = 0;
        for (const auto &ptx : newNode->subblock->vtx)
        {
            if (!ptx->IsCoinBase() && viewExcl.count(ptx->GetId()))
                nOmitted++;
        }
        if (nOmitted)
        {
            LOG(DAG, "%s: excluding %u transaction(s) of subblock %s", __func__, nOmitted, newNode->hash.ToString());
        }

        if (newNode->nSequenceId + mapUncles.size() <= Params().GetConsensus().tailstorm_k - 1)
        {
            const CChainParams &chainparams = Params();
            bool fJustCheck = false;
            bool fScriptChecks = true;
            CAmount nFees = 0;
            CBlockUndo blockundo;
            std::vector<std::pair<uint256, CDiskTxPos> > vPos;
            vPos.reserve(newNode->subblock->vtx.size());
            std::map<CGroupTokenID, CAmount> accumulatedMintages;
            std::map<CGroupTokenID, CAuth> accumulatedAuthorities;
            CValidationState state;
            // Child cache: a failed connect must not dirty the tree view.
            CCoinsViewCache upperview(view);
            bool fOK = ConnectBlockCanonicalOrdering(newNode->subblock, state, pindexSummaryRoot, upperview,
                chainparams, fJustCheck, SINGLE_THREADED, fScriptChecks, nFees, blockundo, vPos, accumulatedMintages,
                accumulatedAuthorities, &mapDagTxns, &viewExcl);
            if (!fOK)
            {
                LOG(DAG, "%s: subblock %s failed to validate: %s", __func__, newNode->hash.ToString(),
                    state.GetLogString());
                dag.erase(newNode->hash);
                conflictRegistry.Unlink(newNode);
                for (const auto &ptx : newNode->subblock->vtx)
                {
                    if (!ptx->IsCoinBase())
                        missingInputs.Remove(ptx->GetId(), newNode->hash);
                }
                return {};
            }

            for (CTransactionRef ptx : newNode->subblock->vtx)
            {
                if (ptx->IsCoinBase() || viewExcl.count(ptx->GetId()))
                    continue;
                mapDagTxns.emplace(ptx->GetId(), ptx);
            }

            bool result = upperview.Flush();
            assert(result);

            const int nHeight = pindexSummaryRoot ? pindexSummaryRoot->height() : 0;
            for (CTransactionRef ptx : newNode->subblock->vtx)
            {
                if (ptx->IsCoinBase() || viewExcl.count(ptx->GetId()))
                    continue;
                ConnectDependentTxs(ptx, *view, nHeight, losers);
            }

            std::list<CTransactionRef> txConflicted;
            {
                WRITELOCK(mempool.cs_txmempool);
                for (const auto &tx : newNode->subblock->vtx)
                {
                    if (tx->IsCoinBase())
                        continue;
                    // An excluded tx is not in the ledger, so its pool conflicts
                    // stay. They are evicted at summary connect.
                    if (viewExcl.count(tx->GetId()))
                    {
                        LOG(DAG, "%s: keeping txpool conflicts of excluded tx %s of subblock %s", __func__,
                            tx->GetId().ToString(), newNode->hash.ToString());
                        continue;
                    }
                    mempool._removeConflicts(*tx, txConflicted);
                }
            }
        }

        newNode->fProcessed = true;

        CTailstormGroveRef grove = nullptr;
        if (tailstormForest.GetGrove(*(pindexSummaryRoot->phashBlock), grove))
            tailstormForest.SetBestGroveForSummaryTip();

        cvCommitQ.notify_all();

        DbgAssert(newNode->nSequenceId > 0 && newNode->fProcessed, );
        if (newNode->fProcessed)
        {
            for (auto &ancestor : newNode->setAncestors)
            {
                DbgAssert(ancestor->fProcessed, );
            }
        }
        return newNode;
    }

    newNode = element->second;
    DbgAssert(newNode->nSequenceId > 0, ); // make sure this was inserted into a grove properly
    return newNode; // must return true because we already have it and don't want it deleted from the grove
}

// Tailstorm Grove

CTailstormGrove::CTailstormGrove(CCoinsViewCache *coinsCache)
{
    tree = std::make_shared<CTailstormTree>();

    _pcoinsTip = coinsCache;
    view = new CCoinsViewCache(coinsCache);
    view->SetBestBlock(roothash);
    assert(_pcoinsTip);
    assert(view);
}

CTailstormGrove::~CTailstormGrove()
{
    if (!tree && view)
    {
        delete view;
        view = nullptr;
    }
}

bool CTailstormGrove::InitializeTree(CTreeNodeRef newNode, CCoinsViewCache *coinsCache)
{
    AssertLockHeld(tailstormForest.cs_forest);

    assert(coinsCache);
    assert(newNode);

    if (!newNode->subblock)
        return false;

    roothash = newNode->subblock->hashPrevBlock;

    tree->_pcoinsSummaryRoot = coinsCache;
    tree->view = view;
    tree->pindexSummaryRoot = LookupBlockIndex(roothash);
    assert(tree->pindexSummaryRoot);

    nRootHeight = tree->pindexSummaryRoot->height();

    newNode = tree->Insert(newNode);
    return newNode != nullptr;
}

void CTailstormGrove::Clear()
{
    AssertLockHeld(tailstormForest.cs_forest);

    // delete all of the nodes in this grove. mapGroveNodes is
    // a subset of mapAllNodes which we can iterate over to efficiently remove
    // the nodes from mapAllNodes
    for (auto &mi : mapGroveNodes)
    {
        LOG(DAG, "%s(): Removing %s from all nodes and grove %s.\n", __func__, mi.first.ToString(),
            roothash.ToString());
        tailstormForest.mapAllNodes.erase(mi.first);
        tailstormForest.mapAllGrovesByNode.erase(mi.first);
    }
    mapGroveNodes.clear();
}

void CTailstormGrove::RecalcDagHeights()
{
    AssertLockHeld(tailstormForest.cs_forest);
    DbgAssert(txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("must have corral paused during DAG regenerate"));

    int needsHeight = 0;
    // Go through all the subblocks, setting their heights to either a sentinel value or to 1 if they have no ancestors.
    for (const auto &[hash, subblock] : mapGroveNodes)
    {
        if (subblock->setAncestors.size() > 0)
        {
            subblock->dagHeight = UINT32_MAX; // to be filled later.
            needsHeight++;
        }
        else
            subblock->dagHeight = 1; // No ancestors so this is a starting subblock
    }

    // Loop until all subblocks are labelled
    while (needsHeight)
    {
        needsHeight = 0;
        // Loop thru every subblock, assigning heights to every one if we know the height of all its ancestors
        for (const auto &[hash, subblock] : mapGroveNodes)
        {
            if (subblock->dagHeight != UINT32_MAX)
                continue; // Skip already labelled
            uint32_t maxAncestorHeight = 0;
            // Find the ancestor with the biggest height
            for (const auto &anc : subblock->setAncestors)
            {
                if (anc->dagHeight > maxAncestorHeight)
                    maxAncestorHeight = anc->dagHeight;
            }
            if (maxAncestorHeight == UINT32_MAX)
                needsHeight++; // Nope an ancestor is not yet labelled with a height
            else
                subblock->dagHeight = maxAncestorHeight + 1;
        }
    }
}

CTreeNodeRef CTailstormGrove::InsertIntoTree(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (!newNode->subblock)
        return {};

    // Check the tree and make sure we don't already have this item.
    {
        auto item = tree->dag.find(newNode->hash);
        if (item != tree->dag.end())
        {
            tailstormForest.mapNodesUnlinked.erase(newNode->hash);
            LOG(DAG, "%s(): Not inserting new node %s since treenode already exists", __func__,
                newNode->hash.ToString());
            return item->second; // We return the existing (inserted one) so it can be used instead of the new
        }
    }

    // Add the very first tree items. These are subblocks with dagHeight 1.  The first time through
    // we initialize the tree.  If there is a second subblock at dagHeight 1 then we just do a simple insert.
    bool fAddedSubblock = false;
    bool fAlreadyExists = false;
    auto setHashes = GetPrevHashes(newNode->subblock->GetBlockHeader());
    if (setHashes.size() == 1 && (*setHashes.begin()) == newNode->subblock->hashPrevBlock)
    {
        auto res = mapGroveNodes.emplace(newNode->hash, newNode);
        if (res.second)
        {
            newNode->dagHeight = 1;
            LOG(DAG, "%s(): Initialize Tree: updated dagHeight to %ld for %s", __func__, newNode->dagHeight,
                newNode->hash.ToString());

            if (tree->dag.empty())
            {
                if (!InitializeTree(newNode, _pcoinsTip))
                {
                    mapGroveNodes.erase(newNode->hash);
                    tailstormForest.AddSubblockOrphan(newNode);
                    return {};
                }
                LOG(DAG, "%s(): Initialize Tree: completed init tree for %s", __func__, newNode->hash.ToString());
            }
            else
            {
                auto tmp = tree->Insert(newNode);
                if (tmp == nullptr)
                {
                    mapGroveNodes.erase(newNode->hash);
                    tailstormForest.AddSubblockOrphan(newNode);
                    LOG(DAG, "%s(): Initialize Tree: adding orphan to unused nodes", __func__);
                    return {};
                }
                newNode = tmp;
                LOG(DAG, "%s(): Initialize Tree: completed insert into tree for %s", __func__,
                    newNode->hash.ToString());
            }

            fAddedSubblock = true;
        }
        else
        {
            fAlreadyExists = true;
        }
    }
    else // Insert all other tree items
    {
        auto res = mapGroveNodes.emplace(newNode->hash, newNode);
        if (res.second)
        {
            bool fHavePrevSubblocks = true;

            // check that we have the treenode of all prevHashes
            std::set<CTreeNodeRef> setPrevNodes;
            {
                auto setPrevHashes = GetPrevHashes(newNode->subblock->GetBlockHeader());
                for (auto prevhash : setPrevHashes)
                {
                    // Then find it in our tree
                    auto iter_tree = tree->dag.find(prevhash);
                    if (iter_tree == tree->dag.end())
                    {
                        LOG(DAG, "%s(): Did not find prevhash %s in dag for %s", __func__, prevhash.ToString(),
                            newNode->hash.ToString());
                        fHavePrevSubblocks = false;
                        break;
                        ;
                    }
                    LOG(DAG, "%s(): Found prevhash  %s in dag for %s", __func__, prevhash.ToString(),
                        newNode->hash.ToString());
                    setPrevNodes.insert(iter_tree->second);
                }
            }

            // If we have all the prev subblocks present in the dag then
            // update the ancestor information and insert this new node into the tree
            if (fHavePrevSubblocks)
            {
                if (!setPrevNodes.empty())
                {
                    uint32_t nBestDagHeight = 0;
                    newNode->AddAncestors(setPrevNodes);
                    for (auto node : setPrevNodes)
                    {
                        node->AddDescendant(newNode);
                        if (nBestDagHeight < node->dagHeight)
                            nBestDagHeight = node->dagHeight;
                    }
                    newNode->dagHeight = nBestDagHeight + 1;
                    LOG(DAG, "%s(): updated dagHeight to %ld dagsize %ld for %s", __func__, newNode->dagHeight,
                        tree->dag.size(), newNode->hash.ToString());
                }
                else
                {
                    newNode->dagHeight = 1;
                    LOG(DAG, "%s(): updated dagHeight to %ld dagsize %ld  for %s", __func__, newNode->dagHeight,
                        tree->dag.size(), newNode->hash.ToString());
                }

                // Insert new node into tree
                auto tmp = tree->Insert(newNode);
                if (tmp != nullptr)
                {
                    fAddedSubblock = true;
                    newNode = tmp;
                    LOG(DAG, "%s(): completed insert into tree dagsize %ld for %s", __func__, tree->dag.size(),
                        newNode->hash.ToString());
                }
                else // Insertion failed, so remove the bad node from the descendants
                {
                    for (auto node : setPrevNodes)
                    {
                        node->RemoveDescendant(newNode);
                    }
                }
            }
        }
        else
        {
            fAlreadyExists = true;
        }
    }

    if (fAddedSubblock)
    {
        // Notify the dagviewer of the new subblock
        ConstCBlockRef pblock = newNode->subblock;
        const CBlockHeader header = pblock->GetBlockHeader();
        uint32_t nSequenceId = newNode->nSequenceId;
        DbgAssert(nSequenceId > 0, );
        uiInterface.NotifyBlockTipDag(false, newNode->dagHeight, nSequenceId, header, true);
    }
    else
    {
        // We added it speculatively to mapGroveNodes, but the insertion into a grove didn't work.
        // So remove it now, but ONLY if the reason the insertion didn't work is that the node doesn't
        // already exist.
        if (!fAlreadyExists)
        {
            mapGroveNodes.erase(newNode->hash);
            tailstormForest.AddSubblockOrphan(newNode);
            LOG(DAG, "%s(): adding orphan to unlinked map for %d", __func__, newNode->hash.ToString());
        }
    }

    // Update the uncles map with any "new" uncles that may have arrived regardless
    // of whether we actually connected this subblocks. This is so that each side of
    // any potential fork will have a full set of uncles which are can be used to
    // determine whether a reorg should happen.
    auto mapUncles = tailstormForest.GetUncles(newNode);
    for (auto &mi : mapUncles)
    {
        if (!tree->mapUncles.count(mi.first))
        {
            tree->mapUncles.emplace(mi.first, mi.second);

            // Notify the dagviewer of any "new" uncles.
            uint32_t nDagHeight = 1; // uncles should always be viewed at this height.
            uiInterface.NotifyDagViewerUncle(
                !IsInitialSyncComplete(), nDagHeight, 0, mi.second->subblock->GetBlockHeader(), mi.second->roothash);
        }
    }

    if (fAddedSubblock)
        return newNode;
    else
        return {};
}

CTreeNodeRef CTailstormGrove::Insert(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    return InsertIntoTree(newNode);
}

bool CTailstormGrove::GetBestDag(std::set<CTreeNodeRef> &dag)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (tree->dag.empty() && tree->mapUncles.empty())
    {
        return false;
    }

    uint32_t nNumSubblocksToReturn = Params().GetConsensus().tailstorm_k - 1;

    // Insert the uncles first.
    for (auto &mi : tree->mapUncles)
    {
        const CTreeNodeRef &node = mi.second;

        // If the uncles included are too many then don't include any more. In practice
        // there would be only a handfull of uncles and so they would all get used but
        // we add this limiter here for regtest testing where k is very small.
        dag.insert(node);
        if (dag.size() == nNumSubblocksToReturn)
        {
            break; // we have all we need.
        }
    }

    // Insert nodes from the current dag.
    if (dag.size() < nNumSubblocksToReturn)
    {
        std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(tree->dag.begin(), tree->dag.end());
        std::sort(vSortedDag.begin(), vSortedDag.end(),
            [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
        for (auto it = vSortedDag.begin(); it != vSortedDag.end(); it++)
        {
            const CTreeNodeRef &node = it->second;
            // Note that a descendant subblock can never be processed if its ancestors are not processed,
            // so we do not neet to worry about having a gap in the best dag.
            if (node->fProcessed)
            {
                dag.insert(node);
                if (dag.size() == nNumSubblocksToReturn)
                    break;
            }
        }
    }

    return true;
}

bool CTailstormGrove::GetFullDag(std::set<CTreeNodeRef> &dag)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (tree->dag.empty() && tree->mapUncles.empty())
    {
        return false;
    }

    // Insert the uncles first.
    for (auto &mi : tree->mapUncles)
    {
        dag.insert(mi.second);
    }

    // Insert nodes from the current dag.
    for (auto &mi : tree->dag)
    {
        dag.insert(mi.second);
    }

    return true;
}

bool CTailstormGrove::GetBestTipHash(uint256 &tiphash)
{
    AssertLockHeld(tailstormForest.cs_forest);

    std::set<CTreeNodeRef> bestDag;
    GetBestDag(bestDag);
    tiphash = FindDagTip(bestDag);
    return true;
}

// Tailstorm Forest
void CTailstormForest::Clear()
{
    LOCK(cs_forest);
    LOG(DAG, "Clearing tailstorm forest\n");
    mapAllGrovesByNode.clear();
    mapAllNodes.clear();
    mapNodesUnlinked.clear();
    mapSummaryBlocksUnlinked.clear();
}

void CTailstormForest::ClearByHeight(const uint32_t nPruneHeight)
{
    AssertLockHeld(tailstormForest.cs_forest);

    auto iter = mapAllNodes.begin();
    while (iter != mapAllNodes.end())
    {
        ConstCBlockRef subblock = iter->second->subblock;
        if (subblock && (subblock->height <= nPruneHeight))
        {
            const uint256 &hash = iter->first;
            LOG(DAG, "pruning subblock %s at height %ld (erased from nodes, groves and orphans)\n", hash.ToString(),
                subblock->height);

            // Unwind all the grove and tree subblock and txn references
            CTailstormGroveRef grove = nullptr;
            if (GetGrove(subblock->hashPrevBlock, grove))
            {
                // Clear out the tree
                grove->tree->dag.clear();
                grove->tree->mapUncles.clear();
                grove->tree->conflictRegistry.clear();
                grove->tree->missingInputs.clear();
                grove->tree->setBadSubblocks.clear();
                grove->tree->mapDagTxns.clear();

                // Clear out the grove
                grove->mapGroveNodes.clear();
            }

            // Remove all the forest references
            mapNodesUnlinked.erase(hash);
            mapAllGrovesByNode.erase(hash);
            iter = mapAllNodes.erase(iter);
        }
        else
        {
            iter++;
        }
    }

    auto iter2 = mapSummaryBlocksUnlinked.begin();
    while (iter2 != mapSummaryBlocksUnlinked.end())
    {
        if (iter2->second->height <= nPruneHeight)
        {
            LOG(DAG, "pruning summary block %s at height %ld\n", iter2->first.ToString(), iter2->second->height);
            iter2 = mapSummaryBlocksUnlinked.erase(iter2);
        }
        else
        {
            iter2++;
        }
    }

    Check();
}

size_t CTailstormForest::Size()
{
    LOCK(cs_forest);
    return mapAllNodes.size();
}

bool CTailstormForest::Insert(const ConstCBlockRef &subblock)
{
    AssertLockNotHeld(cs_forest);

    if (!subblock)
        return false;

    LOCK(cs_forest);
    bool fOK = _Insert(subblock);
    if (fOK)
    {
        LOG(DAG, "Insert success, removing %s:%s from unlinked\n", subblock->GetHash().ToString(),
            subblock->GetHeight());
        RemoveSubblockOrphan(subblock);
    }

    Check();
    return fOK;
}

// After a successful subblock insertion: include dependent txs, then rebuild the coins
// cache if lastWinner is first set or changes on the tip grove.
void CTailstormForest::RefreshTransactionsAfterSubblockInsertion(CTailstormGroveRef grove, const CTreeNodeRef &newNode)
{
    AssertLockHeld(cs_forest);
    if (!grove || !grove->tree || !newNode)
        return;
    CTailstormTree &tree = *grove->tree;

    // Only processed nodes have coins to offer dependents. Winner rescore
    // below still runs for parked links (they change scores).
    if (tree.view && newNode->fProcessed && newNode->subblock)
    {
        std::set<CTreeNodeRef> viewDag;
        grove->GetBestDag(viewDag);
        std::set<uint256> losers;
        auto excl = GetTxnExclusionSet(viewDag, tree.conflictRegistry, tree._pcoinsSummaryRoot, &losers);
        const int nHeight = tree.pindexSummaryRoot ? tree.pindexSummaryRoot->height() : 0;
        for (const auto &ptx : newNode->subblock->vtx)
        {
            if (ptx->IsCoinBase() || excl.count(ptx->GetId()))
                continue;
            tree.ConnectDependentTxs(ptx, *tree.view, nHeight, losers);
        }
    }

    if (tree.conflictRegistry.Empty() && tree.setBadSubblocks.empty())
        return;

    // Score the processed subblocks only: that is the set the coins cache embodies and the set a
    // summary commits, so a parked subblock must not move a winner until regeneration lays it in.
    std::set<CTreeNodeRef> bestDag;
    grove->GetBestDag(bestDag);
    const auto winnersNow =
        ComputeGroupWinners(std::vector<CTreeNodeRef>(bestDag.begin(), bestDag.end()), tree.conflictRegistry);

    // The recorded winner of a group is the one the coins cache was last built against.
    // A group with no recorded winner counts as changed: the first of the two competing
    // spends is already applied to the cache, and the winner may turn out to be the other.
    bool winnersChanged = false;
    for (const auto &kv : winnersNow)
    {
        uint256 oldWinner;
        const bool hadWinner = tree.conflictRegistry.GetLastWinner(kv.first, oldWinner);
        if (!hadWinner || oldWinner != kv.second)
        {
            winnersChanged = true;
            LOG(DAG, "%s: winner group=%llu %s -> %s", __func__, (unsigned long long)kv.first,
                hadWinner ? oldWinner.ToString() : "none", kv.second.ToString());
        }
    }
    // A bad subblock also needs the rebuild, which is what removes it.
    if (!winnersChanged && tree.setBadSubblocks.empty())
        return;

    CBlockIndex *chainTip = chainActive.Tip();
    if (!chainTip || grove->roothash != chainTip->GetHash())
    {
        // Only the tip grove can regenerate, so the cache still holds the old winner.
        // Leave the recorded winners stale on purpose: recording them here would claim a
        // rebuild that never happened, and the next link able to regenerate would then see
        // no change and skip it, leaving the cache on the losing side indefinitely.
        LOG(DAG, "%s: winner changed, skip regen (grove is not the tip)", __func__);
        return;
    }

    {
        TxAdmissionPause txlock;
        ReGenerateDagData(grove);
    }
}

bool CTailstormForest::_Insert(const ConstCBlockRef &subblock)
{
    AssertLockHeld(cs_forest);

    if (!subblock)
        return false;

    // Create new node
    CTreeNodeRef newNode = MakeTreeNodeRef(subblock);
    return _Insert(newNode);
}

bool CTailstormForest::_Insert(CTreeNodeRef &newNode)
{
    // Do not change mapNodesUnlinked in this function, since it is called within a map iteration.

    // Never return true from this function but rather use fOK
    // so we can be sure to set the dag active tip after we've
    // had a successful insert of a treenode.
    bool fOK = false;
    CTailstormGroveRef grove = nullptr;

    auto subblock = newNode->subblock;
    LOG(DAG, "%s: Starting Tailstorm Forest insert %s", newNode->hash.ToString());

    // emplace the new node into the map
    auto [existingItem, inserted] = mapAllNodes.emplace(newNode->hash, newNode);
    if (!inserted)
    {
        // There already exists a node for this subblock, so use it instead
        DbgAssert(existingItem->second != nullptr, );
        newNode = existingItem->second;
    }

    // Insert elements into a new grove or an already existing grove.
    {
        // At this point we need to know if this block connects to a past
        // Summary Block or if it really is an orphan.
        auto pindex = LookupBlockIndex(subblock->hashPrevBlock);

        bool shouldCreateOrHasPrevGrove = false;
        bool fIsLinked = false;
        if (pindex && pindex->pprev)
        {
            CTailstormGroveRef dummyGrove = nullptr;
            if (pindex->height() == 0)
                shouldCreateOrHasPrevGrove = false;
            else
                shouldCreateOrHasPrevGrove = GetGrove(*(pindex->pprev->phashBlock), dummyGrove);

            // Check that the prev headers/blocks are are linked together. At this point we
            // don't need to check that we're on the right for, that check is done
            // when we call Insert() further down. If we did it here then we might
            // end up not adding unprocessed subblocks where the dag size is >= k
            // which could then end up preventing summary blocks from processing or
            // uncles from getting pulled into the next epoch.
            {
                READLOCK(cs_mapBlockIndex);
                fIsLinked = pindex->IsLinked();
            }
        }
        if (pindex && (pindex->height() == chainActive.Height()))
            shouldCreateOrHasPrevGrove = true;

        if (pindex && GetGrove(*(pindex->phashBlock), grove))
            shouldCreateOrHasPrevGrove = true;

        if (pindex && fIsLinked && shouldCreateOrHasPrevGrove)
        {
            // Make sure the height of this subblock is 1 more than the previous summary block
            if (subblock->height != pindex->height() + 1)
            {
                LOG(DAG, "%s: invalid subblock height %ld should be %ld - could not add subblock to grove", __func__,
                    subblock->height, pindex->height() + 1);
                if (inserted)
                    mapAllNodes.erase(newNode->hash);
                return false;
            }

            // Check the chainwork when the subblock gets connected to a grove
            auto expectedNbits = GetNextWorkRequired(pindex, &(*subblock), Params().GetConsensus());
            auto expectedChainWork = ArithToUint256(pindex->chainWork() + GetWorkForDifficultyBits(expectedNbits));
            if (subblock->chainWork != expectedChainWork)
            {
                LOG(DAG, "%s: invalid chainwork - could not add subblock to grove", __func__);
                if (inserted)
                    mapAllNodes.erase(newNode->hash);
                return false;
            }
            // Add new grove and/or insert subblock
            if (grove)
            {
                LOG(DAG, "%s(): adding subblock to new grove %s with a prev summary  %s", __func__,
                    newNode->hash.ToString().c_str(), subblock->hashPrevBlock.GetHex());

                auto res = mapAllGrovesByNode.emplace(newNode->hash, grove);
                if (res.second)
                {
                    auto tmp = grove->Insert(newNode);
                    if (tmp == nullptr)
                    {
                        LOG(DAG, "%s(): grove insertion failed", __func__);
                        fOK = false;
                    }
                    else
                    {
                        // The insertion must have given it a sequence id
                        DbgAssert(tmp->nSequenceId > 0, );
                        fOK = true;
                        newNode = tmp;
                    }
                }
                else
                {
                    LOG(DAG, "%s(): already exists", __func__);
                    DbgAssert(res.first->second == grove, ); // It better point to the same grove
                    auto existing = grove->mapGroveNodes.find(newNode->hash); // And the grove better have it
                    DbgAssert(existing != grove->mapGroveNodes.end(), );
                    // Use the existing one from now on
                    if (existing != grove->mapGroveNodes.end())
                        newNode = existing->second;
                    fOK = true; // it already exists so return true.
                }
            }
            else
            {
                auto res =
                    mapAllGrovesByNode.emplace(newNode->hash, MakeTailstormGroveRef(CTailstormGrove(_pcoinsTip)));
                if (res.second)
                {
                    grove = res.first->second;
                    auto tmp = grove->Insert(newNode);
                    if (tmp != nullptr)
                    {
                        LOG(DAG, "%s(): added subblock %s to new Grove with prev summary is %s", __func__,
                            newNode->hash.GetHex(), newNode->subblock->hashPrevBlock.GetHex());
                        fOK = true;
                        newNode = tmp;
                    }
                    else
                    {
                        LOG(DAG, "%s(): failed to add subblock %s to new Grove with prev summary is %s", __func__,
                            newNode->hash.GetHex(), newNode->subblock->hashPrevBlock.GetHex());
                        fOK = false;
                    }
                }
                else
                {
                    LOG(DAG, "%s: We should never get here! - failed to add new grove because it already exists",
                        __func__);
                    fOK = true;
                    DbgAssert(res.second == true, );
                }
            }
        }
        else
        {
            // It must be an orphan
            AddSubblockOrphan(newNode);

            LOG(DAG, "%s():added subblock %s to unlinked map, missing parent %s", __func__, newNode->hash.GetHex(),
                subblock->hashPrevBlock.GetHex());
            return false;
        }
    }

    if (fOK)
    {
        // We successfully added it so remove from orphans (if its there)
        RemoveSubblockOrphan(newNode->subblock);
        // Find the best treenode tip out of all the dags and update
        // the atomic pointer.
        std::set<CTreeNodeRef> dag;
        GetBestDagFor(subblock->hashPrevBlock, dag);
        CTreeNodeRef bestnode = FindDagTipNode(dag);
        if (bestnode)
        {
            SetDagActiveTip(bestnode);
            // We have enough subblocks to make a summary block so signal to check the summary block orphans
            if (dag.size() >= Params().GetConsensus().tailstorm_k - 1)
            {
                checkSummaryBlockOrphans++;
            }
        }
        RefreshTransactionsAfterSubblockInsertion(grove, newNode);
    }
    else
    {
        LOG(DAG, "%s(): forest insertion failed for subblock %s, erasing from groves", __func__,
            newNode->hash.GetHex());
        AddSubblockOrphan(newNode);
    }
    return fOK;
}

void CTailstormForest::AddSummaryBlockOrphan(ConstCBlockRef pblock)
{
    const uint256 &hash = pblock->GetHash();
    LOG(DAG, "Insert summary block orphan : %s", hash.ToString());

    LOCK(cs_forest);
    mapSummaryBlocksUnlinked.emplace(hash, pblock);
}

void CTailstormForest::RemoveSummaryBlockOrphan(ConstCBlockRef pblock)
{
    const uint256 &hash = pblock->GetHash();
    LOG(DAG, "Remove summary block orphan : %s", hash.ToString());

    LOCK(cs_forest);
    mapSummaryBlocksUnlinked.erase(hash);
}

void CTailstormForest::AddSubblockOrphan(CTreeNodeRef newNode)
{
    LOCK(cs_forest);

    // Remove it from the grove
    CTailstormGroveRef grove = nullptr;
    if (GetGrove(newNode->hash, grove) && grove->tree->dag.count(newNode->hash))
    {
        LOG(DAG, "NOT Adding subblock orphan because it is already in a grove and tree: %s", newNode->hash.ToString());
    }
    else
    {
        LOG(DAG, "Adding subblock orphan (removing from groves and adding to unlinked): %s", newNode->hash.ToString());
        for (auto &node : newNode->setAncestors)
        {
            node->RemoveDescendant(newNode);
        }
        newNode->setAncestors.clear();
        newNode->setDescendants.clear();
        newNode->fProcessed = false;
        newNode->fUncle = false;

        mapAllGrovesByNode.erase(newNode->hash);
        mapNodesUnlinked.emplace(newNode->hash, newNode);
    }
}


void CTailstormForest::RemoveSubblockOrphan(const ConstCBlockRef &pblock) { RemoveSubblockOrphan(pblock->GetHash()); }
void CTailstormForest::RemoveSubblockOrphan(const uint256 &hash)
{
    LOCK(cs_forest);
    LOG(DAG, "Remove subblock orphan: %s", hash.ToString());
    mapNodesUnlinked.erase(hash);
}


std::set<uint256> CTailstormForest::ProcessOrphans()
{
    AssertLockHeld(cs_forest);
    if (mapNodesUnlinked.empty() && mapSummaryBlocksUnlinked.empty())
    {
        return {}; // nothing to do
    }

    processingOrphans = true;
    std::set<uint256> setAllLinked;
    while (true)
    {
        // Process subblock orphans
        std::set<uint256> setLinked;

        // By grouping orphans by prevBlockHash we can prevent unnecessary repeated insert calls
        // failing by checking the prevBlockHash once in advance before processing that group.
        // This only avoids unneeded work - calling _Insert is still free to fail.
        auto canInsertForPrev = [this](const uint256 &prevhash) -> bool
        {
            auto pindex = LookupBlockIndex(prevhash);
            if (!pindex)
                return false;
            {
                READLOCK(cs_mapBlockIndex);
                if (!pindex->IsLinked())
                    return false;
            }
            if (pindex->height() == chainActive.Height())
                return true;

            CTailstormGroveRef grove = nullptr;
            if (GetGrove(*(pindex->phashBlock), grove))
                return true;
            if (pindex->pprev && (pindex->height() != 0) && GetGrove(*(pindex->pprev->phashBlock), grove))
                return true;
            return false;
        };

        // Group the orphans by the prev summary block they wait on, so a blocked group costs one
        // lookup instead of a failed insert per member.
        std::map<uint256, std::vector<CTreeNodeRef> > orphansByPrev;
        {
            std::map<uint256, CTreeNodeRef> orphans;
            orphans.swap(mapNodesUnlinked);
            for (auto &mi : orphans)
            {
                assert(mi.second->subblock);
                orphansByPrev[mi.second->subblock->hashPrevBlock].push_back(mi.second);
            }
        }

        for (auto &group : orphansByPrev)
        {
            const uint256 &prevhash = group.first;
            std::vector<CTreeNodeRef> &pending = group.second;

            if (!canInsertForPrev(prevhash))
            {
                for (auto &node : pending)
                    AddSubblockOrphan(node);
                LOG(DAG, "%s(): %d orphan(s) waiting on prev summary block %s", __func__, (int)pending.size(),
                    prevhash.ToString());
                continue;
            }

            // Inserting one member can make another insertable, so repeat until a pass links nothing.
            bool changes = true;
            while (changes && !pending.empty())
            {
                changes = false;

                std::vector<CTreeNodeRef> stillUnlinked;
                for (auto &node : pending)
                {
                    const uint256 hash = node->hash;
                    if (_Insert(node))
                    {
                        LOG(DAG, "%s(): Success: Insert of subblock orphan %s connecting to prev summary block %s",
                            __func__, hash.ToString(), prevhash.ToString());
                        setLinked.insert(hash);
                        changes = true;
                    }
                    else
                    {
                        stillUnlinked.push_back(node);
                        // If its already inserted, this is a no-op
                        AddSubblockOrphan(node);
                    }
                }

                pending.swap(stillUnlinked);
            }

            // Anything left could not be placed: park it for the next call.
            for (auto &node : pending)
                AddSubblockOrphan(node);
        }


        // Process any summary block orphans that has all subblocks present and valid in the dag.
        // NOTE: we don't add the summary block to setLinked because block processing doesn't
        // finish in this thread so we can't be sure it's linked.  It will instead get announced
        // once the block successfully connects to the blockchain.
        bool fResolvedSummaryOrphan = false;
        auto summaryBlockValidated = [](const uint256 &hash)
        {
            CBlockIndex *pindex = LookupBlockIndex(hash);
            if (!pindex)
                return false;
            READLOCK(cs_mapBlockIndex);
            return pindex->IsValid(BLOCK_VALID_SCRIPTS);
        };
        for (auto iter2 = mapSummaryBlocksUnlinked.begin(); iter2 != mapSummaryBlocksUnlinked.end();)
        {
            const uint256 hash = iter2->first;
            const ConstCBlockRef pblock = iter2->second;
            if (summaryBlockValidated(hash))
            {
                iter2 = mapSummaryBlocksUnlinked.erase(iter2);
                continue;
            }
            {
                // Get all mining hashes from the "full" dag that exists on top of
                // the prevhash of this Summary Block.  Then Check if all
                // the subblock minining hashes in the minerData of this block
                // are present in the best dag.
                std::set<CTreeNodeRef> dag;
                tailstormForest.GetFullDagFor(pblock->GetBlockHeader().hashPrevBlock, dag);
                std::set<uint256> setMiningHashes;
                for (auto &treenode : dag)
                {
                    if (treenode->subblock)
                    {
                        const auto &miningHeaderCommitment = treenode->subblock->GetMiningHeaderCommitment();
                        const auto &nonce = treenode->subblock->GetBlockHeader().nonce;
                        setMiningHashes.insert(GetMiningHash(miningHeaderCommitment, nonce));
                    }
                }

                // Check to make sure all subblocks were received before connecting the Summary Block
                auto ret = ParseSummaryBlockMinerData(pblock->minerData);
                bool fHaveSubblocks = true;
                for (const auto &pair : ret.vSubblockProofs)
                {
                    const auto &miningHeaderCommitment = pair.first;
                    const auto &nonce = pair.second;
                    uint256 mininghash = GetMiningHash(miningHeaderCommitment, nonce);

                    if (!setMiningHashes.count(mininghash))
                    {
                        fHaveSubblocks = false;
                        break;
                    }
                }

                // All subblocks are present that are needed to validate the summary block
                // so now we're able to successfully connect the summary block.
                LOG(DAG, "%s(): Processing Summary block orphan %s", __func__, iter2->first.ToString());
                if (fHaveSubblocks)
                {
                    LEAVE_CRITICAL_SECTION(cs_forest);

                    bool fProcessed = false;
                    CValidationState state;
                    // locking cs_main here prevents any other thread from starting a block validation.
                    {
                        // maintain locking order with cs_forest.
                        // TODO: not sure we really need cs_main here since the dag uses it's own
                        // scriptcheckqueue and we're working on a different coinscache but for now
                        // it's a safe thing to do.
                        LOCK(cs_main);

                        // We need to make sure we take cs_forest because in the dag we are using
                        // a single scriptcheckqueue which is governed by cs_forest, otherwise we
                        // risk some other thread using the queue before it's fully available.
                        // TODO: in the future we should come up with a more robust solution to
                        // getting access to this scriptcheckqueue.
                        LOCK(cs_forest);

                        bool forceProcessing = true;
                        fProcessed = ProcessSummaryBlock(
                            state, Params(), nullptr, pblock, forceProcessing, nullptr, SINGLE_THREADED);
                        LOG(DAG, "%s(): Done processing orphaned summary block %s with result %s", __func__,
                            hash.ToString(), fProcessed ? "success" : "failure");
                    }
                    ENTER_CRITICAL_SECTION(cs_forest);

                    // The map may have changed while cs_forest was released, so erase by hash rather than using
                    // the stale iterator. Definitively invalid entries cannot become valid by retrying, while a
                    // non-invalid failure may only be deferred and must stay queued for a later ProcessOrphans()
                    // call. ClearByHeight() eventually bounds entries that never complete.
                    if (fProcessed || state.IsInvalid() || summaryBlockValidated(hash))
                    {
                        mapSummaryBlocksUnlinked.erase(hash);
                        fResolvedSummaryOrphan = true;
                    }
                    else
                    {
                        LOG(DAG, "%s(): Retaining summary block orphan %s for another validation attempt", __func__,
                            hash.ToString());
                    }
                    break;
                }
                else
                {
                    LOG(DAG, "%s():  FAILED - do not have all subblocks for summary block: %ld", __func__, dag.size());
                    for (auto &treenode : dag)
                    {
                        assert(treenode->subblock);
                        LOG(DAG, "%s(): subblocks in failed dag: %s", __func__, treenode->hash.ToString().c_str());
                    }
                }
            }

            iter2++;
        }

        // If we connected some orphans then add to the total and
        // do another loop until we don't find anymore.
        if (!setLinked.empty())
        {
            setAllLinked.insert(setLinked.begin(), setLinked.end());
        }
        else if (!fResolvedSummaryOrphan)
        {
            break;
        }
    }

    processingOrphans = false;
    Check();
    return setAllLinked;
}

uint256 CTailstormForest::GetDagTipHash(const uint256 &hash)
{
    uint256 tiphash;
    if (GetBestTipHashFor(hash, tiphash))
        return tiphash;
    else
        return hash;
}

bool CTailstormForest::Find(const uint256 &hash, ConstCBlockRef &subblock)
{
    LOCK(cs_forest);
    std::map<uint256, CTreeNodeRef>::iterator iter = mapAllNodes.find(hash);
    if (iter != mapAllNodes.end())
    {
        subblock = iter->second->subblock;
        return true;
    }
    // Not found by subblock hash, so also look for a subblock whose mining header commitment matches.  This
    // lets peers request a subblock by mining header commitment.  This access is rare so until it becomes an issue
    // use a linear search.
    return FindByMHC(hash, subblock);
}

bool CTailstormForest::FindByMHC(const uint256 &hash, ConstCBlockRef &subblock)
{
    LOCK(cs_forest);
    for (auto &mi : mapAllNodes)
    {
        const CTreeNodeRef &node = mi.second;
        if (node->subblock && node->subblock->GetMiningHeaderCommitment() == hash)
        {
            subblock = node->subblock;
            LOG(DAG, "%s: Found subblock by mining header commitment %s, it is %s ", __func__, hash.ToString(),
                subblock->GetHash().ToString());
            return true;
        }
    }
    return false;
}


bool CTailstormForest::Contains(const uint256 &hash)
{
    LOCK(cs_forest);
    return (mapAllNodes.count(hash) != 0);
}

std::map<uint256, CTreeNode> CTailstormForest::GetAllNodes()
{
    LOCK(cs_forest);
    std::map<uint256, CTreeNode> allNodes;
    for (auto &mi : mapAllNodes)
    {
        allNodes.emplace(mi.first, *(mi.second));
    }
    return allNodes;
}

bool CTailstormForest::GetBestDagFor(const uint256 &hash, std::set<CTreeNodeRef> &dag, CTailstormTreeRef *ptree)
{
    LOCK(cs_forest);
    // LOG(DAG, "%s(): Start getbestdagfor", __func__);

    CTailstormGroveRef grove = nullptr;
    if (GetGrove(hash, grove))
    {
        if (!grove->GetBestDag(dag))
        {
            LOG(DAG, "%s(): get best dag returned false", __func__);
            return false;
        }
        if (ptree)
            *ptree = grove->tree;
        // LOG(DAG, "%s(): got grove and returning best dag", __func__);
        //  for (auto item : dag)
        //      LOG(DAG, "%s():     best dag item: %s nSequenceId: %d fProcessed: %d", __func__, item->hash.ToString(),
        //          item->nSequenceId, item->fProcessed);
        return true;
    }
    LOG(DAG, "%s(): did not get grove", __func__);

    return false;
}

bool CTailstormForest::GetFullDagFor(const uint256 &hash, std::set<CTreeNodeRef> &dag)
{
    LOCK(cs_forest);
    // LOG(DAG, "%s(): Start getbestdagfor", __func__);

    CTailstormGroveRef grove = nullptr;
    if (GetGrove(hash, grove))
    {
        if (!grove->GetFullDag(dag))
        {
            LOG(DAG, "%s(): get best dag returned false", __func__);
            return false;
        }
        // LOG(DAG, "%s(): got grove and returning best dag", __func__);
        // for (auto item : dag)
        //     LOG(DAG, "%s():     best dag item: %s nSequenceId: %d fProcessed: %d", __func__, item->hash.ToString(),
        //        item->nSequenceId, item->fProcessed);
        return true;
    }
    LOG(DAG, "%s(): did not get grove", __func__);

    return false;
}

bool CTailstormForest::GetDagForBlock(ConstCBlockRef &pblock, std::set<CTreeNodeRef> &dag, CTailstormTreeRef *ptree)
{
    LOCK(cs_forest);
    DbgAssert(IsSummaryBlock(*pblock), );

    bool fMatch = false;
    CTailstormGroveRef grove = nullptr;
    dag.clear();
    if (GetGrove(pblock->hashPrevBlock, grove))
    {
        // Check the dag tree for a full set of treenodes that match the block. If we find
        // a match then break and return a positive result. If we don't match then keep
        // looking in any other trees than may be in the grove.
        //
        // If this function returns "true" then this means that all subblocks have been correctly
        // accepted into the dag and is not also not an orphaned subblock.
        auto &tree = grove->tree;

        // Refresh the uncle set before matching. It is otherwise written only on
        // insert into this grove, and it only captures what was linked into the PARENT grove
        // at that instant. A parent-epoch subblock that links after this grove's last insert can
        // therefore never enter the set, and any summary committing it as an uncle stays unvalidatable
        // for the life of the grove.
        for (auto &mi : GetUncles(grove))
            tree->mapUncles.emplace(mi.first, mi.second);

        // get all mining hashes in the tree
        std::map<uint256, CTreeNodeRef> mapDagMiningHashes;
        for (auto &mi : tree->dag)
        {
            const CTreeNodeRef &node = mi.second;

            const auto &miningHeaderCommitment = node->subblock->GetMiningHeaderCommitment();
            const auto &nonce = node->subblock->GetBlockHeader().nonce;
            mapDagMiningHashes.emplace(GetMiningHash(miningHeaderCommitment, nonce), node);
        }
        for (auto &mi : tree->mapUncles)
        {
            const CTreeNodeRef &node = mi.second;

            const auto &miningHeaderCommitment = node->subblock->GetMiningHeaderCommitment();
            const auto &nonce = node->subblock->GetBlockHeader().nonce;
            mapDagMiningHashes.emplace(GetMiningHash(miningHeaderCommitment, nonce), node);
        }

        // does each mining hash in the block's minerDag have a corresoponding one in the dag
        auto ret = ParseSummaryBlockMinerData(pblock->minerData);
        for (const auto &pair : ret.vSubblockProofs)
        {
            const auto &miningHeaderCommitment = pair.first;
            const auto &nonce = pair.second;
            uint256 miningHash = GetMiningHash(miningHeaderCommitment, nonce);

            if (!mapDagMiningHashes.count(miningHash))
            {
                // Check failed.
                fMatch = false;
                break;
            }
            else
            {
                dag.insert(mapDagMiningHashes[miningHash]);
                fMatch = true;
            }
        }
        if (fMatch)
        {
            assert(ret.vSubblockProofs.size() == dag.size());
            if (ptree)
                *ptree = tree;
        }
        else
        {
            dag.clear();
        }
    }

    return fMatch;
}
bool CTailstormForest::GetBestTipHashFor(const uint256 &hash, uint256 &tiphash)
{
    LOCK(cs_forest);
    CTailstormGroveRef grove = nullptr;
    if (GetGrove(hash, grove))
    {
        if (!grove->GetBestTipHash(tiphash))
        {
            return false;
        }
        return true;
    }
    return false;
}

void CTailstormForest::GetDagTxns(const std::set<CTreeNodeRef> &dag, std::map<uint256, CTransactionRef> &mapDagTxns)
{
    for (auto &iter : dag)
    {
        if (!iter->subblock)
            continue;
        if (iter->fUncle)
            continue;

        for (CTransactionRef ptx : iter->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;

            mapDagTxns.emplace(ptx->GetId(), ptx);
        }
    }
    return;
}

uint32_t CTailstormForest::GetDagHeight(const uint256 &hash)
{
    LOCK(cs_forest);
    auto iter = mapAllNodes.find(hash);
    if (iter == mapAllNodes.end())
    {
        return 0;
    }
    else
    {
        return iter->second->dagHeight;
    }
}

bool CTailstormForest::GetGrove(const uint256 &hash, CTailstormGroveRef &grove)
{
    LOCK(cs_forest);
    // spammy LOG(DAG, "%s(): get grove for %s\n", __func__, hash.ToString());

    // Look for the subblock in the grove map
    auto iter = mapAllGrovesByNode.find(hash);
    if (iter != mapAllGrovesByNode.end())
    {
        grove = iter->second;
        return true;
    }

    // If the subblock is not found then lookup the grove
    // by the roothash.
    for (auto &mi : mapAllGrovesByNode)
    {
        if (hash == mi.second->roothash && !mi.second->roothash.IsNull())
        {
            grove = mi.second;
            return true;
        }
    }
    LOG(DAG, "%s(): get grove not found for %s\n", __func__, hash.ToString());
    return false;
}

uint32_t CTailstormForest::GetUnlinkedSubblocks()
{
    LOCK(cs_forest);
    uint32_t nSubblocksUnlinked = 0;
    for (auto mi : mapNodesUnlinked)
    {
        if (!IsSummaryBlock(mi.second->subblock))
            nSubblocksUnlinked++;
    }
    return nSubblocksUnlinked;
}

uint32_t CTailstormForest::GetUnlinkedSummaryBlocks()
{
    LOCK(cs_forest);
    uint32_t nSummaryUnlinked = 0;
    for (auto mi : mapNodesUnlinked)
    {
        if (IsSummaryBlock(mi.second->subblock))
            nSummaryUnlinked++;
    }
    return nSummaryUnlinked;
}

void CTailstormForest::CheckForReorg()
{
    AssertLockNotHeld(cs_forest);

    if (!fTailstormEnabled)
        return;

    // Record this request before trying the lock. An in-flight pass consumes requests that arrive
    // before its state snapshot. Requests arriving later remain pending after that iteration
    // releases cs_reorg and cause another caller, or the same thread, to run a fresh pass.
    fRecheckReorg = true;

    // Only allow one thread to run re-org at a time.
    while (fRecheckReorg)
    {
        TRY_LOCK(cs_reorg, lock);
        if (!lock)
        {
            // Another pass owns cs_reorg. This request remains pending until that pass reaches its
            // state snapshot or a thread acquires cs_reorg for a subsequent iteration.
            return;
        }
        _CheckForReorg();
    }
}

void CTailstormForest::_CheckForReorg()
{
    AssertLockHeld(cs_reorg);

    LOCK(cs_main);
    LOCK(cs_forest);

    // Requests received before this point are covered by the state snapshot below.
    // A later request leaves the flag set and causes another serialized pass.
    fRecheckReorg = false;

    CTailstormGroveRef grovetip = nullptr;
    CBlockIndex *startingChainTip = chainActive.Tip();
    CBlockIndex *pindexMostWork = startingChainTip;
    arith_uint256 nChainTipWork = startingChainTip->chainWork();
    arith_uint256 nMaxChainWork = startingChainTip->chainWork();
    auto tailstorm_k = Params().GetConsensus().tailstorm_k;


    LOG(DAG, "%s(): current chain active height %ld for %s", __func__, startingChainTip->height(),
        startingChainTip->phashBlock->ToString());
    {
        // Find all groves
        std::set<CTailstormGroveRef> setAllGroves;
        for (auto &mi : mapAllGrovesByNode)
            setAllGroves.insert(mi.second);

        // Get the chainwork of the current chainactive tip plus all the subblocks in it's dag
        //
        // The chainwork includes "all" subblocks for the full dag, so uncles as well as dag blocks.
        std::set<CTreeNodeRef> tipdag;
        GetFullDagFor(*startingChainTip->phashBlock, tipdag);
        unsigned int subblockCount = 0;
        for (auto node : tipdag)
        {
            nChainTipWork += GetWorkForDifficultyBits(node->subblock->nBits);
        }
        LOG(DAG, "%s: current active chain and dag work: %s", __func__, nChainTipWork.ToString());

        // Create a map of unlinked nodes stored by their "potential" grove node summary root hash.
        std::map<uint256, std::set<CTreeNodeRef> > mapUnlinkedGroves;
        for (auto &mi : mapNodesUnlinked)
        {
            mapUnlinkedGroves[mi.second->subblock->hashPrevBlock].insert(mi.second);
        }

        // Cycle through all the trees of each grove and find the chainWork
        for (auto &grove : setAllGroves)
        {
            auto pindexSummaryRoot = grove->tree->pindexSummaryRoot;
            {
                READLOCK(cs_mapBlockIndex);
                if (!pindexSummaryRoot || !pindexSummaryRoot->IsLinked())
                    continue;
            }

            arith_uint256 nTreeChainWork = pindexSummaryRoot->chainWork();
            std::set<CTreeNodeRef> dag;
            GetFullDagFor(grove->roothash, dag);
            // Add work for every subblock we know about, but no more than will fit in a summary block.
            // This way a fork with extra subblocks will not have more work than a fork with the correct number
            // of subblocks + a summary block.
            //
            // The cap applies per grove so the counter must be reset for each grove. Compare with
            // >= since the counter can step past the cap, and count the unlinked subblocks against
            // the same cap so they can not push a grove's work beyond what fits in a summary block.
            subblockCount = 0;
            for (auto node : dag)
            {
                nTreeChainWork += GetWorkForDifficultyBits(node->subblock->nBits);
                subblockCount++;
                if (subblockCount >= tailstorm_k - 1)
                    break;
            }
            for (auto &mi : mapUnlinkedGroves)
            {
                if (subblockCount >= tailstorm_k - 1)
                    break;
                if (mi.first == grove->roothash)
                {
                    for (auto &si : mi.second)
                    {
                        if (subblockCount >= tailstorm_k - 1)
                            break;
                        nTreeChainWork += GetWorkForDifficultyBits(si->subblock->nBits);
                        subblockCount++;
                    }
                }
            }

            if (nTreeChainWork > nMaxChainWork && nTreeChainWork > nChainTipWork)
            {
                nMaxChainWork = nTreeChainWork;
                grovetip = grove;

                if (pindexMostWork != pindexSummaryRoot)
                {
                    LOG(DAG, "%s : switching summary block: pindexMostWork %s > chaintip %s\n", __func__,
                        pindexMostWork->phashBlock->ToString(), startingChainTip->phashBlock->ToString());
                    pindexMostWork = pindexSummaryRoot;
                }
                else
                {
                    LOG(DAG, "%s : switching grove tip to: %s with work %x\n", __func__, grovetip->id().ToString(),
                        nMaxChainWork.ToString());
                }
            }
        }

        // Cycle through any groupings of unlinked nodes, grouped by their hashPrevBlock. This
        // handles the case where ALL subblocks in a grove are unlinked so the grove has not
        // yet been created.
        for (auto &mi : mapUnlinkedGroves)
        {
            CBlockIndex *pindexSummaryRoot = LookupBlockIndex(mi.first);
            {
                // Make sure we have the block data as well as all previous blocks
                // in this blocks chain.
                READLOCK(cs_mapBlockIndex);
                if (!pindexSummaryRoot || !pindexSummaryRoot->IsLinked())
                    continue;
            }

            arith_uint256 nTreeChainWork = pindexSummaryRoot->chainWork();
            // Apply the same k-1 cap to groves that exist only as unlinked sets.
            unsigned int nUnlinkedCounted = 0;
            for (auto node : mi.second)
            {
                if (nUnlinkedCounted >= tailstorm_k - 1)
                    break;
                nTreeChainWork += GetWorkForDifficultyBits(node->subblock->nBits);
                nUnlinkedCounted++;
            }
            if (nTreeChainWork > nMaxChainWork && nTreeChainWork > nChainTipWork)
            {
                nMaxChainWork = nTreeChainWork;
                pindexMostWork = pindexSummaryRoot;

                LOG(DAG, "%s : pindexMostWork %s > chaintip %s\n", __func__, pindexMostWork->phashBlock->ToString(),
                    startingChainTip->phashBlock->ToString());
            }
        }
    }

    if (!pindexMostWork)
    {
        LOG(DAG, "%s():  could not find pindexMostWork for reorg", __func__);
    }

    {
        READLOCK(cs_mapBlockIndex);
        if (pindexMostWork && !(pindexMostWork->IsLinked()))
        {
            LOG(DAG, "%s():  WARNING: block data is not fully linked for Reorg: %s", __func__,
                pindexMostWork->phashBlock->ToString());
            return;
        }
    }

    const CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);

    // Initiate reorg if there is a tree with greater work on another fork
    // AND that we haven't exceeded our reorg depth
    if (IsReorgInRange(startingChainTip, pindexFork) &&
        (((nMaxChainWork > nChainTipWork) && (startingChainTip != pindexFork)) ||
            // Or just move forward if the next summary block on this chain is ready
            ((startingChainTip == pindexFork) && (pindexMostWork->GetHeight() == startingChainTip->GetHeight() + 1))))
    {
        LOG(DAG, "%s(): Attempting to initiate a reorg from %s at height %d to %s at height %d", __func__,
            startingChainTip->phashBlock->ToString(), startingChainTip->height(),
            pindexMostWork->phashBlock->ToString(), pindexMostWork->height());

        {
            TxAdmissionPause txlock;

            if (startingChainTip != chainActive.Tip())
            {
                LOG(DAG, "%s():  failed to reorg to %s because chain active tip changed already", __func__,
                    pindexMostWork->phashBlock->ToString());
                return;
            }

            CValidationState state;
            const CChainParams &chainparams = Params();
            if (!ActivateBestChainSummaryBlocks(state, chainparams, pindexMostWork, nullptr, SINGLE_THREADED, true))
            {
                if (startingChainTip == chainActive.Tip())
                    LOG(DAG, "%s():  failed to reorg to %s", __func__, pindexMostWork->phashBlock->ToString());
                else
                    LOG(DAG, "%s():  failed to fully reorg to %s but did reorg to %s", __func__,
                        pindexMostWork->phashBlock->ToString(), chainActive.Tip()->phashBlock->ToString());
            }

            // If the starting chaintip changed then a reorg was successful.
            auto newChainTip = chainActive.Tip();
            if (startingChainTip != newChainTip)
            {
                LOG(DAG, "%s():  completed a reorg to %s", __func__, newChainTip->phashBlock->ToString());

                // Regenerate the dag data since there may be unprocessed subblocks present which were
                // added to the tree when the fork was inactive.
                CTailstormGroveRef grove;
                if (GetGrove(*newChainTip->phashBlock, grove))
                    ReGenerateDagData(grove);

                // Since all subblocks already in the dag have been processed we just need to process
                // any unlinked subblocks.
                ProcessOrphans();
            }
        }
    }

    // The tip can also settle onto a grove by the normal forward path
    // (ProcessNewBlock -> ActivateBestChain -> ConnectTip), which runs before CheckForReorg is called.
    // When it does, the reorg logic above is a no-op and the grove's parked subblocks are never re-layered.
    // Subblocks are parked (fProcessed = false) when they arrive for a grove while the active tip is
    // transiently on another fork (see CTailstormTree::Insert). Left unprocessed after the tip settles they
    // remain live descendants of the processed tips yet are excluded from the best dag, so they block each
    // processed tip out of IsTip(). The miner then finds no tip to extend and falls back to mining the root,
    // and once the total subblock count reaches tailstorm_k - 1 a summary can no longer be built and the
    // epoch livelocks. Therefore if the tip did not move above, re-layer any parked subblocks it has.
    if (startingChainTip == chainActive.Tip())
    {
        CTailstormGroveRef grove;
        if (GetGrove(*startingChainTip->phashBlock, grove) && grove->tree)
        {
            uint32_t nProcessed = 0;
            bool fHasUnprocessed = false;
            for (const auto &mi : grove->tree->dag)
            {
                if (mi.second->fProcessed)
                    nProcessed++;
                else
                    fHasUnprocessed = true;
            }

            // Only act while the epoch is genuinely short of a mineable summary. Once tailstorm_k - 1
            // subblocks are processed the dag is full and any further unprocessed subblocks are
            // overflow/uncle candidates, which a regeneration would not adopt in any case.
            if (fHasUnprocessed && (nProcessed + grove->tree->mapUncles.size() < tailstorm_k - 1))
            {
                // Stop txadmission so the subblocks are layered against the tip's coins view, matching how
                // ReGenerateDagData is invoked on the reorg path above.
                TxAdmissionPause txlock;

                // Acquiring the pause can block, so re-check that the tip has not moved underneath us.
                if (startingChainTip != chainActive.Tip())
                {
                    LOG(DAG, "%s(): not reprocessing settled grove %s because the chain active tip changed already",
                        __func__, startingChainTip->phashBlock->ToString());
                    return;
                }

                LOG(DAG, "%s(): reprocessing parked subblocks for settled tip grove %s (%d of %d processed)", __func__,
                    startingChainTip->phashBlock->ToString(), (int)nProcessed, (int)(tailstorm_k - 1));
                ReGenerateDagData(grove);

                // Regenerating may have exposed a grove for subblocks that are still unlinked.
                ProcessOrphans();
            }
        }
    }
    return;
}

void CTailstormForest::ReGenerateDagData(CTailstormGroveRef grove)
{
    LOG(DAG, "%s: Begin ReGenerateDagData for grove %s", __func__, grove->roothash.ToString());
    AssertLockHeld(cs_forest);
    DbgAssert(txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("must have corral paused during DAG regenerate"));

    auto chainparams = Params();
    auto &tree = grove->tree;

    if (tree->dag.size() == 0)
        return; // Nothing to do
    // Ensure that we only regenerate DAGs that extend the current chain tip
    CBlockIndex *chainTip = chainActive.Tip();
    auto treenode = tree->dag.begin()->second;
    DbgAssert(treenode->subblock->hashPrevBlock == chainTip->GetHash(), return);

    // The transactions applied before this rebuild; what the pool must drop is found by comparing
    // them with the applied set the rebuild leaves behind.
    const std::map<uint256, CTransactionRef> currentAppliedTxns = tree->mapDagTxns;
    while (true)
    {
        // Subblocks found to carry an invalid transaction, either before this rebuild was called or
        // by the previous pass, go first: removing them changes the selection below.
        bool fRemovedBad = false;
        while (!tree->setBadSubblocks.empty())
        {
            const uint256 hash = *tree->setBadSubblocks.begin();
            tree->setBadSubblocks.erase(tree->setBadSubblocks.begin());
            auto it = tree->dag.find(hash);
            if (it != tree->dag.end())
            {
                RemoveFromGrove(grove, it->second);
                fRemovedBad = true;
            }
        }
        if (fRemovedBad)
            grove->RecalcDagHeights();

        // Sort the dag from lowest to highest sequence id
        std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(tree->dag.begin(), tree->dag.end());
        std::sort(vSortedDag.begin(), vSortedDag.end(),
            [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
        // A removal above leaves a gap in the sequence. Number every remaining node densely,
        // so the nodes past the prefix selected below stay contiguous with it; Check() requires it.
        uint32_t nNextSequenceId = 0;
        for (auto &entry : vSortedDag)
            entry.second->nSequenceId = ++nNextSequenceId;

        // Get the exclusion set for this dag which is used to pass to connect block and allow
        // processing to continue without a missing inputs error begin returned. This exlusion set is needed
        // because mapDagTxns, which is also used to skip processing a transaction twice,
        // does not get created until the block has succesfully finished connecting.
        auto tailstorm_k = chainparams.GetConsensus().tailstorm_k;
        // Select what the summary will commit, as GetBestDag does: the uncles first, then the
        // first received subblocks up to tailstorm_k - 1 in total.
        std::set<CTreeNodeRef> setDag;
        for (const auto &mi : tree->mapUncles)
        {
            if (setDag.size() >= tailstorm_k - 1)
                break;
            setDag.insert(mi.second);
        }
        std::vector<CTreeNodeRef> kSortedDag; // the exact subblocks we will use
        kSortedDag.reserve(tailstorm_k - 1);
        for (auto it = vSortedDag.begin(); (it != vSortedDag.end()) && (setDag.size() < tailstorm_k - 1); it++)
        {
            setDag.insert(it->second);
            kSortedDag.push_back(it->second);
        }
        std::set<uint256> losers;
        std::set<uint256> setTxnExclusions = GetTxnExclusionSet(setDag, *tree, &losers);
        if (setTxnExclusions.size() > 0)
        {
            std::string logExcl = "Excluding DS transactions: ";
            for (const auto &hash : setTxnExclusions)
            {
                logExcl.append(hash.ToString());
                logExcl.append(" ");
            }
            LOG(DAG, "%s: %s\n", __func__, logExcl);
        }
        else
            LOG(DAG, "%s: No conflicts to exclude\n", __func__);

        auto badSubblock = ReGenerateDagDataForSubblocks(&(*tree), kSortedDag, setTxnExclusions, losers);
        if (!badSubblock)
        {
            // The re-file at the end of a pass retries transactions and can find one invalid; the
            // next pass removes its subblocks.
            if (tree->setBadSubblocks.empty())
                break; // It worked
            continue;
        }
        // If the regeneration did not work, delete the bad block from the dag, and loop trying the next best set
        RemoveFromGrove(grove, badSubblock);
        // RemoveFromGrove leaves a nSequenceId hole, and ReGenerateDagDataForSubblocks renumbers only the
        // tailstorm_k - 1 it selects, yet Check() aborts if a gap is found anywhere in the trees dag. So renumber here.
        // A regeneration follows, which rebuilds mapDagTxns, mapInputs for anything unprocessed that RenumberDag
        // pulls under the tailstorm_k-1 cutoff.
        RenumberDag(*(grove->tree));
        grove->RecalcDagHeights();
    }

    // Drop from the pool everything that depended on a transaction the rebuilt view contradicts:
    // one that was applied before, is not applied now, and whose input is now spent by another
    // applied transaction. That is a double spend loser under its winner, or a displaced
    // transaction whose rival is now applied; neither can be applied again while the rival
    // stands. Their previously applied descendants went with them, so walk those too. A
    // transaction that left the view with no rival is left alone: it may be applied again.
    std::vector<CTransactionRef> dropped;
    {
        // Which previously applied transaction spent each output.
        std::map<COutPoint, CTransactionRef> spentBy;
        for (const auto &kv : currentAppliedTxns)
        {
            for (const CTxIn &txin : kv.second->vin)
                spentBy.emplace(txin.prevout, kv.second);
        }
        // Which applied transaction spends each output now.
        std::map<COutPoint, uint256> spentNow;
        for (const auto &kv : tree->mapDagTxns)
        {
            for (const CTxIn &txin : kv.second->vin)
                spentNow.emplace(txin.prevout, kv.first);
        }
        // Seed with every previously applied transaction that is no longer applied and has an
        // input now spent by another applied transaction.
        std::set<uint256> seen;
        for (const auto &kv : currentAppliedTxns)
        {
            if (tree->mapDagTxns.count(kv.first))
                continue;
            bool fConflicted = false;
            for (const CTxIn &txin : kv.second->vin)
            {
                const auto it = spentNow.find(txin.prevout);
                if (it != spentNow.end() && it->second != kv.first)
                {
                    fConflicted = true;
                    break;
                }
            }
            if (fConflicted && seen.insert(kv.first).second)
                dropped.push_back(kv.second);
        }
        // Breadth-first over the vector: each entry's outputs add their spender to the back, and the
        // walk reaches that spender in turn. Only previously applied spenders are in the index.
        for (size_t i = 0; i < dropped.size(); i++)
        {
            const CTransactionRef ptx = dropped[i];
            for (size_t j = 0; j < ptx->vout.size(); j++)
            {
                const auto it = spentBy.find(ptx->OutpointAt(j));
                if (it != spentBy.end() && seen.insert(it->second->GetId()).second)
                    dropped.push_back(it->second);
            }
        }
    }
    if (!dropped.empty())
    {
        std::list<CTransactionRef> txConflicted;
        WRITELOCK(mempool.cs_txmempool);
        std::string logDropped;
        for (const auto &ptx : dropped)
        {
            mempool._removeRecursive(*ptx, txConflicted);
            logDropped += ptx->GetId().ToString() + " ";
        }
        std::string logRemoved;
        for (const auto &ptx : txConflicted)
            logRemoved += ptx->GetId().ToString() + " ";
        LOG(DAG,
            "%s: dropped %u applied transaction(s) conflicted by the rebuilt view: %sremoved %u txpool entries: %s",
            __func__, (unsigned)dropped.size(), logDropped, (unsigned)txConflicted.size(), logRemoved);
    }

    // Record the winner each group settled on; the insert path regenerates when a later
    // subblock moves one.
    if (!tree->conflictRegistry.Empty())
    {
        std::set<CTreeNodeRef> rebuiltDag;
        grove->GetBestDag(rebuiltDag);
        const auto winners = ComputeGroupWinners(
            std::vector<CTreeNodeRef>(rebuiltDag.begin(), rebuiltDag.end()), tree->conflictRegistry);
        for (const auto &kv : winners)
            tree->conflictRegistry.SetLastWinner(kv.first, kv.second);
    }

    SetBestGroveForSummaryTip();
}

CTreeNodeRef CTailstormForest::ReGenerateDagDataForSubblocks(CTailstormTree *tree,
    std::vector<CTreeNodeRef> &sortedDag,
    const std::set<uint256> &setTxnExclusions,
    const std::set<uint256> &losers)
{
    AssertLockHeld(cs_forest);
    DbgAssert(txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("must have corral paused during DAG regenerate"));

    auto chainparams = Params();

    bool fJustCheck = false;
    bool fParallel = false;
    bool fScriptChecks = true;

    tree->mapDagTxns.clear();
    tree->view->Clear();
    tree->missingInputs.clear();
    // Only the nodes this rebuild connects are in the view. A node outside the
    // selected prefix may have been processed by an earlier rebuild.
    for (auto &mi : tree->dag)
        mi.second->fProcessed = false;

    // Sequence order can layer a child before its parent. Omit txs that
    // cannot spend against the cache so far; heal them after every node
    // is layered. A failed connect uses a child cache so the tree view
    // stays clean.
    std::set<uint256> omit = setTxnExclusions;
    uint32_t nSequenceId = 0;
    for (auto it = sortedDag.begin(); it != sortedDag.end(); it++)
    {
        nSequenceId++;
        const CTreeNodeRef &treenode = *it;

        // Numbers only the tailstorm_k - 1 subblocks passed in, never the rest of the dag.
        // RenumberDag owns the full 1..N and Check() asserts;
        treenode->nSequenceId = nSequenceId;

        CAmount nFees = 0;
        CBlockUndo blockundo;
        std::vector<std::pair<uint256, CDiskTxPos> > vPos;
        vPos.reserve(treenode->subblock->vtx.size());
        std::map<CGroupTokenID, CAmount> accumulatedMintages;
        std::map<CGroupTokenID, CAuth> accumulatedAuthorities;

        tree->OmitUnapplyableTxs(treenode, *tree->view, omit);

        LOG(DAG, "%s: Layering subblock %s into DAG view.  Block details: %s", __func__,
            treenode->subblock->GetHash().ToString(), treenode->subblock->ToString());
        CValidationState state;
        CCoinsViewCache layer(tree->view);
        bool fOK = ConnectBlockCanonicalOrdering(treenode->subblock, state, tree->pindexSummaryRoot, layer, chainparams,
            fJustCheck, fParallel, fScriptChecks, nFees, blockundo, vPos, accumulatedMintages, accumulatedAuthorities,
            &tree->mapDagTxns, &omit);
        if (fOK)
        {
            bool flushed = layer.Flush();
            assert(flushed);
            for (CTransactionRef ptx : treenode->subblock->vtx)
            {
                if (ptx->IsCoinBase() || omit.count(ptx->GetId()))
                    continue;
                tree->mapDagTxns.emplace(ptx->GetId(), ptx);
            }

            treenode->fProcessed = true;
            treenode->nSequenceId = nSequenceId;
        }
        else
        {
            nSequenceId--;
            treenode->fProcessed = false;
            LOG(DAG, "%s(): While regenerating dag, subblock is bad: %s", __func__, treenode->hash.ToString());
            return treenode;
        }
    }

    // Re-index omitted non-losers, then include any that can now source.
    const int nHeight = tree->pindexSummaryRoot ? tree->pindexSummaryRoot->height() : 0;
    for (const auto &treenode : sortedDag)
    {
        if (!treenode || !treenode->subblock)
            continue;
        tree->missingInputs.Add(treenode, omit, losers);
        for (const auto &ptx : treenode->subblock->vtx)
        {
            if (ptx->IsCoinBase() || omit.count(ptx->GetId()))
                continue;
            tree->ConnectDependentTxs(ptx, *tree->view, nHeight, losers);
        }
    }
    return CTreeNodeRef();
}

void CTailstormForest::RenumberDag(CTailstormTree &tree)
{
    AssertLockHeld(cs_forest);

    std::vector<CTreeNodeRef> vSortedDag;
    vSortedDag.reserve(tree.dag.size());
    for (auto &mi : tree.dag)
        vSortedDag.push_back(mi.second);

    // Sort on the current ids, so relative order - the arrival order the id records - is kept.
    // The ids are unique here: they are handed out as dag.size() + 1 over a dense dag, and this
    // function is what keeps it dense, so no two nodes can hold the same value.
    std::sort(vSortedDag.begin(), vSortedDag.end(),
        [](const CTreeNodeRef &a, const CTreeNodeRef &b) { return a->nSequenceId < b->nSequenceId; });

    uint32_t nSequenceId = 0;
    uint32_t nPrevOldId = 0;
    for (auto &node : vSortedDag)
    {
        const uint32_t nOldId = node->nSequenceId;
        node->nSequenceId = ++nSequenceId;

        // A hole moves every subblock above it down, and those ids arrive still one apart. Only
        // the first id after a hole breaks that run, so it is the only one worth a line. That
        // gives one line per hole rather than one per subblock, and a second line in the same
        // pass means a second hole.
        if ((nOldId != nSequenceId) && (nOldId != nPrevOldId + 1))
        {
            LOG(DAG, "%s: dag %d subblocks, nSequenceId %d -> %d at %s", __func__, (int)vSortedDag.size(), nOldId,
                nSequenceId, node->hash.ToString());
        }
        nPrevOldId = nOldId;
    }
}

void CTailstormForest::RemoveFromGrove(CTailstormGroveRef grove, CTreeNodeRef subblock)
{
    LOCK(cs_forest);
    LOG(DAG, "%s: Expunging subblock: %s", __func__, subblock->hash.ToString());
    CTailstormTree &tree = *(grove->tree);
    tree.dag.erase(subblock->hash);
    tree.mapUncles.erase(subblock->hash);
    grove->mapGroveNodes.erase(subblock->hash);
    mapAllGrovesByNode.erase(subblock->hash);
    mapAllNodes.erase(subblock->hash);
    RemoveSubblockOrphan(subblock->hash);

    tree.conflictRegistry.Unlink(subblock);
    if (subblock->subblock)
    {
        for (const auto &ptx : subblock->subblock->vtx)
        {
            if (!ptx->IsCoinBase())
                tree.missingInputs.Remove(ptx->GetId(), subblock->hash);
        }
    }

    std::set<CTreeNodeRef> descendantCopy = subblock->setDescendants;
    // Recursively remove any child subblocks, I have to make a copy because the child will remove itself from
    // my descendant list (modifying the list while I have an iterator on it).
    for (const auto &descendant : descendantCopy)
    {
        RemoveFromGrove(grove, descendant);
    }
    // Remove me from my ancestors
    for (const auto &ancestor : subblock->setAncestors)
    {
        ancestor->RemoveDescendant(subblock);
    }
    // Be absolutely sure these smart pointers are cleared since this subblock will be disconnected from the
    // reachable graph and do not want circular references to prevent reclaiming memory.
    subblock->setAncestors.clear();
    subblock->setDescendants.clear();
}


void CTailstormForest::SetBestGroveForSummaryTip()
{
    AssertLockHeld(tailstormForest.cs_forest);
    DbgAssert(
        txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("Do not have corral pause during activate best tree"));

    auto summaryTip = chainActive.Tip();
    if (!summaryTip)
        return;

    CTailstormGroveRef grove = nullptr;
    if (!GetGrove(*summaryTip->phashBlock, grove))
    {
        _ClearBestGrove();
    }
    else
    {
        bestGrove = grove;
    }

    return;
}

void CTailstormForest::SetDagActiveTip(CTreeNodeRef treenode)
{
    std::atomic_store(&pDagActiveTip, treenode);
    forceTemplateRecalc = true;
}

uint256 CTailstormForest::GetDagActiveTip()
{
    CTreeNodeRef ref = std::atomic_load(&pDagActiveTip);
    if (ref)
    {
        if (ref->hash.IsNull())
            return chainActive.Tip()->GetBlockHash();
        else
            return ref->hash;
    }
    return chainActive.Tip()->GetBlockHash();
}

std::map<uint256, CTreeNodeRef> CTailstormForest::GetUncles(CTreeNodeRef treenode)
{
    CTailstormGroveRef grove = nullptr;
    if (!GetGrove(treenode->hash, grove))
        return {};
    return GetUncles(grove);
}

std::map<uint256, CTreeNodeRef> CTailstormForest::GetUncles(CTailstormGroveRef grove)
{
    std::map<uint256, CTreeNodeRef> mapUncles;

    // Find and include subblock uncles
    if (grove)
    {
        auto pblock = ReadBlockFromDisk(grove->tree->pindexSummaryRoot, Params().GetConsensus());
        if (!pblock)
        {
            LOG(DAG, "%s():  failed to read block from disk to %s", __func__,
                grove->tree->pindexSummaryRoot->phashBlock->ToString());
            return {};
        }

        // First we need the "full" set of dag blocks from the prev summary block (A) to compare
        // to our current summary block (B). Then we can determine which subblocks in the previous dag (A)
        // were not found in our block (B) and which are therefore orphans (uncles).
        std::set<uint256> setSummaryBlockMiningHashes;
        auto ret = ParseSummaryBlockMinerData(pblock->minerData);
        for (const auto &pair : ret.vSubblockProofs)
        {
            const auto &miningHeaderCommitment = pair.first;
            const auto &nonce = pair.second;
            uint256 miningHash = GetMiningHash(miningHeaderCommitment, nonce);
            setSummaryBlockMiningHashes.insert(miningHash);
        }

        std::set<CTreeNodeRef> prevDag;
        GetFullDagFor(pblock->hashPrevBlock, prevDag);
        for (auto prevnode : prevDag)
        {
            // Ignoring any uncles in the previous epoch, check whether the node's mininghash
            // exists in the prev summary block
            if (prevnode->fUncle)
                continue;

            const auto &miningHeaderCommitment = prevnode->subblock->GetMiningHeaderCommitment();
            const auto &nonce = prevnode->subblock->GetBlockHeader().nonce;
            auto miningHash = GetMiningHash(miningHeaderCommitment, nonce);

            // if the subblock is not in the summary block then it's an orphan
            if (!setSummaryBlockMiningHashes.count(miningHash))
            {
                // We need to create a copy of the pointer data and modify the roothash
                CTreeNodeRef orphan = MakeTreeNodeRef(*prevnode);
                orphan->roothash = grove->roothash;
                orphan->fUncle = true;
                mapUncles.emplace(orphan->hash, orphan);
            }
        }
    }

    // Find and include summary block uncles

    return mapUncles;
}

bool CTailstormForest::Remove(uint256 &hash)
{
    LOCK(cs_forest);

    std::map<uint256, CTreeNodeRef>::iterator iter = mapAllNodes.find(hash);
    if (iter != mapAllNodes.end())
    {
        CTailstormGroveRef grove = nullptr;
        if (GetGrove(hash, grove))
        {
            RemoveFromGrove(grove, iter->second);
            return true;
        }
    }

    return false;
}

void CTailstormForest::Check()
{
    if (Params().NetworkIDString() != CBaseChainParams::STORMTEST)
    {
        if (nCheckFrequency == 0)
            return;

        if (GetRand(std::numeric_limits<uint32_t>::max()) >= nCheckFrequency)
            return;
    }

    LOCK(cs_forest);
    // If we are in the middle of retrying orphans, maps will be inconsistent because subblocks could be on both
    // the mapNodesUnlinked and mapAllGrovesByNode data structures.
    // We Check() when orphan processing is done, so skip checks now.
    if (processingOrphans)
        return;

    assert(_pcoinsTip);

    // Check summary blocks unlinked should never have a grove created for it yet.
    for (auto &mi : mapSummaryBlocksUnlinked)
    {
        CTailstormGroveRef grove = nullptr;
        if (GetGrove(mi.first, grove))
        {
            std::set<CTreeNodeRef> setDag;
            if (tailstormForest.GetDagForBlock(mi.second, setDag))
            {
                assert("summary block in unlinked when it should not be");
            }
        }
    }

    // Count up forest nodes and check that all nodes equal grove nodes plus unlinked.
    if (mapAllNodes.size() != mapAllGrovesByNode.size() + mapNodesUnlinked.size())
    {
        LOG(DAG, " failed - mapallnodes %ld mapallgrovenodes %ld mapnodesunlinked %ld\n", mapAllNodes.size(),
            mapAllGrovesByNode.size(), mapNodesUnlinked.size());

        LOG(DAG, "map all nodes: \n");
        for (auto it : mapAllNodes)
        {
            std::string groveStr = "in groves";
            if (mapAllGrovesByNode.find(it.first) == mapAllGrovesByNode.end())
                groveStr = "NOT in groves";
            std::string unlinkedStr = "in unlinked";
            if (mapNodesUnlinked.find(it.first) == mapNodesUnlinked.end())
                unlinkedStr = "NOT in unlinked";
            LOG(DAG, "   %s:  %s, %s\n", it.first.ToString(), groveStr, unlinkedStr);
        }
        LOG(DAG, "map all groves: \n");
        for (auto it : mapAllGrovesByNode)
        {
            std::string allStr = "in all nodes";
            if (mapAllNodes.find(it.first) == mapAllNodes.end())
                allStr = "NOT in all nodes";
            std::string unlinkedStr = "in unlinked";
            if (mapNodesUnlinked.find(it.first) == mapNodesUnlinked.end())
                unlinkedStr = "NOT in unlinked";
            LOG(DAG, "   %s:  %s, %s\n", it.first.ToString(), allStr, unlinkedStr);
        }
        LOG(DAG, "map nodes unlinked: \n");
        for (auto it : mapNodesUnlinked)
        {
            std::string allStr = "in all nodes";
            if (mapAllNodes.find(it.first) == mapAllNodes.end())
                allStr = "NOT in all nodes";
            std::string groveStr = "in groves";
            if (mapAllGrovesByNode.find(it.first) == mapAllGrovesByNode.end())
                groveStr = "NOT in groves";
            LOG(DAG, "   %s:  %s, %s\n", it.first.ToString(), allStr, groveStr);
        }
    }
    DbgAssert(mapAllNodes.size() == mapAllGrovesByNode.size() + mapNodesUnlinked.size(), );

    // Find all unique groves
    std::set<CTailstormGroveRef> setGroves;
    for (auto &mi : mapAllGrovesByNode)
    {
        setGroves.insert(mi.second);
    }

    // Make sure no two groves share the same summary root
    auto setGrovesCopy = setGroves;
    for (auto &grove : setGroves)
    {
        setGrovesCopy.erase(grove);
        for (auto &groveCopy : setGrovesCopy)
        {
            assert(grove->roothash != groveCopy->roothash);
        }
    }

    // Count up nodes (within each grove) and check that all forest nodes equal grove nodes plus unlinked.
    std::set<std::shared_ptr<CTailstormTree> > setAllTrees;
    uint32_t nAllGroveNodes = 0;
    std::set<uint256> setNodesInGrove;
    for (auto &grove : setGroves)
    {
        nAllGroveNodes += grove->mapGroveNodes.size();
        assert(grove->tree);
        assert(grove->_pcoinsTip);
        assert(grove->view);
        assert(!grove->roothash.IsNull());
        assert(grove->nRootHeight > 0);

        setAllTrees.insert(grove->tree);

        for (auto &groveNode : grove->mapGroveNodes)
        {
            auto gn = setNodesInGrove.find(groveNode.first);
            if (gn != setNodesInGrove.end())
            {
                LOG(DAG, "Node in multiple groves: %s", groveNode.first.ToString());
            }
            setNodesInGrove.insert(groveNode.first);
        }

        // make sure all tree entries also have an entry in mapGroveNodes.
        // And also make sure that processed tree nodes have ancestors that are also processed.
        auto &tree = grove->tree;
        {
            for (auto &mi : tree->dag)
            {
                assert(grove->mapGroveNodes.count(mi.first));
                assert(grove->mapGroveNodes[mi.first] == mi.second);

                if (mi.second->fProcessed)
                {
                    for (auto &ancestor : mi.second->setAncestors)
                    {
                        assert(ancestor->fProcessed);
                    }
                }
            }
        }
    }

    if (mapAllNodes.size() != nAllGroveNodes + mapNodesUnlinked.size())
    {
        for (auto &grove : setGroves)
        {
            for (auto &groveNode : grove->mapGroveNodes)
            {
                auto unlinkedNode = mapNodesUnlinked.find(groveNode.first);
                if (unlinkedNode != mapNodesUnlinked.end())
                {
                    LOG(DAG,
                        "ERROR: Grove node is in unlinked (orphan) list: %s mapAllNodes: %ld nAllGroveNodes: %ld "
                        "mapNodesUnlinked: %ld",
                        groveNode.first.ToString(), mapAllNodes.size(), nAllGroveNodes, mapNodesUnlinked.size());
                }
                auto allNodesNode = mapAllNodes.find(groveNode.first);
                if (allNodesNode == mapAllNodes.end())
                {
                    LOG(DAG, "ERROR: Grove node is NOT in allnodes list: %s", groveNode.first.ToString());
                }
            }
        }
    }
    assert(mapAllNodes.size() == nAllGroveNodes + mapNodesUnlinked.size());

    // Count up all nodes (within each tree) and check that all forest nodes equals tree nodes plus unlinked.
    std::set<CTreeNodeRef> setAllTreeNodes;
    for (auto &tree : setAllTrees)
    {
        uint64_t nTreeTxnCount = 0;
        for (auto &mi : tree->dag)
        {
            setAllTreeNodes.insert(mi.second);

            // Check hash
            assert(mi.first == mi.second->hash);

            // Don't include txn count if not processed.
            if (!mi.second->fProcessed)
                continue;

            // Check that treenode is not also an uncle
            assert(!tree->mapUncles.count(mi.first));
            assert(!mi.second->fUncle);

            // Check tree mapDagTxns is correctly reflecting the tree
            nTreeTxnCount += mi.second->subblock->vtx.size() - 1;
        }
        assert(nTreeTxnCount >= tree->mapDagTxns.size());

        // Check uncles map contains only uncles
        for (auto &mi : tree->mapUncles)
        {
            assert(mi.second->fUncle);
        }

        // Check sequence ids are contiguous and match the total number of nodes
        {
            std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(tree->dag.begin(), tree->dag.end());
            std::sort(vSortedDag.begin(), vSortedDag.end(),
                [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
            for (uint32_t i = 0; i < vSortedDag.size(); i++)
                assert(vSortedDag[i].second->nSequenceId == i + 1);
        }

        // Check tree dag heights, ancestors and descendants
        {
            std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDagHeights(tree->dag.begin(), tree->dag.end());
            std::sort(vSortedDagHeights.begin(), vSortedDagHeights.end(),
                [](const auto &a, const auto &b) { return a.second->dagHeight < b.second->dagHeight; });

            for (uint32_t i = 0; i < vSortedDagHeights.size(); i++)
            {
                CTreeNodeRef node = vSortedDagHeights[i].second;
                auto setPrevHashes = GetPrevHashes(node->subblock->GetBlockHeader());
                assert(!setPrevHashes.empty());

                if (i == 0)
                    assert(node->dagHeight == 1);

                if (node->dagHeight == 1)
                {
                    assert(node->setAncestors.empty());
                    assert(setPrevHashes.size() == 1);
                    assert(setPrevHashes.count(node->subblock->hashPrevBlock));
                }
                else
                {
                    for (auto &ancestor : node->setAncestors)
                    {
                        assert(ancestor->dagHeight <= node->dagHeight - 1);
                        assert(setPrevHashes.count(ancestor->hash));
                    }
                    for (auto &desc : node->setDescendants)
                    {
                        auto setDescHashes = GetPrevHashes(desc->subblock->GetBlockHeader());
                        assert(setDescHashes.count(node->hash));
                    }
                }
            }
        }
    }
    assert(mapAllNodes.size() == setAllTreeNodes.size() + mapNodesUnlinked.size());


    // Check minerData versions
    for (auto &mi : mapNodesUnlinked)
    {
        assert(GetMinerDataVersion(mi.second->subblock->minerData) == DEFAULT_MINER_DATA_SUBBLOCK_VERSION);
    }
    for (auto &mi : mapSummaryBlocksUnlinked)
    {
        assert(GetMinerDataVersion(mi.second->minerData) == DEFAULT_MINER_DATA_SUMMARYBLOCK_VERSION);
    }
}

//! Get DAG internal information for display and debugging
UniValue CTailstormForest::GetInternals(UniValue &info)
{
    AssertLockHeld(cs_forest);

    auto unlinked = UniValue(UniValue::VOBJ);
    for (auto &mnu : mapNodesUnlinked)
    {
        auto uv = UniValue(UniValue::VOBJ);
        auto &treenode = mnu.second;
        auto &blk = treenode->subblock;
        uv.pushKV(std::string("processed"), treenode->fProcessed);
        uv.pushKV(std::string("roothash"), treenode->roothash.ToString());
        uv.pushKV(
            std::string("prevSummaryBlock"), std::to_string(blk->height - 1) + ":" + blk->hashPrevBlock.ToString());
        uv.pushKV("txCount", (uint64_t)blk->txCount);
        uv.pushKV("height", (uint64_t)blk->height);
        auto setHashes = GetSubblockHashes(blk->GetBlockHeader());
        auto dependsOn = UniValue(UniValue::VARR);
        for (const auto &dep : setHashes)
        {
            std::string haveIt = (mapAllNodes.count(dep) != 0) ? "x" : "?";
            dependsOn.push_back(haveIt + dep.ToString());
        }
        uv.pushKV("dependsOn", dependsOn);
        unlinked.pushKV(treenode->hash.ToString(), uv);
    }
    info.pushKV("unlinked_subblock_list", unlinked);

    auto subblockToGrove = UniValue(UniValue::VOBJ);
    for (auto &mnu : mapAllGrovesByNode)
    {
        subblockToGrove.pushKV(
            mnu.first.ToString(), std::to_string(mnu.second->nRootHeight) + ":" + mnu.second->roothash.ToString());
    }
    info.pushKV("subblock_to_grove_summaryblock", subblockToGrove);

    // Get all the uncles for each grove and printout by summary root.
    {
        std::set<CTailstormGroveRef> setGroves;
        for (auto &mi : mapAllGrovesByNode)
        {
            setGroves.insert(mi.second);
        }
        auto unclesToGrove = UniValue(UniValue::VOBJ);
        for (auto &grove : setGroves)
        {
            for (auto &mi : grove->tree->mapUncles)
            {
                unclesToGrove.pushKV(
                    mi.first.ToString(), std::to_string(grove->nRootHeight) + ":" + grove->roothash.ToString());
            }
        }
        info.pushKV("uncles_to_grove_summaryblock", unclesToGrove);
    }

    CBlockIndex *tip = chainActive.Tip();
    std::set<CTreeNodeRef> setBestDag;
    tailstormForest.GetBestDagFor(tip->GetBlockHash(), setBestDag);

    // Grab a snapshot of this list because its small and we cannot hold mapBlockIndex through tailstorm operations
    std::set<CBlockIndex *, CBlockIndexWorkComparator> bicSnap;
    {
        READLOCK(cs_mapBlockIndex);
        bicSnap = setBlockIndexCandidates;
    }
    auto summaryToMissing = UniValue(UniValue::VOBJ);
    for (const auto &candidate : bicSnap)
    {
        const auto &hdr = candidate->GetBlockHeader();
        auto mdata = ParseSummaryBlockMinerData(hdr.minerData);

        std::vector<CInv> vGetData;
        for (const auto &pair : mdata.vSubblockProofs)
        {
            const uint256 &miningHeaderCommitment = pair.first;
            ConstCBlockRef subblock;
            // Note, this will not work until tailstormForest.Find is upgraded to also accept
            // miningHeaderCommitments.
            if (!tailstormForest.Find(miningHeaderCommitment, subblock))
            {
                vGetData.emplace_back(MSG_BLOCK, miningHeaderCommitment);
            }
        }

        auto missing = UniValue(UniValue::VARR);
        if (!vGetData.empty())
        {
            for (const auto &mobj : vGetData)
                missing.push_back(mobj.ToString());
        }
        summaryToMissing.pushKV(std::to_string(candidate->height()) + ":" + candidate->GetHash().ToString(), missing);
    }
    info.pushKV("missing_subblocks_by_mhc", summaryToMissing);
    return info;
}
