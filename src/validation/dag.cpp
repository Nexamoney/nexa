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
#include <functional>

extern bool IsInitialBlockDownload();
extern CCriticalSection cs_main;
extern std::atomic<bool> forceTemplateRecalc;

class CValidationState;

CBlockIndex *LookupBlockIndex(const uint256 &hash);

std::set<uint256> GetPrevHashes(const CBlockHeader &header);

// Find the hash of the tip of the dag which has the best dag height
static CTreeNodeRef FindDagTipNode(const std::vector<CTreeNodeRef> &dag)
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
            // the first one in dag order the activetip.
            if (activetip && (node->nSequenceId < activetip->nSequenceId) && (node->dagHeight == activetip->dagHeight))
            {
                activetip = node;
            }
        }
    }
    return activetip;
}

// Find the hash of the tip of the dag which has the best dag height
static uint256 FindDagTip(const std::vector<CTreeNodeRef> &dag)
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

// Compare newNode's inputs to the spend index. True if any spend hits this
// subblock's ancestry. commit writes the index.
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

                // A competing spend in an unrelated branch is allowed: the first in dag order wins it.
                if ((prior.subblock == newNode) || (setAncestors.count(prior.subblock) != 0))
                    hasConflict = true;
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

// Remove this subblock's spends from the index.
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
        }
        spendsBySubblock.erase(itOuts);
    }
    indexed.erase(node->hash);
}

void CDagConflictRegistry::clear()
{
    AssertLockHeld(tailstormForest.cs_forest);
    spendIndex.clear();
    spendsBySubblock.clear();
    indexed.clear();
}

bool CTailstormTree::HasAncestryDoubleSpend(const CTreeNodeRef &newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);
    if (!newNode)
        return false;
    return conflictRegistry.ScanSpends(newNode, false);
}

void CTailstormTree::IndexSpends(const CTreeNodeRef &newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);
    if (newNode)
        conflictRegistry.ScanSpends(newNode, true);
}

// Admit a subblock to the dag: ancestry check, insert, renumber, and index its spends.
bool CTailstormTree::checkUpdateAncestryInsertIntoDag(const CTreeNodeRef &newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);
    // A subblock's transactions after the coinbase must be in increasing txid order. The dag connects
    // transactions without their subblocks (ConnectDagTransactions), so check it here, for every subblock
    // linked, however it is later connected.
    const auto &vtx = newNode->subblock->vtx;
    for (size_t i = 2; i < vtx.size(); i++)
    {
        if (!(vtx[i - 1]->GetId() < vtx[i]->GetId()))
        {
            LOG(DAG, "%s: Rejected - subblock %s transactions are not in txid order at %d", __func__,
                newNode->hash.ToString(), (int)i);
            return false;
        }
    }

    if (HasAncestryDoubleSpend(newNode))
    {
        LOG(DAG, "%s: Rejected - subblock %s has a double spend in its ancestor tree", __func__,
            newNode->hash.ToString());
        return false;
    }

    // Once the selection is full, keep an arrival (a foreign summary may use it) but place it last rather
    // than reorder the dag.  It does not matter if the order is not correct -- only the first k-1 subblocks
    // will be used anyway.
    const bool fSelectionFull = dag.size() >= SelectionSize();
    newNode->fProcessed = false;
    // add to the dag
    dag.emplace(newNode->hash, newNode);
    // renumber the DAG if needed
    if (fSelectionFull)
        newNode->nSequenceId = dag.size();
    else
        tailstormForest.RenumberDag(*this);
    DbgAssert(newNode->nSequenceId > 0, );

    IndexSpends(newNode);
    return true;
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
uint256 GetActiveDagTip(std::vector<CTreeNodeRef> &dag)
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
std::set<uint256> GetTxnExclusionSet(const std::vector<CTreeNodeRef> &sortedNodes,
    const CCoinsViewCache *pcoins,
    std::set<uint256> *pLosers)
{
    // We do not need to be holding a lock like tailstormForest.cs_forest, because all the information is
    // provided to us in the passed parameters: the node list and the coins cache.
    std::set<uint256> excluded;
    if (sortedNodes.empty())
        return excluded;

    std::map<uint256, CTransactionRef> mapTx;
    std::map<COutPoint, uint256> createdBy;
    // The transaction that first spends each outpoint, in dag order.
    std::map<COutPoint, uint256> spentBy;
    std::set<uint256> losers;

    // Upper bound on the distinct transactions: every subblock's vtx, minus coinbases.
    std::vector<uint256> order;
    size_t nMaxTxns = 0;
    for (const auto &node : sortedNodes)
    {
        if (node && node->subblock && !node->subblock->vtx.empty())
            nMaxTxns += node->subblock->vtx.size() - 1;
    }
    order.reserve(nMaxTxns);

    for (const auto &node : sortedNodes)
    {
        // Uncles are only proofs of work; their transactions are not part of this dag.
        if (!node || !node->subblock || node->fUncle)
            continue;
        for (const auto &ptx : node->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;
            const uint256 txid = ptx->GetId();
            // A transaction carried by an earlier subblock is already recorded; it is not a second spend.
            if (!mapTx.emplace(txid, ptx).second)
                continue;
            order.push_back(txid);
            for (size_t j = 0; j < ptx->vout.size(); j++)
                createdBy.emplace(ptx->OutpointAt(j), txid);
            // The first spend of an outpoint is good; any later one loses to it.
            for (const auto &input : ptx->vin)
            {
                if (input.IsReadOnly())
                    continue;
                if (!spentBy.emplace(input.prevout, txid).second)
                    losers.insert(txid);
            }
        }
    }

    /*
      Why do we need to loop every time there is a change?

      Sourcing does not follow dag order. A transaction can spend an output created later in dag order: by a
      transaction in an unrelated branch, or later in its own subblock, whose transactions are in txid order
      rather than dependency order. As in the summary block, which evaluates all of these transactions at once,
      a transaction is included once everything it spends is, wherever that is in the dag.

      Dag order decides only which spend of a double spend wins, above.
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

// Same omit set, taking the tree that produced the dag rather than searching for it.
std::set<uint256> GetTxnExclusionSet(const std::vector<CTreeNodeRef> &sortedNodes,
    const CTailstormTree &tree,
    std::set<uint256> *losers)
{
    return GetTxnExclusionSet(sortedNodes, tree._pcoinsSummaryRoot, losers);
}

// Analyze a summary's subblocks on a private graph built from their headers alone, so that no forest
// state (nSequenceId, links to subblocks the summary does not commit, fUncle) can affect the result.
bool AnalyzeSummaryDag(const uint256 &hashSummaryRoot,
    const std::vector<ConstCBlockRef> &vSubblocks,
    const CCoinsViewCache &coinsSummaryRoot,
    std::vector<ConstCBlockRef> &vOrdered,
    std::set<uint256> &setTxnExclusions,
    std::string &strReject)
{
    vOrdered.clear();
    setTxnExclusions.clear();
    strReject.clear();

    // Fresh nodes: no forest links, not uncles, no nSequenceId.
    std::map<uint256, CTreeNodeRef> mapNodes;
    std::vector<CTreeNodeRef> nodes;
    nodes.reserve(vSubblocks.size());
    for (const auto &subblock : vSubblocks)
    {
        if (!subblock)
        {
            strReject = "bad-summary-dag-missing-subblock";
            return false;
        }
        CTreeNodeRef node = std::make_shared<CTreeNode>(subblock);
        if (!mapNodes.emplace(node->hash, node).second)
        {
            strReject = "bad-summary-dag-duplicate-subblock";
            return false;
        }
        nodes.push_back(node);
    }

    // Link each node to its parents. Every parent must be another of these subblocks, except that a base
    // subblock's only parent is the summary root. Only setAncestors is filled, so these nodes form no
    // shared_ptr cycle and are freed on return.
    for (const auto &node : nodes)
    {
        const auto setPrevHashes = GetPrevHashes(node->subblock->GetBlockHeader());
        if (setPrevHashes.empty())
        {
            strReject = "bad-summary-dag-no-parent";
            return false;
        }
        if (setPrevHashes.size() == 1 && *setPrevHashes.begin() == hashSummaryRoot)
            continue;
        for (const uint256 &prevHash : setPrevHashes)
        {
            auto it = mapNodes.find(prevHash);
            if (it == mapNodes.end())
            {
                strReject = "bad-summary-dag-incomplete";
                return false;
            }
            node->setAncestors.insert(it->second);
        }
    }

    const std::vector<CTreeNodeRef> ordered = OrderDag(nodes);
    if (ordered.size() != nodes.size())
    {
        strReject = "bad-summary-dag-cycle";
        return false;
    }

    setTxnExclusions = GetTxnExclusionSet(ordered, &coinsSummaryRoot);
    vOrdered.reserve(ordered.size());
    for (const auto &node : ordered)
        vOrdered.push_back(node->subblock);
    return true;
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

static bool ConnectDagTransactions(const std::map<uint256, CTransactionRef> &txs,
    CBlockIndex *pindexSummaryRoot,
    CCoinsViewCache &view,
    const CCoinsViewCache &coinsSummaryRoot,
    uint256 &badTxid);

// The number of dag subblocks a summary commits: the tailstorm_k - 1 places the uncles leave.
size_t CTailstormTree::SelectionSize() const
{
    AssertLockHeld(tailstormForest.cs_forest);
    const size_t nMaxSubblocks = Params().GetConsensus().tailstorm_k - 1;
    return nMaxSubblocks - std::min(mapUncles.size(), nMaxSubblocks);
}

// The coins cache embodies the processed subblocks, so it is right only if they are exactly the first
// SelectionSize() in dag order.
bool CTailstormTree::NeedsRegeneration() const
{
    AssertLockHeld(tailstormForest.cs_forest);
    const size_t nSelection = SelectionSize();
    for (const auto &mi : dag)
    {
        if (mi.second->fProcessed != (mi.second->nSequenceId <= nSelection))
            return true;
    }
    return false;
}

std::vector<CTreeNodeRef> CTailstormTree::SortedDag() const
{
    AssertLockHeld(tailstormForest.cs_forest);
    std::vector<CTreeNodeRef> sorted(dag.size());
    bool fDense = true;
    for (const auto &mi : dag)
    {
        const uint32_t nIndex = mi.second->nSequenceId - 1;
        if (nIndex >= sorted.size() || sorted[nIndex])
        {
            fDense = false;
            continue;
        }
        sorted[nIndex] = mi.second;
    }
    // A node that could not be placed leaves an empty slot; drop those rather than hand out nulls.
    DbgAssert(fDense, sorted.erase(std::remove(sorted.begin(), sorted.end(), nullptr), sorted.end()));
    return sorted;
}

CTreeNodeRef CTailstormTree::Insert(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    DbgAssert(newNode->subblock != nullptr, );
    if (!newNode->subblock)
        return {};

    // It makes no sense to insert a subblock if we don't even know its summary root.
    // This is protected against by callers, but double check it here.
    DbgAssert(pindexSummaryRoot, );
    if (!pindexSummaryRoot)
    {
        return {};
    }

    // Add to the tree
    auto element = dag.find(newNode->hash);
    if (element == dag.end()) // We need to add it if it does not already exist
    {
        // In two cases we just want to remember this subblock, but not do anything with it:
        // 1. Once we already have k-1 subblocks, add this to the DAG unprocessed. With k-1
        // it just goes onto the end of the DAG: we will only need it if some foreign summary block uses it.
        // 2. Off the chain tip: A summary can reference a subblock only at its own height (a regular subblock)
        // or one below it (an uncle; uncle depth is 1). So a subblock stays usable while its grove root is within two
        // summaries of the tip - gap 1 is the tip's own epoch, gap 2 an uncle of it. Park anything older.
        auto chainTip = chainActive.Tip();
        const bool fOffTip = chainTip != pindexSummaryRoot;
        const int64_t depth = (int64_t)chainTip->height() - (int64_t)pindexSummaryRoot->height();
        if (depth > 2)
        {
            return {};
        }
        if (fOffTip || dag.size() >= SelectionSize())
            return checkUpdateAncestryInsertIntoDag(newNode) ? newNode : CTreeNodeRef();

        TxAdmissionPause txlock;

        // Each subblock's place before this one arrives, to tell whether the arrival moved any of them, and
        // whether the coins cache embodied exactly the subblocks a summary would commit.
        std::map<CTreeNodeRef, uint32_t> mapPriorIds;
        for (const auto &mi : dag)
            mapPriorIds.emplace(mi.second, mi.second->nSequenceId);
        const bool fWasConsistent = !NeedsRegeneration();

        if (!checkUpdateAncestryInsertIntoDag(newNode))
            return {};

        CTailstormGroveRef grove = nullptr;
        tailstormForest.GetGrove(*(pindexSummaryRoot->phashBlock), grove);
        auto regenerate = [&]()
        {
            if (grove)
                tailstormForest.ReGenerateDagData(grove);
            cvCommitQ.notify_all();
            // Regeneration removes this subblock from the grove if it carries an invalid transaction. It is
            // still returned: it was linked, and the removal has already cleaned up after it.
            return newNode;
        };

        // The arrival can be added on its own only if it lands last and every other subblock keeps its
        // place. Otherwise the order the coins cache was built in has changed (and with it which spend of
        // a double spend comes first), so regenerate.
        bool fAppend = fWasConsistent && (newNode->nSequenceId == dag.size());
        for (const auto &[node, nPriorId] : mapPriorIds)
        {
            if (!fAppend)
                break;
            if (node->nSequenceId != nPriorId)
                fAppend = false;
        }
        if (!fAppend)
        {
            LOG(DAG, "%s: subblock %s placed at %d of %d, regenerating", __func__, newNode->hash.ToString(),
                newNode->nSequenceId, (int)dag.size());
            return regenerate();
        }

        // Landing past the cutoff it stays unprocessed, usable as an uncle.
        if (newNode->nSequenceId > SelectionSize())
            return newNode;

        // It lands last within the cutoff, so the subblocks a summary would commit are now the whole dag.
        // Compute what they exclude as ReGenerateDagData does.
        const std::vector<CTreeNodeRef> vDag = SortedDag();
        const std::set<uint256> setTxnExclusions = GetTxnExclusionSet(vDag, _pcoinsSummaryRoot);

        // A later subblock cannot make an earlier spend lose, nor take away an output, so an earlier
        // subblock's transactions stay as they were applied, except one whose input this arrival supplies:
        // it is now included but not applied. Regenerate to apply it.
        for (const CTreeNodeRef &node : vDag)
        {
            if (node == newNode)
                continue;
            for (const auto &ptx : node->subblock->vtx)
            {
                if (!ptx->IsCoinBase() && !setTxnExclusions.count(ptx->GetId()) && !mapDagTxns.count(ptx->GetId()))
                {
                    LOG(DAG, "%s: subblock %s supplies an input of %s, regenerating", __func__,
                        newNode->hash.ToString(), ptx->GetId().ToString());
                    return regenerate();
                }
            }
        }

        // Apply this subblock's included transactions on top of the cache, as ReGenerateDagData applies them.
        std::map<uint256, CTransactionRef> mapIncluded;
        for (const auto &ptx : newNode->subblock->vtx)
        {
            const uint256 txid = ptx->GetId();
            if (ptx->IsCoinBase() || mapDagTxns.count(txid))
                continue;
            if (setTxnExclusions.count(txid))
            {
                LOG(DAG, "%s: excluding %s of subblock %s", __func__, txid.ToString(), newNode->hash.ToString());
                continue;
            }
            mapIncluded.emplace(txid, ptx);
        }

        uint256 badTxid;
        // Child cache: a failed connect must not dirty the tree view.
        CCoinsViewCache layer(view);
        if (!ConnectDagTransactions(mapIncluded, pindexSummaryRoot, layer, *_pcoinsSummaryRoot, badTxid))
        {
            // As in ReGenerateDagData: a subblock carrying an invalid transaction is removed. Every other
            // subblock's copy of this transaction was applied or excluded already, so only this one carries it.
            LOG(DAG, "%s: subblock %s is bad: transaction %s failed", __func__, newNode->hash.ToString(),
                badTxid.ToString());
            if (grove)
                tailstormForest.RemoveFromGrove(grove, newNode);
            return newNode;
        }
        bool result = layer.Flush();
        assert(result);

        std::list<CTransactionRef> txConflicted;
        {
            WRITELOCK(mempool.cs_txmempool);
            for (const auto &kv : mapIncluded)
                mempool._removeConflicts(*kv.second, txConflicted);
        }
        mapDagTxns.insert(mapIncluded.begin(), mapIncluded.end());
        newNode->fProcessed = true;

        if (grove)
            tailstormForest.SetBestGroveForSummaryTip();

        cvCommitQ.notify_all();

        for (auto &ancestor : newNode->setAncestors)
        {
            DbgAssert(ancestor->fProcessed, );
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

bool CTailstormGrove::GetBestDag(std::vector<CTreeNodeRef> &dag)
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
        dag.push_back(node);
        if (dag.size() == nNumSubblocksToReturn)
        {
            break; // we have all we need.
        }
    }

    // Insert nodes from the current dag.
    if (dag.size() < nNumSubblocksToReturn)
    {
        for (const CTreeNodeRef &node : tree->SortedDag())
        {
            // Note that a descendant subblock can never be processed if its ancestors are not processed,
            // so we do not neet to worry about having a gap in the best dag.
            if (node->fProcessed)
            {
                dag.push_back(node);
                if (dag.size() == nNumSubblocksToReturn)
                    break;
            }
        }
    }

    return true;
}

bool CTailstormGrove::GetFullDag(std::vector<CTreeNodeRef> &dag)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (tree->dag.empty() && tree->mapUncles.empty())
    {
        return false;
    }

    // Insert the uncles first.
    for (auto &mi : tree->mapUncles)
    {
        dag.push_back(mi.second);
    }

    // Insert nodes from the current dag.
    for (const CTreeNodeRef &node : tree->SortedDag())
    {
        dag.push_back(node);
    }

    return true;
}

bool CTailstormGrove::GetDagForReorg(std::vector<CTreeNodeRef> &dag)
{
    AssertLockHeld(tailstormForest.cs_forest);

    dag.clear();
    if (tree->dag.empty() && tree->mapUncles.empty())
    {
        return false;
    }

    uint32_t nNumSubblocksToReturn = Params().GetConsensus().tailstorm_k - 1;

    // Insert the uncles first.
    for (auto &mi : tree->mapUncles)
    {
        dag.push_back(mi.second);
        if (dag.size() == nNumSubblocksToReturn)
            return true;
    }

    // Insert nodes from the current dag.
    for (const CTreeNodeRef &node : tree->SortedDag())
    {
        dag.push_back(node);
        if (dag.size() == nNumSubblocksToReturn)
            return true;
    }

    return true;
}

bool CTailstormGrove::GetBestTipHash(uint256 &tiphash)
{
    AssertLockHeld(tailstormForest.cs_forest);

    std::vector<CTreeNodeRef> bestDag;
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
                grove->tree->mapDagTxns.clear();

                // Clear out the grove
                grove->mapGroveNodes.clear();
            }

            // Break the ancestor/descendant shared_ptr cycle so the node can be reclaimed.
            iter->second->setAncestors.clear();
            iter->second->setDescendants.clear();

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
    if (!subblock)
        return false;

    LOCK(cs_forest);
    bool fOK = _Insert(subblock);
    Check();
    return fOK;
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
    LOG(DAG, "%s: Starting Tailstorm Forest insert %s", __func__, newNode->hash.ToString());

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
        std::vector<CTreeNodeRef> dag;
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
            ConstCBlockRef pblock = iter2->second;
            if (summaryBlockValidated(hash))
            {
                iter2 = mapSummaryBlocksUnlinked.erase(iter2);
                continue;
            }
            {
                // Refresh late uncles before checking whether the summary is ready.
                std::vector<CTreeNodeRef> dag;
                const bool fHaveSubblocks = GetDagForBlock(pblock, dag);

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

bool CTailstormForest::GetBestDagFor(const uint256 &hash, std::vector<CTreeNodeRef> &dag, CTailstormTreeRef *ptree)
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

bool CTailstormForest::GetFullDagFor(const uint256 &hash, std::vector<CTreeNodeRef> &dag)
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

bool CTailstormForest::GetDagForReorg(const uint256 &hash, std::vector<CTreeNodeRef> &dag)
{
    LOCK(cs_forest);
    dag.clear();
    CTailstormGroveRef grove = nullptr;
    if (GetGrove(hash, grove))
    {
        if (!grove->GetDagForReorg(dag))
        {
            LOG(DAG, "%s(): get dag for reorg returned false", __func__);
            return false;
        }
        return true;
    }
    LOG(DAG, "%s(): did not get grove", __func__);

    return false;
}


bool CTailstormForest::GetDagForBlock(ConstCBlockRef &pblock, std::vector<CTreeNodeRef> &dag, CTailstormTreeRef *ptree)
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
        std::set<uint256> setBlockMiningHashes;
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
                setBlockMiningHashes.insert(miningHash);
                fMatch = true;
            }
        }
        if (fMatch)
        {
            // Return the matched nodes in dag order: uncles first, then subblocks by nSequenceId.
            auto addIfInBlock = [&](const CTreeNodeRef &node)
            {
                const auto &miningHeaderCommitment = node->subblock->GetMiningHeaderCommitment();
                const auto &nonce = node->subblock->GetBlockHeader().nonce;
                if (setBlockMiningHashes.count(GetMiningHash(miningHeaderCommitment, nonce)))
                    dag.push_back(node);
            };
            for (auto &mi : tree->mapUncles)
                addIfInBlock(mi.second);
            for (const CTreeNodeRef &node : tree->SortedDag())
                addIfInBlock(node);
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

void CTailstormForest::GetDagTxns(const std::vector<CTreeNodeRef> &dag, std::map<uint256, CTransactionRef> &mapDagTxns)
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
        std::vector<CTreeNodeRef> tipdag;
        GetDagForReorg(*startingChainTip->phashBlock, tipdag);
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
            std::vector<CTreeNodeRef> dag;
            GetDagForReorg(grove->roothash, dag);
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
        // Subblocks past the cutoff are overflow/uncle candidates and stay unprocessed; only a subblock
        // within it that is unprocessed (or one past it that is processed) needs the rebuild.
        if (GetGrove(*startingChainTip->phashBlock, grove) && grove->tree)
        {
            if (grove->tree->NeedsRegeneration())
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

                LOG(DAG, "%s(): reprocessing parked subblocks for settled tip grove %s", __func__,
                    startingChainTip->phashBlock->ToString());
                ReGenerateDagData(grove);

                // Regenerating may have exposed a grove for subblocks that are still unlinked.
                ProcessOrphans();
            }
        }
    }
    return;
}

// Connect txs, in txid order, on top of view as the summary block that commits them would: read-only
// inputs are checked against the summary root's coins before anything changes, then every output is
// added, then every input is checked, then every input is spent. Unlike ConnectBlockCanonicalOrdering,
// scripts are checked inline per transaction, so on failure badTxid always names the transaction.
static bool ConnectDagTransactions(const std::map<uint256, CTransactionRef> &txs,
    CBlockIndex *pindexSummaryRoot,
    CCoinsViewCache &view,
    const CCoinsViewCache &coinsSummaryRoot,
    uint256 &badTxid)
{
    // A stand-in for the not-yet-created summary block that will commit these transactions.
    std::shared_ptr<CBlockHeader> header = std::make_shared<CBlockHeader>();
    header->height = pindexSummaryRoot->height() + 1;
    header->nTime = 0;
    CBlockIndex indexEpoch(header);
    indexEpoch.pprev = pindexSummaryRoot;
    const int nHeight = indexEpoch.height();

    for (const auto &[txid, ptx] : txs)
    {
        for (const auto &input : ptx->vin)
        {
            if (!input.IsReadOnly())
                continue;
            CoinAccessor coin(coinsSummaryRoot, input.prevout);
            if (coin->IsSpent())
            {
                LOG(DAG, "%s: tx %s read only input %s missing or spent", __func__, txid.ToString(),
                    input.prevout.ToString());
                badTxid = txid;
                return false;
            }
        }
    }

    for (const auto &[txid, ptx] : txs)
    {
        try
        {
            AddCoins(view, *ptx, nHeight);
        }
        catch (const std::logic_error &)
        {
            LOG(DAG, "%s: tx %s repeats outputs already in the view", __func__, txid.ToString());
            badTxid = txid;
            return false;
        }
    }

    for (const auto &[txid, ptx] : txs)
    {
        CValidationState state;
        if (!CheckTxFinalAndInputs(ptx, state, view, coinsSummaryRoot, indexEpoch, Params(), true, true, false))
        {
            LOG(DAG, "%s: tx %s failed validation: %s", __func__, txid.ToString(), state.GetLogString());
            badTxid = txid;
            return false;
        }
    }

    for (const auto &[txid, ptx] : txs)
    {
        CTxUndo undo;
        if (!SpendCoins(*ptx, view, undo, nHeight))
        {
            LOG(DAG, "%s: tx %s inputs missing or spent (possibly doublespent)", __func__, txid.ToString());
            badTxid = txid;
            return false;
        }
    }
    return true;
}

void CTailstormForest::ReGenerateDagData(CTailstormGroveRef grove)
{
    LOG(DAG, "%s: Begin ReGenerateDagData for grove %s", __func__, grove->roothash.ToString());
    AssertLockHeld(cs_forest);
    DbgAssert(txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("must have corral paused during DAG regenerate"));

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

    // Remove subblocks found bad below from the grove as soon as they are found. Removing one also
    // removes its descendants, so a later hash may already be gone.
    auto removeBadSubblocks = [&](const std::vector<uint256> &vBad)
    {
        for (const uint256 &hash : vBad)
        {
            auto it = tree->dag.find(hash);
            if (it != tree->dag.end())
                RemoveFromGrove(grove, it->second);
        }
        grove->RecalcDagHeights();
    };

    // its possible for us to discover a bad transaction here.  For example, a subblock might contain a tx
    // that previously we did not know its inputs so skipped.  But now that we resolve its inputs, the tx is
    // bad.  So we need to be able to mark the tx and subblock as bad (permanently bad) and then rebuild the best dag
    while (true)
    {
        // A removal leaves a gap in the sequence and changes scores, so number the dag afresh.
        RenumberDag(*tree);

        // Select the subblocks the summary will commit: the first in dag order. Uncles are not part of the
        // dag, only proofs of work, and their only effect here is to take some of the tailstorm_k - 1 places.
        std::vector<CTreeNodeRef> vDag = tree->SortedDag();
        if (vDag.size() > tree->SelectionSize())
            vDag.resize(tree->SelectionSize());

        const std::set<uint256> setTxnExclusions = GetTxnExclusionSet(vDag, *tree);

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

        // Every transaction of the selected subblocks the summary would include, keyed (so ordered) by txid.
        std::map<uint256, CTransactionRef> mapIncluded;
        for (const CTreeNodeRef &node : vDag)
        {
            const auto &vtx = node->subblock->vtx;
            for (size_t j = 1; j < vtx.size(); j++)
            {
                if (!setTxnExclusions.count(vtx[j]->GetId()))
                    mapIncluded.emplace(vtx[j]->GetId(), vtx[j]);
            }
        }

        // Rebuild the view from the summary root, connecting every included transaction at once.
        tree->mapDagTxns.clear();
        tree->view->Clear();
        for (auto &mi : tree->dag)
            mi.second->fProcessed = false;

        uint256 badTxid;
        CCoinsViewCache layer(tree->view);
        if (ConnectDagTransactions(mapIncluded, tree->pindexSummaryRoot, layer, *tree->_pcoinsSummaryRoot, badTxid))
        {
            bool flushed = layer.Flush();
            assert(flushed);
            tree->mapDagTxns = std::move(mapIncluded);
            for (const CTreeNodeRef &node : vDag)
                node->fProcessed = true;
            break; // It worked
        }

        // Connect rejects a subblock carrying an invalid transaction, so every selected subblock
        // carrying the failed transaction is removed and the next best set is tried.
        std::vector<uint256> vBad;
        for (const CTreeNodeRef &node : vDag)
        {
            for (const auto &ptx : node->subblock->vtx)
            {
                if (ptx->GetId() == badTxid)
                {
                    LOG(DAG, "%s(): While regenerating dag, subblock is bad: %s", __func__, node->hash.ToString());
                    vBad.push_back(node->hash);
                    break;
                }
            }
        }
        if (vBad.empty())
        {
            // Cannot happen: the failed transaction came from one of these subblocks. Stop rather than loop.
            DbgAssert(!"failed transaction not found in the selected subblocks", );
            break;
        }
        removeBadSubblocks(vBad);
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

    // In case the new dag ordering caused a switch of which was the "good" doublespend and which is the bad,
    // we need to remove any tx that conflict with the transactions we've chosen to accept
    {
        std::list<CTransactionRef> txConflicted;
        WRITELOCK(mempool.cs_txmempool);
        for (const auto &kv : tree->mapDagTxns)
        {
            if (!currentAppliedTxns.count(kv.first))
                mempool._removeConflicts(*kv.second, txConflicted);
        }
        if (!txConflicted.empty())
            LOG(DAG, "%s: removed %u txpool entries conflicting with newly applied transactions", __func__,
                (unsigned)txConflicted.size());
    }

    SetBestGroveForSummaryTip();
}

// Dag order of the passed nodes: by dependency (parents before children), then by the highest score among a
// subblock and its descendants, then by lower hash. Only links among the passed nodes are considered, and only
// setAncestors is read, so the result depends on nothing but these nodes.
std::vector<CTreeNodeRef> OrderDag(const std::vector<CTreeNodeRef> &nodes)
{
    const std::set<CTreeNodeRef> setNodes(nodes.begin(), nodes.end());
    const auto mapScores = GetDagScores(nodes);

    // Each node's children among the passed nodes, derived from setAncestors.
    std::map<CTreeNodeRef, std::vector<CTreeNodeRef> > mapChildren;
    // The number of each node's parents among the passed nodes not yet placed.
    std::map<CTreeNodeRef, size_t> mapUnplacedParents;
    for (const auto &node : nodes)
    {
        size_t nParents = 0;
        for (const auto &ancestor : node->setAncestors)
        {
            if (!setNodes.count(ancestor))
                continue;
            mapChildren[ancestor].push_back(node);
            nParents++;
        }
        mapUnplacedParents[node] = nParents;
    }

    // Each subblock's own score and the scores of all its descendants among the passed nodes, highest first.
    std::map<CTreeNodeRef, std::vector<uint32_t> > mapReachScores;
    for (const auto &node : nodes)
    {
        std::vector<uint32_t> vScores{mapScores.at(node)};
        std::set<CTreeNodeRef> seen;
        std::vector<CTreeNodeRef> toVisit;
        auto itChildren = mapChildren.find(node);
        if (itChildren != mapChildren.end())
            toVisit = itChildren->second;
        while (!toVisit.empty())
        {
            const CTreeNodeRef descendant = toVisit.back();
            toVisit.pop_back();
            if (!seen.insert(descendant).second)
                continue;
            vScores.push_back(mapScores.at(descendant));
            auto it = mapChildren.find(descendant);
            if (it != mapChildren.end())
                toVisit.insert(toVisit.end(), it->second.begin(), it->second.end());
        }
        std::sort(vScores.begin(), vScores.end(), std::greater<uint32_t>());
        mapReachScores.emplace(node, std::move(vScores));
    }

    // Of the subblocks whose parents are all placed, the next is the one whose own and descendants'
    // scores rank highest: the two lists are compared highest first, and the first score that differs
    // decides (if one list runs out first, the longer one wins). Descendants two candidates share, where
    // their paths rejoin, put the same scores in both lists and so cancel; the comparison is decided by
    // the descendants each candidate has alone. A tie goes to the lower hash.
    //
    // This order also decides double spends, because GetTxnExclusionSet keeps the first spend in it. Score
    // alone cannot decide every double spend consistently. Suppose subblock C is a child of P1, and an
    // unrelated subblock Q carries one transaction that double spends a transaction in P1 and another that
    // double spends a transaction in C. If score(P1) < score(Q) < score(C), ranking by score says Q beats P1
    // but loses to C. Yet Q's transactions are applied together: Q is placed either before P1 (and so
    // before C), between them, or after C, and in none of those positions does it beat P1 and lose to C.
    // One of Q's two double spends must therefore go against score.
    //
    // The intention of score with respect to a double spend is to pick the transaction that had the higher
    // "visibility" across the network, which is not a well defined term. Ranking a subblock by the highest
    // score among it and its descendants picks the double spend that had the higher visibility subsequent
    // to its issuance.
    //
    // The priority queue's top is its greatest element, so "less" here means placed later.
    auto placedLater = [&mapReachScores](const CTreeNodeRef &a, const CTreeNodeRef &b)
    {
        const std::vector<uint32_t> &vScoresA = mapReachScores.at(a);
        const std::vector<uint32_t> &vScoresB = mapReachScores.at(b);
        if (vScoresA != vScoresB)
            return vScoresA < vScoresB;
        return b->hash < a->hash;
    };
    std::priority_queue<CTreeNodeRef, std::vector<CTreeNodeRef>, decltype(placedLater)> ready(placedLater);
    for (const auto &mi : mapUnplacedParents)
    {
        if (mi.second == 0)
            ready.push(mi.first);
    }

    std::vector<CTreeNodeRef> ordered;
    ordered.reserve(nodes.size());
    while (!ready.empty())
    {
        const CTreeNodeRef node = ready.top();
        ready.pop();
        ordered.push_back(node);
        auto itChildren = mapChildren.find(node);
        if (itChildren == mapChildren.end())
            continue;
        for (const auto &child : itChildren->second)
        {
            if (--mapUnplacedParents[child] == 0)
                ready.push(child);
        }
    }
    return ordered;
}

void CTailstormForest::RenumberDag(CTailstormTree &tree)
{
    AssertLockHeld(cs_forest);

    std::vector<CTreeNodeRef> nodes;
    nodes.reserve(tree.dag.size());
    for (auto &mi : tree.dag)
        nodes.push_back(mi.second);

    uint32_t nSequenceId = 0;
    uint32_t nMoved = 0;
    for (const auto &node : OrderDag(nodes))
    {
        if (node->nSequenceId != ++nSequenceId)
            nMoved++;
        node->nSequenceId = nSequenceId;
    }
    DbgAssert(nSequenceId == nodes.size(), );
    if (nMoved)
        LOG(DAG, "%s: dag %d subblocks, %d nSequenceId(s) changed", __func__, (int)nodes.size(), (int)nMoved);
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

bool CTailstormForest::ReconsiderDag()
{
    LOCK(cs_forest);
    TxAdmissionPause txlock;

    auto chainTip = chainActive.Tip();
    if (!chainTip)
        return false;

    CTailstormGroveRef grove;
    if (!GetGrove(*chainTip->phashBlock, grove) || !grove->tree)
        return false;

    ReGenerateDagData(grove);

    std::vector<CTreeNodeRef> dag;
    GetBestDagFor(*chainTip->phashBlock, dag);
    CTreeNodeRef bestnode = FindDagTipNode(dag);
    if (bestnode)
        SetDagActiveTip(bestnode);
    cvCommitQ.notify_all();
    return true;
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

        std::vector<CTreeNodeRef> prevDag;
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
            RenumberDag(*(grove->tree));
            grove->RecalcDagHeights();
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

        // Check sequence ids are contiguous, match the total number of nodes, and place every
        // subblock after its parents
        {
            const std::vector<CTreeNodeRef> vSortedDag = tree->SortedDag();
            assert(vSortedDag.size() == tree->dag.size());
            for (uint32_t i = 0; i < vSortedDag.size(); i++)
            {
                assert(vSortedDag[i]->nSequenceId == i + 1);
                for (auto &ancestor : vSortedDag[i]->setAncestors)
                    assert(ancestor->nSequenceId < vSortedDag[i]->nSequenceId);
            }
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
    std::vector<CTreeNodeRef> setBestDag;
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
