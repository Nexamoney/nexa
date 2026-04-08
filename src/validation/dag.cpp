// Copyright (c) 2020-2025 The Bitcoin Unlimited developers
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

bool processingOrphans = false;

extern bool IsInitialBlockDownload();
extern CCriticalSection cs_main;
extern std::atomic<bool> forceTemplateRecalc;

class CValidationState;

CBlockIndex *LookupBlockIndex(const uint256 &hash);
bool IsSummaryBlock(const CBlock &block);

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
            if (node->nSequenceId < activetip->nSequenceId && node->dagHeight == activetip->dagHeight)
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
static std::set<CTreeNodeRef> CalculateAncestors(CTreeNodeRef &node)
{
    std::set<CTreeNodeRef> setAncestors;
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

std::map<CTreeNodeRef, uint32_t> GetDagScores(const std::set<CTreeNodeRef> &setBestDag)
{
    // Set the uncle score to a contant which is slightly less that the maximum
    // dag score possible. The idea here is that we want to punish uncles enough
    // to disourage miners from continuing to mine on the previous epoch, but
    // not reduce it so much that it would be beneficial for potential selfish miners.
    uint32_t nUncleScore = 1;
    if (setBestDag.size() > DEFAULT_UNCLE_SCORE_ADJUSTMENT)
        nUncleScore = setBestDag.size() - DEFAULT_UNCLE_SCORE_ADJUSTMENT;

    // Count up how many uncles there are in the dag. We'll need this to initialize
    // the scoring below.
    uint32_t nUncles = 0;
    for (auto node : setBestDag)
    {
        if (node->fUncle)
            nUncles++;
    }

    std::map<CTreeNodeRef, uint32_t> mapBestDagScores;
    for (auto node : setBestDag)
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
        for (auto ancestor : setAllAncestors)
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

std::set<uint256> GetTxnExclusionSet(const std::set<CTreeNodeRef> &setBestDag,
    std::vector<std::map<uint256, CTreeNodeRef> > &_vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> &mapInputs)
{
    // Since we'll be modifying values make a local copy.
    auto vDoubleSpendTxns = _vDoubleSpendTxns;

    // Get the set of invalid double spends which we "DO NOT" want to include in the final summary block.
    //
    // We need to remove low score double spends but if there's a tie then we compare the block
    // hashes of the subblock they are in with the high block hash being the transaction we want to keep.
    std::set<uint256> setTxnExclusions;

    auto mapScores = GetDagScores(setBestDag);
    std::map<uint256, uint32_t> mapScoresByTxId;
    for (auto &mi : mapScores)
    {
        for (auto &ptx : mi.first->subblock->vtx)
        {
            if (ptx->IsCoinBase())
                continue;

            mapScoresByTxId.emplace(ptx->GetId(), mi.second);
        }
    }

    // find scores for ds transactions
    // Add lowest scores to a set of txns to exclude.
    // if there's a tie in score then use the txn with the highest block hash.
    for (auto &mapDoubleSpends : vDoubleSpendTxns)
    {
        // Iterate through each map find the highest score txn and also
        // if there's a tie, the one with the highest block hash.
        // Then remove that txn from the map and insert the remaining
        // map values into the exclusion set.
        uint256 hashHighScore;
        uint256 subblockHashHighScore;
        uint32_t nHighScore = 0;
        for (auto &mi : mapDoubleSpends)
        {
            // Pick and set the high score transaction
            uint32_t nScore = 0;
            if (mapScoresByTxId.count(mi.first))
                nScore = mapScoresByTxId[mi.first];

            if (nScore > nHighScore)
            {
                nHighScore = nScore;
                hashHighScore = mi.first;
                subblockHashHighScore = mi.second->hash;
            }
            // If scores are equal then determine which txn to keep.
            // Keep the one that has the highest "subblock" hash.
            else if (nScore == nHighScore)
            {
                if (mi.second->hash > subblockHashHighScore)
                {
                    hashHighScore = mi.first;
                    subblockHashHighScore = mi.second->hash;
                }
            }
        }
        mapDoubleSpends.erase(hashHighScore);

        // Add any descendant txns to the exclusion set regardless of what score
        // subblock they're in.
        std::map<uint256, CTransactionRef> mapDagTxns;
        tailstormForest.GetDagTxns(setBestDag, mapDagTxns);
        for (auto &mi : mapDoubleSpends)
        {
            setTxnExclusions.insert(mi.first);

            // Anything left in the map needs to have all it's descendants chains also removed.
            // Find all the descendants and add them to the exclusion set.
            if (mapDagTxns.count(mi.first))
            {
                const auto pDoubleSpend = mapDagTxns[mi.first];
                std::set<CTransactionRef> descendants;
                descendants.insert(pDoubleSpend);

                while (!descendants.empty())
                {
                    auto ptx = *descendants.begin();
                    descendants.erase(ptx);
                    for (unsigned int j = 0; j < ptx->vout.size(); j++)
                    {
                        const auto &outpoint = ptx->OutpointAt(j);
                        if (mapInputs.count(outpoint))
                        {
                            auto pNewDescendant = mapInputs[outpoint];
                            descendants.insert(pNewDescendant);
                            setTxnExclusions.insert(pNewDescendant->GetId());
                        }
                    }
                }
            }
        }
    }

    return setTxnExclusions;
}

// Tailstorm Tree
CTreeNodeRef CTailstormTree::Insert(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    DbgAssert(newNode->subblock != nullptr, );
    if (!newNode->subblock)
        return CTreeNodeRef();

    // Add to the tree
    auto element = dag.find(newNode->hash);
    if (element == dag.end()) // We need to add it if it does not already exist
    {
        // Check if we're trying to insert into the tree of the current active summary block tip.
        // If not then we just return true but without setting the fProcessed flag. This way we keep
        // this new tree node linked into a dag but we can process the subblock later if/when
        // we reorg to its summary block root. (This process is analagous to when
        // we accept summary block headers and blocks but don't connect them yet because
        // they're not on the best chain yet).
        if (pindexSummaryRoot && (chainActive.Tip() != pindexSummaryRoot))
        {
            // Alhough we haven't processed this block yet we later need to know
            // the sequence id.
            newNode->nSequenceId = dag.size() + 1;
            DbgAssert(newNode->nSequenceId > 0, );
            dag.emplace(newNode->hash, newNode);
            return newNode;
        }

        bool fMissingOrSpent = false;
        std::set<CTreeNodeRef> setConflictingSubblocks;
        CValidationState state;
        CCoinsViewCache upperview(view);
        bool fOK = true;
        {
            const CChainParams &chainparams = Params();
            bool fJustCheck = false;
            bool fParallel = false;
            bool fScriptChecks = true;
            CAmount nFees = 0;
            CBlockUndo blockundo;
            std::vector<std::pair<uint256, CDiskTxPos> > vPos;
            vPos.reserve(newNode->subblock->vtx.size());
            std::map<CGroupTokenID, CAmount> accumulatedMintages;
            std::map<CGroupTokenID, CAuth> accumulatedAuthorities;

            // Try connecting the block and updating the coins cache.  If successful then we can remove
            // the transactions from the mempool.
            // TODO: connect canonical needs to still prepare the upper view with valid coins
            // even if we find a conflict because we later need to flush the view.
            if (!ConnectBlockCanonicalOrdering(newNode->subblock, state, pindexSummaryRoot, upperview, chainparams,
                    fJustCheck, fParallel, fScriptChecks, nFees, blockundo, vPos, accumulatedMintages,
                    accumulatedAuthorities, &mapDagTxns))
            {
                fOK = false;
                LOG(DAG, "%s(): subblock did not connect: %s", __func__, newNode->hash.ToString());
                int nDos = 0;
                if (state.IsInvalid(nDos))
                {
                    // Check if this subblock is double spending anything in the dag
                    // and if so then fork a new dag and use this subblock as it's
                    // tip.
                    if (state.GetRejectCode() == REJECT_CONFLICT)
                    {
                        fMissingOrSpent = true;
                    }
                }
            }
        }

        if (fMissingOrSpent)
        {
            // The following code verifies whether we actually have a true double spend of if the block has
            // missing inputs. If it has missing inputs then we reject it completely. If it is a double spend
            // then we process it further and add it to the tracking map.
            LOG(DAG, "%s: subbblock %s is potentially a double spend block: %s", __func__, newNode->hash.ToString(),
                state.GetLogString());


            // Create the outpoint map
            std::map<COutPoint, CTransactionRef> mapOutpoints;
            for (CTransactionRef ptx : newNode->subblock->vtx)
            {
                if (ptx->IsCoinBase())
                    continue;

                for (size_t j = 0; j < ptx->vin.size(); j++)
                {
                    mapOutpoints[ptx->vin[j].prevout] = ptx;
                }
            }

            // Cycle through the dag from highest sequence id to lowest looking for a conflicting subblock.
            std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(dag.begin(), dag.end());
            std::sort(vSortedDag.begin(), vSortedDag.end(),
                [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
            for (auto it = vSortedDag.rbegin(); it != vSortedDag.rend(); it++)
            {
                for (CTransactionRef ptx : it->second->subblock->vtx)
                {
                    if (ptx->IsCoinBase())
                        continue;

                    std::map<uint256, CTreeNodeRef> mapTxns;
                    for (size_t j = 0; j < ptx->vin.size(); j++)
                    {
                        if (mapOutpoints.count(ptx->vin[j].prevout))
                        {
                            setConflictingSubblocks.insert(it->second);
                            mapTxns.emplace(ptx->GetId(), it->second);
                            mapTxns.emplace(mapOutpoints[ptx->vin[j].prevout]->GetId(), newNode);
                        }
                    }
                    if (!mapTxns.empty())
                    {
                        vDoubleSpendTxns.push_back(mapTxns);
                    }
                }
            }

            if (!setConflictingSubblocks.empty())
            {
                LOG(DAG, "%s: Found %ld Conflicting subblock(s)", __func__, setConflictingSubblocks.size());

                // If this subblock has its double spent subblock in it's ancestor tree then we "must" reject it.
                auto setAncestors = CalculateAncestors(newNode);
                bool fHasDoubleSpentAncestor = false;
                for (auto &node : setConflictingSubblocks)
                {
                    if (setAncestors.count(node))
                    {
                        fHasDoubleSpentAncestor = true;
                        break;
                    }
                }
                if (fHasDoubleSpentAncestor)
                {
                    LOG(DAG, "%s: Rejected - subbblock %s has a double spend in its ancestor tree: %s", __func__,
                        newNode->hash.ToString(), state.GetLogString());
                    return CTreeNodeRef();
                }
                else
                {
                    // If it's a true and acceptable conflicting subblock then we will accept it.
                    LOG(DAG, "%s: Accepted - subbblock %s double spend not in ancestor tree: %s", __func__,
                        newNode->hash.ToString(), state.GetLogString());
                    fOK = true;
                }
            }
            else
            {
                fOK = false;
                LOG(DAG, "%s: not adding subbblock %s because some inputs are missing: %s", __func__,
                    newNode->hash.ToString(), state.GetLogString());
            }
        }

        if (!fOK)
        {
            LOG(DAG, "%s: subbblock %s failed to validate: %s", __func__, newNode->hash.ToString(),
                state.GetLogString());

            return CTreeNodeRef();
        }
        else
        {
            // Stop txadmission, and flush the commitQ, before we flush coin state, remove txn conflicts and
            // set the active tree as well as pcoinsDag.
            TxAdmissionPause txlock;

            // Update the sequence id
            newNode->nSequenceId = dag.size() + 1;
            DbgAssert(newNode->nSequenceId > 0, );
            dag.emplace(newNode->hash, newNode);
            // Update the map of all current dag transactions. This must be done before
            // we continue processing, especially is we have a double spend block and
            // we need to re-generate the dag data.
            for (CTransactionRef ptx : newNode->subblock->vtx)
            {
                if (ptx->IsCoinBase())
                    continue;

                mapDagTxns.emplace(ptx->GetId(), ptx);

                for (auto &input : ptx->vin)
                {
                    mapInputs.emplace(input.prevout, ptx);
                }
            }

            // After the subblock is validated without error we can flush coin state
            bool result = upperview.Flush();
            assert(result);

            std::list<CTransactionRef> txConflicted;
            // TODO: leave this commented code block as it will be useful in the future.
            // mempool.removeForBlock(pblock->vtx, pblock->height, txConflicted, true);
            // Process orphan pool for transactions in block but do deferr it to be done
            // in another thread.
            // LOCK(orphanpool.cs_blockprocessing);
            // orphanpool.vPostBlockProcessing.push_back(pblock);

            // Remove conflicting txns from the txpool
            {
                WRITELOCK(mempool.cs_txmempool);
                for (const auto &tx : newNode->subblock->vtx)
                {
                    mempool._removeConflicts(*tx, txConflicted);
                }
            }

            CTailstormGroveRef grove = nullptr;
            if (tailstormForest.GetGrove(*(pindexSummaryRoot->phashBlock), grove))
            {
                // If we had a double spend then regenerate all the dag data, exluding all
                // the low score double spends.
                if (!setConflictingSubblocks.empty())
                {
                    // This can delete this block from the grove.  If so, fProcessed will be false
                    tailstormForest.GenerateDagData(grove);
                }
                else
                {
                    // Set the processed flag
                    newNode->fProcessed = true;

                    // Set pcoinsDag to the best dag in the Forest.
                    tailstormForest.SetDagCoinsTip();
                }
            }

            cvCommitQ.notify_all();
        }

        // We found a conflict, regenerated the DAG data and this block was rejected, so return false
        if (!newNode->fProcessed)
            return CTreeNodeRef();
        DbgAssert(newNode->nSequenceId > 0, );
        return newNode;
    }

    newNode = element->second;
    DbgAssert(newNode->nSequenceId > 0, ); // make sure this was inserted into a grove properly
    return newNode; // must return true because we already have it and don't want it deleted from the grove
}

// Tailstorm Grove
bool CTailstormGrove::InitializeTree(CTreeNodeRef newNode, CCoinsViewCache *coinsCache)
{
    AssertLockHeld(tailstormForest.cs_forest);

    assert(coinsCache);
    assert(newNode);

    if (!newNode->subblock)
        return false;

    roothash = newNode->subblock->hashPrevBlock;

    tree->_pcoinsTip = coinsCache;
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
        tailstormForest.mapAllNodes.erase(mi.first);
        tailstormForest.mapAllGrovesByNode.erase(mi.first);
    }

    mapGroveNodes.clear();
}

CTreeNodeRef CTailstormGrove::InsertIntoTree(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    if (!newNode->subblock)
        return CTreeNodeRef();

    // Check the tree and make sure we don't already have this item.
    {
        auto item = tree->dag.find(newNode->hash);
        if (item != tree->dag.end())
        {
            tailstormForest.mapNodesUnlinked.erase(newNode->hash);
            LOG(DAG, "%s(): Not inserting new node since treenode already exists", __func__);
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
                    return CTreeNodeRef();
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
                    return CTreeNodeRef();
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

        // Update the uncles map with any "new" uncles that may have arrived.
        auto mapUncles = tailstormForest.GetUncles(newNode);
        for (auto &mi : mapUncles)
        {
            if (!tree->mapUncles.count(mi.first))
            {
                tree->mapUncles.emplace(mi.first, mi.second);

                // Notify the dagviewer of any "new" uncles.
                uint32_t nDagHeight = 1; // uncles should always be viewed at this height.
                uiInterface.NotifyDagViewerUncle(!IsInitialSyncComplete(), nDagHeight, 0,
                    mi.second->subblock->GetBlockHeader(), mi.second->roothash);
            }
        }
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
        return CTreeNodeRef();
    }

    return newNode;
}

CTreeNodeRef CTailstormGrove::Insert(CTreeNodeRef newNode)
{
    AssertLockHeld(tailstormForest.cs_forest);

    return InsertIntoTree(newNode);
}

bool CTailstormGrove::GetBestDag(std::set<CTreeNodeRef> &dag,
    std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> *mapInputs)
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


            dag.insert(node);
            if (dag.size() == nNumSubblocksToReturn)
                break;
        }
    }

    if (!dag.empty())
    {
        if (vDoubleSpendTxns != nullptr)
            *vDoubleSpendTxns = tree->vDoubleSpendTxns;
        if (mapInputs != nullptr)
            *mapInputs = tree->mapInputs;
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
        if (iter->second->subblock && (iter->second->subblock->height <= nPruneHeight))
        {
            const uint256 &hash = iter->first;
            LOG(DAG, "pruning subblock %s at height %ld\n", hash.ToString(), iter->second->subblock->height);

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
        mapNodesUnlinked.erase(subblock->GetHash());

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

    auto subblock = newNode->subblock;

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

        bool fHavePrevGrove = false;
        if (pindex)
        {
            CTailstormGroveRef dummyGrove = nullptr;
            fHavePrevGrove = GetGrove(*(pindex->pprev->phashBlock), dummyGrove);
        }
        if (pindex && (pindex->height() == chainActive.Height()))
            fHavePrevGrove = true;

        if (pindex && pindex->IsLinked() && fHavePrevGrove)
        {
            // Make sure the height of this subblock is 1 more than the previous summary block
            if (subblock->height != pindex->height() + 1)
            {
                LOG(DAG, "%s: invalid subblock height %ld should be %ld - could not add subblock to grove", __func__,
                    subblock->height, pindex->height() + 1);
                return false;
            }

            // Check the chainwork when the subblock gets connected to a grove
            auto expectedNbits = GetNextWorkRequired(pindex, &(*subblock), Params().GetConsensus());
            auto expectedChainWork = ArithToUint256(pindex->chainWork() + GetWorkForDifficultyBits(expectedNbits));
            if (subblock->chainWork != expectedChainWork)
            {
                LOG(DAG, "%s: invalid chainwork - could not add subblock to grove", __func__);
                return false;
            }
            // Add new grove and/or insert subblock
            CTailstormGroveRef grove = nullptr;
            if (GetGrove(subblock->hashPrevBlock, grove))
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
        // Find the best treenode tip out of all the dags and update
        // the atomic pointer.
        std::set<CTreeNodeRef> dag;
        GetBestDagFor(subblock->hashPrevBlock, dag);
        CTreeNodeRef bestnode = FindDagTipNode(dag);
        if (bestnode)
            SetDagActiveTip(bestnode);
    }
    else
    {
        LOG(DAG, "%s(): forest insertion failed for subblock %s", __func__, newNode->hash.GetHex());
        mapAllGrovesByNode.erase(newNode->hash);
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
    LOG(DAG, "Adding subblock orphan (removing from groves and unlinked): %s", newNode->hash.ToString());
    newNode->setAncestors.clear();
    newNode->setDescendants.clear();
    newNode->fProcessed = false;
    newNode->fUncle = false;
    mapAllGrovesByNode.erase(newNode->hash);
    mapNodesUnlinked.emplace(newNode->hash, newNode);
}

void CTailstormForest::RemoveSubblockOrphan(const ConstCBlockRef &pblock)
{
    LOCK(cs_forest);
    LOG(DAG, "Remove subblock orphan: %s", pblock->GetHash().ToString());
    mapNodesUnlinked.erase(pblock->GetHash());
}


std::set<uint256> CTailstormForest::ProcessOrphans()
{
    AssertLockHeld(cs_forest);
    processingOrphans = true;
    std::set<uint256> setAllLinked;
    while (true)
    {
        // Make sure to remove any blocks from the summary block orphan map that are already connected before
        // we process the subblock orphans since the connecting subblock orphans depends on whether there
        // exists a connected summary block.
        for (auto iter = mapSummaryBlocksUnlinked.begin(); iter != mapSummaryBlocksUnlinked.end();)
        {
            CTailstormGroveRef grove = nullptr;
            const ConstCBlockRef &pblock = iter->second;
            bool fBlockAlreadyConnected = GetGrove(pblock->GetHash(), grove);
            if (fBlockAlreadyConnected)
            {
                iter = mapSummaryBlocksUnlinked.erase(iter);
            }
            else
            {
                iter++;
            }
        }

        // Process subblock orphans
        std::set<uint256> setLinked;

        bool changes = true;
        while (changes)
        {
            changes = false;
            // Move all current orphans to a new map
            std::map<uint256, CTreeNodeRef> orphans;
            while (!mapNodesUnlinked.empty())
            {
                orphans.insert(std::move(mapNodesUnlinked.extract(mapNodesUnlinked.begin())));
            }
            // Now stick them into the dag or back into the orphans list
            for (auto iter = orphans.begin(); iter != orphans.end(); ++iter)
            {
                const auto &subblock = iter->second->subblock;
                assert(subblock);
                const uint256 &prevhash = subblock->hashPrevBlock;
                auto pindex = LookupBlockIndex(prevhash);

                auto setHashes = GetPrevHashes(subblock->GetBlockHeader());
                bool fHaveAllPrevSubblocks = true;
                for (auto &hash : setHashes)
                {
                    if (hash == prevhash)
                        continue;

                    if (!mapAllGrovesByNode.count(hash))
                    {
                        fHaveAllPrevSubblocks = false;
                    }
                }

                bool placed = false;
                if (((pindex && pindex->IsLinked()) && fHaveAllPrevSubblocks) &&
                    !mapSummaryBlocksUnlinked.count(prevhash))
                {
                    auto hash = iter->second->hash;
                    LOG(DAG, "%s(): process orphans - found subblock orphan %s connecting to prev summary block %s",
                        __func__, hash.ToString(), prevhash.ToString());
                    placed = true;
                    if (_Insert(iter->second)) // This will insert the tx into the orphan map on orphan-caused-failure
                    {
                        LOG(DAG, "%s(): Success: Insert of subblock orphan %s connecting to prev summary block %s",
                            __func__, __func__, hash.ToString(), prevhash.ToString());
                        setLinked.insert(hash);
                        changes = true;
                    }
                }
                if (!placed)
                {
                    LOG(DAG, "%s(): Cannot insert orphan subblock %s returning to unlinked map (size %ld)", __func__,
                        iter->second->hash.ToString(), mapNodesUnlinked.size());
                    mapNodesUnlinked.emplace(iter->first, iter->second);
                }
            }
        }

        // Process any summary block orphans that has all subblocks present and valid in the dag.
        // NOTE: we don't add the summary block to setLinked because block processing doesn't
        // finish in this thread so we can't be sure it's linked.  It will instead get announced
        // once the block successfully connects to the blockchain.
        bool fLinkedASummaryBlock = false;
        for (auto iter2 = mapSummaryBlocksUnlinked.begin(); iter2 != mapSummaryBlocksUnlinked.end();)
        {
            const ConstCBlockRef pblock = iter2->second;
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
                    mapSummaryBlocksUnlinked.erase(iter2);
                    LEAVE_CRITICAL_SECTION(cs_forest);

                    // locking cs_main here prevents any other thread from starting a block validation.
                    {
                        LOCK(cs_main);
                        bool forceProcessing = true;
                        CValidationState state;
                        ProcessNewBlock(state, Params(), nullptr, pblock, forceProcessing, nullptr, false);
                        LOG(DAG, "%s(): Done processing new block and connected an orphaned summary block", __func__);
                    }
                    ENTER_CRITICAL_SECTION(cs_forest);

                    // Because we dropped the lock and took it again the iteration may now
                    // have been invalidated by some other thread so set the iterator to the
                    // beginning again. While theoretically it could be a very small performance
                    // hit, in reality it's unlikely there will even be any other entries in the map
                    // to process anyway.
                    fLinkedASummaryBlock = true;
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
        else if (!fLinkedASummaryBlock)
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

bool CTailstormForest::GetBestDagFor(const uint256 &hash,
    std::set<CTreeNodeRef> &dag,
    std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> *mapInputs)
{
    LOCK(cs_forest);
    LOG(DAG, "%s(): Start getbestdagfor", __func__);

    CTailstormGroveRef grove = nullptr;
    if (GetGrove(hash, grove))
    {
        if (!grove->GetBestDag(dag, vDoubleSpendTxns, mapInputs))
        {
            LOG(DAG, "%s(): get best dag returned false", __func__);
            return false;
        }
        LOG(DAG, "%s(): got grove and returning best dag", __func__);
        // for (auto item : dag)
        //     LOG(DAG, "%s():     best dag item: %s nSequenceId: %d fProcessed: %d", __func__, item->hash.ToString(),
        //         item->nSequenceId, item->fProcessed);
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

bool CTailstormForest::GetDagForBlock(ConstCBlockRef &pblock,
    std::set<CTreeNodeRef> &dag,
    std::vector<std::map<uint256, CTreeNodeRef> > *vDoubleSpendTxns,
    std::map<COutPoint, CTransactionRef> *mapInputs)
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
            *vDoubleSpendTxns = tree->vDoubleSpendTxns;
            *mapInputs = tree->mapInputs;
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
    LOG(DAG, "%s(): get grove for %s\n", __func__, hash.ToString());

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
        assert(!mi.second->roothash.IsNull());
        if (hash == mi.second->roothash)
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

    // Only allow one thread to run re-org at a time.
    TRY_LOCK(cs_reorg, lock);
    if (!lock)
        return;

    CTailstormGroveRef grovetip = nullptr;
    CBlockIndex *chainTip = chainActive.Tip();
    CBlockIndex *pindexMostWork = chainTip;
    arith_uint256 nChainTipWork = chainTip->chainWork();
    arith_uint256 nMaxChainWork = chainTip->chainWork();

    LOG(DAG, "%s(): current chain active height %ld for %s", __func__, chainTip->height(),
        chainTip->phashBlock->ToString());
    {
        LOCK(cs_forest);

        // Find all groves
        std::set<CTailstormGroveRef> setAllGroves;
        for (auto &mi : mapAllGrovesByNode)
            setAllGroves.insert(mi.second);

        // Get the chainwork of the current chainactive tip plus all the subblocks in it's dag
        //
        // The chainwork includes "all" subblocks for the full dag, so uncles as well as dag blocks.
        std::set<CTreeNodeRef> tipdag;
        GetFullDagFor(*chainTip->phashBlock, tipdag);
        for (auto node : tipdag)
        {
            nChainTipWork += GetWorkForDifficultyBits(node->subblock->nBits);
        }

        // Cycle through all the trees of each grove and find the chainWork
        for (auto &grove : setAllGroves)
        {
            arith_uint256 nTreeChainWork = grove->tree->pindexSummaryRoot->chainWork();
            std::set<CTreeNodeRef> dag;
            GetFullDagFor(grove->roothash, dag);
            for (auto node : dag)
            {
                nTreeChainWork += GetWorkForDifficultyBits(node->subblock->nBits);
            }
            if (nTreeChainWork > nMaxChainWork && nTreeChainWork > nChainTipWork)
            {
                nMaxChainWork = nTreeChainWork;
                pindexMostWork = grove->tree->pindexSummaryRoot;
                grovetip = grove;

                LOG(DAG, "%s : pindexMostWork %s > chaintip %s\n", __func__, pindexMostWork->phashBlock->ToString(),
                    chainTip->phashBlock->ToString());
            }
        }
    }

    if (!pindexMostWork)
    {
        LOG(DAG, "%s():  could not find pindexMostWork for reorg", __func__);
    }

    if (pindexMostWork && !(pindexMostWork->nStatus & BLOCK_HAVE_DATA))
    {
        LOG(DAG, "%s():  WARNING: block data is not present for Reorg: %s", __func__,
            pindexMostWork->phashBlock->ToString());
        return;
    }

    // Initiate reorg if there is a tree with greater work on another fork
    const CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);
    if ((nMaxChainWork > nChainTipWork) && (chainTip != pindexFork))
    {
        LOG(DAG, "%s(): Attempting to initiate a reorg from %s at height %d to %s at height %d", __func__,
            chainTip->phashBlock->ToString(), chainTip->height(), pindexMostWork->phashBlock->ToString(),
            pindexMostWork->height());

        {
            LOCK(cs_main);
            LOCK(cs_forest);
            TxAdmissionPause txlock;

            if (chainTip != chainActive.Tip())
            {
                LOG(DAG, "%s():  failed to reorg to %s because chain active tip changed", __func__,
                    pindexMostWork->phashBlock->ToString());
                return;
            }

            CValidationState state;
            const CChainParams &chainparams = Params();
            if (!ActivateBestChainStep(state, chainparams, pindexMostWork, nullptr, false))
            {
                LOG(DAG, "%s():  failed to reorg to %s", __func__, pindexMostWork->phashBlock->ToString());
            }
            else
                LOG(DAG, "%s():  completed a reorg to %s", __func__, pindexMostWork->phashBlock->ToString());

            // Rebuild the each tree's coinscache and data structures on the grove we've now set as our best chain tip.
            // We only need to build data for unprocessed subblocks.
            GenerateDagData(grovetip);
        }
    }

    return;
}

void CTailstormForest::GenerateDagData(CTailstormGroveRef grove)
{
    AssertLockHeld(cs_forest);
    DbgAssert(
        txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("Do not have corral pause during activate best tree"));

    // Rebuild the each tree's coinscache and data structures on the grove we've now set as our best chain tip.
    // We only need to build data for unprocessed subblocks.
    CValidationState state;
    auto chainparams = Params();
    auto &tree = grove->tree;
    {
        // Get the exclusion set for this dag which is used to pass to connect block and allow
        // processing to continue without a missing inputs error begin returned. This exlusion set is needed
        // because mapDagTxns, which is also used to skip processing a transaction twice,
        // does not get created until the block has succesfully finished connecting.
        std::vector<std::map<uint256, CTreeNodeRef> > vDoubleSpendTxns;
        std::map<COutPoint, CTransactionRef> mapInputs;
        std::set<CTreeNodeRef> setDag;
        for (auto mi : tree->dag)
            setDag.insert(mi.second);
        std::set<uint256> setTxnExclusions = GetTxnExclusionSet(setDag, tree->vDoubleSpendTxns, tree->mapInputs);

        // TODO: In the future we could check first if we have a higher score ds before
        // and only clear everything if we need to rebuild entirely. But for now
        // just rebuild everything.
        tree->mapDagTxns.clear();
        tree->mapInputs.clear();
        tree->view->Clear();

        std::vector<std::pair<uint256, CTreeNodeRef> > vSortedDag(tree->dag.begin(), tree->dag.end());
        std::sort(vSortedDag.begin(), vSortedDag.end(),
            [](const auto &a, const auto &b) { return a.second->nSequenceId < b.second->nSequenceId; });
        uint32_t nSequenceId = 0;
        for (auto it = vSortedDag.begin(); it != vSortedDag.end(); it++)
        {
            nSequenceId++;
            const CTreeNodeRef &treenode = it->second;
            // if (treenode->fProcessed) TODO: for now rebuild everything.
            //     continue;

            bool fJustCheck = false;
            bool fParallel = false;
            bool fScriptChecks = true;
            CAmount nFees = 0;
            CBlockUndo blockundo;
            std::vector<std::pair<uint256, CDiskTxPos> > vPos;
            vPos.reserve(treenode->subblock->vtx.size());
            std::map<CGroupTokenID, CAmount> accumulatedMintages;
            std::map<CGroupTokenID, CAuth> accumulatedAuthorities;

            // Try connecting the subblock and updating the coins cache.
            if (ConnectBlockCanonicalOrdering(treenode->subblock, state, tree->pindexSummaryRoot, *tree->view,
                    chainparams, fJustCheck, fParallel, fScriptChecks, nFees, blockundo, vPos, accumulatedMintages,
                    accumulatedAuthorities, &tree->mapDagTxns, &setTxnExclusions))
            {
                // Rebuild the mapDagTxns as subblocks are connected.
                for (CTransactionRef ptx : treenode->subblock->vtx)
                {
                    if (ptx->IsCoinBase())
                        continue;

                    tree->mapDagTxns.emplace(ptx->GetId(), ptx);

                    for (auto &input : ptx->vin)
                    {
                        tree->mapInputs.emplace(input.prevout, ptx);
                    }
                }

                treenode->fProcessed = true;
                treenode->nSequenceId = nSequenceId;
            }
            else
            {
                tree->dag.erase(treenode->hash);
                grove->mapGroveNodes.erase(treenode->hash);
                nSequenceId--;
                treenode->fProcessed = false;
                treenode->nSequenceId = 0;
                AddSubblockOrphan(treenode);
                LOG(DAG, "%s():  Unable to process subblock while generating data: %s", __func__,
                    treenode->hash.ToString());
            }
        }
    }

    tailstormForest.SetDagCoinsTip();
}

void CTailstormForest::SetDagCoinsTip()
{
    AssertLockHeld(tailstormForest.cs_forest);
    DbgAssert(
        txProcessingCorral.region() == CORRAL_TX_PAUSE, LOGA("Do not have corral pause during activate best tree"));

    if (!chainActive.Tip())
        return;

    // Cycle through all the trees of each grove and find the chainWork
    arith_uint256 nMaxChainWork = chainActive.Tip()->chainWork();
    bestGrove = nullptr;

    // Find all groves
    std::set<CTailstormGroveRef> setAllGroves;
    for (auto &mi : mapAllGrovesByNode)
        setAllGroves.insert(mi.second);

    for (auto &grove : setAllGroves)
    {
        arith_uint256 nTreeChainWork = grove->tree->pindexSummaryRoot->chainWork();
        std::set<CTreeNodeRef> dag;
        GetBestDagFor(grove->roothash, dag);
        for (auto node : dag)
        {
            nTreeChainWork += GetWorkForDifficultyBits(node->subblock->nBits);
        }
        if (nTreeChainWork > nMaxChainWork)
        {
            nMaxChainWork = nTreeChainWork;
            DbgAssert(grove->view, );
            bestGrove = grove;
        }
    }
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
    std::map<uint256, CTreeNodeRef> mapUncles;

    // Find and include subblock uncles
    CTailstormGroveRef grove = nullptr;
    if (GetGrove(treenode->hash, grove))
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
    // If the node is unlinked, it will not be anywhere else so just remove it from the unlinked list and we are done
    if (mapNodesUnlinked.count(hash))
    {
        mapNodesUnlinked.erase(hash);
        return true;
    }

    std::map<uint256, CTreeNodeRef> oldDag;
    CTailstormGroveRef grove = nullptr;
    if (GetGrove(hash, grove)) // If the subblock is in a grove, clean it out of there
    {
        mapAllNodes.erase(hash);
        mapAllGrovesByNode.erase(hash);
        grove->mapGroveNodes.erase(hash);

        // Erase from uncles first. If nothing was there
        // then try to erase from the dag.
        if (grove->tree->mapUncles.count(hash))
        {
            grove->tree->mapUncles.erase(hash);
            return true;
        }
        else if (grove->tree->dag.count(hash))
        {
            LOG(DAG, "%s(): Removing %s from grove %s requires complete grove reassessment.\n", __func__,
                hash.ToString(), grove->roothash.ToString());
            grove->tree->dag.erase(hash);

            // Clear all the data from the tree.
            grove->tree->view->Clear();
            grove->tree->vDoubleSpendTxns.clear();
            grove->tree->mapInputs.clear();
            grove->tree->mapDagTxns.clear();

            // Now that we've deleted from the dag we have
            // to resubmit everything and re-process.
            grove->tree->dag.swap(oldDag);
            for (auto mi : oldDag)
            {
                AddSubblockOrphan(mi.second);
            }
            ProcessOrphans();
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
            std::vector<std::map<uint256, CTreeNodeRef> > vDoubleSpendTxns;
            std::map<COutPoint, CTransactionRef> mapInputs;
            std::set<CTreeNodeRef> setDag;
            if (tailstormForest.GetDagForBlock(mi.second, setDag, &vDoubleSpendTxns, &mapInputs))
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
        auto &tree = grove->tree;
        {
            for (auto &mi : tree->dag)
            {
                assert(grove->mapGroveNodes.count(mi.first));
                assert(grove->mapGroveNodes[mi.first] == mi.second);
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
                    LOG(DAG, "ERROR: Grove node is in unlinked (orphan) list: %s", groveNode.first.ToString());
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

            // Check tree mapDagTxns is correctly reflecting the tree
            nTreeTxnCount += mi.second->subblock->vtx.size() - 1;

            // Check hash
            assert(mi.first == mi.second->hash);
        }
        assert(nTreeTxnCount >= tree->mapDagTxns.size());

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
    auto unlinked = UniValue(UniValue::VARR);
    for (auto &mnu : mapNodesUnlinked)
    {
        unlinked.push_back(mnu.second->hash.ToString());
    }
    info.pushKV("unlinked_subblock_list", unlinked);

    auto subblockToGrove = UniValue(UniValue::VOBJ);
    for (auto &mnu : mapAllGrovesByNode)
    {
        subblockToGrove.pushKV(
            mnu.first.ToString(), std::to_string(mnu.second->nRootHeight) + ":" + mnu.second->roothash.ToString());
    }
    info.pushKV("subblock_to_grove_summaryblock", subblockToGrove);
    return info;
}
