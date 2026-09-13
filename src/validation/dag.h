// Copyright (c) 2020-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_TAILSTORM_DAG_H
#define NEXA_TAILSTORM_DAG_H


#include "chain.h"
#include "coins.h"
#include "primitives/block.h"
#include "sync.h"

#include <atomic>
#include <deque>
#include <queue>
#include <set>

extern CChain chainActive;
extern CCoinsViewCache *pcoinsTip;

static const uint32_t DEFAULT_UNCLE_SCORE_ADJUSTMENT = 4;

class CTreeNode;
class CDagConflictRegistry;
class CTailstormTree;
typedef std::shared_ptr<CTailstormTree> CTailstormTreeRef;
typedef std::shared_ptr<CTreeNode> CTreeNodeRef;
template <typename Node>
static inline CTreeNodeRef MakeTreeNodeRef(Node &&nodeIn)
{
    return std::make_shared<CTreeNode>(std::forward<Node>(nodeIn));
}
class CTailstormGrove;
typedef std::shared_ptr<CTailstormGrove> CTailstormGroveRef;
template <typename Grove>
static inline CTailstormGroveRef MakeTailstormGroveRef(Grove &&groveIn)
{
    return std::make_shared<CTailstormGrove>(std::forward<Grove>(groveIn));
}

// Return a map of all the subblock scores for any nodes in the dag
// NOTE: An int32_t is used because scores can temporarily go negative during the calculation process.
std::map<CTreeNodeRef, uint32_t> GetDagScores(const std::vector<CTreeNodeRef> &dagNodes);
// Adapter for callers that hold the dag as a set.
std::map<CTreeNodeRef, uint32_t> GetDagScores(const std::set<CTreeNodeRef> &dagNodes);

/** Get the transactions in the passed dag that are considered potentially invalid and must not be included in the
    summary block.  These are conflict losers (where a conflicting tx exists with a lower score) and txs whose inputs
    are unknown, because we cannot easily tell a doublespend from a bogus input.

    Transactions that are unambiguously invalid still invalidate the entire subblock, so would not appear here because
    their subblock would not even be in the setBestDag.

    Pass the tree that produced this dag; its conflict registry and its coins at the summary root are read from it.
    Obtain that tree from the same call that produced the dag: [GetBestDagFor] and [GetDagForBlock] both return it.
    cs_forest must be held for the duration of the call, because the tree's registry is read under it.

    @param dag The DAG to analyze
    @param tree The tree that this DAG is a subset of (used to get the DAG root summary block coins view).
    @param losers The transactions that are being rejected due to a preferred double spend.  So this set does not count
                  their descendants or transactions with unknown inputs.

    @returns all transactions that must be excluded from the summary block or any coins view
*/
std::set<uint256> GetTxnExclusionSet(std::vector<CTreeNodeRef> dagNodes,
    const CTailstormTree &tree,
    std::set<uint256> *losers = nullptr);
// Adapter for callers that hold the dag as a set.
std::set<uint256> GetTxnExclusionSet(const std::set<CTreeNodeRef> &dagNodes,
    const CTailstormTree &tree,
    std::set<uint256> *losers = nullptr);

/** Get the transactions in the passed dag that are considered potentially invalid and must not be included in the
    summary block.  These are conflict losers (where a conflicting tx exists with a lower score) and txs whose inputs
    are unknown, because we cannot easily tell a doublespend from a bogus input.

    An invalid transaction invalidates its whole subblock, and connect rejects such a subblock at insert. A
    transaction omitted at insert for a missing input escapes that check until it is retried from missingInputs;
    if it fails then, the subblocks containing it are removed at the next regeneration, for consistency with the verdict
    connect reaches when the input is present.

    This function also requires the UTXO set [CCoinsViewCache] at the point where this DAG should be applied,
    that is, it should at the root summary block.
*/
// dagNodes is taken by value and sorted in place, so callers that no longer need
// their vector should std::move() it in.
std::set<uint256> GetTxnExclusionSet(std::vector<CTreeNodeRef> dagNodes,
    const CDagConflictRegistry &registry,
    const CCoinsViewCache *pcoins = nullptr,
    std::set<uint256> *losers = nullptr);
// Adapter for callers that hold the dag as a set.
std::set<uint256> GetTxnExclusionSet(const std::set<CTreeNodeRef> &dagNodes,
    const CDagConflictRegistry &registry,
    const CCoinsViewCache *pcoins = nullptr,
    std::set<uint256> *losers = nullptr);

// Is the tailstorm dag activated and ready to receive subblocks
bool IsTailstormDagActivated();

class CTreeNode
{
public:
    uint256 hash; // the subblock hash that is this node
    uint32_t dagHeight = 0;
    // nSequenceId is the order of arrival/insertion of this node into the tree it gets inserted into.
    // If 0, this node is not in a tree.
    // Within the tree, this is used to recover the order in which the subblock was received.
    uint32_t nSequenceId = 0;
    bool fProcessed = false;
    bool fUncle = false; // is this a subblock (uncle) from the previous summary block
    uint256 roothash; // the summary block hash of the dag that the treenode is being added to.

    ConstCBlockRef subblock = nullptr;

    std::set<CTreeNodeRef> setAncestors; // points to the parents of this subblock
    std::set<CTreeNodeRef> setDescendants; // points to the nodes of the children

    CTreeNode() {}

    CTreeNode(ConstCBlockRef _subblock)
    {
        hash = _subblock->GetHash();
        subblock = _subblock;
    }

    friend bool operator<(const CTreeNode a, const CTreeNode b) { return a.hash < b.hash; }

    void AddAncestors(std::set<CTreeNodeRef> &ancestors) { setAncestors.insert(ancestors.begin(), ancestors.end()); }
    void AddDescendant(CTreeNodeRef _descendent) { setDescendants.emplace(_descendent); }
    void RemoveDescendant(CTreeNodeRef _descendent) { setDescendants.erase(_descendent); }

    // This subblock is just after the last summary block
    bool IsBase() { return (setAncestors.empty() && dagHeight == 1); }

    // This subblock is a tree tip
    bool IsTip() { return setDescendants.empty(); }
};

// One indexed spend: this txid spent this outpoint in this subblock.
// A transaction is routinely relayed in more than one subblock, so one spend is
// recorded per subblock containing the transaction. Ancestry checks use the
// subblock the spend was recorded under, so the same txid turning up in two
// subblocks is one transaction carried twice, not a double spend.
struct CDagSpend
{
    uint256 txid;
    // The subblock containing the transaction that made this spend.
    CTreeNodeRef subblock;
};

// All distinct-txid spends of one outpoint. id is assigned when the group is
// created and does not change, so lastWinner can detect a flip.
struct CDagConflictGroup
{
    uint64_t id = 0;
    COutPoint outpoint;
    std::map<uint256, CTreeNodeRef> spenders;
};

/** DAG-wide spend index and conflict registry.
    Every linked subblock (e.g. its in the DAG) is indexed, including parked ones.
    A "group" is created for every outpoint that is doublespent (repeated transactions do not count).

    Owned by a CTailstormTree and guarded by tailstormForest.cs_forest like the rest of the tree's
    state; there is no internal locking. Every method asserts that lock, and callers of the inline
    accessors must hold it too.
*/
class CDagConflictRegistry
{
    uint64_t nextId = 1;

    // Every spend in a linked subblock, keyed by the outpoint spent. When several
    // subblocks contain the same transaction each one contributes its own entry, so
    // the ancestry check can test the subblock that actually linked rather than
    // whichever subblock containing that transaction happened to be indexed first.
    std::map<COutPoint, std::vector<CDagSpend> > spendIndex;

    // The outpoints each subblock contributed to spendIndex, keyed by subblock hash,
    // so Unlink can withdraw exactly what that subblock put in.
    std::map<uint256, std::vector<COutPoint> > spendsBySubblock;

    // Hashes of the subblocks whose transactions are already committed to the index.
    std::set<uint256> indexed;

    std::map<COutPoint, CDagConflictGroup> groups;

    // Last chosen winner txid per group. Missing or changed → rebuild coins.
    std::map<uint64_t, uint256> lastWinner;

    // Record that txidA and txidB both spend outpoint. subblockA and subblockB are
    // the subblocks containing those two transactions.
    void AddGroup(const COutPoint &outpoint,
        const uint256 &txidA,
        const CTreeNodeRef &subblockA,
        const uint256 &txidB,
        const CTreeNodeRef &subblockB);
    // After Unlink removes spends, rewrite this outpoint's group from spendIndex.
    // Erase the group if fewer than two distinct txids remain.
    void UpdateGroup(const COutPoint &outpoint);

public:
    /** Compare the passed newNode's spends to this index of spends.
        @param newNode the subblock to analyze
        @param commit False is lookup only.  True applies this subblocks' tx to this registry.

        @return True if any spend conflicts with this subblock's ancestry.

        Note that following the Nexa convention, transactions in a subblock are considered to be executed
        simultaneously.  That is, they are order independent (see the "ITO" inputs-then-outputs algorithm).
    */
    bool ScanSpends(const CTreeNodeRef &newNode, bool commit);

    void Unlink(const CTreeNodeRef &node);
    void clear();

    bool Empty() const { return groups.empty(); }
    size_t GroupCount() const { return groups.size(); }
    bool IsIndexed(const uint256 &hash) const { return indexed.count(hash) != 0; }

    const std::map<COutPoint, CDagConflictGroup> &Groups() const { return groups; }
    bool GetLastWinner(uint64_t id, uint256 &txid) const
    {
        auto it = lastWinner.find(id);
        if (it == lastWinner.end())
            return false;
        txid = it->second;
        return true;
    }
    void SetLastWinner(uint64_t id, const uint256 &txid);
};

/** DAG transactions excluded only because an input is not at all in the included set.
    Doublespend "losers" are not included here because their input is not missing; we know about it, its just being
    used by a different transaction.

    TODO:
    Why do we need this class?
    When and Where is is used?

    Owned by a CTailstormTree and guarded by tailstormForest.cs_forest like the rest of the tree's
    state; there is no internal locking. Every method asserts that lock.
 */
class CDagMissingInputIndex
{
    std::map<COutPoint, std::set<uint256> > waiting;
    std::map<uint256, std::vector<COutPoint> > watchedByTx;
    std::map<uint256, CTransactionRef> txById;
    // txid -> hashes of every retained subblock containing that transaction. A transaction is
    // routinely in more than one subblock, and stays indexed while any of them remains.
    std::map<uint256, std::set<uint256> > subblockByTx;

public:
    // subblock is the hash of a subblock containing ptx. Adds that subblock; indexes ptx if new.
    void Add(const CTransactionRef &ptx, const uint256 &subblock);
    /** Adds all transaction IDs in excluded, except those in dsLosers.
     The dsLosers do not actually have a missing input, its just that a different transaction "used" it.
     */
    void Add(const CTreeNodeRef &node, const std::set<uint256> &excluded, const std::set<uint256> &dsLosers);
    void Remove(const uint256 &txid);
    // Drop one subblock of txid; the transaction leaves the index only when no subblock remains.
    void Remove(const uint256 &txid, const uint256 &subblock);
    void clear();
    // Take every tx waiting on this outpoint off the index. Each result pairs the
    // transaction with the hashes of the subblocks containing it.
    std::vector<std::pair<CTransactionRef, std::set<uint256> > > RemoveFor(const COutPoint &outpoint);
};

// All data members are protected by cs_forest
class CTailstormTree
{
    friend class CTailstormGrove;
    friend class CTailstormForest;
    friend class CTailstormForestTest;
    // Reads conflictRegistry and _pcoinsSummaryRoot.
    friend std::set<uint256> GetTxnExclusionSet(std::vector<CTreeNodeRef> dagNodes,
        const CTailstormTree &tree,
        std::set<uint256> *losers);

protected:
    // pointers point to the nodes for this dag, a pointer to the same node is
    // also available in mapAllNodes at the forest level
    std::map<uint256, CTreeNodeRef> dag;

    // A map of uncles. Uncles are orphans that didn't get included in the last
    // summary block bbut which we could use in the current summary block. Uncles
    // could be subblocks and/or summary blocks.
    std::map<uint256, CTreeNodeRef> mapUncles;

    // map of unique transactions that are already in the dag for this tree. This
    // data excludes double spend losers and their descendants, and transactions omitted
    // for a missing input until a retry applies them. It is extended after a subblock
    // connects or a retry applies a transaction, and rebuilt when the dag data is
    // regenerated. It is used in connect block to skip the
    // processing of a duplicate transaction which exists in some other subblock.
    std::map<uint256, CTransactionRef> mapDagTxns;

    // Spend index and doublespend conflicts. Every linked subblock is included.
    CDagConflictRegistry conflictRegistry;
    CDagMissingInputIndex missingInputs;

    // Subblocks to remove at the next regeneration because a transaction they carry failed
    // validation when retried from missingInputs. Connect rejects a subblock carrying an invalid
    // transaction at insert; a transaction omitted there for a missing input is only validated on
    // retry, so the same verdict is applied then, keeping this node consistent with nodes that held
    // the input at insert. Validation is judged against pindexSummaryRoot, so the verdict holds for
    // the life of the tree.
    std::set<uint256> setBadSubblocks;

    // The block index of the summary block that this tree is built on top of.
    CBlockIndex *pindexSummaryRoot = nullptr;

    // This is the the UTXO set as of the root summary block: pindexSummaryRoot.
    // As subblocks are added to this tree, their changes are layered on top of this, producing
    // the view (defined below).
    CCoinsViewCache *_pcoinsSummaryRoot = nullptr;

    // Coins cache view for this tree's tip: _pcoinsSummaryRoot plus every subblock the dag has applied on top.
    CCoinsViewCache *view = nullptr;

public:
    CTailstormTree() {}
    ~CTailstormTree();

protected:
    // Returns new_node if inserted, the existing node if it was already inserted, or nullptr if insertion failed
    CTreeNodeRef Insert(CTreeNodeRef new_node);

    // True if any transaction of newNode spends a coin already spent in its own ancestry, which
    // makes the subblock bad. Reads the spend index only.
    bool HasAncestryDoubleSpend(const CTreeNodeRef &newNode);

    // Record newNode's spends in the spend index and open a conflict group for each one that
    // competes with a spend in an unrelated branch. Following the Nexa convention, transactions
    // in a subblock are executed simultaneously, so a spend within the same subblock is not a
    // conflict.
    void IndexSpends(const CTreeNodeRef &newNode);

    /** Admit a subblock to this dag.

        Rejects the subblock if it double spends within its own ancestry. Otherwise gives it a
        sequence id, inserts it, records its spends and any conflict group it opens against an
        unrelated dag branch, recomputes the omit set over the whole dag, and indexes this
        subblock's excluded non-loser transactions so they can be retried when their inputs
        turn up.

        @param[out] excluded  Transactions the dag must not include.
        @param[out] losers    The subset of those excluded for losing a double spend.
        @return False if the subblock must not be linked; excluded and losers are untouched.
    */
    bool checkUpdateAncestryInsertIntoDag(const CTreeNodeRef &newNode,
        std::set<uint256> &excluded,
        std::set<uint256> &losers);
    //! For callers that do not need the omit set afterwards.
    bool checkUpdateAncestryInsertIntoDag(const CTreeNodeRef &newNode)
    {
        std::set<uint256> excluded;
        std::set<uint256> losers;
        return checkUpdateAncestryInsertIntoDag(newNode, excluded, losers);
    }

    void ConnectDependentTxs(const CTransactionRef &ptx,
        CCoinsViewCache &coins,
        int height,
        const std::set<uint256> &losers);

    // Omit txs that cannot spend against coins right now. Absent inputs go
    // to missingInputs. Spent inputs are omitted only (cache still holds
    // another spend). A tx already in mapDagTxns was applied from another
    // subblock containing it, and is left to connect's mapDagTxns skip.
    // Conflict groups are recorded by ScanSpends, not here.
    void OmitUnapplyableTxs(const CTreeNodeRef &node, const CCoinsViewCache &coins, std::set<uint256> &omit);
};

// All datamembers are protected by cs_forest
class CTailstormGrove
{
    friend class CTailstormForest;
    friend class CTailstormTree;

protected:
    // There can be many valid trees in a grove but, "tree" references the current active tree.
    std::shared_ptr<CTailstormTree> tree = nullptr;

    // key is subblock hash for the node in value
    std::map<uint256, CTreeNodeRef> mapGroveNodes;

    // the hash of the summary block that this grove is being built on.
    uint256 roothash;

    // the height of the summary block this grove is being built on.
    uint64_t nRootHeight = 0;

    CCoinsViewCache *_pcoinsTip = nullptr;

    // coins cache view for the this grove backed by _pcoinsTip
    CCoinsViewCache *view = nullptr;


protected:
    bool InitializeTree(CTreeNodeRef newNode, CCoinsViewCache *coinsCache);
    // Returns nullptr if failed, newNode if inserted, or the existing node if already inserted
    CTreeNodeRef InsertIntoTree(CTreeNodeRef newNode);
    // Recalculate the dag height of all subblocks in the dag (call if some subblocks were removed).
    void RecalcDagHeights();

public:
    CTailstormGrove(CCoinsViewCache *coinsCache);
    ~CTailstormGrove();
    uint256 id() { return roothash; }
    uint64_t summaryRootHeight() { return nRootHeight; }

protected:
    void Clear();

    // Returns nullptr if failed, newNode if inserted, or the existing node if already inserted
    CTreeNodeRef Insert(CTreeNodeRef newNode);
    bool GetBestDag(std::set<CTreeNodeRef> &dag);
    bool GetFullDag(std::set<CTreeNodeRef> &dag);
    bool GetBestTipHash(uint256 &hash);
};

class CTailstormForest
{
    friend class CTailstormGrove;
    friend class CTailstormForestTest;

public:
    // Use for locking all data structure except pDagActiveTip and bestGrove.
    CCriticalSection cs_forest;

    // Used for try locking when we check for a re-org
    // to limit execution to one thread.
    CCriticalSection cs_reorg;

protected:
    // Pending reorg-check marker. A pass clears it only when ready to inspect the protected state.
    // Each pass releases cs_reorg before the loop checks whether another iteration is required.
    std::atomic<bool> fRecheckReorg{false};

    // key is subblock hash for the node in value
    // mapAllNodes contains all nodes in the entire forest including orphans. The grove contains two
    // maps that are a subsets of this map. They are only used to speed up grove
    // specific node searching and for faster cleanup of nodes being removed
    // from the forest
    std::map<uint256, CTreeNodeRef> mapAllNodes;

    // Used for finding which grove a subblock is in by hash
    std::map<uint256, CTailstormGroveRef> mapAllGrovesByNode;

    // Contains all orphan nodes
    std::map<uint256, CTreeNodeRef> mapNodesUnlinked;

    // Contains all orphaned summary blocks
    std::map<uint256, ConstCBlockRef> mapSummaryBlocksUnlinked;

    // The main global coins cache
    CCoinsViewCache *_pcoinsTip = nullptr;

    // This is used for the sake of efficiency to access the current best
    // dag tip for mining purposes. This is used primarily in the getbestdagtiphash()
    // rpc call and is accessed in an atomic fashion so does not need locking when
    // accessed by its class methods.
    CTreeNodeRef pDagActiveTip = nullptr;

    // Orphans are currently begin processed if > 0
    int processingOrphans = 0;
    // Set when other events (like subblock inserted) means that we should reevaluate the orphan summary blocks
    // to see if any can be connected.
    int checkSummaryBlockOrphans = 0;

public:
    // The coins cache for the active tree. This is used
    // by txadmission and needs to be set each time the active
    // tree is updated.
    //
    // NOTE: bestGrove is protected by txAdmissionPause().  You must
    // have taken a Corral, either a TX_PAUSE or TX_PROCESSING before using this
    // pointer.
    CCoinsViewCache *bestGroveCoins()
    {
        if (bestGrove == nullptr)
            return _pcoinsTip;
        else
            return bestGrove->view;
    }

protected:
    // The frequency used for sanity checking the dag
    uint32_t nCheckFrequency = 0;
    // The best known grove (most cumulative work) in the forest
    CTailstormGroveRef bestGrove;

public:
    CTailstormForest() {}
    ~CTailstormForest() { Clear(); }

    //! Clear all forest, grove and tree data structures.
    void Clear();

    //! Trim the forest of any nodes <= nPruneHeight
    void ClearByHeight(const uint32_t nPruneHeight);

    //! The number of nodes in the forest
    size_t Size();

    //! Insert a new subblock into a grove
    bool Insert(const ConstCBlockRef &subblock);
    bool _Insert(const ConstCBlockRef &subblock);
    bool _Insert(CTreeNodeRef &newNode);
    /* After a subblock is successfully "linked" into the DAG:
       Connect dependent txs,
       then rescore the full DAG,
       and regenerate if we pick or change a doublespend winner. */
    void RefreshTransactionsAfterSubblockInsertion(CTailstormGroveRef grove, const CTreeNodeRef &newNode);

    //! Add or remove a summary block to the orphan map
    void AddSummaryBlockOrphan(ConstCBlockRef pblock);
    void RemoveSummaryBlockOrphan(ConstCBlockRef pblock);

    //! Add a subblock orphan to the orphans map.
    void AddSubblockOrphan(CTreeNodeRef newNode);
    /** Remove subblock orphan from the orphans map (if it is in there, otherwise no-op) */
    void RemoveSubblockOrphan(const ConstCBlockRef &pblock);
    /** Remove subblock orphan from the orphans map (if it is in there, otherwise no-op) */
    void RemoveSubblockOrphan(const uint256 &hash);

    //! Process all orphaned subblocks and summary blocks
    std::set<uint256> ProcessOrphans();

    //! Return a hash of the dag tip given a hash of some subblock in the dag.
    uint256 GetDagTipHash(const uint256 &hash);

    /** Find and return a subblock in the forest, if it exists, either by block hash or mining header commitment */
    bool Find(const uint256 &hash, ConstCBlockRef &subblock);
    /** Find and return a subblock in the forest, by mining header commitment */
    bool FindByMHC(const uint256 &hash, ConstCBlockRef &subblock);


    //! Find out whether the forst contains a treenode
    bool Contains(const uint256 &hash);

    //! Get DAG internal information for display and debugging
    UniValue GetInternals(UniValue &info);

    //! return a map of all tree nodes.
    std::map<uint256, CTreeNode> GetAllNodes();

    //! Return a set of tree nodes of the best dag. If ptree is set it receives the tree that
    //! produced them, for GetTxnExclusionSet. Only valid while cs_forest is held.
    bool GetBestDagFor(const uint256 &hash, std::set<CTreeNodeRef> &dag, CTailstormTreeRef *ptree = nullptr);

    //! Return the entire set of tree nodes and uncle nodes
    bool GetFullDagFor(const uint256 &hash, std::set<CTreeNodeRef> &dag);

    //! Return a set of nodes from a tree that matches what is in a block. If ptree is set it
    //! receives the tree that produced them, for GetTxnExclusionSet.
    bool GetDagForBlock(ConstCBlockRef &pblock, std::set<CTreeNodeRef> &dag, CTailstormTreeRef *ptree = nullptr);

    //! Return the current hash of the tip of the dag which contains this hash
    bool GetBestTipHashFor(const uint256 &hash, uint256 &tiphash);

    //! Return a map of all the transactions in the given dag
    void GetDagTxns(const std::set<CTreeNodeRef> &dag, std::map<uint256, CTransactionRef> &mapDagTxns);

    //! Return the dag height of a subblock given it's hash.
    uint32_t GetDagHeight(const uint256 &hash);

    //! Return a the grove that a subblock belongs to
    bool GetGrove(const uint256 &hash, CTailstormGroveRef &grove);

    //! Return the number of unlinked subblocks
    uint32_t GetUnlinkedSubblocks();

    //! Return the number of unlinked summary blocks
    uint32_t GetUnlinkedSummaryBlocks();

    //! Detemine if we need to re-org the chainActive tip to one that has a better dag.
    void CheckForReorg();

protected:
    //! Run one reorg-check pass while holding cs_reorg. Go through CheckForReorg(), which serializes
    //! each pass and preserves requests that are not covered by its protected state snapshot.
    void _CheckForReorg();

public:
    /** Regenerate coincache and mapDagTxn data for a tree. */
    void ReGenerateDagData(CTailstormGroveRef grove);
    /** Returns nullptr if it worked, and the bad subblock that should be removed if it did not */
    CTreeNodeRef ReGenerateDagDataForSubblocks(CTailstormTree *tree,
        std::vector<CTreeNodeRef> &sortedDag,
        const std::set<uint256> &setTxnExclusions,
        const std::set<uint256> &losers);

    /** Removes a subblock and its descendants from the forest and the passed tree.
        Subblocks may need to be removed if they are invalid, for example. */
    void RemoveFromGrove(CTailstormGroveRef grove, CTreeNodeRef subblock);

    /** Reassign nSequenceId as a dense 1..N over a tree's dag, keeping the current relative
        order. Removing a subblock leaves a hole, and the numbering must stay dense: Check()
        asserts it. Call after removing a subblock from a dag. */
    void RenumberDag(CTailstormTree &tree);

    //! Set the main coins cache that we build our tailstorm tree views on top of.
    void SetBackend(CCoinsViewCache *coinsCache)
    {
        LOCK(cs_forest);
        _pcoinsTip = coinsCache;
    }

    /** Set the coins tip for the active dag, finding the best dag that is a child of the current (summary block)
        chain tip
    */
    void SetBestGroveForSummaryTip();

    CTailstormGroveRef _BestGrove() { return bestGrove; }

    //! Reset bestGrove to null
    void _ClearBestGrove()
    {
        AssertLockHeld(cs_forest);
        bestGrove = nullptr;
    }

    //! Atomically set the dag active tip
    void SetDagActiveTip(CTreeNodeRef treenode);

    //! Atomically get the dag active tip
    uint256 GetDagActiveTip();

    /** Get all Uncles for this node, whether they be subblocks or
        summary blocks, which can then be added to a trees Uncle map */
    std::map<uint256, CTreeNodeRef> GetUncles(CTreeNodeRef node);

    //! As above, but for a grove that is already resolved.
    std::map<uint256, CTreeNodeRef> GetUncles(CTailstormGroveRef grove);

    //! Remove a node and any descendants from the forest
    bool Remove(uint256 &hash);

    //! Sanity check the dag for errors.
    void Check();
    void setSanityCheck(double dFrequency = 1.0) { nCheckFrequency = dFrequency * 4294967295.0; }
};

extern CTailstormForest tailstormForest;

//! Helper Function: Get the current best dag tip for mining on top of
uint256 GetActiveDagTip(std::set<CTreeNodeRef> &dag);

#endif
