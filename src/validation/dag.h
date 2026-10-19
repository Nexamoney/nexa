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

/** Get the transactions in the passed dag that are considered potentially invalid and must not be included in the
    summary block.  These are conflict losers (a later spend, in dag order, of an outpoint an earlier transaction
    already spends) and txs whose inputs are unknown, because we cannot easily tell a doublespend from a bogus input.

    Transactions that are unambiguously invalid still invalidate the entire subblock, so would not appear here because
    their subblock would not even be in the setBestDag.

    Pass the tree that produced this dag; its coins at the summary root are read from it.
    Obtain that tree from the same call that produced the dag: [GetBestDagFor] and [GetDagForBlock] both return it.
    cs_forest must be held for the duration of the call.

    @param sortedNodes The DAG's subblocks to analyze, in nSequenceId order. Uncles may be included, as the dag
                       getters return them first; they are only proofs of work and are skipped
    @param tree The tree that this DAG is a subset of (used to get the DAG root summary block coins view).
    @param losers The transactions that are being rejected due to a preferred double spend.  So this set does not count
                  their descendants or transactions with unknown inputs.

    @returns all transactions that must be excluded from the summary block or any coins view
*/
std::set<uint256> GetTxnExclusionSet(const std::vector<CTreeNodeRef> &sortedNodes,
    const CTailstormTree &tree,
    std::set<uint256> *losers = nullptr);

/** Get the transactions in the passed dag that are considered potentially invalid and must not be included in the
    summary block.  These are conflict losers and txs whose inputs are unknown, because we cannot easily tell a
    doublespend from a bogus input.

    Subblocks are walked in the order given, and each one's transactions in turn. The first spend of an outpoint is
    good; every later transaction spending that outpoint is a loser.

    An invalid transaction invalidates its whole subblock: a connect that finds one removes every subblock
    carrying it from the grove.

    This function also requires the UTXO set [CCoinsViewCache] at the point where this DAG should be applied,
    that is, it should at the root summary block.
*/
std::set<uint256> GetTxnExclusionSet(const std::vector<CTreeNodeRef> &sortedNodes,
    const CCoinsViewCache *pcoins = nullptr,
    std::set<uint256> *losers = nullptr);

/** Dag order of the passed nodes: by dependency (parents before children), then by the highest score among a
    subblock and its descendants (not counting descendants shared with the subblock it is compared to), then by
    lower hash. Only links among the passed nodes are considered, and only setAncestors is read.
    @returns The subblocks in dependency, score, hash order.
*/
std::vector<CTreeNodeRef> OrderDag(const std::vector<CTreeNodeRef> &nodes);

/** Analyze the subblocks a summary block commits, independently of the forest.

    The result depends only on the passed subblocks, the summary root hash and the coins at the summary root:
    the dag is rebuilt from the subblock headers' prev hashes, so no nSequenceId, uncle flag or link to a
    subblock outside the passed set is used.

    @param hashSummaryRoot The summary block these subblocks build on (the summary's hashPrevBlock).
    @param vSubblocks The committed subblocks of this epoch, uncles excluded, in any order.
    @param coinsSummaryRoot The UTXO set as of hashSummaryRoot.
    @param vOrdered Out: vSubblocks in dag order (see OrderDag), which decides double spends.
    @param setTxnExclusions Out: the transactions that must be omitted from the summary (see GetTxnExclusionSet).
    @param strReject Out: the reject reason when false is returned.

    @returns false if the subblocks are not a self-contained dag: a duplicate, or a parent that is neither one
             of them nor the summary root. A summary committing such a set is invalid.
*/
bool AnalyzeSummaryDag(const uint256 &hashSummaryRoot,
    const std::vector<ConstCBlockRef> &vSubblocks,
    const CCoinsViewCache &coinsSummaryRoot,
    std::vector<ConstCBlockRef> &vOrdered,
    std::set<uint256> &setTxnExclusions,
    std::string &strReject);

// Is the tailstorm dag activated and ready to receive subblocks
bool IsTailstormDagActivated();

class CTreeNode
{
public:
    uint256 hash; // the subblock hash that is this node
    uint32_t dagHeight = 0;
    // nSequenceId is this node's 1-based position in its tree's dag order: by dependency (parents
    // before children), then by the highest score among this node and its descendants, then by lower
    // hash (see RenumberDag). RenumberDag assigns it whenever the dag changes, so it can move as
    // subblocks arrive.  However, once k-1 subblocks are available, an arrival is just appended to the end;
    // we have good subblocks.
    // If 0, this node is not in a tree.
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

/** DAG-wide spend index, used to reject a subblock that double spends within its own ancestry.
    Every linked subblock (e.g. its in the DAG) is indexed, including parked ones. A double spend
    between unrelated branches is allowed; GetTxnExclusionSet picks the first in dag order.

    Owned by a CTailstormTree and guarded by tailstormForest.cs_forest like the rest of the tree's
    state; there is no internal locking. Every method asserts that lock, and callers of the inline
    accessors must hold it too.
*/
class CDagConflictRegistry
{
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

    bool IsIndexed(const uint256 &hash) const { return indexed.count(hash) != 0; }
};

// All data members are protected by cs_forest
class CTailstormTree
{
    friend class CTailstormGrove;
    friend class CTailstormForest;
    friend class CTailstormForestTest;
    // Reads _pcoinsSummaryRoot.
    friend std::set<uint256> GetTxnExclusionSet(const std::vector<CTreeNodeRef> &sortedNodes,
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

    // map of unique transactions that are applied to the coins cache for this tree: those of the
    // processed subblocks less the exclusion set. It is extended when a subblock is appended,
    // and rebuilt when the dag data is regenerated.
    std::map<uint256, CTransactionRef> mapDagTxns;

    // Spend index. Every linked subblock is included.
    CDagConflictRegistry conflictRegistry;

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

    // The dag in nSequenceId order. RenumberDag keeps nSequenceId a dense 1..N, so each node is
    // placed at its index rather than sorted.
    std::vector<CTreeNodeRef> SortedDag() const;

    // The number of dag subblocks a summary commits: the tailstorm_k - 1 places the uncles leave.
    size_t SelectionSize() const;

    // True unless the processed subblocks, which the coins cache embodies, are exactly the first
    // SelectionSize() in dag order.
    bool NeedsRegeneration() const;

protected:
    // Returns new_node if inserted, the existing node if it was already inserted, or nullptr if insertion failed
    CTreeNodeRef Insert(CTreeNodeRef new_node);

    // True if any transaction of newNode spends a coin already spent in its own ancestry, which
    // makes the subblock bad. Reads the spend index only.
    bool HasAncestryDoubleSpend(const CTreeNodeRef &newNode);

    // Record newNode's spends in the spend index.
    void IndexSpends(const CTreeNodeRef &newNode);

    /** Admit a subblock to this dag.

        Rejects the subblock if its transactions are not in txid order or it double spends within
        its own ancestry. Otherwise inserts it, renumbers the dag (or, once the selection is full, places
        it last), and records its spends. It is left unprocessed; the caller decides whether to apply it.

        @return False if the subblock must not be linked.
    */
    bool checkUpdateAncestryInsertIntoDag(const CTreeNodeRef &newNode);
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
    bool GetBestDag(std::vector<CTreeNodeRef> &dag);
    bool GetFullDag(std::vector<CTreeNodeRef> &dag);
    bool GetDagForReorg(std::vector<CTreeNodeRef> &dag);
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

    //! Append the best dag, uncles first then subblocks in nSequenceId order. If ptree is set it receives the tree that
    //! produced them, for GetTxnExclusionSet. Only valid while cs_forest is held.
    bool GetBestDagFor(const uint256 &hash, std::vector<CTreeNodeRef> &dag, CTailstormTreeRef *ptree = nullptr);

    //! Append all uncle nodes then all tree nodes, in nSequenceId order
    bool GetFullDagFor(const uint256 &hash, std::vector<CTreeNodeRef> &dag);

    //! Return the nodes from a tree that match what is in a block, uncles first then subblocks in
    //! nSequenceId order. If ptree is set it
    //! receives the tree that produced them, for GetTxnExclusionSet.
    bool GetDagForBlock(ConstCBlockRef &pblock, std::vector<CTreeNodeRef> &dag, CTailstormTreeRef *ptree = nullptr);

    //! Return the tree nodes (uncles first then subblocks in nSequenceId order) that fit k-1 subblocks regardless of
    //! whether those subblocks were processed or not.
    bool GetDagForReorg(const uint256 &hash, std::vector<CTreeNodeRef> &dag);

    //! Return the current hash of the tip of the dag which contains this hash
    bool GetBestTipHashFor(const uint256 &hash, uint256 &tiphash);

    //! Return a map of all the transactions in the given dag
    void GetDagTxns(const std::vector<CTreeNodeRef> &dag, std::map<uint256, CTransactionRef> &mapDagTxns);

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
    /** Regenerate coincache and mapDagTxn data for a tree: select the first subblocks in dag order,
        as many as the tailstorm_k - 1 places the uncles leave, then connect every transaction they
        carry, less the exclusion set, at once on top of the summary root, as the summary block that
        commits them would. A subblock carrying a transaction that fails is removed and the selection
        retried. */
    void ReGenerateDagData(CTailstormGroveRef grove);

    /** Fully resort and regenerate the dag built on the active chain tip, and update the dag active tip.
        An arrival once the selection is full is placed last without reordering the dag, so this
        forces the order a full resort would give. Returns false if there is no dag on the tip. */
    bool ReconsiderDag();

    /** Removes a subblock and its descendants from the forest and the passed tree.
        Subblocks may need to be removed if they are invalid, for example. */
    void RemoveFromGrove(CTailstormGroveRef grove, CTreeNodeRef subblock);

    /** Reassign nSequenceId as a dense 1..N over a tree's dag in dag order: by dependency
        (parents before children), then by the highest score among a subblock and its descendants
        (not counting descendants shared with the subblock it is compared to), then by lower hash.
        Scores change as subblocks arrive, so call after any subblock is added to or removed from a dag. */
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
uint256 GetActiveDagTip(std::vector<CTreeNodeRef> &dag);

#endif
