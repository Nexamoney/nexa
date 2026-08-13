// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_NET_PROCESSING_H
#define NEXA_NET_PROCESSING_H

#include "net.h"
#include "primitives/block.h"

#include <functional>
#include <map>
#include <vector>

class CUtxo;

static const size_t MAX_UNCONNECTED_SUBBLOCK_HEADERS = 2000;

class CSubblockHeaderCache
{
public:
    mutable CCriticalSection cs_headersCache;

    enum class Tier
    {
        PRIMARY,
        FALLBACK,
    };

    struct Entry
    {
        CBlockHeader header;
        int64_t nTime;
        NodeId source;
        Tier tier = Tier::PRIMARY;
    };

    enum class AddResult
    {
        ADDED,
        ADDED_FALLBACK,
        DUPLICATE,
        PEER_LIMIT,
        GLOBAL_LIMIT,
        FALLBACK_PEER_LIMIT,
        FALLBACK_GLOBAL_LIMIT,
    };

    CSubblockHeaderCache();
    CSubblockHeaderCache(size_t maxCacheSize, size_t maxPeerEntries);
    CSubblockHeaderCache(size_t maxCacheSize,
        size_t maxPeerEntries,
        size_t maxFallbackCacheSize,
        size_t maxFallbackPeerEntries);

    AddResult Add(const CBlockHeader &header, NodeId source, int64_t nTime, Tier tier = Tier::PRIMARY);
    size_t Expire(int64_t now, int64_t timeout);
    std::vector<Entry> ExtractReady(const std::function<bool(const CBlockHeader &)> &isReady);
    void RemovePeer(NodeId source);
    void Clear();

    size_t Size() const
    {
        LOCK(cs_headersCache);
        return entries.size();
    }
    size_t PrimarySize() const
    {
        LOCK(cs_headersCache);
        return primarySize;
    }
    size_t FallbackSize() const
    {
        LOCK(cs_headersCache);
        return fallbackSize;
    }
    size_t Count(NodeId source) const;
    size_t FallbackCount(NodeId source) const;

private:
    typedef std::map<uint256, Entry> EntryMap;

    size_t _TierCount(NodeId source, Tier tier) const;
    void _Erase(EntryMap::iterator it);

    const size_t maxSize;
    const size_t maxPerPeer;
    const size_t maxFallbackSize;
    const size_t maxFallbackPerPeer;
    const bool deriveMaxPerPeer;
    size_t primarySize GUARDED_BY(cs_headersCache) = 0;
    size_t fallbackSize GUARDED_BY(cs_headersCache) = 0;
    EntryMap entries GUARDED_BY(cs_headersCache);
    std::map<NodeId, size_t> peerCounts GUARDED_BY(cs_headersCache);
    std::map<NodeId, size_t> fallbackPeerCounts GUARDED_BY(cs_headersCache);
};
extern CSubblockHeaderCache subblockHeaders;

void RemoveUnconnectedSubblockHeadersForPeer(NodeId nodeid);

/** Process protocol messages received from a given node */
bool ProcessMessages(CNode *pfrom);


/** Process a single protocol messages received from a given node
    @param pfrom The node this message originated from
    @param strCommand The message type
    @param msgCookie A number passed by the requester that should be returned in the response
    @param vRecv The message contents
    @param nStopwatchTimeReceived Stopwatch time in microseconds indicating when this message was received
*/
bool ProcessMessage(CNode *pfrom,
    std::string strCommand,
    uint32_t msgCookie,
    CDataStream &vRecv,
    int64_t nStopwatchTimeReceived);

/**
 * Send queued protocol messages to be sent to a give node.
 *
 * @param[in]   pto             The node which we are sending messages to.
 */
bool SendMessages(CNode *pto);

/** Create a utxo object for sending back data to the requester */
void CreateUTXO(COutPoint &out, CUtxo &utxo);

#endif
