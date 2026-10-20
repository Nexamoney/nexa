// Copyright (c) 2015-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/grouptokencache.h"
#include "config.h"
#include "consensus/grouptokens.h"
#include "main.h"

bool AccumulateTokenData(CTransactionRef ptx, CCoinsViewCache &view, CTokenIndexUpdates &updates)
{
    if (ptx->IsCoinBase())
        return true;

    std::map<CGroupTokenID, CAuth> &accumulatedAuthorities = updates.authorities;
    std::map<CGroupTokenID, CTokenMintage> &accumulatedMintages = updates.mintages;

    struct Amounts
    {
        CAmount nTokenInputs = 0;
        CAmount nTokenOutputs = 0;
    };
    std::map<CGroupTokenID, Amounts> mintages;
    std::map<CGroupTokenID, std::string> mintageGenesis;

    // Get mintages/authorities from the inputs
    CAuth authority;
    bool fHaveInputAuthority = false;
    for (const CTxIn &txin : ptx->vin)
    {
        Coin coin;
        view.GetCoin(txin.prevout, coin);
        if (!coin.IsSpent())
        {
            const CTxOut &txout = coin.out;
            CGroupTokenInfo tg(txout);

            // Get the mintages in the inputs (no amounts count if read only)
            if ((!txin.IsReadOnly()) && (tg.associatedGroup != NoGroup) && (!tg.isAuthority()))
            {
                // Runs before consensus checks, so the sums are not bounded yet
                CAmount &nTokenInputs = mintages[tg.associatedGroup].nTokenInputs;
                if (tg.quantity > 0 && std::numeric_limits<CAmount>::max() - nTokenInputs < tg.quantity)
                    return false;
                nTokenInputs += tg.quantity;
            }

            // Get the authorities in the inputs
            if (tg.associatedGroup != NoGroup && tg.isAuthority())
            {
                // We only let authorities count if the input is consumed or signed
                if (!txin.IsReadOnly() || (txin.IsReadOnly() && tg.allowsRenew() && (txin.scriptSig.size() != 0)))
                {
                    if (accumulatedAuthorities.count(tg.associatedGroup))
                    {
                        std::swap(authority, accumulatedAuthorities[tg.associatedGroup]);
                    }
                    fHaveInputAuthority = true;
                    authority.nMint -= tg.allowsMint();
                    authority.nMelt -= tg.allowsMelt();
                    authority.nRenew -= tg.allowsRenew();
                    authority.nRescript -= tg.allowsRescript();
                    authority.nSubgroup -= tg.allowsSubgroup();
                    accumulatedAuthorities[tg.associatedGroup] = authority;
                }
            }
        }
        else
        {
            return false;
        }
    }

    // Get the mintages/authorities in the outputs.
    bool fHaveOutputAuthority = false;
    bool fHaveOpReturn = false;
    CScript genesisScript;
    for (size_t i = 0; i < ptx->vout.size(); i++)
    {
        const CTxOut &out = ptx->vout[i];
        CGroupTokenInfo tg(out.scriptPubKey);

        // Get mintages from the outputs
        if ((tg.associatedGroup != NoGroup) && !tg.isAuthority())
        {
            CAmount &nTokenOutputs = mintages[tg.associatedGroup].nTokenOutputs;
            if (tg.quantity > 0 && std::numeric_limits<CAmount>::max() - nTokenOutputs < tg.quantity)
                return false;
            nTokenOutputs += tg.quantity;

            // Save the first output address for any subgroup mintage which we'll need later when apply
            // the genesis address to the database.
            CTxDestination dest;
            ExtractDestination(out.scriptPubKey, dest);
            std::string genesisAddress = EncodeDestination(dest, Params(), GetConfig());
            if (!mintageGenesis.count(tg.associatedGroup) && tg.associatedGroup.isSubgroup())
            {
                mintageGenesis[tg.associatedGroup] = genesisAddress;
            }
        }

        // Get authorities from the outputs
        if (!out.scriptPubKey.empty() && out.scriptPubKey[0] == OP_RETURN)
        {
            fHaveOpReturn = true;
            continue;
        }

        if ((tg.associatedGroup != NoGroup) && tg.isAuthority())
        {
            // Capture the genesis address for a new token. There should be just
            // one output authority
            if (!fHaveOutputAuthority)
            {
                fHaveOutputAuthority = true;
                genesisScript = out.scriptPubKey;
            }

            if (accumulatedAuthorities.count(tg.associatedGroup))
            {
                std::swap(authority, accumulatedAuthorities[tg.associatedGroup]);
            }

            authority.nMint += tg.allowsMint();
            authority.nMelt += tg.allowsMelt();
            authority.nRenew += tg.allowsRenew();
            authority.nRescript += tg.allowsRescript();
            authority.nSubgroup += tg.allowsSubgroup();
            accumulatedAuthorities[tg.associatedGroup] = authority;
        }
    }

    // If inputs for a group id equals zero and ouputs > 0, then it's a MINT.
    // if intputs > outputs, then it's a MELT.
    for (auto &it : mintages)
    {
        CAmount &nTokenInputs = it.second.nTokenInputs;
        CAmount &nTokenOutputs = it.second.nTokenOutputs;
        const CGroupTokenID &grpID = it.first;

        // Check for Mint
        if (nTokenInputs == 0 && nTokenOutputs > 0)
        {
            accumulatedMintages[grpID] += nTokenOutputs;

            // Update the genesis address if this is a mint, and MUST be a subgroup.
            // NOTE: only the very first mintage of a subgroup will actually get updated to the database, thus
            // preserving the first mint as the genesis address for that subgroup.
            if (grpID.isSubgroup())
            {
                DbgAssert(mintageGenesis.count(grpID) > 0, );
                updates.genesis.emplace(grpID, mintageGenesis[grpID]);
            }
        }

        // Check for Melt
        if (nTokenInputs > nTokenOutputs)
        {
            CAmount nMeltAmount = nTokenInputs - nTokenOutputs;
            accumulatedMintages[grpID] -= nMeltAmount;
        }
    }

    // if we have both an authority and op_return then look for and update
    // the token description information
    if (!fHaveInputAuthority && fHaveOutputAuthority && fHaveOpReturn)
    {
        // Process the descriptions to add to the token desc database
        std::vector<std::string> vDesc;
        CGroupTokenInfo tg = tokencache.ProcessTokenDescriptions(ptx, vDesc);
        if (tg.associatedGroup != NoGroup)
        {
            updates.descriptions[tg.associatedGroup] = vDesc;

            // get the genesis address and pass it to the token desc database along
            // with the transaction.
            CTxDestination dest;
            ExtractDestination(genesisScript, dest);
            updates.genesis[tg.associatedGroup] = EncodeDestination(dest, Params(), GetConfig());
        }
    }
    return true;
}

void ApplyTokenIndexUpdates(CTokenIndexUpdates &updates)
{
    // The mintages and authorities update these entries, so write them first
    for (const auto &it : updates.descriptions)
        tokencache.AddTokenDesc(it.first, it.second);
    for (const auto &it : updates.genesis)
        tokenmint.AddTokenGenesis(it.first, mint_entry(0, it.second));
    tokenmint.ApplyTokenMintages(updates.mintages);
    tokencache.ApplyTokenAuthorities(updates.authorities);
}

// Token Description Cache methods
void CTokenDescCache::AddTokenDesc(const CGroupTokenID &_grpID, const std::vector<std::string> &_desc)
{
    // When we add a token description we add it only to the database but not the cache.  We instead
    // add values to the cache when reading from the database, when needed. This way we only fill the in
    // memory cache with values we know are needed for the token wallet.  These values would be pulled
    // into the cache during node startup so there is no real performance loss during normal wallet use.
    LOCK(cs_tokencache);
    cache.erase(_grpID.parentGroup());
    ptokenDesc->WriteDesc(_grpID.parentGroup(), _desc);
}

const std::vector<std::string> CTokenDescCache::GetTokenDesc(const CGroupTokenID &_grpID)
{
    std::vector<std::string> _desc;
    CGroupTokenID grpID = _grpID.parentGroup();

    LOCK(cs_tokencache);
    if (cache.count(grpID))
    {
        return cache[grpID];
    }
    else if (ptokenDesc->ReadDesc(grpID, _desc))
    {
        // Limit the size of cache.  If the cache size is exceeded, which is unlikely, then
        // we don't add any more values to the cache and we rather get descrptions directly
        // from the database.
        if (cache.size() <= nMaxCacheSize)
        {
            cache.emplace(grpID, _desc);
        }
        return _desc;
    }
    else
    {
        return {};
    }
}

void CTokenDescCache::EraseTokenDesc(const CGroupTokenID &_grpID)
{
    LOCK(cs_tokencache);
    cache.erase(_grpID.parentGroup());
}

void CTokenDescCache::SetSyncFlag(const bool fSet)
{
    LOCK(cs_tokencache);
    ptokenDesc->WriteSyncFlag(fSet);
}

bool CTokenDescCache::GetSyncFlag()
{
    bool fSet = false;
    LOCK(cs_tokencache);
    ptokenDesc->ReadSyncFlag(fSet);

    return fSet;
}

CGroupTokenInfo CTokenDescCache::ProcessTokenDescriptions(CTransactionRef ptx, std::vector<std::string> &vDesc)
{
    for (size_t i = 0; i < ptx->vout.size(); i++)
    {
        const CTxOut &out = ptx->vout[i];
        CGroupTokenInfo tg(out.scriptPubKey);
        if ((tg.associatedGroup != NoGroup) && tg.isAuthority())
        {
            // If we have an authority then we have to check all the outputs again for an OP_RETURN
            for (size_t j = 0; j < ptx->vout.size(); j++)
            {
                if (i == j) // skip the one we already checked in the upper loop
                    continue;

                // find op_return associated with the tx if there is one
                const CTxOut &out2 = ptx->vout[j];
                if (!out2.scriptPubKey.empty() && out2.scriptPubKey[0] == OP_RETURN)
                {
                    // Token indexing is not consensus, so a parse error must not abort block connection
                    try
                    {
                        if (!GetTokenDescription(out2.scriptPubKey, vDesc))
                        {
                            return CGroupTokenInfo{};
                        }
                    }
                    catch (const std::exception &e)
                    {
                        LOG(TOKEN, "Ignoring token description in tx %s: %s\n", ptx->GetId().ToString(), e.what());
                        return CGroupTokenInfo{};
                    }

                    // return null authorites for now
                    vDesc.push_back("0");
                    vDesc.push_back("0");
                    vDesc.push_back("0");
                    vDesc.push_back("0");
                    vDesc.push_back("0");
                    DbgAssert(vDesc.size() == DESC_ENTRY_SIZE, );

                    return tg;
                }
            }
        }
    }
    return CGroupTokenInfo{};
}

void CTokenDescCache::ApplyTokenAuthorities(std::map<CGroupTokenID, CAuth> &accumulatedAuthorities)
{
    LOCK(cs_tokencache);
    for (auto &it : accumulatedAuthorities)
    {
        std::vector<std::string> vDescNone = vDefaultDesc;
        std::vector<std::string> vDesc = tokencache.GetTokenDesc(it.first);

        // Special case if the token was originally created "new" but without any
        // ticker/name/url/hash/decimals defined.  It will not have had an OP_RETURN in
        // which case there would not be an initial description string in the tracking database created
        // so here we add one when we get our first authority to track.....
        if (vDesc.empty())
        {
            std::swap(vDesc, vDescNone);
        }

        if (vDesc.size() >= DESC_ENTRY_SIZE)
        {
            // Get authorities
            int nMint = 0;
            int nMelt = 0;
            int nRenew = 0;
            int nRescript = 0;
            int nSubgroup = 0;
            try
            {
                nMint = stoi(vDesc[5]) + it.second.nMint;
                nMelt = stoi(vDesc[6]) + it.second.nMelt;
                nRenew = stoi(vDesc[7]) + it.second.nRenew;
                nRescript = stoi(vDesc[8]) + it.second.nRescript;
                nSubgroup = stoi(vDesc[9]) + it.second.nSubgroup;
            }
            catch (...)
            {
                DbgAssert(false, );
            }

            std::vector<std::string> vNewDesc = {vDesc[0], vDesc[1], vDesc[2], vDesc[3], vDesc[4]};
            vNewDesc.push_back(std::to_string(nMint));
            vNewDesc.push_back(std::to_string(nMelt));
            vNewDesc.push_back(std::to_string(nRenew));
            vNewDesc.push_back(std::to_string(nRescript));
            vNewDesc.push_back(std::to_string(nSubgroup));

            AddTokenDesc(it.first, vNewDesc);
        }
        else
            DbgAssert(false, ); // should never happen
    }
}

void CTokenDescCache::RemoveTokenAuthorities(std::map<CGroupTokenID, CAuth> &accumulatedAuthorities)
{
    LOCK(cs_tokencache);
    for (auto &it : accumulatedAuthorities)
    {
        auto vDesc = tokencache.GetTokenDesc(it.first);
        if (vDesc.size() >= DESC_ENTRY_SIZE)
        {
            // Get authorities
            int nMint = 0;
            int nMelt = 0;
            int nRenew = 0;
            int nRescript = 0;
            int nSubgroup = 0;
            try
            {
                nMint = stoi(vDesc[5]) - it.second.nMint;
                nMelt = stoi(vDesc[6]) - it.second.nMelt;
                nRenew = stoi(vDesc[7]) - it.second.nRenew;
                nRescript = stoi(vDesc[8]) - it.second.nRescript;
                nSubgroup = stoi(vDesc[9]) - it.second.nSubgroup;
            }
            catch (...)
            {
                DbgAssert(false, );
            }

            std::vector<std::string> vNewDesc = {vDesc[0], vDesc[1], vDesc[2], vDesc[3], vDesc[4]};
            vNewDesc.push_back(std::to_string(nMint));
            vNewDesc.push_back(std::to_string(nMelt));
            vNewDesc.push_back(std::to_string(nRenew));
            vNewDesc.push_back(std::to_string(nRescript));
            vNewDesc.push_back(std::to_string(nSubgroup));

            AddTokenDesc(it.first, vNewDesc);
        }
        else
            DbgAssert(false, ); // should not happen
    }
}


// Token Mint Cache methods
void CTokenMintCache::AddToCache(const CGroupTokenID &_grpID, const mint_entry &entry)
{
    AssertLockHeld(cs_tokenmint);

    // Limit the size of cache.  If the cache size is exceeded, which is unlikely, then
    // we erase the first value and add the new one to the cache. This way any items with
    // high cache hits will always be in memory since mintage lookups could become quite
    // common for some type of tokens such as "game itmes" used multiplayer video games.
    while (cache.size() >= nMaxCacheSize)
    {
        // remove a random element
        auto iter = cache.begin();
        std::advance(iter, GetRand(cache.size() - 1));
        cache.erase(iter);
    }
    cache[_grpID] = entry;
}

void CTokenMintCache::AddTokenGenesis(const CGroupTokenID &_grpID, const mint_entry &entry)
{
    LOCK(cs_tokenmint);

    // Groups only have one genesis transaction possible but for subgroup genesis is set at
    // the time of the first mint and so, for subgroups, only check and then update the genesis one time.
    if (_grpID.isSubgroup())
    {
        std::string genesis = GetTokenGenesis(_grpID);
        if (!genesis.empty())
            return;
    }

    AddToCache(_grpID, entry);
    ptokenMint->WriteMint(_grpID, entry);
}

namespace
{
CTokenMintage MintIndexBase()
{
    static const CTokenMintage base = CTokenMintage(1) << 64;
    return base;
}

CTokenMintage LoadMintRemainder(const CGroupTokenID &grpID)
{
    CTokenMintRemainder stored;
    if (!ptokenMint->ReadMintRemainder(grpID, stored))
        return 0;
    const CTokenMintage value = (CTokenMintage(stored.hi) << 64) + stored.lo;
    return stored.negative ? -value : value;
}

CTokenMintRemainder DiskRemainder(const CTokenMintage &value)
{
    CTokenMintRemainder stored;
    stored.negative = value < 0 ? 1 : 0;
    const CTokenMintage mag = stored.negative ? -value : value;
    stored.lo = (mag % MintIndexBase()).convert_to<uint64_t>();
    stored.hi = (mag / MintIndexBase()).convert_to<uint64_t>();
    return stored;
}
} // namespace

void CTokenMintCache::UpdateTokenMint(const CGroupTokenID &_grpID, const CTokenMintage &delta)
{
    LOCK(cs_tokenmint);
    mint_entry entry = GetTokenMint(_grpID);
    // The stored total is uint64. Keep the rest so a later melt or disconnect uses the same total.
    const CTokenMintage previous = LoadMintRemainder(_grpID);
    const CTokenMintage amount = CTokenMintage(entry.first) + previous + delta;
    const CTokenMintage maxRepresentable(std::numeric_limits<uint64_t>::max());

    CTokenMintage represented = amount;
    CTokenMintage remainder = 0;
    if (amount < 0)
    {
        represented = 0;
        remainder = amount;
    }
    else if (amount > maxRepresentable)
    {
        represented = maxRepresentable;
        remainder = amount - maxRepresentable;
    }

    const uint64_t stored = represented.convert_to<uint64_t>();
    if (stored == entry.first && remainder == previous)
        return;

    if (remainder != 0 && previous == 0)
        LOG(TOKEN, "Token mintage for group %s does not fit in the index\n", EncodeGroupToken(_grpID));

    entry.first = stored;
    AddToCache(_grpID, entry);
    ptokenMint->UpdateMint(_grpID, entry, remainder != 0, DiskRemainder(remainder));
}

mint_entry CTokenMintCache::GetTokenMint(const CGroupTokenID &_grpID)
{
    mint_entry entry;

    LOCK(cs_tokenmint);
    if (cache.count(_grpID))
    {
        return cache[_grpID];
    }
    else if (ptokenMint->ReadMint(_grpID, entry))
    {
        AddToCache(_grpID, entry);
    }

    return entry;
}

std::string CTokenMintCache::GetTokenGenesis(const CGroupTokenID &_grpID)
{
    mint_entry entry;

    LOCK(cs_tokenmint);
    if (cache.count(_grpID))
    {
        return cache[_grpID].second;
    }
    else if (ptokenMint->ReadMint(_grpID, entry))
    {
        AddToCache(_grpID, entry);
        return entry.second;
    }
    else
    {
        return "";
    }
}

void CTokenMintCache::ApplyTokenMintages(const std::map<CGroupTokenID, CTokenMintage> &accumulatedMintages)
{
    for (const auto &it : accumulatedMintages)
        UpdateTokenMint(it.first, it.second);
}

void CTokenMintCache::RemoveTokenMintages(const std::map<CGroupTokenID, CTokenMintage> &accumulatedMintages)
{
    for (const auto &it : accumulatedMintages)
        UpdateTokenMint(it.first, -it.second);
}

void CTokenMintCache::SetSyncFlag(const bool fSet)
{
    LOCK(cs_tokenmint);
    ptokenDesc->WriteSyncFlag(fSet);
}

bool CTokenMintCache::GetSyncFlag()
{
    bool fSet = false;
    LOCK(cs_tokenmint);
    ptokenDesc->ReadSyncFlag(fSet);

    return fSet;
}
