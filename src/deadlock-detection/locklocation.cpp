// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019-2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "locklocation.h"
#include <cstring>
#include <string>

#ifdef DEBUG_LOCKORDER // this ifdef covers the rest of the file

static std::string variableName(const char *p)
{
    // remove the object prefix, e.g. x in x.y or x->y
    const char *dot = std::strrchr(p, '.');
    const char *gt = std::strrchr(p, '>');

    const char *start = nullptr;

    if (dot && gt)
        start = (dot > gt) ? dot : gt;
    else if (dot)
        start = dot;
    else if (gt)
        start = gt;

    return (start ? std::string(start + 1) : std::string(p));
}


CLockLocation::CLockLocation(const char *pszName,
    const char *pszFile,
    int nLine,
    bool fTryIn,
    OwnershipType eOwnershipIn,
    LockType eLockTypeIn)
{
    mutexName = variableName(pszName);
    sourceFile = pszFile;
    sourceLine = nLine;
    fTry = fTryIn;
    eOwnership = eOwnershipIn;
    eLockType = eLockTypeIn;
}

std::string CLockLocation::ToString() const
{
    return mutexName + "  " + sourceFile + ":" + std::to_string(sourceLine) + (fTry ? " (TRY)" : "") +
           (eOwnership == OwnershipType::EXCLUSIVE ? " (EXCLUSIVE)" : "(SHARED)") + "(HELD)";
}

bool CLockLocation::GetTry() const { return fTry; }
OwnershipType CLockLocation::GetExclusive() const { return eOwnership; }
LockType CLockLocation::GetLockType() const { return eLockType; }
std::string CLockLocation::GetFileName() const { return sourceFile; }
int CLockLocation::GetLineNumber() const { return sourceLine; }
std::string CLockLocation::GetMutexName() const { return mutexName; }
#endif // end DEBUG_LOCKORDER
