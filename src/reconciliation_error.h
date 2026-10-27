// Copyright (c) 2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_RECONCILIATION_ERROR_H
#define NEXA_RECONCILIATION_ERROR_H

#include <ios>
#include <string>

// Thrown for set reconciliation data that no honest node builds, so the receiver can ban the sender.
// Raising these limits needs a new Graphene version, or older nodes would ban upgraded ones.
class reconciliation_limit_error : public std::ios_base::failure
{
public:
    explicit reconciliation_limit_error(const std::string &msg) : std::ios_base::failure(msg) {}
};

#endif // NEXA_RECONCILIATION_ERROR_H
