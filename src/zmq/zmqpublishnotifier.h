// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_ZMQ_ZMQPUBLISHNOTIFIER_H
#define NEXA_ZMQ_ZMQPUBLISHNOTIFIER_H

#include "sync.h"
#include "zmqabstractnotifier.h"

#include <map>
#include <memory>

class CBlockIndex;

class CZMQAbstractPublishNotifier : public CZMQAbstractNotifier
{
public:
    bool Initialize(void *pcontext);
    void Shutdown();

protected:
    /** Send a multipart message: topic, body, and the topic's 4 byte little endian sequence number */
    bool SendZmqMessage(const char *command, const void *data, size_t size);

private:
    // Serializes use of psocket, which is shared by every publish notifier bound to the same address
    std::shared_ptr<CCriticalSection> csZmq;
    // Next sequence number for each topic published by this notifier, guarded by csZmq
    std::map<std::string, uint32_t> mapSequence;
};

class CZMQPublishHashBlockNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyBlock(const CBlockIndex *pindex, const ConstCBlockRef pblock);
};

class CZMQPublishHashTransactionNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyTransaction(const CTransactionRef &ptx);
};

class CZMQPublishHashDoubleSpendNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyDoubleSpend(const CTransactionRef ptx);
};

class CZMQPublishRawBlockNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyBlock(const CBlockIndex *pindex, const ConstCBlockRef pblock);
};

class CZMQPublishRawTransactionNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyTransaction(const CTransactionRef &ptx);
};

class CZMQPublishRawDoubleSpendNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyDoubleSpend(const CTransactionRef ptx);
};

#endif // NEXA_ZMQ_ZMQPUBLISHNOTIFIER_H
