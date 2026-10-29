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

/** A ZMQ PUB socket bound to one address and shared by all notifiers at that address.
 * ZMQ sockets are not thread safe, so every use goes through these helpers, which hold cs_guardedZmqSocket. */
class GuardedZmqSocket
{
public:
    GuardedZmqSocket(void *psocketIn, const std::string &addressIn) : psocket(psocketIn), address(addressIn) {}
    ~GuardedZmqSocket();

    bool Bind();
    /** Send a multipart message: topic, body, and the topic's 4 byte little endian sequence number */
    bool Send(const char *command, const void *data, size_t size);

private:
    int SendMultipart(const void *data, size_t size, ...) EXCLUSIVE_LOCKS_REQUIRED(cs_guardedZmqSocket);
    void Close() EXCLUSIVE_LOCKS_REQUIRED(cs_guardedZmqSocket);

    CCriticalSection cs_guardedZmqSocket;
    // Null once closed, which also happens after a failed send.
    void *psocket GUARDED_BY(cs_guardedZmqSocket);
    // Next sequence number for each topic.
    std::map<std::string, uint32_t> mapSequence GUARDED_BY(cs_guardedZmqSocket);
    const std::string address;
};

class CZMQAbstractPublishNotifier : public CZMQAbstractNotifier
{
public:
    ~CZMQAbstractPublishNotifier();
    bool Initialize(void *pcontext);
    void Shutdown();

protected:
    std::shared_ptr<GuardedZmqSocket> socket;
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
