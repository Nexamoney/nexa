// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zmqpublishnotifier.h"
#include "crypto/common.h"
#include "main.h"
#include "util.h"

static std::multimap<std::string, CZMQAbstractPublishNotifier *> mapPublishNotifiers;

// Internal function to send multipart message
static int zmq_send_multipart(void *sock, const void *data, size_t size, ...)
{
    va_list args;
    va_start(args, size);

    while (1)
    {
        zmq_msg_t msg;

        int rc = zmq_msg_init_size(&msg, size);
        if (rc != 0)
        {
            zmqError("Unable to initialize ZMQ msg");
            va_end(args);
            return -1;
        }

        void *buf = zmq_msg_data(&msg);
        memcpy(buf, data, size);

        data = va_arg(args, const void *);

        do
        {
            rc = zmq_msg_send(&msg, sock, data ? ZMQ_SNDMORE : 0);
        } while (rc == -1 && errno == EINTR);
        if (rc == -1)
        {
            zmqError("Unable to send ZMQ msg");
            zmq_msg_close(&msg);
            va_end(args);
            return -1;
        }

        zmq_msg_close(&msg);

        if (!data)
            break;

        size = va_arg(args, size_t);
    }
    va_end(args);
    return 0;
}

bool CZMQAbstractPublishNotifier::Initialize(void *pcontext)
{
    assert(!psocket);

    // check if address is being used by other publish notifier
    std::multimap<std::string, CZMQAbstractPublishNotifier *>::iterator i = mapPublishNotifiers.find(address);

    if (i == mapPublishNotifiers.end())
    {
        psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket)
        {
            zmqError("Failed to create socket");
            return false;
        }
        socketState = std::make_shared<SocketState>();

        int rc = zmq_bind(psocket, address.c_str());
        if (rc != 0)
        {
            zmqError("Failed to bind address");
            return false;
        }

        // register this notifier for the address, so it can be reused for other publish notifier
        mapPublishNotifiers.insert(std::make_pair(address, this));
        return true;
    }
    else
    {
        LOG(ZMQ, "zmq: Reusing socket for address %s\n", address);

        psocket = i->second->psocket;
        socketState = i->second->socketState;
        mapPublishNotifiers.insert(std::make_pair(address, this));

        return true;
    }
}

void CZMQAbstractPublishNotifier::Shutdown()
{
    // If Initialize did not succeed, or was never called, then shutdown may be called with psocket == nullptr
    if (psocket != nullptr)
    {
        int count = mapPublishNotifiers.count(address);

        // remove this notifier from the list of publishers using this address
        typedef std::multimap<std::string, CZMQAbstractPublishNotifier *>::iterator iterator;
        std::pair<iterator, iterator> iterpair = mapPublishNotifiers.equal_range(address);

        for (iterator it = iterpair.first; it != iterpair.second; ++it)
        {
            if (it->second == this)
            {
                mapPublishNotifiers.erase(it);
                break;
            }
        }

        if (count <= 1)
        {
            LOG(ZMQ, "Close socket at address %s\n", address);
            LOCK(socketState->cs);
            if (!socketState->failed)
            {
                int linger = 0;
                zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
                zmq_close(psocket);
            }
        }

        psocket = nullptr;
        socketState.reset();
    }
}

bool CZMQAbstractPublishNotifier::SendZmqMessage(const char *command, const void *data, size_t size)
{
    assert(psocket);
    LOCK(socketState->cs);
    if (socketState->failed)
        return false;

    // Sequence gaps let subscribers detect messages dropped by PUB at the high water mark.
    uint32_t &nSequence = mapSequence[command];
    unsigned char msgseq[sizeof(uint32_t)];
    WriteLE32(&msgseq[0], nSequence);
    nSequence++;

    int rc = zmq_send_multipart(psocket, command, strlen(command), data, size, msgseq, sizeof(msgseq), nullptr);
    if (rc != 0)
    {
        // A partial multipart message cannot be discarded without closing the socket.
        socketState->failed = true;
        int linger = 0;
        zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(psocket);
        LOGA("zmq: Disabled failed publisher at %s; restart to restore notifications\n", address);
        return false;
    }
    return true;
}

bool CZMQPublishHashBlockNotifier::NotifyBlock(const CBlockIndex *pindex, const ConstCBlockRef /*pblock*/)
{
    uint256 hash = pindex->GetBlockHash();
    LOG(ZMQ, "zmq: Publish hashblock %s\n", hash.GetHex());
    char data[32];
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hash.begin()[i];
    return SendZmqMessage("hashblock", data, 32);
}

bool CZMQPublishHashTransactionNotifier::NotifyTransaction(const CTransactionRef &ptx)
{
    bool rc;

    {
        uint256 hash = ptx->GetId();
        LOG(ZMQ, "zmq: Publish txid %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc = SendZmqMessage("txid", data, 32);
    }

    {
        uint256 hash = ptx->GetIdem();
        LOG(ZMQ, "zmq: Publish txidem %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc &= SendZmqMessage("txidem", data, 32);
    }

    return rc;
}

bool CZMQPublishHashDoubleSpendNotifier::NotifyDoubleSpend(const CTransactionRef ptx)
{
    bool rc;
    {
        uint256 hash = ptx->GetId();
        LOG(ZMQ, "zmq: Publish dsid %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc = SendZmqMessage("dsid", data, 32);
    }

    {
        uint256 hash = ptx->GetIdem();
        LOG(ZMQ, "zmq: Publish dsidem %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc &= SendZmqMessage("dsidem", data, 32);
        return rc;
    }
}

bool CZMQPublishRawBlockNotifier::NotifyBlock(const CBlockIndex *pindex, const ConstCBlockRef pblock)
{
    LOG(ZMQ, "zmq: Publish rawblock %s\n", pindex->GetBlockHash().GetHex());

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *pblock;
    return SendZmqMessage("rawblock", &(*ss.begin()), ss.size());
}

bool CZMQPublishRawTransactionNotifier::NotifyTransaction(const CTransactionRef &ptx)
{
    uint256 id = ptx->GetId();
    uint256 idem = ptx->GetIdem();
    LOG(ZMQ, "zmq: Publish rawtx %s (%s)\n", id.GetHex(), idem.GetHex());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *ptx;
    return SendZmqMessage("rawtx", &(*ss.begin()), ss.size());
}

bool CZMQPublishRawDoubleSpendNotifier::NotifyDoubleSpend(const CTransactionRef ptx)
{
    uint256 id = ptx->GetId();
    uint256 idem = ptx->GetIdem();
    LOG(ZMQ, "zmq: Publish rawds %s (%s)\n", id.GetHex(), idem.GetHex());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << ptx;
    return SendZmqMessage("rawds", &(*ss.begin()), ss.size());
}
