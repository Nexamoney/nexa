// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zmqpublishnotifier.h"
#include "crypto/common.h"
#include "main.h"
#include "util.h"

static std::multimap<std::string, CZMQAbstractPublishNotifier *> mapPublishNotifiers;

GuardedZmqSocket::~GuardedZmqSocket()
{
    LOCK(cs_guardedZmqSocket);
    if (psocket)
    {
        LOG(ZMQ, "Close socket at address %s\n", address);
        Close();
    }
}

void GuardedZmqSocket::Close()
{
    int linger = 0;
    zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_close(psocket);
    psocket = nullptr;
}

bool GuardedZmqSocket::Bind()
{
    LOCK(cs_guardedZmqSocket);
    if (zmq_bind(psocket, address.c_str()) != 0)
    {
        zmqError("Failed to bind address");
        return false;
    }
    return true;
}

// Send each (data, size) pair as one part of a multipart message; the list ends with a null data pointer
int GuardedZmqSocket::SendMultipart(const void *data, size_t size, ...)
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
            rc = zmq_msg_send(&msg, psocket, data ? ZMQ_SNDMORE : 0);
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

bool GuardedZmqSocket::Send(const char *command, const void *data, size_t size)
{
    LOCK(cs_guardedZmqSocket);
    if (!psocket)
        return false;

    // Sequence gaps let subscribers detect messages dropped by PUB at the high water mark.
    uint32_t &nSequence = mapSequence[command];
    unsigned char msgseq[sizeof(uint32_t)];
    WriteLE32(&msgseq[0], nSequence);
    nSequence++;

    int rc = SendMultipart(command, strlen(command), data, size, msgseq, sizeof(msgseq), nullptr);
    if (rc != 0)
    {
        // A partial multipart message cannot be discarded without closing the socket.
        Close();
        LOGA("zmq: Disabled failed publisher at %s; restart to restore notifications\n", address);
        return false;
    }
    return true;
}

CZMQAbstractPublishNotifier::~CZMQAbstractPublishNotifier() { assert(!socket); }

bool CZMQAbstractPublishNotifier::Initialize(void *pcontext)
{
    assert(!socket);

    // check if address is being used by other publish notifier
    std::multimap<std::string, CZMQAbstractPublishNotifier *>::iterator i = mapPublishNotifiers.find(address);

    if (i == mapPublishNotifiers.end())
    {
        void *psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket)
        {
            zmqError("Failed to create socket");
            return false;
        }
        socket = std::make_shared<GuardedZmqSocket>(psocket, address);

        if (!socket->Bind())
            return false;

        // register this notifier for the address, so it can be reused for other publish notifier
        mapPublishNotifiers.insert(std::make_pair(address, this));
        return true;
    }
    else
    {
        LOG(ZMQ, "zmq: Reusing socket for address %s\n", address);

        socket = i->second->socket;
        mapPublishNotifiers.insert(std::make_pair(address, this));

        return true;
    }
}

void CZMQAbstractPublishNotifier::Shutdown()
{
    // If Initialize did not succeed, or was never called, then shutdown may be called with socket == nullptr
    if (socket != nullptr)
    {
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

        // The last notifier using the socket closes it
        socket.reset();
    }
}

bool CZMQPublishHashBlockNotifier::NotifyBlock(const CBlockIndex *pindex, const ConstCBlockRef /*pblock*/)
{
    uint256 hash = pindex->GetBlockHash();
    LOG(ZMQ, "zmq: Publish hashblock %s\n", hash.GetHex());
    char data[32];
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hash.begin()[i];
    return socket->Send("hashblock", data, 32);
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
        rc = socket->Send("txid", data, 32);
    }

    {
        uint256 hash = ptx->GetIdem();
        LOG(ZMQ, "zmq: Publish txidem %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc &= socket->Send("txidem", data, 32);
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
        rc = socket->Send("dsid", data, 32);
    }

    {
        uint256 hash = ptx->GetIdem();
        LOG(ZMQ, "zmq: Publish dsidem %s\n", hash.GetHex());
        char data[32];
        for (unsigned int i = 0; i < 32; i++)
            data[31 - i] = hash.begin()[i];
        rc &= socket->Send("dsidem", data, 32);
        return rc;
    }
}

bool CZMQPublishRawBlockNotifier::NotifyBlock(const CBlockIndex *pindex, const ConstCBlockRef pblock)
{
    LOG(ZMQ, "zmq: Publish rawblock %s\n", pindex->GetBlockHash().GetHex());

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *pblock;
    return socket->Send("rawblock", &(*ss.begin()), ss.size());
}

bool CZMQPublishRawTransactionNotifier::NotifyTransaction(const CTransactionRef &ptx)
{
    uint256 id = ptx->GetId();
    uint256 idem = ptx->GetIdem();
    LOG(ZMQ, "zmq: Publish rawtx %s (%s)\n", id.GetHex(), idem.GetHex());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *ptx;
    return socket->Send("rawtx", &(*ss.begin()), ss.size());
}

bool CZMQPublishRawDoubleSpendNotifier::NotifyDoubleSpend(const CTransactionRef ptx)
{
    uint256 id = ptx->GetId();
    uint256 idem = ptx->GetIdem();
    LOG(ZMQ, "zmq: Publish rawds %s (%s)\n", id.GetHex(), idem.GetHex());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << ptx;
    return socket->Send("rawds", &(*ss.begin()), ss.size());
}
