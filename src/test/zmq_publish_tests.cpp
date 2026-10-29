// Copyright (c) 2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/common.h"
#include "zmq/zmqpublishnotifier.h"

#include <boost/test/unit_test.hpp>
#include <cerrno>
#include <string>
#include <vector>

#ifndef MAC_OSX
namespace
{
struct ZmqFault
{
    int sends = 0;
    int inits = 0;
    int interruptSend = 0;
    int failInit = 0;
};
thread_local ZmqFault fault;
} // namespace

extern "C" int __real_zmq_msg_send(zmq_msg_t *msg, void *socket, int flags);
extern "C" int __real_zmq_msg_init_size(zmq_msg_t *msg, size_t size);

extern "C" int __wrap_zmq_msg_send(zmq_msg_t *msg, void *socket, int flags)
{
    if (++fault.sends == fault.interruptSend)
    {
        errno = EINTR;
        return -1;
    }
    return __real_zmq_msg_send(msg, socket, flags);
}

extern "C" int __wrap_zmq_msg_init_size(zmq_msg_t *msg, size_t size)
{
    if (++fault.inits == fault.failInit)
    {
        errno = ENOMEM;
        return -1;
    }
    return __real_zmq_msg_init_size(msg, size);
}
#endif

namespace
{
class TestPublisher : public CZMQAbstractPublishNotifier
{
public:
    ~TestPublisher() { Shutdown(); }
    using CZMQAbstractPublishNotifier::SendZmqMessage;
};

class TestSubscriber
{
    void *socket;

public:
    TestSubscriber(void *context, const std::string &address) : socket(zmq_socket(context, ZMQ_SUB))
    {
        BOOST_REQUIRE(socket);
        int timeout = 1000;
        int linger = 0;
        BOOST_REQUIRE_EQUAL(zmq_setsockopt(socket, ZMQ_RCVTIMEO, &timeout, sizeof(timeout)), 0);
        BOOST_REQUIRE_EQUAL(zmq_setsockopt(socket, ZMQ_LINGER, &linger, sizeof(linger)), 0);
        BOOST_REQUIRE_EQUAL(zmq_setsockopt(socket, ZMQ_SUBSCRIBE, "", 0), 0);
        BOOST_REQUIRE_EQUAL(zmq_connect(socket, address.c_str()), 0);
    }

    ~TestSubscriber() { zmq_close(socket); }

    bool Ready(int timeout = 0)
    {
        zmq_pollitem_t item = {socket, 0, ZMQ_POLLIN, 0};
        BOOST_REQUIRE(zmq_poll(&item, 1, timeout) >= 0);
        return item.revents & ZMQ_POLLIN;
    }

    std::vector<std::string> Receive()
    {
        std::vector<std::string> frames;
        int more = 0;
        do
        {
            char data[64];
            const int size = zmq_recv(socket, data, sizeof(data), 0);
            BOOST_REQUIRE(size >= 0 && size <= int(sizeof(data)));
            frames.emplace_back(data, size);
            size_t optionSize = sizeof(more);
            BOOST_REQUIRE_EQUAL(zmq_getsockopt(socket, ZMQ_RCVMORE, &more, &optionSize), 0);
        } while (more);
        return frames;
    }

    void Check(const std::string &topic, const std::string &body, uint32_t sequence)
    {
        const auto frames = Receive();
        BOOST_REQUIRE_EQUAL(frames.size(), 3);
        BOOST_CHECK_EQUAL(frames[0], topic);
        BOOST_CHECK_EQUAL(frames[1], body);
        BOOST_REQUIRE_EQUAL(frames[2].size(), 4);
        BOOST_CHECK_EQUAL(ReadLE32(reinterpret_cast<const uint8_t *>(frames[2].data())), sequence);
    }
};

struct ZmqSetup
{
    void *context = zmq_ctx_new();

    ZmqSetup() { BOOST_REQUIRE(context); }
    ~ZmqSetup() { zmq_ctx_term(context); }

    void Initialize(TestPublisher &publisher, const std::string &address)
    {
        publisher.SetAddress(address);
        publisher.SetType("test");
        BOOST_REQUIRE(publisher.Initialize(context));
    }

    void Warmup(TestPublisher &publisher, TestSubscriber &subscriber)
    {
        // Wait for the subscription to reach PUB before testing delivery.
        for (int attempt = 0; attempt < 200 && !subscriber.Ready(); ++attempt)
        {
            BOOST_REQUIRE(publisher.SendZmqMessage("warm", "ready", 5));
            subscriber.Ready(10);
        }
        BOOST_REQUIRE(subscriber.Ready());
        do
            subscriber.Receive();
        while (subscriber.Ready());
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(zmq_publish_tests, ZmqSetup)

BOOST_AUTO_TEST_CASE(shared_endpoint_preserves_topic_sequences)
{
    TestPublisher first, second;
    Initialize(first, "inproc://zmq-sequences");
    Initialize(second, "inproc://zmq-sequences");
    TestSubscriber subscriber(context, first.GetAddress());
    Warmup(first, subscriber);
    BOOST_REQUIRE(first.SendZmqMessage("alpha", "first", 5));
    subscriber.Check("alpha", "first", 0);
    BOOST_REQUIRE(second.SendZmqMessage("beta", "second", 6));
    subscriber.Check("beta", "second", 0);
    BOOST_REQUIRE(first.SendZmqMessage("alpha", "again", 5));
    subscriber.Check("alpha", "again", 1);
}

#ifndef MAC_OSX
BOOST_AUTO_TEST_CASE(interrupted_frames_are_retried)
{
    for (int part = 1; part <= 3; ++part)
    {
        TestPublisher publisher;
        Initialize(publisher, "inproc://zmq-eintr-" + std::to_string(part));
        TestSubscriber subscriber(context, publisher.GetAddress());
        Warmup(publisher, subscriber);
        fault = ZmqFault();
        fault.interruptSend = part;
        BOOST_CHECK(publisher.SendZmqMessage("alpha", "first", 5));
        subscriber.Check("alpha", "first", 0);
        BOOST_REQUIRE(publisher.SendZmqMessage("alpha", "second", 6));
        subscriber.Check("alpha", "second", 1);
        fault = ZmqFault();
    }
}

BOOST_AUTO_TEST_CASE(allocation_failure_disables_only_the_shared_endpoint)
{
    for (int part = 1; part <= 3; ++part)
    {
        TestPublisher first, sibling, healthy;
        const std::string suffix = std::to_string(part);
        Initialize(first, "inproc://zmq-failed-" + suffix);
        Initialize(sibling, "inproc://zmq-failed-" + suffix);
        Initialize(healthy, "inproc://zmq-healthy-" + suffix);
        TestSubscriber failedSub(context, first.GetAddress());
        TestSubscriber healthySub(context, healthy.GetAddress());
        Warmup(first, failedSub);
        Warmup(healthy, healthySub);
        fault = ZmqFault();
        fault.failInit = part;
        BOOST_CHECK(!first.SendZmqMessage("alpha", "first", 5));
        const int sends = fault.sends;
        const int inits = fault.inits;
        BOOST_CHECK(!sibling.SendZmqMessage("beta", "second", 6));
        BOOST_CHECK_EQUAL(fault.sends, sends);
        BOOST_CHECK_EQUAL(fault.inits, inits);
        BOOST_CHECK(!failedSub.Ready(20));
        fault = ZmqFault();
        BOOST_REQUIRE(healthy.SendZmqMessage("alpha", "live", 4));
        healthySub.Check("alpha", "live", 0);
    }
}
#endif

BOOST_AUTO_TEST_SUITE_END()
