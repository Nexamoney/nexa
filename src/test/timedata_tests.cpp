// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include "test/test_nexa.h"
#include "timedata.h"

#include "net_processing.h"
#include "netaddress.h"
#include "util.h"

#include <limits>

#include <boost/test/unit_test.hpp>

using namespace std;

struct ScopedTimeDataReset
{
    const string savedWarning = strMiscWarning;
    const int64_t savedMockTime = IsMockTime() ? GetTime() : 0;

    ScopedTimeDataReset() { ResetTimeDataForTest(); }
    ~ScopedTimeDataReset()
    {
        ResetTimeDataForTest();
        strMiscWarning = savedWarning;
        SetMockTime(savedMockTime);
    }
};

static CNetAddr TimeTestAddress(uint32_t i)
{
    in_addr ipv4;
    ipv4.s_addr = htonl(0x0a5c0000 | i);
    return CNetAddr(ipv4);
}

BOOST_FIXTURE_TEST_SUITE(timedata_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(util_MedianFilter)
{
    CMedianFilter<int> filter(5, 15);

    BOOST_CHECK_EQUAL(filter.median(), 15);

    filter.input(20); // [15 20]
    BOOST_CHECK_EQUAL(filter.median(), 17);

    filter.input(30); // [15 20 30]
    BOOST_CHECK_EQUAL(filter.median(), 20);

    filter.input(3); // [3 15 20 30]
    BOOST_CHECK_EQUAL(filter.median(), 17);

    filter.input(7); // [3 7 15 20 30]
    BOOST_CHECK_EQUAL(filter.median(), 15);

    filter.input(18); // [3 7 18 20 30]
    BOOST_CHECK_EQUAL(filter.median(), 18);

    filter.input(0); // [0 3 7 18 30]
    BOOST_CHECK_EQUAL(filter.median(), 7);
}

BOOST_AUTO_TEST_CASE(time_offset_bounds)
{
    ScopedTimeDataReset reset;
    const pair<int64_t, int64_t> cases[] = {{numeric_limits<int64_t>::min(), 0}, {-4201, 0}, {-4200, 0}, {-4199, -4199},
        {-1, -1}, {0, 0}, {1, 1}, {4199, 4199}, {4200, 0}, {4201, 0}, {numeric_limits<int64_t>::max(), 0}};
    for (const auto &test : cases)
    {
        ResetTimeDataForTest();
        // Four equal peer samples dominate the initial zero sample.
        for (uint32_t i = 1; i <= 4; i++)
            AddTimeData(TimeTestAddress(i), test.first);
        BOOST_CHECK_EQUAL(GetTimeOffset(), test.second);
    }
}

BOOST_AUTO_TEST_CASE(time_data_reset_after_full_sample_set)
{
    ScopedTimeDataReset reset;
    for (uint32_t i = 1; i <= 200; i++)
        AddTimeData(TimeTestAddress(i), 60);
    BOOST_CHECK_EQUAL(GetTimeOffset(), 60);

    ResetTimeDataForTest();
    BOOST_CHECK_EQUAL(GetTimeOffset(), 0);
    for (uint32_t i = 1; i <= 4; i++)
        AddTimeData(TimeTestAddress(i), -60);
    BOOST_CHECK_EQUAL(GetTimeOffset(), -60);
}

BOOST_AUTO_TEST_CASE(time_offset_warning_bounds)
{
    ScopedTimeDataReset reset;
    const pair<int64_t, bool> cases[] = {{numeric_limits<int64_t>::min(), true}, {-300, true}, {-299, false}, {0, true},
        {299, false}, {300, true}, {numeric_limits<int64_t>::max(), true}};
    for (const auto &test : cases)
    {
        ResetTimeDataForTest();
        strMiscWarning.clear();
        AddTimeData(TimeTestAddress(1), test.first);
        // An out-of-range median warns only if no nonzero sample is within five minutes.
        for (uint32_t i = 2; i <= 4; i++)
            AddTimeData(TimeTestAddress(i), 5000);
        BOOST_CHECK_EQUAL(GetTimeOffset(), 0);
        BOOST_CHECK_EQUAL(!strMiscWarning.empty(), test.second);
    }
}

BOOST_FIXTURE_TEST_CASE(version_time_extremes, TestingSetup)
{
    ScopedTimeDataReset reset;
    const int64_t now = 1700000000;
    SetMockTime(now);
    const pair<int64_t, int64_t> cases[] = {{numeric_limits<int64_t>::min(), -now},
        {numeric_limits<int64_t>::min() + now, -now}, {-1, -now}, {0, -now}, {1, 1 - now}, {now - 4199, -4199},
        {now, 0}, {now + 4199, 4199}, {numeric_limits<int64_t>::max(), numeric_limits<int64_t>::max() - now}};
    uint32_t ip = 1;
    for (const auto &test : cases)
    {
        CAddress address(CService(TimeTestAddress(ip++), 10000));
        CNode node(INVALID_SOCKET, address, "", true);
        node.nVersion = 0;
        CDataStream message(SER_NETWORK, PROTOCOL_VERSION);
        message << MIN_PEER_PROTO_VERSION << uint64_t(NODE_NETWORK) << test.first << address;
        BOOST_REQUIRE(ProcessMessage(&node, NetMsgType::VERSION, 0, message, GetStopwatchMicros()));
        BOOST_CHECK_EQUAL(node.nTimeOffset, test.second);
        BOOST_CHECK(GetTimeOffset() > -4200 && GetTimeOffset() < 4200);
    }
}

BOOST_AUTO_TEST_SUITE_END()
