// Copyright (c) 2018-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dosman.h"
#include "extversionmessage.h"
#include "net.h"
#include "net_processing.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_nexa.h"

#include <stdint.h>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_FIXTURE_TEST_SUITE(extversionmessage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(decode1)
{
    std::vector<uint8_t> v;

    std::vector<uint8_t> xmap1 = ParseHex(" 05" // number of entries
                                          " 11   01 22"
                                          " 33   01 44"
                                          " 55   01 66"
                                          " 66   00" // empty (and not a compact integer)
                                          " 67   02 ff ff" // not a compact-size integer
        );
    // clang-format on

    v.insert(v.end(), xmap1.begin(), xmap1.end());

    CExtversionMessage xver;

    CDataStream stream(v, SER_NETWORK, PROTOCOL_VERSION);
    stream.SetVersion(0);

    stream >> xver;

    BOOST_CHECK_EQUAL(xver.xmap.size(), 5UL);
    BOOST_CHECK(xver.xmap[0x11] == std::vector<uint8_t>(1, 0x22));
    BOOST_CHECK(xver.xmap[0x66] == std::vector<uint8_t>());
    BOOST_CHECK(xver.xmap[0x67] == std::vector<uint8_t>(2, 0xff));
    BOOST_CHECK_EQUAL(xver.as_u64c(0x11), 0x22ULL);
    BOOST_CHECK_EQUAL(xver.as_u64c(0x33), 0x44ULL);
    BOOST_CHECK_EQUAL(xver.as_u64c(0x55), 0x66ULL);
    BOOST_CHECK_EQUAL(xver.as_u64c(0x66), 0x00ULL); // compact size decode failure
    BOOST_CHECK_EQUAL(xver.as_u64c(0x67), 0x00ULL); // compact size decode failure
    BOOST_CHECK_EQUAL(xver.as_u64c(0x77), 0x00ULL); // not in map

    BOOST_CHECK_EQUAL(xmap1.size(), GetSerializeSize(REF(CompactMapSerialization(xver.xmap)), SER_NETWORK, PROTOCOL_VERSION));
}

BOOST_AUTO_TEST_CASE(decode_replaces)
{
    // A second map read into the same message replaces the first rather than merging into it
    CExtversionMessage xver;
    CDataStream stream1(ParseHex("02 11 01 22 33 01 44"), SER_NETWORK, PROTOCOL_VERSION);
    stream1 >> xver;
    BOOST_CHECK_EQUAL(xver.xmap.size(), 2UL);
    CDataStream stream2(ParseHex("01 55 01 66"), SER_NETWORK, PROTOCOL_VERSION);
    stream2 >> xver;
    BOOST_CHECK_EQUAL(xver.xmap.size(), 1UL);
    BOOST_CHECK(xver.xmap.count(0x55));
    BOOST_CHECK(!xver.xmap.count(0x11));
}

BOOST_FIXTURE_TEST_CASE(duplicate_extversion_disconnects, TestingSetup)
{
    CNode node(INVALID_SOCKET, CAddress(ipaddress(0xa0b0c001, 10000)), "", true);
    node.nVersion = PROTOCOL_VERSION;
    node.tVersionSent = GetTime();

    CDataStream msg1(ParseHex("01 11 01 22"), SER_NETWORK, PROTOCOL_VERSION);
    ProcessMessage(&node, NetMsgType::EXTVERSION, 0, msg1, GetStopwatchMicros());
    BOOST_CHECK(!node.IsDisconnecting());

    CDataStream msg2(ParseHex("01 33 01 44"), SER_NETWORK, PROTOCOL_VERSION);
    ProcessMessage(&node, NetMsgType::EXTVERSION, 0, msg2, GetStopwatchMicros());
    BOOST_CHECK(node.IsDisconnecting());
    dosMan.ClearBanned();
}

BOOST_AUTO_TEST_SUITE_END()
