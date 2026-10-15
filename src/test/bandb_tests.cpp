// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2023 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addrman.h"
#include "bandb.h"
#include "fs.h"
#include "net.h"
#include "test/test_nexa.h"

#include <string>

#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(bandb_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(unicode_peer_and_ban_files)
{
    // Test opening and replacing the real files, not just path conversion.
    const std::string original = GetArg("-datadir", "");
    BOOST_SCOPE_EXIT(&original)
    {
        SetArg("-datadir", original);
        ClearDatadirCache();
    }
    BOOST_SCOPE_EXIT_END
    const fs::path datadir = pathTemp / stdStringToFsPath("\xed\x95\x9c\xea\xb8\x80");
    fs::create_directories(datadir);
    SetArg("-datadir", fsPathToStdString(datadir));
    ClearDatadirCache();

    CBanDB bans;
    banmap_t expected, actual;
    const CSubNet subnet("192.0.2.1/32");
    expected[subnet] = CBanEntry(GetTime());
    BOOST_REQUIRE(bans.Write(expected));
    BOOST_REQUIRE(bans.Write(expected));
    BOOST_REQUIRE(bans.Read(actual));
    BOOST_REQUIRE_EQUAL(actual.size(), expected.size());
    BOOST_REQUIRE(actual.count(subnet));
    BOOST_CHECK_EQUAL(actual.at(subnet).nCreateTime, expected.at(subnet).nCreateTime);

    CAddrDB peers;
    CAddrMan addresses, restored;
    addresses.Add(CAddress(CService("250.1.1.1", 7228)), CNetAddr("250.1.1.2"));
    BOOST_REQUIRE_EQUAL(addresses.size(), 1u);
    BOOST_REQUIRE(peers.Write(addresses));
    BOOST_REQUIRE(peers.Write(addresses));
    BOOST_REQUIRE(peers.Read(restored));
    BOOST_CHECK_EQUAL(restored.size(), addresses.size());
    BOOST_CHECK(fs::exists(GetDataDir() / "peers.dat"));
    BOOST_CHECK(fs::exists(bans.GetDatabasePath()));
}

bool RemoveLocalDatabase(const fs::path &path)
{
    try
    {
        if (fs::exists(path))
        {
            // if the file already exists, remove it
            fs::remove(path);
        }

        // if we get here, we either successfully deleted the file, or it didn't exist
        return true;
    }
    catch (const std::exception &e)
    {
        // there was an error deleting the file
        return false;
    }
}

BOOST_AUTO_TEST_CASE(bandb_no_database)
{
    // create the CBanDB object
    CBanDB db;

    // Ensure local bandlist.dat has been removed
    BOOST_CHECK(RemoveLocalDatabase(db.GetDatabasePath()));

    // Try to read non-existent file (this shoudl fail)
    banmap_t banset;
    BOOST_CHECK(!db.Read(banset));
}

BOOST_AUTO_TEST_CASE(bandb_read_write_empty_database)
{
    // create the CBanDB object
    CBanDB db;

    // Ensure local bandlist.db has been removed
    BOOST_CHECK(RemoveLocalDatabase(db.GetDatabasePath()));

    // Write an empty banset_t to file
    banmap_t banset_write;
    BOOST_CHECK(db.Write(banset_write));

    // Read an empty banset_t from file
    banmap_t banset_read;
    BOOST_CHECK(db.Read(banset_read));
    // And ensure after reading in the banset is still empty
    BOOST_CHECK(banset_read.size() == 0);
}

BOOST_AUTO_TEST_CASE(bandb_read_write_non_empty_database)
{
    // create the CBanDB object
    CBanDB db;

    // Ensure local bandlist.db has been removed
    BOOST_CHECK(RemoveLocalDatabase(db.GetDatabasePath()));

    // Create sub-nets
    CSubNet singleIP("192.168.1.1/32");
    CSubNet subNet("10.168.1.1/24");

    // Write a non-empty banset_t to file
    banmap_t banset_write;
    // Add single IP
    CBanEntry write1(GetTime());
    write1.banReason = BanReasonNodeMisbehaving;
    write1.nBanUntil = GetTime() + 14400; // Ban 4 hours
    banset_write[singleIP] = write1;
    // Add subnet
    CBanEntry write2(GetTime());
    write2.banReason = BanReasonManuallyAdded;
    write2.nBanUntil = GetTime() + 28800; // Ban 8 hours
    banset_write[subNet] = write2;
    // Ensure we can succesfully write to the banlist.dat file
    BOOST_CHECK(db.Write(banset_write));

    // Read a non-empty banset_t from file
    banmap_t banset_read;
    BOOST_CHECK(db.Read(banset_read));
    // And ensure after reading in the banset contains 2 entries
    BOOST_CHECK(banset_read.size() == 2);

    // Ensure entry 1 matches the pre-write entry
    CBanEntry *read1 = &banset_read[singleIP];
    BOOST_CHECK(read1 != nullptr);
    BOOST_CHECK(read1->banReason == write1.banReason);
    BOOST_CHECK(read1->nBanUntil == write1.nBanUntil);
    BOOST_CHECK(read1->nCreateTime == write1.nCreateTime);

    // Ensure entry 2 matches the pre-write entry
    CBanEntry *read2 = &banset_read[subNet];
    BOOST_CHECK(read2 != nullptr);
    BOOST_CHECK(read2->banReason == write2.banReason);
    BOOST_CHECK(read2->nBanUntil == write2.nBanUntil);
    BOOST_CHECK(read2->nCreateTime == write2.nCreateTime);
}

BOOST_AUTO_TEST_SUITE_END()
