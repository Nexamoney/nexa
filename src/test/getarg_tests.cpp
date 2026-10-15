// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2015-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_nexa.h"
#include "util.h"

#include <string>
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/scope_exit.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(getarg_tests, BasicTestingSetup)

enum Kind
{
    NEXAD = 0,
    CONFIGFILE = 1,
    NEXA_CLI = 2
};

static void ResetArgs(const std::string &strArg, Kind kind = NEXAD)
{
    std::vector<std::string> vecArg;
    if (strArg.size())
        boost::split(vecArg, strArg, boost::is_space(), boost::token_compress_on);

    // Insert dummy executable name:
    vecArg.insert(vecArg.begin(), "testbitcoin");

    // Convert to char*:
    std::vector<const char *> vecChar;
    for (std::string &s : vecArg)
        vecChar.push_back(s.c_str());

    if (kind == CONFIGFILE)
        ParseParameters(vecChar.size(), &vecChar[0], AllowedArgs::ConfigFile(&tweaks));
    else if (kind == NEXAD)
        ParseParameters(vecChar.size(), &vecChar[0], AllowedArgs::Nexad(&tweaks));
    else
        ParseParameters(vecChar.size(), &vecChar[0], AllowedArgs::NexaCli());
}

BOOST_AUTO_TEST_CASE(path_arguments)
{
    // Path options stay UTF-8 until use; command-line values override the config file.
    const auto originalArgs = mapArgs;
    const auto originalMultiArgs = mapMultiArgs;
    const fs::path temp = fs::temp_directory_path() / ("nexa-path-args-" + InsecureRand256().GetHex());
    BOOST_SCOPE_EXIT(&originalArgs, &originalMultiArgs, &temp)
    {
        mapArgs = originalArgs;
        mapMultiArgs = originalMultiArgs;
        ClearDatadirCache();
        fs::remove_all(temp);
    }
    BOOST_SCOPE_EXIT_END

    const fs::path unicode = stdStringToFsPath("\xed\x95\x9c\xea\xb8\x80 dir");
    const fs::path cliDir = temp / unicode;
    const fs::path configDir = temp / "config" / unicode;
    fs::create_directories(cliDir);
    fs::create_directories(configDir);
    const fs::path configName = unicode.native() + fs::path(".conf").native();
    const fs::path forksName = unicode.native() + fs::path(".csv").native();
    const fs::path configPath = cliDir / configName;
    {
        fs_ofstream config(configPath);
        config << "datadir=" << fsPathToStdString(configDir) << "\n";
        BOOST_REQUIRE(config.good());
    }

    const auto parse = [](const std::vector<std::string> &args)
    {
        std::vector<const char *> argv;
        for (const auto &arg : args)
            argv.push_back(arg.c_str());
        ParseParameters(argv.size(), argv.data(), AllowedArgs::Nexad(&tweaks));
        ClearDatadirCache();
    };
    const std::string cliPath = fsPathToStdString(cliDir);
    const std::string configuredPath = fsPathToStdString(configDir);
    parse({"nexad", "-datadir=" + configuredPath, "-datadir=" + cliPath, "-conf=" + fsPathToStdString(configName),
        "-forks=" + fsPathToStdString(forksName)});
    BOOST_CHECK_EQUAL(GetArg("-datadir", ""), cliPath);
    BOOST_REQUIRE_EQUAL(mapMultiArgs.at("-datadir").size(), 2u);
    BOOST_CHECK_EQUAL(mapMultiArgs.at("-datadir").front(), configuredPath);
    BOOST_CHECK_EQUAL(mapMultiArgs.at("-datadir").back(), cliPath);
    BOOST_CHECK(GetDataDir(false) == cliDir);
    BOOST_CHECK(GetConfigFile(GetArg("-conf", "")) == configPath);
    BOOST_CHECK(GetForksCsvFile() == cliDir / forksName);
    ReadConfigFile(mapArgs, mapMultiArgs, AllowedArgs::ConfigFile(&tweaks));
    BOOST_CHECK_EQUAL(GetArg("-datadir", ""), cliPath);
    BOOST_CHECK(GetDataDir(false) == cliDir);
    BOOST_CHECK_EQUAL(mapMultiArgs.at("-datadir").size(), 3u);

    // Re-parsing must not retain the previous command-line data directory.
    parse({"nexad", "-conf=" + fsPathToStdString(configPath), "-forks=" + fsPathToStdString(cliDir / forksName)});
    BOOST_CHECK(mapArgs.count("-datadir") == 0);
    BOOST_CHECK(GetConfigFile(GetArg("-conf", "")) == configPath);
    BOOST_CHECK(GetForksCsvFile() == cliDir / forksName);
    ReadConfigFile(mapArgs, mapMultiArgs, AllowedArgs::ConfigFile(&tweaks));
    BOOST_CHECK_EQUAL(GetArg("-datadir", ""), configuredPath);
    BOOST_CHECK(GetDataDir(false) == configDir);
    BOOST_REQUIRE_EQUAL(mapMultiArgs.at("-datadir").size(), 1u);
    BOOST_CHECK_EQUAL(mapMultiArgs.at("-datadir").front(), configuredPath);
}

BOOST_AUTO_TEST_CASE(boolarg)
{
    ResetArgs("-listen");
    BOOST_CHECK(GetBoolArg("-listen", false));
    BOOST_CHECK(GetBoolArg("-listen", true));

    BOOST_CHECK(!GetBoolArg("-fo", false));
    BOOST_CHECK(GetBoolArg("-fo", true));

    BOOST_CHECK(!GetBoolArg("-fooo", false));
    BOOST_CHECK(GetBoolArg("-fooo", true));

    for (auto strValue : std::list<std::string>{"0", "f", "n", "false", "no"})
    {
        ResetArgs("-listen=" + strValue);
        BOOST_CHECK(!GetBoolArg("-listen", false));
        BOOST_CHECK(!GetBoolArg("-listen", true));
    }

    for (auto strValue : std::list<std::string>{"", "1", "t", "y", "true", "yes"})
    {
        ResetArgs("-listen=" + strValue);
        BOOST_CHECK(GetBoolArg("-listen", false));
        BOOST_CHECK(GetBoolArg("-listen", true));
    }

    // New 0.6 feature: auto-map -nosomething to !-something:
    ResetArgs("-nolisten");
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    ResetArgs("-nolisten=1");
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    ResetArgs("-listen -nolisten"); // -nolisten should win
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    ResetArgs("-listen=1 -nolisten=1"); // -nolisten should win
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    ResetArgs("-listen=0 -nolisten=0"); // -nolisten=0 should win
    BOOST_CHECK(GetBoolArg("-listen", false));
    BOOST_CHECK(GetBoolArg("-listen", true));

    // New 0.6 feature: treat -- same as -:
    ResetArgs("--listen=1");
    BOOST_CHECK(GetBoolArg("-listen", false));
    BOOST_CHECK(GetBoolArg("-listen", true));

    ResetArgs("--nolisten=1");
    BOOST_CHECK(!GetBoolArg("-listen", false));
    BOOST_CHECK(!GetBoolArg("-listen", true));

    BOOST_CHECK_THROW(ResetArgs("-listen=text"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(stringarg)
{
    ResetArgs("");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", "eleven"), "eleven");

    ResetArgs("-connect -listen"); // -connect is an optional string argument
    BOOST_CHECK_EQUAL(GetArg("-connect", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-connect", "eleven"), "");

    ResetArgs("-connect=");
    BOOST_CHECK_EQUAL(GetArg("-connect", ""), "");
    BOOST_CHECK_EQUAL(GetArg("-connect", "eleven"), "");

    ResetArgs("-uacomment=11");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", ""), "11");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", "eleven"), "11");

    ResetArgs("-uacomment=eleven");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", ""), "eleven");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", "eleven"), "eleven");

    BOOST_CHECK_THROW(ResetArgs("-uacomment"), std::runtime_error);
    BOOST_CHECK_THROW(ResetArgs("-uacomment="), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(intarg)
{
#ifdef ENABLE_WALLET
    ResetArgs("");
    BOOST_CHECK_EQUAL(GetArg("-zapwallettxes", 11), 11);
    BOOST_CHECK_EQUAL(GetArg("-zapwallettxes", 0), 0);

    ResetArgs("-zapwallettxes"); // is an optional int argument
    BOOST_CHECK_EQUAL(GetArg("-zapwallettxes", 11), 0);
#endif

#ifdef ENABLE_WALLET
    ResetArgs("-zapwallettxes=11 -maxreceivebuffer=12");
    BOOST_CHECK_EQUAL(GetArg("-zapwallettxes", 0), 11);
#else
    ResetArgs("-maxreceivebuffer=12");
    BOOST_CHECK_EQUAL(GetArg("-maxreceivebuffer", 11), 12);
#endif

    ResetArgs("-par=-1");
    BOOST_CHECK_EQUAL(GetArg("-par", 0), -1);

    BOOST_CHECK_THROW(ResetArgs("-maxreceivebuffer"), std::runtime_error);
    BOOST_CHECK_THROW(ResetArgs("-maxreceivebuffer="), std::runtime_error);
    BOOST_CHECK_THROW(ResetArgs("-maxreceivebuffer=NaN"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(doubledash)
{
    ResetArgs("--listen");
    BOOST_CHECK_EQUAL(GetBoolArg("-listen", false), true);

#ifdef ENABLE_WALLET
    ResetArgs("--uacomment=verbose --zapwallettxes=1");
    BOOST_CHECK_EQUAL(GetArg("-uacomment", ""), "verbose");
    BOOST_CHECK_EQUAL(GetArg("-zapwallettxes", 0), 1);
#endif
}

BOOST_AUTO_TEST_CASE(boolargno)
{
    ResetArgs("-nolisten");
    BOOST_CHECK(!GetBoolArg("-listen", true));
    BOOST_CHECK(!GetBoolArg("-listen", false));

    ResetArgs("-nolisten=1");
    BOOST_CHECK(!GetBoolArg("-listen", true));
    BOOST_CHECK(!GetBoolArg("-listen", false));

    ResetArgs("-nolisten=0");
    BOOST_CHECK(GetBoolArg("-listen", true));
    BOOST_CHECK(GetBoolArg("-listen", false));

    ResetArgs("-listen --nolisten"); // --nolisten should win
    BOOST_CHECK(!GetBoolArg("-listen", true));
    BOOST_CHECK(!GetBoolArg("-listen", false));

    ResetArgs("-nolisten -listen"); // -listen always wins:
    BOOST_CHECK(GetBoolArg("-listen", true));
    BOOST_CHECK(GetBoolArg("-listen", false));
}

BOOST_AUTO_TEST_CASE(tweakArgs)
{
#ifdef ENABLE_WALLET
    ResetArgs("-mining.comment=I_Am_A_Meat_Popsicle -mining.coinbaseReserve=250 -wallet.maxTxFee=0.001");
#else
    ResetArgs("-mining.comment=I_Am_A_Meat_Popsicle -mining.coinbaseReserve=250");
#endif
    BOOST_CHECK_EQUAL(GetArg("-mining.comment", "foo"), "I_Am_A_Meat_Popsicle");
    BOOST_CHECK_EQUAL(GetArg("-mining.coinbaseReserve", 100), 250);
#ifdef ENABLE_WALLET
    BOOST_CHECK_EQUAL(GetArg("-wallet.maxTxFee", ""), "0.001");
#endif
    // Test ConfigFile accepts tweaks
#ifdef ENABLE_WALLET
    ResetArgs("-mining.comment=I_Am_A_Meat_Popsicle -mining.coinbaseReserve=250 -wallet.maxTxFee=0.001", CONFIGFILE);
#else
    ResetArgs("-mining.comment=I_Am_A_Meat_Popsicle -mining.coinbaseReserve=250", CONFIGFILE);
#endif
    BOOST_CHECK_EQUAL(GetArg("-mining.comment", "foo"), "I_Am_A_Meat_Popsicle");
    BOOST_CHECK_EQUAL(GetArg("-mining.coinbaseReserve", 100), 250);
#ifdef ENABLE_WALLET
    BOOST_CHECK_EQUAL(GetArg("-wallet.maxTxFee", ""), "0.001");
#endif
    // Test ConfigFile rejects unknown tweaks
    BOOST_CHECK_THROW(ResetArgs("-some.tweak=something", CONFIGFILE), std::runtime_error);

    // Test bitcoin-cli accepts unknown tweaks
    ResetArgs("-some.tweak=something", NEXA_CLI);
    BOOST_CHECK_EQUAL(GetArg("-some.tweak", "default"), "something");
}

BOOST_AUTO_TEST_CASE(unrecognizedArgs)
{
    BOOST_CHECK_THROW(ResetArgs("-unrecognized_arg"), std::runtime_error);
    BOOST_CHECK_THROW(ResetArgs("-listen -unrecognized_arg"), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
