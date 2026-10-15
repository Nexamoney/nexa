// Copyright (c) 2026 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_WINARGV_H
#define NEXA_WINARGV_H

#ifdef WIN32
#include "fs.h"

#include <windows.h>

// shellapi.h requires the Windows types above.
#include <shellapi.h>

#include <memory>
#include <stdexcept>
#include <vector>

// Keep UTF-8 argument storage alive until the program exits.
class WinCmdLineArgs
{
    std::vector<std::string> args;
    std::vector<char *> pointers;

public:
    WinCmdLineArgs(int &argc, char **&argv, const wchar_t *commandLine = nullptr)
    {
        int count = 0;
        std::unique_ptr<wchar_t *, decltype(&LocalFree)> wideArgs(
            CommandLineToArgvW(commandLine ? commandLine : GetCommandLineW(), &count), &LocalFree);
        if (!wideArgs)
            throw std::runtime_error("Cannot read Windows command line");
        args.reserve(count);
        for (int i = 0; i < count; ++i)
            args.push_back(fsbridge::wcharToString(wideArgs.get()[i]));
        pointers.reserve(count + 1);
        for (auto &arg : args)
            pointers.push_back(arg.data());
        pointers.push_back(nullptr);
        argc = count;
        argv = pointers.data();
    }

    WinCmdLineArgs(const WinCmdLineArgs &) = delete;
    WinCmdLineArgs &operator=(const WinCmdLineArgs &) = delete;
};
#endif

#endif
