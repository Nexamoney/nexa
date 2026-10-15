// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2017-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEXA_FS_H
#define NEXA_FS_H

#include <stdio.h>
#include <string>

#include <filesystem>
#include <fstream>
namespace fs = std::filesystem;

typedef std::fstream fstream;  // Because when we convert to std, it will be std::fstream
typedef std::ifstream fs_ifstream;  // Because when we convert to std, it will be std::fstream
typedef std::ofstream fs_ofstream;  // Because when we convert to std, it will be std::fstream

/** Bridge operations to C stdio */
namespace fsbridge {
#ifdef WIN32
    // windows string conversion functions
    std::wstring charToWstring(const char *cstr);
    std::wstring stringToWstring(const std::string str);
    std::string wcharToString(const wchar_t *wcstr);
    std::string wstringToString(const std::wstring wstr);
#endif

    FILE *fopen(const fs::path& p, const char *mode);
    FILE *freopen(const fs::path& p, const char *mode, FILE *stream);
};

std::string fsPathToStdString(const fs::path &path);
fs::path stdStringToFsPath(const std::string &strPath);

bool RenameOver(fs::path src, fs::path dest);

bool TryCreateDirectories(const fs::path &p);
fs::path GetDefaultDataDir();
const fs::path &GetDataDir(bool fNetSpecific = true);
void ClearDatadirCache();
fs::path GetConfigFile(const std::string &confPath);
#ifndef WIN32
fs::path GetPidFile();
void CreatePidFile(const fs::path &path, pid_t pid);
#endif

#ifdef WIN32
fs::path GetSpecialFolderPath(int nFolder, bool fCreate = true);
#endif

#endif
