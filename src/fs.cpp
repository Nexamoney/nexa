// Copyright (c) 2017-2018 The Bitcoin Core developers
// Copyright (c) 2017-2024 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "fs.h"

#include <cstring>
#include <filesystem>

namespace fsbridge {

#ifdef WIN32
    #include <stringapiset.h>
    std::wstring charToWstring(const char *cstr)
    {
        const size_t length = std::strlen(cstr);
        const int requiredSize = MultiByteToWideChar(CP_UTF8, 0, cstr, length, NULL, 0);
        std::wstring wstr(requiredSize, 0);
        MultiByteToWideChar(CP_UTF8, 0, cstr, length, &wstr[0], requiredSize);
        return wstr;
    }

    std::wstring stringToWstring(const std::string str)
    {
        const char* cstr = str.c_str();
        return charToWstring(cstr);
    }

    std::string wcharToString(const wchar_t *wcstr)
    {
        const size_t length = std::wcslen(wcstr);
        const int requiredSize = WideCharToMultiByte(CP_UTF8, 0, wcstr, length, NULL, 0, NULL, NULL);
        std::string str(requiredSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, wcstr, length, &str[0], requiredSize, NULL, NULL);
        return str;
    }

    std::string wstringToString(const std::wstring wstr)
    {
        const wchar_t* wcstr = wstr.c_str();
        return wcharToString(wcstr);
    }
#endif // WIN32

FILE *fopen(const fs::path& p, const char *mode)
{
#ifdef WIN32
    // note: this conversion to wstring only works because the mode is ansii chars
    std::wstring wmode = charToWstring(mode);
    return ::_wfopen(p.wstring().c_str(), wmode.c_str());
#else // not WIN32
    return ::fopen(p.string().c_str(), mode);
#endif // WIN32
}

FILE *freopen(const fs::path& p, const char *mode, FILE *stream)
{
#ifdef WIN32
    std::wstring wmode = charToWstring(mode);
    return ::_wfreopen(p.wstring().c_str(), wmode.c_str(), stream);
#else // not WIN32
    return ::freopen(p.string().c_str(), mode, stream);
#endif // WIN32
}

} // fsbridge

#if __cplusplus >= 202002L
std::string fsPathToStdString(const fs::path &path)
{
#ifdef WIN32
    // convert to u8string before creating a std stirng to get a multibyte encoding of
    // the utf16 windows filepath
    const std::u8string utf8_str = path.u8string();
    return std::string{utf8_str.begin(), utf8_str.end()};
#else // not WIN32
    // posix is easy, noting special needed
    return path.string();
#endif // WIN32
}
#else // __cplusplus < 202002L
std::string fsPathToStdString(const fs::path &path)
{
#ifdef WIN32
    // the docs for u8string say "The result encoding in the case of u8string() is always UTF-8."
    // without the qualifier that it is true only in c++20 or higher, so this is expected to return a utf8
    // encoded std::string
    return path.u8string();

#else // not WIN32
    // posix is easy, noting special needed
    return path.string();
#endif // WIN32
}
#endif // __cplusplus >= 202002L


#if __cplusplus >= 202002L
fs::path stdStringToFsPath(const std::string &strPath)
{
#ifdef WIN32
    // convert to u8string before passing into fspath to maintain win utf16 encoding
    return fs::path(std::u8string(strPath.begin(), strPath.end()));
#else // not WIN32
    // posix is easy, nothing special needed
    return fs::path(strPath);
#endif // WIN32
}
#else // __cplusplus < 202002L
fs::path stdStringToFsPath(const std::string &strPath)
{
#ifdef WIN32
    // std::u8string is not available, use the windows API to convert to wide chars before
    // creating the path
    return fs::path(fsbridge::stringToWstring(strPath));
#else // not WIN32
    // posix is easy, nothing special needed
    return fs::path(strPath);
#endif // WIN32
}
#endif // __cplusplus >= 202002L
