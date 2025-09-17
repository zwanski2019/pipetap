#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <string>
#include <Windows.h>

namespace pipetap::win {

    inline std::string WideToUtf8(const wchar_t* ws) {
        if (!ws) return {};

        int bytes = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
        if (bytes <= 0) return {};

        std::string out; out.resize(static_cast<size_t>(bytes - 1));
        if (bytes > 1) WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), bytes, nullptr, nullptr);

        return out;
    }

    inline std::wstring Utf8ToWide(const char* s) {
        if (!s) return {};

        int wch = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
        if (wch <= 0) return {};

        std::wstring out; out.resize(static_cast<size_t>(wch - 1));
        if (wch > 1) MultiByteToWideChar(CP_UTF8, 0, s, -1, out.data(), wch);
        return out;
    }

    // Narrow via ANSI code page (used by process snapshot code)
    inline std::string NarrowAcp(const wchar_t* ws) {
        if (!ws) return {};

        int lenW = (int)wcslen(ws);
        if (lenW == 0) return {};

        int bytes = WideCharToMultiByte(CP_ACP, 0, ws, lenW, nullptr, 0, nullptr, nullptr);
        std::string out(bytes, '\0');
        WideCharToMultiByte(CP_ACP, 0, ws, lenW, out.data(), bytes, nullptr, nullptr);

        return out;
    }

} // namespace pipetap::win
