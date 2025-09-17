#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <sstream>
#include <string>
#include <Windows.h>

namespace pipetap::win {

    inline std::string FormatLeA(DWORD le) {
        LPSTR buf = nullptr;
        DWORD n = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, le, 0, (LPSTR)&buf, 0, nullptr);

        std::string out = (n && buf) ? std::string(buf, buf + n) : "unknown error";

        if (buf) LocalFree(buf);

        while (!out.empty() && (out.back() == '\r' || out.back() == '\n' || out.back() == ' ')) out.pop_back();
        std::ostringstream os; os << out << " (le=" << le << ")";

        return os.str();
    }

    inline std::string FormatLastErrorA(DWORD le) { return FormatLeA(le); }

} // namespace pipetap::win
