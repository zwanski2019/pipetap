#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <algorithm>
#include <string>
#include <vector>
#include <Windows.h>

namespace pipetap::inject {

    inline bool is_named_pipe_handle(HANDLE h)
    {
        if (!h || h == INVALID_HANDLE_VALUE) return false;
        if (GetFileType(h) != FILE_TYPE_PIPE) return false;

        DWORD flags = 0, outBuf = 0, inBuf = 0, maxInst = 0;
        if (GetNamedPipeInfo(h, &flags, &outBuf, &inBuf, &maxInst)) return true;
        if (GetNamedPipeHandleStateA(h, &flags, nullptr, nullptr, nullptr, nullptr, 0)) return true;
        return false;
    }

    inline void query_pipe_hints(HANDLE h, uint8_t& is_msg, uint32_t& outHint, uint32_t& inHint)
    {
        is_msg = 0; outHint = 0; inHint = 0;
        DWORD flags = 0, outBuf = 0, inBuf = 0, maxInst = 0;
        if (GetNamedPipeInfo(h, &flags, &outBuf, &inBuf, &maxInst)) {
            is_msg = (flags & PIPE_TYPE_MESSAGE) ? 1U : 0U;
            outHint = outBuf;
            inHint = inBuf;
            return;
        }
        if (GetNamedPipeHandleStateA(h, &flags, nullptr, nullptr, nullptr, nullptr, 0)) {
            is_msg = (flags & PIPE_READMODE_MESSAGE) ? 1U : 0U;
        }
    }

    inline std::string w_to_utf8(const wchar_t* ws, size_t chars)
    {
        if (!ws || chars == 0) return {};
        int need = WideCharToMultiByte(CP_UTF8, 0, ws, (int)chars, nullptr, 0, nullptr, nullptr);
        if (need <= 0) return {};
        std::string out(need, '\0');
        WideCharToMultiByte(CP_UTF8, 0, ws, (int)chars, out.data(), need, nullptr, nullptr);
        return out;
    }

    inline std::string exe_base_name()
    {
        char path[MAX_PATH] = { 0 };
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        const char* base = strrchr(path, '\\');
        return base ? std::string(base + 1) : std::string(path);
    }

    // Prefer \\.\pipe\NAME, else fall back to NT path or "(pipe)".
    inline std::string pipe_name_for_handle(HANDLE h)
    {
        if (!h || h == INVALID_HANDLE_VALUE) return "(pipe)";

        DWORD sz = 0;
        GetFileInformationByHandleEx(h, FileNameInfo, nullptr, 0);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) sz = 4096;
        else sz = 4096;

        std::vector<BYTE> buf(sz);
#pragma warning(push)
#pragma warning(disable : 4996)
        if (!GetFileInformationByHandleEx(h, FileNameInfo, buf.data(), (DWORD)buf.size()))
            return "(pipe)";
        auto* info = reinterpret_cast<FILE_NAME_INFO*>(buf.data());
        size_t wcharCount = info->FileNameLength / sizeof(WCHAR);
        std::wstring ntPath(info->FileName, wcharCount);
#pragma warning(pop)

        const std::wstring needle = L"\\Device\\NamedPipe\\";
        if (ntPath.rfind(needle, 0) == 0) {
            std::wstring tail = ntPath.substr(needle.size());
            std::string tail8 = w_to_utf8(tail.c_str(), tail.size());
            if (!tail8.empty()) return std::string(R"(\\.\pipe\)") + tail8;
        }
        std::string nt8 = w_to_utf8(ntPath.c_str(), ntPath.size());
        return nt8.empty() ? "(pipe)" : nt8;
    }

} // namespace pipetap::inject
