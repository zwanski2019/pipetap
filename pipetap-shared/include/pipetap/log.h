#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <io.h>
#include <mutex>
#include <ShlObj.h>
#include <string>
#include <vector>
#include <Windows.h>

namespace pipetap::log
{

    namespace detail
    {
        inline FILE* g_file = nullptr;
        inline SRWLOCK g_lock = SRWLOCK_INIT;
        inline std::string g_filename = "log.log";
        inline std::string g_explicit_path = {};

        // Prefer %APPDATA%\pipetap\<filename> using Windows API (no environment variables).
        // Fallback to the executable directory if AppData cannot be resolved.
        inline std::string default_dir_file()
        {
            char appdata[MAX_PATH] = { 0 };
            if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, appdata)) &&
                appdata[0] != '\0')
            {
                std::string dir = std::string(appdata) + "\\pipetap";
                // Create the directory if it doesn't exist (ignore ERROR_ALREADY_EXISTS).
                CreateDirectoryA(dir.c_str(), nullptr);
                return dir + "\\" + g_filename;
            }

            // Fallback: alongside the executable
            char exe[MAX_PATH] = { 0 };
            GetModuleFileNameA(nullptr, exe, MAX_PATH);
            char* slash = strrchr(exe, '\\');
            if (!slash)
                return g_filename;
            *(slash + 1) = '\0';
            return std::string(exe) + g_filename;
        }

        inline std::string effective_path()
        {
            if (!g_explicit_path.empty())
                return g_explicit_path;
            return default_dir_file();
        }

        inline void write_line_nolock(const char* s)
        {
            if (!g_file)
                return;
            fwrite(s, 1, strlen(s), g_file);
            fwrite("\n", 1, 1, g_file);
            fflush(g_file);
        }
    } // namespace detail

    inline void set_log_filename(const char* filename)
    {
        if (!filename || !*filename)
            return;

        AcquireSRWLockExclusive(&detail::g_lock);
        detail::g_filename = filename;
        ReleaseSRWLockExclusive(&detail::g_lock);
    }

    inline void set_explicit_path(const char* absolute_path)
    {
        AcquireSRWLockExclusive(&detail::g_lock);
        detail::g_explicit_path = absolute_path ? absolute_path : "";
        ReleaseSRWLockExclusive(&detail::g_lock);
    }

    inline void ensure_open()
    {
        if (detail::g_file)
            return;

        AcquireSRWLockExclusive(&detail::g_lock);
        if (detail::g_file)
        {
            ReleaseSRWLockExclusive(&detail::g_lock);
            return;
        }

        std::string path = detail::effective_path();
        HANDLE hRaw = CreateFileA(
            path.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            nullptr);

        if (hRaw != INVALID_HANDLE_VALUE)
        {
            int fd = ::_open_osfhandle((intptr_t)hRaw, _O_APPEND | _O_BINARY);
            if (fd != -1)
            {
                detail::g_file = ::_fdopen(fd, "ab");
                if (!detail::g_file)
                {
                    ::_close(fd);
                }
            }
            else
            {
                CloseHandle(hRaw);
            }
        }
        if (!detail::g_file)
        {
            fopen_s(&detail::g_file, path.c_str(), "ab");
        }
        if (detail::g_file)
        {
            setvbuf(detail::g_file, nullptr, _IONBF, 0);
            SYSTEMTIME st{};
            GetLocalTime(&st);
            char hdr[256];
            _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
                "===== %s start %04u-%02u-%02u %02u:%02u:%02u.%03u (pid=%lu) =====\r\n",
                detail::g_filename.c_str(),
                (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
                (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds,
                (unsigned long)GetCurrentProcessId());
            fwrite(hdr, 1, strlen(hdr), detail::g_file);
        }
        ReleaseSRWLockExclusive(&detail::g_lock);
    }

    inline void vprintf(const char* fmt, va_list ap)
    {
        ensure_open();
        if (!detail::g_file)
            return;

        SYSTEMTIME st{};
        GetLocalTime(&st);
        DWORD tid = GetCurrentThreadId();

        char line[4096];
        int n = _snprintf_s(line, sizeof(line), _TRUNCATE,
            "[%02u:%02u:%02u.%03u T%lu] ",
            (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond, (unsigned)st.wMilliseconds,
            (unsigned long)tid);
        if (n < 0)
            n = 0;
        size_t off = (size_t)n;
        if (off >= sizeof(line))
            off = sizeof(line) - 1;

        size_t cap = (off < sizeof(line)) ? (sizeof(line) - off) : 0;
        if (cap)
        {
            int wrote = _vsnprintf_s(line + off, cap, _TRUNCATE, fmt, ap);
            (void)wrote;
        }
        line[sizeof(line) - 1] = '\0';

        AcquireSRWLockExclusive(&detail::g_lock);
        fwrite(line, 1, strlen(line), detail::g_file);
        fwrite("\r\n", 1, 2, detail::g_file);
        fflush(detail::g_file);
        ReleaseSRWLockExclusive(&detail::g_lock);
    }

    inline void printf(const char* fmt, ...)
    {
        va_list ap;
        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }

    inline void hexdump(const char* tag, const void* data, size_t len)
    {
        ensure_open();
        if (!detail::g_file)
            return;

        AcquireSRWLockExclusive(&detail::g_lock);

        if (tag && *tag)
            detail::write_line_nolock(tag);
        const uint8_t* p = static_cast<const uint8_t*>(data);
        char line[128];
        for (size_t off = 0; off < len; off += 16)
        {
            size_t n = (len - off) < 16 ? (len - off) : 16;

            int pos = _snprintf_s(line, sizeof(line), _TRUNCATE, "%08zx  ", off);

            for (size_t i = 0; i < 16; ++i)
            {
                if (i < n)
                    pos += _snprintf_s(line + pos, sizeof(line) - pos, _TRUNCATE, "%02X ", p[off + i]);
                else
                    pos += _snprintf_s(line + pos, sizeof(line) - pos, _TRUNCATE, "   ");
                if (i == 7)
                    line[pos++] = ' ';
            }
            line[pos++] = ' ';
            line[pos++] = '|';
            for (size_t i = 0; i < n; ++i)
            {
                uint8_t c = p[off + i];
                line[pos++] = (c >= 32 && c < 127) ? (char)c : '.';
            }
            line[pos++] = '|';
            line[pos] = '\0';
            detail::write_line_nolock(line);
        }
        ReleaseSRWLockExclusive(&detail::g_lock);
    }

    inline void close()
    {
        AcquireSRWLockExclusive(&detail::g_lock);
        if (detail::g_file)
        {
            fflush(detail::g_file);
            fclose(detail::g_file);
            detail::g_file = nullptr;
        }
        ReleaseSRWLockExclusive(&detail::g_lock);
    }

    struct ScopedInit
    {
        explicit ScopedInit(const char* filename = nullptr)
        {
            if (filename)
                set_log_filename(filename);
            ensure_open();
        }
        ~ScopedInit() {}
    };

} // namespace pipetap::log
