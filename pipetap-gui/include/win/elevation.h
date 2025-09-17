#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "log.h"
#include <shellapi.h>
#include <sstream>
#include <string>
#include <vector>
#include <Windows.h>

namespace pipetap::win {

    static bool IsProcessElevated() {
        HANDLE hTok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) return false;

        TOKEN_ELEVATION te{};
        DWORD cb = sizeof(te);
        BOOL ok = GetTokenInformation(hTok, TokenElevation, &te, cb, &cb);
        CloseHandle(hTok);

        return ok ? (te.TokenIsElevated != 0) : false;
    }

    static DWORD QueryCurrentIntegrityRid() {
        HANDLE hTok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) return 0;

        DWORD need = 0; GetTokenInformation(hTok, TokenIntegrityLevel, nullptr, 0, &need);
        std::vector<BYTE> buf(need);
        DWORD rid = 0;
        if (GetTokenInformation(hTok, TokenIntegrityLevel, buf.data(), (DWORD)buf.size(), &need)) {
            auto* tml = (TOKEN_MANDATORY_LABEL*)buf.data();
            if (tml && tml->Label.Sid) {
                DWORD cnt = *GetSidSubAuthorityCount(tml->Label.Sid);
                rid = *GetSidSubAuthority(tml->Label.Sid, cnt - 1);
            }
        }
        CloseHandle(hTok);

        return rid;
    }

    static const char* IntegrityRidToCStr(DWORD rid) {
        switch (rid) {
        case SECURITY_MANDATORY_UNTRUSTED_RID: return "Untrusted";
        case SECURITY_MANDATORY_LOW_RID:       return "Low";
        case SECURITY_MANDATORY_MEDIUM_RID:    return "Medium";
        case SECURITY_MANDATORY_HIGH_RID:      return "High";
        case SECURITY_MANDATORY_SYSTEM_RID:    return "System";
        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: return "Protected";
        default: return "Unknown";
        }
    }

    static void RelaunchAsAdministrator() {
        wchar_t exe[MAX_PATH] = { 0 };
        GetModuleFileNameW(nullptr, exe, MAX_PATH);

        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.hwnd = nullptr;
        sei.lpVerb = L"runas";
        sei.lpFile = exe;
        sei.lpParameters = nullptr;
        sei.lpDirectory = nullptr;
        sei.nShow = SW_SHOWNORMAL;

        if (!ShellExecuteExW(&sei)) {
            pipetap::log::App.Errorf("RelaunchAsAdministrator: ShellExecuteExW failed le=%lu",
                (unsigned long)GetLastError());
            MessageBoxW(nullptr, L"Failed to elevate via ShellExecute (Run as administrator).",
                L"pipetap", MB_ICONERROR);
            return;
        }

        CloseHandle(sei.hProcess);
        PostQuitMessage(0);
    }

} // namespace pipetap::win
