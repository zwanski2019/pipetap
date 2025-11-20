#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "win/unicode.h"
#include <algorithm>
#include <sddl.h>
#include <string>
#include <TlHelp32.h>
#include <vector>
#include <Windows.h>
#include <wtsapi32.h>

namespace pipetap::win {

    struct ProcInfo {
        unsigned    pid = 0;
        std::string name;
        std::string arch;   // "x64"/"x86"/"?"
        std::string il;     // "Low/Medium/High/System/Protected/Unknown"
        DWORD       session_id = 0;
        bool        is_system = false;
    };

    inline bool IsProcessWow64(HANDLE hProc, BOOL& outWow64) {
        typedef BOOL(WINAPI* PFN)(HANDLE, PBOOL);
        static PFN pIsWow64 = (PFN)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
        if (!pIsWow64) {
            outWow64 = FALSE;
            return true;
        }

        BOOL b = FALSE;
        if (!pIsWow64(hProc, &b)) return false;

        outWow64 = b;
        return true;
    }

    inline std::string DetectArchFor(HANDLE hProc) {
        BOOL targetWow64 = FALSE;

        if (!IsProcessWow64(hProc, targetWow64)) return "?";
#if defined(_WIN64)
        return targetWow64 ? "x86" : "x64";
#else
        return "x86";
#endif
    }

    inline DWORD GetProcessIntegrityRid(HANDLE hProc) {
        DWORD rid = 0; HANDLE hTok = nullptr;
        if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) return 0;

        DWORD need = 0; GetTokenInformation(hTok, TokenIntegrityLevel, nullptr, 0, &need);
        std::vector<BYTE> buf(need);
        if (!GetTokenInformation(hTok, TokenIntegrityLevel, buf.data(), (DWORD)buf.size(), &need)) {
            CloseHandle(hTok); return 0;
        }

        CloseHandle(hTok);
        TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)buf.data();
        if (!tml || !tml->Label.Sid) return 0;

        DWORD cnt = *GetSidSubAuthorityCount(tml->Label.Sid);
        rid = *GetSidSubAuthority(tml->Label.Sid, cnt - 1);

        return rid;
    }

    inline std::string IntegrityRidToText(DWORD rid) {
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

    inline bool IsProcessSystemUser(HANDLE hProc, bool& outIsSystem) {
        outIsSystem = false;
        HANDLE hTok = nullptr;

        if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) return false;

        DWORD need = 0; GetTokenInformation(hTok, TokenUser, nullptr, 0, &need);
        std::vector<BYTE> buf(need);
        bool ok = GetTokenInformation(hTok, TokenUser, buf.data(), (DWORD)buf.size(), &need) != 0;
        CloseHandle(hTok);
        if (!ok) return false;

        PSID sid = ((TOKEN_USER*)buf.data())->User.Sid;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        PSID sysSid = nullptr;

        AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sysSid);
        if (sysSid) {
            outIsSystem = EqualSid(sid, sysSid) != 0;
            FreeSid(sysSid);
        }

        return true;
    }

    inline bool ResolveSidToAccountA(PSID sid, std::string& out_user) {
        out_user.clear();
        if (!sid || !IsValidSid(sid)) return false;

        SID_NAME_USE use = SidTypeUnknown;
        DWORD cchName = 0, cchDomain = 0;

        (void)LookupAccountSidA(nullptr, sid, nullptr, &cchName, nullptr, &cchDomain, &use);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || (cchName == 0 && cchDomain == 0)) {
            LPSTR sidStr = nullptr;
            if (ConvertSidToStringSidA(sid, &sidStr) && sidStr) {
                out_user = sidStr;
                LocalFree(sidStr);
                return true;
            }

            return false;
        }

        std::string name(cchName, '\0');
        std::string domain(cchDomain, '\0');

        if (!LookupAccountSidA(nullptr, sid, name.data(), &cchName, domain.data(), &cchDomain, &use))
            return false;

        name.resize(cchName);
        domain.resize(cchDomain);

        if (!domain.empty()) {
            out_user = domain;
            out_user.push_back('\\');
            out_user.append(name);
        }
        else {
            out_user = std::move(name);
        }

        return !out_user.empty();
    }

    inline bool GetUsernameFromToken(DWORD pid, std::string& out_user) {
        out_user.clear();

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) return false;

        HANDLE hTok = nullptr;
        if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) {
            CloseHandle(hProc);
            return false;
        }

        DWORD len = 0;
        GetTokenInformation(hTok, TokenUser, nullptr, 0, &len);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || len == 0) {
            CloseHandle(hTok);
            CloseHandle(hProc);
            return false;
        }

        std::vector<BYTE> buf(len);
        if (!GetTokenInformation(hTok, TokenUser, buf.data(), len, &len)) {
            CloseHandle(hTok);
            CloseHandle(hProc);
            return false;
        }

        const TOKEN_USER* tu = reinterpret_cast<const TOKEN_USER*>(buf.data());
        bool ok = ResolveSidToAccountA(tu->User.Sid, out_user);

        CloseHandle(hTok);
        CloseHandle(hProc);

        return ok;
    }

    inline bool GetUsernameFromWTS(DWORD pid, std::string& out_user) {
        out_user.clear();

        WTS_PROCESS_INFO* list = nullptr;
        DWORD count = 0;
        if (!WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &list, &count))
            return false;

        bool found = false;
        for (DWORD i = 0; i < count; ++i) {
            if (list[i].ProcessId == pid) {
                found = ResolveSidToAccountA(list[i].pUserSid, out_user);
                break;
            }
        }
        if (list) WTSFreeMemory(list);

        return found;
    }

    inline bool GetProcessUserName(DWORD pid, std::string& out_user) {
        if (GetUsernameFromToken(pid, out_user)) return true;
        if (GetUsernameFromWTS(pid, out_user))   return true;

        return false;
    }

    inline void EnumerateProcesses(std::vector<ProcInfo>& out) {
        out.clear();
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
        if (!Process32FirstW(hSnap, &pe)) { CloseHandle(hSnap); return; }

        do {
            ProcInfo info;
            info.pid = (unsigned)pe.th32ProcessID;
            info.name = win::NarrowAcp(pe.szExeFile);

            DWORD sid = 0; if (ProcessIdToSessionId(pe.th32ProcessID, &sid)) info.session_id = sid;

            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (hProc) {
                info.arch = DetectArchFor(hProc);
                DWORD ilRid = GetProcessIntegrityRid(hProc);
                info.il = IntegrityRidToText(ilRid);
                bool isSys = false; IsProcessSystemUser(hProc, isSys); info.is_system = isSys;
                CloseHandle(hProc);
            }
            else {
                info.arch = "?"; info.il = "Unknown"; info.is_system = false;
            }
            out.emplace_back(std::move(info));
        } while (Process32NextW(hSnap, &pe));
        CloseHandle(hSnap);

        std::sort(out.begin(), out.end(), [](const ProcInfo& a, const ProcInfo& b) {
            if (a.name != b.name) return a.name < b.name;
            return a.pid < b.pid;
            });
    }

} // namespace pipetap::win
