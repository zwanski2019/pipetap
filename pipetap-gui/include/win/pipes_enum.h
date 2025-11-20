#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "win/unicode.h"
#include <Aclapi.h>
#include <algorithm>
#include <cctype>
#include <memory>
#include <sddl.h>
#include <string>
#include <vector>
#include <Windows.h>

namespace pipetap::win {

    enum class PipeState : uint8_t { Unknown, Open, Busy, Denied, NotFound, Error };

    struct PipeAclInfo {
        std::string dacl_text;              // textual dump
        DWORD       acl_err = 0;
        int         ace_count = -1;
        int         risk_level = -1;        // -1 unknown, 0 low, 1 medium, 2 high
        bool        network_access = false;
        std::string risk_reason;
    };

    struct PipeRuntime {
        std::string name;                       // "spoolss"
        std::string path;                       // "\\.\pipe\spoolss"
        DWORD       server_pid = 0;
        std::string process_name;               // best-effort
        PipeState   state = PipeState::Unknown;
        std::string type;                       // "message" | "byte"
        DWORD       cur_instances = 0;
        DWORD       max_instances = 0;
        DWORD       open_err = 0;
        PipeAclInfo acl;
    };

    struct PipeEnumOptions {
        bool probe_handle = true;
        bool query_pid = true;
        bool query_inst = true;
        bool read_acl = true;
        int  wait_ms = 80;
    };

    inline void ProcNameFromPidA(DWORD pid, std::string& out) {
        out.clear();
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!h) return;

        DWORD cch = 32768;
        std::unique_ptr<wchar_t[]> wbuf(new wchar_t[cch]);
        if (wbuf) {
            if (QueryFullProcessImageNameW(h, 0, wbuf.get(), &cch) && cch > 0) {
                const wchar_t* base = wbuf.get();
                for (const wchar_t* p = wbuf.get(); *p; ++p)
                    if (*p == L'\\' || *p == L'/') base = p + 1;
                out = win::WideToUtf8(base);
            }
        }

        CloseHandle(h);
    }

    inline std::string RightsFromMask(DWORD mask) {
        GENERIC_MAPPING gm{};
        gm.GenericRead = FILE_GENERIC_READ;
        gm.GenericWrite = FILE_GENERIC_WRITE;
        gm.GenericExecute = FILE_GENERIC_EXECUTE;
        gm.GenericAll = FILE_ALL_ACCESS;
        MapGenericMask(&mask, &gm);

        std::string r;
        if (mask & (FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA)) r += "R";
        if (mask & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA)) {
            if (!r.empty()) r += "|";
            r += "W";
        }
        std::string admin;
        if (mask & WRITE_DAC) { if (!admin.empty()) admin += "|"; admin += "WRITE_DAC"; }
        if (mask & WRITE_OWNER) { if (!admin.empty()) admin += "|"; admin += "WRITE_OWNER"; }
        if (mask & DELETE) { if (!admin.empty()) admin += "|"; admin += "DELETE"; }
        if (mask & READ_CONTROL) { if (!admin.empty()) admin += "|"; admin += "READ_CONTROL"; }

        if (!admin.empty()) {
            if (!r.empty()) r += " + ";
            r += admin;
        }
        if (r.empty()) r = "-";

        return r;
    }

    inline std::string SidToNameUtf8(PSID sid) {
        if (!sid || !IsValidSid(sid)) return "<?>";
        DWORD cchName = 0, cchDom = 0;
        SID_NAME_USE use = SidTypeUnknown;
        LookupAccountSidW(nullptr, sid, nullptr, &cchName, nullptr, &cchDom, &use);
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cchName && cchDom) {
            std::wstring name, dom; name.resize(cchName); dom.resize(cchDom);
            if (LookupAccountSidW(nullptr, sid, name.data(), &cchName, dom.data(), &cchDom, &use)) {
                if (!name.empty() && name.back() == L'\0') name.pop_back();
                if (!dom.empty() && dom.back() == L'\0') dom.pop_back();
                if (!dom.empty()) return win::WideToUtf8((dom + L"\\" + name).c_str());
                return win::WideToUtf8(name.c_str());
            }
        }

        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(sid, &s) && s) {
            std::string out = win::WideToUtf8(s);
            LocalFree(s);
            return out;
        }

        return "<?>";
    }

    inline void AppendAceFlags(std::string& dst, BYTE flags) {
        std::string f;
        if (flags & OBJECT_INHERIT_ACE) { if (!f.empty()) f += "|"; f += "OI"; }
        if (flags & CONTAINER_INHERIT_ACE) { if (!f.empty()) f += "|"; f += "CI"; }
        if (flags & INHERIT_ONLY_ACE) { if (!f.empty()) f += "|"; f += "IO"; }
        if (flags & NO_PROPAGATE_INHERIT_ACE) { if (!f.empty()) f += "|"; f += "NP"; }
        if (flags & INHERITED_ACE) { if (!f.empty()) f += "|"; f += "INH"; }
        if (!f.empty()) { dst += " ["; dst += f; dst += "]"; }
    }

    struct RiskEval {
        int level = -1;  // -1 unknown, 0 low, 1 medium, 2 high
        std::string reason;
        bool network_access = false;
    };

    inline bool is_everyone(const std::string& who_lc) { return who_lc.find("everyone") != std::string::npos || who_lc == "s-1-1-0"; }
    inline bool is_anonymous(const std::string& who_lc) { return who_lc.find("anonymous logon") != std::string::npos || who_lc == "s-1-5-7"; }
    inline bool is_network(const std::string& who_lc) { return who_lc.find("network") != std::string::npos || who_lc == "s-1-5-2"; }
    inline bool is_authusers(const std::string& who_lc) { return who_lc.find("authenticated users") != std::string::npos || who_lc == "s-1-5-11"; }
    inline bool is_users(const std::string& who_lc) { return who_lc.find("\\users") != std::string::npos || who_lc == "s-1-5-32-545"; }
    inline void bump_risk(RiskEval& r, int lvl, const std::string& why) { if (lvl > r.level) { r.level = lvl; r.reason = why; } }

    inline RiskEval AssessAclRiskFromText(const std::string& dacl_text) {
        RiskEval eval{};
        if (dacl_text.find("DACL: none") != std::string::npos) { bump_risk(eval, 2, "NULL DACL (full access)"); return eval; }
        if (dacl_text.find("DACL: <empty>") != std::string::npos) { bump_risk(eval, 0, "Empty DACL"); return eval; }

        size_t pos = 0;
        while (true) {
            size_t i = dacl_text.find("ALLOW ", pos);
            if (i == std::string::npos) break;
            size_t nl = dacl_text.find('\n', i);
            std::string line = dacl_text.substr(i, nl == std::string::npos ? std::string::npos : (nl - i));
            pos = (nl == std::string::npos ? dacl_text.size() : nl + 1);

            size_t who_beg = i + 6;
            size_t sep = dacl_text.find(" : ", who_beg);
            if (sep == std::string::npos) continue;
            std::string who = dacl_text.substr(who_beg, sep - who_beg);
            std::string who_lc = who;
            std::transform(who_lc.begin(), who_lc.end(), who_lc.begin(), [](unsigned char c) { return (char)std::tolower(c); });

            size_t rights_beg = sep + 3;
            size_t rights_end = line.size();
            std::string rights = dacl_text.substr(rights_beg, rights_end - (rights_beg - i));
            std::string rights_lc = rights;
            std::transform(rights_lc.begin(), rights_lc.end(), rights_lc.begin(), [](unsigned char c) { return (char)std::tolower(c); });

            const bool has_w = rights.find('W') != std::string::npos || rights_lc.find("write_") != std::string::npos;
            const bool has_admin = rights_lc.find("write_dac") != std::string::npos ||
                rights_lc.find("write_owner") != std::string::npos ||
                rights_lc.find("delete") != std::string::npos;

            if (is_anonymous(who_lc)) { eval.network_access = true; bump_risk(eval, 2, has_w || has_admin ? "Anonymous write/admin" : "Anonymous read"); continue; }
            if (is_network(who_lc)) { eval.network_access = true; bump_risk(eval, has_w || has_admin ? 2 : 1, has_w || has_admin ? "Network group write/admin" : "Network group read"); continue; }
            if (is_everyone(who_lc)) { bump_risk(eval, has_w || has_admin ? 2 : 1, has_w || has_admin ? "Everyone write/admin" : "Everyone read"); continue; }
            if (is_authusers(who_lc) || is_users(who_lc)) {
                bump_risk(eval, (has_w || has_admin) ? 1 : 0, is_authusers(who_lc) ? ((has_w || has_admin) ? "Authenticated Users write" : "Authenticated Users read")
                    : ((has_w || has_admin) ? "Users write" : "Users read"));
                continue;
            }
        }
        if (eval.level < 0) { eval.level = 0; eval.reason = "Restrictive"; }

        return eval;
    }

    inline std::string BuildDaclStringFromSD(PSECURITY_DESCRIPTOR sd, int& out_ace_count) {
        out_ace_count = -1;
        if (!sd) return "n/a";
        BOOL present = FALSE, defaulted = FALSE;
        PACL dacl = nullptr;
        if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present || !dacl) {
            return "DACL: none";
        }

        ACL_SIZE_INFORMATION asi{};
        if (!GetAclInformation(dacl, &asi, sizeof(asi), AclSizeInformation)) {
            return "DACL: <unknown>";
        }
        if (asi.AceCount == 0) { out_ace_count = 0; return "DACL: <empty>"; }

        out_ace_count = 0;
        std::string out; out.reserve(256);
        bool skipped_non_basic = false;

        for (DWORD i = 0; i < asi.AceCount; ++i) {
            void* acePtr = nullptr;
            if (!GetAce(dacl, i, &acePtr) || !acePtr) continue;
            const ACE_HEADER* hdr = (const ACE_HEADER*)acePtr;
            BYTE type = hdr->AceType;
            DWORD mask = 0; PSID sid = nullptr; const char* tag = nullptr;

            if (type == ACCESS_ALLOWED_ACE_TYPE) {
                auto* aa = (ACCESS_ALLOWED_ACE*)acePtr; mask = aa->Mask; sid = (PSID)&aa->SidStart; tag = "ALLOW";
            }
            else if (type == ACCESS_DENIED_ACE_TYPE) {
                auto* ad = (ACCESS_DENIED_ACE*)acePtr; mask = ad->Mask; sid = (PSID)&ad->SidStart; tag = "DENY";
            }
            else {
                skipped_non_basic = true; continue;
            }

            ++out_ace_count;
            std::string who = SidToNameUtf8(sid);
            std::string rights = RightsFromMask(mask);

            if (!out.empty()) out += "\n";
            out += tag; out += " "; out += who; out += " : "; out += rights;
            AppendAceFlags(out, hdr->AceFlags);
        }

        if (out.empty()) out = "DACL: <parsed none>";
        if (skipped_non_basic) out += "\n... (skipped non-basic ACEs)";

        return out;
    }

    inline std::string ReadDaclForPipeW(const std::wstring& full_path_w, HANDLE h_opt, DWORD& out_err, int& out_ace_count) {
        out_err = 0; out_ace_count = -1;
        PSECURITY_DESCRIPTOR sd = nullptr;
        DWORD le = GetNamedSecurityInfoW(
            full_path_w.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr, &sd);

        if (le == ERROR_SUCCESS && sd) {
            std::string text = BuildDaclStringFromSD(sd, out_ace_count);
            LocalFree(sd);
            return text;
        }
        out_err = le;

        if (h_opt != INVALID_HANDLE_VALUE) {
            PSECURITY_DESCRIPTOR sd2 = nullptr;
            DWORD le2 = GetSecurityInfo(h_opt, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                nullptr, nullptr, nullptr, nullptr, &sd2);
            if (le2 == ERROR_SUCCESS && sd2) {
                std::string text = BuildDaclStringFromSD(sd2, out_ace_count);
                LocalFree(sd2);
                return text;
            }
        }

        if (le == ERROR_PIPE_BUSY)         return "n/a (busy; err=231)";
        if (le == ERROR_INVALID_PARAMETER) return "n/a (invalid param; err=87)";
        if (le == ERROR_ACCESS_DENIED)     return "n/a (access denied; err=5)";

        char buf[96]; std::snprintf(buf, sizeof(buf), "n/a (err=%lu)", (unsigned long)le);
        return std::string(buf);
    }

    inline void EnumeratePipeNames(std::vector<std::string>& out) {
        out.clear();
        WIN32_FIND_DATAW ffd{};
        HANDLE h = FindFirstFileW(LR"(\\.\pipe\*)", &ffd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (wcscmp(ffd.cFileName, L".") != 0 && wcscmp(ffd.cFileName, L"..") != 0) {
                out.emplace_back(win::WideToUtf8(ffd.cFileName));
            }
        } while (FindNextFileW(h, &ffd));

        FindClose(h);
        std::sort(out.begin(), out.end());
    }

    inline void FillPipeRuntime(const PipeEnumOptions& opt, PipeRuntime& r) {
        r.server_pid = 0; r.process_name.clear();
        r.state = PipeState::Unknown;
        r.type.clear(); r.cur_instances = r.max_instances = 0;
        r.open_err = 0; r.acl = PipeAclInfo{};

        std::wstring wpath = win::Utf8ToWide(r.path.c_str());

        if (opt.wait_ms > 0) {
            BOOL wait_ok = WaitNamedPipeW(wpath.c_str(), (DWORD)opt.wait_ms);
            if (!wait_ok) {
                DWORD le = GetLastError(); r.open_err = le;
                if (le == ERROR_PIPE_BUSY || le == ERROR_SEM_TIMEOUT) r.state = PipeState::Busy;
                else if (le == ERROR_FILE_NOT_FOUND) r.state = PipeState::NotFound;
                else if (le == ERROR_ACCESS_DENIED) r.state = PipeState::Denied;
                else r.state = PipeState::Error;

                r.acl.dacl_text = ReadDaclForPipeW(wpath, INVALID_HANDLE_VALUE, r.acl.acl_err, r.acl.ace_count);
                auto risk = AssessAclRiskFromText(r.acl.dacl_text);
                r.acl.risk_level = risk.level; r.acl.risk_reason = risk.reason; r.acl.network_access = risk.network_access;
                return;
            }
        }

        HANDLE h = INVALID_HANDLE_VALUE;
        if (opt.probe_handle) {
            auto try_open = [&](DWORD access)->bool {
                h = CreateFileW(wpath.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
                if (h != INVALID_HANDLE_VALUE) return true;
                r.open_err = GetLastError(); return false;
                };
            bool opened = try_open(GENERIC_READ) || try_open(GENERIC_WRITE) || try_open(GENERIC_READ | GENERIC_WRITE);
            if (!opened) {
                DWORD le = r.open_err;
                if (le == ERROR_PIPE_BUSY) r.state = PipeState::Busy;
                else if (le == ERROR_ACCESS_DENIED) r.state = PipeState::Denied;
                else if (le == ERROR_FILE_NOT_FOUND) r.state = PipeState::NotFound;
                else r.state = PipeState::Error;

                r.acl.dacl_text = ReadDaclForPipeW(wpath, INVALID_HANDLE_VALUE, r.acl.acl_err, r.acl.ace_count);
                auto risk = AssessAclRiskFromText(r.acl.dacl_text);
                r.acl.risk_level = risk.level; r.acl.risk_reason = risk.reason; r.acl.network_access = risk.network_access;
                return;
            }
        }
        r.state = PipeState::Open;

        if (opt.query_pid && h != INVALID_HANDLE_VALUE) {
            ULONG spid = 0;
            typedef BOOL(WINAPI* PFN_GetNamedPipeServerProcessId)(HANDLE, PULONG);
            static PFN_GetNamedPipeServerProcessId pGetPid =
                (PFN_GetNamedPipeServerProcessId)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetNamedPipeServerProcessId");
            if (pGetPid && pGetPid(h, &spid)) {
                r.server_pid = (DWORD)spid;
                ProcNameFromPidA(r.server_pid, r.process_name);
            }
        }

        if (opt.query_inst && h != INVALID_HANDLE_VALUE) {
            DWORD flags_info = 0, outSz = 0, inSz = 0, maxInst = 0;
            if (GetNamedPipeInfo(h, &flags_info, &outSz, &inSz, &maxInst)) {
                r.type = (flags_info & PIPE_TYPE_MESSAGE) ? "message" : "byte";
                r.max_instances = maxInst;
            }
            DWORD curInst = 0, flags_state = 0;
            if (GetNamedPipeHandleStateW(h, &flags_state, &curInst, nullptr, nullptr, nullptr, 0)) {
                r.cur_instances = curInst;
            }
        }

        r.acl.dacl_text = ReadDaclForPipeW(wpath, h, r.acl.acl_err, r.acl.ace_count);
        auto risk = AssessAclRiskFromText(r.acl.dacl_text);
        r.acl.risk_level = risk.level; r.acl.risk_reason = risk.reason; r.acl.network_access = risk.network_access;

        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }

    inline void EnumeratePipes(const PipeEnumOptions& opts, std::vector<PipeRuntime>& out_rows) {
        std::vector<std::string> names; EnumeratePipeNames(names);
        out_rows.clear(); out_rows.reserve(names.size());
        for (const auto& n : names) {
            PipeRuntime r;
            r.name = n;
            r.path = std::string(R"(\\.\pipe\)") + n;
            FillPipeRuntime(opts, r);
            out_rows.emplace_back(std::move(r));
        }
    }

} // namespace pipetap::win
