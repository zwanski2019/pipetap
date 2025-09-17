#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "injection.h"
#include "log.h"
#include "session.h"
#include "win/error.h"
#include "win/process_enum.h"
#include <algorithm>
#include <string>
#include <TlHelp32.h>
#include <vector>
#include <Windows.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Advapi32.lib")

namespace pipetap::injection {

    using pipetap::win::FormatLastErrorA;
    using pipetap::win::EnumerateProcesses;
    using pipetap::win::DetectArchFor;
    using pipetap::win::GetProcessIntegrityRid;
    using pipetap::win::IntegrityRidToText;
    using pipetap::win::IsProcessSystemUser;
    using pipetap::win::GetProcessUserName;

    static bool EnablePrivilege(LPCWSTR name, bool enable, std::string* why = nullptr) {
        HANDLE hTok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
            if (why) *why = "OpenProcessToken failed: " + FormatLastErrorA(GetLastError());
            return false;
        }

        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
            if (why) *why = "LookupPrivilegeValueW failed: " + FormatLastErrorA(GetLastError());
            CloseHandle(hTok);
            return false;
        }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

        if (!AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
            if (why) *why = "AdjustTokenPrivileges failed: " + FormatLastErrorA(GetLastError());
            CloseHandle(hTok);
            return false;
        }
        DWORD le = GetLastError();
        CloseHandle(hTok);

        if (le == ERROR_NOT_ALL_ASSIGNED) {
            if (why) *why = "Privilege not held (ERROR_NOT_ALL_ASSIGNED)";
            return false;
        }
        return le == ERROR_SUCCESS;
    }

    void GetDefaultDllPath(char* out, size_t outsz) {
        char exe[MAX_PATH] = { 0 };
        GetModuleFileNameA(nullptr, exe, MAX_PATH);
        char* slash = strrchr(exe, '\\');
        if (!slash) { strncpy_s(out, outsz, "pipetap-dll.dll", _TRUNCATE); return; }
        *(slash + 1) = '\0';
        strncpy_s(out, outsz, exe, _TRUNCATE);
        strncat_s(out, outsz, "pipetap-dll.dll", _TRUNCATE);
    }

    static void* GetRemoteKernel32Base(DWORD pid) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return nullptr;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(MODULEENTRY32W);

        void* base = nullptr;
        if (Module32FirstW(snap, &me)) {
            do {
                if (_wcsicmp(me.szModule, L"kernel32.dll") == 0) { base = me.modBaseAddr; break; }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return base;
    }

    void RefreshProcesses(VM& s) {
        s.processes.clear();
        std::vector<pipetap::win::ProcInfo> tmp;
        EnumerateProcesses(tmp);
        s.processes.reserve(tmp.size());
        for (auto& p : tmp) {
            ProcInfo q;
            q.pid = p.pid;
            q.name = std::move(p.name);
            q.arch = std::move(p.arch);
            q.il = std::move(p.il);
            q.session_id = p.session_id;
            q.is_system = p.is_system;

            std::string u;
            if (GetProcessUserName(q.pid, u)) {
                std::string ul = u;
                std::transform(ul.begin(), ul.end(), ul.begin(),
                    [](unsigned char c) -> char {
                        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    });
                if (ul == "system" || ul == "nt authority\\system") q.user = "NT AUTHORITY\\SYSTEM";
                else q.user = std::move(u);
            }
            else if (q.is_system) {
                q.user = "NT AUTHORITY\\SYSTEM";
            }
            else {
                q.user.clear();
            }

            s.processes.emplace_back(std::move(q));
        }
    }

    void DoInject(VM* st_ptr) {
        VM& s = *st_ptr;
        if (s.injecting.exchange(true)) return;

        if (!s.log_ch) {
            s.log_ch = &pipetap::log::channel("injector/default");
            s.log_channel_name = "injector/default";
        }
        auto& ch = *s.log_ch;

        unsigned pid = s.pid_manual;
        char dllPath[260]; strncpy_s(dllPath, s.dll_path, _TRUNCATE);
        ch.Infof("start pid=%u", pid);

        {
            std::string why;
            bool okPriv = EnablePrivilege(SE_DEBUG_NAME, true, &why);
            if (okPriv) ch.Infof("Enable SeDebugPrivilege: OK");
            else        ch.Warnf("Enable SeDebugPrivilege: FAIL (%s)", why.c_str());
        }

        DWORD desiredAccess =
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
        HANDLE hProc = OpenProcess(desiredAccess, FALSE, pid);
        if (!hProc) {
            DWORD le = GetLastError();
            ch.Errorf("OpenProcess failed: %s", FormatLastErrorA(le).c_str());
            if (le == ERROR_ACCESS_DENIED) {
                ch.Warnf("HINT: For SYSTEM targets, run GUI elevated and with SeDebugPrivilege enabled. "
                    "Verify target is not Protected Process (PPL) and that your bitness matches.");
            }
            s.injecting = false;
            return;
        }
        ch.Infof("OpenProcess: OK");

        {
            BOOL selfWow64 = FALSE, targetWow64 = FALSE;
            pipetap::win::IsProcessWow64(GetCurrentProcess(), selfWow64);
            pipetap::win::IsProcessWow64(hProc, targetWow64);
            if (selfWow64 != targetWow64) {
                ch.Warnf("architecture mismatch (self Wow64=%s, target Wow64=%s). "
                    "LoadLibrary injection will fail across bitness.",
                    selfWow64 ? "true" : "false", targetWow64 ? "true" : "false");
            }
        }

        {
            DWORD ilRid = GetProcessIntegrityRid(hProc);
            bool isSys = false; IsProcessSystemUser(hProc, isSys);
            if (ilRid >= SECURITY_MANDATORY_SYSTEM_RID) {
                ch.Warnf("SYSTEM processes may be Protected Process Light (PPL). "
                    "Standard CreateRemoteThread/LoadLibrary can fail with ACCESS_DENIED/NOT_SUPPORTED.");
            }
        }

        HMODULE localK32 = GetModuleHandleA("kernel32.dll");
        FARPROC localLLA = localK32 ? GetProcAddress(localK32, "LoadLibraryA") : nullptr;
        if (!localK32 || !localLLA) {
            ch.Errorf("Resolve local LoadLibraryA failed");
            CloseHandle(hProc); s.injecting = false;
            return;
        }
        SIZE_T rva = (SIZE_T)((BYTE*)localLLA - (BYTE*)localK32);

        void* remoteK32 = GetRemoteKernel32Base(pid);
        if (!remoteK32) {
            ch.Errorf("GetRemoteKernel32Base failed");
            CloseHandle(hProc); s.injecting = false;
            return;
        }
        LPTHREAD_START_ROUTINE remoteLLA = (LPTHREAD_START_ROUTINE)((BYTE*)remoteK32 + rva);
        ch.Infof("Resolved remote LoadLibraryA");

        SIZE_T pathLen = strlen(dllPath) + 1;
        LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem) {
            ch.Errorf("VirtualAllocEx failed: %s", FormatLastErrorA(GetLastError()).c_str());
            CloseHandle(hProc); s.injecting = false;
            return;
        }
        ch.Infof("VirtualAllocEx: OK");

        SIZE_T wrote = 0;
        if (!WriteProcessMemory(hProc, remoteMem, dllPath, pathLen, &wrote) || wrote != pathLen) {
            ch.Errorf("WriteProcessMemory failed: %s", FormatLastErrorA(GetLastError()).c_str());
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProc); s.injecting = false;
            return;
        }
        ch.Infof("WriteProcessMemory: OK");

        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, remoteLLA, remoteMem, 0, nullptr);
        if (!hThread) {
            DWORD le = GetLastError();
            ch.Errorf("CreateRemoteThread failed: %s", FormatLastErrorA(le).c_str());
            if (le == ERROR_ACCESS_DENIED || le == ERROR_NOT_SUPPORTED) {
                ch.Warnf("Target may be protected (PPL) or cross-bitness. "
                    "Try matching bitness and/or alternative techniques (APC, RtlCreateUserThread, manual map).");
            }
            VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
            CloseHandle(hProc); s.injecting = false;
            return;
        }
        ch.Infof("CreateRemoteThread: OK (waiting...)");

        WaitForSingleObject(hThread, INFINITE);
        DWORD exitCode = 0; GetExitCodeThread(hThread, &exitCode);
        ch.Infof("thread exit code = %u", exitCode);

        CloseHandle(hThread);
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);

        if (exitCode == 0) {
            ch.Errorf("LoadLibraryA returned NULL (likely failed to load)");
        }
        else {
            ch.Infof("injection completed successfully");
            session::NoteInjectedPid(pid);
        }
        s.injecting = false;
    }

} // namespace pipetap::injection
