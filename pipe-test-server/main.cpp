#define WIN32_LEAN_AND_MEAN

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>

#include <bcrypt.h>
#include <psapi.h>
#include <sddl.h>
#include <softpub.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <winver.h>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Advapi32.lib")

#include "pipetap/constants.h"
#include "pipetap/version.h"
#include "pipetap/utils.h"


/*
* Create a SECURITY_ATTRIBUTES structure with a NULL DACL.
* Anyone should be able to open the pipe and interact with it (test-only).
*/
static SECURITY_ATTRIBUTES nullDacl()
{
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);

    auto sd = new SECURITY_DESCRIPTOR{};
    if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION)) {
        std::abort();
    }
    if (!SetSecurityDescriptorDacl(sd, TRUE, nullptr, FALSE)) {
        std::abort();
    }

    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    return sa;
}

static std::atomic_bool g_running = true;

static BOOL WINAPI CtrlHandler(DWORD ctrlType)
{
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT ||
        ctrlType == CTRL_CLOSE_EVENT) {
        g_running = false;
        std::cout << " | shutting down..." << std::endl;

        return TRUE;
    }

    return FALSE;
}

/*
 * Overlapped ConnectNamedPipe that polls g_running so Ctrl+C can break out of accept.
 * Returns true on successful connect; false if failed or cancelled during shutdown.
 */
static bool AcceptClientWithPolling(HANDLE hPipe)
{
    OVERLAPPED ov{};
    ov.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        return false;
    }

    BOOL ok = ConnectNamedPipe(hPipe, &ov);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_CONNECTED) {
            CloseHandle(ov.hEvent);
            return true; // client already connected
        }
        if (err != ERROR_IO_PENDING) {
            CloseHandle(ov.hEvent);
            return false;
        }
    }

    for (;;) {
        DWORD wr = WaitForSingleObject(ov.hEvent, 100);
        if (wr == WAIT_OBJECT_0) break;
        if (!g_running.load(std::memory_order_relaxed)) {
            CancelIoEx(hPipe, &ov); // cancel pending connect
            CloseHandle(ov.hEvent);
            return false;
        }
    }

    DWORD unused = 0;
    ok = GetOverlappedResult(hPipe, &ov, &unused, FALSE);
    CloseHandle(ov.hEvent);

    return ok != FALSE;
}

static std::string utf8(const std::wstring& ws) {
    if (ws.empty()) return {};

    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), s.data(), len, nullptr, nullptr);

    return s;
}

static std::string sha256File(const std::wstring& path) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (f == INVALID_HANDLE_VALUE) return {};

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (st < 0) {
        CloseHandle(f);
        return {};
    }

    DWORD objLen = 0, cb = 0;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &cb, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(f);
        return {};
    }
    std::vector<BYTE> obj(objLen);
    if (BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(f);
        return {};
    }

    std::array<BYTE, 64 * 1024> buf{};
    DWORD rd = 0;
    while (ReadFile(f, buf.data(), (DWORD)buf.size(), &rd, nullptr) && rd) {
        if (BCryptHashData(hash, buf.data(), rd, 0) < 0) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
            CloseHandle(f);
            return {};
        }
    }
    BYTE digest[32];
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) < 0) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(f); return {};
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(f);

    static const char* hex = "0123456789abcdef";
    std::string out; out.reserve(64);
    for (BYTE b : digest) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0xF]);
    }

    return out;
}

static void fileVersionInfo(const std::wstring& path, std::string& company, std::string& filever) {
    DWORD handle = 0;
    DWORD sz = GetFileVersionInfoSizeW(path.c_str(), &handle);
    if (!sz) return;

    std::vector<BYTE> blob(sz);
    if (!GetFileVersionInfoW(path.c_str(), 0, sz, blob.data())) return;

    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; };
    LANGANDCODEPAGE* trans = nullptr; UINT tlen = 0;
    if (!VerQueryValueW(blob.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&trans, &tlen) || tlen < sizeof(LANGANDCODEPAGE)) return;

    wchar_t subblock[64];
    swprintf_s(subblock, L"\\StringFileInfo\\%04x%04x\\CompanyName", trans[0].wLanguage, trans[0].wCodePage);
    void* val = nullptr; UINT vlen = 0;
    if (VerQueryValueW(blob.data(), subblock, &val, &vlen) && vlen) company = utf8((wchar_t*)val);

    swprintf_s(subblock, L"\\StringFileInfo\\%04x%04x\\FileVersion", trans[0].wLanguage, trans[0].wCodePage);
    if (VerQueryValueW(blob.data(), subblock, &val, &vlen) && vlen) filever = utf8((wchar_t*)val);
}

static bool verifySignatureAndPublisher(const std::wstring& path, std::string& publisher) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &data);

    // Try to pull publisher from signer cert
    if (status == ERROR_SUCCESS) {
        CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if (prov) {
            CRYPT_PROVIDER_SGNR* sgn = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
            if (sgn && sgn->pasCertChain && sgn->csCertChain > 0) {
                PCCERT_CONTEXT cert = sgn->pasCertChain[0].pCert;
                wchar_t name[512];
                DWORD n = CertGetNameStringW(cert, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nullptr, name, 512);
                if (n > 1) publisher = utf8(name);
                else {
                    n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 512);
                    if (n > 1) publisher = utf8(name);
                }
            }
        }
    }

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &action, &data);

    return status == ERROR_SUCCESS;
}

static std::wstring processImagePath(HANDLE hProc) {
    std::wstring out(32768, L'\0');
    DWORD sz = (DWORD)out.size();
    if (QueryFullProcessImageNameW(hProc, 0, out.data(), &sz)) {
        out.resize(sz);
        return out;
    }

    // fallback
    out.resize(MAX_PATH);
    if (GetProcessImageFileNameW(hProc, out.data(), (DWORD)out.size())) {
        out.resize(wcslen(out.c_str()));
        return out;
    }
    return L"";
}

static DWORD parentPid(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                DWORD ppid = pe.th32ParentProcessID;
                CloseHandle(snap);
                return ppid;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return 0;
}

static void tokenInfo(HANDLE hProc, std::string& user, std::string& sidStr,
    std::string& integrity, std::string& elevation) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &tok)) return;

    // User + SID
    DWORD sz = 0; GetTokenInformation(tok, TokenUser, nullptr, 0, &sz);
    std::vector<BYTE> buf(sz);
    if (GetTokenInformation(tok, TokenUser, buf.data(), sz, &sz)) {
        TOKEN_USER* tu = (TOKEN_USER*)buf.data();
        LPWSTR s = nullptr;
        if (ConvertSidToStringSidW(tu->User.Sid, &s)) { sidStr = utf8(s); LocalFree(s); }
        wchar_t name[256], dom[256]; DWORD n1 = 256, n2 = 256; SID_NAME_USE use;
        if (LookupAccountSidW(nullptr, tu->User.Sid, name, &n1, dom, &n2, &use)) {
            user = utf8(std::wstring(dom)) + "\\" + utf8(std::wstring(name));
        }
    }

    // Integrity level
    sz = 0; GetTokenInformation(tok, TokenIntegrityLevel, nullptr, 0, &sz);
    if (sz) {
        std::vector<BYTE> ibuf(sz);
        if (GetTokenInformation(tok, TokenIntegrityLevel, ibuf.data(), sz, &sz)) {
            TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)ibuf.data();
            DWORD rid = *GetSidSubAuthority(tml->Label.Sid, *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
            if (rid >= SECURITY_MANDATORY_SYSTEM_RID) integrity = "System";
            else if (rid >= SECURITY_MANDATORY_HIGH_RID)   integrity = "High";
            else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) integrity = "Medium";
            else                                           integrity = "Low";
        }
    }

    // Elevation
    TOKEN_ELEVATION_TYPE et; sz = sizeof(et);
    if (GetTokenInformation(tok, TokenElevationType, &et, sz, &sz)) {
        switch (et) {
        case TokenElevationTypeFull: elevation = "Elevated"; break;
        case TokenElevationTypeLimited: elevation = "Limited (UAC split)"; break;
        default: elevation = "Default"; break;
        }
    }
    else {
        TOKEN_ELEVATION el; sz = sizeof(el);
        if (GetTokenInformation(tok, TokenElevation, &el, sz, &sz)) {
            elevation = el.TokenIsElevated ? "Elevated" : "Not elevated";
        }
    }

    CloseHandle(tok);
}

static std::string archOfProcess(HANDLE hProc) {
    typedef BOOL(WINAPI* IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    IsWow64Process2_t p = nullptr;
    if (hKernel32) {
        p = (IsWow64Process2_t)GetProcAddress(hKernel32, "IsWow64Process2");
    }
    if (p) {
        USHORT proc = 0, native = 0;
        if (p(hProc, &proc, &native)) {
            auto name = [&](USHORT a)->const char* {
                switch (a) {
                case IMAGE_FILE_MACHINE_I386: return "x86";
                case IMAGE_FILE_MACHINE_AMD64: return "x64";
                case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
                default: return "unknown";
                }
                };
            return std::string(name(proc ? proc : native));
        }
    }
    else {
        BOOL wow = FALSE;
        if (IsWow64Process(hProc, &wow)) {
            SYSTEM_INFO si{}; GetNativeSystemInfo(&si);
            return (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? (wow ? "x86 (WOW64)" : "x64")
                : "x86";
        }
    }
    return "unknown";
}

static std::string startTime(HANDLE hProc) {
    FILETIME ct, et, kt, ut;
    if (!GetProcessTimes(hProc, &ct, &et, &kt, &ut)) return {};

    SYSTEMTIME stUTC{}, stLocal{};
    FileTimeToSystemTime(&ct, &stUTC);
    SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u",
        stLocal.wYear, stLocal.wMonth, stLocal.wDay, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

    return buf;
}

static DWORD sessionIdOfPid(DWORD pid) {
    DWORD sid = 0xFFFFFFFF;
    ProcessIdToSessionId(pid, &sid);

    return sid;
}

static void printClientProcessInfo(DWORD /*instanceId*/, DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::cout << "   | client-info: (pid=" << pid << ") OpenProcess failed: " << GetLastError() << "\n";
        return;
    }

    std::wstring wimg = processImagePath(hProc);
    std::string img = utf8(wimg);
    std::string company, filever; fileVersionInfo(wimg, company, filever);
    std::string sha = wimg.empty() ? "" : sha256File(wimg);

    std::string publisher; bool signedOk = false;
    if (!wimg.empty()) signedOk = verifySignatureAndPublisher(wimg, publisher);

    std::string user, sid, integrity, elevation;
    tokenInfo(hProc, user, sid, integrity, elevation);

    DWORD ppid = parentPid(pid);
    DWORD sess = sessionIdOfPid(pid);
    std::string a = archOfProcess(hProc);
    std::string started = startTime(hProc);

    std::cout << "   | client-info:\n";
    std::cout << "   |   image:       " << (img.empty() ? "(unknown)" : img) << "\n";
    if (!company.empty() || !filever.empty())
        std::cout << "   |   version:     " << (company.empty() ? "" : (company + " ")) << filever << "\n";
    if (!sha.empty())
        std::cout << "   |   sha256:      " << sha << "\n";
    std::cout << "   |   signed:      " << (signedOk ? "yes" : "no");
    if (signedOk && !publisher.empty()) std::cout << " (" << publisher << ")";
    std::cout << "\n";
    std::cout << "   |   user:        " << (user.empty() ? "(unknown)" : user)
        << "  sid=" << (sid.empty() ? "(unknown)" : sid) << "\n";
    std::cout << "   |   integrity:   " << (integrity.empty() ? "(unknown)" : integrity)
        << "  elevation: " << (elevation.empty() ? "(unknown)" : elevation) << "\n";
    std::cout << "   |   pid:         " << pid << "  ppid: " << ppid << "  session: " << sess << "\n";
    std::cout << "   |   arch:        " << a << "\n";
    if (!started.empty())
        std::cout << "   |   started:     " << started << "\n";

    CloseHandle(hProc);
}

static void printPipeBanner(HANDLE hPipe, DWORD instanceId, DWORD pid)
{
    DWORD flags = 0, outBuf = 0, inBuf = 0, maxInst = 0;
    GetNamedPipeInfo(hPipe, &flags, &outBuf, &inBuf, &maxInst);

    DWORD state = 0; DWORD col = 0, rcv = 0, inst = 0;
    GetNamedPipeHandleStateA(hPipe, &state, &col, &rcv, &inst, nullptr, 0);

    std::cout << " | [#" << instanceId << " pid=" << pid << "] client connected\n";
    printClientProcessInfo(instanceId, pid);

    std::cout << "   | pipe-info:\n";
    std::cout << "   | type:        " << ((flags & PIPE_TYPE_MESSAGE) ? "message" : "byte") << "\n";
    std::cout << "   | read-mode:   " << ((state & PIPE_READMODE_MESSAGE) ? "message" : "byte") << "\n";
    std::cout << "   | wait:        " << ((state & PIPE_NOWAIT) ? "nonblocking" : "blocking") << "\n";
    std::cout << "   | out-buf:     " << outBuf << " bytes\n";
    std::cout << "   | in-buf:      " << inBuf << " bytes\n";
    std::cout << "   | max-inst:    " << maxInst << "\n";
}

static void clientWorker(HANDLE hPipe, DWORD instanceId)
{
    DWORD pid = 0;
    DWORD got = 0;
    (void)GetNamedPipeClientProcessId(hPipe, &pid);
    printPipeBanner(hPipe, instanceId, pid);

    // Put pipe into message-read mode so reads return whole messages when possible
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr)) {
        std::cout << " | [#" << instanceId << " pid=" << pid << "] SetNamedPipeHandleState failed: "
            << GetLastError() << std::endl;
    }

    // --- heap buffer instead of stack buffer (64 KiB) ---
    constexpr DWORD kBufSize = 64u * 1024u; // max atomic message size for message-type pipes
    uint8_t* buf = static_cast<uint8_t*>(std::malloc(kBufSize));
    if (!buf) {
        std::cout << " | [#" << instanceId << " pid=" << pid << "] malloc(" << kBufSize << ") failed\n";
        goto cleanup; // bail out cleanly
    }

    for (;;) {
        BOOL ok = ReadFile(hPipe, buf, kBufSize, &got, nullptr);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_MORE_DATA) {
                std::cout << " | [#" << instanceId << "] read chunk. more data to read..." << std::endl;
                pipetap::utils::hexDump(buf, got);

                // echo the chunk; handle partial writes
                DWORD total = 0;
                while (total < got) {
                    DWORD wrote = 0;
                    if (!WriteFile(hPipe, buf + total, got - total, &wrote, nullptr)) {
                        std::cout << " | [#" << instanceId << "] WriteFile error: " << GetLastError() << std::endl;
                        break;
                    }
                    total += wrote;
                }
                continue;
            }
            if (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA) {
                std::cout << " | [#" << instanceId << " pid=" << pid << "] client disconnected" << std::endl;
            }
            else {
                std::cout << " | [#" << instanceId << " pid=" << pid << "] ReadFile error: " << err << std::endl;
            }
            break;
        }

        std::cout << " |< [#" << instanceId << "] received " << got << " bytes" << std::endl;
        pipetap::utils::hexDump(buf, got);

        // Echo back (handle partial write)
        DWORD total = 0;
        while (total < got) {
            DWORD wrote = 0;
            if (!WriteFile(hPipe, buf + total, got - total, &wrote, nullptr)) {
                std::cout << " | [#" << instanceId << "] WriteFile error: " << GetLastError() << std::endl;
                goto cleanup;
            }
            total += wrote;
        }
    }

cleanup:
    if (buf) std::free(buf);
    if (!FlushFileBuffers(hPipe)) {
        DWORD e = GetLastError();
        if (e != ERROR_BROKEN_PIPE && e != ERROR_NO_DATA) {
            std::cout << " | FlushFileBuffers error: " << e << std::endl;
        }
    }
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}


int main()
{
    std::cout << pipetap::constants::kLogo << " v" << pipetap::version_string() << std::endl;
    std::cout << " | pipe-test-server" << std::endl;
    std::cout << " | pipe-name: " << pipetap::constants::kPipeNameTest << std::endl;
    std::cout << " | anyone can connect to the pipe. this is an echo server used for testing..." << std::endl;

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    auto sa = nullDacl();

    DWORD instanceCounter = 0;

    HANDLE first = CreateNamedPipeA(
        pipetap::constants::kPipeNameTest,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        64 * 1024, 64 * 1024, 0,
        &sa
    );

    if (first == INVALID_HANDLE_VALUE) {
        std::cout << " | CreateNamedPipeA (first) failed: " << GetLastError() << std::endl;
        delete static_cast<SECURITY_DESCRIPTOR*>(sa.lpSecurityDescriptor);
        return 1;
    }

    SetHandleInformation(first, HANDLE_FLAG_INHERIT, 0);

    std::cout << " | waiting for first client..." << std::endl;
    if (!AcceptClientWithPolling(first)) {
        if (!g_running.load(std::memory_order_relaxed)) {
            CloseHandle(first);
            delete static_cast<SECURITY_DESCRIPTOR*>(sa.lpSecurityDescriptor);
            return 0;
        }
        std::cout << " | ConnectNamedPipe (first) failed: " << GetLastError() << std::endl;
        CloseHandle(first);
        delete static_cast<SECURITY_DESCRIPTOR*>(sa.lpSecurityDescriptor);
        return 1;
    }

    std::thread(clientWorker, first, ++instanceCounter).detach();

    // Accept more clients until Ctrl+C
    while (g_running.load(std::memory_order_relaxed)) {
        HANDLE h = CreateNamedPipeA(
            pipetap::constants::kPipeNameTest,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024, 64 * 1024, 0,
            &sa
        );

        if (h == INVALID_HANDLE_VALUE) {
            std::cout << " | CreateNamedPipeA failed: " << GetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);

        if (!AcceptClientWithPolling(h)) {
            CloseHandle(h);
            if (!g_running.load(std::memory_order_relaxed)) break;
            continue;
        }

        std::thread(clientWorker, h, ++instanceCounter).detach();
    }

    delete static_cast<SECURITY_DESCRIPTOR*>(sa.lpSecurityDescriptor);

    return 0;
}
