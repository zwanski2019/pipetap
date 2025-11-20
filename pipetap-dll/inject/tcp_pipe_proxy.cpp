#include "pch.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <atomic>
#include "pipetap/log.h"
#include "pipetap/winpipe_helpers.h"
#include "inject/tcp_pipe_proxy.h"
#include "inject/hook_guards.h"   // SuppressHooksGuard
#include "inject/pipe_utils.h"    // query_pipe_hints()

#pragma comment(lib, "Ws2_32.lib")


namespace pipetap::inject {

    static inline void closesocket_safe(SOCKET s) {
        if (s != INVALID_SOCKET) ::closesocket(s);
    }

    static inline std::string fmt_addr(const sockaddr_in& sa) {
        char ip[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, (const void*)&sa.sin_addr, ip, static_cast<socklen_t>(sizeof(ip))) == nullptr) {
            strncpy_s(ip, sizeof(ip), "0.0.0.0", _TRUNCATE);
        }
        unsigned port = ntohs(sa.sin_port);
        char out[64] = {};
        _snprintf_s(out, _TRUNCATE, "%s:%u", ip, port);

        return std::string(out);
    }

    static HANDLE open_named_pipe_best_effort(const std::string& name,
        DWORD timeoutMs,
        /*out*/bool& isMessageMode,
        /*out*/uint32_t& outHint,
        /*out*/uint32_t& inHint,
        /*out*/DWORD& lastErr)
    {
        isMessageMode = false;
        outHint = inHint = 0;
        lastErr = 0;

        {
            SuppressHooksGuard _guard;
            if (!WaitNamedPipeA(name.c_str(), timeoutMs ? timeoutMs : NMPWAIT_USE_DEFAULT_WAIT)) {
                lastErr = GetLastError();
                return INVALID_HANDLE_VALUE;
            }
        }

        const DWORD tries[3] = {
            GENERIC_READ | GENERIC_WRITE,
            GENERIC_READ,
            GENERIC_WRITE
        };
        const char* tryNames[3] = { "RW", "R", "W" };

        for (int i = 0; i < 3; ++i) {
            HANDLE h = INVALID_HANDLE_VALUE;
            {
                SuppressHooksGuard _guard;
                h = CreateFileA(name.c_str(),
                    tries[i],
                    0, nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, nullptr);
            }
            if (h != INVALID_HANDLE_VALUE) {
                uint8_t is_msg = 0; uint32_t outBuf = 0, inBuf = 0;
                query_pipe_hints(h, is_msg, outBuf, inBuf);
                isMessageMode = (is_msg != 0);
                outHint = outBuf; inHint = inBuf;

                if (isMessageMode) {
                    DWORD m = PIPE_READMODE_MESSAGE;
                    {
                        SuppressHooksGuard _guard;
                        SetNamedPipeHandleState(h, &m, nullptr, nullptr);
                    }

                    is_msg = 0; outBuf = inBuf = 0;
                    query_pipe_hints(h, is_msg, outBuf, inBuf);
                    isMessageMode = (is_msg != 0);
                    outHint = outBuf; inHint = inBuf;
                }

                log::printf("TcpPipeProxy: pipe open ok (%s) handle=%p msg=%u out_hint=%u in_hint=%u",
                    tryNames[i], h, isMessageMode ? 1u : 0u, outHint, inHint);
                return h;
            }

            lastErr = GetLastError();
            log::printf("TcpPipeProxy: pipe open attempt %s failed gle=%lu (will %s)",
                tryNames[i], lastErr, (i < 2) ? "retry" : "stop");
        }

        return INVALID_HANDLE_VALUE;
    }

    static bool recv_exact_socket(SOCKET s, void* out, size_t need) {
        uint8_t* p = static_cast<uint8_t*>(out);
        size_t have = 0;
        while (have < need) {
            int r = ::recv(s, reinterpret_cast<char*>(p + have), static_cast<int>(need - have), 0);
            if (r == 0) return false;                // EOF
            if (r == SOCKET_ERROR) return false;     // error
            have += static_cast<size_t>(r);
        }
        return true;
    }

    static bool send_all_socket(SOCKET s, const void* data, size_t n) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        size_t off = 0;
        while (off < n) {
            int w = ::send(s, reinterpret_cast<const char*>(p + off), static_cast<int>(n - off), 0);
            if (w <= 0) return false;
            off += static_cast<size_t>(w);
        }
        return true;
    }

    static bool send_framed(SOCKET s, const uint8_t* data, uint32_t n) {
        uint32_t be = htonl(n);
        return send_all_socket(s, &be, sizeof(be)) && (n == 0 || send_all_socket(s, data, n));
    }

    static bool recv_framed_header(SOCKET s, uint32_t& outLen) {
        uint32_t be = 0;
        if (!recv_exact_socket(s, &be, sizeof(be))) return false;
        outLen = ntohl(be);
        return true;
    }

    TcpPipeProxyService& TcpPipeProxyService::instance() {
        static TcpPipeProxyService g;
        return g;
    }

    void TcpPipeProxyService::start() {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) return;

        WSADATA wsa{};
        int wrc = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (wrc == 0) {
            wsa_init_.store(true, std::memory_order_release);
            log::printf("TcpPipeProxy: WSAStartup ok v%u.%u", LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));
        }
        else {
            wsa_init_.store(false, std::memory_order_release);
            log::printf("TcpPipeProxy: WSAStartup failed rc=%d", wrc);
            running_.store(false, std::memory_order_release);
            return;
        }

        thread_ = CreateThread(nullptr, 0, &TcpPipeProxyService::worker_thunk, this, 0, nullptr);
        if (!thread_) {
            log::printf("TcpPipeProxy: CreateThread failed gle=%lu", GetLastError());
            running_.store(false, std::memory_order_release);
            if (wsa_init_.load(std::memory_order_acquire)) WSACleanup();
        }
        else {
            log::printf("TcpPipeProxy: worker thread started");
        }
    }

    void TcpPipeProxyService::stop() {
        if (!running_.exchange(false, std::memory_order_acq_rel)) return;
        log::printf("TcpPipeProxy: stopping...");

        if (listen_ != INVALID_SOCKET) {
            ::closesocket(listen_);
            listen_ = INVALID_SOCKET;
            log::printf("TcpPipeProxy: listener closed from stop(); port released");
        }

        if (thread_) {
            WaitForSingleObject(thread_, 5000);
            CloseHandle(thread_);
            thread_ = nullptr;
            log::printf("TcpPipeProxy: worker stopped");
        }

        if (wsa_init_.load(std::memory_order_acquire)) {
            WSACleanup();
            wsa_init_.store(false, std::memory_order_release);
            log::printf("TcpPipeProxy: WSA cleaned up");
        }
    }

    DWORD WINAPI TcpPipeProxyService::worker_thunk(LPVOID p) {
        static_cast<TcpPipeProxyService*>(p)->worker_loop();
        return 0;
    }

    SOCKET TcpPipeProxyService::create_and_bind_ephemeral(uint16_t& outPort) {
        outPort = 0;

        const uint32_t kMaxAttempts = 20000;
        uint16_t start = next_port_.load(std::memory_order_relaxed);
        if (start < 61337) start = 61337;

        uint16_t port = start;

        for (uint32_t attempt = 0; attempt < kMaxAttempts; ++attempt) {
            SOCKET ls = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (ls == INVALID_SOCKET) {
                int e = WSAGetLastError();
                log::printf("TcpPipeProxy: socket() failed wsae=%d", e);
                return INVALID_SOCKET;
            }

            BOOL reuse = TRUE;
            ::setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY); // all interfaces
            addr.sin_port = htons(port);

            if (::bind(ls, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                int be = WSAGetLastError();
                log::printf("TcpPipeProxy: bind(0.0.0.0:%u) failed wsae=%d; trying next", (unsigned)port, be);
                ::closesocket(ls);
                port = static_cast<uint16_t>((port == 65535) ? 61337 : (port + 1));
                continue;
            }
            if (::listen(ls, SOMAXCONN) == SOCKET_ERROR) {
                int le = WSAGetLastError();
                log::printf("TcpPipeProxy: listen(0.0.0.0:%u) failed wsae=%d; trying next", (unsigned)port, le);
                ::closesocket(ls);
                port = static_cast<uint16_t>((port == 65535) ? 61337 : (port + 1));
                continue;
            }

            outPort = port;
            uint16_t next = static_cast<uint16_t>((port == 65535) ? 61337 : (port + 1));
            next_port_.store(next, std::memory_order_release);

            log::printf("TcpPipeProxy: listening on 0.0.0.0:%u", (unsigned)outPort);
            return ls;
        }

        log::printf("TcpPipeProxy: could not bind any port in range after %u attempts (starting at %u)",
            (unsigned)kMaxAttempts, (unsigned)start);
        return INVALID_SOCKET;
    }

    void TcpPipeProxyService::worker_loop() {
        if (listen_ == INVALID_SOCKET) {
            listen_ = create_and_bind_ephemeral(listen_port_);
            if (listen_ == INVALID_SOCKET) {
                log::printf("TcpPipeProxy: failed to create initial listener; exiting worker");
                return;
            }
        }
        else {
            log::printf("TcpPipeProxy: reusing existing listener on 0.0.0.0:%u", (unsigned)listen_port_);
        }

        while (running_.load(std::memory_order_acquire)) {
            SOCKET cli = INVALID_SOCKET;
            sockaddr_in ra{}; int ralen = sizeof(ra);

            for (;;) {
                if (!running_.load(std::memory_order_acquire)) break;

                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(listen_, &rfds);
                timeval tv{ 0, 250 * 1000 }; // 250ms
                int sel = ::select(0, &rfds, nullptr, nullptr, &tv);
                if (sel == SOCKET_ERROR) {
                    int e = WSAGetLastError();
                    log::printf("TcpPipeProxy: select() on listener failed wsae=%d", e);
                    // Try to recreate the listener once if it died.
                    ::closesocket(listen_);
                    listen_ = create_and_bind_ephemeral(listen_port_);
                    if (listen_ == INVALID_SOCKET) {
                        log::printf("TcpPipeProxy: could not re-create listener; exiting worker");
                        return;
                    }
                    continue;
                }
                if (sel == 0) continue; // timeout, loop again

                cli = ::accept(listen_, reinterpret_cast<sockaddr*>(&ra), &ralen);
                if (cli == INVALID_SOCKET) {
                    int e = WSAGetLastError();
                    if (e == WSAEINTR) continue;
                    log::printf("TcpPipeProxy: accept() failed wsae=%d", e);
                    // If accept fails hard, try to rebuild listener.
                    ::closesocket(listen_);
                    listen_ = create_and_bind_ephemeral(listen_port_);
                    if (listen_ == INVALID_SOCKET) {
                        log::printf("TcpPipeProxy: could not re-create listener after accept failure; exiting worker");
                        return;
                    }
                    continue;
                }
                break;
            }

            if (!running_.load(std::memory_order_acquire)) {
                if (cli != INVALID_SOCKET) ::closesocket(cli);
                break;
            }

            if (cli == INVALID_SOCKET) {
                continue;
            }

            sockaddr_in la{}; int lalen = sizeof(la);
            if (getsockname(cli, reinterpret_cast<sockaddr*>(&la), &lalen) == 0) {
                std::string remote = fmt_addr(ra);
                std::string local = fmt_addr(la);
                log::printf("TcpPipeProxy: client connected remote=%s local=%s",
                    remote.c_str(), local.c_str());
            }
            else {
                char rip[INET_ADDRSTRLEN] = {}; inet_ntop(AF_INET, &ra.sin_addr, rip, sizeof(rip));
                log::printf("TcpPipeProxy: client connected remote=%s:%u (local unknown)",
                    rip[0] ? rip : "0.0.0.0", ntohs(ra.sin_port));
            }

            serve_single_client(cli);
        }

        // Worker stopping: close listener to release the port.
        if (listen_ != INVALID_SOCKET) {
            ::closesocket(listen_);
            listen_ = INVALID_SOCKET;
            log::printf("TcpPipeProxy: listener closed; port %u released", (unsigned)listen_port_);
            listen_port_ = 0;
        }
        log::printf("TcpPipeProxy: worker loop exit");
    }

    bool TcpPipeProxyService::recv_target_pipe_name(SOCKET s, std::string& outName) {
        outName.clear();
        static constexpr size_t kMax = 4096;

        std::vector<char> buf;
        buf.reserve(256);

        log::printf("TcpPipeProxy: awaiting target pipe name (nul or LF-terminated)");
        for (;;) {
            char tmp[256];
            int got = ::recv(s, tmp, sizeof(tmp), 0);
            if (got == 0) {
                log::printf("TcpPipeProxy: socket closed while reading target name");
                return false; // orderly shutdown
            }
            if (got == SOCKET_ERROR) {
                log::printf("TcpPipeProxy: recv() while reading target name failed wsae=%d", WSAGetLastError());
                return false; // error
            }

            for (int i = 0; i < got; ++i) {
                char c = tmp[i];
                if (c == '\0' || c == '\n') {
                    if (!buf.empty() && buf.back() == '\r') buf.pop_back(); // Trim CR
                    outName.assign(buf.begin(), buf.end());
                    log::printf("TcpPipeProxy: target name received: '%s'", outName.c_str());
                    return !outName.empty();
                }
                buf.push_back(c);
                if (buf.size() >= kMax) {
                    log::printf("TcpPipeProxy: target name too long (> %zu)", kMax);
                    return false; // unreasonable
                }
            }
        }
    }

    void TcpPipeProxyService::serve_single_client(SOCKET cli) {
        u_long nb = 0;
        ::ioctlsocket(cli, FIONBIO, &nb);
        BOOL nodelay = TRUE;
        ::setsockopt(cli, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

        std::string targetPipe;
        if (!recv_target_pipe_name(cli, targetPipe)) {
            log::printf("TcpPipeProxy: no valid target name; closing client");
            closesocket_safe(cli);
            return;
        }

        // Allow leaf names by prefixing \\.\pipe
        if (targetPipe.rfind("\\\\", 0) != 0) {
            targetPipe = R"(\\.\pipe\)" + targetPipe;
            log::printf("TcpPipeProxy: normalized target to '%s'", targetPipe.c_str());
        }

        bool isMsg = false;
        uint32_t outHint = 0, inHint = 0;
        DWORD le = 0;
        HANDLE hPipe = open_named_pipe_best_effort(targetPipe, /*timeoutMs*/15000, isMsg, outHint, inHint, le);
        if (hPipe == INVALID_HANDLE_VALUE) {
            log::printf("TcpPipeProxy: failed to open pipe '%s' gle=%lu", targetPipe.c_str(), le);
            closesocket_safe(cli);
            return;
        }

        bridge_socket_and_pipe(cli, hPipe);
        log::printf("TcpPipeProxy: session fully torn down (client + pipe). Returning to listener.");
    }

    DWORD WINAPI TcpPipeProxyService::sock_to_pipe_thunk(LPVOID p) {
        BridgeCtx* ctx = static_cast<BridgeCtx*>(p);
        if (!ctx) return 0;

        static constexpr uint32_t kMaxFrame = 64 * 1024 * 1024;  // 64 MB safety cap
        static constexpr DWORD kBufSz = 64 * 1024;

        std::vector<uint8_t> buf(kBufSz);

        const DWORD fallback_chunk =
            (ctx->in_hint > 0 && ctx->in_hint < kBufSz) ? ctx->in_hint : kBufSz;

        uint64_t total_bytes = 0;

        for (;;) {
            if (ctx->cancelFlag && ctx->cancelFlag->load(std::memory_order_acquire)) break;

            uint32_t n = 0;
            if (!recv_framed_header(ctx->s, n)) {
                int e = WSAGetLastError();
                log::printf("TcpPipeProxy: sock->pipe: header recv failed (eof or wsae=%d)", e);
                break;
            }
            if (n > kMaxFrame) {
                log::printf("TcpPipeProxy: sock->pipe: frame too large (%u > %u)", n, kMaxFrame);
                break;
            }

            if (buf.size() < n) buf.resize(n);
            if (n > 0 && !recv_exact_socket(ctx->s, buf.data(), n)) {
                int e = WSAGetLastError();
                log::printf("TcpPipeProxy: sock->pipe: payload recv failed wsae=%d (expected=%u)", e, n);
                break;
            }

            DWORD remaining = n;
            DWORD offset = 0;

            if (remaining > 0) {
                DWORD wrote = 0;
                BOOL ok;
                {
                    SuppressHooksGuard g;
                    ok = WriteFile(ctx->hPipe, buf.data() + offset, remaining, &wrote, nullptr);
                }
                if (!ok) {
                    DWORD le = GetLastError();
                    log::printf("TcpPipeProxy: sock->pipe: WriteFile (single) failed gle=%lu after wrote=%u of %u",
                        le, wrote, remaining);
                    goto done;
                }

                remaining -= wrote;
                offset += wrote;

                if (remaining > 0) {
                    log::printf("TcpPipeProxy: sock->pipe: partial single write wrote=%u of %u; finishing...",
                        wrote, n);
                    while (remaining > 0) {
                        const DWORD to_write = (remaining < fallback_chunk) ? remaining : fallback_chunk;
                        DWORD w = 0;
                        BOOL ok2;
                        {
                            SuppressHooksGuard g;
                            ok2 = WriteFile(ctx->hPipe, buf.data() + offset, to_write, &w, nullptr);
                        }
                        if (!ok2) {
                            DWORD le = GetLastError();
                            log::printf("TcpPipeProxy: sock->pipe: WriteFile (fallback) failed gle=%lu after wrote=%u of %u",
                                le, w, to_write);
                            goto done;
                        }
                        remaining -= w;
                        offset += w;
                    }
                }

                total_bytes += n;
            }

            log::printf("TcpPipeProxy: sock->pipe: wrote frame len=%u (cumulative=%llu)%s",
                n, static_cast<unsigned long long>(total_bytes),
                (ctx->is_message_mode ? " mode=MESSAGE" : " mode=BYTE"));
        }

    done:
        if (ctx->cancelFlag) ctx->cancelFlag->store(true, std::memory_order_release);
        log::printf("TcpPipeProxy: sock->pipe thread exit (total=%llu)",
            static_cast<unsigned long long>(total_bytes));
        return 0;
    }


    DWORD WINAPI TcpPipeProxyService::pipe_to_sock_thunk(LPVOID p) {
        BridgeCtx* ctx = static_cast<BridgeCtx*>(p);
        if (!ctx) return 0;

        static constexpr DWORD kBufSz = 64 * 1024;
        std::vector<uint8_t> buf(kBufSz);

        uint64_t total_bytes = 0;

        for (;;) {
            if (ctx->cancelFlag && ctx->cancelFlag->load(std::memory_order_acquire)) break;

            DWORD state = 0;
            {
                SuppressHooksGuard g;
                GetNamedPipeInfo(ctx->hPipe, &state, nullptr, nullptr, nullptr);
            }
            bool isMsg = (state & PIPE_TYPE_MESSAGE) != 0;

            DWORD got = 0;
            BOOL ok = TRUE;

            if (isMsg) {
                DWORD avail = 0, left = 0;
                {
                    SuppressHooksGuard g;
                    if (!PeekNamedPipe(ctx->hPipe, nullptr, 0, nullptr, &avail, &left)) {
                        DWORD le = GetLastError();
                        log::printf("TcpPipeProxy: pipe->sock: PeekNamedPipe failed gle=%lu", le);
                        break;
                    }
                }
                if (avail == 0) { Sleep(1); continue; }
                if (buf.size() < avail) buf.resize(avail);
                {
                    SuppressHooksGuard g;
                    if (!::pipetap::PipeReadExact(ctx->hPipe, buf.data(), avail)) {
                        DWORD le = GetLastError();
                        log::printf("TcpPipeProxy: pipe->sock: PipeReadExact failed gle=%lu", le);
                        break;
                    }
                }
                got = avail;
            }
            else {
                {
                    SuppressHooksGuard g;
                    ok = ReadFile(ctx->hPipe, buf.data(), kBufSz, &got, nullptr);
                }
                if (!ok) {
                    DWORD le = GetLastError();
                    log::printf("TcpPipeProxy: pipe->sock: ReadFile failed gle=%lu", le);
                    break;
                }
                if (got == 0) {
                    log::printf("TcpPipeProxy: pipe->sock: EOF (got=0)");
                    break;
                }
            }

            if (!send_framed(ctx->s, buf.data(), got)) {
                int we = WSAGetLastError();
                log::printf("TcpPipeProxy: pipe->sock: send_framed failed wsae=%d (len=%lu)", we, got);
                goto done;
            }

            total_bytes += static_cast<uint64_t>(got);
            log::printf("TcpPipeProxy: pipe->sock: framed send len=%lu (cumulative=%llu) mode=%s",
                got, static_cast<unsigned long long>(total_bytes), isMsg ? "MESSAGE" : "BYTE");
        }

    done:
        if (ctx->cancelFlag) ctx->cancelFlag->store(true, std::memory_order_release);
        log::printf("TcpPipeProxy: pipe->sock thread exit (total=%llu)", static_cast<unsigned long long>(total_bytes));
        return 0;
    }

    void TcpPipeProxyService::bridge_socket_and_pipe(SOCKET s, HANDLE hPipe) {
        std::atomic<bool> cancel{ false };

        uint8_t is_msg = 0; uint32_t outHint = 0, inHint = 0;
        query_pipe_hints(hPipe, is_msg, outHint, inHint);

        BridgeCtx ctx{};
        ctx.s = s;
        ctx.hPipe = hPipe;
        ctx.cancelFlag = &cancel;
        ctx.in_hint = inHint;
        ctx.out_hint = outHint;
        ctx.is_message_mode = (is_msg != 0);

        log::printf("TcpPipeProxy: starting bridge (mode=%s in_hint=%u out_hint=%u)",
            ctx.is_message_mode ? "MESSAGE" : "BYTE", ctx.in_hint, ctx.out_hint);

        HANDLE t_sock_to_pipe = CreateThread(nullptr, 0, &TcpPipeProxyService::sock_to_pipe_thunk, &ctx, 0, nullptr);
        HANDLE t_pipe_to_sock = CreateThread(nullptr, 0, &TcpPipeProxyService::pipe_to_sock_thunk, &ctx, 0, nullptr);

        if (!t_sock_to_pipe || !t_pipe_to_sock) {
            log::printf("TcpPipeProxy: failed to create bridge threads (t1=%p t2=%p)", t_sock_to_pipe, t_pipe_to_sock);
        }

        HANDLE list[2]{ t_sock_to_pipe, t_pipe_to_sock };
        DWORD which = WaitForMultipleObjects(2, list, FALSE, INFINITE);
        log::printf("TcpPipeProxy: first bridge thread completed (which=%lu)", which);

        HANDLE other = (which == WAIT_OBJECT_0) ? t_pipe_to_sock : t_sock_to_pipe;
        if (other) CancelSynchronousIo(other);
        ::shutdown(s, SD_BOTH);
        cancel.store(true, std::memory_order_release);

        if (t_sock_to_pipe) { WaitForSingleObject(t_sock_to_pipe, 3000); CloseHandle(t_sock_to_pipe); }
        if (t_pipe_to_sock) { WaitForSingleObject(t_pipe_to_sock, 3000); CloseHandle(t_pipe_to_sock); }

        {
            SuppressHooksGuard _guard;
            if (hPipe && hPipe != INVALID_HANDLE_VALUE) {
                CloseHandle(hPipe);
                log::printf("TcpPipeProxy: closed pipe handle=%p", hPipe);
            }
        }
        closesocket_safe(s);
        log::printf("TcpPipeProxy: closed client socket and stopped bridge");
    }

} // namespace pipetap::inject
