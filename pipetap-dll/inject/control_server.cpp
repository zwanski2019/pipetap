#include "pch.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <memory>
#include <atomic>
#include <string>

#include "pipetap/log.h"
#include "pipetap/controlpipe.h"
#include "pipetap/winpipe_helpers.h"

#include "inject/control_server.h"
#include "inject/hook_guards.h"
#include "inject/pipe_utils.h"
#include "inject/tcp_pipe_proxy.h"
#include "inject/namedpipe_client.h"


namespace pipetap::inject {

    static inline HANDLE atomic_load_handle(const HANDLE& h) {
        return (HANDLE)InterlockedCompareExchangePointer((PVOID*)&h, nullptr, nullptr);
    }
    static inline HANDLE atomic_exchange_handle(HANDLE& h, HANDLE hNew) {
        return (HANDLE)InterlockedExchangePointer((PVOID*)&h, hNew);
    }

    struct SrwExclusive {
        SRWLOCK* l; explicit SrwExclusive(SRWLOCK* p) : l(p) { AcquireSRWLockExclusive(l); }
        ~SrwExclusive() { ReleaseSRWLockExclusive(l); }
    };
    struct SrwShared {
        SRWLOCK* l; explicit SrwShared(SRWLOCK* p) : l(p) { AcquireSRWLockShared(l); }
        ~SrwShared() { ReleaseSRWLockShared(l); }
    };

    static std::wstring wbasename(const std::wstring& w) {
        size_t pos = w.find_last_of(L"\\/");
        return (pos == std::wstring::npos) ? w : w.substr(pos + 1);
    }

    static std::string utf8_from_w(const std::wstring& w) {
        if (w.empty()) return std::string();
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        if (len <= 0) return std::string();
        std::string out; out.resize((size_t)len);
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), len, nullptr, nullptr);
        return out;
    }

    class ProcessImageCache {
    public:
        static ProcessImageCache& instance() {
            static ProcessImageCache g;
            return g;
        }

        std::string get_image_basename(uint32_t pid) {
            if (pid == 0) return std::string();

            {
                SrwShared s(&lock_);
                auto it = map_.find(pid);
                if (it != map_.end()) return it->second;
            }

            std::string name = resolve_image_basename(pid);

            {
                SrwExclusive e(&lock_);
                map_[pid] = name;
            }

            return name;
        }

    private:
        SRWLOCK lock_ = SRWLOCK_INIT;
        std::unordered_map<uint32_t, std::string> map_;

        static std::string resolve_image_basename(uint32_t pid) {
            std::wstring wpath;
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (hp) {
                wchar_t buf[MAX_PATH * 4] = { 0 };
                DWORD sz = (DWORD)(std::size(buf));
                if (QueryFullProcessImageNameW(hp, 0, buf, &sz) && sz > 0) {
                    wpath.assign(buf, buf + sz);
                }

                CloseHandle(hp);
            }
            if (wpath.empty()) return std::string();

            return utf8_from_w(wbasename(wpath));
        }
    };

    struct PeerInfo { uint32_t pid; uint8_t role; };

    class PipePeerCache {
    public:
        static PipePeerCache& instance() {
            static PipePeerCache g;
            return g;
        }

        PeerInfo get_peer(HANDLE h) {
            if (!h || h == INVALID_HANDLE_VALUE) return { 0, 0 };

            PeerInfo cached{ 0, 0 };
            bool     haveCached = false;
            {
                SrwShared s(&lock_);
                auto it = map_.find(h);
                if (it != map_.end()) {
                    cached = it->second;
                    haveCached = true;
                }
            }

            PeerInfo live = resolve_peer(h);

            if (!haveCached) {
                SrwExclusive e(&lock_);
                map_[h] = live;
                return live;
            }

            if (live.pid != cached.pid || live.role != cached.role) {
                SrwExclusive e(&lock_);
                map_[h] = live;
                return live;
            }
            return cached;
        }

        void invalidate(HANDLE h) {
            SrwExclusive e(&lock_);
            map_.erase(h);
        }

    private:
        SRWLOCK lock_ = SRWLOCK_INIT;
        std::unordered_map<HANDLE, PeerInfo> map_;

        static PeerInfo resolve_peer(HANDLE h) {
            ULONG pid = 0;
            if (GetNamedPipeClientProcessId(h, &pid) && pid) return { (uint32_t)pid, 1 }; // server end
            if (GetNamedPipeServerProcessId(h, &pid) && pid) return { (uint32_t)pid, 2 }; // client end
            return { 0u, 0u }; // disconnected/unknown/listening
        }
    };

    ControlServer& ControlServer::instance() {
        static ControlServer g_instance;
        return g_instance;
    }

    void ControlServer::start()
    {
        if (running_.exchange(true, std::memory_order_acq_rel)) return;
        connected_.store(false, std::memory_order_release);

        HANDLE th = CreateThread(nullptr, 0, control_pipe_thread_thunk, this, 0, nullptr);
        if (th) CloseHandle(th);

        ::pipetap::inject::TcpPipeProxyService::instance().start();
    }

    void ControlServer::stop()
    {
        running_.store(false, std::memory_order_release);

        ::pipetap::inject::TcpPipeProxyService::instance().stop();

        NamedPipeClient::instance().close_all(/*reason=*/0u, /*win32err=*/0u);

        HANDLE r = (HANDLE)InterlockedExchangePointer((PVOID*)&ctrl_r_, INVALID_HANDLE_VALUE);
        HANDLE w = (HANDLE)InterlockedExchangePointer((PVOID*)&ctrl_w_, INVALID_HANDLE_VALUE);

        if (r && r != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(r); CloseHandle(r); }
        if (w && w != INVALID_HANDLE_VALUE) { CloseHandle(w); }

        ctrl_broken_.store(true, std::memory_order_release);
        connected_.store(false, std::memory_order_release);

        AcquireSRWLockExclusive(&edit_lock_);
        for (auto& kv : pending_) SetEvent(kv.second->evt);
        pending_.clear();
        ReleaseSRWLockExclusive(&edit_lock_);
    }

    bool ControlServer::is_ctrl_handle(HANDLE h) const
    {
        HANDLE r = (HANDLE)InterlockedCompareExchangePointer((PVOID*)&ctrl_r_, nullptr, nullptr);
        HANDLE w = (HANDLE)InterlockedCompareExchangePointer((PVOID*)&ctrl_w_, nullptr, nullptr);
        return h && h != INVALID_HANDLE_VALUE && (h == r || h == w);
    }

    void ControlServer::send_hello()
    {
        if (!is_connected()) return;

        PT_Hello hello{};
        hello.pid = GetCurrentProcessId();
        std::string name = exe_base_name();
        strncpy_s(hello.proc_name, sizeof(hello.proc_name), name.c_str(), _TRUNCATE);
        log::printf("SendHello: pid=%lu exe=%s", (unsigned long)hello.pid, hello.proc_name);

        send_control_message(PT_ControlFrame::FromStruct(PT_HELLO, hello));
    }

    void ControlServer::send_error(uint32_t code, const char* what)
    {
        if (!is_connected()) return;

        PT_Error e{};
        e.code = code;
        strncpy_s(e.what, sizeof(e.what), (what ? what : "err"), _TRUNCATE);

        send_control_message(PT_ControlFrame::FromStruct(PT_ERROR, e));
    }

    void ControlServer::send_pipe_io(uint16_t message_type, HANDLE pipe,
        const void* buf, uint32_t total,
        uint8_t dir, uint64_t op_id,
        const char* apiName)
    {
        if (!connected_.load(std::memory_order_relaxed)) return;

        uint8_t  is_msg = 0;
        uint32_t outHint = 0, inHint = 0;
        query_pipe_hints(pipe, is_msg, outHint, inHint);

        static constexpr uint32_t kMaxSample = 24 * 1024;

        std::string pipeName = pipe_name_for_handle(pipe);
        if (pipeName.size() > 0xFFFE) pipeName.resize(0xFFFE);

        std::string api = (apiName && *apiName) ? std::string(apiName) : std::string("(unknown)");
        if (api.size() > 0xFFFE) api.resize(0xFFFE);

        PeerInfo peer = PipePeerCache::instance().get_peer(pipe);
        std::string peerImg;
        if (peer.pid != 0) {
            peerImg = ProcessImageCache::instance().get_image_basename(peer.pid);
            if (peerImg.size() > 0xFFFE) peerImg.resize(0xFFFE);
        }

        PT_PipeIoEnvelope env{};
        env.meta.pid = GetCurrentProcessId();
        env.meta.tid = GetCurrentThreadId();
        env.meta.dir = dir;
        env.meta.is_message_mode = is_msg;
        env.meta.total_size = total;
        env.meta.out_buf_hint = outHint;
        env.meta.in_buf_hint = inHint;
        env.meta.op_id = op_id;
        env.meta.peer_pid = peer.pid;
        env.meta.endpoint_role = peer.role; // 0=unknown, 1=server-end, 2=client-end

        env.pipe_name = pipeName;
        env.api_name = api;
        env.peer_image = peerImg;
        env.payload = static_cast<const uint8_t*>(buf);
        env.payload_len = (buf && total) ? total : 0;
        env.max_sample = kMaxSample;

        auto frame = PT_BuildPipeIoMessage(message_type, env);
        send_control_message(frame);
    }

    void ControlServer::send_proxy_opened(uint64_t session_id,
        uint32_t win32_error,
        uint8_t  is_message_mode,
        uint32_t out_hint,
        uint32_t in_hint)
    {
        if (!is_connected()) return;
        PT_ProxyOpenResult r{};
        r.session_id = session_id;
        r.win32_error = win32_error;
        r.is_message_mode = is_message_mode;
        r.out_buf_hint = out_hint;
        r.in_buf_hint = in_hint;
        send_control_message(PT_ControlFrame::FromStruct(PT_EVT_PROXY_OPENED, r));
    }

    void ControlServer::send_proxy_closed(uint64_t session_id,
        uint32_t reason,
        uint32_t win32_error)
    {
        if (!is_connected()) return;
        PT_ProxyClosed ev{};
        ev.session_id = session_id;
        ev.reason = reason;
        ev.win32_error = win32_error;
        send_control_message(PT_ControlFrame::FromStruct(PT_EVT_PROXY_CLOSED, ev));
    }

    BOOL ControlServer::wait_for_edit_and_maybe_replace(uint64_t op_id,
        const void* /*orig*/, DWORD /*origSz*/,
        std::vector<uint8_t>& outBuf,
        BOOL* hasReplacement,
        DWORD timeoutMs)
    {
        if (!hasReplacement) return FALSE;
        *hasReplacement = FALSE;

        if (!is_connected()) return TRUE;

        PendingEdit* pe = create_pending(op_id);
        DWORD w = WaitForSingleObject(pe->evt, timeoutMs);
        if (w == WAIT_OBJECT_0) {
            if (pe->action == 1 && !pe->bytes.empty()) {
                outBuf = std::move(pe->bytes);
                *hasReplacement = TRUE;
            }
        }
        else if (w == WAIT_TIMEOUT) {
            send_error(1001u, "edit_timeout");
        }

        PendingEdit* rem = take_pending(op_id);
        if (!rem) rem = pe;
        delete rem;

        return TRUE;
    }

    DWORD WINAPI ControlServer::control_pipe_thread_thunk(LPVOID p) {
        static_cast<ControlServer*>(p)->control_pipe_thread();
        return 0;
    }

    void ControlServer::control_pipe_thread()
    {
        std::snprintf(pipe_ev_name_, sizeof(pipe_ev_name_), "%s%lu",
            PT_CTRL_EVENTS_PREFIX, GetCurrentProcessId());
        std::snprintf(pipe_cmd_name_, sizeof(pipe_cmd_name_), "%s%lu",
            PT_CTRL_COMMANDS_PREFIX, GetCurrentProcessId());

        log::printf("ControlPipeThread: events=%s commands=%s", pipe_ev_name_, pipe_cmd_name_);

        while (running_.load(std::memory_order_acquire))
        {
            HANDLE hEvSrv = create_events_pipe_instance();
            if (hEvSrv == INVALID_HANDLE_VALUE) { Sleep(250); continue; }

            HANDLE hCmdSrv = create_commands_pipe_instance();
            if (hCmdSrv == INVALID_HANDLE_VALUE) {
                CloseHandle(hEvSrv);
                Sleep(250); continue;
            }

            BOOL okEv = ConnectNamedPipe(hEvSrv, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
            BOOL okCmd = ConnectNamedPipe(hCmdSrv, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

            if (!okEv || !okCmd) {
                if (hEvSrv && hEvSrv != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(hEvSrv);  CloseHandle(hEvSrv); }
                if (hCmdSrv && hCmdSrv != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(hCmdSrv); CloseHandle(hCmdSrv); }
                Sleep(150);
                continue;
            }

            DWORD sm = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(hCmdSrv, &sm, nullptr, nullptr);

            (void)atomic_exchange_handle(ctrl_w_, hEvSrv);
            (void)atomic_exchange_handle(ctrl_r_, hCmdSrv);
            ctrl_broken_.store(false, std::memory_order_release);
            edit_req_.store(0, std::memory_order_release);
            edit_resp_.store(0, std::memory_order_release);

            connected_.store(true, std::memory_order_release);

            send_hello();

            handle_inbound_commands(hCmdSrv);

            HANDLE myR = atomic_exchange_handle(ctrl_r_, INVALID_HANDLE_VALUE);
            HANDLE myW = atomic_exchange_handle(ctrl_w_, INVALID_HANDLE_VALUE);

            if (myR && myR != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(myR); CloseHandle(myR); }
            if (myW && myW != INVALID_HANDLE_VALUE) { CloseHandle(myW); }

            // Drop all remote proxy sessions since control path died (reason=2=error)
            NamedPipeClient::instance().close_all(/*reason=*/2u, /*win32err=*/ERROR_BROKEN_PIPE);

            // Transition to disconnected state and fail outstanding edits so hooks can continue
            ctrl_broken_.store(true, std::memory_order_release);
            connected_.store(false, std::memory_order_release);

            AcquireSRWLockExclusive(&edit_lock_);
            for (auto& kv : pending_) SetEvent(kv.second->evt);
            pending_.clear();
            ReleaseSRWLockExclusive(&edit_lock_);

            Sleep(50);
        }
    }

    HANDLE ControlServer::create_events_pipe_instance()
    {
        return CreateNamedPipeA(
            pipe_ev_name_,
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 256 * 1024, 0, 0, nullptr);
    }

    HANDLE ControlServer::create_commands_pipe_instance()
    {
        return CreateNamedPipeA(
            pipe_cmd_name_,
            PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 0, 256 * 1024, 0, nullptr);
    }

    void ControlServer::send_control_message(const PT_ControlFrame& frame)
    {
        if (!connected_.load(std::memory_order_relaxed)) return;

        HANDLE hW = atomic_load_handle(ctrl_w_);
        if (ctrl_broken_.load(std::memory_order_acquire) || !hW || hW == INVALID_HANDLE_VALUE) {
            connected_.store(false, std::memory_order_release);
            return;
        }

        AcquireSRWLockExclusive(&ctrl_lock_);
        {
            SuppressHooksGuard _guard;
            DWORD wrote = 0;
            bool ok = ::pipetap::WriteControlFrame(hW, frame, &wrote);
            if (!ok) {
                ctrl_broken_.store(true, std::memory_order_release);
                connected_.store(false, std::memory_order_release);
                (void)atomic_exchange_handle(ctrl_w_, INVALID_HANDLE_VALUE);
            }
        }
        ReleaseSRWLockExclusive(&ctrl_lock_);
    }

    void ControlServer::handle_inbound_commands(HANDLE h)
    {
        for (;;)
        {
            if (!running_.load(std::memory_order_acquire)) break;

            DWORD totalAvail = 0, bytesLeftMsg = 0;
            {
                SuppressHooksGuard _guard;
                if (!PeekNamedPipe(h, nullptr, 0, nullptr, &totalAvail, &bytesLeftMsg)) break;
            }
            if (totalAvail < sizeof(PT_ControlMessageHeader)) { Sleep(1); continue; }

            PT_ControlFrame frame;
            {
                SuppressHooksGuard _guard;
                if (!::pipetap::ReadControlFrame(h, frame)) break;
            }

            ctrl_broken_.store(false, std::memory_order_release);
            connected_.store(true, std::memory_order_release);

            switch (frame.header.type) {
            case PT_CMD_SET_EDIT:
                {
                    PT_EditFlags fl{};
                    if (frame.TryAs(fl)) {
                        edit_req_.store(fl.edit_request ? 1u : 0u, std::memory_order_release);
                        edit_resp_.store(fl.edit_response ? 1u : 0u, std::memory_order_release);
                    }
                }
                break;

            case PT_CMD_EDIT_REPLY:
                {
                    PT_ControlFrame::Reader rd = frame.AsReader();
                    PT_EditReply rep{};
                    if (!rd.Next(rep)) break;

                    const uint8_t* bytes = nullptr;
                    uint32_t bsz = 0;
                    if (rep.action == 1 && rep.new_size) {
                        if (!rd.NextBytes(rep.new_size, bytes)) break;
                        bsz = rep.new_size;
                    }
                    complete_pending(rep.op_id, rep.action, bytes, bsz);
                }
                break;

            case PT_CMD_PROXY_OPEN:
                {
                    PT_ControlFrame::Reader rd = frame.AsReader();
                    PT_ProxyOpen op{};
                    if (!rd.Next(op)) break;

                    const uint8_t* name = nullptr;
                    if (op.name_len && !rd.NextBytes(op.name_len, name)) break;

                    uint32_t win32err = ERROR_INVALID_PARAMETER;
                    bool ok = false;

                    if (name && op.session_id != 0) {
                        uint8_t  is_msg = 0;
                        uint32_t out_hint = 0, in_hint = 0;

                        DWORD le = NamedPipeClient::instance().open_session(
                            *this,
                            op.session_id,
                            std::string(reinterpret_cast<const char*>(name), reinterpret_cast<const char*>(name) + op.name_len),
                            op.timeout_ms,
                            op.wait_for_server != 0,
                            op.set_message_readmode != 0,
                            /*out*/ is_msg,
                            /*out*/ out_hint,
                            /*out*/ in_hint);

                        if (le == 0) {
                            send_proxy_opened(op.session_id, 0, is_msg, out_hint, in_hint);
                            ok = true;
                        }
                        else {
                            win32err = le;
                        }
                    }

                    if (!ok) {
                        send_proxy_opened(op.session_id, win32err, 0, 0, 0);
                    }
                }
                break;

            case PT_CMD_PROXY_SEND:
                {
                    PT_ControlFrame::Reader rd = frame.AsReader();
                    PT_ProxySend ps{};
                    if (!rd.Next(ps)) break;

                    const uint8_t* data = nullptr;
                    if (ps.data_size && !rd.NextBytes(ps.data_size, data)) {
                        send_error(2001u, "proxy_send_bad_session");
                        break;
                    }
                    if (ps.data_size == 0 || !data) {
                        send_error(2001u, "proxy_send_bad_session");
                        break;
                    }

                    DWORD le = NamedPipeClient::instance().send_to_session(*this, ps.session_id, data, ps.data_size);
                    if (le != 0) {
                        if (le == ERROR_BROKEN_PIPE) {
                            // already notified by send_to_session via close + send_proxy_closed
                        }
                        else {
                            send_error(le ? le : 2002u, "proxy_send_write_failed");
                        }
                    }
                }
                break;

            case PT_CMD_PROXY_CLOSE:
                {
                    PT_ProxyClose c{};
                    if (frame.TryAs(c)) {
                        NamedPipeClient::instance().close_session(c.session_id, /*reason=*/0u, /*win32err=*/0u);
                    }
                }
                break;

            case PT_CMD_CLIENT_DISCONNECT:
                NamedPipeClient::instance().close_all(/*reason=*/0u, /*win32err=*/0u);
                break;

            default:
                // Ignore unknown control messages
                break;
            }
        }
    }

    ControlServer::PendingEdit* ControlServer::create_pending(uint64_t op)
    {
        auto* p = new PendingEdit();
        AcquireSRWLockExclusive(&edit_lock_);
        pending_.emplace(op, p);
        ReleaseSRWLockExclusive(&edit_lock_);
        return p;
    }

    ControlServer::PendingEdit* ControlServer::take_pending(uint64_t op)
    {
        PendingEdit* p = nullptr;
        AcquireSRWLockExclusive(&edit_lock_);
        auto it = pending_.find(op);
        if (it != pending_.end()) { p = it->second; pending_.erase(it); }
        ReleaseSRWLockExclusive(&edit_lock_);
        return p;
    }

    void ControlServer::complete_pending(uint64_t op, uint8_t action, const uint8_t* bytes, uint32_t n)
    {
        AcquireSRWLockExclusive(&edit_lock_);
        auto it = pending_.find(op);
        if (it != pending_.end()) {
            PendingEdit* p = it->second;
            p->action = action;
            if (action == 1 && bytes && n) p->bytes.assign(bytes, bytes + n);
            SetEvent(p->evt);
        }
        ReleaseSRWLockExclusive(&edit_lock_);
    }

} // namespace pipetap::inject
