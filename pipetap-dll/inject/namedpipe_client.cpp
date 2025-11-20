#include "pch.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <unordered_map>
#include <atomic>
#include <vector>
#include <string>
#include <memory>
#include "pipetap/controlpipe.h"
#include "pipetap/winpipe_helpers.h"
#include "inject/hook_guards.h"
#include "inject/pipe_utils.h"
#include "inject/control_server.h"
#include "inject/namedpipe_client.h"

namespace pipetap::inject {

    static inline HANDLE atomic_load_handle(const HANDLE& h) {
        return (HANDLE)InterlockedCompareExchangePointer((PVOID*)&h, nullptr, nullptr);
    }
    static inline HANDLE atomic_exchange_handle(HANDLE& h, HANDLE hNew) {
        return (HANDLE)InterlockedExchangePointer((PVOID*)&h, hNew);
    }

    static std::atomic<uint64_t> g_proxyNextOpId{ 1 };
    static inline uint64_t NewProxyOpId() { return g_proxyNextOpId.fetch_add(1, std::memory_order_relaxed); }

    struct NamedPipeClient::MapImpl {
        std::unordered_map<uint64_t, std::unique_ptr<Session>> sessions;
    };

    struct NamedPipeClient::Session {
        ControlServer* owner = nullptr;
        uint64_t session_id = 0;
        std::string pipe_path;

        HANDLE hPipe = INVALID_HANDLE_VALUE;
        HANDLE hThread = nullptr;

        bool want_message_readmode = false;
        bool is_message_mode = false;
        uint32_t out_hint = 0;
        uint32_t in_hint = 0;

        explicit Session(ControlServer* o, uint64_t sid, std::string path, bool req_msg_mode)
            : owner(o), session_id(sid), pipe_path(std::move(path)), want_message_readmode(req_msg_mode) {
        }

        ~Session() { stop(); }

        DWORD open_and_start(uint32_t timeout_ms, bool wait_for_server)
        {
            SuppressHooksGuard _guard;

            if (wait_for_server) {
                if (!WaitNamedPipeA(pipe_path.c_str(), timeout_ms ? timeout_ms : NMPWAIT_USE_DEFAULT_WAIT)) {
                    DWORD le = GetLastError();
                    return le ? le : ERROR_SEM_TIMEOUT;
                }
            }

            hPipe = CreateFileA(pipe_path.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hPipe == INVALID_HANDLE_VALUE) {
                return GetLastError();
            }

            // Query mode/hints
            uint8_t is_msg = 0; uint32_t outBuf = 0, inBuf = 0;
            query_pipe_hints(hPipe, is_msg, outBuf, inBuf);
            is_message_mode = (is_msg != 0);
            out_hint = outBuf; in_hint = inBuf;

            if (want_message_readmode && is_message_mode) {
                DWORD m = PIPE_READMODE_MESSAGE;
                SetNamedPipeHandleState(hPipe, &m, nullptr, nullptr);
            }

            is_msg = 0; outBuf = inBuf = 0;
            query_pipe_hints(hPipe, is_msg, outBuf, inBuf);
            is_message_mode = (is_msg != 0);
            out_hint = outBuf; in_hint = inBuf;

            hThread = CreateThread(nullptr, 0, &Session::ReaderThunk, this, 0, nullptr);
            if (!hThread) {
                DWORD le = GetLastError();
                CloseHandle(hPipe); hPipe = INVALID_HANDLE_VALUE;
                return le ? le : ERROR_GEN_FAILURE;
            }
            return 0;
        }

        void stop()
        {
            SuppressHooksGuard _guard;

            HANDLE h = hPipe;
            hPipe = INVALID_HANDLE_VALUE;

            if (h && h != INVALID_HANDLE_VALUE) {
                CloseHandle(h);
            }
            if (hThread) {
                WaitForSingleObject(hThread, 5000);
                CloseHandle(hThread);
                hThread = nullptr;
            }
        }

        bool write_all(const void* buf, DWORD len, DWORD* last_err)
        {
            SuppressHooksGuard _guard;

            if (!hPipe || hPipe == INVALID_HANDLE_VALUE) { if (last_err) *last_err = ERROR_INVALID_HANDLE; return false; }
            const uint8_t* p = static_cast<const uint8_t*>(buf);
            DWORD total = 0;
            while (total < len) {
                DWORD wrote = 0;
                BOOL ok = WriteFile(hPipe, p + total, len - total, &wrote, nullptr);
                if (!ok) {
                    if (last_err) *last_err = GetLastError();
                    return false;
                }
                total += wrote;
            }
            return true;
        }

        static DWORD WINAPI ReaderThunk(LPVOID ctx)
        {
            static constexpr DWORD kMaxByteRead = 64 * 1024;
            Session* self = static_cast<Session*>(ctx);
            if (!self) return 0;

            HANDLE h = self->hPipe;

            std::vector<uint8_t> buf;
            buf.reserve(kMaxByteRead);

            for (;;) {
                if (!h || h == INVALID_HANDLE_VALUE) break;

                if (self->is_message_mode) {
                    DWORD totalAvail = 0, bytesLeft = 0;
                    {
                        SuppressHooksGuard g;
                        if (!PeekNamedPipe(h, nullptr, 0, nullptr, &totalAvail, &bytesLeft)) {
                            DWORD le = GetLastError();
                            self->notify_closed((le == ERROR_BROKEN_PIPE) ? 1u : 2u, le);
                            break;
                        }
                    }
                    if (totalAvail == 0) { Sleep(1); continue; }

                    buf.resize(totalAvail);
                    {
                        SuppressHooksGuard g;
                        if (!::pipetap::PipeReadExact(h, buf.data(), totalAvail)) {
                            DWORD le = GetLastError();
                            self->notify_closed((le == ERROR_BROKEN_PIPE) ? 1u : 2u, le);
                            break;
                        }
                    }

                    self->owner->send_pipe_io(PT_PIPE_READ, h, buf.data(), (uint32_t)buf.size(),
                        /*dir=*/0, NewProxyOpId(), "ProxyRead");
                }
                else {
                    buf.resize(kMaxByteRead);
                    DWORD got = 0;
                    BOOL ok = FALSE;
                    {
                        SuppressHooksGuard g;
                        ok = ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr);
                    }
                    if (!ok) {
                        DWORD le = GetLastError();
                        if (le == ERROR_BROKEN_PIPE) self->notify_closed(1u, le);
                        else self->notify_closed(2u, le);
                        break;
                    }
                    if (got == 0) { Sleep(1); continue; }
                    buf.resize(got);

                    self->owner->send_pipe_io(PT_PIPE_READ, h, buf.data(), (uint32_t)buf.size(),
                        /*dir=*/0, NewProxyOpId(), "ProxyRead");
                }
            }

            return 0;
        }

        void notify_closed(uint32_t reason, uint32_t win32err)
        {
            owner->send_proxy_closed(session_id, reason, win32err);
        }
    };

    NamedPipeClient& NamedPipeClient::instance() {
        static NamedPipeClient g;
        return g;
    }

    NamedPipeClient::Session* NamedPipeClient::get(uint64_t sid)
    {
        NamedPipeClient::Session* p = nullptr;
        AcquireSRWLockShared(&lock_);
        if (map_) {
            auto it = map_->sessions.find(sid);
            if (it != map_->sessions.end()) p = it->second.get();
        }
        ReleaseSRWLockShared(&lock_);
        return p;
    }

    void NamedPipeClient::add(std::unique_ptr<Session> s)
    {
        AcquireSRWLockExclusive(&lock_);
        if (!map_) map_ = std::make_unique<MapImpl>();
        map_->sessions.emplace(s->session_id, std::move(s));
        ReleaseSRWLockExclusive(&lock_);
    }

    std::unique_ptr<NamedPipeClient::Session> NamedPipeClient::take(uint64_t sid)
    {
        std::unique_ptr<Session> out;
        AcquireSRWLockExclusive(&lock_);
        if (map_) {
            auto it = map_->sessions.find(sid);
            if (it != map_->sessions.end()) {
                out = std::move(it->second);
                map_->sessions.erase(it);
            }
        }
        ReleaseSRWLockExclusive(&lock_);
        return out;
    }

    DWORD NamedPipeClient::open_session(
        ControlServer& owner,
        uint64_t       session_id,
        const std::string& pipe_path,
        uint32_t       timeout_ms,
        bool           wait_for_server,
        bool           want_message_readmode,
        uint8_t& is_message_mode,
        uint32_t& out_hint,
        uint32_t& in_hint)
    {
        // Replace-if-exists
        {
            auto old = take(session_id);
            if (old) { old->notify_closed(0u, 0u); old->stop(); }
        }

        auto sess = std::make_unique<Session>(&owner, session_id, pipe_path, want_message_readmode);
        DWORD le = sess->open_and_start(timeout_ms, wait_for_server);
        if (le != 0) {
            return le;
        }

        is_message_mode = sess->is_message_mode ? 1u : 0u;
        out_hint = sess->out_hint;
        in_hint = sess->in_hint;

        add(std::move(sess));
        return 0;
    }

    DWORD NamedPipeClient::send_to_session(
        ControlServer& owner,
        uint64_t       session_id,
        const uint8_t* data,
        uint32_t       size)
    {
        Session* s = get(session_id);
        if (!s || !data || size == 0) return ERROR_INVALID_PARAMETER;

        DWORD last = 0;
        if (!s->write_all(data, size, &last)) {
            if (last == ERROR_BROKEN_PIPE) {
                auto sp = take(session_id);
                if (sp) {
                    sp->notify_closed(/*reason=*/1u, last);
                    sp->stop();
                }
            }
            return last ? last : ERROR_GEN_FAILURE;
        }

        owner.send_pipe_io(PT_PIPE_WRITE,
            s->hPipe,
            data,
            size,
            /*dir=*/1,
            NewProxyOpId(),
            "ProxyWrite");

        return 0;
    }

    void NamedPipeClient::close_session(
        uint64_t       session_id,
        uint32_t       reason,
        uint32_t       win32err)
    {
        auto sp = take(session_id);
        if (sp) {
            sp->notify_closed(reason, win32err);
            sp->stop();
        }
    }

    void NamedPipeClient::close_all(
        uint32_t       reason,
        uint32_t       win32err)
    {
        AcquireSRWLockExclusive(&lock_);
        if (map_) {
            for (auto& kv : map_->sessions) {
                if (kv.second) {
                    kv.second->notify_closed(reason, win32err);
                    kv.second->stop();
                }
            }
            map_->sessions.clear();
        }
        ReleaseSRWLockExclusive(&lock_);
    }

} // namespace pipetap::inject
