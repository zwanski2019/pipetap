#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "ctrlclient.h"
#include "log.h"
#include "session.h"
#include "pipetap/winpipe_helpers.h"
#include "win/error.h"
#include <cstring>
#include <sstream>
#include <thread>
#include <vector>
#include <Windows.h>

namespace pipetap::ctrlclient {

    using pipetap::win::FormatLeA;

    void CtrlClient::Start(CtrlMsgCallback cb) {
        Stop();
        fixed_pid_.store(0, std::memory_order_release);
        { std::lock_guard<std::mutex> lk(cb_mx_); cb_ = std::move(cb); }
        run_.store(true, std::memory_order_release);
        reader_ = std::thread([this]() { this->Loop(); });
    }

    void CtrlClient::StartForPid(DWORD pid, CtrlMsgCallback cb) {
        Stop();
        fixed_pid_.store(pid, std::memory_order_release);
        { std::lock_guard<std::mutex> lk(cb_mx_); cb_ = std::move(cb); }
        run_.store(true, std::memory_order_release);
        reader_ = std::thread([this]() { this->Loop(); });
    }

    void CtrlClient::Stop() {
        run_.store(false, std::memory_order_release);

        // prevent late UI calls
        { std::lock_guard<std::mutex> lk(cb_mx_); cb_ = nullptr; }

        HANDLE ev_to_cancel = INVALID_HANDLE_VALUE;
        HANDLE cmd_to_cancel = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> lk(wr_mtx_);
            ev_to_cancel = h_ev_;  h_ev_ = INVALID_HANDLE_VALUE;
            cmd_to_cancel = h_cmd_; h_cmd_ = INVALID_HANDLE_VALUE;
            connected.store(false, std::memory_order_release);
        }

        if (ev_to_cancel != INVALID_HANDLE_VALUE) CancelIoEx(ev_to_cancel, nullptr);
        if (cmd_to_cancel != INVALID_HANDLE_VALUE) CancelIoEx(cmd_to_cancel, nullptr);

        if (reader_.joinable()) {
            HANDLE th = (HANDLE)reader_.native_handle();
            if (th) CancelSynchronousIo(th);
        }

        if (reader_.joinable()) {
            reader_.join();
        }

        if (ev_to_cancel != INVALID_HANDLE_VALUE) CloseHandle(ev_to_cancel);
        if (cmd_to_cancel != INVALID_HANDLE_VALUE) CloseHandle(cmd_to_cancel);
    }

    void CtrlClient::DisconnectHandles(bool cancel_io)
    {
        HANDLE ev_to_close = INVALID_HANDLE_VALUE;
        HANDLE cmd_to_close = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> lk(wr_mtx_);
            ev_to_close = h_ev_;  h_ev_ = INVALID_HANDLE_VALUE;
            cmd_to_close = h_cmd_; h_cmd_ = INVALID_HANDLE_VALUE;
            connected.store(false, std::memory_order_release);
        }

        if (cancel_io) {
            if (cmd_to_close != INVALID_HANDLE_VALUE) CancelIoEx(cmd_to_close, nullptr);
            if (ev_to_close != INVALID_HANDLE_VALUE) CancelIoEx(ev_to_close, nullptr);
        }

        if (cmd_to_close != INVALID_HANDLE_VALUE) CloseHandle(cmd_to_close);
        if (ev_to_close != INVALID_HANDLE_VALUE) CloseHandle(ev_to_close);
    }

    bool CtrlClient::SendTLV(uint16_t type, const void* v1, uint32_t n1, const void* v2, uint32_t n2) {

        std::vector<::pipetap::TlvFragment> fragments;
        size_t expected = 0;
        if (n1 && v1) ++expected;
        if (n2 && v2) ++expected;
        fragments.reserve(expected);
        if (n1 && v1) fragments.push_back({ v1, n1 });
        if (n2 && v2) fragments.push_back({ v2, n2 });
        auto msg = ::pipetap::BuildTlvMessage(type, fragments);

        HANDLE h = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> lk(wr_mtx_);
            if (!connected.load(std::memory_order_acquire) || h_cmd_ == INVALID_HANDLE_VALUE) {
                pipetap::log::App.Error("CtrlClient::SendTLV: not connected");
                return false;
            }
            h = h_cmd_;
        }

        DWORD wrote = 0;
        pipetap::log::App.Infof("CtrlClient::SendTLV: type=%u total=%lu", (unsigned)type, (unsigned long)msg.size());
        if (!WriteFile(h, msg.data(), (DWORD)msg.size(), &wrote, nullptr) || wrote != msg.size()) {
            DWORD le = GetLastError();
            pipetap::log::App.Errorf("CtrlClient::SendTLV: write failed wrote=%lu/%lu le=%lu",
                (unsigned long)wrote, (unsigned long)msg.size(), (unsigned long)le);

            {
                std::ostringstream os; os << "Write failed on commands pipe: " << FormatLeA(le);
                DWORD p = fixed_pid_.load(std::memory_order_acquire);
                if (!p) p = pipetap::session::Session().ctrl_pid;
                this->SetLastError(p, os.str());
            }

            DisconnectHandles(true);
            return false;
        }
        return true;
    }

    void CtrlClient::Loop()
    {
        run_.store(true, std::memory_order_release);
        DWORD last_pid = 0;

        pipetap::log::App.Infof("CtrlClient::Loop: start (fixed_pid=%lu)",
            (unsigned long)fixed_pid_.load(std::memory_order_acquire));

        while (run_.load(std::memory_order_acquire)) {
            const DWORD pinned = fixed_pid_.load(std::memory_order_acquire);
            const DWORD cur_pid = pinned ? pinned : session::Session().ctrl_pid;
            const char* display = session::Session().ctrl_pipe;

            // TODO: think this is legacy
            if (cur_pid == 0) {
                if (connected.load(std::memory_order_acquire)) {
                    pipetap::log::App.Infof("CtrlClient::Loop: pid=0 -> close handles");
                    DisconnectHandles(false);
                    last_pid = 0;
                }
                this->ClearLastError();

                Sleep(150);
                continue;
            }

            if (!pinned && connected.load(std::memory_order_acquire) && last_pid != cur_pid) {
                pipetap::log::App.Infof("CtrlClient::Loop: pid changed %lu -> %lu",
                    (unsigned long)last_pid, (unsigned long)cur_pid);

                DisconnectHandles(false);
            }

            if (!connected.load(std::memory_order_acquire)) {
                last_pid = cur_pid;

                std::string ev_path = MakeEventsPipeForPid(cur_pid);
                std::string cmd_path = MakeCommandsPipeForPid(cur_pid);
                pipetap::log::App.Infof("CtrlClient::Loop: connecting events=%s  commands=%s  (ui:%s)",
                    ev_path.c_str(), cmd_path.c_str(), display);

                for (int i = 0; i < 60 && run_.load(std::memory_order_acquire); ++i) {
                    BOOL ev_ready = WaitNamedPipeA(ev_path.c_str(), 250);
                    BOOL cmd_ready = WaitNamedPipeA(cmd_path.c_str(), 250);
                    if (ev_ready && cmd_ready) break;
                    Sleep(50);
                }
                if (!run_.load(std::memory_order_acquire)) break;

                HANDLE h_ev = CreateFileA(ev_path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
                if (h_ev == INVALID_HANDLE_VALUE) {
                    const DWORD le = GetLastError();
                    pipetap::log::App.Errorf("CtrlClient::Loop: CreateFileA(events) failed le=%lu", (unsigned long)le);
                    this->SetLastError(cur_pid, std::string("Open events pipe failed: ") + FormatLeA(le));
                    Sleep(250);
                    continue;
                }

                HANDLE h_cmd = CreateFileA(cmd_path.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
                if (h_cmd == INVALID_HANDLE_VALUE) {
                    const DWORD le = GetLastError();
                    pipetap::log::App.Errorf("CtrlClient::Loop: CreateFileA(commands) failed le=%lu", (unsigned long)le);
                    this->SetLastError(cur_pid, std::string("Open commands pipe failed: ") + FormatLeA(le));
                    CloseHandle(h_ev);
                    Sleep(250);
                    continue;
                }

                DWORD mode = PIPE_READMODE_BYTE;
                SetNamedPipeHandleState(h_ev, &mode, nullptr, nullptr);

                if (!run_.load(std::memory_order_acquire)) {
                    CloseHandle(h_ev);
                    CloseHandle(h_cmd);
                    break;
                }

                {
                    std::lock_guard<std::mutex> lk(wr_mtx_);
                    // Close any stale members first (defensive)
                    if (h_ev_ != INVALID_HANDLE_VALUE) CloseHandle(h_ev_);
                    if (h_cmd_ != INVALID_HANDLE_VALUE) CloseHandle(h_cmd_);
                    h_ev_ = h_ev;
                    h_cmd_ = h_cmd;
                    connected.store(true, std::memory_order_release);
                }

                this->ClearLastError();
                pipetap::log::App.Info((std::string("[control] connected to ") + ev_path + " / " + cmd_path).c_str());
                pipetap::log::App.Info("CtrlClient::Loop: connected");
            }

            HANDLE ev_snapshot = INVALID_HANDLE_VALUE;
            {
                std::lock_guard<std::mutex> lk(wr_mtx_);
                ev_snapshot = h_ev_;
            }
            if (ev_snapshot == INVALID_HANDLE_VALUE) {
                connected.store(false, std::memory_order_release);
                continue;
            }

            PT_TlvHeader hdr{};
            if (!::pipetap::PipeReadExact(ev_snapshot, &hdr, static_cast<DWORD>(sizeof(hdr)))) {
                const DWORD le = GetLastError();
                pipetap::log::App.Errorf("CtrlClient::Loop: header read failed -> disconnect le=%lu", (unsigned long)le);
                this->SetLastError(cur_pid, std::string("Read header failed: ") + FormatLeA(le));

                DisconnectHandles(false);
                continue;
            }

            if (hdr.length > (512u * 1024u * 1024u)) {
                pipetap::log::App.Errorf("CtrlClient::Loop: invalid length %u -> disconnect", (unsigned)hdr.length);
                this->SetLastError(cur_pid, "Invalid message length from events pipe");

                DisconnectHandles(false);
                continue;
            }

            std::vector<uint8_t> val(hdr.length);
            if (hdr.length && !::pipetap::PipeReadExact(ev_snapshot, val.data(), hdr.length)) {
                const DWORD le = GetLastError();
                pipetap::log::App.Errorf("CtrlClient::Loop: value read failed -> disconnect le=%lu", (unsigned long)le);
                this->SetLastError(cur_pid, std::string("Read value failed: ") + FormatLeA(le));

                DisconnectHandles(false);
                continue;
            }

            if (!run_.load(std::memory_order_acquire))
                break;

            CtrlMsgCallback local_cb;
            {
                std::lock_guard<std::mutex> lk(cb_mx_);
                local_cb = cb_;
            }
            if (local_cb) {
                local_cb(hdr, val);
            }
        }

        DisconnectHandles(false);

        pipetap::log::App.Info("CtrlClient::Loop: exit");
    }


    CtrlClient& Control() {
        static CtrlClient g_ctrlclient_singleton;
        return g_ctrlclient_singleton;
    }
} // namespace pipetap::ctrlclient
