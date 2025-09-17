#pragma once

#include "pipetap/controlpipe.h"
#include "session.h"
#include "ui/sharedui.h"
#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace pipetap::ctrlclient {

    using CtrlMsgCallback = std::function<void(const PT_TlvHeader&, const std::vector<uint8_t>&)>;

    class CtrlClient {
    public:
        CtrlClient() = default;
        ~CtrlClient() { Stop(); }

        CtrlClient(const CtrlClient&) = delete;
        CtrlClient& operator=(const CtrlClient&) = delete;
        CtrlClient(CtrlClient&&) = delete;
        CtrlClient& operator=(CtrlClient&&) = delete;

        void Start(CtrlMsgCallback cb);
        void Stop();

        void StartForPid(DWORD pid, CtrlMsgCallback cb);
        void Disconnect() { Stop(); }

        bool SendTLV(uint16_t type, const void* v1, uint32_t n1, const void* v2 = nullptr, uint32_t n2 = 0);

        std::atomic_bool connected{ false };

        DWORD BoundPid() const { return fixed_pid_; }

        std::string LastErrorForPid(DWORD pid) {
            std::lock_guard<std::mutex> lk(err_mtx_);
            return (last_error_pid_ == pid) ? last_error_msg_ : std::string();
        }
        void ClearLastError() {
            std::lock_guard<std::mutex> lk(err_mtx_);
            last_error_pid_ = 0;
            last_error_msg_.clear();
        }

    private:
        void Loop();
        static bool ReadExact(HANDLE h, void* buf, DWORD len);

        std::thread        reader_;
        std::atomic_bool   run_{ false };
        HANDLE             h_ev_{ INVALID_HANDLE_VALUE };
        HANDLE             h_cmd_{ INVALID_HANDLE_VALUE };
        std::mutex         wr_mtx_;

        std::atomic<DWORD> fixed_pid_{ 0 };

        std::mutex         err_mtx_;
        DWORD              last_error_pid_ = 0;
        std::string        last_error_msg_;

        std::mutex cb_mx_;
        CtrlMsgCallback cb_;

        void SetLastErrorUnlocked(DWORD pid, const std::string& msg) {
            last_error_pid_ = pid; last_error_msg_ = msg;
        }
        void SetLastError(DWORD pid, const std::string& msg) {
            std::lock_guard<std::mutex> lk(err_mtx_);
            SetLastErrorUnlocked(pid, msg);
        }
    };

    CtrlClient& Control();

} // namespace pipetap::ctrlclient
