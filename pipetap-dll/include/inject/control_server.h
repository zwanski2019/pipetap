#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <atomic>
#include <string>
#include <unordered_map>
#include <vector>

namespace pipetap::inject {

    class ControlServer {
    public:
        static ControlServer& instance();

        void start();
        void stop();

        bool is_ctrl_handle(HANDLE h) const;

        bool is_connected() const { return connected_.load(std::memory_order_acquire); }

        void send_hello();
        void send_error(uint32_t code, const char* what);

        void send_pipe_io(uint16_t tlv_type, HANDLE pipe,
            const void* buf, uint32_t total,
            uint8_t dir, uint64_t op_id,
            const char* apiName);

        BOOL wait_for_edit_and_maybe_replace(uint64_t op_id,
            const void* /*orig*/, DWORD /*origSz*/,
            std::vector<uint8_t>& outBuf,
            BOOL* hasReplacement,
            DWORD timeoutMs = 15000);

        bool editing_requests_enabled()  const { return edit_req_.load(std::memory_order_relaxed) != 0; }
        bool editing_responses_enabled() const { return edit_resp_.load(std::memory_order_relaxed) != 0; }

        void send_proxy_opened(uint64_t session_id,
            uint32_t win32_error,
            uint8_t is_message_mode,
            uint32_t out_hint,
            uint32_t in_hint);
        void send_proxy_closed(uint64_t session_id,
            uint32_t reason,
            uint32_t win32_error);

    private:
        ControlServer() = default;
        ~ControlServer() = default;
        ControlServer(const ControlServer&) = delete;
        ControlServer& operator=(const ControlServer&) = delete;

        // Threads
        static DWORD WINAPI control_pipe_thread_thunk(LPVOID);
        void control_pipe_thread();

        void handle_inbound_tlv(HANDLE h);

        void send_tlv_streamed(uint16_t type,
            const void* meta, uint32_t meta_len,
            const void* payload, uint32_t payload_len);

        HANDLE create_events_pipe_instance();   // outbound only (we write)
        HANDLE create_commands_pipe_instance(); // inbound only (we read)

        struct PendingEdit {
            HANDLE evt;
            uint8_t action;
            std::vector<uint8_t> bytes;
            PendingEdit() : evt(CreateEventW(nullptr, TRUE, FALSE, nullptr)), action(0) {}
            ~PendingEdit() { if (evt) CloseHandle(evt); }
        };
        PendingEdit* create_pending(uint64_t op);
        PendingEdit* take_pending(uint64_t op);
        void complete_pending(uint64_t op, uint8_t action, const uint8_t* bytes, uint32_t n);

        std::atomic<bool> running_{ false };
        std::atomic<bool> ctrl_broken_{ false };

        HANDLE ctrl_r_{ INVALID_HANDLE_VALUE }; // commands.in (GUI->DLL)
        HANDLE ctrl_w_{ INVALID_HANDLE_VALUE }; // events.out (DLL->GUI)

        std::atomic<bool> connected_{ false };

        char pipe_ev_name_[128]{};
        char pipe_cmd_name_[128]{};

        SRWLOCK ctrl_lock_ = SRWLOCK_INIT;

        SRWLOCK edit_lock_ = SRWLOCK_INIT;
        std::unordered_map<uint64_t, PendingEdit*> pending_;

        std::atomic<uint8_t> edit_req_{ 0 };
        std::atomic<uint8_t> edit_resp_{ 0 };
    };

} // namespace pipetap::inject
