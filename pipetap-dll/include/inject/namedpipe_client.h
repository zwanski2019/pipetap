#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <cstdint>
#include <memory>
#include <string>

namespace pipetap::inject {

    // A tiny facade that manages multiple remote pipe "sessions" (one reader thread per session)
    // and reports events back to ControlServer.
    class NamedPipeClient {
    public:
        static NamedPipeClient& instance();

        DWORD open_session(
            ControlServer& owner,
            uint64_t       session_id,
            const std::string& pipe_path,
            uint32_t       timeout_ms,
            bool           wait_for_server,
            bool           want_message_readmode,
            /*out*/ uint8_t& is_message_mode,
            /*out*/ uint32_t& out_hint,
            /*out*/ uint32_t& in_hint);

        DWORD send_to_session(
            ControlServer& owner,
            uint64_t       session_id,
            const uint8_t* data,
            uint32_t       size);

        void close_session(
            uint64_t       session_id,
            uint32_t       reason,   // 0=requested, 1=remote-broken, 2=error
            uint32_t       win32err);

        void close_all(
            uint32_t       reason,
            uint32_t       win32err);

    private:
        NamedPipeClient() = default;
        ~NamedPipeClient() = default;
        NamedPipeClient(const NamedPipeClient&) = delete;
        NamedPipeClient& operator=(const NamedPipeClient&) = delete;

        struct Session;
        Session* get(uint64_t sid);
        void add(std::unique_ptr<Session> s);
        std::unique_ptr<Session> take(uint64_t sid);

        SRWLOCK lock_ = SRWLOCK_INIT;
        struct MapImpl;
        std::unique_ptr<MapImpl> map_;
    };

} // namespace pipetap::inject
