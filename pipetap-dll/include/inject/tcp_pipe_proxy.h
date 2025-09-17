#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <atomic>
#include <cstdint>
#include <string>
#include <Windows.h>
#include <winsock2.h>

namespace pipetap::inject {

    class TcpPipeProxyService {
    public:
        static TcpPipeProxyService& instance();

        void start();
        void stop();

    private:
        TcpPipeProxyService() = default;
        ~TcpPipeProxyService() = default;
        TcpPipeProxyService(const TcpPipeProxyService&) = delete;
        TcpPipeProxyService& operator=(const TcpPipeProxyService&) = delete;

        // Context passed to the bridge threads.
        struct BridgeCtx {
            SOCKET s = INVALID_SOCKET;
            HANDLE hPipe = INVALID_HANDLE_VALUE;
            std::atomic<bool>* cancelFlag = nullptr;

            uint32_t in_hint = 0;       // server's inbound buffer size (client -> server)
            uint32_t out_hint = 0;      // server's outbound buffer size (server -> client)
            bool is_message_mode = false;
        };

        static DWORD WINAPI worker_thunk(LPVOID);
        static DWORD WINAPI sock_to_pipe_thunk(LPVOID);
        static DWORD WINAPI pipe_to_sock_thunk(LPVOID);

        void   worker_loop();
        SOCKET create_and_bind_ephemeral(uint16_t& outPort); // prefers 61337, then increments
        bool   recv_target_pipe_name(SOCKET s, std::string& outName);
        void   serve_single_client(SOCKET cli);
        void   bridge_socket_and_pipe(SOCKET s, HANDLE hPipe);

        std::atomic<bool> running_{ false };
        std::atomic<bool> wsa_init_{ false };
        HANDLE thread_ = nullptr;

        std::atomic<uint16_t> next_port_{ 61337 };

        SOCKET listen_ = INVALID_SOCKET;
        uint16_t listen_port_ = 0;
    };

} // namespace pipetap::inject
