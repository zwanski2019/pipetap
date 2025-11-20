#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "log.h"
#include "pipetap/controlpipe.h"
#include "pipetap/winpipe_helpers.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <Windows.h>

namespace pipetap::transport {

    class RemoteNamedPipeClient {
    public:
        enum class ReadMode { Byte, Message };

        RemoteNamedPipeClient() = default;
        ~RemoteNamedPipeClient() { Disconnect(); }

        void SetLogChannel(pipetap::log::Channel* ch) { log_ch_ = ch; }
        void SetLogChannelName(const std::string& name) { log_ch_ = &pipetap::log::channel(name); }

        uint32_t ServerPid() const { return server_pid_.load(std::memory_order_acquire); }
        std::string ServerImage() const { std::lock_guard<std::mutex> lk(mx_); return server_image_; }

        bool ConnectSmart(uint32_t pid,
            const char* pipe_path,
            DWORD open_wait_ms = 2000,
            bool wait_for_server = true,
            bool set_message_readmode = true)
        {
            last_error_.clear();
            Disconnect();

            if (!pipe_path || !*pipe_path) {
                last_error_ = "remote connect: empty pipe path";
                LogError(last_error_);
                return false;
            }

            pid_ = pid;
            target_pipe_ = pipe_path;
            target_tail_ = CanonicalPipeTail_(target_pipe_);
            LogInfo(std::string("remote: filter=") + target_tail_);

            std::string ev_name = MakeEventsPipeForPid(pid_);
            std::string cmd_name = MakeCommandsPipeForPid(pid_);

            LogInfo("remote: connecting control pipes...");

            hEv_ = CreateFileA(ev_name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hEv_ == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                last_error_ = "open ev pipe failed (" + std::to_string(err) + "): " + HResultMessage(err);
                LogError(last_error_);
                CleanupHandles_();
                return false;
            }

            hCmd_ = CreateFileA(cmd_name.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hCmd_ == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                last_error_ = "open cmd pipe failed (" + std::to_string(err) + "): " + HResultMessage(err);
                LogError(last_error_);
                CleanupHandles_();
                return false;
            }

            stop_reader_.store(false, std::memory_order_release);
            reader_ = std::thread([this] { ReaderLoop_(); });

            session_id_ = NextSessionId_();
            PT_ProxyOpen op{};
            op.session_id = session_id_;
            op.timeout_ms = open_wait_ms;
            op.wait_for_server = wait_for_server ? 1 : 0;
            op.set_message_readmode = set_message_readmode ? 1 : 0;
            if (target_pipe_.size() > 0xFFFF) target_pipe_.resize(0xFFFF);
            op.name_len = static_cast<uint16_t>(target_pipe_.size());

            PT_ControlFrame open_frame(PT_CMD_PROXY_OPEN);
            open_frame.Append(op);
            if (!target_pipe_.empty()) {
                open_frame.AppendBytes(target_pipe_.data(), target_pipe_.size());
            }

            if (!SendControlFrame_(open_frame)) {
                Disconnect();
                return false;
            }

            bool need_disconnect = false;
            {
                std::unique_lock<std::mutex> lk(mx_);
                const DWORD wait_ms = open_wait_ms ? open_wait_ms : 2000;
                if (!cv_opened_.wait_for(lk, std::chrono::milliseconds(wait_ms),
                    [this] { return opened_result_ready_; })) {
                    last_error_ = "remote: open timed out waiting for PT_EVT_PROXY_OPENED";
                    LogError(last_error_);
                    need_disconnect = true;
                }
                else {
                    opened_result_ready_ = false;
                    if (opened_error_ != 0) {
                        std::ostringstream oss;
                        oss << "remote: DLL open failed (" << opened_error_
                            << "): " << HResultMessage(opened_error_);
                        last_error_ = oss.str();
                        LogError(last_error_);
                        need_disconnect = true;
                    }
                    else {
                        is_message_type_server_ = (opened_is_msg_ != 0);
                        actual_mode_ = is_message_type_server_ ? ReadMode::Message : ReadMode::Byte;
                        out_hint_ = opened_out_hint_;
                        in_hint_ = opened_in_hint_;
                    }
                }
                // lk released here
            }

            if (need_disconnect) {
                Disconnect();
                return false;
            }

            connected_.store(true, std::memory_order_release);

            LogInfo(is_message_type_server_ ? "server: message-type pipe" : "server: byte-type pipe");
            {
                std::ostringstream oss;
                oss << "connected(smart): readmode="
                    << ((actual_mode_ == ReadMode::Message) ? "message" : "byte");
                LogInfo(oss.str());
            }
            {
                DWORD rec = in_hint_ ? in_hint_ : 4096;
                std::ostringstream oss;
                oss << "recommend: write_chunk<=" << rec
                    << (is_message_type_server_ ? " (keeps messages atomic when possible)" : " (byte pipe)");
                LogInfo(oss.str());
            }

            LogInfo(std::string("remote: connected '") + target_pipe_ +
                "' msg=" + (is_message_type_server_ ? "yes" : "no"));
            return true;
        }


        void Disconnect() {
            if (session_id_ != 0 && hCmd_ && hCmd_ != INVALID_HANDLE_VALUE) {
                PT_ProxyClose c{ session_id_ };
                PT_ControlFrame close_frame = PT_ControlFrame::FromStruct(PT_CMD_PROXY_CLOSE, c);
                (void)SendControlFrame_(close_frame);
            }

            stop_reader_.store(true, std::memory_order_release);
            if (reader_.joinable()) {
                CleanupHandles_();
                reader_.join();
            }
            else {
                CleanupHandles_();
            }

            {
                std::lock_guard<std::mutex> lk(mx_);
                rxq_.clear();
                opened_result_ready_ = false;
                opened_error_ = 0;
                opened_is_msg_ = 0;
                opened_out_hint_ = opened_in_hint_ = 0;

                server_image_.clear();
            }
            server_pid_.store(0, std::memory_order_release);

            connected_.store(false, std::memory_order_release);
            session_id_ = 0;
            last_error_.clear();
            is_message_type_server_ = false;
            actual_mode_ = ReadMode::Byte;
            in_hint_ = out_hint_ = 0;
            target_tail_.clear();
        }

        bool IsConnected() const { return connected_.load(std::memory_order_acquire); }
        const std::string& LastError() const { return last_error_; }
        bool IsMessageTypeServer() const { return is_message_type_server_; }
        ReadMode Mode() const { return actual_mode_; }
        DWORD RecommendedWriteChunk() const { return in_hint_ ? in_hint_ : 4096; }
        bool SetReadMode(ReadMode) { return true; } // no-op remotely

        bool WriteAll(const uint8_t* data, DWORD len, DWORD* written_out = nullptr) {
            if (!IsConnected()) { last_error_ = "remote: not connected"; LogError(last_error_); return false; }
            if (!data || len == 0) { if (written_out) *written_out = 0; return true; }

            { std::ostringstream oss; oss << "write: " << len << " bytes"; LogInfo(oss.str()); }

            PT_ProxySend s{ session_id_, len };
            PT_ControlFrame send_frame(PT_CMD_PROXY_SEND);
            send_frame.Append(s);
            send_frame.AppendBytes(data, len);
            if (!SendControlFrame_(send_frame)) {
                return false;
            }

            if (written_out) *written_out = len;
            { std::ostringstream oss; oss << "write: done (" << len << " bytes)"; LogInfo(oss.str()); }
            return true;
        }

        bool ReadSome(std::string& out, DWORD max_total = 1 << 20, DWORD window_ms = 200) {
            if (!IsConnected()) { last_error_ = "remote: not connected"; LogError(last_error_); return false; }

            { std::ostringstream oss; oss << "readsome: window=" << window_ms << " ms, max=" << max_total; LogInfo(oss.str()); }

            bool ok = DequeueOne_(out, max_total, window_ms);
            if (!ok) { last_error_ = "remote: read failed"; LogError(last_error_); return false; }

            { std::ostringstream oss; oss << "readsome: got " << out.size() << " bytes"; LogInfo(oss.str()); }
            return true;
        }

        bool ReadMessage(std::string& out, DWORD max_total = 1 << 20, DWORD first_wait_ms = 200) {
            if (!IsConnected()) { last_error_ = "remote: not connected"; LogError(last_error_); return false; }

            if (!is_message_type_server_) {
                LogWarn("readmessage: server is byte-type; falling back to readsome");
                return ReadSome(out, max_total, first_wait_ms);
            }

            { std::ostringstream oss; oss << "readmessage: waiting up to " << first_wait_ms << " ms"; LogInfo(oss.str()); }

            bool ok = DequeueOne_(out, max_total, first_wait_ms);
            if (!ok) { last_error_ = "remote: read failed"; LogError(last_error_); return false; }

            if (out.empty()) { LogInfo("readmessage: no data available"); return true; }

            { std::ostringstream oss; oss << "readmessage: frame " << out.size() << " bytes"; LogInfo(oss.str()); }
            return true;
        }

    private:
        void LogInfo(const std::string& m) { (log_ch_ ? *log_ch_ : pipetap::log::channel("replay/remote")).Info(m); }
        void LogWarn(const std::string& m) { (log_ch_ ? *log_ch_ : pipetap::log::channel("replay/remote")).Warn(m); }
        void LogError(const std::string& m) { (log_ch_ ? *log_ch_ : pipetap::log::channel("replay/remote")).Error(m); }

        static std::string HResultMessage(DWORD err) {
            if (err == 0) return {};
            LPWSTR wbuf = nullptr;
            DWORD len = FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPWSTR)&wbuf, 0, nullptr);
            std::string s;
            if (len && wbuf) {
                int bytes = WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)len, nullptr, 0, nullptr, nullptr);
                if (bytes > 0) { s.resize(bytes); WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)len, s.data(), bytes, nullptr, nullptr); }
                LocalFree(wbuf);
                while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
            }
            return s;
        }

        static uint64_t NextSessionId_() {
            static std::atomic<uint64_t> g{ 1 };
            return g.fetch_add(1, std::memory_order_relaxed);
        }

        void CleanupHandles_() {
            if (hCmd_ && hCmd_ != INVALID_HANDLE_VALUE) { CloseHandle(hCmd_); hCmd_ = INVALID_HANDLE_VALUE; }
            if (hEv_ && hEv_ != INVALID_HANDLE_VALUE) { CloseHandle(hEv_);  hEv_ = INVALID_HANDLE_VALUE; }
        }

        static std::string CanonicalPipeTail_(std::string s) {
            for (auto& c : s) if (c == '/') c = '\\';

            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
            auto ltrim = [](std::string& x) { size_t i = 0; while (i < x.size() && std::isspace((unsigned char)x[i])) ++i; if (i) x.erase(0, i); };
            auto rtrim = [](std::string& x) { while (!x.empty() && std::isspace((unsigned char)x.back())) x.pop_back(); };
            ltrim(s); rtrim(s);

            if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) s = s.substr(1, s.size() - 2);
            while (!s.empty() && s[0] == '\\') s.erase(0, 1);

            if (s.size() >= 2 && s[0] == '.' && s[1] == '\\') s.erase(0, 2);

            auto starts = [&](const char* p) {
                size_t n = std::strlen(p);
                return s.size() >= n && std::equal(p, p + n, s.begin());
                };
            auto strip = [&](const char* p) { if (starts(p)) s.erase(0, std::strlen(p)); };

            strip("device\\namedpipe\\"); strip("globalroot\\device\\namedpipe\\");
            strip("??\\pipe\\"); strip("?\\pipe\\"); strip(".\\pipe\\"); strip("pipe\\");
            if (starts(".\\pipe\\")) s.erase(0, 7);
            return s;
        }

        bool SendControlFrame_(const PT_ControlFrame& frame) {
            if (!hCmd_ || hCmd_ == INVALID_HANDLE_VALUE) {
                last_error_ = "remote: cmd pipe not open";
                LogError(last_error_);
                return false;
            }
            DWORD wrote = 0;
            bool ok = ::pipetap::WriteControlFrame(hCmd_, frame, &wrote);
            if (!ok) {
                DWORD err = GetLastError();
                last_error_ = "remote: write cmd failed (" + std::to_string(err) + "): " + HResultMessage(err);
                LogError(last_error_);
                return false;
            }
            return true;
        }

        void ReaderLoop_() {
            auto maybe_update_peer = [this](const PT_PipeIo& meta, const PT_PipeIoView& view, const std::string& pipeName) {
                // Respect filter
                if (!target_tail_.empty()) {
                    std::string ev_tail = CanonicalPipeTail_(pipeName);
                    if (ev_tail != target_tail_) return;
                }
                if (meta.peer_pid != 0) {
                    server_pid_.store(meta.peer_pid, std::memory_order_release);
                }
                if (view.peer_image && view.image_len) {
                    std::lock_guard<std::mutex> lk(mx_);
                    server_image_.assign(view.peer_image, view.image_len);
                }
                };

            for (;;) {
                if (stop_reader_.load(std::memory_order_acquire)) break;
                if (!hEv_ || hEv_ == INVALID_HANDLE_VALUE) break;

                DWORD avail = 0, bytesLeft = 0;
                if (!PeekNamedPipe(hEv_, nullptr, 0, nullptr, &avail, &bytesLeft)) {
                    DWORD le = GetLastError();
                    NotifyClosed_((le == ERROR_BROKEN_PIPE) ? 1u : 2u, le);
                    break;
                }
                if (avail < sizeof(PT_ControlMessageHeader)) { Sleep(1); continue; }

                PT_ControlFrame frame;
                if (!::pipetap::ReadControlFrame(hEv_, frame)) break;

                switch (frame.header.type) {
                case PT_HELLO:
                    break;

                case PT_EVT_PROXY_OPENED: {
                    PT_ProxyOpenResult r{};
                    if (frame.TryAs(r) && r.session_id == session_id_) {
                        std::lock_guard<std::mutex> lk(mx_);
                        opened_error_ = r.win32_error;
                        opened_is_msg_ = r.is_message_mode;
                        opened_out_hint_ = r.out_buf_hint;
                        opened_in_hint_ = r.in_buf_hint;
                        opened_result_ready_ = true;
                        cv_opened_.notify_all();
                    }
                } break;

                case PT_EVT_PROXY_CLOSED: {
                    PT_ProxyClosed c{};
                    if (frame.TryAs(c) && c.session_id == session_id_) { NotifyClosed_(c.reason, c.win32_error); }
                } break;

                case PT_PIPE_EVENT:
                case PT_PIPE_READ:
                case PT_TNP_RESPONSE:
                case PT_PIPE_WRITE:
                case PT_TNP_REQUEST: {
                    PT_DecodedPipeIo decoded{};
                    if (!PT_DecodePipeIo(frame.body.data(), frame.body.size(), &decoded)) break;

                    const bool has_payload = (frame.header.type != PT_PIPE_EVENT)
                        && decoded.view.payload && decoded.view.payload_len > 0
                        && decoded.meta.sample_size > 0;

                    std::string pipeName = (decoded.view.pipe_name && decoded.view.pipe_len)
                        ? std::string(decoded.view.pipe_name, decoded.view.pipe_len)
                        : std::string();

                    maybe_update_peer(decoded.meta, decoded.view, pipeName);

                    const bool is_rx = (frame.header.type == PT_PIPE_READ || frame.header.type == PT_TNP_RESPONSE);
                    if (is_rx && has_payload) {
                        std::string payload(reinterpret_cast<const char*>(decoded.view.payload),
                            reinterpret_cast<const char*>(decoded.view.payload) + decoded.view.payload_len);
                        {
                            std::lock_guard<std::mutex> lk(mx_);
                            rxq_.push_back(std::move(payload));
                        }
                        cv_rx_.notify_all();
                    }
                } break;

                default: break;
                }
            }
        }

        void NotifyClosed_(uint32_t reason, uint32_t win32err) {
            {
                std::lock_guard<std::mutex> lk(mx_);
                rxq_.push_back(std::string());
            }
            cv_rx_.notify_all();
            connected_.store(false, std::memory_order_release);
            LogWarn("remote: proxy closed (reason=" + std::to_string(reason) + ", err=" + std::to_string(win32err) + ")");
        }

        bool DequeueOne_(std::string& out, DWORD max_total, DWORD wait_ms) {
            out.clear();
            std::unique_lock<std::mutex> lk(mx_);
            if (rxq_.empty()) {
                if (!cv_rx_.wait_for(lk, std::chrono::milliseconds(wait_ms), [this] { return !rxq_.empty(); })) {
                    return true;
                }
            }
            std::string front = std::move(rxq_.front());
            rxq_.pop_front();
            lk.unlock();

            if (front.empty()) return true;
            if (front.size() > max_total) front.resize(max_total);
            out.swap(front);
            return true;
        }

    private:
        HANDLE hEv_ = INVALID_HANDLE_VALUE;
        HANDLE hCmd_ = INVALID_HANDLE_VALUE;

        std::atomic<bool> connected_{ false };
        std::atomic<bool> stop_reader_{ false };
        std::thread reader_;

        uint32_t pid_ = 0;
        uint64_t session_id_ = 0;
        std::string target_pipe_;
        std::string target_tail_;

        mutable std::mutex mx_;
        std::condition_variable cv_opened_;
        bool     opened_result_ready_ = false;
        uint32_t opened_error_ = 0;
        uint8_t  opened_is_msg_ = 0;
        uint32_t opened_out_hint_ = 0;
        uint32_t opened_in_hint_ = 0;

        std::condition_variable cv_rx_;
        std::deque<std::string> rxq_;

        std::string last_error_;
        bool  is_message_type_server_ = false;
        ReadMode actual_mode_ = ReadMode::Byte;
        DWORD out_hint_ = 0;
        DWORD in_hint_ = 0;

        std::atomic<uint32_t> server_pid_{ 0 };
        std::string server_image_;

        pipetap::log::Channel* log_ch_ = nullptr;
    };

} // namespace pipetap::transport
