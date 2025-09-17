#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "log.h"
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>
#include <Windows.h>


namespace pipetap::transport {

    class NamedPipeClient {
    public:
        enum class ReadMode { Byte, Message };

        struct ProbeResult {
            bool        success = false;
            DWORD       desired_access = 0;
            DWORD       qos_attrs = 0;
            bool        opened_read = false;
            bool        opened_write = false;
            bool        server_message_type = false;
            ReadMode    negotiated_mode = ReadMode::Byte;
            DWORD       out_buffer_size = 0;
            DWORD       in_buffer_size = 0;
            DWORD       recommended_write_chunk = 0;
            std::string notes;
        };

        NamedPipeClient() = default;
        ~NamedPipeClient() { Disconnect(); }

        void SetLogChannel(pipetap::log::Channel* ch) { log_ch_ = ch; }
        void SetLogChannelName(const std::string& name) { log_ch_ = &pipetap::log::channel(name); }

        uint32_t ServerPid() const { return server_pid_; }
        const std::string& ServerImage() const { return server_image_base_; }

        bool Connect(const char* pipe_path, DWORD wait_ms = 2000, ReadMode preferred = ReadMode::Message) {
            last_error_.clear();
            Disconnect();
            is_message_type_ = false;
            actual_mode_ = ReadMode::Byte;
            recommended_write_chunk_ = 0;
            server_pid_ = 0;
            server_image_base_.clear();

            if (!pipe_path || !*pipe_path) {
                last_error_ = "empty pipe path";
                LogError("connect: empty pipe path");
                return false;
            }

            {
                std::ostringstream oss;
                oss << "connect: waiting up to " << wait_ms << " ms for \"" << pipe_path << '"';
                LogInfo(oss.str());
            }

            if (!WaitNamedPipeA(pipe_path, wait_ms)) {
                DWORD err = GetLastError();
                std::ostringstream oss;
                oss << "WaitNamedPipe failed (" << err << "): " << HResultMessage(err);
                last_error_ = oss.str();
                LogError(last_error_);
                return false;
            }

            LogInfo("connect: opening handle...");
            HANDLE h = CreateFileA(
                pipe_path,
                GENERIC_READ | GENERIC_WRITE,
                0, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);

            if (h == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                std::ostringstream oss;
                oss << "CreateFile failed (" << err << "): " << HResultMessage(err);
                last_error_ = oss.str();
                LogError(last_error_);
                return false;
            }

            LogInfo("connect: querying pipe info...");
            DWORD flags = 0, outSize = 0, inSize = 0, inst = 0;
            if (!GetNamedPipeInfo(h, &flags, &outSize, &inSize, &inst)) {
                DWORD err = GetLastError();
                std::ostringstream oss;
                oss << "GetNamedPipeInfo failed (" << err << "): " << HResultMessage(err);
                last_error_ = oss.str();
                CloseHandle(h);
                LogError(last_error_);
                return false;
            }

            is_message_type_ = (flags & PIPE_TYPE_MESSAGE) != 0;
            LogInfo(is_message_type_ ? "server: message-type pipe" : "server: byte-type pipe");

            if (is_message_type_) {
                DWORD mode = (preferred == ReadMode::Message) ? PIPE_READMODE_MESSAGE : PIPE_READMODE_BYTE;
                {
                    std::ostringstream oss;
                    oss << "connect: requesting readmode=" << ((preferred == ReadMode::Message) ? "message" : "byte");
                    LogInfo(oss.str());
                }
                if (!SetNamedPipeHandleState(h, &mode, nullptr, nullptr)) {
                    DWORD err = GetLastError();
                    std::ostringstream oss;
                    oss << "SetNamedPipeHandleState(readmode) failed (" << err << "): " << HResultMessage(err);
                    last_error_ = oss.str();
                    LogWarn(last_error_);
                    actual_mode_ = ReadMode::Byte;
                }
                else {
                    actual_mode_ = (mode == PIPE_READMODE_MESSAGE) ? ReadMode::Message : ReadMode::Byte;
                }
            }
            else {
                actual_mode_ = ReadMode::Byte;
                if (preferred == ReadMode::Message) {
                    last_error_ = "server pipe is byte-type; message mode unsupported";
                    LogWarn(last_error_);
                }
            }

            hpipe_ = h;
            {
                std::ostringstream oss;
                oss << "connected: readmode=" << ((actual_mode_ == ReadMode::Message) ? "message" : "byte");
                LogInfo(oss.str());
            }
            recommended_write_chunk_ = (inSize != 0) ? inSize : 4096;

            PopulateServerPeerInfo_();

            return true;
        }

        bool ConnectSmart(const char* pipe_path, DWORD wait_ms = 2000, ReadMode preferred = ReadMode::Message, ProbeResult* out_probe = nullptr) {
            last_error_.clear();
            Disconnect();
            is_message_type_ = false;
            actual_mode_ = ReadMode::Byte;
            recommended_write_chunk_ = 0;
            server_pid_ = 0;
            server_image_base_.clear();

            if (!pipe_path || !*pipe_path) {
                last_error_ = "empty pipe path";
                LogError("connect-smart: empty pipe path");
                return false;
            }

            ProbeResult pr;
            bool ok = ProbeAndBind_(pipe_path, wait_ms, preferred, pr);
            if (out_probe) *out_probe = pr;
            if (!ok) return false;

            is_message_type_ = pr.server_message_type;
            actual_mode_ = pr.negotiated_mode;
            recommended_write_chunk_ = pr.recommended_write_chunk;

            {
                std::ostringstream oss;
                oss << "connected(smart): readmode=" << ((actual_mode_ == ReadMode::Message) ? "message" : "byte");
                LogInfo(oss.str());
            }

            PopulateServerPeerInfo_();

            return true;
        }

        void Disconnect() {
            if (hpipe_ != INVALID_HANDLE_VALUE) {
                CloseHandle(hpipe_);
                hpipe_ = INVALID_HANDLE_VALUE;
                LogInfo("disconnected");
            }
            last_error_.clear();
            is_message_type_ = false;
            actual_mode_ = ReadMode::Byte;
            recommended_write_chunk_ = 0;
            server_pid_ = 0;
            server_image_base_.clear();
        }

        bool IsConnected() const { return hpipe_ != INVALID_HANDLE_VALUE; }
        const std::string& LastError() const { return last_error_; }

        bool IsMessageTypeServer() const { return is_message_type_; }
        ReadMode Mode() const { return actual_mode_; }
        DWORD RecommendedWriteChunk() const { return recommended_write_chunk_; }

        bool SetReadMode(ReadMode mode) {
            if (!IsConnected()) { last_error_ = "not connected"; LogError(last_error_); return false; }
            if (!is_message_type_ && mode == ReadMode::Message) {
                last_error_ = "server pipe is byte-type; message mode unsupported";
                actual_mode_ = ReadMode::Byte;
                LogWarn(last_error_);
                return false;
            }

            DWORD raw = (mode == ReadMode::Message) ? PIPE_READMODE_MESSAGE : PIPE_READMODE_BYTE;
            {
                std::ostringstream oss;
                oss << "set-readmode: requesting " << ((mode == ReadMode::Message) ? "message" : "byte");
                LogInfo(oss.str());
            }
            if (!SetNamedPipeHandleState(hpipe_, &raw, nullptr, nullptr)) {
                DWORD err = GetLastError();
                std::ostringstream oss;
                oss << "SetNamedPipeHandleState(readmode) failed (" << err << "): " << HResultMessage(err);
                last_error_ = oss.str();
                LogError(last_error_);
                return false;
            }
            actual_mode_ = mode;
            LogInfo((mode == ReadMode::Message) ? "set-readmode: message" : "set-readmode: byte");
            return true;
        }

        bool WriteAll(const uint8_t* data, DWORD len, DWORD* written_out = nullptr) {
            if (!IsConnected()) { last_error_ = "not connected"; LogError(last_error_); return false; }
            {
                std::ostringstream oss; oss << "write: " << len << " bytes";
                LogInfo(oss.str());
            }

            DWORD total = 0;
            while (total < len) {
                DWORD w = 0;
                if (!WriteFile(hpipe_, data + total, len - total, &w, nullptr)) {
                    DWORD err = GetLastError();
                    std::ostringstream oss;
                    oss << "WriteFile failed (" << err << "): " << HResultMessage(err);
                    last_error_ = oss.str();
                    LogError(last_error_);
                    return false;
                }
                if (w == 0) break;
                total += w;
            }
            if (written_out) *written_out = total;
            {
                std::ostringstream oss; oss << "write: done (" << total << " bytes)";
                LogInfo(oss.str());
            }
            return true;
        }

        bool ReadSome(std::string& out, DWORD max_total = 1 << 20, DWORD window_ms = 200) {
            if (!IsConnected()) { last_error_ = "not connected"; LogError(last_error_); return false; }
            {
                std::ostringstream oss; oss << "readsome: window=" << window_ms << " ms, max=" << max_total;
                LogInfo(oss.str());
            }

            ULONGLONG start_tick = GetTickCount64();
            std::string acc;

            while (GetTickCount64() - start_tick < window_ms && acc.size() < max_total) {
                DWORD avail = 0;
                if (!PeekNamedPipe(hpipe_, nullptr, 0, nullptr, &avail, nullptr)) {
                    DWORD err = GetLastError();
                    std::ostringstream oss;
                    oss << "PeekNamedPipe failed (" << err << "): " << HResultMessage(err);
                    last_error_ = oss.str();
                    LogError(last_error_);
                    return false;
                }
                if (avail == 0) { Sleep(10); continue; }

                std::vector<char> buf(avail);
                DWORD r = 0;
                if (!ReadFile(hpipe_, buf.data(), (DWORD)buf.size(), &r, nullptr)) {
                    DWORD err = GetLastError();
                    if (err == ERROR_MORE_DATA) { acc.append(buf.data(), r); continue; }
                    std::ostringstream oss;
                    oss << "ReadFile failed (" << err << "): " << HResultMessage(err);
                    last_error_ = oss.str();
                    LogError(last_error_);
                    return false;
                }
                if (r > 0) acc.append(buf.data(), r);
            }

            {
                std::ostringstream oss; oss << "readsome: got " << acc.size() << " bytes";
                LogInfo(oss.str());
            }
            out.swap(acc);
            return true;
        }

        bool ReadMessage(std::string& out, DWORD max_total = 1 << 20, DWORD first_wait_ms = 200) {
            if (!IsConnected()) { last_error_ = "not connected"; LogError(last_error_); return false; }
            if (!is_message_type_) {
                LogWarn("readmessage: server is byte-type; falling back to readsome");
                return ReadSome(out, max_total, first_wait_ms);
            }

            {
                std::ostringstream oss; oss << "readmessage: waiting up to " << first_wait_ms << " ms";
                LogInfo(oss.str());
            }

            ULONGLONG start_tick = GetTickCount64();

            while (GetTickCount64() - start_tick < first_wait_ms) {
                DWORD avail = 0;
                if (!PeekNamedPipe(hpipe_, nullptr, 0, nullptr, &avail, nullptr)) {
                    DWORD err = GetLastError();
                    std::ostringstream oss;
                    oss << "PeekNamedPipe failed (" << err << "): " << HResultMessage(err);
                    last_error_ = oss.str();
                    LogError(last_error_);
                    return false;
                }
                if (avail > 0) break;
                Sleep(10);
            }

            DWORD avail_now = 0;
            if (!PeekNamedPipe(hpipe_, nullptr, 0, nullptr, &avail_now, nullptr)) {
                DWORD err = GetLastError();
                std::ostringstream oss;
                oss << "PeekNamedPipe failed (" << err << "): " << HResultMessage(err);
                last_error_ = oss.str();
                LogError(last_error_);
                return false;
            }
            if (avail_now == 0) { LogInfo("readmessage: no data available"); out.clear(); return true; }

            if (is_message_type_ && actual_mode_ != ReadMode::Message) {
                DWORD raw = PIPE_READMODE_MESSAGE;
                (void)SetNamedPipeHandleState(hpipe_, &raw, nullptr, nullptr);
                actual_mode_ = ReadMode::Message;
            }

            std::string acc;
            acc.reserve((avail_now < max_total) ? avail_now : max_total);

            for (;;) {
                if (acc.size() >= max_total) break;

                DWORD to_read = 4096;
                if (acc.size() + to_read > max_total) to_read = (DWORD)(max_total - acc.size());

                std::vector<char> buf(to_read);
                DWORD r = 0;
                if (!ReadFile(hpipe_, buf.data(), (DWORD)buf.size(), &r, nullptr)) {
                    DWORD err = GetLastError();
                    if (err == ERROR_MORE_DATA) { if (r > 0) acc.append(buf.data(), r); continue; }
                    std::ostringstream oss; oss << "ReadFile failed (" << err << "): " << HResultMessage(err);
                    last_error_ = oss.str();
                    LogError(last_error_);
                    return false;
                }

                if (r > 0) acc.append(buf.data(), r);
                break;
            }

            {
                std::ostringstream oss; oss << "readmessage: frame " << acc.size() << " bytes";
                LogInfo(oss.str());
            }
            out.swap(acc);
            return true;
        }

    private:
        void LogInfo(const std::string& m) { (log_ch_ ? *log_ch_ : pipetap::log::channel("replay/local")).Info(m); }
        void LogWarn(const std::string& m) { (log_ch_ ? *log_ch_ : pipetap::log::channel("replay/local")).Warn(m); }
        void LogError(const std::string& m) { (log_ch_ ? *log_ch_ : pipetap::log::channel("replay/local")).Error(m); }

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
                if (bytes > 0) {
                    s.resize(bytes);
                    WideCharToMultiByte(CP_UTF8, 0, wbuf, (int)len, s.data(), bytes, nullptr, nullptr);
                }
                LocalFree(wbuf);
                while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
            }
            return s;
        }

        struct OpenAttempt { DWORD desired_access; DWORD qos_attrs; const char* label; };
        static DWORD NowQosAttrsImpersonation() { return SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION; }
        static DWORD NowQosAttrsIdentification() { return SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION; }
        static DWORD NowQosAttrsAnonymous() { return SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS; }

        HANDLE TryOpenWithQoS_(const char* pipe_path, DWORD desired_access, DWORD qos_attrs, std::string& err_out) {
            DWORD flags = FILE_ATTRIBUTE_NORMAL | qos_attrs;
            HANDLE h = CreateFileA(pipe_path, desired_access, 0, nullptr, OPEN_EXISTING, flags, nullptr);
            if (h == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                std::ostringstream oss;
                oss << "CreateFile(" << std::hex << desired_access << ", qos=" << std::hex << qos_attrs
                    << ") failed (" << std::dec << err << "): " << HResultMessage(err);
                err_out = oss.str();
                return INVALID_HANDLE_VALUE;
            }
            err_out.clear();
            return h;
        }

        bool ProbeAndBind_(const char* pipe_path, DWORD wait_ms, ReadMode preferred, ProbeResult& pr) {
            {
                std::ostringstream oss;
                oss << "connect-smart: waiting up to " << wait_ms << " ms for \"" << pipe_path << '"';
                LogInfo(oss.str());
            }
            if (!WaitNamedPipeA(pipe_path, wait_ms)) {
                DWORD err = GetLastError();
                std::ostringstream oss; oss << "WaitNamedPipe failed (" << err << "): " << HResultMessage(err);
                last_error_ = oss.str();
                LogError(last_error_);
                return false;
            }

            std::vector<OpenAttempt> attempts = {
                { GENERIC_READ | GENERIC_WRITE, NowQosAttrsImpersonation(), "RW+impersonation" },
                { GENERIC_READ | GENERIC_WRITE, NowQosAttrsIdentification(),"RW+identification" },
                { GENERIC_READ | GENERIC_WRITE, NowQosAttrsAnonymous(),     "RW+anonymous" },
                { GENERIC_WRITE,               NowQosAttrsImpersonation(), "W+impersonation" },
                { GENERIC_WRITE,               NowQosAttrsIdentification(),"W+identification" },
                { GENERIC_READ,                NowQosAttrsImpersonation(), "R+impersonation" },
                { GENERIC_READ,                NowQosAttrsIdentification(), "R+identification" },
                { GENERIC_READ,                NowQosAttrsAnonymous(),      "R+anonymous" }
            };

            HANDLE h = INVALID_HANDLE_VALUE;
            std::string last_err;

            for (const auto& a : attempts) {
                {
                    std::ostringstream oss; oss << "connect-smart: opening (" << a.label << ")...";
                    LogInfo(oss.str());
                }
                h = TryOpenWithQoS_(pipe_path, a.desired_access, a.qos_attrs, last_err);
                if (h != INVALID_HANDLE_VALUE) {
                    pr.desired_access = a.desired_access;
                    pr.qos_attrs = a.qos_attrs;
                    pr.opened_read = ((a.desired_access & GENERIC_READ) != 0);
                    pr.opened_write = ((a.desired_access & GENERIC_WRITE) != 0);
                    break;
                }
                else {
                    LogWarn(last_err);
                }
            }

            if (h == INVALID_HANDLE_VALUE) {
                last_error_ = last_err.empty() ? "could not open pipe with any tested combination" : last_err;
                LogError(last_error_);
                return false;
            }

            DWORD flags = 0, outSize = 0, inSize = 0, inst = 0;
            if (!GetNamedPipeInfo(h, &flags, &outSize, &inSize, &inst)) {
                DWORD err = GetLastError();
                std::ostringstream oss; oss << "GetNamedPipeInfo failed (" << err << "): " << HResultMessage(err);
                last_error_ = oss.str();
                CloseHandle(h);
                LogError(last_error_);
                return false;
            }
            pr.server_message_type = (flags & PIPE_TYPE_MESSAGE) != 0;

            {
                std::ostringstream oss;
                oss << "server: " << (pr.server_message_type ? "message-type" : "byte-type")
                    << ", outBuf=" << outSize << ", inBuf=" << inSize;
                LogInfo(oss.str());
            }

            ReadMode negotiated = ReadMode::Byte;
            if (pr.server_message_type) {
                DWORD want = (preferred == ReadMode::Message) ? PIPE_READMODE_MESSAGE : PIPE_READMODE_BYTE;
                {
                    std::ostringstream oss;
                    oss << "connect-smart: requesting readmode=" << ((want == PIPE_READMODE_MESSAGE) ? "message" : "byte");
                    LogInfo(oss.str());
                }
                if (!SetNamedPipeHandleState(h, &want, nullptr, nullptr)) {
                    DWORD err = GetLastError();
                    std::ostringstream oss;
                    oss << "SetNamedPipeHandleState(readmode) failed (" << err << "): " << HResultMessage(err);
                    LogWarn(oss.str());
                    negotiated = ReadMode::Byte;
                }
                else {
                    negotiated = (want == PIPE_READMODE_MESSAGE) ? ReadMode::Message : ReadMode::Byte;
                }
            }
            else {
                negotiated = ReadMode::Byte;
                if (preferred == ReadMode::Message) {
                    LogWarn("server pipe is byte-type; message mode unsupported");
                }
            }
            pr.negotiated_mode = negotiated;

            DWORD rec = 0;
            if (inSize != 0) rec = inSize;
            else if (outSize != 0) rec = (outSize >= 4096) ? 4096 : outSize;
            else rec = 4096;
            pr.in_buffer_size = inSize;
            pr.out_buffer_size = outSize;
            pr.recommended_write_chunk = rec;

            {
                std::ostringstream oss;
                oss << "recommend: write_chunk<=" << pr.recommended_write_chunk
                    << (pr.server_message_type ? " (keeps messages atomic when possible)" : " (byte pipe)");
                LogInfo(oss.str());
            }

            hpipe_ = h;
            pr.success = true;
            pr.notes = "Connected via probe; adjusted readmode and recorded buffer sizes.";
            return true;
        }

        // NEW: query server pid + image basename (best effort)
        void PopulateServerPeerInfo_() {
            server_pid_ = 0;
            server_image_base_.clear();
            if (hpipe_ == INVALID_HANDLE_VALUE) return;

            ULONG pid = 0;
            if (GetNamedPipeServerProcessId(hpipe_, &pid)) {
                server_pid_ = static_cast<uint32_t>(pid);
                // Try to get image path
                HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)server_pid_);
                if (ph) {
                    wchar_t buf[MAX_PATH];
                    DWORD n = (DWORD)std::size(buf);
                    if (QueryFullProcessImageNameW(ph, 0, buf, &n)) {
                        // Extract basename
                        std::wstring ws(buf, n);
                        size_t pos = ws.find_last_of(L"\\/");
                        std::wstring base = (pos == std::wstring::npos) ? ws : ws.substr(pos + 1);
                        int bytes = WideCharToMultiByte(CP_UTF8, 0, base.c_str(), (int)base.size(), nullptr, 0, nullptr, nullptr);
                        if (bytes > 0) {
                            server_image_base_.resize(bytes);
                            WideCharToMultiByte(CP_UTF8, 0, base.c_str(), (int)base.size(), server_image_base_.data(), bytes, nullptr, nullptr);
                        }
                    }
                    CloseHandle(ph);
                }
            }
        }

    private:
        HANDLE       hpipe_ = INVALID_HANDLE_VALUE;
        std::string  last_error_;
        bool         is_message_type_ = false;
        ReadMode     actual_mode_ = ReadMode::Byte;
        DWORD        recommended_write_chunk_ = 0;

        // NEW: cached peer info
        uint32_t     server_pid_ = 0;
        std::string  server_image_base_;

        pipetap::log::Channel* log_ch_ = nullptr;
    };

} // namespace pipetap::transport
