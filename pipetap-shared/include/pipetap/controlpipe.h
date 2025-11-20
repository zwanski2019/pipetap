#pragma once

#include <cstdint>
#include <cstring>
#include <limits>
#include <string> 
#include <utility>
#include <type_traits>
#include <vector>

// -----------------------------------------------------------------------------
// Control pipe naming (two one-way pipes per target PID)
// -----------------------------------------------------------------------------
//
//   DLL -> GUI (events/telemetry):
//     \\.\pipe\pipetap.ctrl.ev.<pid>
//
//   GUI -> DLL (commands):
//     \\.\pipe\pipetap.ctrl.cmd.<pid>
//
// DLL is the server endpoint for both pipes.
// -----------------------------------------------------------------------------

static constexpr const char* PT_CTRL_EVENTS_PREFIX = R"(\\.\pipe\pipetap.ctrl.ev.)";
static constexpr const char* PT_CTRL_COMMANDS_PREFIX = R"(\\.\pipe\pipetap.ctrl.cmd.)";

// Build full pipe names for a given PID (header-only helpers).
inline std::string MakeEventsPipeForPid(uint32_t pid) {
    return std::string(PT_CTRL_EVENTS_PREFIX) + std::to_string(pid);
}
inline std::string MakeCommandsPipeForPid(uint32_t pid) {
    return std::string(PT_CTRL_COMMANDS_PREFIX) + std::to_string(pid);
}

// -----------------------------------------------------------------------------
// Control pipe message basics
// -----------------------------------------------------------------------------
#pragma pack(push, 1)

struct PT_ControlMessageHeader {
    uint16_t type;    // PT_* (see enums below)
    uint32_t length;  // length of VALUE (bytes that follow this header)
};

// -----------------------------------------------------------------------------
// Events DLL -> GUI
// -----------------------------------------------------------------------------
enum : uint16_t {
    // Handshake / meta
    PT_HELLO = 0x0001, // VALUE: PT_Hello

    // Observability (DLL -> GUI)
    PT_PIPE_WRITE = 0x0010, // VALUE: PT_PipeIo + payload bytes
    PT_PIPE_READ = 0x0011, // VALUE: PT_PipeIo + payload bytes
    PT_TNP_REQUEST = 0x0012, // VALUE: PT_PipeIo + payload bytes
    PT_TNP_RESPONSE = 0x0013, // VALUE: PT_PipeIo + payload bytes
    PT_PIPE_EVENT = 0x0014, // VALUE: PT_PipeIo (no payload bytes)

    // Error reporting (DLL -> GUI)
    PT_ERROR = 0x0100, // VALUE: PT_Error

    // Remote namedpipe proxy (DLL -> GUI)
    PT_EVT_PROXY_OPENED = 0x1211, // VALUE: PT_ProxyOpenResult
    PT_EVT_PROXY_CLOSED = 0x1212, // VALUE: PT_ProxyClosed
};

// -----------------------------------------------------------------------------
// Commands GUI -> DLL
// -----------------------------------------------------------------------------
enum : uint16_t {
    PT_CMD_SET_EDIT = 0x1000, // VALUE: PT_EditFlags
    PT_CMD_EDIT_REPLY = 0x1001, // VALUE: PT_EditReply + optional bytes

    // outbound named pipe proxy
    PT_CMD_PROXY_OPEN = 0x1201, // VALUE: PT_ProxyOpen + name bytes
    PT_CMD_PROXY_SEND = 0x1202, // VALUE: PT_ProxySend + data bytes
    PT_CMD_PROXY_CLOSE = 0x1203, // VALUE: PT_ProxyClose
    PT_CMD_CLIENT_DISCONNECT = 0x12F0, // VALUE: PT_ClientDisconnect (GUI closing)
};

// PT_HELLO
struct PT_Hello {
    uint32_t pid;
    char     proc_name[64];
};

// Common envelope for pipe IO messages
struct PT_PipeIo {
    uint32_t pid;
    uint32_t tid;
    uint8_t  dir;             // 0 = <- (read/response), 1 = -> (write/request)
    uint8_t  is_message_mode; // 1 if PIPE_TYPE_MESSAGE, else 0
    uint16_t reserved;

    uint32_t total_size;
    uint32_t sample_size;

    uint32_t out_buf_hint;
    uint32_t in_buf_hint;

    uint64_t op_id;           // unique operation id for edit coordination

    uint16_t pipe_len;        // number of bytes of UTF-8 pipe name immediately following this struct
    uint16_t api_len;         // number of bytes of UTF-8 API name immediately following pipe name

    // peer / endpoint info
    uint32_t peer_pid;         // the other side's PID if known (0 if unknown)
    uint8_t  endpoint_role;    // 0 = unknown, 1 = server-end handle, 2 = client-end handle
    uint8_t  flags;            // PT_PIO_FLAG_* bits
    uint16_t image_len;        // bytes of UTF-8 peer image basename immediately following API name
};

// PT_ERROR
struct PT_Error {
    uint32_t code;
    char     what[80];
};

// PT_CMD_SET_EDIT
struct PT_EditFlags {
    uint8_t  edit_request;  // 1 = block Write/Transact request and wait for reply
    uint8_t  edit_response; // 1 = block Read/TNP response and wait for reply
    uint16_t reserved;
};

// PT_CMD_EDIT_REPLY
struct PT_EditReply {
    uint64_t op_id;
    uint8_t  action;      // 0 = passthrough, 1 = replace
    uint8_t  reserved[7];
    uint32_t new_size;    // count of replacement bytes that follow
    // followed by new_size bytes
};

// -----------------------------------------------------------------------------
// === Outbound proxy payloads (GUI<->DLL) ===
// -----------------------------------------------------------------------------

// Request to open a pipe client from injected process.
// Control message value layout: [PT_ProxyOpen][pipe_name bytes (utf8, not 0-terminated)]
struct PT_ProxyOpen {
    uint64_t session_id;      // chosen by GUI (unique per session)
    uint32_t timeout_ms;      // WaitNamedPipe / connect timeout
    uint8_t  wait_for_server; // 0 = single attempt, 1 = WaitNamedPipe
    uint8_t  set_message_readmode; // 1 to set PIPE_READMODE_MESSAGE after connect if supported
    uint16_t name_len;        // number of bytes following with pipe name (UTF-8)
};

// Result of open (DLL -> GUI)
struct PT_ProxyOpenResult {
    uint64_t session_id;
    uint32_t win32_error;     // 0 == success
    uint8_t  is_message_mode; // 1 if message mode
    uint32_t out_buf_hint;    // from query_pipe_hints
    uint32_t in_buf_hint;     // from query_pipe_hints
};

// Send data to remote over the opened session (GUI -> DLL)
// Control message value layout: [PT_ProxySend][data bytes...]
struct PT_ProxySend {
    uint64_t session_id;
    uint32_t data_size; // number of bytes that follow in the control message body
};

// Close request (GUI -> DLL)
struct PT_ProxyClose {
    uint64_t session_id;
};

// GUI notifying DLL that the control client is intentionally dropping
struct PT_ClientDisconnect {
    uint32_t reason; // 0 = GUI exit
};

// Closed event (DLL -> GUI)
struct PT_ProxyClosed {
    uint64_t session_id;
    uint32_t reason;      // 0 = requested, 1 = remote closed, 2 = error
    uint32_t win32_error; // when reason==2
};


#pragma pack(pop)

// -------------------------------------------------------------------------
// Control frame helpers (header + payload container)
// -------------------------------------------------------------------------

static constexpr uint32_t PT_MAX_CONTROL_VALUE = 512u * 1024u * 1024u;

struct PT_ControlFrame {
    PT_ControlMessageHeader header{};
    std::vector<uint8_t> body;

    PT_ControlFrame() = default;
    explicit PT_ControlFrame(uint16_t type) { header.type = type; header.length = 0; }

    static PT_ControlFrame FromOwned(uint16_t type, std::vector<uint8_t> payload) {
        PT_ControlFrame f(type);
        f.body = std::move(payload);
        f.header.length = static_cast<uint32_t>(f.body.size());
        return f;
    }

    template <typename T>
    static PT_ControlFrame FromStruct(uint16_t type, const T& value) {
        PT_ControlFrame f(type);
        f.Append(value);
        return f;
    }

    bool IsTooLarge() const { return body.size() > PT_MAX_CONTROL_VALUE; }

    template <typename T>
    PT_ControlFrame& Append(const T& pod) {
        static_assert(std::is_trivially_copyable_v<T>, "PT_ControlFrame::Append requires trivially copyable type");
        return AppendBytes(&pod, sizeof(pod));
    }

    PT_ControlFrame& AppendBytes(const void* data, size_t len) {
        if (!data || len == 0) return *this;

        const size_t new_size = body.size() + len;
        if (new_size > static_cast<size_t>((std::numeric_limits<uint32_t>::max)())) return *this;
        if (new_size > PT_MAX_CONTROL_VALUE) return *this;

        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        body.insert(body.end(), bytes, bytes + len);
        header.length = static_cast<uint32_t>(body.size());
        return *this;
    }

    PT_ControlFrame& AppendVector(const std::vector<uint8_t>& data) {
        return AppendBytes(data.data(), data.size());
    }

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> out;
        out.resize(sizeof(header) + body.size());
        std::memcpy(out.data(), &header, sizeof(header));
        if (!body.empty()) {
            std::memcpy(out.data() + sizeof(header), body.data(), body.size());
        }
        return out;
    }

    struct Reader {
        const uint8_t* cur = nullptr;
        size_t remaining = 0;

        Reader() = default;
        Reader(const void* data, size_t len)
            : cur(static_cast<const uint8_t*>(data)), remaining(len) {}

        template <typename T>
        bool Next(T& out) {
            static_assert(std::is_trivially_copyable_v<T>, "PT_ControlFrame::Reader::Next requires trivially copyable type");
            if (remaining < sizeof(T) || !cur) return false;
            std::memcpy(&out, cur, sizeof(T));
            cur += sizeof(T);
            remaining -= sizeof(T);
            return true;
        }

        bool NextBytes(uint32_t len, const uint8_t*& view) {
            if (len == 0) { view = nullptr; return true; }
            if (!cur || remaining < len) return false;
            view = cur;
            cur += len;
            remaining -= len;
            return true;
        }

        size_t BytesRemaining() const { return remaining; }
    };

    Reader AsReader() const { return Reader(body.data(), body.size()); }

    template <typename T>
    bool TryAs(T& out) const {
        static_assert(std::is_trivially_copyable_v<T>, "PT_ControlFrame::TryAs requires trivially copyable type");
        if (body.size() < sizeof(T)) return false;
        std::memcpy(&out, body.data(), sizeof(T));
        return true;
    }
};

// ---- PipeIo parser helpers ----
static constexpr uint8_t PT_PIO_FLAG_HAS_PAYLOAD = 0x01;

struct PT_PipeIoView {
    // Names are not NUL-terminated; use len fields.
    const char* pipe_name = nullptr; uint16_t pipe_len = 0;
    const char* api_name = nullptr; uint16_t api_len = 0;
    const char* peer_image = nullptr; uint16_t image_len = 0;

    // Payload points to the sampled bytes that follow the metadata sections.
    const uint8_t* payload = nullptr; uint32_t payload_len = 0;
};

template <typename T> static inline T pt_min_(T a, T b) { return (a < b) ? a : b; }

struct PT_DecodedPipeIo {
    PT_PipeIo meta{};
    PT_PipeIoView view{};
    size_t meta_and_names_len = 0;    // bytes consumed by meta + variable names
    size_t payload_bytes_in_frame = 0;
    bool expect_payload = false;
    bool has_payload = false;
};

inline bool PT_DecodePipeIo(const void* value, size_t value_len, PT_DecodedPipeIo* out)
{
    if (!value || !out) return false;
    *out = PT_DecodedPipeIo{};

    if (value_len < sizeof(PT_PipeIo)) return false;

    const uint8_t* p = static_cast<const uint8_t*>(value);
    const uint8_t* end = p + value_len;

    PT_PipeIo meta{};
    std::memcpy(&meta, p, sizeof(meta));
    p += sizeof(meta);

    const size_t names_len = static_cast<size_t>(meta.pipe_len)
        + static_cast<size_t>(meta.api_len)
        + static_cast<size_t>(meta.image_len);
    if (static_cast<size_t>(end - p) < names_len) return false;

    PT_PipeIoView v{};

    if (meta.pipe_len) { v.pipe_name = reinterpret_cast<const char*>(p); v.pipe_len = meta.pipe_len; }
    p += meta.pipe_len;

    if (meta.api_len) { v.api_name = reinterpret_cast<const char*>(p); v.api_len = meta.api_len; }
    p += meta.api_len;

    if (meta.image_len) { v.peer_image = reinterpret_cast<const char*>(p); v.image_len = meta.image_len; }
    p += meta.image_len;

    const size_t remaining = static_cast<size_t>(end - p);
    const bool expect_payload = (meta.flags & PT_PIO_FLAG_HAS_PAYLOAD) != 0;

    if (remaining != static_cast<size_t>(meta.sample_size)) {
        return false; // frame malformed or truncated/overlong
    }

    v.payload = (remaining && p) ? p : nullptr;
    v.payload_len = static_cast<uint32_t>(remaining);

    out->meta = meta;
    out->view = v;
    out->meta_and_names_len = sizeof(PT_PipeIo) + names_len;
    out->payload_bytes_in_frame = remaining;
    out->expect_payload = expect_payload;
    out->has_payload = (v.payload && v.payload_len > 0);
    return true;
}

// Parse a PT_PipeIo control message VALUE buffer into meta + view. Returns true on success.
inline bool PT_TryParsePipeIo(const void* value, size_t value_len,
    PT_PipeIo* meta_out, PT_PipeIoView* view_out)
{
    if (!meta_out || !view_out) return false;
    PT_DecodedPipeIo dec{};
    if (!PT_DecodePipeIo(value, value_len, &dec)) return false;
    *meta_out = dec.meta;
    *view_out = dec.view;
    return true;
}

// Convenience overloads
inline bool PT_TryParsePipeIo(const std::vector<uint8_t>& val,
    PT_PipeIo* meta_out, PT_PipeIoView* view_out)
{
    return PT_TryParsePipeIo(val.data(), val.size(), meta_out, view_out);
}

struct PT_PipeIoEnvelope {
    PT_PipeIo meta{};
    std::string pipe_name;
    std::string api_name;
    std::string peer_image;
    const uint8_t* payload = nullptr;
    uint32_t payload_len = 0;
    uint32_t max_sample = 24u * 1024u;
};

inline PT_ControlFrame PT_BuildPipeIoMessage(uint16_t type, const PT_PipeIoEnvelope& env)
{
    PT_PipeIo meta = env.meta;
    meta.pipe_len = static_cast<uint16_t>(pt_min_<size_t>(env.pipe_name.size(), 0xFFFF));
    meta.api_len = static_cast<uint16_t>(pt_min_<size_t>(env.api_name.size(), 0xFFFF));
    meta.image_len = static_cast<uint16_t>(pt_min_<size_t>(env.peer_image.size(), 0xFFFF));

    const uint32_t sample = pt_min_(env.payload_len, env.max_sample);
    meta.sample_size = sample;
    if (sample > 0) meta.flags |= PT_PIO_FLAG_HAS_PAYLOAD;
    else            meta.flags &= ~PT_PIO_FLAG_HAS_PAYLOAD;

    PT_ControlFrame frame(type);
    frame.Append(meta);

    if (meta.pipe_len)  frame.AppendBytes(env.pipe_name.data(), meta.pipe_len);
    if (meta.api_len)   frame.AppendBytes(env.api_name.data(), meta.api_len);
    if (meta.image_len) frame.AppendBytes(env.peer_image.data(), meta.image_len);
    if (sample && env.payload) frame.AppendBytes(env.payload, sample);

    return frame;
}


static_assert(sizeof(PT_ControlMessageHeader) == 6, "PT_ControlMessageHeader must be 6 bytes");
static_assert(sizeof(PT_Hello) == 68, "PT_Hello must be 68 bytes");
static_assert(sizeof(PT_PipeIo) == 48, "PT_PipeIo must be 48 bytes");
static_assert(sizeof(PT_Error) == 84, "PT_Error must be 84 bytes");
static_assert(sizeof(PT_EditFlags) == 4, "PT_EditFlags must be 4 bytes");
static_assert(sizeof(PT_EditReply) == 20, "PT_EditReply must be 20 bytes");
static_assert(sizeof(PT_ProxyOpen) == 16, "PT_ProxyOpen must be 16 bytes");
static_assert(sizeof(PT_ProxyOpenResult) == 21, "PT_ProxyOpenResult must be 21 bytes");
static_assert(sizeof(PT_ProxySend) == 12, "PT_ProxySend must be 12 bytes");
static_assert(sizeof(PT_ProxyClose) == 8, "PT_ProxyClose must be 8 bytes");
static_assert(sizeof(PT_ProxyClosed) == 16, "PT_ProxyClosed must be 16 bytes");
