#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "imgui.h"
#include "log.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace pipetap::sharedui {

    void DrawHexAscii(const std::vector<uint8_t>& bytes);
    void DrawHexAscii(const void* data, size_t size);
    std::string MakePrintablePreview(const uint8_t* data, size_t len);

    inline std::string MakePrintablePreview(const std::vector<uint8_t>& v) {
        return MakePrintablePreview(v.data(), v.size());
    }
    inline std::string MakePrintablePreview(const std::string& s) {
        return MakePrintablePreview(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    void DrawControlBar();

    inline std::string NowTimeString() {
        std::time_t t = std::time(nullptr);
        std::tm tm{}; localtime_s(&tm, &t);
        char buf[32]; std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
        return buf;
    }

    inline std::string MakeSnippet(const std::string& s, size_t max_chars = 48) {
        std::string flat; flat.reserve(std::min(max_chars, s.size()));
        for (char c : s) {
            if (c == '\r' || c == '\n') c = ' ';
            flat.push_back(c);
            if (flat.size() == max_chars) break;
        }
        if (s.size() > max_chars) flat += "...";
        return flat;
    }

    void ColoredText(const ImVec4& col, const char* s);

    enum class Direction : uint8_t { Out, In };
    inline const char* DirToStr(Direction d) { return d == Direction::Out ? "->" : "<-"; }

    struct MsgLogEntry {
        uint64_t    id = 0;              // op_id from DLL
        std::string time;
        std::string pipe;
        std::string winapi;              // e.g. NtReadFile / NtWriteFile / ProxyRead / ProxyWrite

        uint32_t    peer_pid = 0;        // other side PID (0 if unknown)
        std::string peer_image;          // basename of peer image (may be empty)

        Direction   dir = Direction::Out;
        size_t      size = 0;            // total bytes reported in event (sample may be truncated)
        std::string data;                // printable version of sample (full sample if small)
        std::string snippet;             // a short preview for the table
        std::vector<uint8_t> raw;        // raw sample bytes (may be empty)
        bool        is_event = true;     // true=event with no data (e.g. connect, disconnect)
    };

    inline std::string AsciiPrintableOnly(const std::vector<uint8_t>& raw, const std::string& fallback) {
        std::string out;

        if (!raw.empty()) {
            out.resize(raw.size());
            for (size_t i = 0; i < raw.size(); ++i) {
                uint8_t b = raw[i];
                out[i] = (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
            }
        }
        else {
            out.resize(fallback.size());
            for (size_t i = 0; i < fallback.size(); ++i) {
                unsigned char c = static_cast<unsigned char>(fallback[i]);
                out[i] = (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
            }
        }

        return out;
    }

    using SendToReplayFn = std::function<void(const std::string& pipe, const std::vector<uint8_t>& raw)>;

    struct SegmentedToggleColors {
        ImVec4 active_btn = ImVec4(0.20f, 0.55f, 0.95f, 1.0f);
        ImVec4 active_btn_hover = ImVec4(0.26f, 0.62f, 1.00f, 1.0f);
        ImVec4 active_btn_active = ImVec4(0.18f, 0.50f, 0.90f, 1.0f);
        ImVec4 active_text = ImVec4(1.00f, 1.00f, 1.00f, 1.0f);

        ImVec4 inactive_btn = ImVec4(0.10f, 0.10f, 0.10f, 1.0f);
        ImVec4 inactive_btn_hover = ImVec4(0.14f, 0.14f, 0.14f, 1.0f);
        ImVec4 inactive_btn_active = ImVec4(0.12f, 0.12f, 0.12f, 1.0f);
        ImVec4 inactive_text = ImVec4(0.70f, 0.70f, 0.70f, 1.0f);
    };

    bool SegmentedToggle(const char* id,
        const char* left_label,
        const char* right_label,
        bool& is_right_selected,
        float gap_px = 6.0f,
        float rounding_px = 6.0f,
        const SegmentedToggleColors* colors = nullptr);

    struct FilterCache {
        int         dir = 0;                 // 0=All, 1=Out, 2=In
        std::string needle_lower;            // lowercased needle
        size_t      last_log_size = 0;       // size snapshot when indices built
        bool        dirty = true;            // rebuild request
        std::vector<int> indices;            // filtered row indices into source
    };

    std::string ToLowerStr(const char* s);
    bool icontains_noalloc(std::string_view hay, std::string_view needle_lower);

    void RebuildFilterIndices(const std::vector<MsgLogEntry>& src, FilterCache& c);
    void EnsureFilterUpToDate(const std::vector<MsgLogEntry>& src, FilterCache& c);

    struct MsgTableOpts {
        int   tooltip_max_bytes = 256;
        float tooltip_mono_cols = 43.0f;
        bool  show_context_send = true;
        const char* context_label = "Send to Replay";
    };

    int DrawMessageTableIndexed(const std::vector<MsgLogEntry>& src,
        const std::vector<int>& indices,
        int& filtered_sel,
        int  selected_row_original,
        const char* table_id,
        SendToReplayFn send_to_replay,
        const MsgTableOpts& opts,
        int* out_current_original);

    struct LogDrainState {
        std::vector<pipetap::log::Event> feed;
    };

    inline float LogDrainCompactHeight() { return ImGui::GetFrameHeight() + 6.0f; }
    inline float LogDrainFeedDefaultHeight() { return 140.0f; }

    void DrainLogChannelToState(LogDrainState& st,
        pipetap::log::Channel& ch,
        size_t cap = 2000);

    void DrawLogDrainCompact(const char* id,
        LogDrainState& st,
        pipetap::log::Channel& ch,
        size_t cap = 2000,
        float height = -1.0f,
        const char* heading = "Status");

    void DrawLogDrainFeed(const char* id,
        LogDrainState& st,
        pipetap::log::Channel& ch,
        size_t cap = 2000,
        float height = -1.0f,
        bool show_clear = true,
        bool auto_scroll = true,
        const char* heading = "Status");

    bool ExportTrafficLogToJsonFile(const std::vector<MsgLogEntry>& log);

} // namespace pipetap::shared
