#define WIN32_LEAN_AND_MEAN

#include "ctrlclient.h"
#include "session.h"
#include "ui/sharedui.h"
#include <cstdio>
#include <fstream>
#include <nlohmann/json.hpp>
#include <Shobjidl.h>
#include <string>
#include <vector>
#include <wincrypt.h>
#include <Windows.h>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Crypt32.lib")

using nlohmann::json;

namespace pipetap::sharedui {

    void DrawControlBar() {
        static char prev_pipe[128] = { 0 };

        ImGui::SeparatorText("Control Channel");
        ImGui::TextUnformatted("Control pipe:");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - 160.0f);

        bool changed = ImGui::InputText("##ctrlpipe", session::Session().ctrl_pipe, IM_ARRAYSIZE(session::Session().ctrl_pipe));
        if (changed && strcmp(prev_pipe, session::Session().ctrl_pipe) != 0) {
            strncpy_s(prev_pipe, session::Session().ctrl_pipe, _TRUNCATE);
        }

        ImGui::SameLine();
        bool up = ctrlclient::Control().connected.load();
        ImGui::TextColored(up ? ImVec4(0.2f, 0.8f, 0.2f, 1.f) : ImVec4(0.9f, 0.2f, 0.2f, 1.f),
            "%s", up ? "[connected]" : "[disconnected]");
    }

    void ColoredText(const ImVec4& col, const char* s) {
        ImGui::PushStyleColor(ImGuiCol_Text, col);
        ImGui::TextUnformatted(s);
        ImGui::PopStyleColor();
    }

    void DrawHexAscii(const void* data, size_t size) {
        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        const size_t n = size;

        for (size_t i = 0; i < n; i += 16) {
            char hexbuf[16 * 3 + 2 + 1] = { 0 };
            char asciibuf[16 + 1] = { 0 };

            int hpos = 0, apos = 0;
            for (size_t j = 0; j < 16; ++j) {
                size_t idx = i + j;
                if (idx < n) {
                    unsigned b = bytes[idx];
                    hpos += std::snprintf(hexbuf + hpos, (int)sizeof(hexbuf) - hpos, "%02X ", b);
                    asciibuf[apos++] = (b >= 32 && b < 127) ? (char)b : '.';
                }
                else {
                    hpos += std::snprintf(hexbuf + hpos, (int)sizeof(hexbuf) - hpos, "   ");
                    asciibuf[apos++] = ' ';
                }
                if (j == 7) { // extra gap in middle
                    if (hpos < (int)sizeof(hexbuf) - 1) hexbuf[hpos++] = ' ';
                }
            }
            asciibuf[apos] = '\0';
            ImGui::Text("%08llX  %s |%s|", (unsigned long long)i, hexbuf, asciibuf);
        }
    }

    void DrawHexAscii(const std::vector<uint8_t>& bytes) {
        DrawHexAscii(bytes.data(), bytes.size());
    }

    std::string MakePrintablePreview(const uint8_t* data, size_t len) {
        if (!data || len == 0) return {};
        std::string out;
        out.resize(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char b = data[i];
            out[i] = (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
        }
        return out;
    }

    static inline void PushSegmentStyle(bool active, const SegmentedToggleColors& c) {
        const ImVec4* btn = active ? &c.active_btn : &c.inactive_btn;
        const ImVec4* btn_hover = active ? &c.active_btn_hover : &c.inactive_btn_hover;
        const ImVec4* btn_active = active ? &c.active_btn_active : &c.inactive_btn_active;
        const ImVec4* text = active ? &c.active_text : &c.inactive_text;

        ImGui::PushStyleColor(ImGuiCol_Button, *btn);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, *btn_hover);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, *btn_active);
        ImGui::PushStyleColor(ImGuiCol_Text, *text);
    }
    static inline void PopSegmentStyle() { ImGui::PopStyleColor(4); }

    bool SegmentedToggle(const char* id,
        const char* left_label,
        const char* right_label,
        bool& is_right_selected,
        float gap_px,
        float rounding_px,
        const SegmentedToggleColors* colors)
    {
        using namespace ImGui;
        bool changed = false;

        SegmentedToggleColors local_colors;
        if (!colors) colors = &local_colors;

        PushID(id);
        const ImGuiStyle& st = GetStyle();
        PushStyleVar(ImGuiStyleVar_FrameRounding, rounding_px);
        PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(gap_px, st.ItemSpacing.y));

        BeginGroup();

        // Left segment (active when right is NOT selected)
        PushID(0);
        const bool left_active = !is_right_selected;
        PushSegmentStyle(left_active, *colors);
        if (Button(left_label)) {
            if (is_right_selected) { is_right_selected = false; changed = true; }
        }
        PopSegmentStyle();
        PopID();

        SameLine();

        // Right segment (active when right IS selected)
        PushID(1);
        const bool right_active = is_right_selected;
        PushSegmentStyle(right_active, *colors);
        if (Button(right_label)) {
            if (!is_right_selected) { is_right_selected = true; changed = true; }
        }
        PopSegmentStyle();
        PopID();

        EndGroup();

        PopStyleVar(2);
        PopID();
        return changed;
    }

    std::string ToLowerStr(const char* s) {
        if (!s) return {};
        std::string out; out.reserve(std::strlen(s));
        for (const unsigned char* p = (const unsigned char*)s; *p; ++p)
            out.push_back((char)std::tolower(*p));
        return out;
    }

    bool icontains_noalloc(std::string_view hay, std::string_view needle_lower) {
        if (needle_lower.empty()) return true;
        auto eq = [](char a, char b) {
            return (unsigned char)std::tolower(a) == (unsigned char)std::tolower(b);
            };
        return std::search(hay.begin(), hay.end(), needle_lower.begin(), needle_lower.end(), eq) != hay.end();
    }

    void RebuildFilterIndices(const std::vector<MsgLogEntry>& src, FilterCache& c)
    {
        c.indices.clear();
        c.indices.reserve(src.size());

        for (int i = 0; i < (int)src.size(); ++i) {
            const auto& e = src[(size_t)i];

            if (c.dir == 1 && e.dir != Direction::Out) continue;
            if (c.dir == 2 && e.dir != Direction::In)  continue;

            if (!c.needle_lower.empty()) {
                bool hit = icontains_noalloc(e.snippet, c.needle_lower)
                    || icontains_noalloc(e.pipe, c.needle_lower)
                    || icontains_noalloc(e.data, c.needle_lower)
                    || icontains_noalloc(e.winapi, c.needle_lower)
                    || icontains_noalloc(e.peer_image, c.needle_lower);
                if (!hit) {
                    std::string pid_txt = std::to_string(e.peer_pid);
                    if (!icontains_noalloc(pid_txt, c.needle_lower)) continue;
                }
            }

            c.indices.push_back(i);
        }

        c.last_log_size = src.size();
        c.dirty = false;
    }

    void EnsureFilterUpToDate(const std::vector<MsgLogEntry>& src, FilterCache& c) {
        if (c.dirty || c.last_log_size != src.size()) RebuildFilterIndices(src, c);
    }

    int DrawMessageTableIndexed(const std::vector<MsgLogEntry>& src,
        const std::vector<int>& indices,
        int& filtered_sel,
        int  selected_row_original,
        const char* table_id,
        SendToReplayFn send_to_replay,
        const MsgTableOpts& opts,
        int* out_current_original)
    {
        using namespace ImGui;
        int activated_original = -1;

        ImGuiTableFlags flags = ImGuiTableFlags_Resizable |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Borders |
            ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_Sortable;

        if (BeginTable(table_id, 9, flags, ImVec2(0, 0))) {
            TableSetupScrollFreeze(0, 1);
            TableSetupColumn("ID", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending, 40.f);
            TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 70.f);
            TableSetupColumn("Dir", ImGuiTableColumnFlags_WidthFixed, 28.f);
            TableSetupColumn("Pipe", ImGuiTableColumnFlags_WidthFixed, 180.f);
            TableSetupColumn("API", ImGuiTableColumnFlags_WidthFixed, 100.f);
            TableSetupColumn("Peer Image", ImGuiTableColumnFlags_WidthFixed, 200.f);
            TableSetupColumn("Peer PID", ImGuiTableColumnFlags_WidthFixed, 80.f);
            TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 60.f);
            TableSetupColumn("Data", ImGuiTableColumnFlags_WidthStretch, 0.f);
            TableHeadersRow();

            const ImGuiTableSortSpecs* sort_specs = TableGetSortSpecs();
            std::vector<int> view = indices;

            if (sort_specs && sort_specs->SpecsCount > 0) {
                auto cmp = [&](int li, int ri) {
                    const auto& a = src[(size_t)li];
                    const auto& b = src[(size_t)ri];

                    for (int s = 0; s < sort_specs->SpecsCount; ++s) {
                        const ImGuiTableColumnSortSpecs& spec = sort_specs->Specs[s];
                        int delta = 0;
                        switch (spec.ColumnIndex) {
                        case 0: if (a.id < b.id) delta = -1; else if (a.id > b.id) delta = +1; break;
                        case 1: delta = (a.time < b.time) ? -1 : (a.time > b.time) ? +1 : 0; break;
                        case 2: { int da = (a.dir == Direction::Out) ? 1 : 0; int db = (b.dir == Direction::Out) ? 1 : 0; delta = da - db; } break;
                        case 3: delta = a.pipe.compare(b.pipe); break;
                        case 4: delta = a.winapi.compare(b.winapi); break;
                        case 5: delta = a.peer_image.compare(b.peer_image); break;
                        case 6: if (a.peer_pid < b.peer_pid) delta = -1; else if (a.peer_pid > b.peer_pid) delta = +1; break;
                        case 7: if (a.size < b.size) delta = -1; else if (a.size > b.size) delta = +1; break;
                        case 8: delta = a.snippet.compare(b.snippet); break;
                        default: break;
                        }
                        if (delta != 0)
                            return (spec.SortDirection == ImGuiSortDirection_Ascending) ? (delta < 0) : (delta > 0);
                    }
                    return li < ri; // stable tiebreak
                    };
                std::sort(view.begin(), view.end(), cmp);
            }

            if (filtered_sel < 0 && selected_row_original >= 0) {
                for (int i = 0; i < (int)view.size(); ++i) {
                    if (view[i] == selected_row_original) { filtered_sel = i; break; }
                }
            }

            int scroll_to_row = -1;
            if (IsWindowFocused(ImGuiFocusedFlags_None) && !GetIO().WantTextInput) {
                const int max_idx = (int)view.size() - 1;
                if (IsKeyPressed(ImGuiKey_UpArrow, false)) {
                    if (filtered_sel < 0) filtered_sel = 0;
                    else if (filtered_sel > 0) filtered_sel--;
                    scroll_to_row = filtered_sel;
                }
                if (IsKeyPressed(ImGuiKey_DownArrow, false)) {
                    if (filtered_sel < 0) filtered_sel = 0;
                    else if (filtered_sel < max_idx) filtered_sel++;
                    scroll_to_row = filtered_sel;
                }
            }

            ImGuiListClipper clipper;
            clipper.Begin((int)view.size());
            while (clipper.Step()) {
                for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
                    const int original_idx = view[(size_t)r];
                    const auto& e = src[(size_t)original_idx];

                    TableNextRow();
                    const bool is_selected = (filtered_sel == r);

                    // Slightly grey-out event rows (no interception).
                    int pushed_vars = 0;
                    if (e.is_event) { PushStyleVar(ImGuiStyleVar_Alpha, GetStyle().Alpha * 0.60f); ++pushed_vars; }

                    PushID(original_idx);

                    TableSetColumnIndex(0);
                    ImGuiSelectableFlags row_flags =
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowDoubleClick;

                    if (Selectable("##row", is_selected, row_flags)) {
                        filtered_sel = r;
                        if (IsMouseDoubleClicked(0)) activated_original = original_idx;
                        scroll_to_row = filtered_sel;
                    }

                    if (scroll_to_row == r) SetScrollHereY(0.25f);

                    if (BeginPopupContextItem()) {
                        // For events we hide the "Send to Replay" action since there's no payload.
                        const bool can_send = (!e.is_event) && (!e.raw.empty() || !e.data.empty());
                        if (opts.show_context_send && send_to_replay && can_send &&
                            MenuItem(opts.context_label ? opts.context_label : "Send to Replay")) {
                            if (!e.raw.empty()) send_to_replay(e.pipe, e.raw);
                            else {
                                std::vector<uint8_t> tmp(e.data.begin(), e.data.end());
                                send_to_replay(e.pipe, tmp);
                            }
                        }
                        EndPopup();
                    }

                    SameLine(0.0f, 0.0f);
                    Text("%llu", (unsigned long long)e.id);

                    TableSetColumnIndex(1); TextUnformatted(e.time.c_str());

                    TableSetColumnIndex(2);
                    if (e.is_event) TextUnformatted("--");
                    else            TextUnformatted((e.dir == Direction::Out) ? "->" : "<-");

                    TableSetColumnIndex(3);
                    if (!e.pipe.empty()) {
                        TextUnformatted(e.pipe.c_str());
                        if (IsItemHovered(ImGuiHoveredFlags_DelayNormal))
                            SetTooltip("%s", e.pipe.c_str());
                    }

                    TableSetColumnIndex(4);
                    if (!e.winapi.empty()) {
                        TextUnformatted(e.winapi.c_str());
                    }

                    TableSetColumnIndex(5);
                    TextUnformatted(e.peer_image.empty() ? "<unknown>" : e.peer_image.c_str());

                    TableSetColumnIndex(6);
                    if (e.peer_pid) Text("%u", e.peer_pid);
                    else            TextUnformatted("-");

                    TableSetColumnIndex(7);
                    if (e.is_event) TextUnformatted("-");
                    else            Text("%zu", e.size);

                    TableSetColumnIndex(8);
                    if (!e.is_event) {
                        std::string ascii_only = AsciiPrintableOnly(e.raw, e.data);
                        TextUnformatted(ascii_only.c_str());

                        if (IsItemHovered(ImGuiHoveredFlags_DelayNone)) {
                            std::vector<uint8_t> preview;
                            preview.reserve((size_t)opts.tooltip_max_bytes);
                            if (!e.raw.empty()) {
                                size_t n = (std::min)((size_t)opts.tooltip_max_bytes, e.raw.size());
                                preview.assign(e.raw.begin(), e.raw.begin() + n);
                            }
                            else {
                                size_t n = (std::min)((size_t)opts.tooltip_max_bytes, e.data.size());
                                preview.assign(reinterpret_cast<const uint8_t*>(e.data.data()),
                                    reinterpret_cast<const uint8_t*>(e.data.data()) + n);
                            }

                            const int lines = (int)((preview.size() + 15) / 16);
                            const ImGuiStyle& style = GetStyle();
                            const float line_h = GetTextLineHeightWithSpacing();
                            float h = lines * line_h + style.FramePadding.y * 2.0f;
                            float w = GetFontSize() * opts.tooltip_mono_cols;

                            BeginTooltip();
                            BeginChild("##hex_preview",
                                ImVec2(w, h),
                                true,
                                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                            DrawHexAscii(preview);
                            EndChild();
                            EndTooltip();
                        }
                    }
                    else {
                        TextUnformatted("");
                    }

                    PopID();

                    if (pushed_vars) PopStyleVar(pushed_vars);
                }
            }

            EndTable();

            if (out_current_original) {
                if (filtered_sel >= 0 && filtered_sel < (int)view.size())
                    *out_current_original = view[filtered_sel];
                else
                    *out_current_original = -1;
            }
        }

        return activated_original;
    }

    static ImVec4 ColorForLogLevel(pipetap::log::Level lv) {
        switch (lv) {
        case pipetap::log::Level::Debug:   return ImVec4(0.80f, 0.80f, 0.80f, 1.0f);
        case pipetap::log::Level::Info:    return ImVec4(0.65f, 0.85f, 1.00f, 1.0f);
        case pipetap::log::Level::Warning: return ImVec4(1.00f, 0.85f, 0.35f, 1.0f);
        case pipetap::log::Level::Error:   return ImVec4(1.00f, 0.40f, 0.40f, 1.0f);
        default:                           return ImVec4(0.80f, 0.80f, 0.80f, 1.0f);
        }
    }

    void DrainLogChannelToState(LogDrainState& st,
        pipetap::log::Channel& ch,
        size_t cap)
    {
        std::vector<pipetap::log::Event> tmp;
        ch.Drain(tmp); // non-blocking; thread-safe
        if (!tmp.empty()) {
            if (st.feed.size() + tmp.size() > cap) {
                size_t over = st.feed.size() + tmp.size() - cap;
                if (over > st.feed.size()) over = st.feed.size();
                st.feed.erase(st.feed.begin(), st.feed.begin() + over);
            }
            st.feed.insert(st.feed.end(),
                std::make_move_iterator(tmp.begin()),
                std::make_move_iterator(tmp.end()));
        }
    }

    void DrawLogDrainCompact(const char* id,
        LogDrainState& st,
        pipetap::log::Channel& ch,
        size_t cap,
        float height,
        const char* heading)
    {
        using namespace ImGui;
        DrainLogChannelToState(st, ch, cap);

        if (height < 0.0f) height = LogDrainCompactHeight();
        BeginChild(id, ImVec2(0, height), false,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        AlignTextToFramePadding();
        const char* label = (heading && *heading) ? heading : "Status";
        TextUnformatted(label);
        SameLine();

        if (!st.feed.empty()) {
            const auto& ev = st.feed.back();
            SameLine();
            TextColored(ColorForLogLevel(ev.level), "|");
            SameLine();
            TextUnformatted(ev.text.c_str());
        }
        else {
            SameLine();
            TextDisabled("(idle)");
        }

        EndChild();
    }

    void DrawLogDrainFeed(const char* id,
        LogDrainState& st,
        pipetap::log::Channel& ch,
        size_t cap,
        float height,
        bool show_clear,
        bool auto_scroll,
        const char* heading)
    {
        using namespace ImGui;
        DrainLogChannelToState(st, ch, cap);

        if (height < 0.0f) height = LogDrainFeedDefaultHeight();
        BeginChild(id, ImVec2(0, height), false,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        AlignTextToFramePadding();
        const char* label = (heading && *heading) ? heading : "Status";
        TextUnformatted(label);

        if (show_clear) {
            float right = GetContentRegionAvail().x;
            float bw = CalcTextSize("Clear").x + GetStyle().FramePadding.x * 2.0f;
            SameLine(GetCursorPosX() + (right - bw));
            if (Button("Clear")) st.feed.clear();
        }

        BeginChild("##log_drain_feed", ImVec2(0, -2.0f), true,
            ImGuiWindowFlags_HorizontalScrollbar);

        ImGuiListClipper clipper;
        clipper.Begin((int)st.feed.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto& ev = st.feed[(size_t)i];

                PushStyleColor(ImGuiCol_Text, ColorForLogLevel(ev.level));
                TextUnformatted("|");
                PopStyleColor();
                SameLine();

                int secs = (int)ev.t;
                int mm = (secs / 60) % 60;
                int hh = (secs / 3600);
                int ss = secs % 60;
                char ts[32];
                if (hh > 0) std::snprintf(ts, sizeof(ts), "%02d:%02d:%02d", hh, mm, ss);
                else        std::snprintf(ts, sizeof(ts), "%02d:%02d", mm, ss);

                TextDisabled("[%s]", ts);
                SameLine();
                TextWrapped("%s", ev.text.c_str());
            }
        }

        if (auto_scroll) {
            float max_y = GetScrollMaxY();
            if (max_y > 0.0f) {
                float cur = GetScrollY();
                if (max_y - cur < 8.0f) SetScrollHereY(1.0f);
            }
        }

        EndChild(); // ##log_drain_feed
        EndChild(); // id
    }

    static std::string Base64EncodeNoCrlf(const void* data, size_t size) {
        if (!data || size == 0) return {};
        DWORD out_chars = 0;
        if (!CryptBinaryToStringW(reinterpret_cast<const BYTE*>(data),
            static_cast<DWORD>(size),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr, &out_chars)) {
            return {};
        }
        std::wstring wbuf(out_chars, L'\0');
        if (!CryptBinaryToStringW(reinterpret_cast<const BYTE*>(data),
            static_cast<DWORD>(size),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            wbuf.data(), &out_chars)) {
            return {};
        }
        if (!wbuf.empty() && wbuf.back() == L'\0') wbuf.pop_back();

        int need = WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(),
            static_cast<int>(wbuf.size()),
            nullptr, 0, nullptr, nullptr);
        if (need <= 0) return {};
        std::string utf8(need, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(),
            static_cast<int>(wbuf.size()),
            utf8.data(), need, nullptr, nullptr);
        return utf8;
    }

    static std::string PromptSaveJsonPath() {
        std::string result;

        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        const bool did_init = SUCCEEDED(hr);

        IFileSaveDialog* dlg = nullptr;
        hr = CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&dlg));
        if (SUCCEEDED(hr) && dlg) {
            COMDLG_FILTERSPEC spec[] = {
                { L"JSON Files (*.json)", L"*.json" },
                { L"All Files (*.*)",     L"*.*" }
            };
            dlg->SetFileTypes(_countof(spec), spec);
            dlg->SetDefaultExtension(L"json");
            dlg->SetFileName(L"traffic-log.json");

            if (SUCCEEDED(dlg->Show(nullptr))) {
                IShellItem* item = nullptr;
                if (SUCCEEDED(dlg->GetResult(&item)) && item) {
                    PWSTR w = nullptr;
                    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &w)) && w) {
                        int need = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
                        if (need > 0) {
                            std::string path(need - 1, '\0');
                            WideCharToMultiByte(CP_UTF8, 0, w, -1, path.data(), need - 1, nullptr, nullptr);
                            result = std::move(path);
                        }
                        CoTaskMemFree(w);
                    }
                    item->Release();
                }
            }
            dlg->Release();
        }

        if (did_init) CoUninitialize();
        return result;
    }

    static std::string BuildTrafficJsonAll(const std::vector<MsgLogEntry>& src) {
        json arr = json::array();

        for (const auto& e : src) {
            // Prefer raw bytes; fall back to printable text bytes if needed
            const uint8_t* data_ptr = nullptr;
            size_t data_sz = 0;
            std::vector<uint8_t> fallback;

            if (!e.raw.empty()) {
                data_ptr = e.raw.data();
                data_sz = e.raw.size();
            }
            else if (!e.data.empty()) {
                fallback.assign(e.data.begin(), e.data.end());
                data_ptr = fallback.data();
                data_sz = fallback.size();
            }

            std::string b64 = Base64EncodeNoCrlf(data_ptr, data_sz);

            json obj{
                { "id",          e.id },
                { "time",        e.time },
                { "direction",   (e.dir == Direction::Out ? "out" : "in") },
                { "pipe",        e.pipe },
                { "api",         e.winapi },
                { "peer_pid",    e.peer_pid },
                { "peer_image",  e.peer_image },
                { "size",        e.size },
                { "payload_b64", b64 }
            };
            arr.push_back(std::move(obj));
        }

        return arr.dump(2);
    }

    bool ExportTrafficLogToJsonFile(const std::vector<MsgLogEntry>& log) {
        const std::string json_text = BuildTrafficJsonAll(log);

        const std::string path = PromptSaveJsonPath();
        if (path.empty()) return false; // cancelled

        std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
        if (!ofs) return false;
        ofs.write(json_text.data(), static_cast<std::streamsize>(json_text.size()));
        return ofs.good();
    }

} // namespace pipetap::sharedui
