#define NOMINMAX

#include "bytes/format.h"
#include "ctrlclient.h"
#include "log.h"
#include "session.h"
#include "ui/clipboard.h"
#include "ui/hex_editor.h"
#include "ui/proxy.h"
#include "ui/sharedui.h"
#include "ui/widgets.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace pipetap::ui::proxy {

    static std::unordered_map<Tab*, std::string>              g_tabTitles;
    static std::unordered_map<Tab*, int>                      g_tabOrdinals;
    static std::unordered_map<Tab*, std::array<char, 128>>    g_tabEdit;

    static std::unordered_map<Tab*, bool>   g_connecting;
    static std::unordered_map<Tab*, double> g_connectStartedAt;

    static std::unordered_map<Tab*, bool> g_req_is_hex, g_resp_is_hex;
    static std::unordered_map<Tab*, bool> g_req_wide, g_resp_wide;
    static std::unordered_map<Tab*, bool> g_req_prev_hex, g_resp_prev_hex;

    static std::unordered_map<Tab*, MemoryEditor>          g_req_hex, g_resp_hex;
    static std::unordered_map<Tab*, std::vector<ImU8>>     g_req_hex_buf, g_resp_hex_buf;

    static int g_nextOrdinal = 1;

    static void RegisterTabIfNeeded(Tab* t) {
        if (!t) return;

        if (g_tabOrdinals.find(t) == g_tabOrdinals.end()) {
            int ord = g_nextOrdinal++;
            g_tabOrdinals[t] = ord;
            std::string def = std::string("#") + std::to_string(ord);
            g_tabTitles[t] = def;
            auto& buf = g_tabEdit[t];
            buf.fill(0);
            std::snprintf(buf.data(), buf.size(), "%s", def.c_str());
            g_connecting[t] = false;
            g_connectStartedAt[t] = 0.0;

            g_req_is_hex[t] = false;  g_resp_is_hex[t] = false;
            g_req_prev_hex[t] = false;  g_resp_prev_hex[t] = false;
            g_req_wide[t] = false;  g_resp_wide[t] = false;

            g_req_hex[t] = MemoryEditor(); g_resp_hex[t] = MemoryEditor();
            g_req_hex[t].ReadOnly = false; g_resp_hex[t].ReadOnly = false;
            g_req_hex[t].OptShowOptions = true; g_resp_hex[t].OptShowOptions = true;

            g_req_hex_buf[t] = {}; g_resp_hex_buf[t] = {};
        }
    }

    static void UnregisterTab(Tab* t) {
        if (!t) return;

        g_tabTitles.erase(t);
        g_tabOrdinals.erase(t);
        g_tabEdit.erase(t);
        g_connecting.erase(t);
        g_connectStartedAt.erase(t);

        g_req_is_hex.erase(t);  g_resp_is_hex.erase(t);
        g_req_prev_hex.erase(t); g_resp_prev_hex.erase(t);
        g_req_wide.erase(t);    g_resp_wide.erase(t);
        g_req_hex.erase(t);     g_resp_hex.erase(t);
        g_req_hex_buf.erase(t); g_resp_hex_buf.erase(t);
    }

    static void SendEditReply(ctrlclient::CtrlClient* client, uint64_t op_id, bool replace, const char* bytes, size_t len) {
        if (!client) return;
        PT_EditReply rep{};
        rep.op_id = op_id;
        rep.action = replace ? 1 : 0;
        rep.new_size = replace ? (uint32_t)len : 0;
        if (replace && bytes && len)
            client->SendTLV(PT_CMD_EDIT_REPLY, &rep, (uint32_t)sizeof(rep), bytes, (uint32_t)len);
        else
            client->SendTLV(PT_CMD_EDIT_REPLY, &rep, (uint32_t)sizeof(rep));
    }

    static std::unordered_map<Tab*, pipetap::sharedui::FilterCache> g_filterCache;

    struct IncomingBuffer {
        std::mutex mtx;
        std::vector<pipetap::sharedui::MsgLogEntry> items;
    };
    static std::unordered_map<Tab*, std::unique_ptr<IncomingBuffer>> g_incoming;

    static IncomingBuffer* EnsureIncoming(Tab* t) {
        auto it = g_incoming.find(t);
        if (it != g_incoming.end()) return it->second.get();

        auto up = std::make_unique<IncomingBuffer>();
        auto* raw = up.get();
        g_incoming[t] = std::move(up);
        return raw;
    }

    static void DrainIncomingToLog(Tab* t) {
        if (!t) return;

        auto* inc = EnsureIncoming(t);
        std::vector<pipetap::sharedui::MsgLogEntry> tmp;
        {
            std::lock_guard<std::mutex> lk(inc->mtx);
            if (inc->items.empty()) return;
            tmp.swap(inc->items); // move out quickly
        }
        {
            std::lock_guard<std::mutex> lk(t->s.log_mtx);
            if (!tmp.empty()) t->s.log.reserve(t->s.log.size() + tmp.size());
            for (auto& e : tmp) t->s.log.push_back(std::move(e));
        }
        g_filterCache[t].dirty = true;
    }

    static std::vector<uint8_t> BuildBytesForSend(const char* text_utf8, bool is_hex_mode, bool is_wide_utf16,
        const std::vector<ImU8>& hexbuf) {

        if (is_hex_mode) {
            std::vector<uint8_t> out;
            out.assign(hexbuf.begin(), hexbuf.end());
            return out;
        }

        if (is_wide_utf16) {
            std::vector<uint8_t> out;
            pipetap::bytes::Utf8ToUtf16LE(text_utf8, out);
            return out;
        }

        size_t n = std::strlen(text_utf8);

        return std::vector<uint8_t>((const uint8_t*)text_utf8, (const uint8_t*)text_utf8 + n);
    }

    static void DrawEditorOneSide(Tab& tab, bool is_request_side)
    {
        using namespace ImGui;

        const bool is_req = is_request_side;
        const char* title = is_req ? "Next Request" : "Next Response";

        uint64_t op_snapshot = 0;
        char buf_local[4096] = {};
        char orig_local[4096] = {};
        char pipe_local[128] = {};

        {
            std::lock_guard<std::mutex> lk(tab.s.edit_mtx);
            if (is_req) {
                op_snapshot = tab.s.pending_req_op;
                std::memcpy(buf_local, tab.s.req_buf, sizeof(buf_local));
                std::memcpy(orig_local, tab.s.req_original, sizeof(orig_local));
                std::memcpy(pipe_local, tab.s.req_pipe, sizeof(pipe_local));
            }
            else {
                op_snapshot = tab.s.pending_resp_op;
                std::memcpy(buf_local, tab.s.resp_buf, sizeof(buf_local));
                std::memcpy(orig_local, tab.s.resp_original, sizeof(orig_local));
                std::memcpy(pipe_local, tab.s.resp_pipe, sizeof(pipe_local));
            }
        }

        // Per-tab editor state
        bool& is_hex = is_req ? g_req_is_hex[&tab] : g_resp_is_hex[&tab];
        bool& was_hex = is_req ? g_req_prev_hex[&tab] : g_resp_prev_hex[&tab];
        bool& is_wide = is_req ? g_req_wide[&tab] : g_resp_wide[&tab];

        auto& hex_editor = is_req ? g_req_hex[&tab] : g_resp_hex[&tab];
        auto& hex_buf = is_req ? g_req_hex_buf[&tab] : g_resp_hex_buf[&tab];

        // If we just switched into Hex mode, seed the hex buffer from the current text + encoding.
        if (!was_hex && is_hex) {
            auto seeded = BuildBytesForSend(buf_local, /*is_hex*/false, is_wide, /*hexbuf*/{});
            hex_buf.assign(seeded.begin(), seeded.end());
            if (hex_buf.empty()) hex_buf.resize(1, 0); // MemoryEditor requires >=1 byte
        }
        was_hex = is_hex;

        AlignTextToFramePadding();
        TextUnformatted(title);
        if (op_snapshot != 0 && pipe_local[0] != '\0') {
            SameLine();
            TextDisabled("on: %s", pipe_local);
        }

        SameLine();
        TextDisabled("| Mode:");
        SameLine();
        {
            char id_mode[32];
            std::snprintf(id_mode, sizeof(id_mode), "%s_mode", is_req ? "req" : "resp");
            bool sel = is_hex;
            if (pipetap::sharedui::SegmentedToggle(id_mode, "Text", "Hex", sel)) is_hex = sel;
        }

        SameLine();
        BeginDisabled(is_hex);
        TextDisabled("| Encoding:");
        SameLine();
        {
            char id_enc[32];
            std::snprintf(id_enc, sizeof(id_enc), "%s_enc", is_req ? "req" : "resp");
            bool wide_sel = is_wide;
            if (pipetap::sharedui::SegmentedToggle(id_enc, "UTF-8", "UTF-16", wide_sel)) is_wide = wide_sel;
        }
        EndDisabled();

        {
            auto cur_bytes = BuildBytesForSend(buf_local, is_hex, is_wide, hex_buf);
            SameLine();
            TextDisabled("| %zu byte(s)", cur_bytes.size());
        }

        Separator();

        // Editor body
        BeginDisabled(op_snapshot == 0);

        const ImGuiStyle& style = GetStyle();
        const float footer_extra_pad = style.FramePadding.y;
        const float reserved_footer = GetFrameHeightWithSpacing() + footer_extra_pad;

        {
            ImVec2 avail = GetContentRegionAvail();
            ImVec2 editor_size(-FLT_MIN, std::max(0.0f, avail.y - reserved_footer));

            if (!is_hex) {
                if (InputTextMultiline(is_req ? "##req_edit" : "##resp_edit",
                    buf_local, IM_ARRAYSIZE(buf_local),
                    editor_size, ImGuiInputTextFlags_AllowTabInput))
                {
                    std::lock_guard<std::mutex> lk(tab.s.edit_mtx);
                    if (is_req)  std::memcpy(tab.s.req_buf, buf_local, sizeof(tab.s.req_buf));
                    else         std::memcpy(tab.s.resp_buf, buf_local, sizeof(tab.s.resp_buf));
                }
            }
            else {
                // Editable hex buffer; keep pointer stable with resize adapter
                hex_editor.UseDefaultResizeFor(hex_buf);
                hex_editor.OptAutoExtend = true;
                hex_editor.ReadOnly = false;

                BeginChild(is_req ? "##req_hex_child" : "##resp_hex_child",
                    editor_size,
                    false,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                void* memptr = hex_buf.empty() ? nullptr : (void*)hex_buf.data();
                size_t memsz = hex_buf.size();
                if (hex_buf.empty()) { hex_buf.resize(1, 0); memptr = hex_buf.data(); memsz = 1; }
                hex_editor.DrawContents(memptr, memsz, 0);
                EndChild();
            }
        }

        auto cur_bytes = BuildBytesForSend(buf_local, is_hex, is_wide, hex_buf);
        auto orig_bytes = BuildBytesForSend(orig_local, /*is_hex*/false, is_wide, /*hexbuf*/{});
        const bool modified = (op_snapshot != 0) && (cur_bytes != orig_bytes);

        {
            const ImGuiStyle& st = GetStyle();
            const float gap = st.ItemInnerSpacing.x;

            const char* L_replace_vis = "Replace & Continue";
            const char* L_reset_vis = "Reset";
            const char* L_pass_vis = "Passthrough";

            const char* L_replace_id = is_req ? "Replace & Continue##req" : "Replace & Continue##resp";
            const char* L_reset_id = is_req ? "Reset##req" : "Reset##resp";
            const char* L_pass_id = is_req ? "Passthrough##req" : "Passthrough##resp";

            auto btn_w = [&](const char* vis) {
                return CalcTextSize(vis).x + st.FramePadding.x * 2.0f;
                };

            float total_w = btn_w(L_replace_vis) + gap + btn_w(L_reset_vis) + gap + btn_w(L_pass_vis);

            SetCursorPosY(GetCursorPosY() + st.ItemInnerSpacing.y);

            float x = GetCursorPosX() + (GetContentRegionAvail().x - total_w);
            if (x < GetCursorPosX()) x = GetCursorPosX();
            SetCursorPosX(x);

            int pushed = 0;
            if (modified) {
                PushStyleColor(ImGuiCol_Button, ImVec4(0.20f, 0.60f, 0.25f, 1.0f)); ++pushed;
                PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.24f, 0.72f, 0.30f, 1.0f)); ++pushed;
                PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.18f, 0.52f, 0.22f, 1.0f)); ++pushed;
            }
            BeginDisabled(!modified);
            if (Button(L_replace_id)) {
                std::lock_guard<std::mutex> lk(tab.s.edit_mtx);
                if (is_req && tab.s.pending_req_op) {
                    auto out = BuildBytesForSend(tab.s.req_buf, is_hex, is_wide, hex_buf);
                    SendEditReply(tab.client.get(), tab.s.pending_req_op, true, (const char*)out.data(), out.size());
                    tab.s.pending_req_op = 0;
                    tab.s.req_buf[0] = tab.s.req_original[0] = tab.s.req_pipe[0] = '\0';
                    hex_buf.clear();
                }
                if (!is_req && tab.s.pending_resp_op) {
                    auto out = BuildBytesForSend(tab.s.resp_buf, is_hex, is_wide, hex_buf);
                    SendEditReply(tab.client.get(), tab.s.pending_resp_op, true, (const char*)out.data(), out.size());
                    tab.s.pending_resp_op = 0;
                    tab.s.resp_buf[0] = tab.s.resp_original[0] = tab.s.resp_pipe[0] = '\0';
                    hex_buf.clear();
                }
            }
            EndDisabled();
            if (pushed) PopStyleColor(pushed);

            SameLine(0.0f, gap);

            BeginDisabled(!op_snapshot || !modified);
            if (Button(L_reset_id)) {
                std::lock_guard<std::mutex> lk(tab.s.edit_mtx);
                if (!is_hex) {
                    if (is_req)  std::memcpy(tab.s.req_buf, tab.s.req_original, sizeof(tab.s.req_buf));
                    else         std::memcpy(tab.s.resp_buf, tab.s.resp_original, sizeof(tab.s.resp_buf));
                }
                else {
                    auto base = BuildBytesForSend(is_req ? tab.s.req_original : tab.s.resp_original,
                        /*is_hex*/false, is_wide, /*hexbuf*/{});
                    hex_buf.assign(base.begin(), base.end());
                    if (hex_buf.empty()) hex_buf.resize(1, 0);
                }
            }
            EndDisabled();

            SameLine(0.0f, gap);
            if (Button(L_pass_id)) {
                std::lock_guard<std::mutex> lk(tab.s.edit_mtx);
                if (is_req && tab.s.pending_req_op) {
                    SendEditReply(tab.client.get(), tab.s.pending_req_op, false, nullptr, 0);
                    tab.s.pending_req_op = 0;
                    tab.s.req_buf[0] = tab.s.req_original[0] = tab.s.req_pipe[0] = '\0';
                    hex_buf.clear();
                }
                if (!is_req && tab.s.pending_resp_op) {
                    SendEditReply(tab.client.get(), tab.s.pending_resp_op, false, nullptr, 0);
                    tab.s.pending_resp_op = 0;
                    tab.s.resp_buf[0] = tab.s.resp_original[0] = tab.s.resp_pipe[0] = '\0';
                    hex_buf.clear();
                }
            }
        }

        EndDisabled();
    }

    static void DrawSelection(Tab& tab)
    {
        using namespace ImGui;

        std::vector<uint8_t> raw_local;
        std::string fallback_printable;

        if (tab.s.selected_row >= 0) {
            std::lock_guard<std::mutex> lk(tab.s.log_mtx);
            if (tab.s.selected_row >= 0 && tab.s.selected_row < (int)tab.s.log.size()) {
                const auto& e = tab.s.log[(size_t)tab.s.selected_row];
                if (!e.raw.empty()) raw_local = e.raw;
                else {
                    fallback_printable = e.data;
                    raw_local.assign(fallback_printable.begin(), fallback_printable.end());
                }
            }
        }

        SeparatorText("Selection Data");

        pipetap::ui::DrawCopyPopupForBytes("copy_popup_selection", raw_local);
        SameLine(0.0f, GetStyle().ItemInnerSpacing.x);
        if (Button("Close##selection_close")) {
            std::lock_guard<std::mutex> lk(tab.s.log_mtx);
            tab.s.selected_row = -1;
            return;
        }

        BeginChild("##selection_hexascii", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
        if (!raw_local.empty()) {
            pipetap::sharedui::DrawHexAscii(raw_local);
        }
        else {
            TextDisabled("No data available for this entry.");
        }
        EndChild();
    }

    static void DrawTraffic(Tab& tab, Manager& mgr)
    {
        using namespace ImGui;

        DrainIncomingToLog(&tab);

        SeparatorText("Traffic Log");

        if (Button("Clear")) {
            std::lock_guard<std::mutex> lk(tab.s.log_mtx);
            tab.s.log.clear();
            tab.s.selected_row = -1;
            auto& fc = g_filterCache[&tab];
            fc.indices.clear();
            fc.last_log_size = 0;
            fc.dirty = true;
        }
        SameLine();

        Text("Direction:");
        SameLine();
        SetNextItemWidth(90.f);
        const char* dir_items[] = { "All", "Out (->)", "In (<-)" };
        if (Combo("##dir", &tab.filter_dir, dir_items, IM_ARRAYSIZE(dir_items))) {
            auto& fc = g_filterCache[&tab];
            fc.dir = tab.filter_dir;
            fc.dirty = true;
        }
        SameLine();

        SetNextItemWidth(260.f);
        bool needle_changed = InputTextWithHint("##flt", "filter", tab.filter_text, IM_ARRAYSIZE(tab.filter_text));
        if (needle_changed) {
            auto& fc = g_filterCache[&tab];
            fc.needle_lower = pipetap::sharedui::ToLowerStr(tab.filter_text);
            fc.dirty = true;
        }

        SameLine();
        if (Button("Save...")) {
            std::vector<pipetap::sharedui::MsgLogEntry> snapshot;
            {
                std::lock_guard<std::mutex> lk(tab.s.log_mtx);
                snapshot = tab.s.log;
            }

            const bool ok = pipetap::sharedui::ExportTrafficLogToJsonFile(snapshot);
            if (!ok) {
                pipetap::log::App.Warnf("Save cancelled or failed.");
            }
            else {
                pipetap::log::App.Infof("Traffic log exported.");
            }
        }

        std::vector<int>* index_map_ptr = nullptr;
        {
            auto& fc = g_filterCache[&tab];

            size_t cur_size = 0;
            {
                std::lock_guard<std::mutex> lk(tab.s.log_mtx);
                cur_size = tab.s.log.size();
            }

            {
                std::lock_guard<std::mutex> lk(tab.s.log_mtx);
                pipetap::sharedui::EnsureFilterUpToDate(tab.s.log, fc);
            }

            index_map_ptr = &fc.indices;
        }

        BeginChild("##proxy_log_child", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);

        pipetap::sharedui::SendToReplayFn cb = mgr.send_to_replay
            ? mgr.send_to_replay
            : [](const std::string&, const std::vector<uint8_t>&) {};

        int filtered_sel = -1;
        int selected_original_after = -1;

        pipetap::sharedui::MsgTableOpts opts;

        std::lock_guard<std::mutex> lk(tab.s.log_mtx);
        pipetap::sharedui::DrawMessageTableIndexed(
            tab.s.log,
            *index_map_ptr,
            filtered_sel,
            tab.s.selected_row,
            "proxy_table_indexed",
            cb,                 // SendToReplayFn
            opts,
            &selected_original_after
        );

        if (selected_original_after >= 0) {
            tab.s.selected_row = selected_original_after;
        }

        EndChild();
    }

    static void DrawOneTab(Tab& tab, bool is_active_tab, bool panel_focused, Manager& mgr)
    {
        using namespace ImGui;

        PushID(&tab);

        if (is_active_tab && panel_focused) {
            tab.has_unseen = false;

            if (IsKeyPressed(ImGuiKey_Escape)) {
                std::lock_guard<std::mutex> lk(tab.s.log_mtx);
                if (tab.s.selected_row >= 0)
                    tab.s.selected_row = -1;
            }
        }

        {
            SeparatorText("Target");
            SetNextItemWidth(80.0f);
            InputScalar("PID", ImGuiDataType_U32, &tab.pid);

            SameLine();
            bool is_connected = (tab.client && tab.client->connected.load());

            if (!is_connected) {
                if (Button("Connect")) {
                    if (!tab.client) tab.client = std::make_unique<ctrlclient::CtrlClient>();
                    tab.client->StartForPid(tab.pid, BindHandler(mgr));
                    g_connecting[&tab] = true;
                    g_connectStartedAt[&tab] = ImGui::GetTime();
                }
            }
            else {
                if (Button("Disconnect")) {
                    if (tab.client) {
                        tab.client->Stop();
                        tab.client->ClearLastError();
                    }
                    g_connecting[&tab] = false;
                }
            }

            SameLine();
            if (is_connected) {
                g_connecting[&tab] = false;
                TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), "[connected]");
            }
            else {
                std::string err = (tab.client ? tab.client->LastErrorForPid(tab.pid) : std::string());
                if (g_connecting[&tab] && err.empty()) {
                    float elapsed = (float)(ImGui::GetTime() - g_connectStartedAt[&tab]);
                    SetNextItemWidth(180.0f);
                    ProgressBar(-(float)ImGui::GetTime(), ImVec2(0, 0), "connecting...");
                    SameLine();
                    TextDisabled("(%.1fs)", elapsed);
                }
                else if (!err.empty()) {
                    g_connecting[&tab] = false;
                    TextColored(ImVec4(0.9f, 0.2f, 0.2f, 1.0f), "[error] %s", err.c_str());
                }
                else {
                    TextColored(ImVec4(0.9f, 0.2f, 0.2f, 1.0f), "[disconnected]");
                }
            }

            SameLine();
            bool prev_req = tab.edit_requests;
            bool prev_resp = tab.edit_responses;
            Checkbox("Edit requests", &tab.edit_requests);
            SameLine();
            Checkbox("Edit responses", &tab.edit_responses);

            if (prev_req && !tab.edit_requests) {
                std::lock_guard<std::mutex> lk(tab.s.edit_mtx);
                if (tab.s.pending_req_op) {
                    SendEditReply(tab.client.get(), tab.s.pending_req_op, false, nullptr, 0);
                    tab.s.pending_req_op = 0; tab.s.req_buf[0] = '\0'; tab.s.req_original[0] = '\0';
                }
            }
            if (prev_resp && !tab.edit_responses) {
                std::lock_guard<std::mutex> lk(tab.s.edit_mtx);
                if (tab.s.pending_resp_op) {
                    SendEditReply(tab.client.get(), tab.s.pending_resp_op, false, nullptr, 0);
                    tab.s.pending_resp_op = 0; tab.s.resp_buf[0] = '\0'; tab.s.resp_original[0] = '\0';
                }
            }
        }

        const bool editors_visible = (tab.edit_requests || tab.edit_responses);
        bool has_selection = false;
        {
            std::lock_guard<std::mutex> lk(tab.s.log_mtx);
            has_selection = (tab.s.selected_row >= 0 && tab.s.selected_row < (int)tab.s.log.size());
        }

        if (editors_visible) SeparatorText("Payload Editor");

        float avail_h = ImGui::GetContentRegionAvail().y;
        const float min_h = 120.0f;
        const float splitter_thickness = 6.0f;
        float needed_splitters = editors_visible ? 1.0f : 0.0f;
        if (has_selection) needed_splitters += 1.0f;
        float total_h = std::max(0.0f, avail_h - needed_splitters * splitter_thickness);

        if (!editors_visible) tab.edit_h = 0.0f;
        else                  tab.edit_h = std::clamp(tab.edit_h, min_h, std::max(min_h, total_h - 2.0f * min_h));

        float rest_h = total_h - tab.edit_h;

        if (has_selection) {
            tab.data_h = std::clamp(tab.data_h, min_h, std::max(min_h, rest_h - min_h));
        }
        else {
            tab.data_h = 0.0f;
        }
        float log_h = rest_h - tab.data_h;

        if (editors_visible) {
            ImGui::BeginChild("##proxy_editors", ImVec2(0, tab.edit_h), false,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

            const float editor_inner_w = ImGui::GetContentRegionAvail().x;
            const float hsplit_thick = 6.0f;
            const float min_side_w = 120.0f;

            ImGuiWindowFlags editor_flags =
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

            if (tab.edit_requests && tab.edit_responses) {
                float left_w = (editor_inner_w - hsplit_thick) * tab.edit_split_ratio;
                float right_w = editor_inner_w - hsplit_thick - left_w;

                if (left_w < min_side_w) left_w = min_side_w;
                if (right_w < min_side_w) right_w = min_side_w;
                if (left_w + hsplit_thick + right_w > editor_inner_w) {
                    if (left_w > right_w) left_w = editor_inner_w - hsplit_thick - right_w;
                    else                  right_w = editor_inner_w - hsplit_thick - left_w;
                    if (left_w < min_side_w) left_w = min_side_w;
                    if (right_w < min_side_w) right_w = min_side_w;
                }

                // Left editor
                ImGui::BeginChild("##edit_left", ImVec2(left_w, -1), true, editor_flags);
                DrawEditorOneSide(tab, /*is_request_side*/true);
                ImGui::EndChild();

                ImGui::SameLine(0.0f, 0.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
                ImGui::BeginChild("##edit_splitter", ImVec2(hsplit_thick, -1), false, editor_flags
                    | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoDecoration);
                HSplitterRatio("##hsplit", hsplit_thick, min_side_w, min_side_w, editor_inner_w, tab.edit_split_ratio);
                ImGui::EndChild();
                ImGui::PopStyleVar();

                // Right editor
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::BeginChild("##edit_right", ImVec2(right_w, -1), true, editor_flags);
                DrawEditorOneSide(tab, /*is_request_side*/false);
                ImGui::EndChild();
            }
            else {
                // Single editor: use the exact same inner width as the two-editor math
                ImGui::BeginChild("##edit_single", ImVec2(editor_inner_w, -1), true, editor_flags);
                DrawEditorOneSide(tab, /*is_request_side*/tab.edit_requests);
                ImGui::EndChild();
            }

            ImGui::EndChild();

            VSplitter("##split_edit_rest", splitter_thickness, min_h, min_h, tab.edit_h, rest_h);
            rest_h = std::max(min_h, rest_h);
            tab.edit_h = std::max(min_h, tab.edit_h);

            if (has_selection) {
                tab.data_h = std::clamp(tab.data_h, min_h, std::max(min_h, rest_h - min_h));
                log_h = rest_h - tab.data_h;
            }
            else {
                tab.data_h = 0.0f;
                log_h = rest_h;
            }
        }
        else {
            rest_h = total_h;
            if (has_selection) {
                tab.data_h = std::clamp(tab.data_h, min_h, std::max(min_h, rest_h - min_h));
                log_h = rest_h - tab.data_h;
            }
            else {
                tab.data_h = 0.0f;
                log_h = rest_h;
            }
        }

        if (has_selection) {
            ImGui::BeginChild("##proxy_selection", ImVec2(0, tab.data_h), false, ImGuiWindowFlags_HorizontalScrollbar);
            DrawSelection(tab);
            ImGui::EndChild();

            VSplitter("##split_data_log", splitter_thickness, min_h, min_h, tab.data_h, log_h);
            log_h = std::max(min_h, log_h);
            tab.data_h = std::max(min_h, tab.data_h);
        }

        ImGui::BeginChild("##proxy_log_holder", ImVec2(0, 0), false);
        DrawTraffic(tab, mgr);
        ImGui::EndChild();

        PopID();
    }

    void StartNewTabAndConnect(Manager& m, std::uint32_t pid)
    {
        auto tab = std::make_unique<Tab>();
        tab->pid = pid;
        RegisterTabIfNeeded(tab.get());

        tab->client = std::make_unique<ctrlclient::CtrlClient>();
        tab->client->StartForPid(tab->pid, BindHandler(m));

        g_connecting[tab.get()] = true;
        g_connectStartedAt[tab.get()] = ImGui::GetTime();

        m.tabs.push_back(std::move(tab));
        m.active = static_cast<int>(m.tabs.size()) - 1;
    }

    static Tab* FindTabByPid(Manager& m, std::uint32_t pid)
    {
        for (auto& up : m.tabs) {
            if (up && up->pid == pid) return up.get();
        }

        return nullptr;
    }

    void PumpAutoConnect(Manager& m)
    {
        DWORD last_injected = pipetap::session::Session().last_injected_pid.load();
        if (!last_injected) return;

        const bool want_auto = pipetap::session::Session().auto_connect_proxy.load();
        if (!want_auto) return;

        if (FindTabByPid(m, last_injected)) {
            pipetap::session::Session().last_injected_pid.store(0);
            return;
        }

        StartNewTabAndConnect(m, last_injected);

        pipetap::session::Session().last_injected_pid.store(0);
    }

    void Draw(Manager& m)
    {
        if (m.tabs.empty()) {
            m.tabs.push_back(std::make_unique<Tab>());
            RegisterTabIfNeeded(m.tabs.back().get());
            m.active = 0;
        }

        m.panel_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);

        if (ImGui::BeginTabBar("proxy_tabs",
            ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_TabListPopupButton)) {

            for (int i = 0; i < (int)m.tabs.size(); ) {
                Tab& t = *m.tabs[i];
                RegisterTabIfNeeded(&t);

                const std::string& visible = g_tabTitles[&t];

                char unique_id[64];
                std::snprintf(unique_id, sizeof(unique_id), "tab_%p", (void*)&t);

                char label[128];
                std::snprintf(label, sizeof(label), "%s##%s", visible.c_str(), unique_id);

                bool open = true;
                const bool allow_close = (m.tabs.size() > 1);

                int color_pushed = 0;
                if (t.has_unseen) {
                    ImGui::PushStyleColor(ImGuiCol_Tab, ImVec4(0.95f, 0.60f, 0.15f, 1.0f)); ++color_pushed;
                    ImGui::PushStyleColor(ImGuiCol_TabHovered, ImVec4(1.00f, 0.70f, 0.25f, 1.0f)); ++color_pushed;
                    ImGui::PushStyleColor(ImGuiCol_TabUnfocused, ImVec4(0.70f, 0.45f, 0.12f, 1.0f)); ++color_pushed;
                }

                bool began = false;
                if (allow_close) began = ImGui::BeginTabItem(label, &open);
                else             began = ImGui::BeginTabItem(label);

                if (color_pushed) ImGui::PopStyleColor(color_pushed);

                if (ImGui::BeginPopupContextItem()) {
                    auto& buf = g_tabEdit[&t];
                    ImGui::TextUnformatted("Rename Tab");
                    ImGui::Separator();
                    ImGui::InputText("Name", buf.data(), buf.size());
                    if (ImGui::Button("Apply")) {
                        std::string new_name = buf.data();
                        if (new_name.empty()) {
                            int ord = g_tabOrdinals[&t];
                            new_name = std::string("#") + std::to_string(ord);
                            std::snprintf(buf.data(), buf.size(), "%s", new_name.c_str());
                        }
                        g_tabTitles[&t] = new_name;
                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Reset")) {
                        int ord = g_tabOrdinals[&t];
                        std::string def = std::string("#") + std::to_string(ord);
                        g_tabTitles[&t] = def;
                        std::snprintf(buf.data(), buf.size(), "%s", def.c_str());
                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::EndPopup();
                }

                if (began) {
                    m.active = i;
                    DrawOneTab(t, /*is_active_tab*/true, m.panel_focused, m);
                    ImGui::EndTabItem();
                }

                if (allow_close && !open) {
                    if (t.client) t.client->Stop();
                    UnregisterTab(&t);
                    m.tabs.erase(m.tabs.begin() + i);
                    if (m.active >= (int)m.tabs.size()) m.active = (int)m.tabs.size() - 1;
                    continue;
                }
                ++i;
            }

            // trailing buttons
            if (ImGui::TabItemButton("+", ImGuiTabItemFlags_Trailing)) {
                m.tabs.push_back(std::make_unique<Tab>());
                RegisterTabIfNeeded(m.tabs.back().get());
                m.active = (int)m.tabs.size() - 1;
            }

            ImGui::EndTabBar();
        }
    }

    static void OnCtrlMsgWithManager(Manager& mgr, const PT_TlvHeader& hdr, const std::vector<uint8_t>& val)
    {
        if (hdr.type == PT_HELLO && val.size() >= sizeof(PT_Hello)) {
            PT_Hello hello{}; std::memcpy(&hello, val.data(), sizeof(hello));
            pipetap::log::App.Infof("Proxy: HELLO pid=%lu name='%.*s'", (unsigned long)hello.pid,
                (int)strnlen(hello.proc_name, sizeof(hello.proc_name)), hello.proc_name);

            Tab* target = nullptr;
            for (auto& up : mgr.tabs) { if (up->pid == hello.pid) { target = up.get(); break; } }
            if (!target) {
                auto t = std::make_unique<Tab>();
                t->pid = hello.pid;
                target = t.get();
                RegisterTabIfNeeded(target);
                mgr.tabs.push_back(std::move(t));
            }
            target->has_unseen = true;
            return;
        }

        if (hdr.type == PT_ERROR && val.size() >= sizeof(PT_Error)) {
            PT_Error e{}; std::memcpy(&e, val.data(), sizeof(e));
            size_t n = strnlen(e.what, sizeof(e.what));
            pipetap::log::App.Errorf("Proxy: ERROR code=%u what='%.*s'", (unsigned)e.code, (int)n, e.what);
            return;
        }

        // Accept both IO and EVENT TLVs here
        const bool is_pipeio_or_event =
            (hdr.type == PT_PIPE_WRITE || hdr.type == PT_PIPE_READ ||
                hdr.type == PT_TNP_REQUEST || hdr.type == PT_TNP_RESPONSE ||
                hdr.type == PT_PIPE_EVENT);

        if (is_pipeio_or_event) {
            PT_PipeIo meta{};
            PT_PipeIoView view{};
            if (!PT_TryParsePipeIo(val, &meta, &view)) {
                pipetap::log::App.Warnf("Proxy: malformed PT_PipeIo");
                return;
            }

            std::string pipe_name = (view.pipe_name && view.pipe_len)
                ? std::string(view.pipe_name, view.pipe_len) : std::string();
            std::string api_name = (view.api_name && view.api_len)
                ? std::string(view.api_name, view.api_len) : std::string();
            std::string peer_img = (view.peer_image && view.image_len)
                ? std::string(view.peer_image, view.image_len) : std::string();

            Tab* target = nullptr;
            for (auto& up : mgr.tabs) { if (up->pid == meta.pid) { target = up.get(); break; } }
            if (!target) {
                auto t = std::make_unique<Tab>();
                t->pid = meta.pid;
                target = t.get();
                RegisterTabIfNeeded(target);
                mgr.tabs.push_back(std::move(t));
            }

            std::string data_printable;
            if (hdr.type != PT_PIPE_EVENT && view.payload && view.payload_len) {
                data_printable = pipetap::sharedui::MakePrintablePreview(
                    reinterpret_cast<const uint8_t*>(view.payload),
                    static_cast<size_t>(view.payload_len));
            }

            pipetap::sharedui::Direction dir =
                (hdr.type == PT_PIPE_READ || hdr.type == PT_TNP_RESPONSE) ? pipetap::sharedui::Direction::In : pipetap::sharedui::Direction::Out;

            pipetap::sharedui::MsgLogEntry ent;
            ent.id = meta.op_id;
            ent.time = pipetap::sharedui::NowTimeString();
            ent.pipe = pipe_name;
            ent.winapi = api_name;
            ent.peer_pid = meta.peer_pid;
            ent.peer_image = peer_img;
            ent.dir = dir;
            ent.size = (hdr.type == PT_PIPE_EVENT) ? 0u : static_cast<size_t>(meta.total_size);
            ent.data = (hdr.type == PT_PIPE_EVENT) ? std::string() : data_printable;
            ent.snippet = pipetap::sharedui::MakeSnippet(ent.data);
            if (hdr.type != PT_PIPE_EVENT && view.payload && view.payload_len) {
                ent.raw.assign(view.payload, view.payload + view.payload_len);
            }
            ent.is_event = (hdr.type == PT_PIPE_EVENT);

            {
                auto* inc = EnsureIncoming(target);
                std::lock_guard<std::mutex> lk(inc->mtx);
                inc->items.push_back(std::move(ent));
            }

            const bool is_io_frame =
                (hdr.type == PT_PIPE_WRITE || hdr.type == PT_PIPE_READ ||
                    hdr.type == PT_TNP_REQUEST || hdr.type == PT_TNP_RESPONSE);

            if (is_io_frame) {
                const bool want_req = (hdr.type == PT_PIPE_WRITE || hdr.type == PT_TNP_REQUEST) && target->edit_requests;
                const bool want_resp = (hdr.type == PT_PIPE_READ || hdr.type == PT_TNP_RESPONSE) && target->edit_responses;

                if (want_req || want_resp) {
                    if (want_req) {
                        std::lock_guard<std::mutex> lk(target->s.edit_mtx);
                        if (target->s.pending_req_op == 0) {
                            size_t n = std::min<size_t>(data_printable.size(), sizeof(target->s.req_buf) - 1);
                            std::memcpy(target->s.req_buf, data_printable.data(), n);
                            target->s.req_buf[n] = '\0';
                            std::memcpy(target->s.req_original, target->s.req_buf, sizeof(target->s.req_original));
                            std::snprintf(target->s.req_pipe, sizeof(target->s.req_pipe), "%s", pipe_name.c_str());
                            target->s.pending_req_op = meta.op_id;
                        }
                        else {
                            SendEditReply(target->client.get(), meta.op_id, false, nullptr, 0);
                        }
                    }
                    else {
                        std::lock_guard<std::mutex> lk(target->s.edit_mtx);
                        if (target->s.pending_resp_op == 0) {
                            size_t n = std::min<size_t>(data_printable.size(), sizeof(target->s.resp_buf) - 1);
                            std::memcpy(target->s.resp_buf, data_printable.data(), n);
                            target->s.resp_buf[n] = '\0';
                            std::memcpy(target->s.resp_original, target->s.resp_buf, sizeof(target->s.resp_original));
                            std::snprintf(target->s.resp_pipe, sizeof(target->s.resp_pipe), "%s", pipe_name.c_str());
                            target->s.pending_resp_op = meta.op_id;
                        }
                        else {
                            SendEditReply(target->client.get(), meta.op_id, false, nullptr, 0);
                        }
                    }
                }
                else {
                    SendEditReply(target->client.get(), meta.op_id, false, nullptr, 0);
                }
            }

            const bool is_active_tab = (mgr.active >= 0 && mgr.active < (int)mgr.tabs.size() && mgr.tabs[mgr.active].get() == target);
            if (!(mgr.panel_focused && is_active_tab)) target->has_unseen = true;

#ifdef _DEBUG
            pipetap::log::App.Infof(
                "Proxy: %s type=0x%04x dir=%u pid=%lu tid=%lu total=%u sample=%u is_msg=%u op=%llu outHint=%u inHint=%u pipe='%s' api='%s' peer_pid=%u peer_img='%s'",
                ent.is_event ? "EVENT" : "PIPEIO",
                (unsigned)hdr.type, (unsigned)ent.dir,
                (unsigned long)meta.pid, (unsigned long)meta.tid,
                (unsigned)meta.total_size, (unsigned)meta.sample_size,
                (unsigned)meta.is_message_mode,
                (unsigned long long)meta.op_id,
                (unsigned)meta.out_buf_hint, (unsigned)meta.in_buf_hint,
                pipe_name.c_str(), api_name.c_str(),
                (unsigned)meta.peer_pid, peer_img.c_str());
#endif
            return;
        }

        // finally, log unrecognized TLVs
        pipetap::log::App.Info("[control] unrecognized TLV or short frame");
    }

    BoundCtrlHandler BindHandler(Manager& m) {
        return [&m](const PT_TlvHeader& hdr, const std::vector<uint8_t>& val) {
            OnCtrlMsgWithManager(m, hdr, val);
            };
    }

} // namespace pipetap::ui::proxy
