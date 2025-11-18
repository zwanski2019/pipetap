#define NOMINMAX

#include "bytes/format.h"
#include "log.h"
#include "transport/namedpipe_client.h"
#include "ui/clipboard.h"
#include "ui/hex_editor.h"
#include "ui/replay.h"
#include "ui/sharedui.h"
#include "ui/widgets.h"
#include <algorithm>
#include <array>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <imgui.h>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <stringapiset.h>
#include <thread>
#include <unordered_map>
#include <vector>
#include <windows.h>


namespace pipetap::ui::replay {

    using pipetap::bytes::Utf16LEToUtf8;
    using pipetap::bytes::Utf8ToUtf16LE;

    // Normalize arbitrary user input to a canonical named-pipe path: "\\\\.\\pipe\\name"
    static std::string NormalizePipePath(const std::string& user_input) {
        auto s = user_input;

        auto ltrim = [](std::string& x) {
            size_t i = 0; while (i < x.size() && (x[i] == ' ' || x[i] == '\t' || x[i] == '\r' || x[i] == '\n')) ++i;
            if (i) x.erase(0, i);
            };
        auto rtrim = [](std::string& x) {
            while (!x.empty() && (x.back() == ' ' || x.back() == '\t' || x.back() == '\r' || x.back() == '\n')) x.pop_back();
            };
        ltrim(s); rtrim(s);
        if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
            s = s.substr(1, s.size() - 2);
        }

        for (char& c : s) if (c == '/') c = '\\';

        auto starts_with_ci = [](const std::string& a, const char* pfx) {
            size_t n = std::strlen(pfx);
            if (a.size() < n) return false;
            for (size_t i = 0; i < n; ++i) {
                char ac = a[i], bc = pfx[i];
                if (ac >= 'A' && ac <= 'Z') ac = char(ac - 'A' + 'a');
                if (bc >= 'A' && bc <= 'Z') bc = char(bc - 'A' + 'a');
                if (ac != bc) return false;
            }
            return true;
            };

        if (s.empty()) return s;
        if (starts_with_ci(s, R"(\\.\pipe\)")) return s;

        auto strip_prefix_ci = [&](const char* pfx) {
            if (starts_with_ci(s, pfx)) s.erase(0, std::strlen(pfx));
            };

        while (!s.empty() && s[0] == '\\') s.erase(0, 1);
        if (starts_with_ci(s, R"(.\\)")) s.erase(0, 2);

        strip_prefix_ci(R"(device\namedpipe\)");
        strip_prefix_ci(R"(globalroot\device\namedpipe\)");
        strip_prefix_ci(R"(?\pipe\)");
        strip_prefix_ci(R"(??\pipe\)");
        strip_prefix_ci(R"(pipe\)");

        if (s.empty()) return std::string(R"(\\.\pipe\)");
        return std::string(R"(\\.\pipe\)") + s;
    }

    void PipeClientDeleter::operator()(transport::NamedPipeClient* p) noexcept { delete p; }
    State::~State() = default;

    static void ReceiveFromOtherTable(State& s, const std::string& pipe, const std::vector<uint8_t>& raw) {
        if (!pipe.empty()) {
            size_t n = (std::min)(pipe.size(), sizeof(s.target_pipe) - 1);
            std::memcpy(s.target_pipe, pipe.data(), n);
            s.target_pipe[n] = '\0';
        }

        s.tx_is_hex = false;

        std::memset(s.tx_buf, 0, sizeof(s.tx_buf));
        if (!raw.empty()) {
            size_t n = (std::min)(raw.size(), sizeof(s.tx_buf) - 1);
            std::memcpy(s.tx_buf, raw.data(), n);
        }
        s.tx_bytes.assign(raw.begin(), raw.end());

        s.focus_editor_next = true;
    }

    static float CalcStatusBarHeight(const State& s) {
        if (s.status_expanded)
            return 140.0f;
        return ImGui::GetFrameHeight() + 6.0f;
    }

    static int g_nextOrdinal = 1;

    struct ReplayTabState {
        std::string title;
        std::array<char, 128> title_edit{};
        int ordinal = 0;

        float editor_height = 240.0f;
        float editor_split_ratio = 0.5f;

        bool rx_is_hex = false;
        MemoryEditor rx_hex;

        std::vector<pipetap::log::Event> status_cache;
        pipetap::sharedui::FilterCache traffic_filter;
    };

    static std::unordered_map<Tab*, ReplayTabState> g_tabState;

    static ReplayTabState& RegisterTabIfNeeded(Tab* t) {
        IM_ASSERT(t && "RegisterTabIfNeeded called with null Tab*");
        auto [it, inserted] = g_tabState.try_emplace(t);
        ReplayTabState& state = it->second;
        if (inserted) {
            state.ordinal = g_nextOrdinal++;
            state.title = std::string("#") + std::to_string(state.ordinal);
            state.title_edit.fill(0);
            std::snprintf(state.title_edit.data(), state.title_edit.size(), "%s", state.title.c_str());

            state.rx_hex.ReadOnly = true;
            state.rx_hex.OptShowOptions = true;

            t->s.status_channel = std::string("replay/status/") + state.title;
        }
        return state;
    }

    static void UnregisterTab(Tab* t) {
        if (!t) return;
        g_tabState.erase(t);
    }

    static void DrawControlChannel(State& s)
    {
        using namespace ImGui;

        ImGui::SeparatorText("Target");

        ImGui::SetNextItemWidth(380.0f);
        InputTextWithHint("##target_pipe", R"(\\.\pipe\name ...)",
            s.target_pipe, IM_ARRAYSIZE(s.target_pipe));
        ImGui::SameLine();

        ImGui::Checkbox("Remote", &s.use_remote);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(120.0f);
        ImGui::InputScalar("PID", ImGuiDataType_U32, &s.remote_pid);
        ImGui::SameLine();

        const bool local_connected = (s.client && s.client->IsConnected());
        const bool remote_connected = (s.rclient && s.rclient->IsConnected());
        const bool is_connected = s.use_remote ? remote_connected : local_connected;

        if (!is_connected) {
            if (ImGui::Button("Connect")) {
                std::string norm = NormalizePipePath(std::string(s.target_pipe));
                std::snprintf(s.target_pipe, IM_ARRAYSIZE(s.target_pipe), "%s", norm.c_str());

                s.connecting = true;
                s.connect_started_at = ImGui::GetTime();

                if (s.use_remote) {
                    if (!s.rclient) s.rclient = std::make_unique<transport::RemoteNamedPipeClient>();
                    s.rclient->SetLogChannelName(s.status_channel);

                    auto* rc = s.rclient.get();
                    uint32_t pid = s.remote_pid;
                    std::string pipe = norm;
                    std::thread([rc, pid, pipe]() {
                        bool ok = false;
                        if (rc) ok = rc->ConnectSmart(pid, pipe.c_str(), 3000, /*wait_for_server=*/true, /*message_mode=*/true);
                        pipetap::log::App.Info(ok
                            ? (std::string("[replay] remote connected to ") + pipe).c_str()
                            : (std::string("[replay] remote connect failed") + (rc ? (": " + rc->LastError()) : "")).c_str());
                        }).detach();
                }
                else {
                    if (!s.client) s.client.reset(new transport::NamedPipeClient());
                    s.client->SetLogChannelName(s.status_channel);

                    auto* lc = s.client.get();
                    std::string pipe = norm;
                    std::thread([lc, pipe]() {
                        bool ok = false;
                        if (lc) ok = lc->ConnectSmart(pipe.c_str(), 3000);
                        pipetap::log::App.Info(ok
                            ? (std::string("[replay] connected to ") + pipe).c_str()
                            : (std::string("[replay] connect failed") + (lc ? (": " + lc->LastError()) : "")).c_str());
                        }).detach();
                }
            }
        }
        else {
            if (ImGui::Button("Disconnect")) {
                if (s.use_remote && s.rclient) s.rclient->Disconnect();
                if (!s.use_remote && s.client) s.client->Disconnect();
                pipetap::log::App.Info(s.use_remote ? "[replay] remote disconnected" : "[replay] disconnected");
            }
        }

        ImGui::SameLine();
        if (is_connected) {
            s.connecting = false;
            ImVec4 ok_col(0.2f, 0.8f, 0.2f, 1.0f);
            ImGui::TextColored(ok_col, s.use_remote ? "[remote connected]" : "[connected]");
            ImGui::SameLine();
            if (s.use_remote) {
                auto mode = s.rclient->Mode();
                ImGui::TextDisabled("(%s%s)",
                    s.rclient->IsMessageTypeServer() ? "message-type" : "byte-type",
                    (mode == transport::RemoteNamedPipeClient::ReadMode::Message) ? ", readmode=message" : ", readmode=byte");
            }
            else {
                ImGui::TextDisabled("(%s%s)",
                    (s.client && s.client->IsMessageTypeServer()) ? "message-type" : "byte-type",
                    (s.client && s.client->Mode() == transport::NamedPipeClient::ReadMode::Message) ? ", readmode=message" : ", readmode=byte");
            }
        }
        else {
            if (s.connecting) {
                if ((s.use_remote && s.rclient && s.rclient->IsConnected()) ||
                    (!s.use_remote && s.client && s.client->IsConnected())) {
                    s.connecting = false;
                    ImGui::TextColored(ImVec4(0.2f, 0.8f, 0.2f, 1.0f), s.use_remote ? "[remote connected]" : "[connected]");
                }
                else {
                    float elapsed = (float)(ImGui::GetTime() - s.connect_started_at);
                    ImGui::SetNextItemWidth(160.0f);
                    ImGui::ProgressBar(-(float)ImGui::GetTime(), ImVec2(0, 0), "connecting...");
                    ImGui::SameLine();
                    ImGui::TextDisabled("(%.1fs)", elapsed);
                }
            }
            else {
                ImGui::TextColored(ImVec4(0.9f, 0.2f, 0.2f, 1.0f), s.use_remote ? "[remote disconnected]" : "[disconnected]");
            }
        }
    }

    static void DrawEditorAndResponse(Tab& tab, uint64_t& nextId)
    {
        using namespace ImGui;
        State& s = tab.s;

        const bool is_connected = s.use_remote
            ? (s.rclient && s.rclient->IsConnected())
            : (s.client && s.client->IsConnected());

        SeparatorText("Payload Composer");

        const float hsplit_thick = 6.0f;
        const float min_side_w = 120.0f;

        ReplayTabState& state = RegisterTabIfNeeded(&tab);

        float& editors_h = state.editor_height;
        float& ratio = state.editor_split_ratio;
        editors_h = std::max(140.0f, editors_h);
        ratio = std::clamp(ratio, 0.1f, 0.9f);

        BeginChild("##replay_editors", ImVec2(0, editors_h), false,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        const float editor_inner_w = GetContentRegionAvail().x;

        ImGuiWindowFlags editor_flags =
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

        float left_w = (editor_inner_w - hsplit_thick) * ratio;
        float right_w = editor_inner_w - hsplit_thick - left_w;

        if (left_w < min_side_w)  left_w = min_side_w;
        if (right_w < min_side_w) right_w = min_side_w;
        if (left_w + hsplit_thick + right_w > editor_inner_w) {
            if (left_w > right_w) left_w = editor_inner_w - hsplit_thick - right_w;
            else                  right_w = editor_inner_w - hsplit_thick - left_w;
            if (left_w < min_side_w) left_w = min_side_w;
            if (right_w < min_side_w) right_w = min_side_w;
        }

        BeginChild("##edit_left", ImVec2(left_w, -1), true, editor_flags);

        {
            AlignTextToFramePadding();
            TextUnformatted("Request");
            SameLine();
            TextDisabled("| Mode:");
            SameLine();
            bool hex_sel = s.tx_is_hex;
            if (pipetap::sharedui::SegmentedToggle("req_mode", "Text", "Hex", hex_sel)) s.tx_is_hex = hex_sel;

            SameLine();
            BeginDisabled(s.tx_is_hex);
            TextDisabled("| Encoding:");
            SameLine();
            bool wide_sel = s.tx_text_is_wide;
            if (pipetap::sharedui::SegmentedToggle("req_enc", "UTF-8", "UTF-16", wide_sel)) {
                s.tx_text_is_wide = wide_sel;
                if (!s.tx_is_hex) {
                    if (s.tx_text_is_wide) Utf8ToUtf16LE(s.tx_buf, s.tx_bytes);
                    else {
                        size_t n = std::strlen(s.tx_buf);
                        s.tx_bytes.assign((const uint8_t*)s.tx_buf, (const uint8_t*)s.tx_buf + n);
                    }
                }
            }
            EndDisabled();

            SameLine();
            TextDisabled("| %zu byte(s)", s.tx_bytes.size());
        }

        Separator();

        {
            const ImGuiStyle& style = GetStyle();
            const float footer_extra_pad = style.FramePadding.y;
            const float reserved_footer = GetFrameHeightWithSpacing() + footer_extra_pad;

            if (s.focus_editor_next) { SetKeyboardFocusHere(); s.focus_editor_next = false; }
            ImVec2 avail = GetContentRegionAvail();
            ImVec2 editor_size(-FLT_MIN, std::max(0.0f, avail.y - reserved_footer));

            if (!s.tx_is_hex) {
                std::string view_utf8 = s.tx_text_is_wide
                    ? Utf16LEToUtf8(s.tx_bytes)
                    : std::string((const char*)s.tx_bytes.data(),
                        (const char*)s.tx_bytes.data() + s.tx_bytes.size());
                size_t limit = std::min(view_utf8.size(), sizeof(s.tx_buf) - 1);
                bool needs = (std::strncmp(s.tx_buf, view_utf8.c_str(), limit) != 0) ||
                    (std::strlen(s.tx_buf) != limit);
                if (needs) { std::memset(s.tx_buf, 0, sizeof(s.tx_buf)); if (limit) std::memcpy(s.tx_buf, view_utf8.data(), limit); }

                InputTextMultiline("##tx_text", s.tx_buf, IM_ARRAYSIZE(s.tx_buf),
                    editor_size,
                    ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_NoHorizontalScroll);

                if (s.tx_text_is_wide) Utf8ToUtf16LE(s.tx_buf, s.tx_bytes);
                else {
                    size_t n = std::strlen(s.tx_buf);
                    s.tx_bytes.assign((const uint8_t*)s.tx_buf, (const uint8_t*)s.tx_buf + n);
                }
            }
            else {
                s.tx_hex.UseDefaultResizeFor(s.tx_bytes);
                s.tx_hex.OptAutoExtend = true;
                s.tx_hex.OptShowOptions = true;
                s.tx_hex.ReadOnly = false;

                BeginChild("##tx_hex_child", editor_size, false,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                void* memptr = s.tx_bytes.empty() ? nullptr : (void*)s.tx_bytes.data();
                size_t memsz = s.tx_bytes.size();
                if (s.tx_bytes.empty()) { s.tx_bytes.resize(1, 0); memptr = s.tx_bytes.data(); memsz = 1; }
                s.tx_hex.DrawContents(memptr, memsz, 0);
                EndChild();

                std::string view_utf8 = s.tx_text_is_wide ? Utf16LEToUtf8(s.tx_bytes)
                    : std::string((const char*)s.tx_bytes.data(),
                        (const char*)s.tx_bytes.data() + s.tx_bytes.size());
                std::memset(s.tx_buf, 0, sizeof(s.tx_buf));
                size_t limit = std::min(view_utf8.size(), sizeof(s.tx_buf) - 1);
                if (limit) std::memcpy(s.tx_buf, view_utf8.data(), limit);
            }
        }

        {
            const ImGuiStyle& st = GetStyle();
            const float gap = st.ItemInnerSpacing.x;

            const char* L_send_vis = "Send";
            const char* L_paste_vis = "Paste";
            const char* L_clear_vis = "Clear TX";

            auto btn_w = [&](const char* vis) { return CalcTextSize(vis).x + st.FramePadding.x * 2.0f; };
            float total_w = btn_w(L_send_vis) + gap + btn_w(L_paste_vis) + gap + btn_w(L_clear_vis);

            SetCursorPosY(GetCursorPosY() + st.ItemInnerSpacing.y); // top pad like proxy

            float x = GetCursorPosX() + (GetContentRegionAvail().x - total_w);
            if (x < GetCursorPosX()) x = GetCursorPosX();
            SetCursorPosX(x);

            bool did_paste = false;
            bool do_send = false;

            {
                ImVec4 base = ImVec4(0.20f, 0.65f, 0.20f, 1.0f);
                ImVec4 hov = ImVec4(0.25f, 0.75f, 0.25f, 1.0f);
                ImVec4 act = ImVec4(0.18f, 0.58f, 0.18f, 1.0f);
                PushStyleColor(ImGuiCol_Button, base);
                PushStyleColor(ImGuiCol_ButtonHovered, hov);
                PushStyleColor(ImGuiCol_ButtonActive, act);
                BeginDisabled(!is_connected);
                if (Button("Send")) do_send = true;
                EndDisabled();
                PopStyleColor(3);
            }

            SameLine(0.0f, gap);

            PushID("req_paste");
            if (Button("Paste")) {
                std::vector<uint8_t> clip;
                if (pipetap::ui::GetClipboardRawBytes(clip)) { s.tx_bytes = std::move(clip); did_paste = true; }
            }
            if (IsItemHovered() && IsMouseReleased(ImGuiMouseButton_Right))
                OpenPopup("paste_popup");
            if (BeginPopup("paste_popup")) {
                if (MenuItem("Paste (Base64)")) {
                    std::vector<uint8_t> raw;
                    if (pipetap::ui::GetClipboardBase64AsBytes(raw)) { s.tx_bytes = std::move(raw); did_paste = true; }
                }
                EndPopup();
            }
            PopID();

            SameLine(0.0f, gap);
            if (Button("Clear TX")) { s.tx_bytes.clear(); s.tx_buf[0] = '\0'; }

            if (did_paste) {
                std::string view_utf8 = s.tx_text_is_wide ? Utf16LEToUtf8(s.tx_bytes)
                    : std::string((const char*)s.tx_bytes.data(),
                        (const char*)s.tx_bytes.data() + s.tx_bytes.size());
                std::memset(s.tx_buf, 0, sizeof(s.tx_buf));
                size_t limit = std::min(view_utf8.size(), sizeof(s.tx_buf) - 1);
                if (limit) std::memcpy(s.tx_buf, view_utf8.data(), limit);
                s.focus_editor_next = true;
            }

            if (do_send) {
                const std::vector<uint8_t>& out = s.tx_bytes;
                std::string rx;

                if (is_connected) {
                    if (s.use_remote && s.rclient) {
                        if (!s.rclient->WriteAll(out.data(), (DWORD)out.size())) {
                            pipetap::log::App.Error((std::string("[replay] remote write failed: ") + s.rclient->LastError()).c_str());
                        }
                        else {
                            auto mode = s.rclient->Mode();
                            (void)((mode == transport::RemoteNamedPipeClient::ReadMode::Message)
                                ? s.rclient->ReadMessage(rx, 1 << 20, 200)
                                : s.rclient->ReadSome(rx, 1 << 20, 200));
                        }
                    }
                    else if (s.client) {
                        if (!s.client->WriteAll(out.data(), (DWORD)out.size())) {
                            pipetap::log::App.Error((std::string("[replay] write failed: ") + s.client->LastError()).c_str());
                        }
                        else {
                            auto mode = s.client->Mode();
                            (void)((mode == transport::NamedPipeClient::ReadMode::Message)
                                ? s.client->ReadMessage(rx, 1 << 20, 200)
                                : s.client->ReadSome(rx, 1 << 20, 200));
                        }
                    }
                }

                uint32_t peer_pid = 0;
                std::string peer_image;
                if (!s.use_remote && s.client) {
                    peer_pid = s.client->ServerPid();
                    peer_image = s.client->ServerImage();
                }
                else if (s.use_remote && s.rclient) {
                    peer_pid = s.rclient->ServerPid();
                    peer_image = s.rclient->ServerImage();
                }

                // TX log entry (always push raw + printable preview)
                {
                    pipetap::sharedui::MsgLogEntry tx;
                    tx.id = nextId++;
                    tx.time = pipetap::sharedui::NowTimeString();
                    tx.pipe = (s.target_pipe[0] ? std::string(s.target_pipe) : std::string("(pipe)"));
                    tx.dir = pipetap::sharedui::Direction::Out;
                    tx.size = out.size();

                    tx.data = pipetap::sharedui::MakePrintablePreview(out);
                    tx.snippet = pipetap::sharedui::MakeSnippet(tx.data);
                    tx.raw.assign(out.begin(), out.end());

                    tx.peer_pid = peer_pid;
                    tx.peer_image = peer_image;

                    tx.is_event = false;
                    tx.winapi = "Write";

                    s.log.push_back(std::move(tx));
                }

                if (!rx.empty()) {
                    s.rx_text = rx;

                    pipetap::sharedui::MsgLogEntry ent;
                    ent.id = nextId++;
                    ent.time = pipetap::sharedui::NowTimeString();
                    ent.pipe = (s.target_pipe[0] ? std::string(s.target_pipe) : std::string("(pipe)"));
                    ent.dir = pipetap::sharedui::Direction::In;
                    ent.size = rx.size();

                    std::vector<uint8_t> rx_bytes(rx.begin(), rx.end());
                    ent.data = pipetap::sharedui::MakePrintablePreview(rx_bytes);
                    ent.snippet = pipetap::sharedui::MakeSnippet(ent.data);
                    ent.raw.assign(rx_bytes.begin(), rx_bytes.end());

                    ent.peer_pid = peer_pid;
                    ent.peer_image = peer_image;

                    ent.is_event = false;
                    ent.winapi = "Read";

                    s.log.push_back(std::move(ent));
                }
            }
        }

        EndChild(); // ##edit_left

        SameLine(0.0f, 0.0f);
        PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
        BeginChild("##edit_splitter", ImVec2(hsplit_thick, -1), false,
            editor_flags | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoDecoration);
        HSplitterRatio("##hsplit", hsplit_thick, min_side_w, min_side_w, editor_inner_w, ratio);
        EndChild();
        PopStyleVar();

        SameLine(0.0f, 0.0f);
        BeginChild("##edit_right", ImVec2(right_w, -1), true, editor_flags);

        AlignTextToFramePadding();
        TextUnformatted("Response");
        SameLine();
        TextDisabled("| Mode:");
        SameLine();
        bool& rx_is_hex = state.rx_is_hex;
        (void)pipetap::sharedui::SegmentedToggle("resp_mode", "Text", "Hex", rx_is_hex);

        SameLine();
        TextDisabled("| %zu byte(s)", s.rx_text.size());
        SameLine();
        {
            const char* L_copy = "Copy...";
            const char* L_clear = "Clear RX";
            std::vector<uint8_t> resp_bytes(s.rx_text.begin(), s.rx_text.end());
            pipetap::ui::DrawCopyPopupForBytes("copy_resp_popup", resp_bytes, L_copy);
            SameLine();
            BeginDisabled(s.rx_text.empty());
            if (Button(L_clear)) s.rx_text.clear();
            EndDisabled();
        }

        Separator();

        {
            const ImGuiStyle& style = GetStyle();
            const float footer_extra_pad = style.FramePadding.y;
            const float reserved_footer = GetFrameHeightWithSpacing() + footer_extra_pad;

            ImVec2 avail = GetContentRegionAvail();
            ImVec2 editor_size(-FLT_MIN, std::max(0.0f, avail.y - reserved_footer));

            if (!rx_is_hex) {
                const char* rx_cstr = s.rx_text.c_str();
                InputTextMultiline("##rx_view",
                    const_cast<char*>(rx_cstr),
                    (size_t)(s.rx_text.size() + 1),
                    editor_size,
                    ImGuiInputTextFlags_ReadOnly | ImGuiInputTextFlags_NoHorizontalScroll);
            }
            else {
                auto& hex = state.rx_hex;
                std::vector<uint8_t> bytes(s.rx_text.begin(), s.rx_text.end());
                void* memptr = bytes.empty() ? nullptr : (void*)bytes.data();
                size_t memsz = bytes.size();
                if (bytes.empty()) { bytes.resize(1, 0); memptr = bytes.data(); memsz = 1; }
                BeginChild("##rx_hex_child", editor_size, false,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
                hex.ReadOnly = true;
                hex.DrawContents(memptr, memsz, 0);
                EndChild();
            }
        }

        {
            const char* L_more = "Read More";
            const ImGuiStyle& st = GetStyle();
            float btn_w = CalcTextSize(L_more).x + st.FramePadding.x * 2.0f;

            SetCursorPosY(GetCursorPosY() + st.ItemInnerSpacing.y);
            float x = GetCursorPosX() + (GetContentRegionAvail().x - btn_w);
            if (x < GetCursorPosX()) x = GetCursorPosX();
            SetCursorPosX(x);

            bool pressed = false;
            BeginDisabled(!is_connected);
            pressed = Button(L_more);
            EndDisabled();

            if (IsItemHovered(ImGuiHoveredFlags_DelayNone | ImGuiHoveredFlags_AllowWhenDisabled)) {
                ImGui::SetTooltip(
                    "Reading additional bytes is best-effort:\n"
                    "- If no data is available right now, nothing will happen.\n"
                    "- Message mode: next complete message if available.\n"
                    "- Byte mode: may return partial fragments.\n"
                    "- A short timeout is used; inactivity often returns nothing.\n"
                    "- Notes/timeouts/errors appear in the Status panel."
                );
            }

            if (pressed) {
                std::string rx_more;
                bool read_ok = false;
                constexpr DWORD kMax = 1 << 20, kWaitMs = 50;

                if (s.use_remote && s.rclient) {
                    auto mode = s.rclient->Mode();
                    read_ok = (mode == transport::RemoteNamedPipeClient::ReadMode::Message)
                        ? s.rclient->ReadMessage(rx_more, kMax, kWaitMs)
                        : s.rclient->ReadSome(rx_more, kMax, kWaitMs);
                    if (!read_ok && !s.rclient->LastError().empty())
                        pipetap::log::App.Error((std::string("[replay] remote read note: ") + s.rclient->LastError()).c_str());
                }
                else if (s.client) {
                    auto mode = s.client->Mode();
                    read_ok = (mode == transport::NamedPipeClient::ReadMode::Message)
                        ? s.client->ReadMessage(rx_more, kMax, kWaitMs)
                        : s.client->ReadSome(rx_more, kMax, kWaitMs);
                    if (!read_ok && !s.client->LastError().empty())
                        pipetap::log::App.Error((std::string("[replay] read note: ") + s.client->LastError()).c_str());
                }

                if (!rx_more.empty()) {
                    s.rx_text += rx_more;

                    pipetap::sharedui::MsgLogEntry ent;
                    ent.id = nextId++;
                    ent.time = pipetap::sharedui::NowTimeString();
                    ent.pipe = (s.target_pipe[0] ? std::string(s.target_pipe) : std::string("(pipe)"));
                    ent.dir = pipetap::sharedui::Direction::In;
                    ent.size = rx_more.size();

                    ent.data = pipetap::sharedui::MakePrintablePreview(rx_more);
                    ent.snippet = pipetap::sharedui::MakeSnippet(ent.data);
                    ent.raw.assign(rx_more.begin(), rx_more.end());

                    ent.is_event = false;
                    ent.winapi = "Read";

                    s.log.push_back(std::move(ent));
                }

            }
        }

        EndChild(); // ##edit_right
        EndChild(); // ##replay_editors
    }

    static void DrawTraffic(Tab& t, float reserve_bottom_h)
    {
        using namespace ImGui;

        SeparatorText("Traffic Log");

        ReplayTabState& state = RegisterTabIfNeeded(&t);
        if (Button("Clear")) {
            t.s.log.clear();
            t.s.selected_row = -1;
            auto& fc = state.traffic_filter;
            fc.indices.clear();
            fc.last_log_size = 0;
            fc.dirty = true;
        }
        SameLine();

        Text("Direction:");
        SameLine();
        SetNextItemWidth(90.f);
        const char* dir_items[] = { "All", "Out (->)", "In (<-)" };
        if (Combo("##dir", &t.s.filter_dir, dir_items, IM_ARRAYSIZE(dir_items))) {
            auto& fc = state.traffic_filter;
            fc.dir = t.s.filter_dir;
            fc.dirty = true;
        }
        SameLine();

        SetNextItemWidth(260.f);
        bool needle_changed = InputTextWithHint("##flt", "filter", t.s.filter_text, IM_ARRAYSIZE(t.s.filter_text));
        if (needle_changed) {
            auto& fc = state.traffic_filter;
            fc.needle_lower = pipetap::sharedui::ToLowerStr(t.s.filter_text);
            fc.dirty = true;
        }

        SameLine();
        if (Button("Save...")) {
            std::vector<pipetap::sharedui::MsgLogEntry> snapshot = t.s.log;
            const bool ok = pipetap::sharedui::ExportTrafficLogToJsonFile(snapshot);
            if (!ok) {
                pipetap::log::App.Warnf("[replay] Save cancelled or failed.");
            }
            else {
                pipetap::log::App.Infof("[replay] Traffic log exported.");
            }
        }

        BeginChild("##replay_log_child", ImVec2(0, -reserve_bottom_h), false, ImGuiWindowFlags_HorizontalScrollbar);

        // Build/update filtered indices (index-only)
        std::vector<int>* index_map_ptr = nullptr;
        {
            auto& fc = state.traffic_filter;
            size_t cur_size = t.s.log.size();
            if (fc.dirty || fc.last_log_size != cur_size) {
                pipetap::sharedui::RebuildFilterIndices(t.s.log, fc);
            }
            index_map_ptr = &fc.indices;
        }
        auto& index_map = *index_map_ptr;

        // SendToReplay callback for row context menu (raw bytes)
        pipetap::sharedui::SendToReplayFn cb = [&](const std::string& pipe, const std::vector<uint8_t>& raw) {
            ReceiveFromOtherTable(t.s, pipe, raw);
            };

        int filtered_sel = -1; // selection within sorted/filtered list
        int selected_original_after = -1;

        pipetap::sharedui::MsgTableOpts opts;
        (void)pipetap::sharedui::DrawMessageTableIndexed(
            t.s.log,
            index_map,
            filtered_sel,
            t.s.selected_row,
            "replay_table_indexed",
            cb,                    // SendToReplayFn
            opts,
            &selected_original_after
        );

        if (selected_original_after >= 0) {
            t.s.selected_row = selected_original_after;
        }

        EndChild();
    }

    // Status bar that drains the per-tab channel and keeps a small UI cache
    static void DrawStatusBar(Tab& tab) {
        State& s = tab.s;
        ReplayTabState& state = RegisterTabIfNeeded(&tab);

        // Non-blocking drain from the channel into our per-tab cache
        auto& ch = pipetap::log::channel(s.status_channel);
        std::vector<pipetap::log::Event> tmp;
        (void)ch.Drain(tmp); // non-blocking (returns false if busy; we just skip this frame)
        if (!tmp.empty()) {
            auto& cache = state.status_cache;
            const size_t cap = 2000;
            if (cache.size() + tmp.size() > cap) {
                size_t over = cache.size() + tmp.size() - cap;
                if (over > cache.size()) over = cache.size();
                cache.erase(cache.begin(), cache.begin() + over);
            }
            // append drained events
            cache.insert(cache.end(),
                std::make_move_iterator(tmp.begin()),
                std::make_move_iterator(tmp.end()));
        }

        // UI
        const float reserve_h = CalcStatusBarHeight(s);

        ImGui::BeginChild("##status_bar", ImVec2(0, reserve_h), false,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);

        auto color_for = [](pipetap::log::Level lv) -> ImVec4 {
            using L = pipetap::log::Level;
            switch (lv) {
            case L::Info:    return ImVec4(0.65f, 0.85f, 1.00f, 1.0f);
            case L::Warning: return ImVec4(1.00f, 0.85f, 0.35f, 1.0f);
            case L::Error:   return ImVec4(1.00f, 0.40f, 0.40f, 1.0f);
            case L::Debug:   return ImVec4(0.75f, 0.75f, 0.75f, 1.0f);
            }
            return ImVec4(0.80f, 0.80f, 0.80f, 1.0f);
            };

        auto& cache = state.status_cache;

        if (!s.status_expanded) {
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Status");
            ImGui::SameLine();

            if (!cache.empty()) {
                const auto& ev = cache.back();
                ImGui::SameLine();
                ImGui::TextColored(color_for(ev.level), "|");
                ImGui::SameLine();
                ImGui::TextUnformatted(ev.text.c_str());
            }
            else {
                ImGui::SameLine();
                ImGui::TextDisabled("(idle)");
            }

            float avail = ImGui::GetContentRegionAvail().x;
            float btn_w = ImGui::CalcTextSize("Expand").x + ImGui::GetStyle().FramePadding.x * 2.0f;
            ImGui::SameLine(ImGui::GetCursorPosX() + (avail - btn_w));
            if (ImGui::Button("Expand")) s.status_expanded = true;
        }
        else {
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Status");
            ImGui::SameLine();

            // Right controls
            {
                float right = ImGui::GetContentRegionAvail().x;
                float b1 = ImGui::CalcTextSize("Clear").x + ImGui::GetStyle().FramePadding.x * 2.0f;
                float b2 = ImGui::CalcTextSize("Collapse").x + ImGui::GetStyle().FramePadding.x * 2.0f;
                float bx = b1 + ImGui::GetStyle().ItemInnerSpacing.x + b2;
                ImGui::SameLine(ImGui::GetCursorPosX() + (right - bx));

                if (ImGui::Button("Clear")) cache.clear();
                ImGui::SameLine();
                if (ImGui::Button("Collapse")) s.status_expanded = false;
            }

            // Feed area
            ImGui::BeginChild("##status_feed", ImVec2(0, -2.0f), true,
                ImGuiWindowFlags_HorizontalScrollbar);

            ImGuiListClipper clipper;
            clipper.Begin((int)cache.size());
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    const auto& ev = cache[(size_t)i];
                    ImGui::PushStyleColor(ImGuiCol_Text, color_for(ev.level));
                    ImGui::TextUnformatted("|");
                    ImGui::PopStyleColor();
                    ImGui::SameLine();

                    // show mm:ss (or hh:mm:ss)
                    int secs = (int)ev.t;
                    int mm = (secs / 60) % 60;
                    int hh = (secs / 3600);
                    int ss = secs % 60;
                    char ts[32];
                    if (hh > 0) std::snprintf(ts, sizeof(ts), "%02d:%02d:%02d", hh, mm, ss);
                    else        std::snprintf(ts, sizeof(ts), "%02d:%02d", mm, ss);

                    ImGui::TextDisabled("[%s]", ts);
                    ImGui::SameLine();
                    ImGui::TextWrapped("%s", ev.text.c_str());
                }
            }

            float max_y = ImGui::GetScrollMaxY();
            if (max_y > 0.0f) {
                float cur = ImGui::GetScrollY();
                if (max_y - cur < 8.0f) ImGui::SetScrollHereY(1.0f);
            }

            ImGui::EndChild();
        }

        ImGui::EndChild();
    }

    // ============================================================================
    // Tabs manager
    // ============================================================================
    void StartNewTabFromProxy(Manager& m, const std::string& pipe, const std::vector<uint8_t>& raw)
    {
        auto tab = std::make_unique<Tab>();

        // Pre-populate editor + pipe (but do NOT auto-connect)
        if (!pipe.empty()) {
            size_t n = (std::min)(pipe.size(), sizeof(tab->s.target_pipe) - 1);
            std::memcpy(tab->s.target_pipe, pipe.data(), n);
            tab->s.target_pipe[n] = '\0';
        }

        // Always default to string view; fill both text and bytes.
        tab->s.tx_is_hex = false;
        std::memset(tab->s.tx_buf, 0, sizeof(tab->s.tx_buf));
        if (!raw.empty()) {
            size_t n = (std::min)(raw.size(), sizeof(tab->s.tx_buf) - 1);
            std::memcpy(tab->s.tx_buf, raw.data(), n);
        }
        tab->s.tx_bytes.assign(raw.begin(), raw.end());
        tab->s.focus_editor_next = true;

        RegisterTabIfNeeded(tab.get());
        m.tabs.push_back(std::move(tab));
        m.active = (int)m.tabs.size() - 1;
        pipetap::log::App.Info("[replay] new tab opened from Proxy");
    }

    // Draw single tab content
    static void DrawOneTab(Tab& t, bool is_active_panel)
    {
        static uint64_t nextId = 1;
        ReplayTabState& state = RegisterTabIfNeeded(&t);

        if (is_active_panel) t.has_unseen = false;

        // Top: target/connect
        DrawControlChannel(t.s);

        // Middle: editors (request + response) with H-splitter
        DrawEditorAndResponse(t, nextId);

        // Splitter between editors and traffic (adjust editors height vs remaining)
        {
            float& editors_h = state.editor_height;
            if (editors_h < 140.0f) editors_h = 140.0f;
            float rest = ImGui::GetContentRegionAvail().y;
            float dummy_log_h = rest - 6.0f;
            VSplitter("##split_edit_log", 6.0f, 120.0f, 120.0f, editors_h, dummy_log_h);
        }

        // Reserve bottom space for the status bar and draw traffic above it.
        const float status_h = CalcStatusBarHeight(t.s);
        DrawTraffic(t, status_h);

        // Bottom-most: the status bar itself
        DrawStatusBar(t);
    }

    void Draw(Manager& m)
    {
        if (m.tabs.empty()) {
            auto t = std::make_unique<Tab>();
            RegisterTabIfNeeded(t.get());
            m.tabs.push_back(std::move(t));
            m.active = 0;
        }

        m.panel_focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);

        if (ImGui::BeginTabBar("replay_tabs",
            ImGuiTabBarFlags_Reorderable | ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_TabListPopupButton)) {

            for (int i = 0; i < (int)m.tabs.size();) {
                Tab& t = *m.tabs[i];
                ReplayTabState& state = RegisterTabIfNeeded(&t);

                char unique_id[64];
                std::snprintf(unique_id, sizeof(unique_id), "replay_tab_%p", (void*)&t);

                char label[256];
                std::snprintf(label, sizeof(label), "%s##%s", state.title.c_str(), unique_id);

                bool open = true;
                bool began = ImGui::BeginTabItem(label, (m.tabs.size() > 1) ? &open : nullptr);

                // Right-click context menu for rename (manual; NOT tied to typing)
                if (ImGui::BeginPopupContextItem()) {
                    auto& buf = state.title_edit;
                    ImGui::TextUnformatted("Rename Tab");
                    ImGui::Separator();
                    ImGui::InputText("Name", buf.data(), buf.size());
                    if (ImGui::Button("Apply")) {
                        std::string new_name = buf.data();
                        if (new_name.empty()) {
                            new_name = std::string("#") + std::to_string(state.ordinal);
                            std::snprintf(buf.data(), buf.size(), "%s", new_name.c_str());
                        }
                        state.title = new_name;
                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("Reset")) {
                        std::string def = std::string("#") + std::to_string(state.ordinal);
                        state.title = def;
                        std::snprintf(buf.data(), buf.size(), "%s", def.c_str());
                        ImGui::CloseCurrentPopup();
                    }
                    ImGui::EndPopup();
                }

                if (began) {
                    m.active = i;
                    DrawOneTab(t, /*is_active_panel*/m.panel_focused);
                    ImGui::EndTabItem();
                }

                if (!open && m.tabs.size() > 1) {
                    // Close tab
                    UnregisterTab(&t);
                    m.tabs.erase(m.tabs.begin() + i);
                    if (m.active >= (int)m.tabs.size()) m.active = (int)m.tabs.size() - 1;
                    continue;
                }

                ++i;
            }

            // New tab button
            if (ImGui::TabItemButton("+", ImGuiTabItemFlags_Trailing)) {
                auto t = std::make_unique<Tab>();
                RegisterTabIfNeeded(t.get());
                m.tabs.push_back(std::move(t));
                m.active = (int)m.tabs.size() - 1;
            }

            ImGui::EndTabBar();
        }
    }

} // namespace pipetap::ui::replay
