#include "log.h"
#include "session.h"
#include "ui/injector.h"
#include "ui/sharedui.h"
#include <thread>

namespace pipetap::ui::injector {

    static pipetap::sharedui::LogDrainState g_injectorLog;

    static void DrawProcessTable(pipetap::injection::VM& s)
    {
        using pipetap::injection::ProcInfo;

        ImGui::SeparatorText("Target Process");

        ImGui::InputTextWithHint("##filter", "filter (name contains...)", s.filter, IM_ARRAYSIZE(s.filter));
        ImGui::SameLine(); if (ImGui::Button("Refresh")) s.need_refresh = true;

        std::vector<int> index_map;
        index_map.reserve(s.processes.size());
        for (int i = 0; i < (int)s.processes.size(); ++i) {
            const auto& p = s.processes[i];
            if (s.filter[0] != '\0') {
                std::string hay = p.name;
                std::string needle = s.filter;
                std::transform(hay.begin(), hay.end(), hay.begin(), [](unsigned char c) { return (char)tolower(c); });
                std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c) { return (char)tolower(c); });
                if (hay.find(needle) == std::string::npos) continue;
            }
            index_map.push_back(i);
        }

        ImGuiTableFlags flags =
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Borders |
            ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_Sortable;

        ImVec2 tbl_size = ImVec2(0, 260);
        if (ImGui::BeginTable("##proc_tbl", 7, flags, tbl_size)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_DefaultSort);
            ImGui::TableSetupColumn("User", ImGuiTableColumnFlags_WidthFixed, 180.f);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 90.f);
            ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 60.f);
            ImGui::TableSetupColumn("IL", ImGuiTableColumnFlags_WidthFixed, 90.f);
            ImGui::TableSetupColumn("Session", ImGuiTableColumnFlags_WidthFixed, 70.f);
            ImGui::TableSetupColumn("System", ImGuiTableColumnFlags_WidthFixed, 70.f);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sort = ImGui::TableGetSortSpecs()) {
                if (sort->SpecsCount == 1) {
                    const ImGuiTableColumnSortSpecs& sp = sort->Specs[0];
                    const bool asc = (sp.SortDirection == ImGuiSortDirection_Ascending);
                    auto cmp = [&](int ia, int ib) {
                        const ProcInfo& a = s.processes[ia];
                        const ProcInfo& b = s.processes[ib];
                        switch (sp.ColumnIndex) {
                        case 0: return asc ? (a.name < b.name) : (a.name > b.name);
                        case 1: return asc ? (a.user < b.user) : (a.user > b.user);
                        case 2: return asc ? (a.pid < b.pid) : (a.pid > b.pid);
                        case 3: return asc ? (a.arch < b.arch) : (a.arch > b.arch);
                        case 4: return asc ? (a.il < b.il) : (a.il > b.il);
                        case 5: return asc ? (a.session_id < b.session_id) : (a.session_id > b.session_id);
                        case 6: return asc ? (a.is_system < b.is_system) : (a.is_system > b.is_system);
                        default: return false;
                        }
                        };
                    std::stable_sort(index_map.begin(), index_map.end(), cmp);
                    sort->SpecsDirty = false;
                }
            }

            ImGuiListClipper clipper;
            clipper.Begin((int)index_map.size());
            while (clipper.Step()) {
                for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
                    const int i = index_map[r];
                    const auto& p = s.processes[i];

                    ImGui::TableNextRow();
                    ImGui::PushID(i);

                    ImGui::TableNextColumn();
                    ImGuiSelectableFlags selFlags =
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowDoubleClick;

                    bool is_sel = (s.selected_index == i);
                    if (ImGui::Selectable("##row", is_sel, selFlags)) {
                        s.selected_index = i;
                        s.pid_manual = p.pid;
                        if (ImGui::IsMouseDoubleClicked(0) && !s.injecting.load()) {
                            if (s.dll_path[0] == '\0') pipetap::injection::GetDefaultDllPath(s.dll_path, sizeof(s.dll_path));
                            std::thread(pipetap::injection::DoInject, &s).detach();
                        }
                    }

                    if (ImGui::BeginPopupContextItem()) {
                        s.selected_index = i;
                        s.pid_manual = p.pid;
                        if (ImGui::MenuItem("Copy PID")) {
                            char pidbuf[32];
                            std::snprintf(pidbuf, sizeof(pidbuf), "%u", p.pid);
                            ImGui::SetClipboardText(pidbuf);
                        }
                        ImGui::EndPopup();
                    }

                    ImGui::SameLine();
                    ImGui::TextUnformatted(p.name.c_str());

                    ImGui::TableNextColumn();
                    if (!p.user.empty()) {
                        ImGui::TextUnformatted(p.user.c_str());
                    }
                    else if (p.is_system) {
                        ImGui::TextColored(ImVec4(0.90f, 0.30f, 0.15f, 1.0f), "SYSTEM");
                    }
                    else {
                        ImGui::TextDisabled("");
                    }

                    ImGui::TableNextColumn(); ImGui::Text("%u", p.pid);
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(p.arch.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(p.il.c_str());
                    ImGui::TableNextColumn(); ImGui::Text("%lu", (unsigned long)p.session_id);
                    ImGui::TableNextColumn();
                    if (p.is_system)
                        ImGui::TextColored(ImVec4(0.90f, 0.30f, 0.15f, 1.0f), "SYSTEM");
                    else
                        ImGui::TextDisabled("user");

                    ImGui::PopID();
                }
            }

            ImGui::EndTable();
        }
    }

    void Draw(pipetap::injection::VM& s)
    {
        using pipetap::injection::RefreshProcesses;
        using pipetap::injection::GetDefaultDllPath;
        using pipetap::injection::DoInject;

        if (!s.log_ch) {
            char name[64];
            std::snprintf(name, sizeof(name), "injector/status/%p", (void*)&s);
            s.log_channel_name = name;
            s.log_ch = &pipetap::log::channel(s.log_channel_name);
        }

        if (!s.dll_defaulted) { GetDefaultDllPath(s.dll_path, sizeof(s.dll_path)); s.dll_defaulted = true; }
        if (s.need_refresh) { RefreshProcesses(s); s.need_refresh = false; }

        DrawProcessTable(s);

        ImGui::SeparatorText("Parameters");

        const ImGuiStyle& style = ImGui::GetStyle();

        const float pid_w = 140.0f;
        const char* inject_label = "Inject Support DLL";

        float use_default_w = ImGui::CalcTextSize("Use Default").x + style.FramePadding.x * 2.0f;
        use_default_w = std::max(use_default_w, 110.0f);

        float inject_w = ImGui::CalcTextSize(inject_label).x + style.FramePadding.x * 2.0f;
        inject_w = std::max(inject_w, 170.0f);

        ImGui::SetNextItemWidth(pid_w);
        ImGui::InputScalar("PID", ImGuiDataType_U32, &s.pid_manual);

        ImGui::SameLine();
        {
            float remain = ImGui::GetContentRegionAvail().x;
            float auto_chk_w = ImGui::CalcTextSize("Auto-connect proxy").x + style.FramePadding.x * 6.0f;

            const float gaps = style.ItemSpacing.x * 3.0f;
            float path_w = remain - (use_default_w + auto_chk_w + inject_w + gaps);
            path_w = std::max(path_w, 240.0f);

            ImGui::SetNextItemWidth(path_w);
            ImGui::InputTextWithHint("##dll_path", "DLL Path", s.dll_path, IM_ARRAYSIZE(s.dll_path));
        }

        ImGui::SameLine();
        if (ImGui::Button("Use Default", ImVec2(use_default_w, 0))) {
            pipetap::injection::GetDefaultDllPath(s.dll_path, sizeof(s.dll_path));
        }

        ImGui::SameLine();
        {
            bool ac = pipetap::session::Session().auto_connect_proxy.load();
            if (ImGui::Checkbox("Auto-connect proxy", &ac)) {
                pipetap::session::Session().auto_connect_proxy.store(ac);
            }
        }

        ImGui::SameLine();
        {
            const ImVec4 b = ImVec4(0.11f, 0.41f, 0.87f, 1.0f);
            const ImVec4 bHov = ImVec4(0.13f, 0.49f, 0.98f, 1.0f);
            const ImVec4 bAct = ImVec4(0.09f, 0.36f, 0.77f, 1.0f);

            if (!s.injecting) {
                ImGui::PushStyleColor(ImGuiCol_Button, b);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, bHov);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, bAct);
            }

            bool clicked = ImGui::Button(s.injecting ? "Injecting..." : inject_label, ImVec2(inject_w, 0));

            if (!s.injecting) ImGui::PopStyleColor(3);

            if (clicked && !s.injecting.load()) {
                if (s.pid_manual == 0 || s.dll_path[0] == '\0') {
                    pipetap::log::App.Info("[injector] missing PID or DLL path");
                }
                else {
                    std::thread(pipetap::injection::DoInject, &s).detach();
                }
            }
        }

        // ---------- Log (newest-first) via channel ----------
        ImGui::Separator();
        pipetap::sharedui::DrainLogChannelToState(g_injectorLog, *s.log_ch, /*cap=*/2000);

        float h = ImGui::GetContentRegionAvail().y;
        if (h < pipetap::sharedui::LogDrainFeedDefaultHeight()) h = pipetap::sharedui::LogDrainFeedDefaultHeight();

        pipetap::sharedui::DrawLogDrainFeed("##injector_status", g_injectorLog, *s.log_ch,
            /*cap=*/2000, /*height=*/h, /*show_clear=*/true, /*auto_scroll=*/true, /*heading=*/"Injector Status");
    }

} // namespace pipetap::ui::injector
