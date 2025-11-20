#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "app.h"
#include "imgui.h"
#include "injection.h"
#include "log.h"
#include "session.h"
#include "ui/about.h"
#include "ui/injector.h"
#include "ui/pipelist.h"
#include "ui/proxy.h"
#include "ui/replay.h"
#include "ui/sharedui.h"
#include "win/elevation.h"
#include <functional>
#include <string>
#include <Windows.h>


namespace pipetap {

    using pipetap::win::IsProcessElevated;
    using pipetap::win::QueryCurrentIntegrityRid;
    using pipetap::win::IntegrityRidToCStr;
    using pipetap::win::RelaunchAsAdministrator;

    static void MenuBarRightText(const char* txt, const ImVec4* color = nullptr) {
        float w = ImGui::CalcTextSize(txt).x;
        float full = ImGui::GetWindowContentRegionMax().x;
        float x = full - w - ImGui::GetStyle().ItemSpacing.x;
        float curY = ImGui::GetCursorPosY();
        ImGui::SameLine(0.0f, 0.0f);
        ImGui::SetCursorPosX(x);
        ImGui::SetCursorPosY(curY);
        if (color) {
            ImGui::PushStyleColor(ImGuiCol_Text, *color);
            ImGui::TextUnformatted(txt);
            ImGui::PopStyleColor();
        }
        else {
            ImGui::TextUnformatted(txt);
        }
    }

    void UI() {
        static ui::replay::Manager   replay;
        static ui::proxy::Manager    proxy;
        static injection::VM         inj;
        static ui::pipelist::VM      pipelist;

        // visibility for each panel
        static bool show_replay = true;
        static bool show_proxy = true;
        static bool show_injector = true;
        static bool show_pipelist = true;
        static bool show_app_log = false;
        static bool about_requested = false;
        // boot
        static bool focus_proxy_once = true;

#ifdef _DEBUG
        static bool show_demo = false;
#endif

        // boot
        static bool once = true;
        if (once) {
            session::Session().is_elevated = IsProcessElevated();
            session::Session().il_rid = QueryCurrentIntegrityRid();
            strncpy_s(session::Session().il_text, sizeof(session::Session().il_text),
                IntegrityRidToCStr(session::Session().il_rid), _TRUNCATE);
            pipetap::log::App.Infof("UI boot: elevated=%d, IL=%s",
                (int)session::Session().is_elevated, session::Session().il_text);

            proxy.send_to_replay = [&](const std::string& pipe, const std::vector<uint8_t>& raw) {
                ui::replay::StartNewTabFromProxy(replay, pipe, raw);
                };

            pipelist.send_to_replay = proxy.send_to_replay;

            once = false;
        }

        // pump auto-connect if enabled
        ui::proxy::PumpAutoConnect(proxy);

        // maximize the content to fill the native window
        ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::SetNextWindowViewport(viewport->ID);

        ImGuiWindowFlags host_flags =
            ImGuiWindowFlags_MenuBar |
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoNavFocus |
            ImGuiWindowFlags_NoDocking;

        ImGuiWindowFlags child_flags =
            ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoScrollWithMouse;

        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(4, 4)); // tighten the window padding

        if (ImGui::Begin("pipetap", nullptr, host_flags)) {
            if (ImGui::BeginMenuBar()) {
                if (ImGui::BeginMenu("File")) {
                    const bool elevated = session::Session().is_elevated;
                    if (ImGui::MenuItem("Relaunch as Administrator", nullptr, false, !elevated)) {
                        RelaunchAsAdministrator();
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("About pipetap")) {
                        about_requested = true;
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("Exit")) PostQuitMessage(0);
                    ImGui::EndMenu();
                }
                if (ImGui::BeginMenu("View")) {
                    ImGui::MenuItem("Application Log", nullptr, &show_app_log);
#ifdef _DEBUG
                    ImGui::MenuItem("Debug Tools", nullptr, &show_demo);
#endif
                    ImGui::EndMenu();
                }
                if (ImGui::BeginMenu("Panels")) {
                    static bool want_focus_replay = false;
                    static bool want_focus_proxy = false;
                    static bool want_focus_injector = false;
                    static bool want_focus_pipelist = false;

                    if (ImGui::MenuItem("Proxy", nullptr, &show_proxy)) { if (show_proxy) want_focus_proxy = true; }
                    if (ImGui::MenuItem("Replay", nullptr, &show_replay)) { if (show_replay) want_focus_replay = true; }
                    if (ImGui::MenuItem("Injector", nullptr, &show_injector)) { if (show_injector) want_focus_injector = true; }
                    if (ImGui::MenuItem("Pipelist", nullptr, &show_pipelist)) { if (show_pipelist) want_focus_pipelist = true; }
                    ImGui::EndMenu();

                    if (want_focus_replay) { ImGui::SetWindowFocus("Replay");   want_focus_replay = false; }
                    if (want_focus_proxy) { ImGui::SetWindowFocus("Proxy");    want_focus_proxy = false; }
                    if (want_focus_injector) { ImGui::SetWindowFocus("Injector"); want_focus_injector = false; }
                    if (want_focus_pipelist) { ImGui::SetWindowFocus("Pipelist"); want_focus_pipelist = false; }
                }

                // right aligned elevation indicator
                const bool elevated = session::Session().is_elevated;
                if (elevated) {
                    const ImVec4 adminColor = ImVec4(1.0f, 0.2f, 0.2f, 1.0f);
                    MenuBarRightText("Administrator", &adminColor);
                }

                ImGui::EndMenuBar();
            }

            // --- About modal ---
            pipetap::ui::ShowAboutModal(&about_requested);

            // a dockspace that fills the rest of the window
            ImGui::BeginChild("##dock_host", ImVec2(0, 0), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
            {
                ImGuiID dockspace_id = ImGui::GetID("pipetap_inner_dockspace");
                ImGuiDockNodeFlags dock_flags = 0;

                ImVec2 dock_sz = ImGui::GetContentRegionAvail();
                if (dock_sz.x < 1.0f) dock_sz.x = 1.0f;
                if (dock_sz.y < 1.0f) dock_sz.y = 1.0f;

                ImGui::DockSpace(dockspace_id, dock_sz, dock_flags);

                struct PanelDef {
                    const char* name;
                    bool* visible;
                    ImGuiWindowFlags flags;
                    std::function<void()> draw;
                };

                static pipetap::sharedui::LogDrainState app_log_state;

                PanelDef panels[] = {
                    { "Proxy", &show_proxy, child_flags, [&]() { ui::proxy::Draw(proxy); } },
                    { "Replay", &show_replay, child_flags, [&]() { ui::replay::Draw(replay); } },
                    { "Injector", &show_injector, 0, [&]() { ui::injector::Draw(inj); } },
                    { "Pipelist", &show_pipelist, child_flags, [&]() { ui::pipelist::Draw(pipelist); } },
                    { "Application Log", &show_app_log, 0, [&]() {
                        const float h = ImGui::GetContentRegionAvail().y;
                        pipetap::sharedui::DrawLogDrainFeed("##app_log_feed", app_log_state, pipetap::log::App,
                            /*cap=*/4000,
                            /*height=*/h,
                            /*show_clear=*/true,
                            /*auto_scroll=*/true,
                            /*heading=*/"Application");
                    } },
                };

                for (auto& panel : panels) {
                    if (!panel.visible || !(*panel.visible)) continue;
                    ImGui::SetNextWindowDockID(dockspace_id, ImGuiCond_Appearing);
                    if (ImGui::Begin(panel.name, panel.visible, panel.flags)) {
                        panel.draw();
                    }
                    ImGui::End();
                }
#ifdef _DEBUG
                // demo that includes runtime debugging tools
                if (show_demo) {
                    ImGui::ShowDemoWindow();
                }
#endif

                if (focus_proxy_once) {
                    ImGui::SetWindowFocus("Proxy");   // selects the proxy tab on first run
                    focus_proxy_once = false;
                }
            }
            ImGui::EndChild();
        }
        ImGui::End();
        ImGui::PopStyleVar();
    }
} // namespace pipetap
