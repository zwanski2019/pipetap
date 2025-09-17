#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "pipetap/version.h"
#include "ui/about.h"
#include <shellapi.h>
#include <string>


#pragma comment(lib, "Shell32.lib")

namespace {

    inline void Link(const char* label, const char* url)
    {
        // Style: slightly blue like a link
        const ImVec4 link_col(0.20f, 0.55f, 0.95f, 1.0f);

        ImGui::PushStyleColor(ImGuiCol_Text, link_col);
        ImGui::TextUnformatted(label);
        ImGui::PopStyleColor();

        // Make it feel like a link: underline on hover and hand cursor.
        if (ImGui::IsItemHovered()) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
            // underline
            ImVec2 min = ImGui::GetItemRectMin();
            ImVec2 max = ImGui::GetItemRectMax();
            auto* dl = ImGui::GetWindowDrawList();
            dl->AddLine(ImVec2(min.x, max.y - 1.0f), ImVec2(max.x, max.y - 1.0f),
                ImGui::GetColorU32(link_col));
            if (ImGui::IsItemClicked()) {
                ShellExecuteA(nullptr, "open", url, nullptr, nullptr, SW_SHOWNORMAL);
            }
        }
    }

} // namespace

namespace pipetap::ui {

    void ShowAboutModal(bool* p_open_request)
    {
        if (!p_open_request) return;

        if (*p_open_request) {
            ImGui::OpenPopup("About##pipetap");
            *p_open_request = false;
        }

        // Bind and center on main viewport when (re)appearing
        ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowViewport(vp->ID);
        ImGui::SetNextWindowPos(vp->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        ImGui::SetNextWindowSize(ImVec2(420, 0), ImGuiCond_Appearing);

        if (ImGui::BeginPopupModal("About##pipetap", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            // Derive a small arch string
            const char* arch =
#if defined(_WIN64)
                "x64";
#elif defined(_M_IX86)
                "x86";
#else
                "unknown";
#endif

            // Build configuration
            const char* cfg =
#if defined(_DEBUG)
                "Debug";
#else
                "Release";
#endif
            ImGui::TextUnformatted("pipetap by ");
            ImGui::SameLine(0, 0); Link("@leonjza", "https://x.com/leonjza");
            ImGui::SameLine(0, 0); ImGui::TextUnformatted(" / ");
            ImGui::SameLine(0, 0); Link("@sensepost", "https://x.com/sensepost");
            ImGui::Separator();

            // Key/Value section with aligned colons
            if (ImGui::BeginTable("about_kv", 2, ImGuiTableFlags_SizingFixedFit)) {
                ImGui::TableSetupColumn("k", ImGuiTableColumnFlags_WidthFixed, 85.0f); // tweak width as desired
                ImGui::TableSetupColumn("v", ImGuiTableColumnFlags_WidthStretch);

                auto row = [](const char* k, auto&& drawValue) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%s:", k);
                    ImGui::TableSetColumnIndex(1);
                    drawValue();
                    };

                row("Version", [] {
                    ImGui::TextUnformatted(pipetap::version_string().c_str());
                    });

                row("Build", [arch] {
                    ImGui::Text("%s %s (%s)", __DATE__, __TIME__, arch);
                    });

                row("Config", [cfg] {
                    ImGui::TextUnformatted(cfg);
                    });

#if defined(_MSC_FULL_VER)
                row("Compiler", [] {
                    ImGui::Text("MSVC %d", (int)_MSC_FULL_VER);
                    });
#endif

                row("ImGui", [] {
                    ImGui::TextUnformatted(ImGui::GetVersion());
                    });

                row("Source", [] {
                    Link("github.com/sensepost/pipetap", "https://github.com/sensepost/pipetap");
                    });

                ImGui::EndTable();
            }

            ImGui::NewLine();
            ImGui::TextWrapped(
                "pipetap is a Windows named pipe analysis and replay tool.\n"
                "Use Proxy to capture traffic, Replay to craft requests, "
                "Injector to load the support DLL, and Pipelist to browse pipes."
            );
            ImGui::NewLine();

            if (ImGui::Button("OK", ImVec2(120, 0))) {
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
    }

} // namespace pipetap::ui
