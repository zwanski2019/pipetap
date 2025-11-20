#pragma once

#include "imgui.h"

namespace pipetap::ui {

    // Vertical splitter controlling heights a/b.
    inline bool VSplitter(const char* id, float thickness, float min_a, float min_b, float& a, float& b) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.25f, 0.25f, 0.25f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.35f, 0.35f, 0.35f, 1.0f));
        ImGui::Button(id, ImVec2(-1.0f, thickness));
        bool active = ImGui::IsItemActive();
        bool hovered = ImGui::IsItemHovered();
        ImGui::PopStyleColor(3);
        if (hovered || active) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);

        bool changed = false;
        if (active) {
            float delta = ImGui::GetIO().MouseDelta.y;
            if (delta != 0.0f) {
                float na = a + delta;
                float nb = b - delta;
                if (na < min_a) { nb -= (min_a - na); na = min_a; }
                if (nb < min_b) { na -= (min_b - nb); nb = min_b; }
                a = na; b = nb; changed = true;
            }
        }
        return changed;
    }

    // Horizontal splitter using ratio.
    inline bool HSplitterRatio(const char* id, float thickness, float min_left, float min_right, float total_w, float& ratio) {
        float left_w = total_w * ratio;
        float right_w = total_w - left_w - thickness;
        if (left_w < min_left) left_w = min_left;
        if (right_w < min_right) { right_w = min_right; left_w = total_w - min_right - thickness; }

        ImGui::SameLine();
        ImGui::SetCursorPosX(ImGui::GetCursorPosX());

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.25f, 0.25f, 0.25f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.35f, 0.35f, 0.35f, 1.0f));
        ImGui::InvisibleButton(id, ImVec2(thickness, -1.0f));
        bool active = ImGui::IsItemActive();
        bool hovered = ImGui::IsItemHovered();
        ImGui::PopStyleColor(3);
        if (hovered || active) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);

        bool changed = false;
        if (active) {
            float delta = ImGui::GetIO().MouseDelta.x;
            if (delta != 0.0f) {
                float new_left = left_w + delta;
                if (new_left < min_left) new_left = min_left;
                if (new_left > total_w - thickness - min_right) new_left = total_w - thickness - min_right;
                ratio = (total_w > 0.0f) ? (new_left / total_w) : ratio;
                changed = true;
            }
        }
        return changed;
    }

} // namespace pipetap::ui
