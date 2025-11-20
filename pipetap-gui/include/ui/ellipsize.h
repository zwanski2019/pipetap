#pragma once

#include "imgui.h"
#include <algorithm>
#include <string>

namespace pipetap::ui {

    inline std::string EllipsizeToWidth(const std::string& s, float max_w) {
        if (max_w <= 0.f) return s;
        ImVec2 full = ImGui::CalcTextSize(s.c_str());
        if (full.x <= max_w) return s;
        const char* dots = "...";
        ImVec2 dsz = ImGui::CalcTextSize(dots);
        if (dsz.x >= max_w) return std::string();
        int lo = 0, hi = (int)s.size();
        while (lo < hi) {
            int mid = (lo + hi) / 2;
            std::string t = s.substr(0, mid) + dots;
            float w = ImGui::CalcTextSize(t.c_str()).x;
            if (w <= max_w) lo = mid + 1; else hi = mid;
        }
        int take = (std::max)(0, lo - 1);
        return s.substr(0, take) + dots;
    }

} // namespace pipetap::ui
