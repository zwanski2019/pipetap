#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "imgui.h"
#include "ui/clipboard.h"
#include "ui/ellipsize.h"
#include "ui/pipelist.h"
#include "win/pipes_enum.h"
#include "win/unicode.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cwchar>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <Windows.h>

namespace pipetap::ui::pipelist {

    using pipetap::ui::EllipsizeToWidth;
    using pipetap::ui::CopyUnicodeAndAnsiTextToClipboard;
    using pipetap::win::RiskEval;
    using pipetap::win::Utf8ToWide;
    using pipetap::win::WideToUtf8;
    using pipetap::win::AssessAclRiskFromText;
    using pipetap::win::ReadDaclForPipeW;
    using pipetap::win::EnumeratePipeNames;
    using pipetap::win::ProcNameFromPidA;

    namespace {
        struct PidNameCache {
            std::mutex mtx;
            std::unordered_map<DWORD, std::string> map;
            static constexpr size_t kMaxEntries = 4096;

            std::string get_or_resolve(DWORD pid) {
                if (pid == 0) return {};
                {
                    std::lock_guard<std::mutex> _{ mtx };
                    auto it = map.find(pid);
                    if (it != map.end()) return it->second;
                }
                std::string name;
                ProcNameFromPidA(pid, name);
                {
                    std::lock_guard<std::mutex> _{ mtx };
                    if (map.size() >= kMaxEntries) map.clear();
                    map.emplace(pid, name);
                }
                return name;
            }
        };

        PidNameCache g_pid_cache;
    }

    static const char* StateToText(Row::PipeState s) {
        switch (s) {
        case Row::PipeState::Open:     return "Open";
        case Row::PipeState::Busy:     return "Busy";
        case Row::PipeState::Denied:   return "Denied";
        case Row::PipeState::NotFound: return "NotFound";
        case Row::PipeState::Error:    return "Error";
        default:                       return "Unknown";
        }
    }

    static int StateRank(Row::PipeState s) {
        switch (s) {
        case Row::PipeState::Open:     return 0;
        case Row::PipeState::Busy:     return 1;
        case Row::PipeState::Denied:   return 2;
        case Row::PipeState::NotFound: return 3;
        case Row::PipeState::Error:    return 4;
        default:                       return 5;
        }
    }

    static ImU32 ColorForState(Row::PipeState s) {
        switch (s) {
        case Row::PipeState::Open:     return IM_COL32(40, 200, 90, 255);
        case Row::PipeState::Busy:     return IM_COL32(230, 180, 60, 255);
        case Row::PipeState::Denied:   return IM_COL32(235, 80, 80, 255);
        case Row::PipeState::NotFound: return IM_COL32(150, 150, 150, 255);
        case Row::PipeState::Error:    return IM_COL32(235, 80, 160, 255);
        default:                       return IM_COL32(160, 160, 160, 255);
        }
    }
    static ImU32 ColorForAclRiskLevel(int lvl) {
        switch (lvl) {
        case 2: return IM_COL32(235, 80, 80, 255);
        case 1: return IM_COL32(230, 180, 60, 255);
        default:return IM_COL32(40, 200, 90, 255);
        }
    }

    static const char* DataTypeText(Row::DataType t) {
        switch (t) {
        case Row::DataType::Message: return "msg";
        case Row::DataType::Byte:    return "byte";
        default:                     return "";
        }
    }

    static int RankDataType(Row::DataType t) {
        switch (t) {
        case Row::DataType::Message: return 0;
        case Row::DataType::Byte:    return 1;
        default:                     return 2;
        }
    }

    static std::string MakeAclRiskPreview(const std::string& dacl_text, int ace_count) {
        RiskEval r = AssessAclRiskFromText(dacl_text);
        char buf[128];
        if (ace_count >= 0)
            std::snprintf(buf, sizeof(buf), "%s  (%d ACEs)", r.reason.c_str(), ace_count);
        else
            std::snprintf(buf, sizeof(buf), "%s", r.reason.c_str());
        return std::string(buf);
    }

    static void FillRowRuntimeInfo(Row& r, int wait_ms, bool aggressive)
    {
        r.server_pid = 0;
        r.proc_name[0] = '\0';
        r.state = Row::PipeState::Unknown;

        r.data_type = Row::DataType::Unknown;

        r.cur_instances = 0;
        r.max_instances = 0;
        r.open_err = 0;
        r.acl_err = 0;
        r.ace_count = -1;
        r.dacl.clear();
        r.dacl_preview.clear();
        r.acl_risk_level = -1;
        r.acl_network_access = false;

        const std::wstring wpath = Utf8ToWide(r.path.c_str());
        const DWORD kWait = (wait_ms >= 0) ? (DWORD)wait_ms : 20;

        // Safe enumeration: avoid touching pipe endpoints entirely to not disturb fragile servers.
        if (!aggressive) {
            r.state = Row::PipeState::Unknown;
            r.open_err = 0;
            r.dacl = "(not queried; safe mode)";
            r.dacl_preview = "not queried (safe mode)";
            r.acl_err = 0;
            r.ace_count = -1;
            r.acl_risk_level = -1;
            r.acl_network_access = false;
            return;
        }

        BOOL wait_ok = WaitNamedPipeW(wpath.c_str(), kWait);
        if (!wait_ok) {
            DWORD le = GetLastError();
            r.open_err = le;
            if (le == ERROR_PIPE_BUSY || le == ERROR_SEM_TIMEOUT)       r.state = Row::PipeState::Busy;
            else if (le == ERROR_FILE_NOT_FOUND)                        r.state = Row::PipeState::NotFound;
            else if (le == ERROR_ACCESS_DENIED)                         r.state = Row::PipeState::Denied;
            else                                                        r.state = Row::PipeState::Error;

            r.dacl = ReadDaclForPipeW(wpath, INVALID_HANDLE_VALUE, r.acl_err, r.ace_count);
            RiskEval rsk = AssessAclRiskFromText(r.dacl);
            r.acl_risk_level = rsk.level;
            r.acl_network_access = rsk.network_access;
            r.dacl_preview = MakeAclRiskPreview(r.dacl, r.ace_count);
            return;
        }

        HANDLE h = INVALID_HANDLE_VALUE;

        auto try_open = [&](DWORD access) -> bool {
            h = CreateFileW(wpath.c_str(), access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (h != INVALID_HANDLE_VALUE) return true;
            r.open_err = GetLastError();
            return false;
            };

        bool opened =
            try_open(GENERIC_READ | GENERIC_WRITE) ||
            try_open(GENERIC_READ) ||
            try_open(GENERIC_WRITE);

        if (!opened) {
            DWORD le = r.open_err;
            if (le == ERROR_PIPE_BUSY)           r.state = Row::PipeState::Busy;
            else if (le == ERROR_ACCESS_DENIED)  r.state = Row::PipeState::Denied;
            else if (le == ERROR_FILE_NOT_FOUND) r.state = Row::PipeState::NotFound;
            else                                 r.state = Row::PipeState::Error;

            r.dacl = ReadDaclForPipeW(wpath, INVALID_HANDLE_VALUE, r.acl_err, r.ace_count);
            RiskEval rsk = AssessAclRiskFromText(r.dacl);
            r.acl_risk_level = rsk.level;
            r.acl_network_access = rsk.network_access;
            r.dacl_preview = MakeAclRiskPreview(r.dacl, r.ace_count);
            return;
        }

        r.state = Row::PipeState::Open;

        if (h != INVALID_HANDLE_VALUE) {
            ULONG spid = 0;
            using PFN_GetNamedPipeServerProcessId = BOOL(WINAPI*)(HANDLE, PULONG);
            static PFN_GetNamedPipeServerProcessId pGetPid =
                (PFN_GetNamedPipeServerProcessId)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                    "GetNamedPipeServerProcessId");
            if (pGetPid && pGetPid(h, &spid)) {
                r.server_pid = (DWORD)spid;
                std::string pname = g_pid_cache.get_or_resolve(r.server_pid);
                if (!pname.empty()) {
                    _snprintf_s(r.proc_name, sizeof(r.proc_name), _TRUNCATE, "%s", pname.c_str());
                }
            }

            DWORD flags_info = 0, outSz = 0, inSz = 0, maxInst = 0;
            if (GetNamedPipeInfo(h, &flags_info, &outSz, &inSz, &maxInst)) {
                const bool is_msg_type = (flags_info & PIPE_TYPE_MESSAGE) != 0;

                r.data_type = is_msg_type ? Row::DataType::Message : Row::DataType::Byte;
                r.max_instances = maxInst;

                DWORD curInst = 0, flags_state = 0;
                if (GetNamedPipeHandleStateW(h, &flags_state, &curInst, nullptr, nullptr, nullptr, 0)) {
                    r.cur_instances = curInst;
                }
            }
            else {
                DWORD dummy_flags = 0, outSz2 = 0, inSz2 = 0, maxInst2 = 0;
                if (GetNamedPipeInfo(h, &dummy_flags, &outSz2, &inSz2, &maxInst2)) {
                    r.data_type = (dummy_flags & PIPE_TYPE_MESSAGE) ? Row::DataType::Message : Row::DataType::Byte;
                    r.max_instances = maxInst2;
                }
                DWORD curInst = 0, flags_state = 0;
                if (GetNamedPipeHandleStateW(h, &flags_state, &curInst, nullptr, nullptr, nullptr, 0)) {
                    r.cur_instances = curInst;
                }
            }
        }

        r.dacl = ReadDaclForPipeW(wpath, h, r.acl_err, r.ace_count);
        RiskEval rsk = AssessAclRiskFromText(r.dacl);
        r.acl_risk_level = rsk.level;
        r.acl_network_access = rsk.network_access;
        r.dacl_preview = MakeAclRiskPreview(r.dacl, r.ace_count);

        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }

    static void DoEnumerateOnce(std::stop_token st, std::vector<Row>& out_rows, int wait_ms, bool aggressive) {
        std::vector<std::string> names;
        EnumeratePipeNames(names);

        out_rows.clear();
        out_rows.resize(names.size());

        unsigned hc = std::max(2u, std::thread::hardware_concurrency());
        const unsigned kMaxWorkers = 8;
        const unsigned par = std::min(hc, kMaxWorkers);

        std::atomic<size_t> next_idx{ 0 };

        auto worker_fn = [&](std::stop_token wst) {
            while (!wst.stop_requested() && !st.stop_requested()) {
                size_t i = next_idx.fetch_add(1, std::memory_order_relaxed);
                if (i >= names.size()) break;

                Row r;
                r.name = names[i];
                r.path = std::string(R"(\\.\pipe\)") + r.name;

                FillRowRuntimeInfo(r, wait_ms, aggressive);

                out_rows[i] = std::move(r);
            }
            };

        std::vector<std::jthread> workers;
        workers.reserve(par);
        for (unsigned t = 0; t < par; ++t) {
            if (st.stop_requested()) break;
            workers.emplace_back(worker_fn);
        }

        for (auto& th : workers) {
            if (th.joinable()) th.join();
        }
    }

    static void StartRefresh(VM& vm) {
        if (vm.shutting_down.load(std::memory_order_acquire)) return;
        if (vm.resolving.load(std::memory_order_acquire)) return;

        if (vm.worker.joinable()) vm.worker.join();

        vm.resolving.store(true, std::memory_order_release);
        vm.resolving_started_at = ImGui::GetTime();

        const int wait_ms = vm.wait_timeout_ms;
        const bool aggressive = vm.aggressive;

        vm.worker = std::jthread([&vm, wait_ms, aggressive](std::stop_token st) {
            struct ScopeReset {
                std::atomic<bool>& flag;
                ~ScopeReset() { flag.store(false, std::memory_order_release); }
            } sr{ vm.resolving };

            if (vm.shutting_down.load(std::memory_order_acquire) || st.stop_requested()) return;

            std::vector<Row> fresh;
            DoEnumerateOnce(st, fresh, wait_ms, aggressive);
            if (vm.shutting_down.load(std::memory_order_acquire) || st.stop_requested()) return;

            {
                std::lock_guard<std::mutex> _{ vm.rows_mtx };
                vm.rows.swap(fresh);
            }
            vm.last_refresh_tp = std::chrono::steady_clock::now();
            });
    }

    void Draw(VM& vm) {
        if (vm.shutting_down.load(std::memory_order_acquire)) return;

        ImGui::SeparatorText("Pipelist");

        ImGui::SetNextItemWidth(220.0f);
        ImGui::InputTextWithHint("##pl_filter", "filter (name/process/acl)", vm.filter, IM_ARRAYSIZE(vm.filter));
        ImGui::SameLine();
        if (ImGui::Button("Refresh")) vm.need_refresh = true;
        ImGui::SameLine();
        if (ImGui::Checkbox("Aggressive (opens pipes)", &vm.aggressive)) {
            vm.need_refresh = true;
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone)) {
            ImGui::SetTooltip("Opens each pipe handle to query PID/instances/type; may disturb servers.");
        }
        if (vm.resolving.load(std::memory_order_acquire)) {
            ImGui::SameLine();
            float elapsed = (float)(ImGui::GetTime() - vm.resolving_started_at);
            const float t = fmodf((float)ImGui::GetTime() * 0.35f, 1.0f);
            ImGui::SetNextItemWidth(160.0f);
            ImGui::ProgressBar(t, ImVec2(0, 0), "resolving...");
            ImGui::SameLine();
            ImGui::TextDisabled("(%.1fs)", elapsed);
        }

        if (vm.need_refresh && !vm.shutting_down.load(std::memory_order_acquire)) {
            StartRefresh(vm);
            vm.need_refresh = false;
        }

        std::vector<Row> snapshot;
        {
            std::lock_guard<std::mutex> lock(vm.rows_mtx);
            snapshot = vm.rows;
        }

        ImGui::SameLine();
        {
            char buf[64];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Pipes: %zu", snapshot.size());
            float text_w = ImGui::CalcTextSize(buf).x;
            float avail = ImGui::GetContentRegionAvail().x;
            if (text_w < avail) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (avail - text_w));
            ImGui::TextDisabled("%s", buf);
        }

        ImGui::Separator();

        std::vector<int> index_map;
        index_map.reserve(snapshot.size());
        std::string needle = vm.filter[0] ? std::string(vm.filter) : std::string();
        std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c) { return (char)std::tolower(c); });

        for (int i = 0; i < (int)snapshot.size(); ++i) {
            const Row& r = snapshot[i];
            if (!needle.empty()) {
                std::string hay = r.name + " " + r.path + " " + r.dacl + " " + std::string(r.proc_name);
                std::transform(hay.begin(), hay.end(), hay.begin(), [](unsigned char c) { return (char)std::tolower(c); });
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

        if (ImGui::BeginTable("##pipelist_tbl", 7, flags, ImVec2(0, 0))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Pipe", ImGuiTableColumnFlags_WidthFixed, 240.f);
            ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 72.f);
            ImGui::TableSetupColumn("PID",
                ImGuiTableColumnFlags_WidthFixed
                | ImGuiTableColumnFlags_DefaultSort
                | ImGuiTableColumnFlags_PreferSortDescending, 56.f);
            ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthFixed, 180.f);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 56.f); // msg/byte (data type)
            ImGui::TableSetupColumn("Inst", ImGuiTableColumnFlags_WidthFixed, 80.f);
            ImGui::TableSetupColumn("ACL (summary)", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sort = ImGui::TableGetSortSpecs()) {
                if (sort->SpecsCount == 1) {
                    const ImGuiTableColumnSortSpecs& sp = sort->Specs[0];
                    const bool asc = (sp.SortDirection == ImGuiSortDirection_Ascending);
                    auto cmp = [&](int ia, int ib) {
                        const Row& a = snapshot[ia];
                        const Row& b = snapshot[ib];
                        switch (sp.ColumnIndex) {
                        case 0: return asc ? (a.name < b.name) : (a.name > b.name);
                        case 1: return asc ? (StateRank(a.state) < StateRank(b.state)) : (StateRank(a.state) > StateRank(b.state));
                        case 2: return asc ? (a.server_pid < b.server_pid) : (a.server_pid > b.server_pid);
                        case 3: return asc ? (std::string(a.proc_name) < std::string(b.proc_name))
                            : (std::string(a.proc_name) > std::string(b.proc_name));
                        case 4: { // Type (data type)
                            int ra = RankDataType(a.data_type), rb = RankDataType(b.data_type);
                            if (ra != rb) return asc ? (ra < rb) : (ra > rb);
                            return asc ? (std::string(DataTypeText(a.data_type)) < std::string(DataTypeText(b.data_type)))
                                : (std::string(DataTypeText(a.data_type)) > std::string(DataTypeText(b.data_type)));
                        }
                        case 5:
                            if (a.cur_instances != b.cur_instances) return asc ? (a.cur_instances < b.cur_instances) : (a.cur_instances > b.cur_instances);
                            return asc ? (a.max_instances < b.max_instances) : (a.max_instances > b.max_instances);
                        case 6: {
                            int la = a.acl_risk_level, lb = b.acl_risk_level;
                            if (la != lb) return asc ? (la < lb) : (la > lb);
                            return asc ? (a.dacl_preview < b.dacl_preview) : (a.dacl_preview > b.dacl_preview);
                        }
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
                    const Row& row = snapshot[index_map[r]];
                    ImGui::TableNextRow();

                    ImGui::PushID(index_map[r]);
                    ImGui::TableNextColumn();
                    ImVec2 cur = ImGui::GetCursorPos();

                    float row_h = ImGui::GetTextLineHeightWithSpacing();
                    ImGui::Selectable("##rowctx",
                        false,
                        ImGuiSelectableFlags_SpanAllColumns,
                        ImVec2(0, row_h));

                    if (ImGui::BeginPopupContextItem("##row_popup")) {
                        if (ImGui::MenuItem("Copy")) {
                            std::string text;
                            text.reserve(512);
                            text += "Pipe: ";       text += row.path;                      text += "\r\n";
                            text += "State: ";      text += StateToText(row.state);        text += "\r\n";
                            if (row.open_err) { text += "LastError: "; text += std::to_string(row.open_err); text += "\r\n"; }
                            if (row.server_pid) {
                                text += "Server PID: "; text += std::to_string(row.server_pid); text += "\r\n";
                                if (row.proc_name[0]) { text += "Process: "; text += row.proc_name; text += "\r\n"; }
                            }
                            {
                                text += "Type: "; text += DataTypeText(row.data_type); text += "\r\n";
                            }
                            if (row.max_instances || row.cur_instances) {
                                text += "Instances: ";
                                text += std::to_string(row.cur_instances); text += "/";
                                text += std::to_string(row.max_instances); text += "\r\n";
                            }
                            RiskEval risk = AssessAclRiskFromText(row.dacl);
                            if (risk.network_access) {
                                text += "Network: allowed\r\n";
                            }
                            if (!row.dacl.empty()) {
                                text += "ACL note: "; text += risk.reason; text += "\r\n";
                                text += "DACL:\r\n";
                                text += row.dacl;
                                if (text.size() < 2 || text[text.size() - 2] != '\r') text += "\r\n";
                            }
                            else {
                                text += "DACL: ";
                                if (row.acl_err) text += "n/a (err=" + std::to_string(row.acl_err) + ")";
                                else text += "not available";
                                text += "\r\n";
                            }
                            CopyUnicodeAndAnsiTextToClipboard(text);
                        }

                        if (ImGui::MenuItem("Send to Replay", nullptr, false, vm.send_to_replay != nullptr)) {
                            if (vm.send_to_replay) {
                                {
                                    vm.send_to_replay(row.path, {});
                                }
                            }
                        }

                        ImGui::EndPopup();
                    }

                    ImGui::SetCursorPos(cur);

                    {
                        float cell_w = ImGui::GetColumnWidth() - ImGui::GetStyle().CellPadding.x * 2.0f;
                        std::string clipped = EllipsizeToWidth(row.name, cell_w);
                        ImGui::TextUnformatted(clipped.c_str());
                        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone | ImGuiHoveredFlags_NoSharedDelay)) {
                            ImGui::BeginTooltip();
                            ImGui::TextUnformatted(row.path.c_str());
                            ImGui::Separator();
                            ImGui::Text("State: %s  (open_err=%lu)", StateToText(row.state), (unsigned long)row.open_err);
                            ImGui::EndTooltip();
                        }
                    }

                    ImGui::TableNextColumn();
                    {
                        ImU32 col = ColorForState(row.state);
                        ImGui::PushStyleColor(ImGuiCol_Text, col);
                        ImGui::TextUnformatted(StateToText(row.state));
                        ImGui::PopStyleColor();
                    }

                    ImGui::TableNextColumn();
                    if (row.server_pid) ImGui::Text("%lu", (unsigned long)row.server_pid);
                    else ImGui::TextUnformatted("");

                    ImGui::TableNextColumn();
                    {
                        float cell_w = ImGui::GetColumnWidth() - ImGui::GetStyle().CellPadding.x * 2.0f;
                        std::string clipped = EllipsizeToWidth(row.proc_name[0] ? row.proc_name : "", cell_w);
                        ImGui::TextUnformatted(clipped.c_str());
                        if (row.proc_name[0] && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone | ImGuiHoveredFlags_NoSharedDelay)) {
                            ImGui::BeginTooltip();
                            ImGui::TextUnformatted(row.proc_name);
                            ImGui::EndTooltip();
                        }
                    }

                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(DataTypeText(row.data_type));

                    ImGui::TableNextColumn();
                    if (row.max_instances || row.cur_instances)
                        ImGui::Text("%lu/%lu", (unsigned long)row.cur_instances, (unsigned long)row.max_instances);
                    else
                        ImGui::TextUnformatted("");

                    ImGui::TableNextColumn();
                    {
                        RiskEval risk = row.acl_risk_level >= 0
                            ? RiskEval{ row.acl_risk_level, row.dacl_preview, row.acl_network_access }
                            : AssessAclRiskFromText(row.dacl);
                        ImU32 col = ColorForAclRiskLevel(risk.level);
                        const std::string& preview = row.dacl_preview.empty()
                            ? MakeAclRiskPreview(row.dacl, row.ace_count)
                            : row.dacl_preview;

                        float cell_w = ImGui::GetColumnWidth() - ImGui::GetStyle().CellPadding.x * 2.0f;
                        std::string clipped = EllipsizeToWidth(preview, cell_w);

                        ImGui::PushStyleColor(ImGuiCol_Text, col);
                        ImGui::TextUnformatted(clipped.c_str());
                        ImGui::PopStyleColor();

                        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone | ImGuiHoveredFlags_NoSharedDelay)) {
                            ImGui::BeginTooltip();
                            ImGui::TextUnformatted(row.path.c_str());
                            ImGui::Separator();
                            ImGui::Text("State: %s  (open_err=%lu)", StateToText(row.state), (unsigned long)row.open_err);
                            if (row.max_instances || row.cur_instances ||
                                row.data_type != Row::DataType::Unknown) {
                                ImGui::Text("Type: %s Inst: %lu/%lu",
                                    DataTypeText(row.data_type),
                                    (unsigned long)row.cur_instances,
                                    (unsigned long)row.max_instances);
                            }
                            if (row.acl_err) {
                                ImGui::Separator();
                                ImGui::TextDisabled("ACL note: err=%lu", (unsigned long)row.acl_err);
                            }
                            if (row.ace_count >= 0) {
                                ImGui::TextDisabled("ACE count: %d", row.ace_count);
                            }
                            if (risk.network_access) {
                                ImGui::TextDisabled("Network: allowed");
                            }
                            ImGui::Separator();
                            if (row.dacl.empty()) {
                                if (row.acl_err) ImGui::TextDisabled("ACL error: %lu", (unsigned long)row.acl_err);
                                else ImGui::TextUnformatted("ACL not available.");
                            }
                            else {
                                ImGui::TextUnformatted(row.dacl.c_str());
                            }
                            ImGui::EndTooltip();
                        }
                    }

                    ImGui::PopID(); // row context id
                }
            }
            ImGui::EndTable();
        }
    }

    void Dispose(VM& vm) {
        vm.shutting_down.store(true, std::memory_order_release);

        if (vm.worker.joinable()) {
            vm.worker.request_stop();
            vm.worker.join();
        }

        vm.resolving.store(false, std::memory_order_release);
        vm.need_refresh = false;
    }

} // namespace pipetap::ui::pipelist
