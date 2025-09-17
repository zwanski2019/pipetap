#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "log.h"
#include <atomic>
#include <mutex>
#include <string>
#include <utility>
#include <vector>
#include <Windows.h>


namespace pipetap::injection {

    struct ProcInfo {
        unsigned    pid = 0;
        std::string name;
        std::string arch;       // "x64" / "x86" / "?"
        std::string il;         // "Low/Medium/High/System/Protected/Unknown"
        DWORD       session_id = 0;
        bool        is_system = false;
        std::string user;
    };

    // view model for the UI
    struct VM {
        char filter[128] = {};
        int selected_index = -1;
        std::vector<ProcInfo> processes;

        unsigned pid_manual = 0;
        char dll_path[260] = {};

        std::atomic_bool injecting{ false };
        bool need_refresh = true;
        bool dll_defaulted = false;

        // log events
        pipetap::log::Channel* log_ch = nullptr;                // set once in UI
        std::string                     log_channel_name;       // for debugging/inspection

        // UI niceties
        bool autoscroll_log = true;
    };

    // backend ops
    void RefreshProcesses(VM& s);
    void GetDefaultDllPath(char* out, size_t outsz);
    void DoInject(VM* s);

} // namespace pipetap::injection
