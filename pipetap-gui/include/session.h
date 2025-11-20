#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "log.h"
#include "pipetap/controlpipe.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <Windows.h>

namespace pipetap::session {

    struct SessionState {
        DWORD ctrl_pid = 0;
        char  ctrl_pipe[128] = { 0 };  // display-only: "\\.\pipe\pipetap.ctrl.ev.<pid>"

        bool  is_elevated = false;     // TOKEN_ELEVATION.TokenIsElevated != 0
        DWORD il_rid = 0;              // SECURITY_MANDATORY_*_RID
        char  il_text[32] = {};        // "Low", "Medium", "High", "System", "Protected", ...

        std::atomic<DWORD> last_injected_pid{ 0 };
        std::atomic_bool auto_connect_proxy{ true };
    };

    inline SessionState& Session() { static SessionState s; return s; }

    inline void UpdateControlPipeForPid(DWORD pid) {
        Session().ctrl_pid = pid;
        std::snprintf(Session().ctrl_pipe, sizeof(Session().ctrl_pipe),
            "%s%lu", PT_CTRL_EVENTS_PREFIX, (unsigned long)pid);
        pipetap::log::App.Info((std::string("[control] target set to ") + Session().ctrl_pipe).c_str());
    }

    inline void NoteInjectedPid(DWORD pid) {
        Session().last_injected_pid.store(pid);
        pipetap::log::App.Info((std::string("[injector] noted pid ") + std::to_string(pid) + " for proxy tab").c_str());
    }

} // namespace pipetap::session
