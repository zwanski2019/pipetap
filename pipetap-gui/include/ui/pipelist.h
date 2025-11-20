#pragma once

#include "ui/sharedui.h"
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <Windows.h>

namespace pipetap::ui::pipelist {

    struct Row {
        std::string name;        // just "spoolss"
        std::string path;        // "\\.\pipe\spoolss"

        DWORD       server_pid = 0;
        char        proc_name[64] = {};

        enum class PipeState : uint8_t { Unknown, Open, Busy, Denied, NotFound, Error };
        PipeState   state = PipeState::Unknown;

        enum class DataType : uint8_t { Unknown, Byte, Message };

        DataType    data_type = DataType::Unknown;      // PIPE_TYPE_MESSAGE vs byte
        DWORD       cur_instances = 0;                  // if queried
        DWORD       max_instances = 0;                  // if queried
        DWORD       open_err = 0;                       // last CreateFile/WaitNamedPipe error

        std::string dacl;                               // multi-line, full text (tooltip)
        std::string dacl_preview;                       // compact single-line preview (table cell)
        DWORD       acl_err = 0;                        // last ACL query error (0 = ok)
        int         ace_count = -1;                     // ALLOW/DENY ACEs parsed; -1 unknown
        int         acl_risk_level = 0;                 // 0=low, 1=medium, 2=high (cached)
        bool        acl_network_access = false;         // cached
    };

    struct VM {
        std::vector<Row> rows;

        char  filter[96] = {};
        bool  need_refresh = false;
        bool  aggressive = false;            // when true, opens pipes to query PID/inst/type

        int   wait_timeout_ms = 80;

        std::atomic<bool> resolving{ false };
        std::atomic<bool> shutting_down{ false };
        std::mutex rows_mtx;
        std::jthread worker;

        std::chrono::steady_clock::time_point last_refresh_tp{};
        double resolving_started_at = 0.0;   // UI timestamp to mimic proxy-style progress

        sharedui::SendToReplayFn send_to_replay;
    };

    void Draw(VM& vm);
    void Dispose(VM& vm);
}
