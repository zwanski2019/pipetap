#pragma once

#include "ctrlclient.h"
#include "pipetap/controlpipe.h"
#include "ui/sharedui.h"
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

//namespace pipetap::ctrlclient { class CtrlClient; }

namespace pipetap::ui::proxy {

    struct State {
        uint64_t pending_req_op = 0;
        uint64_t pending_resp_op = 0;

        char req_buf[4096] = {};
        char resp_buf[4096] = {};

        char req_original[4096] = {};
        char resp_original[4096] = {};

        char req_pipe[128] = {};
        char resp_pipe[128] = {};

        std::vector<sharedui::MsgLogEntry> log;
        int selected_row = -1;

        std::mutex log_mtx;
        std::mutex edit_mtx;
    };


    struct Tab {
        unsigned pid = 0;
        std::unique_ptr<ctrlclient::CtrlClient> client;
        State    s;

        float edit_h = 260.0f;   // editors block height
        float data_h = 80.0f;   // selection block height

        float edit_split_ratio = 0.50f; // request | response

        bool edit_requests = false;     // default: off (hide editors when both are off)
        bool edit_responses = false;    // default: off

        int   filter_dir = 0;       // 0=All, 1=Out, 2=In
        char  filter_text[128] = {};

        bool  has_unseen = false;
    };

    struct Manager {
        std::vector<std::unique_ptr<Tab>> tabs;
        int  active = -1;
        bool panel_focused = false;

        sharedui::SendToReplayFn send_to_replay;
    };

    void PumpAutoConnect(Manager& m);
    void StartNewTabAndConnect(Manager& m, std::uint32_t pid);
    void Draw(Manager& m);

    using BoundCtrlHandler = std::function<void(const PT_ControlFrame&)>;
    BoundCtrlHandler BindHandler(Manager& m);

} // namespace pipetap::ui::proxy
