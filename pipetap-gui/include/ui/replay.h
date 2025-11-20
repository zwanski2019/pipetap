#pragma once

#include "transport/namedpipe_client.h"
#include "transport/remote_namedpipe_client.h"
#include "ui/hex_editor.h"
#include "ui/sharedui.h"
#include <memory>
#include <string>
#include <vector>

namespace pipetap::ui::replay {

    struct PipeClientDeleter {
        void operator()(pipetap::transport::NamedPipeClient*) noexcept;
    };
    using NamedPipeClientPtr = std::unique_ptr<pipetap::transport::NamedPipeClient, PipeClientDeleter>;

    struct State {
        NamedPipeClientPtr client;
        bool   connecting = false;
        double connect_started_at = 0.0;
        bool   use_remote = false;
        uint32_t remote_pid = 0;
        std::unique_ptr<pipetap::transport::RemoteNamedPipeClient> rclient;

        char target_pipe[260] = {};

        char        tx_buf[4096] = {};
        std::vector<ImU8> tx_bytes;
        MemoryEditor      tx_hex;
        bool        tx_is_hex = false;
        bool        tx_text_is_wide = false;
        std::string rx_text;

        std::vector<sharedui::MsgLogEntry> log;
        int selected_row = -1;

        int  filter_dir = 0;
        char filter_text[128] = {};

        bool        status_expanded = false;
        std::string status_channel;

        bool focus_editor_next = false;

        ~State();
    };

    struct Tab {
        State s;
        bool has_unseen = false;
    };

    struct Manager {
        std::vector<std::unique_ptr<Tab>> tabs;
        int  active = -1;
        bool panel_focused = false;
        int  next_ordinal = 1;
    };

    void StartNewTabFromProxy(Manager& m, const std::string& pipe, const std::vector<uint8_t>& raw);
    void Draw(Manager& m);

} // namespace pipetap::ui::replay
