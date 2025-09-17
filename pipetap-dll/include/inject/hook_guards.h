#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace pipetap::inject {

    // Re-entrancy suppression for control-pipe IO and other internal calls.
    extern __declspec(thread) int tls_suppress_hooks;
    struct SuppressHooksGuard {
        SuppressHooksGuard() { ++tls_suppress_hooks; }
        ~SuppressHooksGuard() { --tls_suppress_hooks; }
        SuppressHooksGuard(const SuppressHooksGuard&) = delete;
        SuppressHooksGuard& operator=(const SuppressHooksGuard&) = delete;
    };

    // Marks execution from Win32 layer hooks so ntdll hooks can skip double-processing.
    extern __declspec(thread) int tls_in_win32_layer;
    struct InWin32LayerGuard {
        InWin32LayerGuard() { ++tls_in_win32_layer; }
        ~InWin32LayerGuard() { --tls_in_win32_layer; }
        InWin32LayerGuard(const InWin32LayerGuard&) = delete;
        InWin32LayerGuard& operator=(const InWin32LayerGuard&) = delete;
    };

} // namespace pipetap::inject
