#include "pch.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "pipetap/log.h"
#include "inject/control_server.h"
#include "inject/hook_manager.h"

using namespace pipetap;

static DWORD WINAPI StartupThread(LPVOID)
{
    // Configure header-only logger for this component and open it early.
    log::set_log_filename("injected.log");
    log::ensure_open();
    log::printf("StartupThread: begin (pid=%lu)", (unsigned long)GetCurrentProcessId());

    // Start control pipe server (DLL is the server).
    inject::ControlServer::instance().start();

    // Install Detours hooks.
    bool ok = inject::HookManager::install();
    log::printf("StartupThread: HookManager::install => %s", ok ? "OK" : "FAIL");

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule); // use the correct module handle
        HANDLE th = CreateThread(nullptr, 0, StartupThread, nullptr, 0, nullptr);
        if (th) CloseHandle(th);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        inject::HookManager::uninstall();
        inject::ControlServer::instance().stop();
        log::close();
    }
    return TRUE;
}
