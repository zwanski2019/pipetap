#include "pch.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif
#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x00000103L)
#endif

#include <cstdint>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <atomic>
#include <string>

#include "pipetap/log.h"
#include "pipetap/controlpipe.h"

#include "inject/hook_manager.h"
#include "inject/control_server.h"
#include "inject/pipe_utils.h"

#include "detours/detours.h"

namespace pipetap::inject {

    __declspec(thread) int tls_suppress_hooks = 0;

    // ========================= ntdll prototypes =========================
    using PFN_NtReadFile = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
        PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

    using PFN_NtWriteFile = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
        PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);

    using PFN_NtWaitForSingleObject = NTSTATUS(NTAPI*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
    using PFN_NtWaitForMultipleObjects = NTSTATUS(NTAPI*)(ULONG, const HANDLE*, BOOLEAN, BOOLEAN, PLARGE_INTEGER);

    using PFN_NtCreateFile = NTSTATUS(NTAPI*)(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength);

    using PFN_NtCreateNamedPipeFile = NTSTATUS(NTAPI*)(
        PHANDLE FileHandle,
        ULONG DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        ULONG NamedPipeType,
        ULONG ReadMode,
        ULONG CompletionMode,
        ULONG MaximumInstances,
        ULONG InboundQuota,
        ULONG OutboundQuota,
        PLARGE_INTEGER DefaultTimeout);

    using PFN_NtClose = NTSTATUS(NTAPI*)(HANDLE);

    static PFN_NtReadFile                 Real_NtReadFile = nullptr;
    static PFN_NtWriteFile                Real_NtWriteFile = nullptr;
    static PFN_NtWaitForSingleObject      Real_NtWaitForSingleObject = nullptr;
    static PFN_NtWaitForMultipleObjects   Real_NtWaitForMultipleObjects = nullptr;
    static PFN_NtCreateFile               Real_NtCreateFile = nullptr;
    static PFN_NtCreateNamedPipeFile      Real_NtCreateNamedPipeFile = nullptr;
    static PFN_NtClose                    Real_NtClose = nullptr;

    static std::atomic<uint64_t> g_nextOpId{ 1 };
    static inline uint64_t NewOpId() { return g_nextOpId.fetch_add(1, std::memory_order_relaxed); }

    static inline bool IsCtrlHandle(HANDLE h) {
        return ControlServer::instance().is_ctrl_handle(h);
    }

    static inline bool HasCtrlPrefix(const std::string& name) {
        if (name.empty()) return false;
        return name.rfind(PT_CTRL_EVENTS_PREFIX, 0) == 0
            || name.rfind(PT_CTRL_COMMANDS_PREFIX, 0) == 0;
    }

    static inline bool IsNamedPipeHandleSafe(HANDLE h) {
        return h && h != INVALID_HANDLE_VALUE && is_named_pipe_handle(h);
    }

    static inline void SendEvent(const char* apiName, HANDLE h) {
        ControlServer::instance().send_pipe_io(
            PT_PIPE_EVENT, h, nullptr, 0, /*dir=*/0, NewOpId(), apiName);
    }

    struct PendingRead {
        HANDLE           file = nullptr;
        PIO_STATUS_BLOCK iosb = nullptr;
        PVOID            buffer = nullptr;
        ULONG            length = 0;
        uint64_t         op_id = 0;
    };

    static SRWLOCK g_pr_lock = SRWLOCK_INIT;
    static std::unordered_map<DWORD, PendingRead> g_pendingReads;

    static void TrackPendingRead(DWORD tid, const PendingRead& pr) {
        AcquireSRWLockExclusive(&g_pr_lock);
        g_pendingReads[tid] = pr;
        ReleaseSRWLockExclusive(&g_pr_lock);
    }

    static bool TakePendingRead(DWORD tid, PendingRead& out) {
        bool ok = false;
        AcquireSRWLockExclusive(&g_pr_lock);
        auto it = g_pendingReads.find(tid);
        if (it != g_pendingReads.end()) {
            out = it->second;
            g_pendingReads.erase(it);
            ok = true;
        }
        ReleaseSRWLockExclusive(&g_pr_lock);
        return ok;
    }

    static void PutBackPendingRead(DWORD tid, const PendingRead& pr) {
        TrackPendingRead(tid, pr);
    }

    static bool TryCompletePendingReadForCurrentThread()
    {
        PendingRead pr{};
        DWORD tid = GetCurrentThreadId();
        if (!TakePendingRead(tid, pr)) return true;

        if (!pr.iosb) return true;

        NTSTATUS iosbSt = (NTSTATUS)pr.iosb->Status;
        ULONG_PTR xfer = pr.iosb->Information;

        if (iosbSt == STATUS_PENDING) {
            PutBackPendingRead(tid, pr);
            return false;
        }

        log::printf("TryCompletePendingRead: iosb->Status=0x%08lx got=%llu",
            (unsigned long)iosbSt, (unsigned long long)xfer);

        if (NT_SUCCESS(iosbSt) && xfer) {
            auto& ctrl = ControlServer::instance();
            ctrl.send_pipe_io(PT_PIPE_READ, pr.file, pr.buffer,
                (uint32_t)xfer, /*dir=*/0, pr.op_id, "NtReadFile(wait-complete)");

            if (ctrl.editing_responses_enabled()) {
                std::vector<uint8_t> repl; BOOL hasRepl = FALSE;
                (void)ctrl.wait_for_edit_and_maybe_replace(pr.op_id, pr.buffer,
                    (DWORD)xfer, repl, &hasRepl);
                if (hasRepl) {
                    ULONG use = (ULONG)std::min<size_t>(repl.size(), (size_t)pr.length);
                    std::memcpy(pr.buffer, repl.data(), use);
                    if (use < pr.length) std::memset((uint8_t*)pr.buffer + use, 0, pr.length - use);
                    pr.iosb->Information = use;
                }
            }
        }

        return true;
    }

    // ================================ Hooks ================================
    static NTSTATUS NTAPI Hook_NtWriteFile(
        HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
        PLARGE_INTEGER ByteOffset, PULONG Key)
    {
        if (!Real_NtWriteFile) return STATUS_NOT_IMPLEMENTED;

        if (tls_suppress_hooks || IsCtrlHandle(FileHandle))
            return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                Buffer, Length, ByteOffset, Key);

        if (!is_named_pipe_handle(FileHandle))
            return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                Buffer, Length, ByteOffset, Key);

        if (Event || ApcRoutine)
            return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                Buffer, Length, ByteOffset, Key);

        uint64_t op = NewOpId();
        auto& ctrl = ControlServer::instance();
        ctrl.send_pipe_io(PT_PIPE_WRITE, FileHandle, Buffer, Length, /*dir=*/1, op, "NtWriteFile");

        std::vector<uint8_t> repl;
        BOOL hasRepl = FALSE;
        if (ctrl.editing_requests_enabled()) {
            (void)ctrl.wait_for_edit_and_maybe_replace(op, Buffer, Length, repl, &hasRepl);
        }

        if (hasRepl) {
            return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                (PVOID)repl.data(), (ULONG)repl.size(), ByteOffset, Key);
        }

        return Real_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            Buffer, Length, ByteOffset, Key);
    }

    static NTSTATUS NTAPI Hook_NtReadFile(
        HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
        PLARGE_INTEGER ByteOffset, PULONG Key)
    {
        if (!Real_NtReadFile) return STATUS_NOT_IMPLEMENTED;

        if (tls_suppress_hooks || IsCtrlHandle(FileHandle))
            return Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                Buffer, Length, ByteOffset, Key);

        if (!is_named_pipe_handle(FileHandle))
            return Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                Buffer, Length, ByteOffset, Key);

        NTSTATUS st = Real_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
            Buffer, Length, ByteOffset, Key);

        if (NT_SUCCESS(st) && st != STATUS_PENDING && IoStatusBlock) {
            ULONG_PTR xfer = IoStatusBlock->Information;
            if (xfer) {
                uint64_t op = NewOpId();
                auto& ctrl = ControlServer::instance();
                ctrl.send_pipe_io(PT_PIPE_READ, FileHandle, Buffer,
                    (uint32_t)xfer, /*dir=*/0, op, "NtReadFile");
                if (ctrl.editing_responses_enabled()) {
                    std::vector<uint8_t> repl; BOOL hasRepl = FALSE;
                    (void)ctrl.wait_for_edit_and_maybe_replace(op, Buffer,
                        (DWORD)xfer, repl, &hasRepl);
                    if (hasRepl) {
                        ULONG use = (ULONG)std::min<size_t>(repl.size(), (size_t)Length);
                        std::memcpy(Buffer, repl.data(), use);
                        if (use < Length) std::memset((uint8_t*)Buffer + use, 0, Length - use);
                        IoStatusBlock->Information = use;
                    }
                }
            }

            return st;
        }

        if (st == STATUS_PENDING && IoStatusBlock && !Event && !ApcRoutine) {
            uint64_t op = NewOpId();
            PendingRead pr{ FileHandle, IoStatusBlock, Buffer, Length, op };
            TrackPendingRead(GetCurrentThreadId(), pr);

            return st;
        }

        return st;
    }

    static NTSTATUS NTAPI Hook_NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
    {
        if (!Real_NtWaitForSingleObject) return STATUS_NOT_IMPLEMENTED;
        NTSTATUS st = Real_NtWaitForSingleObject(Handle, Alertable, Timeout);
        (void)TryCompletePendingReadForCurrentThread();

        return st;
    }

    static NTSTATUS NTAPI Hook_NtWaitForMultipleObjects(ULONG Count, const HANDLE* Handles, BOOLEAN WaitAll, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
    {
        if (!Real_NtWaitForMultipleObjects) return STATUS_NOT_IMPLEMENTED;
        NTSTATUS st = Real_NtWaitForMultipleObjects(Count, Handles, WaitAll, Alertable, Timeout);
        (void)TryCompletePendingReadForCurrentThread();

        return st;
    }

    static NTSTATUS NTAPI Hook_NtCreateNamedPipeFile(
        PHANDLE            NamedPipeFileHandle,
        ULONG              DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK   IoStatusBlock,
        ULONG              ShareAccess,
        ULONG              CreateDisposition,
        ULONG              CreateOptions,
        ULONG              NamedPipeType,
        ULONG              ReadMode,
        ULONG              CompletionMode,
        ULONG              MaximumInstances,
        ULONG              InboundQuota,
        ULONG              OutboundQuota,
        PLARGE_INTEGER     DefaultTimeout)
    {
        if (!Real_NtCreateNamedPipeFile) return STATUS_NOT_IMPLEMENTED;

        NTSTATUS ret = Real_NtCreateNamedPipeFile(
            NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
            ShareAccess, CreateDisposition, CreateOptions,
            NamedPipeType, ReadMode, CompletionMode,
            MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);

        if (!NT_SUCCESS(ret) || !NamedPipeFileHandle || !*NamedPipeFileHandle || *NamedPipeFileHandle == INVALID_HANDLE_VALUE)
            return ret;

        HANDLE h = *NamedPipeFileHandle;

        if (tls_suppress_hooks || IsCtrlHandle(h))
            return ret;

        DWORD ft = GetFileType(h);
        if (ft != FILE_TYPE_PIPE)
            return ret;

        std::string name = pipe_name_for_handle(h);
        if (!name.empty() && HasCtrlPrefix(name))
            return ret;

        SendEvent("NtCreateNamedPipeFile", h);
        return ret;
    }

    static NTSTATUS NTAPI Hook_NtCreateFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength)
    {
        if (!Real_NtCreateFile) return STATUS_NOT_IMPLEMENTED;

        NTSTATUS st = Real_NtCreateFile(
            FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
            AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);

        if (NT_SUCCESS(st) && FileHandle && *FileHandle && *FileHandle != INVALID_HANDLE_VALUE) {
            HANDLE h = *FileHandle;
            // Only care if the resulting handle is a named pipe (client open path).
            if (!tls_suppress_hooks && !IsCtrlHandle(h) && IsNamedPipeHandleSafe(h)) {
                std::string name = pipe_name_for_handle(h);
                if (!HasCtrlPrefix(name))
                    SendEvent("NtCreateFile(pipe)", h);
            }
        }

        return st;
    }

    static NTSTATUS NTAPI Hook_NtClose(HANDLE Handle)
    {
        if (!Real_NtClose) return STATUS_NOT_IMPLEMENTED;

        // Emit BEFORE closing so metadata (name/peer) is still resolvable.
        if (!tls_suppress_hooks && Handle && Handle != INVALID_HANDLE_VALUE &&
            !IsCtrlHandle(Handle) && IsNamedPipeHandleSafe(Handle))
        {
            SendEvent("NtClose", Handle);
        }

        return Real_NtClose(Handle);
    }

    bool HookManager::install()
    {
        DetourRestoreAfterWith();

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            Real_NtReadFile = (PFN_NtReadFile)GetProcAddress(hNtdll, "NtReadFile");
            Real_NtWriteFile = (PFN_NtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
            Real_NtWaitForSingleObject = (PFN_NtWaitForSingleObject)GetProcAddress(hNtdll, "NtWaitForSingleObject");
            Real_NtWaitForMultipleObjects = (PFN_NtWaitForMultipleObjects)GetProcAddress(hNtdll, "NtWaitForMultipleObjects");

            Real_NtCreateFile = (PFN_NtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
            Real_NtCreateNamedPipeFile = (PFN_NtCreateNamedPipeFile)GetProcAddress(hNtdll, "NtCreateNamedPipeFile");
            Real_NtClose = (PFN_NtClose)GetProcAddress(hNtdll, "NtClose");

            // Fallbacks to Zw* where needed
            if (!Real_NtReadFile)                Real_NtReadFile = (PFN_NtReadFile)GetProcAddress(hNtdll, "ZwReadFile");
            if (!Real_NtWriteFile)               Real_NtWriteFile = (PFN_NtWriteFile)GetProcAddress(hNtdll, "ZwWriteFile");
            if (!Real_NtWaitForSingleObject)     Real_NtWaitForSingleObject = (PFN_NtWaitForSingleObject)GetProcAddress(hNtdll, "ZwWaitForSingleObject");
            if (!Real_NtWaitForMultipleObjects)  Real_NtWaitForMultipleObjects = (PFN_NtWaitForMultipleObjects)GetProcAddress(hNtdll, "ZwWaitForMultipleObjects");

            if (!Real_NtCreateFile)              Real_NtCreateFile = (PFN_NtCreateFile)GetProcAddress(hNtdll, "ZwCreateFile");
            if (!Real_NtCreateNamedPipeFile)     Real_NtCreateNamedPipeFile = (PFN_NtCreateNamedPipeFile)GetProcAddress(hNtdll, "ZwCreateNamedPipeFile");
            if (!Real_NtClose)                   Real_NtClose = (PFN_NtClose)GetProcAddress(hNtdll, "ZwClose");
        }

        if (DetourTransactionBegin() != NO_ERROR) return false;
        if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR) { DetourTransactionAbort(); return false; }

        // ntdll hooks (data I/O + wait glue)
        if (Real_NtReadFile)                DetourAttach((PVOID*)&Real_NtReadFile, Hook_NtReadFile);
        if (Real_NtWriteFile)               DetourAttach((PVOID*)&Real_NtWriteFile, Hook_NtWriteFile);
        if (Real_NtWaitForSingleObject)     DetourAttach((PVOID*)&Real_NtWaitForSingleObject, Hook_NtWaitForSingleObject);
        if (Real_NtWaitForMultipleObjects)  DetourAttach((PVOID*)&Real_NtWaitForMultipleObjects, Hook_NtWaitForMultipleObjects);

        // creation / close
        if (Real_NtCreateFile)              DetourAttach((PVOID*)&Real_NtCreateFile, Hook_NtCreateFile);
        if (Real_NtCreateNamedPipeFile)     DetourAttach((PVOID*)&Real_NtCreateNamedPipeFile, Hook_NtCreateNamedPipeFile);
        if (Real_NtClose)                   DetourAttach((PVOID*)&Real_NtClose, Hook_NtClose);

        LONG rc = DetourTransactionCommit();
        log::printf(
            "HookManager::install: detour commit rc=%ld "
            "(NtRead=%p NtWrite=%p NtWait=%p NtWaitMany=%p | "
            "NtCreateFile=%p NtCreateNamedPipeFile=%p NtClose=%p)",
            rc,
            Real_NtReadFile, Real_NtWriteFile, Real_NtWaitForSingleObject, Real_NtWaitForMultipleObjects,
            Real_NtCreateFile, Real_NtCreateNamedPipeFile, Real_NtClose);

        if (rc != NO_ERROR) {
            ControlServer::instance().send_error((uint32_t)rc, "detours_attach");
            return false;
        }
        return true;
    }

    void HookManager::uninstall()
    {
        if (DetourTransactionBegin() != NO_ERROR) return;
        DetourUpdateThread(GetCurrentThread());

        if (Real_NtReadFile)               DetourDetach((PVOID*)&Real_NtReadFile, Hook_NtReadFile);
        if (Real_NtWriteFile)              DetourDetach((PVOID*)&Real_NtWriteFile, Hook_NtWriteFile);
        if (Real_NtWaitForSingleObject)    DetourDetach((PVOID*)&Real_NtWaitForSingleObject, Hook_NtWaitForSingleObject);
        if (Real_NtWaitForMultipleObjects) DetourDetach((PVOID*)&Real_NtWaitForMultipleObjects, Hook_NtWaitForMultipleObjects);

        if (Real_NtCreateFile)             DetourDetach((PVOID*)&Real_NtCreateFile, Hook_NtCreateFile);
        if (Real_NtCreateNamedPipeFile)    DetourDetach((PVOID*)&Real_NtCreateNamedPipeFile, Hook_NtCreateNamedPipeFile);
        if (Real_NtClose)                  DetourDetach((PVOID*)&Real_NtClose, Hook_NtClose);

        DetourTransactionCommit();
    }

} // namespace pipetap::inject
