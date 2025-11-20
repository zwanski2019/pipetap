#pragma once

#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

#include "pipetap/controlpipe.h"

namespace pipetap {

    inline bool PipeReadExact(HANDLE h, void* buf, DWORD len)
    {
        if (!h || h == INVALID_HANDLE_VALUE) return false;
        if (len == 0) return true;
        if (!buf) return false;

        auto* p = static_cast<uint8_t*>(buf);
        DWORD total = 0;

        while (total < len) {
            DWORD got = 0;
            if (ReadFile(h, p + total, len - total, &got, nullptr)) {
                total += got;
                if (total == len) return true;
                continue;
            }

            DWORD le = GetLastError();
            if (le == ERROR_MORE_DATA && got > 0) {
                total += got;
                if (total == len) return true;
                continue;
            }
            return false;
        }

        return true;
    }

    inline bool ReadControlFrame(HANDLE h, PT_ControlFrame& out)
    {
        if (!h || h == INVALID_HANDLE_VALUE) return false;

        PT_ControlMessageHeader hdr{};
        if (!PipeReadExact(h, &hdr, static_cast<DWORD>(sizeof(hdr)))) return false;
        if (hdr.length > PT_MAX_CONTROL_VALUE) { SetLastError(ERROR_INVALID_DATA); return false; }

        std::vector<uint8_t> payload(hdr.length);
        if (hdr.length) {
            if (!PipeReadExact(h, payload.data(), hdr.length)) return false;
        }

        out = PT_ControlFrame::FromOwned(hdr.type, std::move(payload));
        return true;
    }

    inline bool WriteControlFrame(HANDLE h, const PT_ControlFrame& frame, DWORD* wrote_out = nullptr)
    {
        if (!h || h == INVALID_HANDLE_VALUE) return false;
        if (frame.IsTooLarge()) { SetLastError(ERROR_INVALID_DATA); return false; }

        auto bytes = frame.Serialize();
        DWORD wrote = 0;
        const BOOL ok = WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &wrote, nullptr);
        if (wrote_out) *wrote_out = wrote;
        return (ok && wrote == bytes.size());
    }

} // namespace pipetap
