#pragma once

#include <Windows.h>

#include <cstdint>
#include <initializer_list>
#include <vector>
#include <cstring>

#include "pipetap/controlpipe.h"

namespace pipetap {

    struct ControlMessageFragment {
        const void* data = nullptr;
        uint32_t length = 0;
    };

    inline std::vector<uint8_t> BuildControlMessage(uint16_t type,
        const ControlMessageFragment* fragments, size_t count)
    {
        uint32_t total_len = 0;
        for (size_t i = 0; i < count; ++i) {
            total_len += fragments[i].length;
        }

        PT_ControlMessageHeader hdr{ type, total_len };
        std::vector<uint8_t> msg(sizeof(hdr) + total_len);
        std::memcpy(msg.data(), &hdr, sizeof(hdr));

        size_t offset = sizeof(hdr);
        for (size_t i = 0; i < count; ++i) {
            const ControlMessageFragment& frag = fragments[i];
            if (frag.length && frag.data) {
                std::memcpy(msg.data() + offset, frag.data, frag.length);
            }
            offset += frag.length;
        }
        return msg;
    }

    inline std::vector<uint8_t> BuildControlMessage(uint16_t type,
        std::initializer_list<ControlMessageFragment> fragments)
    {
        return BuildControlMessage(type, fragments.begin(), fragments.size());
    }

    inline std::vector<uint8_t> BuildControlMessage(uint16_t type,
        const std::vector<ControlMessageFragment>& fragments)
    {
        return BuildControlMessage(type, fragments.data(), fragments.size());
    }

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

} // namespace pipetap
