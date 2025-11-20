#pragma once

#include <iostream>

namespace pipetap::utils
{

    static void hexDump(const void* data, size_t len)
    {
        constexpr size_t kRow = 16;
        auto* bytes = static_cast<const uint8_t*>(data);

        for (size_t off = 0; off < len; off += kRow)
        {
            size_t n = (std::min)(kRow, len - off);

            // offset
            std::printf("%08zx  ", off);

            // hex
            for (size_t i = 0; i < kRow; ++i)
            {
                if (i < n)
                    std::printf("%02X ", bytes[off + i]);
                else
                    std::printf("   ");
                if (i == 7)
                    std::printf(" ");
            }
            std::printf(" |");

            // ascii
            for (size_t i = 0; i < n; ++i)
            {
                uint8_t c = bytes[off + i];
                std::printf("%c", (c >= 32 && c <= 126) ? char(c) : '.');
            }
            std::printf("|\n");
        }
        if (len == 0)
            std::printf("(empty)\n");
    }

}
