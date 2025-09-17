#pragma once

#include <cstdint>
#include <string>

namespace pipetap
{

    // bump here in one place:
    inline constexpr uint16_t kVerMajor = 0;
    inline constexpr uint16_t kVerMinor = 0;
    inline constexpr uint16_t kVerPatch = 1;

    struct Version
    {
        uint16_t major, minor, patch;
    };
    inline constexpr Version kVersion{ kVerMajor, kVerMinor, kVerPatch };

    inline std::string version_string()
    {
        return std::to_string(kVerMajor) + "." +
            std::to_string(kVerMinor) + "." +
            std::to_string(kVerPatch);
    }
}
