#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace pipetap::inject {

    class HookManager {
    public:
        static bool install();
        static void uninstall();
    };

} // namespace pipetap::inject
