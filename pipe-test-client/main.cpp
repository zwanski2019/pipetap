#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <random>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cstdio>

#include "pipetap/constants.h"
#include "pipetap/version.h"
#include "pipetap/utils.h"

// Send data and wait for echoed reply
static bool sendAndEcho(HANDLE hPipe, const std::vector<uint8_t>& data)
{
    DWORD written = 0;
    if (!WriteFile(hPipe, data.data(), DWORD(data.size()), &written, nullptr)) {
        std::cout << " | WriteFile failed: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << " |> sent " << written << " bytes" << std::endl;
    pipetap::utils::hexDump(data.data(), written);

    // read back echoed data
    std::vector<uint8_t> buf(64 * 1024);
    DWORD got = 0;
    if (!ReadFile(hPipe, buf.data(), DWORD(buf.size()), &got, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_BROKEN_PIPE) {
            std::cout << " | server closed pipe" << std::endl;
        }
        else {
            std::cout << " | ReadFile failed: " << err << std::endl;
        }
        return false;
    }
    std::cout << " |< received " << got << " bytes" << std::endl;
    pipetap::utils::hexDump(buf.data(), got);
    return true;
}

int main()
{
    std::cout << pipetap::constants::kLogo << " v" << pipetap::version_string() << std::endl;
    std::cout << " | pipe-echo-client" << std::endl;
    std::cout << " | connecting to: " << pipetap::constants::kPipeNameTest << std::endl;

    // Wait until server is ready
    for (;;) {
        HANDLE hPipe = CreateFileA(
            pipetap::constants::kPipeNameTest,
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING,
            0, nullptr);

        if (hPipe != INVALID_HANDLE_VALUE) {
            std::cout << " | connected!" << std::endl;

            // set message-read mode
            DWORD mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);

            std::mt19937 rng{ std::random_device{}() };
            std::uniform_int_distribution<int> lenDist(1, 256);
            std::uniform_int_distribution<int> byteDist(0, 255);

            std::cout << " | type a line and press Enter to send.\n"
                " | press Enter on an empty line to send a random byte blob.\n";

            std::string line;
            while (true) {
                std::cout << " > ";
                if (!std::getline(std::cin, line)) {
                    // stdin closed (Ctrl+Z/Ctrl+D), exit gracefully
                    break;
                }

                std::vector<uint8_t> payload;

                if (line.empty()) {
                    // generate random blob
                    int len = lenDist(rng);
                    payload.resize(static_cast<size_t>(len));
                    for (int i = 0; i < len; ++i) {
                        payload[static_cast<size_t>(i)] = static_cast<uint8_t>(byteDist(rng));
                    }
                    std::cout << " | generating random payload of " << len << " bytes\n";
                }
                else {
                    // send typed line as bytes (no terminating NUL)
                    payload.assign(line.begin(), line.end());
                }

                if (!sendAndEcho(hPipe, payload)) {
                    break; // server closed or I/O error
                }
            }

            CloseHandle(hPipe);
            break;
        }

        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY) {
            if (!WaitNamedPipeA(pipetap::constants::kPipeNameTest, 5000)) {
                std::cout << " | WaitNamedPipe failed: " << GetLastError() << std::endl;
                return 1;
            }
        }
        else {
            std::cout << " | Could not open pipe: " << err << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    return 0;
}
