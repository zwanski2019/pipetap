#pragma once

#define WIN32_LEAN_AND_MEAN
#include <cstdint>
#include <string>
#include <vector>
#include <Windows.h>

namespace pipetap::bytes {

    inline std::string MakePrintable(const uint8_t* data, size_t len) {
        std::string out; out.resize(len);
        for (size_t i = 0; i < len; ++i) {
            unsigned char c = data[i];
            out[i] = (c >= 32 && c < 127) ? (char)c : '.';
        }

        return out;
    }

    inline std::string ToHex(const std::vector<uint8_t>& v, bool spaced = true, bool uppercase = true) {
        static const char* lutU = "0123456789ABCDEF";
        static const char* lutL = "0123456789abcdef";
        const char* lut = uppercase ? lutU : lutL;
        if (v.empty()) return {};
        std::string out; out.reserve(v.size() * (spaced ? 3 : 2));

        for (size_t i = 0; i < v.size(); ++i) {
            unsigned b = v[i];
            out.push_back(lut[(b >> 4) & 0xF]);
            out.push_back(lut[b & 0xF]);
            if (spaced && i + 1 != v.size()) out.push_back(' ');
        }

        return out;
    }

    inline std::string ToCSlashX(const std::vector<uint8_t>& v, bool spaced = false) {
        if (v.empty()) return {};

        std::string out; out.reserve(v.size() * (spaced ? 5 : 4));
        for (size_t i = 0; i < v.size(); ++i) {
            char buf[5]; std::snprintf(buf, sizeof(buf), "\\x%02X", (unsigned)v[i]);
            out.append(buf);
            if (spaced && i + 1 != v.size()) out.push_back(' ');
        }

        return out;
    }

    inline std::string ToBase64(const uint8_t* data, size_t len) {
        static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        if (!len) return {};

        std::string out; out.reserve(((len + 2) / 3) * 4);
        size_t i = 0;
        while (i + 3 <= len) {
            uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
            out.push_back(tbl[(n >> 18) & 63]);
            out.push_back(tbl[(n >> 12) & 63]);
            out.push_back(tbl[(n >> 6) & 63]);
            out.push_back(tbl[n & 63]);
            i += 3;
        }

        if (i < len) {
            uint32_t n = (data[i] << 16);
            out.push_back(tbl[(n >> 18) & 63]);
            if (i + 1 < len) {
                n |= (data[i + 1] << 8);
                out.push_back(tbl[(n >> 12) & 63]);
                out.push_back(tbl[(n >> 6) & 63]);
                out.push_back('=');
            }
            else {
                out.push_back(tbl[(n >> 12) & 63]);
                out.push_back('='); out.push_back('=');
            }
        }

        return out;
    }
    inline void Utf8ToUtf16LE(const char* utf8, std::vector<uint8_t>& out_bytes) {
        out_bytes.clear();
        if (!utf8) return;

        int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, nullptr, 0);
        if (wlen <= 0) return;

        std::vector<wchar_t> wide((size_t)wlen);
        MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide.data(), wlen);

        // drop the NUL terminator from the payload; send only the content
        size_t payload = (wide.empty() ? 0 : (wide.size() - 1)) * sizeof(wchar_t);
        out_bytes.resize(payload);

        if (payload) std::memcpy(out_bytes.data(), wide.data(), payload);
    }

    inline std::string Utf16LEToUtf8(const std::vector<uint8_t>& bytes) {
        if (bytes.size() < 2 || (bytes.size() & 1)) {
            // odd length or tiny: best effort by truncation
        }

        int wlen = (int)(bytes.size() / 2);
        const wchar_t* wptr = (const wchar_t*)bytes.data();

        if (wlen == 0) return std::string();

        int u8len = WideCharToMultiByte(CP_UTF8, 0, wptr, wlen, nullptr, 0, nullptr, nullptr);
        if (u8len <= 0) return std::string();

        std::string out((size_t)u8len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wptr, wlen, out.data(), u8len, nullptr, nullptr);

        return out;
    }

} // namespace pipetap::bytes
