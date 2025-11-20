#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "bytes/format.h"
#include "imgui.h"
#include "log.h"
#include <string>
#include <vector>
#include <Windows.h>

namespace pipetap::ui {

    inline bool CopyUnicodeAndAnsiTextToClipboard(const std::string& utf8) {
        if (!OpenClipboard(nullptr)) return false;
        bool ok_any = false;
        if (EmptyClipboard()) {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
            if (wlen > 0) {
                HGLOBAL hW = GlobalAlloc(GMEM_MOVEABLE, (wlen + 1) * sizeof(wchar_t));
                if (hW) {
                    wchar_t* wptr = (wchar_t*)GlobalLock(hW);
                    if (wptr) {
                        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), wptr, wlen);
                        wptr[wlen] = L'\0';
                        GlobalUnlock(hW);
                        if (SetClipboardData(CF_UNICODETEXT, hW)) ok_any = true; else GlobalFree(hW);
                    }
                    else {
                        GlobalFree(hW);
                    }
                }
            }
            int wlen2 = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
            if (wlen2 > 0) {
                std::wstring wtmp; wtmp.resize(wlen2);
                MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), wtmp.data(), wlen2);
                int a2 = WideCharToMultiByte(CP_ACP, 0, wtmp.c_str(), (int)wtmp.size(), nullptr, 0, nullptr, nullptr);
                if (a2 > 0) {
                    HGLOBAL hA = GlobalAlloc(GMEM_MOVEABLE, (a2 + 1));
                    if (hA) {
                        char* aptr = (char*)GlobalLock(hA);
                        if (aptr) {
                            WideCharToMultiByte(CP_ACP, 0, wtmp.c_str(), (int)wtmp.size(), aptr, a2, nullptr, nullptr);
                            aptr[a2] = '\0';
                            GlobalUnlock(hA);
                            if (!SetClipboardData(CF_TEXT, hA)) GlobalFree(hA); else ok_any = true;
                        }
                        else {
                            GlobalFree(hA);
                        }
                    }
                }
            }
        }
        CloseClipboard();
        return ok_any;
    }

    inline bool CopyRawBytesToClipboard(const std::vector<uint8_t>& bytes, const char* format_name = "pipetap/raw-bytes") {
        if (bytes.empty()) return false;
        if (!OpenClipboard(nullptr)) return false;
        bool ok = false;

        if (EmptyClipboard()) {
            UINT fmt = RegisterClipboardFormatA(format_name);
            SIZE_T sz = bytes.size();
            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, sz);
            if (hMem) {
                void* p = GlobalLock(hMem);
                if (p) {
                    memcpy(p, bytes.data(), sz);
                    GlobalUnlock(hMem);
                    if (SetClipboardData(fmt, hMem)) ok = true; else GlobalFree(hMem);
                }
                else {
                    GlobalFree(hMem);
                }
            }
        }
        CloseClipboard();
        return ok;
    }

    inline bool CopyTextAndRawBytesToClipboard(const std::string& utf8_text,
        const std::vector<uint8_t>& raw,
        const char* format_name = "pipetap/raw-bytes") {
        if (!OpenClipboard(nullptr)) return false;
        bool ok_any = false;
        if (EmptyClipboard()) {
            // UNICODETEXT
            if (!utf8_text.empty()) {
                int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8_text.c_str(), (int)utf8_text.size(), nullptr, 0);
                if (wlen > 0) {
                    HGLOBAL hW = GlobalAlloc(GMEM_MOVEABLE, (wlen + 1) * sizeof(wchar_t));
                    if (hW) {
                        wchar_t* wptr = (wchar_t*)GlobalLock(hW);
                        if (wptr) {
                            MultiByteToWideChar(CP_UTF8, 0, utf8_text.c_str(), (int)utf8_text.size(), wptr, wlen);
                            wptr[wlen] = L'\0';
                            GlobalUnlock(hW);
                            if (SetClipboardData(CF_UNICODETEXT, hW)) ok_any = true; else GlobalFree(hW);
                        }
                        else {
                            GlobalFree(hW);
                        }
                    }
                }
                // ANSI TEXT
                int wlen2 = MultiByteToWideChar(CP_UTF8, 0, utf8_text.c_str(), (int)utf8_text.size(), nullptr, 0);
                if (wlen2 > 0) {
                    std::wstring wtmp; wtmp.resize(wlen2);
                    MultiByteToWideChar(CP_UTF8, 0, utf8_text.c_str(), (int)utf8_text.size(), wtmp.data(), wlen2);
                    int a2 = WideCharToMultiByte(CP_ACP, 0, wtmp.c_str(), (int)wtmp.size(), nullptr, 0, nullptr, nullptr);
                    if (a2 > 0) {
                        HGLOBAL hA = GlobalAlloc(GMEM_MOVEABLE, (a2 + 1));
                        if (hA) {
                            char* aptr = (char*)GlobalLock(hA);
                            if (aptr) {
                                WideCharToMultiByte(CP_ACP, 0, wtmp.c_str(), (int)wtmp.size(), aptr, a2, nullptr, nullptr);
                                aptr[a2] = '\0';
                                GlobalUnlock(hA);
                                if (!SetClipboardData(CF_TEXT, hA)) GlobalFree(hA); else ok_any = true;
                            }
                            else {
                                GlobalFree(hA);
                            }
                        }
                    }
                }
            }
            // Custom raw bytes
            if (!raw.empty()) {
                UINT fmt = RegisterClipboardFormatA(format_name);
                SIZE_T sz = raw.size();
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, sz);
                if (hMem) {
                    void* p = GlobalLock(hMem);
                    if (p) {
                        memcpy(p, raw.data(), sz);
                        GlobalUnlock(hMem);
                        if (SetClipboardData(fmt, hMem)) ok_any = true; else GlobalFree(hMem);
                    }
                    else {
                        GlobalFree(hMem);
                    }
                }
            }
        }
        CloseClipboard();
        return ok_any;
    }

    inline bool GetClipboardRawBytes(std::vector<uint8_t>& out, const char* preferred_format_name = "pipetap/raw-bytes") {
        out.clear();
        if (!OpenClipboard(nullptr)) return false;

        auto read_hglobal_bytes = [](HANDLE h, std::vector<uint8_t>& dst) -> bool {
            if (!h) return false;
            SIZE_T sz = GlobalSize(h);
            if (sz == 0) return false;
            void* p = GlobalLock(h);
            if (!p) return false;
            dst.assign(static_cast<const uint8_t*>(p), static_cast<const uint8_t*>(p) + sz);
            GlobalUnlock(h);
            return true;
            };

        bool ok = false;

        if (preferred_format_name && *preferred_format_name) {
            UINT fmt = RegisterClipboardFormatA(preferred_format_name);
            if (fmt && IsClipboardFormatAvailable(fmt)) {
                HANDLE h = GetClipboardData(fmt);
                ok = read_hglobal_bytes(h, out);
            }
        }

        if (!ok && IsClipboardFormatAvailable(CF_TEXT)) {
            HANDLE h = GetClipboardData(CF_TEXT);
            if (h) {
                SIZE_T sz = GlobalSize(h);
                if (sz > 0) {
                    const char* p = static_cast<const char*>(GlobalLock(h));
                    if (p) {
                        size_t n = 0;
                        while (n + 1 < sz && p[n] != '\0') ++n;
                        out.assign(reinterpret_cast<const uint8_t*>(p), reinterpret_cast<const uint8_t*>(p) + n);
                        GlobalUnlock(h);
                        ok = true;
                    }
                }
            }
        }

        if (!ok && IsClipboardFormatAvailable(CF_UNICODETEXT)) {
            HANDLE h = GetClipboardData(CF_UNICODETEXT);
            if (h) {
                const wchar_t* w = static_cast<const wchar_t*>(GlobalLock(h));
                if (w) {
                    int wlen = 0; while (w[wlen] != L'\0') ++wlen;
                    int need = WideCharToMultiByte(CP_UTF8, 0, w, wlen, nullptr, 0, nullptr, nullptr);
                    if (need > 0) {
                        std::string utf8; utf8.resize(need);
                        WideCharToMultiByte(CP_UTF8, 0, w, wlen, utf8.data(), need, nullptr, nullptr);
                        out.assign(utf8.begin(), utf8.end());
                        ok = true;
                    }
                    GlobalUnlock(h);
                }
            }
        }

        CloseClipboard();
        return ok;
    }

    inline bool GetClipboardUtf8Text(std::string& out) {
        out.clear();
        if (!OpenClipboard(nullptr)) return false;
        bool ok = false;

        // Prefer UNICODETEXT
        if (IsClipboardFormatAvailable(CF_UNICODETEXT)) {
            HANDLE h = GetClipboardData(CF_UNICODETEXT);
            if (h) {
                const wchar_t* w = static_cast<const wchar_t*>(GlobalLock(h));
                if (w) {
                    int wlen = 0; while (w[wlen] != L'\0') ++wlen;
                    int need = WideCharToMultiByte(CP_UTF8, 0, w, wlen, nullptr, 0, nullptr, nullptr);
                    if (need > 0) {
                        out.resize(need);
                        WideCharToMultiByte(CP_UTF8, 0, w, wlen, out.data(), need, nullptr, nullptr);
                        ok = true;
                    }
                    GlobalUnlock(h);
                }
            }
        }

        // Fallback: ANSI TEXT
        if (!ok && IsClipboardFormatAvailable(CF_TEXT)) {
            HANDLE h = GetClipboardData(CF_TEXT);
            if (h) {
                const char* p = static_cast<const char*>(GlobalLock(h));
                if (p) {
                    size_t n = 0; size_t cap = GlobalSize(h);
                    while (n + 1 < cap && p[n] != '\0') ++n;
                    out.assign(p, p + n);
                    GlobalUnlock(h);
                    ok = true;
                }
            }
        }

        CloseClipboard();
        return ok;
    }

    inline bool GetClipboardBase64AsBytes(std::vector<uint8_t>& out) {
        out.clear();
        std::string txt;
        if (!GetClipboardUtf8Text(txt) || txt.empty())
            return false;

        auto is_ws = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
        size_t i = 0, j = txt.size();
        while (i < j && is_ws(txt[i])) ++i;
        while (j > i && is_ws(txt[j - 1])) --j;
        if (j <= i) return false;

        // Accept missing padding.
        std::string s = txt.substr(i, j - i);
        // Add padding if necessary
        size_t mod = s.size() % 4;
        if (mod == 2) s.append("==");
        else if (mod == 3) s.append("=");
        else if (mod == 1) return false; // invalid

        // Lightweight decoder
        auto val = [](int c)->int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/' || c == '_') return 63;
            return -1;
            };

        std::vector<uint8_t> out_local;
        out_local.reserve(s.size() * 3 / 4);
        int buf = 0, bits = 0;
        for (char ch : s) {
            if (ch == '=' || ch == '-') break; // stop at padding / tolerate '-'
            int v = val((unsigned char)ch);
            if (v < 0) continue; // skip whitespace or invalid chars
            buf = (buf << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out_local.push_back(uint8_t((buf >> bits) & 0xFF));
            }
        }
        if (out_local.empty()) return false;
        out.swap(out_local);
        return true;
    }

    inline void DrawCopyPopupForBytes(const char* popup_id,
        const std::vector<uint8_t>& bytes,
        const char* button_label = "Copy...",
        const char* custom_format_name = "pipetap/raw-bytes")
    {
        using namespace ImGui;

        using pipetap::bytes::MakePrintable;
        using pipetap::bytes::ToBase64;
        using pipetap::bytes::ToCSlashX;
        using pipetap::bytes::ToHex;

        BeginDisabled(bytes.empty());
        if (Button(button_label)) OpenPopup(popup_id);
        EndDisabled();

        if (!BeginPopup(popup_id)) return;

        if (MenuItem("Hex string (DE AD BE EF)")) {
            std::string txt = ToHex(bytes, /*uppercase*/true, /*with_spaces*/true);
            if (CopyUnicodeAndAnsiTextToClipboard(txt)) pipetap::log::App.Info("hex string copied to clipboard");
        }
        if (MenuItem("C string (\\xDE\\xAD...)")) {
            std::string txt = ToCSlashX(bytes, /*uppercase*/false);
            if (CopyUnicodeAndAnsiTextToClipboard(txt)) pipetap::log::App.Info("C-style string copied to clipboard");
        }
        if (MenuItem("Base64")) {
            std::string txt = ToBase64(bytes.data(), bytes.size());
            if (CopyUnicodeAndAnsiTextToClipboard(txt)) pipetap::log::App.Info("base64 copied to clipboard");
        }
        if (MenuItem("ASCII (dots for non-printable)")) {
            std::string txt = MakePrintable(bytes.data(), bytes.size());
            if (CopyUnicodeAndAnsiTextToClipboard(txt)) pipetap::log::App.Info("ASCII (.) copied to clipboard");
        }
        if (MenuItem("Raw bytes (custom clipboard format)")) {
            // Put both a human-readable representation and the raw block on the clipboard
            std::string hexTxt = ToHex(bytes, /*uppercase*/true, /*with_spaces*/true);
            bool ok = CopyTextAndRawBytesToClipboard(hexTxt, bytes, custom_format_name);
            if (ok) pipetap::log::App.Info("raw bytes placed on clipboard (with hex text)");
        }

        EndPopup();
    }

} // namespace pipetap::ui
