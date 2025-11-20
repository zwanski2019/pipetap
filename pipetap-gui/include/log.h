#pragma once

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace pipetap::log {

    enum class Level { Debug, Info, Warning, Error };

    struct Event {
        double      t;     // seconds since a process-local monotonic epoch
        Level       level;
        std::string text;
    };

    // A drainable log channel
    class Channel {
    public:
        using Sink = std::function<void(const Event&)>;

        explicit Channel(size_t capacity = 1024) : cap_(capacity ? capacity : 1) {}

        void set_capacity(size_t cap) {
            std::lock_guard<std::mutex> lock(mtx_);
            cap_ = cap ? cap : 1;
            trim_to_capacity_();
        }

        size_t capacity() const noexcept { return cap_; }

        void Log(Level lvl, const std::string& msg) {
            Event ev{ NowSeconds(), lvl, msg };
            Event ev_for_sinks = ev; // copy for fan-out after releasing lock

            std::vector<Sink> sinks_copy;
            {
                std::lock_guard<std::mutex> lock(mtx_);

                // Enforce capacity strictly (cap_ is >= 1)
                if (buf_.size() >= cap_) {
                    const size_t drop = buf_.size() - cap_ + 1;
                    drop_front_(drop);
                }

                buf_.push_back(std::move(ev));
                sinks_copy = sinks_; // copy under lock; invoke out of lock
            }

            // Fan-out to sinks (e.g., file logger) without holding the lock.
            for (auto& s : sinks_copy) {
                if (s) s(ev_for_sinks);
            }
        }

        void Logf(Level lvl, const char* fmt, ...) {
            if (!fmt) return;

            char stackbuf[512];
            va_list ap;
            va_start(ap, fmt);
            int n = std::vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap);
            va_end(ap);

            if (n >= 0 && static_cast<size_t>(n) < sizeof(stackbuf)) {
                Log(lvl, std::string(stackbuf, stackbuf + n));
                return;
            }

            // grow
            size_t need = (n > 0) ? static_cast<size_t>(n) + 1 : 2048;
            std::string big; big.resize(need);
            va_start(ap, fmt);
            n = std::vsnprintf(big.data(), big.size(), fmt, ap);
            va_end(ap);
            if (n > 0) big.resize(static_cast<size_t>(n)); else big.clear();
            Log(lvl, big);
        }

        // Convenience shorthands
        void Debug(const std::string& m) { Log(Level::Debug, m); }
        void Info(const std::string& m) { Log(Level::Info, m); }
        void Warn(const std::string& m) { Log(Level::Warning, m); }
        void Error(const std::string& m) { Log(Level::Error, m); }

        void Debugf(const char* fmt, ...) {
            va_list ap; va_start(ap, fmt); LogfImpl(Level::Debug, fmt, ap); va_end(ap);
        }
        void Infof(const char* fmt, ...) {
            va_list ap; va_start(ap, fmt); LogfImpl(Level::Info, fmt, ap); va_end(ap);
        }
        void Warnf(const char* fmt, ...) {
            va_list ap; va_start(ap, fmt); LogfImpl(Level::Warning, fmt, ap); va_end(ap);
        }
        void Errorf(const char* fmt, ...) {
            va_list ap; va_start(ap, fmt); LogfImpl(Level::Error, fmt, ap); va_end(ap);
        }

        bool Drain(std::vector<Event>& out) {
            if (!mtx_.try_lock()) return false;
            std::lock_guard<std::mutex> _{ mtx_, std::adopt_lock };
            if (!buf_.empty()) {
                out.insert(out.end(),
                    std::make_move_iterator(buf_.begin()),
                    std::make_move_iterator(buf_.end()));
                buf_.clear();
            }
            return true;
        }

        bool DrainLatest(size_t max_events, std::vector<Event>& out) {
            if (!mtx_.try_lock()) return false;
            std::lock_guard<std::mutex> _{ mtx_, std::adopt_lock };
            if (buf_.empty()) return true;
            size_t n = (buf_.size() > max_events) ? max_events : buf_.size();
            auto start = buf_.end() - static_cast<std::ptrdiff_t>(n);
            out.insert(out.end(),
                std::make_move_iterator(start),
                std::make_move_iterator(buf_.end()));
            buf_.erase(start, buf_.end());
            return true;
        }

        void AddSink(Sink s) {
            std::lock_guard<std::mutex> lock(mtx_);
            sinks_.push_back(std::move(s));
        }

        void ClearSinks() {
            std::lock_guard<std::mutex> lock(mtx_);
            sinks_.clear();
        }

    private:
        static double NowSeconds() noexcept {
            using clock = std::chrono::steady_clock;
            static const auto t0 = clock::now();
            auto dt = clock::now() - t0;
            return std::chrono::duration<double>(dt).count();
        }

        // helper for *f methods
        void LogfImpl(Level lvl, const char* fmt, va_list ap) {
            if (!fmt) return;

            char stackbuf[512];
            va_list ap2;
            va_copy(ap2, ap);
            int n = std::vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap2);
            va_end(ap2);

            if (n >= 0 && static_cast<size_t>(n) < sizeof(stackbuf)) {
                Log(lvl, std::string(stackbuf, stackbuf + n));
                return;
            }

            size_t need = (n > 0) ? static_cast<size_t>(n) + 1 : 2048;
            std::string big; big.resize(need);
            std::vsnprintf(big.data(), big.size(), fmt, ap);
            if (!big.empty() && big.back() == '\0') big.pop_back();
            Log(lvl, big);
        }

        void trim_to_capacity_() {
            if (buf_.size() <= cap_) return;
            drop_front_(buf_.size() - cap_);
        }

        void drop_front_(size_t n) {
            // Pop in chunks to avoid massive single-range operations
            while (n-- && !buf_.empty()) buf_.pop_front();
        }

        mutable std::mutex      mtx_;
        std::deque<Event>       buf_;
        size_t                  cap_ = 1024;
        std::vector<Sink>       sinks_;
    };

    // Global application-wide logger 
    inline Channel App{};

    // Hub: get channels by name
    class Hub {
    public:
        static Hub& Instance() {
            static Hub h; return h;
        }

        Channel& Get(const std::string& name) {
            std::lock_guard<std::mutex> lock(mtx_);
            auto it = chans_.find(name);
            if (it != chans_.end()) return *it->second;
            auto ch = std::make_shared<Channel>();
            chans_[name] = ch;
            return *ch;
        }

        Channel& Create(const std::string& name, size_t capacity) {
            std::lock_guard<std::mutex> lock(mtx_);
            auto ch = std::make_shared<Channel>(capacity);
            chans_[name] = ch;
            return *ch;
        }
    private:
        std::mutex mtx_;
        std::unordered_map<std::string, std::shared_ptr<Channel>> chans_;
    };

    inline Channel& channel(const std::string& name = "app") {
        return Hub::Instance().Get(name);
    }

    inline const char* to_string(Level L) {
        switch (L) {
        case Level::Debug:   return "Debug";
        case Level::Info:    return "Info";
        case Level::Warning: return "Warning";
        case Level::Error:   return "Error";
        }
        return "";
    }

} // namespace pipetap::log
