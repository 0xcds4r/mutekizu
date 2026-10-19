#include "log.hpp"

#include <cstring>
#include <ctime>

namespace dpi {
namespace {
LogLevel g_level = LogLevel::Info;
}

LogLevel log_level_from_string(std::string_view s) noexcept
{
    if (s == "error") return LogLevel::Error;
    if (s == "warn") return LogLevel::Warn;
    if (s == "info") return LogLevel::Info;
    if (s == "debug") return LogLevel::Debug;
    return LogLevel::Info;
}

const char* log_level_name(LogLevel l) noexcept
{
    switch (l) {
    case LogLevel::Error: return "error";
    case LogLevel::Warn: return "warn";
    case LogLevel::Info: return "info";
    case LogLevel::Debug: return "debug";
    }
    return "info";
}

void set_log_level(LogLevel l) noexcept { g_level = l; }
LogLevel log_level() noexcept { return g_level; }

void log_msg(LogLevel l, const char* fmt, ...)
{
    if (static_cast<int>(l) > static_cast<int>(g_level)) return;

    char ts[32];
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    std::fprintf(stderr, "%s %s: ", ts, log_level_name(l));

    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);

    std::fputc('\n', stderr);
}

} // namespace dpi
