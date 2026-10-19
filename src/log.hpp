#pragma once

#include <cstdarg>
#include <cstdio>
#include <string_view>

namespace dpi {

enum class LogLevel : int { Error = 0, Warn = 1, Info = 2, Debug = 3 };

LogLevel log_level_from_string(std::string_view s) noexcept;
const char* log_level_name(LogLevel l) noexcept;
void set_log_level(LogLevel l) noexcept;
LogLevel log_level() noexcept;

// Deliberately never logs packet payloads. Tags are static strings.
void log_msg(LogLevel l, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

} // namespace dpi
