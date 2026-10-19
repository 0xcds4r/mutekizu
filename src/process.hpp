#pragma once

#include <string>
#include <vector>

namespace dpi {

struct CmdResult {
    int exit_code = -1;
    bool timed_out = false;
    std::string output; // stdout+stderr combined
};

// fork/execvp only. No shell, no string concatenation of untrusted input.
bool run_command(const std::vector<std::string>& argv, CmdResult& result,
                 std::string& error, int timeout_ms = 8000);

bool file_exists(const std::string& path) noexcept;

} // namespace dpi
