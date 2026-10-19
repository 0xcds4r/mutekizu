#include "process.hpp"

#include <cerrno>
#include <cstring>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace dpi {

bool file_exists(const std::string& path) noexcept
{
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

bool run_command(const std::vector<std::string>& argv, CmdResult& result,
                 std::string& error, int timeout_ms)
{
    result = CmdResult{};
    if (argv.empty()) { error = "empty command"; return false; }

    int pipefd[2];
    if (::pipe2(pipefd, O_CLOEXEC) != 0) {
        error = std::string("pipe2: ") + std::strerror(errno);
        return false;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        error = std::string("fork: ") + std::strerror(errno);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return false;
    }

    if (pid == 0) {
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        std::vector<char*> args;
        args.reserve(argv.size() + 1);
        for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        ::execvp(args[0], args.data());
        _exit(127);
    }

    ::close(pipefd[1]);

    const int deadline_ms = timeout_ms;
    int elapsed = 0;
    char buf[4096];
    bool eof = false;

    while (!eof && elapsed <= deadline_ms) {
        pollfd pfd{pipefd[0], POLLIN, 0};
        const int wait = deadline_ms - elapsed;
        const int rc = ::poll(&pfd, 1, wait < 0 ? 0 : wait);
        if (rc < 0) {
            if (errno == EINTR) continue;
            error = std::string("poll: ") + std::strerror(errno);
            break;
        }
        if (rc == 0) { result.timed_out = true; break; }

        const ssize_t n = ::read(pipefd[0], buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            result.timed_out = true;
            break;
        }
        if (n == 0) { eof = true; break; }
        if (result.output.size() < (1u << 20))
            result.output.append(buf, static_cast<std::size_t>(n));
        elapsed = 0; // progress resets the idle deadline
    }

    ::close(pipefd[0]);

    if (result.timed_out) {
        ::kill(pid, SIGKILL);
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (!result.timed_out) {
        if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) result.exit_code = 128 + WTERMSIG(status);
    }

    if (result.timed_out && error.empty()) {
        error = argv[0] + ": timed out after " + std::to_string(timeout_ms) + " ms";
    }
    return true;
}

} // namespace dpi
