#include "config.hpp"
#include "doctor.hpp"
#include "profiles.hpp"
#include "log.hpp"
#include "nfq_engine.hpp"
#include "nft_rules.hpp"
#include "process.hpp"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

constexpr const char* kDefaultConfig = "/etc/mutekizu/mutekizu.conf";
const char* pidfile_path()
{
    const char* env = std::getenv("MUTEKIZU_PIDFILE");
    return (env != nullptr && *env != '\0') ? env : "/run/mutekizu/mutekizu.pid";
}

std::atomic<dpi::NfqEngine*> g_engine{nullptr};
std::atomic<bool> g_stop_requested{false};
int g_lock_fd = -1;

void on_signal(int)
{
    g_stop_requested.store(true, std::memory_order_relaxed);
    dpi::NfqEngine* e = g_engine.load(std::memory_order_relaxed);
    if (e != nullptr) e->request_stop();
}

void usage()
{
    const std::string text =
        "mutekizu " MUTEKIZU_VERSION "\n"
        "\n"
        "Local TCP/TLS ClientHello splitter (no VPN, no proxy, no MITM).\n"
        "\n"
        "Usage: mutekizu [--config PATH] [--dry-run] [--verbose] COMMAND\n"
        "\n"
        "Commands:\n"
        "  run         Bind the NFQUEUE and install our nftables table, then serve.\n"
        "  doctor      Read-only environment and configuration diagnostics.\n"
        "  status      Show pidfile and whether our table is installed.\n"
        "  validate    Validate config/domain list and print the planned ruleset.\n"
        "  rules apply Install only our nftables table (queue must already exist).\n"
        "  rules remove Remove only our nftables table.\n"
        "  rules show  Print only our nftables table.\n"
        "  version     Print version.\n"
        "\n"
        "Options:\n"
        "  -c, --config PATH   configuration file (default " + std::string(kDefaultConfig) + ")\n"
        "  -n, --dry-run       print planned changes; never touch nftables\n"
        "  -v, --verbose       more diagnostics\n"
        "  -h, --help          this text\n";
    std::fputs(text.c_str(), stdout);
}

struct Options {
    std::string config = kDefaultConfig;
    bool dry_run = false;
    bool verbose = false;
    std::string command;
    std::string subcommand;
};

bool parse_args(int argc, char** argv, Options& o, std::string& error)
{
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-h" || a == "--help") { usage(); std::exit(0); }
        if (a == "-c" || a == "--config") {
            if (i + 1 >= argc) { error = "missing value for " + a; return false; }
            o.config = argv[++i];
        } else if (a.rfind("--config=", 0) == 0) {
            o.config = a.substr(9);
        } else if (a == "-n" || a == "--dry-run") {
            o.dry_run = true;
        } else if (a == "-v" || a == "--verbose") {
            o.verbose = true;
        } else if (!a.empty() && a[0] == '-') {
            error = "unknown option: " + a;
            return false;
        } else if (o.command.empty()) {
            o.command = a;
        } else if (o.subcommand.empty()) {
            o.subcommand = a;
        } else {
            error = "unexpected argument: " + a;
            return false;
        }
    }
    if (o.command.empty()) { error = "no command given"; return false; }
    return true;
}

bool acquire_instance_lock(std::string& error)
{
    // Refuse to overwrite a live instance.
    {
        std::ifstream in(pidfile_path());
        long pid = 0;
        if (in >> pid && pid > 0 && ::kill(static_cast<pid_t>(pid), 0) == 0) {
            error = "another instance appears to be running (pid " + std::to_string(pid) + ")";
            return false;
        }
    }
    {
        std::string path = pidfile_path();
        const auto slash = path.rfind('/');
        const std::string dir = slash == std::string::npos ? "" : path.substr(0, slash);
        if (!dir.empty() && !dpi::file_exists(dir)) {
            if (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST) {
                error = "mkdir " + dir + ": " + std::strerror(errno);
                return false;
            }
        }
    }
    const int fd = ::open(pidfile_path(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        error = std::string("open pidfile: ") + std::strerror(errno);
        return false;
    }
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        error = "another instance holds the lock on " + std::string(pidfile_path());
        ::close(fd);
        return false;
    }
    g_lock_fd = fd;
    const std::string pid = std::to_string(::getpid()) + "\n";
    const ssize_t n = ::write(fd, pid.data(), pid.size());
    ::close(fd);
    if (n != static_cast<ssize_t>(pid.size())) {
        error = "short write to pidfile";
        return false;
    }
    return true;
}

void release_instance_lock()
{
    if (g_lock_fd >= 0) {
        ::unlink(pidfile_path());
        ::close(g_lock_fd);
        g_lock_fd = -1;
    }
}

long read_pidfile()
{
    std::ifstream in(pidfile_path());
    long pid = 0;
    if (in >> pid) return pid;
    return -1;
}

int cmd_run(const dpi::Config& cfg, const dpi::DomainSet& domains,
            const dpi::AddressSet& mss_targets, bool dry_run)
{
    if (dry_run) {
        std::string err;
        if (!dpi::rules_apply(cfg, mss_targets, true, err)) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        std::fprintf(stdout,
                     "dry-run: config valid, %zu domain(s), %zu MSS target(s); "
                     "no nftables changes made\n",
                     domains.domains.size(), mss_targets.v4.size() + mss_targets.v6.size());
        return 0;
    }

    std::string err;
    if (!acquire_instance_lock(err)) {
        dpi::log_msg(dpi::LogLevel::Error, "%s", err.c_str());
        return 1;
    }

    std::unique_ptr<dpi::NfqEngine> engine;
    if (cfg.split_enabled) {
        engine = std::make_unique<dpi::NfqEngine>(cfg, domains);
        if (!engine->init(err)) {
            dpi::log_msg(dpi::LogLevel::Error, "cannot initialise NFQUEUE: %s", err.c_str());
            release_instance_lock();
            return 1;
        }
    }

    // Bind the queue before installing the rule: `bypass` covers the tiny gap,
    // and there is never a window where packets queue without a listener.
    if (!dpi::rules_apply(cfg, mss_targets, false, err)) {
        dpi::log_msg(dpi::LogLevel::Error, "cannot install nftables rules: %s", err.c_str());
        release_instance_lock();
        return 1;
    }

    g_engine.store(engine.get(), std::memory_order_relaxed);
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    ::sigaction(SIGTERM, &sa, nullptr);
    ::sigaction(SIGINT, &sa, nullptr);

    dpi::log_msg(dpi::LogLevel::Info,
                 "running: split=%s queue=%u mark=0x%x mss=%s value=%u domains=%zu targets=%zu",
                 cfg.split_enabled ? "on" : "off", static_cast<unsigned>(cfg.queue_num),
                 cfg.fwmark, cfg.mss_clamp ? "on" : "off",
                 static_cast<unsigned>(cfg.mss_value), domains.domains.size(),
                 mss_targets.v4.size() + mss_targets.v6.size());

    int rc = 0;
    if (engine) {
        rc = engine->run();
    } else {
        while (!g_stop_requested.load(std::memory_order_relaxed)) ::sleep(1);
    }
    g_engine.store(nullptr, std::memory_order_relaxed);

    std::string remove_err;
    if (!dpi::rules_remove(false, remove_err))
        dpi::log_msg(dpi::LogLevel::Warn, "could not remove rules on shutdown: %s",
                     remove_err.c_str());
    release_instance_lock();

    if (engine) {
        const auto& s = engine->stats();
        dpi::log_msg(dpi::LogLevel::Info,
                     "stopped: packets=%llu splits=%llu accepted=%llu parse_errors=%llu send_errors=%llu",
                     static_cast<unsigned long long>(s.packets),
                     static_cast<unsigned long long>(s.splits),
                     static_cast<unsigned long long>(s.accepted_unmodified),
                     static_cast<unsigned long long>(s.parse_errors),
                     static_cast<unsigned long long>(s.split_send_errors));
    } else {
        dpi::log_msg(dpi::LogLevel::Info, "stopped");
    }
    return rc;
}

int cmd_status()
{
    const long pid = read_pidfile();
    bool alive = false;
    if (pid > 0 && ::kill(static_cast<pid_t>(pid), 0) == 0) {
        alive = true;
        std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
        std::string name;
        std::getline(comm, name);
        std::printf("process: running (pid %ld, comm %s)\n", pid, name.c_str());
    } else {
        std::printf("process: not running\n");
    }

    std::string err;
    std::string table;
    if (dpi::rules_show(table, err)) {
        std::printf("rules: installed\n%s", table.c_str());
    } else {
        std::printf("rules: not installed\n");
    }
    return alive ? 0 : 3;
}

} // namespace

int main(int argc, char** argv)
{    Options opt;
    std::string err;
    if (!parse_args(argc, argv, opt, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        usage();
        return 2;
    }

    if (opt.command == "version") {
        std::printf("mutekizu " MUTEKIZU_VERSION "\n");
        return 0;
    }
    if (opt.command == "status") return cmd_status();

    // Cleanup/inspection needs no configuration: the table name is fixed and
    // this must keep working even if the config or targets file is broken.
    // Cleanup/inspection must work even if the targets file is gone.
    if (opt.command == "rules" && opt.subcommand == "remove") {
        if (!dpi::rules_remove(opt.dry_run, err)) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        return 0;
    }
    if (opt.command == "rules" && opt.subcommand == "show") {
        std::string out;
        if (!dpi::rules_show(out, err)) {
            std::fprintf(stderr, "error: %s\n", err.empty() ? "table not present" : err.c_str());
            return 1;
        }
        std::fputs(out.c_str(), stdout);
        return 0;
    }

    dpi::Config cfg;
    if (!dpi::load_config(opt.config, cfg, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    std::vector<dpi::Profile> profiles;
    if (!dpi::load_profiles(cfg.profiles_file, profiles, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    dpi::DomainSet domains;
    if (cfg.split_enabled && !dpi::load_domains(cfg.domains_file, domains, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }
    dpi::set_log_level(dpi::log_level_from_string(cfg.log_level));
    if (opt.verbose && dpi::log_level() < dpi::LogLevel::Debug)
        dpi::set_log_level(dpi::LogLevel::Debug);

    dpi::AddressSet mss_targets;
    if (cfg.mss_clamp && !dpi::load_mss_targets(cfg.mss_targets_file, mss_targets, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 2;
    }

    if (opt.command == "check-config") {
        std::printf("configuration OK\n");
        return 0;
    }

    if (opt.command == "doctor")
        return dpi::run_doctor(cfg, domains, mss_targets, opt.verbose);

    if (opt.command == "validate") {
        std::printf("config: ok (%zu domains, %zu ports, queue %u, mark 0x%x, mss=%s/%u, targets=%zu)\n",
                    domains.domains.size(), cfg.ports.size(),
                    static_cast<unsigned>(cfg.queue_num), cfg.fwmark,
                    cfg.mss_clamp ? "on" : "off", static_cast<unsigned>(cfg.mss_value),
                    mss_targets.v4.size() + mss_targets.v6.size());
        std::fputs(dpi::render_ruleset(cfg, mss_targets).c_str(), stdout);
        return 0;
    }

    if (opt.command == "run") return cmd_run(cfg, domains, mss_targets, opt.dry_run);

    if (opt.command == "rules") {
        if (opt.subcommand == "apply") {
            if (!dpi::rules_apply(cfg, mss_targets, opt.dry_run, err)) {
                std::fprintf(stderr, "error: %s\n", err.c_str());
                return 1;
            }
            return 0;
        }
        std::fprintf(stderr, "error: rules requires apply|remove|show\n");
        return 2;
    }

    std::fprintf(stderr, "error: unknown command '%s'\n", opt.command.c_str());
    usage();
    return 2;
}
