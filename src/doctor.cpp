#include "doctor.hpp"
#include "log.hpp"
#include "nft_rules.hpp"
#include "process.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <vector>

#include <arpa/inet.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

namespace dpi {
namespace {

int g_warnings = 0;
int g_errors = 0;

void ok(const char* fmt, ...)
{
    std::fprintf(stdout, "[ ok ] ");
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stdout, fmt, ap);
    va_end(ap);
    std::fputc('\n', stdout);
}
void warn(const char* fmt, ...)
{
    ++g_warnings;
    std::fprintf(stdout, "[warn] ");
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stdout, fmt, ap);
    va_end(ap);
    std::fputc('\n', stdout);
}
void fail(const char* fmt, ...)
{
    ++g_errors;
    std::fprintf(stdout, "[fail] ");
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stdout, fmt, ap);
    va_end(ap);
    std::fputc('\n', stdout);
}

bool have_cap(int cap_bit)
{
    std::ifstream in("/proc/self/status");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("CapEff:", 0) != 0) continue;
        std::istringstream is(line.substr(7));
        unsigned long long v = 0;
        is >> std::hex >> v;
        return (v & (1ull << cap_bit)) != 0;
    }
    return false;
}

std::string module_state(const std::string& name)
{
    std::ifstream in("/proc/modules");
    std::string line;
    while (std::getline(in, line)) {
        if (line.compare(0, name.size(), name) == 0 && line.size() > name.size() &&
            line[name.size()] == ' ')
            return line;
    }
    return {};
}

std::string trim_copy(const std::string& s)
{
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

struct ActiveService {
    bool running = false;
    bool admin = false;
    bool raw = false;
    int pid = 0;
};

ActiveService active_service()
{
    ActiveService out;
    DIR* dir = ::opendir("/proc");
    if (dir == nullptr) return out;
    while (dirent* e = ::readdir(dir)) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        const int pid = std::atoi(e->d_name);
        if (pid <= 0 || pid == ::getpid()) continue;

        std::ifstream cmd(std::string("/proc/") + e->d_name + "/cmdline",
                          std::ios::binary);
        std::string cmdline((std::istreambuf_iterator<char>(cmd)),
                            std::istreambuf_iterator<char>());
        if (cmdline.find("mutekizu") == std::string::npos ||
            cmdline.find("run") == std::string::npos)
            continue;

        std::ifstream status(std::string("/proc/") + e->d_name + "/status");
        std::string line;
        bool admin = false, raw = false;
        while (std::getline(status, line)) {
            if (line.rfind("CapEff:", 0) != 0) continue;
            std::istringstream is(line.substr(7));
            unsigned long long v = 0;
            is >> std::hex >> v;
            admin = (v & (1ull << 12)) != 0;
            raw = (v & (1ull << 13)) != 0;
            break;
        }
        if (admin || raw) {
            out.running = true;
            out.admin = admin;
            out.raw = raw;
            out.pid = pid;
            if (admin && raw) break;
        }
    }
    ::closedir(dir);
    return out;
}

} // namespace

bool nft_queue_conflicts(std::uint16_t queue_num, std::string& detail, std::string& error)
{
    CmdResult r;
    if (!run_command({"/usr/bin/nft", "list", "ruleset"}, r, error)) return false;
    if (r.exit_code != 0) {
        error = r.output;
        return false;
    }
    const std::string needle = "queue num " + std::to_string(queue_num);
    const std::string needle2 = "to " + std::to_string(queue_num);
    std::istringstream is(r.output);
    std::string line;
    bool found = false;
    while (std::getline(is, line)) {
        // Our own active table legitimately references the queue; only a
        // reference from another table is a conflict.
        if (line.find("comment \"mutekizu\"") != std::string::npos) continue;
        if (line.find("table inet mutekizu") != std::string::npos) continue;
        if (line.find(needle) != std::string::npos || line.find(needle2) != std::string::npos) {
            detail += line + "\n";
            found = true;
        }
    }
    return found;
}

int run_doctor(const Config& cfg, const DomainSet& domains, const AddressSet& mss_targets,
               bool verbose)
{
    g_warnings = 0;
    g_errors = 0;

    utsname u{};
    if (uname(&u) == 0) ok("kernel %s %s", u.release, u.machine);
    else fail("uname failed");

    std::string nft_version;
    if (nft_available(nft_version)) ok("%s", nft_version.c_str());
    else fail("nftables binary not usable at /usr/bin/nft");

    const ActiveService svc = active_service();
    if (svc.running) {
        if (svc.admin && svc.raw)
            ok("mutekizu.service running (pid %d) with CAP_NET_ADMIN + CAP_NET_RAW", svc.pid);
        else
            warn("mutekizu.service running (pid %d) but missing a capability", svc.pid);
    } else {
        warn("mutekizu.service is not running");
    }

    const bool self_admin = have_cap(12);
    const bool self_raw = have_cap(13);
    if (self_admin) ok("CAP_NET_ADMIN present");
    else if (svc.running && svc.admin)
        warn("CAP_NET_ADMIN missing in this diagnostic process; the running service has it");
    else fail("CAP_NET_ADMIN missing (run as root or via the systemd unit)");
    if (self_raw) ok("CAP_NET_RAW present");
    else if (svc.running && svc.raw)
        warn("CAP_NET_RAW missing in this diagnostic process; the running service has it");
    else fail("CAP_NET_RAW missing (raw segment injection needs it)");
    if ((!self_admin || !self_raw) && svc.running && svc.admin && svc.raw)
        warn("CAP checks describe this diagnostic process; the systemd unit has its own capabilities");

    {
        const int fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (fd >= 0) { ::close(fd); ok("raw IP socket available"); }
        else warn("raw IP socket unavailable: %s", std::strerror(errno));
    }
    {
        const int fd = ::socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (fd >= 0) { ::close(fd); ok("raw IPv6 socket available"); }
        else warn("raw IPv6 socket unavailable: %s", std::strerror(errno));
    }

    for (const char* mod : {"nfnetlink_queue", "nf_tables", "nf_conntrack"}) {
        const std::string st = module_state(mod);
        if (!st.empty()) ok("module %s loaded", mod);
        else if (file_exists(std::string("/sys/module/") + mod)) ok("module %s built-in", mod);
        else warn("module %s not loaded (it may autoload on first use)", mod);
    }

    std::string err;
    const TableState table = nft_table_exists(err);
    if (table == TableState::Present) {
        std::string own_err;
        if (table_owned(own_err))
            warn("owned table inet %s is present (service may be running; remove only when stopped)", kTableName);
        else
            fail("table inet %s exists but is not ours: %s", kTableName, own_err.c_str());
    } else if (table == TableState::Absent)
        ok("no pre-existing table inet %s", kTableName);
    else
        warn("cannot check table inet %s (insufficient privileges)", kTableName);

    if (cfg.split_enabled) {
        std::string conflict_detail;
        std::string conflict_err;
        if (nft_queue_conflicts(cfg.queue_num, conflict_detail, conflict_err)) {
            fail("queue number %u is already referenced by nftables:\n%s",
                 static_cast<unsigned>(cfg.queue_num), conflict_detail.c_str());
        } else if (!conflict_err.empty()) {
            warn("cannot inspect nftables ruleset: %s", conflict_err.c_str());
        } else {
            ok("queue number %u not referenced by a foreign table", static_cast<unsigned>(cfg.queue_num));
        }
    } else {
        ok("SNI splitter disabled; NFQUEUE is not used");
    }

    if (cfg.mss_clamp) {
        if (mss_targets.empty())
            fail("MSS clamp enabled but the targets file is empty");
        else
            ok("MSS clamp: value %u, %zu IPv4 / %zu IPv6 target(s)",
               static_cast<unsigned>(cfg.mss_value), mss_targets.v4.size(), mss_targets.v6.size());
    }

    {
        CmdResult r;
        std::string ip_err;
        if (run_command({"/usr/bin/ip", "rule", "show"}, r, ip_err) && r.exit_code == 0) {
            std::istringstream is(r.output);
            std::string line;
            bool any_fwmark = false;
            while (std::getline(is, line)) {
                if (line.find("fwmark") != std::string::npos) {
                    any_fwmark = true;
                    std::ostringstream hex, dec;
                    hex << "0x" << std::hex << cfg.fwmark;
                    dec << std::dec << cfg.fwmark;
                    if (line.find(hex.str()) != std::string::npos ||
                        line.find(dec.str()) != std::string::npos)
                        fail("routing policy uses our fwmark: %s", trim_copy(line).c_str());
                }
            }
            if (any_fwmark && g_errors == 0)
                warn("policy routing uses fwmark; verify it does not match 0x%x", cfg.fwmark);
            if (!any_fwmark) ok("no fwmark-based policy routing rules");
        } else {
            warn("cannot inspect 'ip rule': %s", ip_err.c_str());
        }
    }

    {
        ifaddrs* ifa = nullptr;
        if (getifaddrs(&ifa) == 0) {
            std::set<std::string> seen;
            std::set<std::string> v6_global;
            int min_mtu = 1 << 30;
            for (ifaddrs* p = ifa; p != nullptr; p = p->ifa_next) {
                if (p->ifa_name == nullptr) continue;
                const std::string name = p->ifa_name;
                if (seen.insert(name).second) {
                    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
                    if (fd >= 0) {
                        ifreq ifr{};
                        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
                        if (::ioctl(fd, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0)
                            min_mtu = std::min(min_mtu, ifr.ifr_mtu);
                        ::close(fd);
                    }
                }
                if (p->ifa_addr != nullptr && p->ifa_addr->sa_family == AF_INET6) {
                    const auto* a6 = reinterpret_cast<const sockaddr_in6*>(p->ifa_addr);
                    if (!IN6_IS_ADDR_LINKLOCAL(&a6->sin6_addr) &&
                        !IN6_IS_ADDR_LOOPBACK(&a6->sin6_addr))
                        v6_global.emplace(name);
                }
            }
            ::freeifaddrs(ifa);
            if (min_mtu < (1 << 30)) ok("minimum interface MTU: %d (split MSS cap: %u)",
                                        min_mtu, static_cast<unsigned>(cfg.mss));
            if (v6_global.empty() && cfg.enable_ipv6)
                warn("no global IPv6 address; IPv6 handling will be mostly idle");
            else if (!v6_global.empty())
                ok("global IPv6 present on %zu interface(s)", v6_global.size());
        }
    }

    ok("config valid; %zu target domain(s); queue %u, mark 0x%x",
       domains.domains.size(), static_cast<unsigned>(cfg.queue_num), cfg.fwmark);
    if (verbose) {
        std::fputs("--- planned ruleset (not applied) ---\n", stdout);
        std::fputs(render_ruleset(cfg, mss_targets).c_str(), stdout);
    }

    if (g_errors > 0) return 1;
    if (g_warnings > 0) return 2;
    return 0;
}

} // namespace dpi
