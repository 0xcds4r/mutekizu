#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <set>
#include <sstream>

#include <arpa/inet.h>

namespace dpi {
namespace {

bool parse_u64(std::string_view s, std::uint64_t& out) noexcept
{
    if (s.empty()) return false;
    std::uint64_t v = 0;
    const auto* first = s.data();
    const auto* last = s.data() + s.size();
    auto rc = std::from_chars(first, last, v, 10);
    if (rc.ec != std::errc{} || rc.ptr != last) return false;
    out = v;
    return true;
}

bool parse_hex32(std::string_view s, std::uint32_t& out) noexcept
{
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
    if (s.empty() || s.size() > 8) return false;
    std::uint32_t v = 0;
    const auto* first = s.data();
    const auto* last = s.data() + s.size();
    auto rc = std::from_chars(first, last, v, 16);
    if (rc.ec != std::errc{} || rc.ptr != last) return false;
    out = v;
    return true;
}

bool parse_bool(std::string_view s, bool& out) noexcept
{
    if (s == "1" || s == "true" || s == "yes" || s == "on") { out = true; return true; }
    if (s == "0" || s == "false" || s == "no" || s == "off") { out = false; return true; }
    return false;
}

bool parse_ports(std::string_view s, std::vector<std::uint16_t>& out, std::string& error)
{
    out.clear();
    std::size_t start = 0;
    while (start <= s.size()) {
        std::size_t comma = s.find(',', start);
        if (comma == std::string_view::npos) comma = s.size();
        auto item = trim(s.substr(start, comma - start));
        if (!item.empty()) {
            std::uint64_t v = 0;
            if (!parse_u64(item, v) || v == 0 || v > 65535) {
                error = "invalid port: " + item;
                return false;
            }
            out.push_back(static_cast<std::uint16_t>(v));
        }
        if (comma == s.size()) break;
        start = comma + 1;
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    if (out.empty()) { error = "at least one port is required"; return false; }
    if (out.size() > 16) { error = "too many ports (max 16)"; return false; }
    return true;
}

} // namespace

std::string trim(std::string_view s)
{
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

bool valid_domain(std::string_view s) noexcept
{
    if (s.empty() || s.size() > 253) return false;
    if (s.front() == '.' || s.back() == '.') return false;
    for (char c : s) {
        unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '-' || c == '.' || c == '_')) return false;
    }
    return true;
}

void DomainSet::normalize()
{
    for (auto& d : domains)
        std::transform(d.begin(), d.end(), d.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    domains.erase(std::remove_if(domains.begin(), domains.end(),
                                 [](const std::string& d) { return !valid_domain(d); }),
                  domains.end());
    std::sort(domains.begin(), domains.end());
    domains.erase(std::unique(domains.begin(), domains.end()), domains.end());
}

bool DomainSet::matches(std::string_view host) const noexcept
{
    for (const auto& d : domains) {
        if (host.size() == d.size()) {
            if (std::equal(d.begin(), d.end(), host.begin(), [](char a, char b) {
                    return std::tolower(static_cast<unsigned char>(b)) == a;
                }))
                return true;
        } else if (host.size() > d.size() && host[host.size() - d.size() - 1] == '.' &&
                   std::equal(d.rbegin(), d.rend(), host.rbegin(), [](char a, char b) {
                       return std::tolower(static_cast<unsigned char>(b)) == a;
                   })) {
            return true;
        }
    }
    return false;
}

bool load_config(const std::string& path, Config& cfg, std::string& error)
{
    std::ifstream in(path);
    if (!in) { error = "cannot open config: " + path; return false; }

    Config out;
    std::string line;
    unsigned line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        auto t = trim(line);
        if (t.empty()) continue;
        auto eq = t.find('=');
        if (eq == std::string::npos) {
            error = "line " + std::to_string(line_no) + ": expected key=value";
            return false;
        }
        auto key = trim(std::string_view(t).substr(0, eq));
        auto val = trim(std::string_view(t).substr(eq + 1));
        auto bad = [&](const char* what) {
            error = "line " + std::to_string(line_no) + ": invalid " + what + " '" + val + "'";
            return false;
        };

        if (key == "queue_num") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 65535) return bad("queue_num");
            out.queue_num = static_cast<std::uint16_t>(v);
        } else if (key == "fwmark") {
            std::uint32_t v = 0;
            if (!parse_hex32(val, v) || v == 0 || v == 0xffffffffu) return bad("fwmark");
            out.fwmark = v;
        } else if (key == "max_queue_len") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 65535) return bad("max_queue_len");
            out.max_queue_len = static_cast<std::uint32_t>(v);
        } else if (key == "copy_range") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v < 64 || v > 65535) return bad("copy_range");
            out.copy_range = static_cast<std::uint32_t>(v);
        } else if (key == "split_delta") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 200) return bad("split_delta");
            out.split_delta = static_cast<std::uint16_t>(v);
        } else if (key == "split_stride") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v > 64) return bad("split_stride");
            out.split_stride = static_cast<std::uint16_t>(v);
        } else if (key == "split_max") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 128) return bad("split_max");
            out.split_max = static_cast<std::uint16_t>(v);
        } else if (key == "split_gap_ms") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v > 100) return bad("split_gap_ms");
            out.split_gap_ms = static_cast<std::uint16_t>(v);
        } else if (key == "split_disorder") {
            if (!parse_bool(val, out.split_disorder)) return bad("split_disorder");
        } else if (key == "split_multidisorder") {
            if (!parse_bool(val, out.split_multidisorder)) return bad("split_multidisorder");
        } else if (key == "split_data") {
            if (!parse_bool(val, out.split_data)) return bad("split_data");
        } else if (key == "split_data_pos") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 1400) return bad("split_data_pos");
            out.split_data_pos = static_cast<std::uint16_t>(v);
        } else if (key == "split_jitter_ms") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v > 50) return bad("split_jitter_ms");
            out.split_jitter_ms = static_cast<std::uint16_t>(v);
        } else if (key == "fake_enabled") {
            if (!parse_bool(val, out.fake_enabled)) return bad("fake_enabled");
        } else if (key == "fake_ttl") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 64) return bad("fake_ttl");
            out.fake_ttl = static_cast<std::uint16_t>(v);
        } else if (key == "fake_repeats") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 16) return bad("fake_repeats");
            out.fake_repeats = static_cast<std::uint16_t>(v);
        } else if (key == "fake_sni") {
            if (val.empty() || !valid_domain(val)) return bad("fake_sni");
            out.fake_sni = val;
        } else if (key == "fake_bad_checksum") {
            if (!parse_bool(val, out.fake_bad_checksum)) return bad("fake_bad_checksum");
        } else if (key == "fake_seq_offset") {
            std::int64_t v = 0;
            const auto* first = val.data();
            const auto* last = val.data() + val.size();
            auto rc = std::from_chars(first, last, v, 10);
            if (rc.ec != std::errc{} || rc.ptr != last || v < -32768 || v > 32767)
                return bad("fake_seq_offset");
            out.fake_seq_offset = static_cast<std::int16_t>(v);
        } else if (key == "fake_timestamp") {
            if (!parse_bool(val, out.fake_timestamp)) return bad("fake_timestamp");
        } else if (key == "seqovl_enabled") {
            if (!parse_bool(val, out.seqovl_enabled)) return bad("seqovl_enabled");
        } else if (key == "seqovl_bytes") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 1400) return bad("seqovl_bytes");
            out.seqovl_bytes = static_cast<std::uint16_t>(v);
        } else if (key == "udp_fake_enabled") {
            if (!parse_bool(val, out.udp_fake_enabled)) return bad("udp_fake_enabled");
        } else if (key == "udp_fake_ttl") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 64) return bad("udp_fake_ttl");
            out.udp_fake_ttl = static_cast<std::uint16_t>(v);
        } else if (key == "udp_fake_repeats") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 16) return bad("udp_fake_repeats");
            out.udp_fake_repeats = static_cast<std::uint16_t>(v);
        } else if (key == "udp_fake_type") {
            if (val != "stun" && val != "quic" && val != "discord" && val != "random")
                return bad("udp_fake_type");
            out.udp_fake_type = val;
        } else if (key == "seqovl_repeats") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 16) return bad("seqovl_repeats");
            out.seqovl_repeats = static_cast<std::uint16_t>(v);
        } else if (key == "mss") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v < 200 || v > 9000) return bad("mss");
            out.mss = static_cast<std::uint16_t>(v);
        } else if (key == "inspect_packets") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 64) return bad("inspect_packets");
            out.inspect_packets = static_cast<std::uint32_t>(v);
        } else if (key == "split_enabled") {
            if (!parse_bool(val, out.split_enabled)) return bad("split_enabled");
        } else if (key == "mss_clamp") {
            if (!parse_bool(val, out.mss_clamp)) return bad("mss_clamp");
        } else if (key == "mss_value") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v < 88 || v > 536) return bad("mss_value");
            out.mss_value = static_cast<std::uint16_t>(v);
        } else if (key == "mss_targets_file") {
            if (val.empty()) return bad("mss_targets_file");
            out.mss_targets_file = val;
        } else if (key == "ipv4") {
            if (!parse_bool(val, out.enable_ipv4)) return bad("ipv4");
        } else if (key == "ipv6") {
            if (!parse_bool(val, out.enable_ipv6)) return bad("ipv6");
        } else if (key == "ports") {
            if (!parse_ports(val, out.ports, error)) {
                error = "line " + std::to_string(line_no) + ": " + error;
                return false;
            }
        } else if (key == "domains_file") {
            if (val.empty()) return bad("domains_file");
            out.domains_file = val;
        } else if (key == "profiles_file") {
            if (val.empty()) return bad("profiles_file");
            out.profiles_file = val;
        } else if (key == "auto_profile") {
            if (!parse_bool(val, out.auto_profile)) return bad("auto_profile");
        } else if (key == "auto_retry_window_s") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 300) return bad("auto_retry_window_s");
            out.auto_retry_window_s = static_cast<std::uint16_t>(v);
        } else if (key == "reply_observe") {
            if (!parse_bool(val, out.reply_observe)) return bad("reply_observe");
        } else if (key == "reply_queue_num") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 65535) return bad("reply_queue_num");
            out.reply_queue_num = static_cast<std::uint16_t>(v);
        } else if (key == "reply_inspect_packets") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 16) return bad("reply_inspect_packets");
            out.reply_inspect_packets = static_cast<std::uint32_t>(v);
        } else if (key == "log_level") {
            if (val != "error" && val != "warn" && val != "info" && val != "debug")
                return bad("log_level");
            out.log_level = val;
        } else if (key == "log_sni") {
            if (!parse_bool(val, out.log_sni)) return bad("log_sni");
        } else if (key == "auto_discover") {
            if (!parse_bool(val, out.auto_discover)) return bad("auto_discover");
        } else if (key == "auto_domains_file") {
            if (val.empty()) return bad("auto_domains_file");
            out.auto_domains_file = val;
        } else if (key == "auto_probe_timeout_ms") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v < 500 || v > 10000) return bad("auto_probe_timeout_ms");
            out.auto_probe_timeout_ms = static_cast<std::uint32_t>(v);
        } else if (key == "auto_probe_max") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 32) return bad("auto_probe_max");
            out.auto_probe_max = static_cast<std::uint32_t>(v);
        } else if (key == "auto_domain_limit") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v < 64 || v > 65536) return bad("auto_domain_limit");
            out.auto_domain_limit = static_cast<std::uint32_t>(v);
        } else if (key == "auto_probe_interval_s") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v < 60 || v > 86400) return bad("auto_probe_interval_s");
            out.auto_probe_interval_s = static_cast<std::uint32_t>(v);
        } else if (key == "max_flows") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 65536) return bad("max_flows");
            out.max_flows = static_cast<std::uint32_t>(v);
        } else if (key == "flow_buffer") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v < 512 || v > 65535) return bad("flow_buffer");
            out.flow_buffer = static_cast<std::uint32_t>(v);
        } else if (key == "flow_timeout_s") {
            std::uint64_t v = 0;
            if (!parse_u64(val, v) || v == 0 || v > 3600) return bad("flow_timeout_s");
            out.flow_timeout_s = static_cast<std::uint32_t>(v);
        } else {
            error = "line " + std::to_string(line_no) + ": unknown key '" + key + "'";
            return false;
        }
    }

    if (!out.enable_ipv4 && !out.enable_ipv6) {
        error = "at least one of ipv4/ipv6 must be enabled";
        return false;
    }
    if (out.reply_observe && out.reply_queue_num == out.queue_num) {
        error = "reply_queue_num must differ from queue_num";
        return false;
    }
    if (!out.split_enabled && !out.mss_clamp) {
        error = "split_enabled and mss_clamp are both false; nothing to do";
        return false;
    }
    cfg = std::move(out);
    return true;
}

bool load_domains(const std::string& path, DomainSet& set, std::string& error)
{
    std::ifstream in(path);
    if (!in) { error = "cannot open domains file: " + path; return false; }

    DomainSet out;
    std::string line;
    unsigned line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        auto t = trim(line);
        if (t.empty()) continue;
        if (!valid_domain(t)) {
            error = path + ":" + std::to_string(line_no) + ": invalid domain '" + t + "'";
            return false;
        }
        out.domains.push_back(std::move(t));
        if (out.domains.size() > 8192) { error = "too many domains (max 8192)"; return false; }
    }
    out.normalize();
    if (out.domains.empty()) error = "domains file contains no entries: " + path;
    if (!error.empty()) return false;
    set = std::move(out);
    return true;
}

bool load_mss_targets(const std::string& path, AddressSet& set, std::string& error)
{
    std::ifstream in(path);
    if (!in) { error = "cannot open MSS targets file: " + path; return false; }

    AddressSet out;
    std::set<std::string> seen;
    std::string line;
    unsigned line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        auto t = trim(line);
        if (t.empty()) continue;
        if (t.find('/') != std::string::npos) {
            error = path + ":" + std::to_string(line_no) +
                    ": CIDR is not accepted; list explicit addresses";
            return false;
        }
        std::uint8_t buf[16]{};
        int family = 0;
        if (::inet_pton(AF_INET, t.c_str(), buf) == 1) family = AF_INET;
        else if (::inet_pton(AF_INET6, t.c_str(), buf) == 1) family = AF_INET6;
        else {
            error = path + ":" + std::to_string(line_no) + ": not a literal IP address: " + t;
            return false;
        }
        char canonical[INET6_ADDRSTRLEN]{};
        if (::inet_ntop(family, buf, canonical, sizeof(canonical)) == nullptr) {
            error = "inet_ntop failed";
            return false;
        }
        const std::string key = (family == AF_INET ? "4:" : "6:") + std::string(canonical);
        if (!seen.insert(key).second) continue;
        auto& list = family == AF_INET ? out.v4 : out.v6;
        if (list.size() >= 256) {
            error = "too many addresses (max 256 per family)";
            return false;
        }
        list.emplace_back(canonical);
    }
    if (out.empty()) { error = "MSS targets file contains no addresses: " + path; return false; }
    set = std::move(out);
    return true;
}

} // namespace dpi
