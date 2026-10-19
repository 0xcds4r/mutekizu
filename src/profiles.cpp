#include "profiles.hpp"
#include "config.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <set>

namespace dpi {
namespace {

bool u64(std::string_view s, std::uint64_t& v)
{
    if (s.empty()) return false;
    const auto* first = s.data();
    const auto* last = s.data() + s.size();
    const auto rc = std::from_chars(first, last, v, 10);
    return rc.ec == std::errc{} && rc.ptr == last;
}

bool boolean(std::string_view s, bool& v)
{
    if (s == "1" || s == "true" || s == "yes" || s == "on") { v = true; return true; }
    if (s == "0" || s == "false" || s == "no" || s == "off") { v = false; return true; }
    return false;
}

bool set_u16(std::string_view val, std::uint16_t lo, std::uint16_t hi,
             std::optional<std::uint16_t>& out)
{
    std::uint64_t v = 0;
    if (!u64(val, v) || v < lo || v > hi) return false;
    out = static_cast<std::uint16_t>(v);
    return true;
}

} // namespace

bool load_profiles(const std::string& path, std::vector<Profile>& out,
                   std::string& error)
{
    out.clear();
    std::ifstream in(path);
    if (!in) return true; // optional file

    Profile* current = nullptr;
    std::set<std::string> names;
    std::string line;
    unsigned line_no = 0;
    while (std::getline(in, line)) {
        ++line_no;
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        auto t = trim(line);
        if (t.empty()) continue;
        if (t.front() == '[') {
            if (t.back() != ']') {
                error = "line " + std::to_string(line_no) + ": malformed section";
                return false;
            }
            const std::string name = trim(std::string_view(t).substr(1, t.size() - 2));
            if (name.empty() || !valid_domain(name)) {
                error = "line " + std::to_string(line_no) + ": invalid profile name";
                return false;
            }
            if (!names.insert(name).second) {
                error = "line " + std::to_string(line_no) + ": duplicate profile " + name;
                return false;
            }
            out.push_back(Profile{});
            current = &out.back();
            current->name = name;
            continue;
        }
        if (current == nullptr) {
            error = "line " + std::to_string(line_no) + ": key outside [profile]";
            return false;
        }
        const auto eq = t.find('=');
        if (eq == std::string::npos) {
            error = "line " + std::to_string(line_no) + ": expected key=value";
            return false;
        }
        const std::string key = trim(std::string_view(t).substr(0, eq));
        const std::string val = trim(std::string_view(t).substr(eq + 1));
        auto bad = [&](const char* what) {
            error = "line " + std::to_string(line_no) + ": invalid " + what + " '" + val + "'";
            return false;
        };

        if (key == "interfaces") {
            current->interfaces.clear();
            std::size_t start = 0;
            while (start <= val.size()) {
                std::size_t comma = val.find(',', start);
                if (comma == std::string::npos) comma = val.size();
                std::string itf = trim(std::string_view(val).substr(start, comma - start));
                if (itf.empty() || itf.size() >= 16) return bad("interface");
                for (char c : itf)
                    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' ||
                          c == '_' || c == '.'))
                        return bad("interface");
                if (std::find(current->interfaces.begin(), current->interfaces.end(), itf) ==
                    current->interfaces.end())
                    current->interfaces.push_back(std::move(itf));
                if (comma == val.size()) break;
                start = comma + 1;
            }
            if (current->interfaces.empty()) return bad("interfaces");
        } else if (key == "domains") {
            current->domains.clear();
            std::size_t start = 0;
            while (start <= val.size()) {
                std::size_t comma = val.find(',', start);
                if (comma == std::string::npos) comma = val.size();
                std::string d = trim(std::string_view(val).substr(start, comma - start));
                std::transform(d.begin(), d.end(), d.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (!valid_domain(d)) return bad("domain");
                if (std::find(current->domains.begin(), current->domains.end(), d) ==
                    current->domains.end())
                    current->domains.push_back(std::move(d));
                if (comma == val.size()) break;
                start = comma + 1;
            }
            if (current->domains.empty()) return bad("domains");
        } else if (key == "split_enabled") {
            bool v = false;
            if (!boolean(val, v)) return bad("split_enabled");
            current->split_enabled = v;
        } else if (key == "split_delta") {
            if (!set_u16(val, 1, 200, current->split_delta)) return bad("split_delta");
        } else if (key == "split_stride") {
            if (!set_u16(val, 0, 64, current->split_stride)) return bad("split_stride");
        } else if (key == "split_max") {
            if (!set_u16(val, 1, 128, current->split_max)) return bad("split_max");
        } else if (key == "split_gap_ms") {
            if (!set_u16(val, 0, 100, current->split_gap_ms)) return bad("split_gap_ms");
        } else if (key == "split_disorder") {
            bool v = false;
            if (!boolean(val, v)) return bad("split_disorder");
            current->split_disorder = v;
        } else if (key == "split_multidisorder") {
            bool v = false;
            if (!boolean(val, v)) return bad("split_multidisorder");
            current->split_multidisorder = v;
        } else if (key == "split_data") {
            bool v = false;
            if (!boolean(val, v)) return bad("split_data");
            current->split_data = v;
        } else if (key == "split_data_pos") {
            if (!set_u16(val, 1, 1400, current->split_data_pos)) return bad("split_data_pos");
        } else if (key == "split_jitter_ms") {
            if (!set_u16(val, 0, 50, current->split_jitter_ms)) return bad("split_jitter_ms");
        } else if (key == "fake_enabled") {
            bool v = false;
            if (!boolean(val, v)) return bad("fake_enabled");
            current->fake_enabled = v;
        } else if (key == "fake_ttl") {
            if (!set_u16(val, 1, 64, current->fake_ttl)) return bad("fake_ttl");
        } else if (key == "fake_repeats") {
            if (!set_u16(val, 1, 16, current->fake_repeats)) return bad("fake_repeats");
        } else if (key == "fake_sni") {
            if (!valid_domain(val)) return bad("fake_sni");
            current->fake_sni = val;
        } else if (key == "seqovl_enabled") {
            bool v = false;
            if (!boolean(val, v)) return bad("seqovl_enabled");
            current->seqovl_enabled = v;
        } else if (key == "seqovl_bytes") {
            if (!set_u16(val, 1, 1400, current->seqovl_bytes)) return bad("seqovl_bytes");
        } else if (key == "seqovl_repeats") {
            if (!set_u16(val, 1, 16, current->seqovl_repeats)) return bad("seqovl_repeats");
        } else {
            error = "line " + std::to_string(line_no) + ": unknown profile key '" + key + "'";
            return false;
        }
    }
    for (const auto& p : out) {
        if (p.domains.empty()) {
            error = "profile '" + p.name + "' has no domains";
            return false;
        }
    }
    return true;
}

} // namespace dpi
