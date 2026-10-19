#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dpi {

// Optional per-domain overrides. The global [profile] defaults come from
// mutekizu.conf; a profile only stores the keys it overrides.
struct Profile {
    std::string name;
    std::vector<std::string> domains;

    std::optional<bool> split_enabled;
    std::optional<std::uint16_t> split_delta;
    std::optional<std::uint16_t> split_stride;
    std::optional<std::uint16_t> split_max;
    std::optional<std::uint16_t> split_gap_ms;
    std::optional<bool> split_disorder;
    std::optional<bool> split_multidisorder;
    std::optional<bool> split_data;
    std::optional<std::uint16_t> split_data_pos;
    std::optional<std::uint16_t> split_jitter_ms;

    std::optional<bool> fake_enabled;
    std::optional<std::uint16_t> fake_ttl;
    std::optional<std::uint16_t> fake_repeats;
    std::optional<std::string> fake_sni;

    std::optional<bool> seqovl_enabled;
    std::optional<std::uint16_t> seqovl_bytes;
    std::optional<std::uint16_t> seqovl_repeats;
};

// INI-like file:
//   [discord]
//   domains = discord.com, discord.gg, gateway.discord.gg
//   split_disorder = true
//   fake_enabled = true
//   fake_sni = www.microsoft.com
// Unknown keys and invalid ranges are hard errors. A missing file means
// "no profiles", not an error.
bool load_profiles(const std::string& path, std::vector<Profile>& out,
                   std::string& error);

} // namespace dpi
