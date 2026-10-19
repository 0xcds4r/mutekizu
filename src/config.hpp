#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dpi {

// Fixed names. Making these configurable would allow a user to aim the tool at
// foreign firewall objects; the tool only ever owns what it creates.
inline constexpr const char* kTableName = "mutekizu";
inline constexpr const char* kChainName = "output";
inline constexpr const char* kQueueComment = "mutekizu";

struct Config {
    std::uint16_t queue_num = 2000;
    std::uint32_t fwmark = 0x44495054u;
    std::uint32_t max_queue_len = 256;
    std::uint32_t copy_range = 65535;
    std::uint16_t split_delta = 4;   // bytes into the SNI hostname
    std::uint16_t split_stride = 4;  // 0 = one boundary; >0 = multi-split
    std::uint16_t split_max = 64;    // upper bound for multi-split boundaries
    std::uint16_t split_gap_ms = 0;  // delay between raw segments (experimental)
    bool split_disorder = false;     // emit segments in reverse order
    bool split_multidisorder = false; // emit segments outside-in
    bool split_data = false;          // also split later payloads of target flows
    std::uint16_t split_data_pos = 1; // split byte for later payloads
    std::uint16_t split_jitter_ms = 0; // random extra delay per segment
    bool fake_enabled = false;       // send a low-TTL fake ClientHello first
    std::uint16_t fake_ttl = 3;      // fake packet TTL/hop limit
    std::uint16_t fake_repeats = 3;  // fake packets per ClientHello
    std::string fake_sni = "www.google.com"; // SNI inside the fake hello
    bool seqovl_enabled = false;     // overlapping low-TTL fake segment
    std::uint16_t seqovl_bytes = 664; // sequence overlap
    std::uint16_t seqovl_repeats = 1;
    bool udp_fake_enabled = false;  // fake STUN for Discord/RTC UDP
    std::uint16_t udp_fake_ttl = 3;
    std::uint16_t udp_fake_repeats = 3;
    std::uint16_t mss = 1200;        // cap for our re-segmentation
    std::uint32_t inspect_packets = 10; // nft: ct original packets 0-N
    bool split_enabled = true;   // SNI ClientHello splitter (NFQUEUE)
    bool mss_clamp = false;      // MSS rewrite in SYN-ACK (nftables only)
    std::uint16_t mss_value = 96;
    std::string mss_targets_file = "/etc/mutekizu/mss_targets.txt";
    bool enable_ipv4 = true;
    bool enable_ipv6 = true;
    std::vector<std::uint16_t> ports{443};
    std::string domains_file = "/etc/mutekizu/domains.txt";
    std::string profiles_file = "/etc/mutekizu/profiles.conf";
    bool auto_profile = true;      // rotate matching profiles on failed attempts
    std::uint16_t auto_retry_window_s = 10;
    std::string log_level = "info";
    bool log_sni = false;

    // Auto-discovery: probe unknown SNIs without splitting; if the direct TLS
    // handshake does not answer, remember the SNI and split it next time.
    bool auto_discover = true;
    std::string auto_domains_file = "/var/lib/mutekizu/auto-domains.txt";
    std::uint32_t auto_probe_timeout_ms = 2500;
    std::uint32_t auto_probe_max = 4;
    std::uint32_t auto_domain_limit = 4096;
    std::uint32_t auto_probe_interval_s = 600;

    std::uint32_t max_flows = 1024;
    std::uint32_t flow_buffer = 8192;
    std::uint32_t flow_timeout_s = 30;
};

struct AddressSet {
    std::vector<std::string> v4;
    std::vector<std::string> v6;
    bool empty() const noexcept { return v4.empty() && v6.empty(); }
};

struct DomainSet {
    // Lowercase. An entry "example.com" matches example.com and *.example.com.
    std::vector<std::string> domains;

    bool matches(std::string_view host) const noexcept;
    void normalize();
};

// Returns false and fills error on any invalid/unknown key.
bool load_config(const std::string& path, Config& cfg, std::string& error);
bool load_domains(const std::string& path, DomainSet& set, std::string& error);
bool load_mss_targets(const std::string& path, AddressSet& set, std::string& error);

bool valid_domain(std::string_view s) noexcept;
std::string trim(std::string_view s);

} // namespace dpi
