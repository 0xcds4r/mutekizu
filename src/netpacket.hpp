#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <sys/socket.h>

namespace dpi {

// Parsed view of one L3 packet as delivered by NFQUEUE (no Ethernet header).
// The pointers refer to the caller-owned buffer and are valid only during the
// callback.
struct TcpPacket {
    std::uint8_t family = 0; // AF_INET or AF_INET6
    std::array<std::uint8_t, 16> src{};
    std::array<std::uint8_t, 16> dst{};
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint16_t window = 0;
    std::uint8_t flags = 0;
    std::uint8_t hop_limit = 64;
    std::uint8_t traffic_class = 0;
    std::uint16_t ip_id = 0;
    std::uint32_t flow_label = 0;
    bool dont_fragment = false;
    std::uint8_t tcp_options[40]{};
    std::uint8_t tcp_options_len = 0;
    const std::uint8_t* payload = nullptr;
    std::size_t payload_len = 0;

    bool is_ipv4() const noexcept { return family == AF_INET; }
    bool is_ipv6() const noexcept { return family == AF_INET6; }
};

// Rejects fragments, IPv6 extension headers, truncated or malformed packets.
bool parse_l3_packet(const std::uint8_t* data, std::size_t len, TcpPacket& out) noexcept;

struct UdpPacket {
    std::uint8_t family = 0;
    std::array<std::uint8_t, 16> src{};
    std::array<std::uint8_t, 16> dst{};
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint8_t hop_limit = 64;
    std::uint8_t traffic_class = 0;
    std::uint16_t ip_id = 0;
    bool dont_fragment = false;
    const std::uint8_t* payload = nullptr;
    std::size_t payload_len = 0;
    bool is_ipv4() const noexcept { return family == AF_INET; }
    bool is_ipv6() const noexcept { return family == AF_INET6; }
};

bool parse_udp_packet(const std::uint8_t* data, std::size_t len, UdpPacket& out) noexcept;
bool send_fake_udp(int raw_fd, const UdpPacket& p,
                   const std::uint8_t* payload, std::size_t payload_len,
                   std::uint8_t ttl, std::uint16_t ip_id, std::string& error);


struct SendSplitResult {
    bool ok = false;
    std::size_t segments = 0;
    std::string error;
};

struct SendOptions {
    std::size_t max_payload_per_segment = 1200;
    std::uint32_t gap_ms = 0;
    bool disorder = false;
    bool multidisorder = false;
    std::uint32_t jitter_ms = 0;
};

// Re-emits the TCP payload of `p` as multiple segments, with the first boundary
// at `split_in_payload`. Uses a raw IP socket opened by the caller.
SendSplitResult send_split_segments(int raw_fd, const TcpPacket& p,
                                    const std::vector<std::size_t>& boundaries,
                                    std::size_t max_payload_per_segment,
                                    std::uint32_t gap_ms = 0);
SendSplitResult send_split_segments(int raw_fd, const TcpPacket& p,
                                    const std::vector<std::size_t>& boundaries,
                                    const SendOptions& options);

// Sends one fake TCP data segment with the supplied TTL/hop limit. The caller
// uses a low TTL so the segment reaches an on-path DPI but not the server.
bool send_fake_segment(int raw_fd, const TcpPacket& p, std::uint32_t seq,
                       const std::uint8_t* payload, std::size_t payload_len,
                       std::uint8_t ttl, std::uint16_t ip_id, std::string& error);

} // namespace dpi
