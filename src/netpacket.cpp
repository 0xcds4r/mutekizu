#include "netpacket.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <random>
#include <thread>
#include <cstring>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace dpi {
namespace {

constexpr std::uint8_t kProtoTcp = 6;
constexpr std::uint8_t kTcpFin = 0x01;
constexpr std::uint8_t kTcpSyn = 0x02;
constexpr std::uint8_t kTcpRst = 0x04;
constexpr std::uint8_t kTcpPush = 0x08;
constexpr std::uint8_t kTcpAck = 0x10;

std::uint16_t read16(const std::uint8_t* p) noexcept
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1]);
}

std::uint32_t read32(const std::uint8_t* p) noexcept
{
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

void write16(std::uint8_t* p, std::uint16_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xff);
}

void write32(std::uint8_t* p, std::uint32_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>((v >> 16) & 0xff);
    p[2] = static_cast<std::uint8_t>((v >> 8) & 0xff);
    p[3] = static_cast<std::uint8_t>(v & 0xff);
}

std::uint32_t sum_bytes(std::uint32_t sum, const std::uint8_t* p, std::size_t n) noexcept
{
    while (n > 1) {
        sum += read16(p);
        p += 2;
        n -= 2;
    }
    if (n != 0) sum += static_cast<std::uint16_t>(p[0] << 8);
    return sum;
}

std::uint16_t checksum_fold(std::uint32_t sum) noexcept
{
    while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum & 0xffff);
}

std::vector<std::uint8_t> build_segment(const TcpPacket& p, std::uint32_t seq,
                                        const std::uint8_t* payload, std::size_t payload_len,
                                        bool push, std::uint16_t ip_id, std::uint8_t ttl)
{
    const std::size_t tcp_hdr_len = 20 + p.tcp_options_len;
    const std::size_t tcp_len = tcp_hdr_len + payload_len;

    std::vector<std::uint8_t> pkt;
    std::size_t ip_hdr_len = 0;
    std::size_t total = 0;

    if (p.is_ipv4()) {
        ip_hdr_len = 20;
        total = ip_hdr_len + tcp_len;
        pkt.assign(total, 0);
        pkt[0] = 0x45;
        pkt[1] = p.traffic_class;
        write16(pkt.data() + 2, static_cast<std::uint16_t>(total));
        write16(pkt.data() + 4, ip_id);
        std::uint16_t frag = 0;
        if (p.dont_fragment) frag |= 0x4000;
        write16(pkt.data() + 6, frag);
        pkt[8] = ttl;
        pkt[9] = kProtoTcp;
        std::memcpy(pkt.data() + 12, p.src.data(), 4);
        std::memcpy(pkt.data() + 16, p.dst.data(), 4);
        write16(pkt.data() + 10, checksum_fold(sum_bytes(0, pkt.data(), ip_hdr_len)));
    } else {
        ip_hdr_len = 40;
        total = ip_hdr_len + tcp_len;
        pkt.assign(total, 0);
        const std::uint32_t vtf = (6u << 28) |
                                  (static_cast<std::uint32_t>(p.traffic_class) << 20) |
                                  (p.flow_label & 0x000fffffu);
        write32(pkt.data(), vtf);
        write16(pkt.data() + 4, static_cast<std::uint16_t>(tcp_len));
        pkt[6] = kProtoTcp;
        pkt[7] = ttl;
        std::memcpy(pkt.data() + 8, p.src.data(), 16);
        std::memcpy(pkt.data() + 24, p.dst.data(), 16);
    }

    std::uint8_t* tcp = pkt.data() + ip_hdr_len;
    write16(tcp + 0, p.sport);
    write16(tcp + 2, p.dport);
    write32(tcp + 4, seq);
    write32(tcp + 8, p.ack);
    tcp[12] = static_cast<std::uint8_t>((tcp_hdr_len / 4) << 4);
    std::uint8_t flags = static_cast<std::uint8_t>(
        (p.flags & ~(kTcpSyn | kTcpFin | kTcpRst | kTcpPush)) | kTcpAck);
    if (push) flags |= kTcpPush;
    tcp[13] = flags;
    write16(tcp + 14, p.window);
    write16(tcp + 16, 0);
    write16(tcp + 18, 0);
    if (p.tcp_options_len != 0)
        std::memcpy(tcp + 20, p.tcp_options, p.tcp_options_len);
    if (payload_len != 0)
        std::memcpy(tcp + tcp_hdr_len, payload, payload_len);

    std::uint32_t sum = 0;
    if (p.is_ipv4()) {
        sum = sum_bytes(sum, p.src.data(), 4);
        sum = sum_bytes(sum, p.dst.data(), 4);
        sum += kProtoTcp;
        sum += static_cast<std::uint16_t>(tcp_len);
    } else {
        sum = sum_bytes(sum, p.src.data(), 16);
        sum = sum_bytes(sum, p.dst.data(), 16);
        sum += static_cast<std::uint32_t>(tcp_len >> 16);
        sum += static_cast<std::uint16_t>(tcp_len & 0xffff);
        sum += kProtoTcp;
    }
    sum = sum_bytes(sum, tcp, tcp_len);
    write16(tcp + 16, checksum_fold(sum));

    return pkt;
}

bool send_one(int fd, const TcpPacket& p, std::uint32_t seq,
              const std::uint8_t* payload, std::size_t len, bool push,
              std::uint16_t ip_id, std::uint8_t ttl, bool bad_checksum,
              std::string& error)
{
    auto pkt = build_segment(p, seq, payload, len, push, ip_id, ttl);
    if (bad_checksum) {
        const std::size_t ip_hdr = p.is_ipv4() ? 20 : 40;
        if (pkt.size() >= ip_hdr + 18) {
            pkt[ip_hdr + 16] = 0;
            pkt[ip_hdr + 17] = 0;
        }
    }
    ssize_t wr = -1;
    if (p.is_ipv4()) {
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(p.dport);
        std::memcpy(&dst.sin_addr, p.dst.data(), 4);
        wr = sendto(fd, pkt.data(), pkt.size(), 0,
                    reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    } else {
        sockaddr_in6 dst{};
        dst.sin6_family = AF_INET6;
        dst.sin6_port = 0; // must be zero for IPV6_HDRINCL raw sockets
        std::memcpy(&dst.sin6_addr, p.dst.data(), 16);
        wr = sendto(fd, pkt.data(), pkt.size(), 0,
                    reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    }
    if (wr < 0) {
        error = std::string(std::strerror(errno)) + " (family=" +
                (p.is_ipv4() ? "4" : "6") + ", len=" + std::to_string(pkt.size()) +
                ", payload=" + std::to_string(len) + ")";
        return false;
    }
    if (static_cast<std::size_t>(wr) != pkt.size()) {
        error = "short raw send";
        return false;
    }
    return true;
}

} // namespace

bool parse_l3_packet(const std::uint8_t* data, std::size_t len, TcpPacket& out) noexcept
{
    out = TcpPacket{};
    if (data == nullptr || len < 20) return false;

    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    std::size_t ip_hdr_len = 0;
    std::size_t l4_off = 0;
    std::size_t ip_total = len;

    if (version == 4) {
        ip_hdr_len = static_cast<std::size_t>(data[0] & 0x0f) * 4;
        if (ip_hdr_len < 20 || ip_hdr_len > len) return false;
        ip_total = read16(data + 2);
        if (ip_total < ip_hdr_len || ip_total > len) return false;
        if (data[9] != kProtoTcp) return false;
        const std::uint16_t frag = read16(data + 6);
        if ((frag & 0x3fff) != 0) return false; // MF or fragment offset
        out.family = AF_INET;
        std::memcpy(out.src.data(), data + 12, 4);
        std::memcpy(out.dst.data(), data + 16, 4);
        out.traffic_class = data[1];
        out.ip_id = read16(data + 4);
        out.dont_fragment = (frag & 0x4000) != 0;
        out.hop_limit = data[8];
        l4_off = ip_hdr_len;
    } else if (version == 6) {
        if (len < 40) return false;
        ip_hdr_len = 40;
        const std::uint16_t payload_len = read16(data + 4);
        ip_total = ip_hdr_len + static_cast<std::size_t>(payload_len);
        if (ip_total > len) return false;
        if (data[6] != kProtoTcp) return false; // no extension-header walking
        out.family = AF_INET6;
        std::memcpy(out.src.data(), data + 8, 16);
        std::memcpy(out.dst.data(), data + 24, 16);
        const std::uint32_t vtf = read32(data);
        out.traffic_class = static_cast<std::uint8_t>((vtf >> 20) & 0xff);
        out.flow_label = vtf & 0x000fffffu;
        out.hop_limit = data[7];
        l4_off = 40;
    } else {
        return false;
    }

    if (l4_off + 20 > ip_total) return false;
    const std::uint8_t* tcp = data + l4_off;
    const std::size_t tcp_hdr_len = static_cast<std::size_t>(tcp[12] >> 4) * 4;
    if (tcp_hdr_len < 20 || tcp_hdr_len > 60 || l4_off + tcp_hdr_len > ip_total) return false;

    out.sport = read16(tcp + 0);
    out.dport = read16(tcp + 2);
    out.seq = read32(tcp + 4);
    out.ack = read32(tcp + 8);
    out.flags = tcp[13];
    out.window = read16(tcp + 14);
    out.tcp_options_len = static_cast<std::uint8_t>(tcp_hdr_len - 20);
    if (out.tcp_options_len != 0)
        std::memcpy(out.tcp_options, tcp + 20, out.tcp_options_len);
    out.payload = tcp + tcp_hdr_len;
    out.payload_len = ip_total - l4_off - tcp_hdr_len;
    return true;
}

SendSplitResult send_split_segments(int raw_fd, const TcpPacket& p,
                                    const std::vector<std::size_t>& boundaries,
                                    std::size_t max_payload_per_segment,
                                    std::uint32_t gap_ms)
{
    SendOptions o;
    o.max_payload_per_segment = max_payload_per_segment;
    o.gap_ms = gap_ms;
    return send_split_segments(raw_fd, p, boundaries, o);
}

SendSplitResult send_split_segments(int raw_fd, const TcpPacket& p,
                                    const std::vector<std::size_t>& boundaries,
                                    const SendOptions& options)
{
    SendSplitResult r;
    if (raw_fd < 0) { r.error = "raw socket is not available"; return r; }
    if (p.payload == nullptr || p.payload_len < 2) { r.error = "empty payload"; return r; }

    std::vector<std::size_t> points;
    points.reserve(boundaries.size());
    for (std::size_t b : boundaries)
        if (b > 0 && b < p.payload_len) points.push_back(b);
    std::sort(points.begin(), points.end());
    points.erase(std::unique(points.begin(), points.end()), points.end());
    if (points.empty()) { r.error = "no valid split boundary in this packet"; return r; }

    const std::size_t chunk_cap =
        std::max<std::size_t>(200, options.max_payload_per_segment);
    const std::uint8_t ttl = p.hop_limit != 0 ? p.hop_limit : 64;

    struct Segment {
        std::size_t from;
        std::size_t to;
        bool push;
    };
    std::vector<Segment> segments;

    std::size_t from = 0;
    auto add_until = [&](std::size_t to) {
        while (from + chunk_cap < to) {
            segments.push_back({from, from + chunk_cap, false});
            from += chunk_cap;
        }
        if (to > from) {
            segments.push_back({from, to, false});
            from = to;
        }
    };

    for (std::size_t b : points) add_until(b);
    while (from < p.payload_len) {
        const std::size_t to = std::min(p.payload_len, from + chunk_cap);
        segments.push_back({from, to, false});
        from = to;
    }
    if (segments.empty()) { r.error = "no segments"; return r; }
    if (options.multidisorder && segments.size() > 1) {
        std::vector<Segment> shuffled;
        shuffled.reserve(segments.size());
        std::size_t left = 0, right = segments.size() - 1;
        bool take_right = true;
        while (left <= right) {
            if (take_right) shuffled.push_back(segments[right--]);
            else shuffled.push_back(segments[left++]);
            take_right = !take_right;
        }
        segments = std::move(shuffled);
    } else if (options.disorder) {
        std::reverse(segments.begin(), segments.end());
    }
    for (auto& s : segments) s.push = (s.to == p.payload_len);

    std::mt19937 jitter_rng(static_cast<std::uint32_t>(p.seq) ^
                             (static_cast<std::uint32_t>(p.sport) << 16) ^
                             static_cast<std::uint32_t>(p.dport));
    std::uniform_int_distribution<std::uint32_t> jitter_dist(0, options.jitter_ms);

    std::uint16_t ip_id = p.ip_id;
    for (const Segment& s : segments) {
        if (!send_one(raw_fd, p, p.seq + static_cast<std::uint32_t>(s.from),
                      p.payload + s.from, s.to - s.from, s.push, ip_id, ttl, false, r.error))
            return r;
        ++r.segments;
        if (p.is_ipv4()) ++ip_id;
        const std::uint32_t delay = options.gap_ms +
            (options.jitter_ms != 0 ? jitter_dist(jitter_rng) : 0);
        if (delay != 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }

    r.ok = true;
    return r;
}

bool send_fake_segment(int raw_fd, const TcpPacket& p, std::uint32_t seq,
                       const std::uint8_t* payload, std::size_t payload_len,
                       std::uint8_t ttl, std::uint16_t ip_id,
                       bool bad_checksum, std::int32_t seq_offset, bool tcp_ts,
                       std::string& error)
{
    if (raw_fd < 0) { error = "raw socket is not available"; return false; }
    if (payload == nullptr || payload_len == 0) { error = "empty fake payload"; return false; }

    TcpPacket fp = p;
    if (tcp_ts && static_cast<std::size_t>(fp.tcp_options_len) + 12 <=
                    sizeof(fp.tcp_options)) {
        std::uint8_t* o = fp.tcp_options + fp.tcp_options_len;
        o[0] = 1; // NOP
        o[1] = 1; // NOP
        o[2] = 8; // TCP timestamp
        o[3] = 10;
        write32(o + 4, static_cast<std::uint32_t>(seq ^ (ip_id << 16)));
        write32(o + 8, 0);
        fp.tcp_options_len = static_cast<std::uint8_t>(fp.tcp_options_len + 12);
    }
    const std::uint32_t fake_seq = seq + static_cast<std::uint32_t>(seq_offset);
    return send_one(raw_fd, fp, fake_seq, payload, payload_len, true, ip_id, ttl,
                    bad_checksum, error);
}

namespace {
constexpr std::uint8_t kProtoUdp = 17;

std::vector<std::uint8_t> build_udp_segment(const UdpPacket& p, const std::uint8_t* payload,
                                            std::size_t payload_len, std::uint8_t ttl,
                                            std::uint16_t ip_id)
{
    const std::size_t ip_hdr_len = p.is_ipv4() ? 20 : 40;
    const std::size_t udp_len = 8 + payload_len;
    std::vector<std::uint8_t> pkt(ip_hdr_len + udp_len, 0);
    if (p.is_ipv4()) {
        const std::size_t total = pkt.size();
        pkt[0] = 0x45;
        pkt[1] = p.traffic_class;
        write16(pkt.data() + 2, static_cast<std::uint16_t>(total));
        write16(pkt.data() + 4, ip_id);
        std::uint16_t frag = p.dont_fragment ? 0x4000 : 0;
        write16(pkt.data() + 6, frag);
        pkt[8] = ttl;
        pkt[9] = kProtoUdp;
        std::memcpy(pkt.data() + 12, p.src.data(), 4);
        std::memcpy(pkt.data() + 16, p.dst.data(), 4);
        write16(pkt.data() + 10, checksum_fold(sum_bytes(0, pkt.data(), ip_hdr_len)));
    } else {
        const std::uint32_t vtf = (6u << 28) |
                                  (static_cast<std::uint32_t>(p.traffic_class) << 20);
        write32(pkt.data(), vtf);
        write16(pkt.data() + 4, static_cast<std::uint16_t>(udp_len));
        pkt[6] = kProtoUdp;
        pkt[7] = ttl;
        std::memcpy(pkt.data() + 8, p.src.data(), 16);
        std::memcpy(pkt.data() + 24, p.dst.data(), 16);
    }
    std::uint8_t* udp = pkt.data() + ip_hdr_len;
    write16(udp + 0, p.sport);
    write16(udp + 2, p.dport);
    write16(udp + 4, static_cast<std::uint16_t>(udp_len));
    write16(udp + 6, 0);
    if (payload_len != 0) std::memcpy(udp + 8, payload, payload_len);

    std::uint32_t sum = 0;
    if (p.is_ipv4()) {
        sum = sum_bytes(sum, p.src.data(), 4);
        sum = sum_bytes(sum, p.dst.data(), 4);
        sum += kProtoUdp;
        sum += static_cast<std::uint16_t>(udp_len);
    } else {
        sum = sum_bytes(sum, p.src.data(), 16);
        sum = sum_bytes(sum, p.dst.data(), 16);
        sum += static_cast<std::uint32_t>(udp_len >> 16);
        sum += static_cast<std::uint16_t>(udp_len & 0xffff);
        sum += kProtoUdp;
    }
    sum = sum_bytes(sum, udp, udp_len);
    std::uint16_t c = checksum_fold(sum);
    if (c == 0) c = 0xffff;
    write16(udp + 6, c);
    return pkt;
}
} // namespace

bool parse_udp_packet(const std::uint8_t* data, std::size_t len, UdpPacket& out) noexcept
{
    out = UdpPacket{};
    if (data == nullptr || len < 28) return false;
    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    std::size_t ip_hdr_len = 0, ip_total = len;
    if (version == 4) {
        ip_hdr_len = static_cast<std::size_t>(data[0] & 0x0f) * 4;
        if (ip_hdr_len < 20 || ip_hdr_len > len) return false;
        ip_total = read16(data + 2);
        if (ip_total < ip_hdr_len + 8 || ip_total > len) return false;
        if (data[9] != kProtoUdp) return false;
        const std::uint16_t frag = read16(data + 6);
        if ((frag & 0x3fff) != 0) return false;
        out.family = AF_INET;
        std::memcpy(out.src.data(), data + 12, 4);
        std::memcpy(out.dst.data(), data + 16, 4);
        out.traffic_class = data[1];
        out.ip_id = read16(data + 4);
        out.dont_fragment = (frag & 0x4000) != 0;
        out.hop_limit = data[8];
    } else if (version == 6) {
        if (len < 48) return false;
        ip_hdr_len = 40;
        const std::uint16_t plen = read16(data + 4);
        ip_total = ip_hdr_len + static_cast<std::size_t>(plen);
        if (ip_total > len) return false;
        if (data[6] != kProtoUdp) return false;
        out.family = AF_INET6;
        std::memcpy(out.src.data(), data + 8, 16);
        std::memcpy(out.dst.data(), data + 24, 16);
        const std::uint32_t vtf = read32(data);
        out.traffic_class = static_cast<std::uint8_t>((vtf >> 20) & 0xff);
        out.hop_limit = data[7];
    } else {
        return false;
    }
    const std::uint8_t* udp = data + ip_hdr_len;
    const std::size_t udp_len = read16(udp + 4);
    if (udp_len < 8 || ip_hdr_len + udp_len > ip_total) return false;
    out.sport = read16(udp + 0);
    out.dport = read16(udp + 2);
    out.payload = udp + 8;
    out.payload_len = udp_len - 8;
    return true;
}

bool send_fake_udp(int raw_fd, const UdpPacket& p, const std::uint8_t* payload,
                   std::size_t payload_len, std::uint8_t ttl, std::uint16_t ip_id,
                   std::string& error)
{
    if (raw_fd < 0) { error = "raw socket is not available"; return false; }
    if (payload == nullptr || payload_len == 0) { error = "empty fake payload"; return false; }
    auto pkt = build_udp_segment(p, payload, payload_len, ttl, ip_id);
    ssize_t wr = -1;
    if (p.is_ipv4()) {
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(p.dport);
        std::memcpy(&dst.sin_addr, p.dst.data(), 4);
        wr = sendto(raw_fd, pkt.data(), pkt.size(), 0,
                    reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    } else {
        sockaddr_in6 dst{};
        dst.sin6_family = AF_INET6;
        dst.sin6_port = 0;
        std::memcpy(&dst.sin6_addr, p.dst.data(), 16);
        wr = sendto(raw_fd, pkt.data(), pkt.size(), 0,
                    reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
    }
    if (wr < 0) { error = std::strerror(errno); return false; }
    if (static_cast<std::size_t>(wr) != pkt.size()) { error = "short raw send"; return false; }
    return true;
}

} // namespace dpi
