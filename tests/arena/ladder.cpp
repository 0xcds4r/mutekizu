#include "ladder.hpp"

#include <algorithm>
#include <cstring>

namespace arena {
namespace {

std::string flow_key(const dpi::TcpPacket& p)
{
    std::string k;
    k.reserve(1 + 32 + 4);
    k.push_back(static_cast<char>(p.family));
    k.append(reinterpret_cast<const char*>(p.src.data()), 16);
    k.append(reinterpret_cast<const char*>(p.dst.data()), 16);
    k.push_back(static_cast<char>(p.sport >> 8));
    k.push_back(static_cast<char>(p.sport & 0xff));
    k.push_back(static_cast<char>(p.dport >> 8));
    k.push_back(static_cast<char>(p.dport & 0xff));
    return k;
}

bool starts_tls_handshake(const std::uint8_t* d, std::size_t n)
{
    return n >= 3 && d[0] == 0x16 && d[1] == 0x03 && d[2] <= 0x04;
}

} // namespace

DpiFilter::DpiFilter(Level level, std::string blocked_sni)
    : level_(level), blocked_(std::move(blocked_sni))
{
}

bool DpiFilter::blocked_sni(const std::string& sni) const
{
    if (blocked_.empty()) return false;
    if (sni == blocked_) return true;
    // Domain suffix match at a label boundary, like a real SNI blocklist.
    if (sni.size() > blocked_.size() &&
        sni.compare(sni.size() - blocked_.size(), blocked_.size(), blocked_) == 0 &&
        sni[sni.size() - blocked_.size() - 1] == '.')
        return true;
    return false;
}

DpiFilter::Flow& DpiFilter::flow_for(const dpi::TcpPacket& pkt)
{
    const std::string key = flow_key(pkt);
    auto it = flows_.find(key);
    if (it != flows_.end()) {
        it->second.last = std::chrono::steady_clock::now();
        return it->second;
    }
    if (flows_.size() > 4096) flows_.clear();
    Flow f;
    f.base_seq = pkt.seq;
    f.next_seq = pkt.seq;
    f.last = std::chrono::steady_clock::now();
    auto [ins, _] = flows_.emplace(key, std::move(f));
    stats_.flows = flows_.size();
    return ins->second;
}

bool DpiFilter::on_packet(const dpi::TcpPacket& pkt)
{
    ++stats_.packets;
    if (pkt.payload == nullptr || pkt.payload_len == 0) return false;

    dpi::ClientHelloInfo info;

    switch (level_) {
    case Level::L1_SegmentCompleteHello: {
        const auto rc = dpi::parse_client_hello(pkt.payload, pkt.payload_len, info,
                                                pkt.payload_len);
        // The model only acts if the whole first record is inside this segment.
        if (rc == dpi::ParseResult::Ok && info.record_end <= pkt.payload_len &&
            blocked_sni(info.sni)) {
            ++stats_.dropped;
            return true;
        }
        return false;
    }
    case Level::L2_SegmentNeedle: {
        if (blocked_.size() <= pkt.payload_len) {
            for (std::size_t i = 0; i + blocked_.size() <= pkt.payload_len; ++i) {
                if (std::memcmp(pkt.payload + i, blocked_.data(), blocked_.size()) == 0) {
                    ++stats_.dropped;
                    return true;
                }
            }
        }
        return false;
    }
    case Level::L3_FirstSegmentPolicy: {
        Flow& f = flow_for(pkt);
        if (f.decided) {
            if (f.blocked) { ++stats_.dropped; return true; }
            return false;
        }
        if (!starts_tls_handshake(pkt.payload, pkt.payload_len)) {
            f.decided = true;
            return false;
        }
        const auto rc = dpi::parse_client_hello(pkt.payload, pkt.payload_len, info,
                                                pkt.payload_len);
        f.decided = true;
        if (rc == dpi::ParseResult::Ok) {
            f.blocked = blocked_sni(info.sni);
        } else {
            // POLICY: an incomplete or ambiguous first ClientHello segment is
            // treated as suspicious. This deliberately creates false positives
            // for clients that legitimately fragment the hello.
            f.blocked = true;
        }
        if (f.blocked) { ++stats_.dropped; return true; }
        return false;
    }
    case Level::L4_TcpReassembly:
    case Level::L5_ReassemblyStrict: {
        Flow& f = flow_for(pkt);
        if (f.blocked) { ++stats_.dropped; return true; }
        if (f.decided) return false;

        f.segments.emplace(pkt.seq, std::vector<std::uint8_t>(
                                        pkt.payload, pkt.payload + pkt.payload_len));

        // A segment that starts before the current buffer can be prepended.
        // This is what makes a later-arriving first half work even if a higher
        // sequence segment was queued first.
        if (pkt.seq < f.base_seq) {
            const std::uint32_t end = pkt.seq + static_cast<std::uint32_t>(pkt.payload_len);
            if (end >= f.base_seq) {
                const std::size_t prefix = f.base_seq - pkt.seq;
                f.buffer.insert(f.buffer.begin(), pkt.payload, pkt.payload + prefix);
                f.base_seq = pkt.seq;
                f.next_seq = f.base_seq + static_cast<std::uint32_t>(f.buffer.size());
                auto self = f.segments.find(pkt.seq);
                if (self != f.segments.end()) f.segments.erase(self);
            }
        }

        // Reassemble contiguous bytes. Out-of-order segments wait in the map;
        // retransmissions/overlaps contribute only their unseen tail.
        for (;;) {
            auto it = f.segments.begin();
            if (it == f.segments.end() || it->first > f.next_seq) break;
            const std::uint32_t seq = it->first;
            const std::vector<std::uint8_t>& data = it->second;
            const std::uint32_t end = seq + static_cast<std::uint32_t>(data.size());
            if (end <= f.next_seq) { f.segments.erase(it); continue; }
            const std::size_t skip = f.next_seq - seq;
            f.buffer.insert(f.buffer.end(), data.begin() + static_cast<std::ptrdiff_t>(skip),
                            data.end());
            f.next_seq = end;
            f.segments.erase(it);
            if (f.buffer.size() > max_buffer_) {
                // POLICY: bounded memory must not become a free bypass.
                f.decided = true;
                f.blocked = true;
                ++stats_.overflow_blocks;
                ++stats_.dropped;
                return true;
            }
        }

        const auto rc = dpi::parse_client_hello(f.buffer.data(), f.buffer.size(), info,
                                                max_buffer_);
        if (rc == dpi::ParseResult::Ok) {
            if (level_ == Level::L5_ReassemblyStrict && info.record_end > f.buffer.size()) {
                return false; // wait for the complete record
            }
            f.decided = true;
            f.blocked = blocked_sni(info.sni);
            if (f.blocked) { ++stats_.dropped; return true; }
            return false;
        }
        if (rc == dpi::ParseResult::Malformed || rc == dpi::ParseResult::TooLarge) {
            ++stats_.parse_errors;
            if (level_ == Level::L5_ReassemblyStrict) {
                f.decided = true;
                f.blocked = true;
                ++stats_.dropped;
                return true;
            }
        }
        return false;
    }
    }
    return false;
}

} // namespace arena
