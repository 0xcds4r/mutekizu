#pragma once

#include "netpacket.hpp"
#include "tls_clienthello.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace arena {

// Synthetic DPI ladder. Every level is strictly stronger than the previous one
// for the blocked SNI, but levels 1-3 are deliberately simplified.
enum class Level : int {
    L1_SegmentCompleteHello = 1,
    L2_SegmentNeedle = 2,
    L3_FirstSegmentPolicy = 3,
    L4_TcpReassembly = 4,
    L5_ReassemblyStrict = 5,
};

struct Stats {
    unsigned long packets = 0;
    unsigned long dropped = 0;
    unsigned long flows = 0;
    unsigned long overflow_blocks = 0;
    unsigned long parse_errors = 0;
};

class DpiFilter {
public:
    DpiFilter(Level level, std::string blocked_sni);

    // Returns true if this packet must be dropped. Flow key is the 5-tuple;
    // callers only feed the client->server direction.
    bool on_packet(const dpi::TcpPacket& pkt);

    const Stats& stats() const noexcept { return stats_; }
    Level level() const noexcept { return level_; }

private:
    struct Flow {
        std::uint32_t base_seq = 0; // stream offset of buffer[0]
        std::uint32_t next_seq = 0; // base_seq + buffer.size()
        std::map<std::uint32_t, std::vector<std::uint8_t>> segments;
        std::vector<std::uint8_t> buffer;
        bool decided = false;
        bool blocked = false;
        bool first_data = false;
        std::chrono::steady_clock::time_point last{};
    };

    Flow& flow_for(const dpi::TcpPacket& pkt);
    bool blocked_sni(const std::string& sni) const;

    Level level_;
    std::string blocked_;
    Stats stats_{};
    std::map<std::string, Flow> flows_;
    std::size_t max_buffer_ = 65536;
};

} // namespace arena
