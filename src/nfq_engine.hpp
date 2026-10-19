#pragma once

#include "config.hpp"
#include "netpacket.hpp"
#include "profiles.hpp"
#include "strategy.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct nfq_handle;
struct nfq_q_handle;
struct nfq_data;
struct nfgenmsg;

namespace dpi {

class NfqEngine {
public:
    NfqEngine(Config cfg, DomainSet domains);
    ~NfqEngine();

    NfqEngine(const NfqEngine&) = delete;
    NfqEngine& operator=(const NfqEngine&) = delete;

    bool init(std::string& error);
    int run();
    void request_stop() noexcept;

    struct Stats {
        std::uint64_t packets = 0;
        std::uint64_t splits = 0;
        std::uint64_t accepted_unmodified = 0;
        std::uint64_t parse_errors = 0;
        std::uint64_t split_send_errors = 0;
        std::uint64_t fakes_sent = 0;
        std::uint64_t seqovl_sent = 0;
        std::uint64_t udp_fakes = 0;
        std::uint64_t reply_packets = 0;
        std::uint64_t server_hellos = 0;
        std::uint64_t flows = 0;
    };
    const Stats& stats() const noexcept { return stats_; }

private:
    static int callback(nfq_q_handle* qh, nfgenmsg* nfmsg, nfq_data* nfad, void* ctx);
    static int reply_callback(nfq_q_handle* qh, nfgenmsg* nfmsg, nfq_data* nfad, void* ctx);
    int handle(nfq_q_handle* qh, nfq_data* nfad);
    int handle_reply(nfq_q_handle* qh, nfq_data* nfad);

    struct FlowKey {
        std::uint8_t family = 0;
        std::uint8_t src[16]{};
        std::uint8_t dst[16]{};
        std::uint16_t sport = 0;
        std::uint16_t dport = 0;
        bool operator==(const FlowKey& o) const noexcept;
    };
    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& k) const noexcept;
    };
    struct StrategyValues {
        bool split_enabled = true;
        std::uint16_t split_delta = 4;
        std::uint16_t split_stride = 4;
        std::uint16_t split_max = 64;
        std::uint16_t split_gap_ms = 0;
        bool split_disorder = false;
        bool split_multidisorder = false;
        bool split_data = false;
        std::uint16_t split_data_pos = 1;
        std::uint16_t split_jitter_ms = 0;
        bool fake_enabled = false;
        std::uint16_t fake_ttl = 3;
        std::uint16_t fake_repeats = 3;
        std::string fake_sni;
        bool fake_bad_checksum = false;
        std::int16_t fake_seq_offset = 0;
        bool fake_timestamp = false;
        bool seqovl_enabled = false;
        std::uint16_t seqovl_bytes = 664;
        std::uint16_t seqovl_repeats = 1;
    };
    struct Flow {
        std::uint32_t base_seq = 0;
        std::uint32_t next_seq = 0;
        std::vector<std::uint8_t> buf;
        bool ignore = false;
        std::vector<std::uint32_t> split_offsets; // relative to base_seq
        bool data_split = false;
        int profile_index = -1;
        std::string sni;
        std::uint32_t hello_end_seq = 0;
        bool hello_done = false;
        bool success = false;
        std::chrono::steady_clock::time_point last{};
    };

    Flow& flow_for(const TcpPacket& p);
    void prune_flows();
    bool handle_split(nfq_q_handle* qh, std::uint32_t id, const TcpPacket& pkt,
                      const std::vector<std::size_t>& boundaries,
                      const StrategyValues& st, bool data = false);
    int accept(nfq_q_handle* qh, std::uint32_t id);

    struct AutoState {
        std::size_t index = 0;
        bool has_attempt = false;
        bool last_ok = false;
        std::chrono::steady_clock::time_point last_attempt{};
    };
    StrategyValues effective_for(int profile_index) const;
    int profile_index_for(const std::string& sni) const;
    std::vector<int> matching_profiles(const std::string& sni,
                                       const std::string& ifname) const;
    int choose_profile(const std::string& sni, const std::vector<int>& candidates);
    void mark_profile_success(const std::string& sni);
    void loadAutoDomains();
    bool isAutoTarget(const std::string& sni) const;
    void maybeProbe(const TcpPacket& pkt, const std::string& sni);
    void runProbe(int family, std::array<std::uint8_t, 16> dst, std::uint16_t port,
                  std::string sni);
    void addAutoDomain(const std::string& sni);

    Config cfg_;
    DomainSet domains_;
    std::vector<Profile> profiles_;
    std::vector<DomainSet> profile_sets_;
    std::unordered_map<std::string, AutoState> autoStates_;
    Stats stats_{};
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
    std::uint64_t packet_counter_ = 0;
    volatile bool stop_ = false;

    nfq_handle* nfq_ = nullptr;
    nfq_q_handle* queue_ = nullptr;
    nfq_q_handle* reply_queue_ = nullptr;
    int nfq_fd_ = -1;
    int raw4_ = -1;
    int raw6_ = -1;

    mutable std::mutex autoMutex_;
    std::unordered_set<std::string> autoDomains_;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> probeSeen_;
    std::atomic<int> probesInFlight_{0};
    std::atomic<bool> stopping_{false};
};

} // namespace dpi
