#include "nfq_engine.hpp"
#include "config.hpp"
#include "log.hpp"
#include "strategy.hpp"
#include "tls_probe.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <thread>
#include <random>
#include <cstring>

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 36
#endif

namespace dpi {
namespace {

constexpr std::uint8_t kTcpFin = 0x01;
constexpr std::uint8_t kTcpSyn = 0x02;
constexpr std::uint8_t kTcpRst = 0x04;

bool port_selected(const Config& cfg, std::uint16_t dport) noexcept
{
    return std::find(cfg.ports.begin(), cfg.ports.end(), dport) != cfg.ports.end();
}

int make_raw_socket(int family, std::uint32_t mark, std::string& error)
{
    const int fd = ::socket(family, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
        error = std::string("socket(AF_") + (family == AF_INET ? "INET" : "INET6") +
                ", SOCK_RAW): " + std::strerror(errno);
        return -1;
    }
    const int one = 1;
    if (family == AF_INET) {
        if (::setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) != 0) {
            error = std::string("IP_HDRINCL: ") + std::strerror(errno);
            ::close(fd);
            return -1;
        }
    } else {
        if (::setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one)) != 0) {
            error = std::string("IPV6_HDRINCL: ") + std::strerror(errno);
            ::close(fd);
            return -1;
        }
    }
    if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        error = std::string("SO_MARK: ") + std::strerror(errno);
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

bool NfqEngine::FlowKey::operator==(const FlowKey& o) const noexcept
{
    return family == o.family && sport == o.sport && dport == o.dport &&
           std::memcmp(src, o.src, sizeof(src)) == 0 &&
           std::memcmp(dst, o.dst, sizeof(dst)) == 0;
}

std::size_t NfqEngine::FlowKeyHash::operator()(const FlowKey& k) const noexcept
{
    std::uint64_t h = 1469598103934665603ull;
    auto mix = [&h](const void* data, std::size_t n) {
        const auto* p = static_cast<const std::uint8_t*>(data);
        for (std::size_t i = 0; i < n; ++i) {
            h ^= p[i];
            h *= 1099511628211ull;
        }
    };
    mix(&k.family, 1);
    mix(&k.sport, sizeof(k.sport));
    mix(&k.dport, sizeof(k.dport));
    mix(k.src, sizeof(k.src));
    mix(k.dst, sizeof(k.dst));
    return static_cast<std::size_t>(h);
}

NfqEngine::NfqEngine(Config cfg, DomainSet domains)
    : cfg_(std::move(cfg)), domains_(std::move(domains))
{
}

NfqEngine::~NfqEngine()
{
    stopping_.store(true, std::memory_order_relaxed);
    for (int i = 0; i < 300 && probesInFlight_.load(std::memory_order_relaxed) > 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (reply_queue_ != nullptr) nfq_destroy_queue(reply_queue_);
    if (queue_ != nullptr) nfq_destroy_queue(queue_);
    if (nfq_ != nullptr) nfq_close(nfq_);
    if (raw4_ >= 0) ::close(raw4_);
    if (raw6_ >= 0) ::close(raw6_);
}

bool NfqEngine::init(std::string& error)
{
    raw4_ = make_raw_socket(AF_INET, cfg_.fwmark, error);
    if (raw4_ < 0) return false;
    if (cfg_.enable_ipv6) {
        raw6_ = make_raw_socket(AF_INET6, cfg_.fwmark, error);
        if (raw6_ < 0) return false;
    }

    nfq_ = nfq_open();
    if (nfq_ == nullptr) {
        error = std::string("nfq_open: ") + std::strerror(errno);
        return false;
    }

    // Deprecated bind calls are harmless on modern kernels; failures are ignored.
    nfq_unbind_pf(nfq_, AF_INET);
    nfq_bind_pf(nfq_, AF_INET);
    if (cfg_.enable_ipv6) {
        nfq_unbind_pf(nfq_, AF_INET6);
        nfq_bind_pf(nfq_, AF_INET6);
    }

    queue_ = nfq_create_queue(nfq_, cfg_.queue_num, &NfqEngine::callback, this);
    if (queue_ == nullptr) {
        error = std::string("nfq_create_queue(") + std::to_string(cfg_.queue_num) +
                "): " + std::strerror(errno) +
                " (is another process using this queue number?)";
        return false;
    }
    if (nfq_set_mode(queue_, NFQNL_COPY_PACKET, cfg_.copy_range) < 0) {
        error = std::string("nfq_set_mode: ") + std::strerror(errno);
        return false;
    }
    if (nfq_set_queue_maxlen(queue_, cfg_.max_queue_len) < 0) {
        error = std::string("nfq_set_queue_maxlen: ") + std::strerror(errno);
        return false;
    }
    const std::uint32_t flags = NFQA_CFG_F_FAIL_OPEN;
    if (nfq_set_queue_flags(queue_, flags, flags) < 0) {
        // Not fatal on old kernels, but report it: overflow semantics differ.
        log_msg(LogLevel::Warn, "could not enable NFQA_CFG_F_FAIL_OPEN: %s",
                std::strerror(errno));
    }

    nfq_fd_ = nfq_fd(nfq_);
    if (nfq_fd_ < 0) {
        error = "nfq_fd failed";
        return false;
    }
    loadAutoDomains();
    if (!load_profiles(cfg_.profiles_file, profiles_, error)) return false;
    profile_sets_.reserve(profiles_.size());
    for (const auto& prof : profiles_) {
        DomainSet set;
        set.domains = prof.domains;
        set.normalize();
        profile_sets_.push_back(std::move(set));
    }
    if (!profiles_.empty())
        log_msg(LogLevel::Info, "profiles: loaded %zu domain profile(s)", profiles_.size());
    return true;
}

NfqEngine::StrategyValues NfqEngine::effective_for(int profile_index) const
{
    StrategyValues st;
    st.split_enabled = cfg_.split_enabled;
    st.split_delta = cfg_.split_delta;
    st.split_stride = cfg_.split_stride;
    st.split_max = cfg_.split_max;
    st.split_gap_ms = cfg_.split_gap_ms;
    st.split_disorder = cfg_.split_disorder;
    st.split_multidisorder = cfg_.split_multidisorder;
    st.split_data = cfg_.split_data;
    st.split_data_pos = cfg_.split_data_pos;
    st.split_jitter_ms = cfg_.split_jitter_ms;
    st.fake_enabled = cfg_.fake_enabled;
    st.fake_ttl = cfg_.fake_ttl;
    st.fake_repeats = cfg_.fake_repeats;
    st.fake_sni = cfg_.fake_sni;
    st.fake_bad_checksum = cfg_.fake_bad_checksum;
    st.fake_seq_offset = cfg_.fake_seq_offset;
    st.fake_timestamp = cfg_.fake_timestamp;
    st.seqovl_enabled = cfg_.seqovl_enabled;
    st.seqovl_bytes = cfg_.seqovl_bytes;
    st.seqovl_repeats = cfg_.seqovl_repeats;

    if (profile_index >= 0 &&
        static_cast<std::size_t>(profile_index) < profiles_.size()) {
        const Profile& p = profiles_[static_cast<std::size_t>(profile_index)];
        auto set = [](auto& dst, const auto& src) { if (src) dst = *src; };
        set(st.split_enabled, p.split_enabled);
        set(st.split_delta, p.split_delta);
        set(st.split_stride, p.split_stride);
        set(st.split_max, p.split_max);
        set(st.split_gap_ms, p.split_gap_ms);
        set(st.split_disorder, p.split_disorder);
        set(st.split_multidisorder, p.split_multidisorder);
        set(st.split_data, p.split_data);
        set(st.split_data_pos, p.split_data_pos);
        set(st.split_jitter_ms, p.split_jitter_ms);
        set(st.fake_enabled, p.fake_enabled);
        set(st.fake_ttl, p.fake_ttl);
        set(st.fake_repeats, p.fake_repeats);
        set(st.fake_sni, p.fake_sni);
        set(st.seqovl_enabled, p.seqovl_enabled);
        set(st.seqovl_bytes, p.seqovl_bytes);
        set(st.seqovl_repeats, p.seqovl_repeats);
    }
    return st;
}

int NfqEngine::profile_index_for(const std::string& sni) const
{
    for (std::size_t i = 0; i < profile_sets_.size(); ++i)
        if (profile_sets_[i].matches(sni)) return static_cast<int>(i);
    return -1;
}

std::vector<int> NfqEngine::matching_profiles(const std::string& sni,
                                              const std::string& ifname) const
{
    std::vector<int> out;
    for (std::size_t i = 0; i < profile_sets_.size(); ++i) {
        if (!profile_sets_[i].matches(sni)) continue;
        const auto& itfs = profiles_[i].interfaces;
        if (itfs.empty() ||
            std::find(itfs.begin(), itfs.end(), ifname) != itfs.end())
            out.push_back(static_cast<int>(i));
    }
    return out;
}

int NfqEngine::choose_profile(const std::string& sni,
                              const std::vector<int>& candidates)
{
    if (candidates.empty()) return -1;
    if (!cfg_.auto_profile || candidates.size() < 2) return candidates.front();

    const auto now = std::chrono::steady_clock::now();
    if (autoStates_.size() > 4096) autoStates_.clear();
    AutoState& st = autoStates_[sni];
    if (st.has_attempt && !st.last_ok &&
        now - st.last_attempt < std::chrono::seconds(cfg_.auto_retry_window_s)) {
        st.index = (st.index + 1) % candidates.size();
    }
    st.has_attempt = true;
    st.last_ok = false;
    st.last_attempt = now;
    return candidates[st.index % candidates.size()];
}

void NfqEngine::mark_profile_success(const std::string& sni)
{
    auto it = autoStates_.find(sni);
    if (it != autoStates_.end()) it->second.last_ok = true;
}

void NfqEngine::request_stop() noexcept { stop_ = true; }

int NfqEngine::callback(nfq_q_handle* qh, nfgenmsg* nfmsg, nfq_data* nfad, void* ctx)
{
    (void)nfmsg;
    auto* self = static_cast<NfqEngine*>(ctx);
    return self->handle(qh, nfad);
}

int NfqEngine::accept(nfq_q_handle* qh, std::uint32_t id)
{
    ++stats_.accepted_unmodified;
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

NfqEngine::Flow& NfqEngine::flow_for(const TcpPacket& p)
{
    FlowKey key;
    key.family = p.family;
    key.sport = p.sport;
    key.dport = p.dport;
    std::memcpy(key.src, p.src.data(), sizeof(key.src));
    std::memcpy(key.dst, p.dst.data(), sizeof(key.dst));

    auto it = flows_.find(key);
    if (it != flows_.end()) {
        it->second.last = std::chrono::steady_clock::now();
        return it->second;
    }

    if (flows_.size() >= cfg_.max_flows) prune_flows();
    if (flows_.size() >= cfg_.max_flows) flows_.clear(); // bounded fallback

    Flow f;
    f.base_seq = p.seq;
    f.next_seq = p.seq;
    f.last = std::chrono::steady_clock::now();
    auto [ins, _] = flows_.emplace(key, std::move(f));
    stats_.flows = flows_.size();
    return ins->second;
}

void NfqEngine::prune_flows()
{
    const auto now = std::chrono::steady_clock::now();
    for (auto it = flows_.begin(); it != flows_.end();) {
        const auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last);
        if (age.count() > static_cast<long>(cfg_.flow_timeout_s))
            it = flows_.erase(it);
        else
            ++it;
    }
    stats_.flows = flows_.size();
}

void NfqEngine::loadAutoDomains()
{
    if (cfg_.auto_domains_file.empty()) return;
    std::ifstream in(cfg_.auto_domains_file);
    if (!in) return;
    std::string line;
    std::lock_guard<std::mutex> lock(autoMutex_);
    while (std::getline(in, line)) {
        const auto hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        line = trim(line);
        std::transform(line.begin(), line.end(), line.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!valid_domain(line)) continue;
        if (autoDomains_.size() >= cfg_.auto_domain_limit) break;
        autoDomains_.insert(line);
    }
    if (!autoDomains_.empty())
        log_msg(LogLevel::Info, "auto-discovery: loaded %zu remembered domain(s)",
                autoDomains_.size());
}

bool NfqEngine::isAutoTarget(const std::string& sni) const
{
    std::lock_guard<std::mutex> lock(autoMutex_);
    return autoDomains_.find(sni) != autoDomains_.end();
}

void NfqEngine::addAutoDomain(const std::string& sni)
{
    if (sni.empty() || !valid_domain(sni)) return;
    {
        std::lock_guard<std::mutex> lock(autoMutex_);
        if (autoDomains_.find(sni) != autoDomains_.end()) return;
        if (autoDomains_.size() >= cfg_.auto_domain_limit) return;
        autoDomains_.insert(sni);
        log_msg(cfg_.log_sni ? LogLevel::Info : LogLevel::Debug,
                "auto-discovery: remembered blocked SNI%s%s", cfg_.log_sni ? " " : "",
                cfg_.log_sni ? sni.c_str() : "");
    }
    std::error_code ec;
    const std::filesystem::path path(cfg_.auto_domains_file);
    std::filesystem::create_directories(path.parent_path(), ec);
    const int fd = ::open(cfg_.auto_domains_file.c_str(),
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        log_msg(LogLevel::Debug, "auto-discovery: cannot append to %s: %s",
                cfg_.auto_domains_file.c_str(), std::strerror(errno));
        return;
    }
    const std::string line = sni + "\n";
    const ssize_t n = ::write(fd, line.data(), line.size());
    (void)n;
    ::close(fd);
}

void NfqEngine::maybeProbe(const TcpPacket& pkt, const std::string& sni)
{
    if (!cfg_.auto_discover || sni.empty()) return;
    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(autoMutex_);
        if (autoDomains_.find(sni) != autoDomains_.end()) return;
        auto it = probeSeen_.find(sni);
        if (it != probeSeen_.end() &&
            now - it->second < std::chrono::seconds(cfg_.auto_probe_interval_s))
            return;
        if (probesInFlight_.load(std::memory_order_relaxed) >=
            static_cast<int>(cfg_.auto_probe_max))
            return;
        probeSeen_[sni] = now;
        probesInFlight_.fetch_add(1, std::memory_order_relaxed);
    }
    std::array<std::uint8_t, 16> dst = pkt.dst;
    try {
        std::thread([this, family = pkt.family, dst, port = pkt.dport, sni] {
            runProbe(family, dst, port, sni);
        }).detach();
    } catch (const std::exception& e) {
        probesInFlight_.fetch_sub(1, std::memory_order_relaxed);
        log_msg(LogLevel::Debug, "auto-discovery: cannot start probe thread: %s", e.what());
    }
}

void NfqEngine::runProbe(int family, std::array<std::uint8_t, 16> dst,
                         std::uint16_t port, std::string sni)
{
    auto finish = [this, &sni](bool blocked) {
        probesInFlight_.fetch_sub(1, std::memory_order_relaxed);
        if (!blocked) {
            log_msg(LogLevel::Debug, "auto-discovery: probe reachable");
            return;
        }
        if (stopping_.load(std::memory_order_relaxed)) return;
        addAutoDomain(sni);
    };

    const int fd = ::socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { finish(false); return; }
    const int mark = static_cast<int>(cfg_.fwmark);
    if (::setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        // Without the mark the probe would itself be queued and could recurse.
        log_msg(LogLevel::Debug, "auto-discovery: SO_MARK failed: %s", std::strerror(errno));
        ::close(fd);
        probesInFlight_.fetch_sub(1, std::memory_order_relaxed);
        return;
    }

    sockaddr_storage ss{};
    socklen_t sl = 0;
    if (family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        std::memcpy(&a->sin_addr, dst.data(), 4);
        sl = sizeof(*a);
    } else {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        std::memcpy(&a->sin6_addr, dst.data(), 16);
        sl = sizeof(*a);
    }

    bool connected = false;
    if (::connect(fd, reinterpret_cast<sockaddr*>(&ss), sl) == 0) {
        connected = true;
    } else if (errno == EINPROGRESS) {
        pollfd pfd{fd, POLLOUT, 0};
        const int rc = ::poll(&pfd, 1, static_cast<int>(cfg_.auto_probe_timeout_ms));
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (rc > 0 && ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 &&
            soerr == 0)
            connected = true;
    }

    bool got_answer = false;
    if (connected) {
        const auto hello = build_probe_client_hello(sni);
        const ssize_t sent = ::send(fd, hello.data(), hello.size(), MSG_NOSIGNAL);
        if (sent > 0) {
            pollfd pfd{fd, POLLIN, 0};
            const int rc = ::poll(&pfd, 1, static_cast<int>(cfg_.auto_probe_timeout_ms));
            if (rc > 0) {
                std::uint8_t buf[4096];
                const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                // ServerHello, alert, or any TLS bytes: the TLS endpoint is
                // reachable. A zero-length read means the peer closed without
                // answering; that is treated as blocked.
                got_answer = n > 0;
            }
        }
    }
    ::close(fd);
    finish(!got_answer);
}

bool NfqEngine::handle_split(nfq_q_handle* qh, std::uint32_t id, const TcpPacket& pkt,
                             const std::vector<std::size_t>& boundaries,
                             const StrategyValues& st, bool data)
{
    const int fd = pkt.is_ipv4() ? raw4_ : raw6_;

    if (!data && st.fake_enabled && !st.fake_sni.empty()) {
        const auto fake = build_probe_client_hello(st.fake_sni);
        std::uint16_t ip_id = static_cast<std::uint16_t>(pkt.ip_id + 0x4000);
        for (std::uint16_t i = 0; i < st.fake_repeats; ++i) {
            std::string ferr;
            if (!send_fake_segment(fd, pkt, pkt.seq, fake.data(), fake.size(),
                                   static_cast<std::uint8_t>(st.fake_ttl), ip_id,
                                   st.fake_bad_checksum, st.fake_seq_offset,
                                   st.fake_timestamp, ferr)) {
                log_msg(LogLevel::Debug, "fake send failed: %s", ferr.c_str());
                break;
            }
            ++stats_.fakes_sent;
            if (pkt.is_ipv4()) ++ip_id;
        }
    }

    if (!data && st.seqovl_enabled) {
        const auto fake = build_probe_client_hello(st.fake_sni);
        std::vector<std::uint8_t> overlap(st.seqovl_bytes, 0);
        overlap.insert(overlap.end(), fake.begin(), fake.end());
        std::uint16_t ip_id = static_cast<std::uint16_t>(pkt.ip_id + 0x6000);
        for (std::uint16_t i = 0; i < st.seqovl_repeats; ++i) {
            std::string oerr;
            if (!send_fake_segment(fd, pkt, pkt.seq - st.seqovl_bytes,
                                   overlap.data(), overlap.size(),
                                   static_cast<std::uint8_t>(st.fake_ttl), ip_id,
                                   st.fake_bad_checksum, 0,
                                   st.fake_timestamp, oerr)) {
                log_msg(LogLevel::Debug, "seqovl send failed: %s", oerr.c_str());
                break;
            }
            ++stats_.seqovl_sent;
            if (pkt.is_ipv4()) ++ip_id;
        }
    }

    SendOptions opts;
    opts.max_payload_per_segment = cfg_.mss;
    opts.gap_ms = st.split_gap_ms;
    opts.disorder = st.split_disorder;
    opts.multidisorder = st.split_multidisorder;
    opts.jitter_ms = st.split_jitter_ms;
    auto res = send_split_segments(fd, pkt, boundaries, opts);
    if (!res.ok) {
        ++stats_.split_send_errors;
        log_msg(LogLevel::Debug, "split send failed (%s); accepting original packet", res.error.c_str());
        // Fail open: the original packet is still delivered. Duplicates from any
        // already-emitted segment are harmless because they carry identical bytes.
        return accept(qh, id) == 0;
    }
    ++stats_.splits;
    log_msg(LogLevel::Debug,
            "split ClientHello: %zu segment(s), %zu boundary(ies), disorder=%d multi=%d "
            "fake=%d seqovl=%d jitter=%u",
            res.segments, boundaries.size(), st.split_disorder ? 1 : 0,
            st.split_multidisorder ? 1 : 0, st.fake_enabled ? 1 : 0,
            st.seqovl_enabled ? 1 : 0, static_cast<unsigned>(st.split_jitter_ms));
    return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr) == 0;
}

int NfqEngine::reply_callback(nfq_q_handle* qh, nfgenmsg* nfmsg, nfq_data* nfad,
                              void* ctx)
{
    (void)nfmsg;
    auto* self = static_cast<NfqEngine*>(ctx);
    return self->handle_reply(qh, nfad);
}

int NfqEngine::handle_reply(nfq_q_handle* qh, nfq_data* nfad)
{
    ++stats_.reply_packets;
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
    if (ph == nullptr) return -1;
    const std::uint32_t id = ntohl(ph->packet_id);

    unsigned char* data = nullptr;
    const int len = nfq_get_payload(nfad, &data);
    if (len <= 0 || data == nullptr) return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    TcpPacket pkt;
    if (!parse_l3_packet(data, static_cast<std::size_t>(len), pkt))
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    FlowKey key;
    key.family = pkt.family;
    key.sport = pkt.dport;
    key.dport = pkt.sport;
    std::memcpy(key.src, pkt.dst.data(), sizeof(key.src));
    std::memcpy(key.dst, pkt.src.data(), sizeof(key.dst));
    auto it = flows_.find(key);
    if (it == flows_.end())
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    Flow& flow = it->second;
    // TLS ServerHello: content type 22, version 3.x, handshake type 2.
    if (pkt.payload_len >= 6 && pkt.payload[0] == 0x16 &&
        pkt.payload[1] == 0x03 && pkt.payload[5] == 0x02) {
        if (!flow.success) {
            flow.success = true;
            mark_profile_success(flow.sni);
            ++stats_.server_hellos;
            log_msg(LogLevel::Debug, "server hello observed for %s",
                    flow.sni.empty() ? "target" : flow.sni.c_str());
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

int NfqEngine::handle(nfq_q_handle* qh, nfq_data* nfad)
{
    ++stats_.packets;
    ++packet_counter_;

    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
    if (ph == nullptr) return -1;
    const std::uint32_t id = ntohl(ph->packet_id);

    unsigned char* data = nullptr;
    const int len = nfq_get_payload(nfad, &data);
    if (len <= 0 || data == nullptr) return accept(qh, id);

    const std::uint8_t version = static_cast<std::uint8_t>(data[0] >> 4);
    const bool is_udp = (version == 4 && len > 9 && data[9] == 17) ||
                        (version == 6 && len > 6 && data[6] == 17);
    if (is_udp) {
        if (!cfg_.udp_fake_enabled) return accept(qh, id);
        UdpPacket up;
        if (!parse_udp_packet(data, static_cast<std::size_t>(len), up)) return accept(qh, id);
        const bool voice_port =
            up.dport == 443 ||
            (up.dport >= 19294 && up.dport <= 19344) ||
            (up.dport >= 50000 && up.dport <= 50100);
        if (!voice_port) return accept(qh, id);

        // Fake UDP payload. The low TTL keeps it away from the server; the
        // on-path DPI still sees a plausible protocol header.
        std::random_device rd;
        std::vector<std::uint8_t> fake;
        if (cfg_.udp_fake_type == "quic") {
            fake = {0xc0, 0x00, 0x00, 0x00, 0x01, 0x08};
            for (int i = 0; i < 8; ++i) fake.push_back(static_cast<std::uint8_t>(rd()));
            fake.push_back(0x00); // SCID length
            fake.push_back(0x00); // token length
            fake.push_back(0x40); fake.push_back(0x20); // length varint (32)
            fake.push_back(0x00); // packet number
            for (int i = 0; i < 32; ++i) fake.push_back(static_cast<std::uint8_t>(rd()));
        } else if (cfg_.udp_fake_type == "discord") {
            fake = {0x80, 0x78, 0x00, 0x01};
            for (int i = 0; i < 8; ++i) fake.push_back(static_cast<std::uint8_t>(rd()));
        } else if (cfg_.udp_fake_type == "random") {
            fake.resize(32);
            for (auto& b : fake) b = static_cast<std::uint8_t>(rd());
        } else {
            fake = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42};
            for (int i = 0; i < 12; ++i) fake.push_back(static_cast<std::uint8_t>(rd()));
        }

        const int fd = up.is_ipv4() ? raw4_ : raw6_;
        std::uint16_t ip_id = static_cast<std::uint16_t>(up.ip_id + 0x7000);
        for (std::uint16_t i = 0; i < cfg_.udp_fake_repeats; ++i) {
            std::string uerr;
            if (!send_fake_udp(fd, up, fake.data(), fake.size(),
                               static_cast<std::uint8_t>(cfg_.udp_fake_ttl), ip_id, uerr)) {
                log_msg(LogLevel::Debug, "udp fake failed: %s", uerr.c_str());
                break;
            }
            ++stats_.udp_fakes;
            if (up.is_ipv4()) ++ip_id;
        }
        return accept(qh, id);
    }

    TcpPacket pkt;
    if (!parse_l3_packet(data, static_cast<std::size_t>(len), pkt)) return accept(qh, id);
    if (pkt.family == AF_INET && !cfg_.enable_ipv4) return accept(qh, id);
    if (pkt.family == AF_INET6 && !cfg_.enable_ipv6) return accept(qh, id);
    if (!port_selected(cfg_, pkt.dport)) return accept(qh, id);
    if (pkt.payload_len == 0) return accept(qh, id);
    if ((pkt.flags & (kTcpSyn | kTcpFin | kTcpRst)) != 0) return accept(qh, id);

    Flow& flow = flow_for(pkt);
    if (flow.hello_done && !flow.success && !flow.sni.empty() &&
        static_cast<std::int32_t>(pkt.seq - flow.hello_end_seq) >= 0) {
        flow.success = true;
        mark_profile_success(flow.sni);
    }
    StrategyValues flow_strategy = effective_for(flow.profile_index);

    if (flow.data_split && flow_strategy.split_data && pkt.payload_len > 2) {
        const std::size_t pos = std::min<std::size_t>(
            std::max<std::size_t>(1, flow_strategy.split_data_pos), pkt.payload_len - 1);
        return handle_split(qh, id, pkt, {pos}, flow_strategy, true);
    }

    // Retransmission / overlap: never grow the buffer twice, but re-split the
    // packet if any known boundary falls inside it. This keeps the hostname
    // fragmented even for retransmitted ClientHellos.
    if (!flow.split_offsets.empty()) {
        std::vector<std::size_t> in_packet;
        for (std::uint32_t b : flow.split_offsets) {
            const std::uint32_t off = (flow.base_seq + b) - pkt.seq;
            if (off > 0 && off < pkt.payload_len) in_packet.push_back(off);
        }
        if (!in_packet.empty()) return handle_split(qh, id, pkt, in_packet, flow_strategy);
    }
    if (flow.ignore) return accept(qh, id);

    // In-order reassembly of the first bytes of the client stream.
    std::size_t consumed = 0;
    if (pkt.seq == flow.next_seq) {
        consumed = pkt.payload_len;
    } else if (static_cast<std::int32_t>(pkt.seq - flow.next_seq) < 0) {
        const std::uint32_t behind = flow.next_seq - pkt.seq;
        if (behind >= pkt.payload_len) return accept(qh, id); // pure duplicate
        consumed = pkt.payload_len - behind;
    } else {
        return accept(qh, id); // gap: wait for the missing segment
    }

    if (flow.buf.size() + consumed > cfg_.flow_buffer) {
        flow.ignore = true;
        return accept(qh, id);
    }
    const std::uint8_t* start = pkt.payload + (pkt.payload_len - consumed);
    flow.buf.insert(flow.buf.end(), start, start + consumed);
    flow.next_seq += static_cast<std::uint32_t>(consumed);

    ClientHelloInfo info;
    const ParseResult rc = parse_client_hello(flow.buf.data(), flow.buf.size(), info,
                                               cfg_.flow_buffer);
    if (rc == ParseResult::NeedMore) return accept(qh, id);
    if (rc != ParseResult::Ok) {
        flow.ignore = true;
        if (rc != ParseResult::NoSni) ++stats_.parse_errors;
        return accept(qh, id);
    }

    char ifname[IF_NAMESIZE]{};
    const std::uint32_t outdev = nfq_get_outdev(nfad);
    if (outdev != 0) (void)if_indextoname(outdev, ifname);
    const std::vector<int> candidates = matching_profiles(info.sni, ifname);
    const int profile_index = candidates.empty()
                                  ? -1
                                  : choose_profile(info.sni, candidates);
    const bool target = domains_.matches(info.sni) || isAutoTarget(info.sni) ||
                        !candidates.empty();
    if (!target) {
        maybeProbe(pkt, info.sni);
        flow.ignore = true;
        return accept(qh, id);
    }

    const StrategyValues st = effective_for(profile_index);
    flow.profile_index = profile_index;
    flow.sni = info.sni;
    flow.hello_done = true;
    flow.hello_end_seq = flow.base_seq + static_cast<std::uint32_t>(info.record_end);
    if (!st.split_enabled) {
        flow.ignore = true;
        return accept(qh, id);
    }

    const StrategyConfig sc{st.split_delta, st.split_stride, st.split_max};
    const Decision d = decide_for_target(info, sc);
    if (d.action != Decision::Action::Split) {
        flow.ignore = true;
        return accept(qh, id);
    }

    if (cfg_.log_sni)
        log_msg(LogLevel::Info, "target ClientHello for %s", info.sni.c_str());

    flow.split_offsets.clear();
    flow.data_split = st.split_data;
    std::vector<std::size_t> in_packet;
    for (std::size_t b : d.boundaries) {
        flow.split_offsets.push_back(static_cast<std::uint32_t>(b));
        const std::uint32_t off = (flow.base_seq + static_cast<std::uint32_t>(b)) - pkt.seq;
        if (off > 0 && off < pkt.payload_len) in_packet.push_back(off);
    }
    log_msg(LogLevel::Debug,
            "decision: base_seq=%u pkt_seq=%u payload=%zu sni_off=%zu boundaries=%zu in_packet=%zu",
            flow.base_seq, pkt.seq, pkt.payload_len, info.sni_offset,
            d.boundaries.size(), in_packet.size());
    if (!in_packet.empty()) return handle_split(qh, id, pkt, in_packet, st);

    // Boundaries are in later segments; they will be handled when those
    // segments are queued (nft keeps the first N original-direction packets).
    return accept(qh, id);
}

int NfqEngine::run()
{
    std::vector<std::uint8_t> buf(1u << 18);
    auto last_prune = std::chrono::steady_clock::now();

    while (!stop_) {
        pollfd pfd{nfq_fd_, POLLIN, 0};
        const int rc = ::poll(&pfd, 1, 500);
        if (rc < 0) {
            if (errno == EINTR) continue;
            log_msg(LogLevel::Error, "poll: %s", std::strerror(errno));
            return 1;
        }
        if (rc == 0) {
            const auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_prune).count() > 10) {
                if (flows_.size() > 0) prune_flows();
                last_prune = now;
            }
            continue;
        }

        const ssize_t rd = ::recv(nfq_fd_, buf.data(), buf.size(), 0);
        if (rd < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) continue; // kernel queue pressure; fail-open
            log_msg(LogLevel::Error, "recv(nfqueue): %s", std::strerror(errno));
            return 1;
        }
        if (rd == 0) continue;
        nfq_handle_packet(nfq_, reinterpret_cast<char*>(buf.data()), static_cast<int>(rd));
    }
    return 0;
}

} // namespace dpi
