// Test-only helper. Models a deliberately naive, stateless DPI: it looks for a
// literal byte string inside a SINGLE TCP payload and drops that packet.
// It is not part of mutekizu and is not installed.
#include "netpacket.hpp"
#include "tls_clienthello.hpp"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <poll.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

namespace {

volatile sig_atomic_t g_stop = 0;
std::string g_needle;
std::string g_mode = "needle";
unsigned long g_packets = 0;
unsigned long g_dropped = 0;

void on_signal(int) { g_stop = 1; }

bool complete_client_hello(const std::uint8_t* data, std::size_t len)
{
    dpi::ClientHelloInfo info;
    const auto rc = dpi::parse_client_hello(data, len, info, 65535);
    return rc == dpi::ParseResult::Ok && info.record_end <= len;
}

bool contains(const std::uint8_t* data, std::size_t len, const std::string& needle)
{
    if (needle.empty() || len < needle.size()) return false;
    for (std::size_t i = 0; i + needle.size() <= len; ++i) {
        if (std::memcmp(data + i, needle.data(), needle.size()) == 0) return true;
    }
    return false;
}

int cb(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfad, void*)
{
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
    if (ph == nullptr) return -1;
    const std::uint32_t id = ntohl(ph->packet_id);
    ++g_packets;

    unsigned char* data = nullptr;
    const int len = nfq_get_payload(nfad, &data);
    if (len > 0 && data != nullptr) {
        dpi::TcpPacket pkt;
        const bool hit = dpi::parse_l3_packet(data, static_cast<std::size_t>(len), pkt) &&
                         pkt.payload_len > 0 &&
                         (g_mode == "hello"
                              ? complete_client_hello(pkt.payload, pkt.payload_len)
                              : contains(pkt.payload, pkt.payload_len, g_needle));
        if (hit) {
            ++g_dropped;
            return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

} // namespace

int main(int argc, char** argv)
{
    unsigned queue_num = 2001;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--queue" && i + 1 < argc) queue_num = static_cast<unsigned>(std::stoul(argv[++i]));
        else if (a == "--needle" && i + 1 < argc) g_needle = argv[++i];
        else if (a == "--mode" && i + 1 < argc) g_mode = argv[++i];
        else {
            std::fprintf(stderr, "usage: %s --queue N [--needle STRING | --mode hello]\n", argv[0]);
            return 2;
        }
    }
    if (g_mode == "needle" && g_needle.empty()) {
        std::fprintf(stderr, "--needle is required in needle mode\n");
        return 2;
    }
    if (g_mode != "needle" && g_mode != "hello") {
        std::fprintf(stderr, "unknown mode\n");
        return 2;
    }

    nfq_handle* h = nfq_open();
    if (h == nullptr) { std::perror("nfq_open"); return 1; }
    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);
    nfq_unbind_pf(h, AF_INET6);
    nfq_bind_pf(h, AF_INET6);
    nfq_q_handle* q = nfq_create_queue(h, static_cast<std::uint16_t>(queue_num), &cb, nullptr);
    if (q == nullptr) { std::perror("nfq_create_queue"); return 1; }
    nfq_set_mode(q, NFQNL_COPY_PACKET, 0xffff);
    nfq_set_queue_maxlen(q, 128);

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    std::vector<std::uint8_t> buf(1u << 18);
    const int fd = nfq_fd(h);
    while (!g_stop) {
        pollfd pfd{fd, POLLIN, 0};
        const int rc = ::poll(&pfd, 1, 200);
        if (rc > 0) {
            const ssize_t rd = ::recv(fd, buf.data(), buf.size(), 0);
            if (rd > 0) nfq_handle_packet(h, reinterpret_cast<char*>(buf.data()), static_cast<int>(rd));
        }
    }

    std::fprintf(stderr, "dpi-model: packets=%lu dropped=%lu\n", g_packets, g_dropped);
    nfq_destroy_queue(q);
    nfq_close(h);
    return 0;
}
