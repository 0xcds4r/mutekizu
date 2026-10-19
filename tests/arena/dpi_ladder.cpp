// Configurable synthetic DPI used by the arena. It is a lab model, not a TSPU
// emulator. It only sees the client->server direction, as selected by nftables.
#include "ladder.hpp"

#include <cerrno>
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
arena::DpiFilter* g_filter = nullptr;

void on_signal(int) { g_stop = 1; }

int cb(nfq_q_handle* qh, nfgenmsg*, nfq_data* nfad, void*)
{
    nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
    if (ph == nullptr) return -1;
    const std::uint32_t id = ntohl(ph->packet_id);

    unsigned char* data = nullptr;
    const int len = nfq_get_payload(nfad, &data);
    dpi::TcpPacket pkt;
    if (len <= 0 || data == nullptr || !dpi::parse_l3_packet(data, static_cast<std::size_t>(len), pkt))
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);

    if (g_filter->on_packet(pkt))
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}
} // namespace

int main(int argc, char** argv)
{
    int level = 4;
    unsigned queue = 3001;
    std::string block = "test.example";

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--level" && i + 1 < argc) level = std::stoi(argv[++i]);
        else if (a == "--queue" && i + 1 < argc) queue = static_cast<unsigned>(std::stoul(argv[++i]));
        else if (a == "--block" && i + 1 < argc) block = argv[++i];
        else {
            std::fprintf(stderr, "usage: %s --level 1..5 [--queue N] [--block SNI]\n", argv[0]);
            return 2;
        }
    }
    if (level < 1 || level > 5) {
        std::fprintf(stderr, "level must be 1..5\n");
        return 2;
    }

    arena::DpiFilter filter(static_cast<arena::Level>(level), block);
    g_filter = &filter;

    nfq_handle* h = nfq_open();
    if (h == nullptr) { std::perror("nfq_open"); return 1; }
    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);
    nfq_unbind_pf(h, AF_INET6);
    nfq_bind_pf(h, AF_INET6);
    nfq_q_handle* q = nfq_create_queue(h, static_cast<std::uint16_t>(queue), &cb, nullptr);
    if (q == nullptr) { std::perror("nfq_create_queue"); return 1; }
    if (nfq_set_mode(q, NFQNL_COPY_PACKET, 0xffff) < 0) { std::perror("nfq_set_mode"); return 1; }
    // Deliberately fail-closed: this is the DPI, not the circumvention tool.
    nfq_set_queue_maxlen(q, 1024);

    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);

    std::printf("READY level=%d queue=%u block=%s\n", level, queue, block.c_str());
    std::fflush(stdout);

    std::vector<std::uint8_t> buf(1u << 18);
    const int fd = nfq_fd(h);
    while (!g_stop) {
        pollfd pfd{fd, POLLIN, 0};
        const int rc = ::poll(&pfd, 1, 200);
        if (rc <= 0) continue;
        const ssize_t rd = ::recv(fd, buf.data(), buf.size(), 0);
        if (rd > 0)
            nfq_handle_packet(h, reinterpret_cast<char*>(buf.data()), static_cast<int>(rd));
    }

    const auto& s = filter.stats();
    std::fprintf(stderr,
                 "dpi-ladder: level=%d packets=%lu dropped=%lu flows=%lu overflow_blocks=%lu parse_errors=%lu\n",
                 level, s.packets, s.dropped, s.flows, s.overflow_blocks, s.parse_errors);
    nfq_destroy_queue(q);
    nfq_close(h);
    return 0;
}
