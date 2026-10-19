// Unit corpus for the synthetic DPI ladder itself: verifies that the models
// reassemble/parse what they claim before any network experiment is run.
#include "ladder.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sys/socket.h>

namespace {

int g_fail = 0;

void check(bool cond, const std::string& what)
{
    if (!cond) { ++g_fail; std::printf("FAIL: %s\n", what.c_str()); }
}

std::vector<std::uint8_t> client_hello(const std::string& host)
{
    std::vector<std::uint8_t> body;
    auto u8 = [&](std::uint8_t v) { body.push_back(v); };
    auto u16 = [&](std::uint16_t v) { body.push_back(v >> 8); body.push_back(v & 0xff); };

    u16(0x0303);
    for (int i = 0; i < 32; ++i) u8(static_cast<std::uint8_t>(i));
    u8(0);
    u16(2); u16(0x1301);
    u8(1); u8(0);

    std::vector<std::uint8_t> sni;
    const std::uint16_t list_len = static_cast<std::uint16_t>(host.size() + 3);
    sni.push_back(static_cast<std::uint8_t>(list_len >> 8));
    sni.push_back(static_cast<std::uint8_t>(list_len & 0xff));
    sni.push_back(0);
    sni.push_back(static_cast<std::uint8_t>(host.size() >> 8));
    sni.push_back(static_cast<std::uint8_t>(host.size() & 0xff));
    sni.insert(sni.end(), host.begin(), host.end());

    std::vector<std::uint8_t> ext;
    ext.push_back(0); ext.push_back(0);
    ext.push_back(static_cast<std::uint8_t>(sni.size() >> 8));
    ext.push_back(static_cast<std::uint8_t>(sni.size() & 0xff));
    ext.insert(ext.end(), sni.begin(), sni.end());
    u16(static_cast<std::uint16_t>(ext.size()));
    body.insert(body.end(), ext.begin(), ext.end());

    std::vector<std::uint8_t> hs;
    hs.push_back(0x01);
    hs.push_back(static_cast<std::uint8_t>((body.size() >> 16) & 0xff));
    hs.push_back(static_cast<std::uint8_t>((body.size() >> 8) & 0xff));
    hs.push_back(static_cast<std::uint8_t>(body.size() & 0xff));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<std::uint8_t> rec;
    rec.push_back(0x16); rec.push_back(0x03); rec.push_back(0x01);
    rec.push_back(static_cast<std::uint8_t>(hs.size() >> 8));
    rec.push_back(static_cast<std::uint8_t>(hs.size() & 0xff));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

dpi::TcpPacket mk(std::uint32_t seq, const std::uint8_t* data, std::size_t len)
{
    dpi::TcpPacket p;
    p.family = AF_INET;
    p.src[0] = 10; p.src[3] = 1;
    p.dst[0] = 10; p.dst[3] = 2;
    p.sport = 40000;
    p.dport = 443;
    p.seq = seq;
    p.payload = data;
    p.payload_len = len;
    return p;
}

bool feed(arena::DpiFilter& f, std::uint32_t seq, const std::vector<std::uint8_t>& data)
{
    dpi::TcpPacket p = mk(seq, data.data(), data.size());
    return f.on_packet(p);
}

void expect(arena::Level level, const std::string& name, bool want_drop,
            const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>>& segs,
            const std::string& blocked = "test.example")
{
    arena::DpiFilter f(level, blocked);
    bool got = false;
    for (const auto& [seq, data] : segs) got = feed(f, seq, data) || got;
    check(got == want_drop,
          "L" + std::to_string(static_cast<int>(level)) + " " + name +
              " expected=" + (want_drop ? "drop" : "pass") +
              " got=" + (got ? "drop" : "pass"));
}

} // namespace

int main()
{
    using arena::Level;
    const auto hello = client_hello("test.example");
    const auto allowed = client_hello("other.example");
    const std::uint32_t base = 1000;
    const auto whole = std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>>{
        {base, hello}};
    const auto allowed_whole = std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>>{
        {base, allowed}};

    for (int l = 1; l <= 5; ++l) {
        const auto level = static_cast<Level>(l);
        expect(level, "whole hello", true, whole);
        expect(level, "allowed SNI", false, allowed_whole);
    }

    // Split strictly inside the SNI of this synthetic hello.
    dpi::ClientHelloInfo hello_info;
    dpi::parse_client_hello(hello.data(), hello.size(), hello_info, 8192);
    const std::size_t split = hello_info.sni_offset + 4;
    const std::vector<std::uint8_t> p1(hello.begin(), hello.begin() + split);
    const std::vector<std::uint8_t> p2(hello.begin() + split, hello.end());
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> in_order{
        {base, p1}, {base + static_cast<std::uint32_t>(split), p2}};
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> reversed{
        {base + static_cast<std::uint32_t>(split), p2}, {base, p1}};
    const std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> duplicate{
        {base, p1}, {base, p1}, {base + static_cast<std::uint32_t>(split), p2}};

    expect(Level::L1_SegmentCompleteHello, "split hello", false, in_order);
    expect(Level::L2_SegmentNeedle, "split inside SNI", false, in_order);
    expect(Level::L3_FirstSegmentPolicy, "split hello (strict first segment)", true, in_order);
    expect(Level::L4_TcpReassembly, "split hello", true, in_order);
    expect(Level::L5_ReassemblyStrict, "split hello", true, in_order);
    expect(Level::L4_TcpReassembly, "out-of-order", true, reversed);
    expect(Level::L5_ReassemblyStrict, "out-of-order", true, reversed);
    expect(Level::L4_TcpReassembly, "duplicate segment", true, duplicate);

    // Truncated before the SNI: no model can know the name. L5 must not act
    // without the complete record; L4 acts only once the SNI is available.
    const std::vector<std::uint8_t> cut(hello.begin(),
                                        hello.begin() + static_cast<std::ptrdiff_t>(
                                            hello_info.sni_offset));
    expect(Level::L4_TcpReassembly, "truncated before SNI", false, {{base, cut}});
    expect(Level::L5_ReassemblyStrict, "truncated before SNI", false, {{base, cut}});

    // Malformed TLS-looking input: L3's policy blocks; L4 does not guess.
    std::vector<std::uint8_t> junk{0x16, 0x03, 0x03, 0xff, 0xff, 0x00, 0x00};
    expect(Level::L3_FirstSegmentPolicy, "malformed TLS", true, {{base, junk}});
    expect(Level::L4_TcpReassembly, "malformed TLS", false, {{base, junk}});

    // Bounded memory is not a free bypass: oversized buffered stream blocks.
    std::vector<std::uint8_t> huge(70000, 0);
    huge[0] = 0x16; huge[1] = 0x03; huge[2] = 0x03; huge[3] = 0x00; huge[4] = 0x10;
    expect(Level::L4_TcpReassembly, "buffer overflow policy", true, {{base, huge}});

    // Boundary corpus: split at every offset. L1 must never see a complete
    // record in one segment (except the unsplit case); L4 must always block.
    for (std::size_t k = 1; k < hello.size(); ++k) {
        const std::vector<std::uint8_t> a(hello.begin(), hello.begin() + static_cast<std::ptrdiff_t>(k));
        const std::vector<std::uint8_t> b(hello.begin() + static_cast<std::ptrdiff_t>(k), hello.end());
        arena::DpiFilter f1(Level::L1_SegmentCompleteHello, "test.example");
        bool d1 = feed(f1, base, a) || feed(f1, base + static_cast<std::uint32_t>(k), b);
        check(!d1, "L1 split k=" + std::to_string(k));
        arena::DpiFilter f4(Level::L4_TcpReassembly, "test.example");
        bool d4 = feed(f4, base, a) || feed(f4, base + static_cast<std::uint32_t>(k), b);
        check(d4, "L4 split k=" + std::to_string(k));
    }

    std::printf("%s (%d failure(s))\n", g_fail == 0 ? "ALL OK" : "FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
