#include "tls_probe.hpp"

#include <random>

namespace dpi {
namespace {

void u8(std::vector<std::uint8_t>& v, std::uint8_t x) { v.push_back(x); }
void u16(std::vector<std::uint8_t>& v, std::uint16_t x)
{
    v.push_back(static_cast<std::uint8_t>(x >> 8));
    v.push_back(static_cast<std::uint8_t>(x & 0xff));
}
void u24(std::vector<std::uint8_t>& v, std::uint32_t x)
{
    v.push_back(static_cast<std::uint8_t>((x >> 16) & 0xff));
    v.push_back(static_cast<std::uint8_t>((x >> 8) & 0xff));
    v.push_back(static_cast<std::uint8_t>(x & 0xff));
}
void ext(std::vector<std::uint8_t>& out, std::uint16_t type,
         const std::vector<std::uint8_t>& data)
{
    u16(out, type);
    u16(out, static_cast<std::uint16_t>(data.size()));
    out.insert(out.end(), data.begin(), data.end());
}

} // namespace

std::vector<std::uint8_t> build_probe_client_hello(std::string_view sni)
{
    std::vector<std::uint8_t> exts;

    // server_name
    {
        std::vector<std::uint8_t> d;
        u16(d, static_cast<std::uint16_t>(sni.size() + 3));
        u8(d, 0);
        u16(d, static_cast<std::uint16_t>(sni.size()));
        d.insert(d.end(), sni.begin(), sni.end());
        ext(exts, 0x0000, d);
    }
    // supported_versions: TLS 1.3, TLS 1.2
    {
        std::vector<std::uint8_t> d;
        u8(d, 4);
        u16(d, 0x0304);
        u16(d, 0x0303);
        ext(exts, 0x002b, d);
    }
    // supported_groups: x25519, secp256r1
    {
        std::vector<std::uint8_t> d;
        u16(d, 4);
        u16(d, 0x001d);
        u16(d, 0x0017);
        ext(exts, 0x000a, d);
    }
    // signature_algorithms
    {
        std::vector<std::uint8_t> d;
        u16(d, 8);
        u16(d, 0x0403);
        u16(d, 0x0804);
        u16(d, 0x0401);
        u16(d, 0x0503);
        ext(exts, 0x000d, d);
    }
    // ec_point_formats: uncompressed
    {
        std::vector<std::uint8_t> d;
        u8(d, 1);
        u8(d, 0);
        ext(exts, 0x000b, d);
    }
    // ALPN: http/1.1
    {
        const std::string_view proto = "http/1.1";
        std::vector<std::uint8_t> d;
        u16(d, static_cast<std::uint16_t>(proto.size() + 1));
        u8(d, static_cast<std::uint8_t>(proto.size()));
        d.insert(d.end(), proto.begin(), proto.end());
        ext(exts, 0x0010, d);
    }

    std::vector<std::uint8_t> body;
    u16(body, 0x0303);
    std::random_device rd;
    for (int i = 0; i < 32; ++i) u8(body, static_cast<std::uint8_t>(rd()));
    u8(body, 0); // session id
    const std::uint16_t ciphers[] = {0x1301, 0x1302, 0x1303, 0x1304, 0xc02b, 0xc02f,
                                     0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c, 0x009d,
                                     0x002f, 0x0035};
    u16(body, static_cast<std::uint16_t>(sizeof(ciphers)));
    for (std::uint16_t c : ciphers) u16(body, c);
    u8(body, 1);
    u8(body, 0);
    u16(body, static_cast<std::uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    std::vector<std::uint8_t> hs;
    u8(hs, 0x01);
    u24(hs, static_cast<std::uint32_t>(body.size()));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<std::uint8_t> rec;
    u8(rec, 0x16);
    u8(rec, 0x03);
    u8(rec, 0x01);
    u16(rec, static_cast<std::uint16_t>(hs.size()));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

} // namespace dpi
