#include "tls_clienthello.hpp"

#include <algorithm>
#include <cctype>

namespace dpi {
namespace {

constexpr std::uint8_t kHandshake = 0x16;
constexpr std::uint8_t kClientHello = 0x01;

struct Cursor {
    const std::uint8_t* p = nullptr;
    std::size_t pos = 0;
    std::size_t avail_end = 0;  // bytes actually present
    bool record_complete = false;
    bool bad = false;
    bool need_more = false;

    bool need(std::size_t k) noexcept
    {
        if (k <= avail_end - std::min(avail_end, pos)) return true;
        if (!record_complete) need_more = true;
        else bad = true;
        return false;
    }
    std::uint8_t u8() noexcept
    {
        if (!need(1)) return 0;
        return p[pos++];
    }
    std::uint16_t u16() noexcept
    {
        if (!need(2)) return 0;
        const std::uint16_t v = static_cast<std::uint16_t>((p[pos] << 8) | p[pos + 1]);
        pos += 2;
        return v;
    }
    std::uint32_t u24() noexcept
    {
        if (!need(3)) return 0;
        const std::uint32_t v = (static_cast<std::uint32_t>(p[pos]) << 16) |
                                (static_cast<std::uint32_t>(p[pos + 1]) << 8) |
                                static_cast<std::uint32_t>(p[pos + 2]);
        pos += 3;
        return v;
    }
    void skip(std::size_t k) noexcept
    {
        if (need(k)) pos += k;
    }
};

bool plausible_hostname(std::string_view s) noexcept
{
    if (s.empty() || s.size() > 253) return false;
    for (char c : s) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '-' || c == '.' || c == '_')) return false;
    }
    return s.front() != '.' && s.back() != '.';
}

} // namespace

ParseResult parse_client_hello(const std::uint8_t* data, std::size_t len,
                               ClientHelloInfo& out, std::size_t max_need) noexcept
{
    if (len < 5) return ParseResult::NeedMore;
    if (data[0] != kHandshake) return ParseResult::NotTls;
    if (data[1] != 0x03 || data[2] > 0x04) return ParseResult::NotTls;

    const std::size_t rec_len = (static_cast<std::size_t>(data[3]) << 8) | data[4];
    if (rec_len < 4) return ParseResult::Malformed;
    if (rec_len > max_need) return ParseResult::TooLarge;

    const std::size_t rec_end = 5 + rec_len;         // declared end
    const std::size_t avail_end = std::min(len, rec_end); // parsed bytes
    Cursor c{data, 5, avail_end, len >= rec_end, false, false};

    const std::uint8_t hs_type = c.u8();
    const std::uint32_t hs_len = c.u24();
    if (c.bad) return ParseResult::Malformed;
    if (c.need_more) return ParseResult::NeedMore;
    if (hs_type != kClientHello) return ParseResult::NoSni;
    if (hs_len < 38 || 9 + static_cast<std::size_t>(hs_len) > rec_end)
        return ParseResult::Malformed;

    c.skip(2);  // legacy_version
    c.skip(32); // random
    const std::uint8_t session_id_len = c.u8();
    if (c.bad) return ParseResult::Malformed;
    if (c.need_more) return ParseResult::NeedMore;
    if (session_id_len > 32) return ParseResult::Malformed;
    c.skip(session_id_len);

    const std::uint16_t ciphers_len = c.u16();
    if (c.bad) return ParseResult::Malformed;
    if (c.need_more) return ParseResult::NeedMore;
    if (ciphers_len < 2 || (ciphers_len % 2) != 0) return ParseResult::Malformed;
    c.skip(ciphers_len);

    const std::uint8_t comp_len = c.u8();
    if (c.bad) return ParseResult::Malformed;
    if (c.need_more) return ParseResult::NeedMore;
    if (comp_len < 1) return ParseResult::Malformed;
    c.skip(comp_len);

    const std::uint16_t ext_total = c.u16();
    if (c.bad) return ParseResult::Malformed;
    if (c.need_more) return ParseResult::NeedMore;
    const std::size_t ext_end = c.pos + ext_total;
    if (ext_end > rec_end) return ParseResult::Malformed;

    // Extensions are walked incrementally. We may stop as soon as the SNI is
    // complete, even if the tail of the ClientHello has not arrived yet.
    while (c.pos < ext_end) {
        const std::uint16_t type = c.u16();
        const std::uint16_t ext_len = c.u16();
        if (c.bad) return ParseResult::Malformed;
        if (c.need_more) return ParseResult::NeedMore;
        if (c.pos + ext_len > ext_end) return ParseResult::Malformed;

        if (type != 0x0000) { // server_name
            c.skip(ext_len);
            if (c.bad) return ParseResult::Malformed;
            if (c.need_more) return ParseResult::NeedMore;
            continue;
        }

        const std::size_t ext_start = c.pos;
        const std::uint16_t list_len = c.u16();
        if (c.bad) return ParseResult::Malformed;
        if (c.need_more) return ParseResult::NeedMore;
        if (c.pos + list_len > ext_start + ext_len) return ParseResult::Malformed;

        const std::size_t list_end = c.pos + list_len;
        while (c.pos + 3 <= list_end) {
            const std::uint8_t name_type = c.u8();
            const std::uint16_t name_len = c.u16();
            if (c.bad) return ParseResult::Malformed;
            if (c.need_more) return ParseResult::NeedMore;
            if (c.pos + name_len > list_end || name_len == 0)
                return ParseResult::Malformed;
            if (!c.need(name_len)) {
                if (c.need_more) return ParseResult::NeedMore;
                return ParseResult::Malformed;
            }
            if (name_type == 0) {
                std::string host(reinterpret_cast<const char*>(data + c.pos), name_len);
                if (!plausible_hostname(host)) return ParseResult::NoSni;
                std::transform(host.begin(), host.end(), host.begin(),
                               [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                out.sni = std::move(host);
                out.sni_offset = c.pos; // relative to the buffer (record) start
                out.sni_length = name_len;
                out.record_end = rec_end;
                return ParseResult::Ok;
            }
            c.skip(name_len);
            if (c.bad) return ParseResult::Malformed;
            if (c.need_more) return ParseResult::NeedMore;
        }
        return ParseResult::NoSni;
    }

    return ParseResult::NoSni;
}

} // namespace dpi
