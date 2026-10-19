#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dpi {

enum class ParseResult {
    Ok,
    NeedMore,      // more bytes of the first TLS record are required
    NotTls,        // first bytes are not a TLS handshake record
    Malformed,     // structurally invalid TLS data
    NoSni,         // valid ClientHello without a usable server_name
    TooLarge       // record larger than the configured reassembly bound
};

struct ClientHelloInfo {
    std::string sni;          // lowercase hostname
    std::size_t sni_offset = 0; // offset of the hostname from buffer start
    std::size_t sni_length = 0;
    std::size_t record_end = 0; // offset one past the first TLS record
};

// Strict, bounds-checked parser for the FIRST TLS record of a client stream.
// It never searches for strings; it walks the handshake/extension lengths.
// `max_need` bounds how many bytes the parser is willing to wait for.
ParseResult parse_client_hello(const std::uint8_t* data, std::size_t len,
                               ClientHelloInfo& out, std::size_t max_need) noexcept;

} // namespace dpi
