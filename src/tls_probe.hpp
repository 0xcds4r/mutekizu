#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace dpi {

// Minimal TLS 1.2/1.3 ClientHello used only by the auto-discovery probe.
// It carries SNI, supported_versions, groups and signature algorithms, and an
// http/1.1 ALPN. No certificate is validated: the probe only checks whether
// the destination answers the TLS handshake at all.
std::vector<std::uint8_t> build_probe_client_hello(std::string_view sni);

} // namespace dpi
