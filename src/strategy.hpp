#pragma once

#include "config.hpp"
#include "tls_clienthello.hpp"

#include <cstddef>
#include <vector>

namespace dpi {

struct StrategyConfig {
    std::uint16_t split_delta = 4;
    std::uint16_t split_stride = 0; // 0 = one boundary, >0 = every N bytes inside SNI
    std::uint16_t split_max = 64;
};

struct Decision {
    enum class Action { Accept, Split };
    Action action = Action::Accept;
    // Strictly increasing boundaries inside the SNI, relative to the stream.
    std::vector<std::size_t> boundaries;
};

// Only acts on TLS ClientHello records whose SNI is in the target set.
Decision decide(const ClientHelloInfo& info, const DomainSet& domains,
                const StrategyConfig& sc) noexcept;

// Same split decision, but the SNI has already been accepted as a target
// (e.g. by the auto-discovery set).
Decision decide_for_target(const ClientHelloInfo& info, const StrategyConfig& sc) noexcept;

} // namespace dpi
