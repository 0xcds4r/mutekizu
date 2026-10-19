#include "strategy.hpp"

#include <algorithm>

namespace dpi {

Decision decide(const ClientHelloInfo& info, const DomainSet& domains,
                const StrategyConfig& sc) noexcept
{
    if (info.sni.empty() || info.sni_length == 0) return {};
    if (!domains.matches(info.sni)) return {};
    return decide_for_target(info, sc);
}

Decision decide_for_target(const ClientHelloInfo& info, const StrategyConfig& sc) noexcept
{
    Decision d;
    if (info.sni.empty() || info.sni_length == 0) return d;

    // Boundaries stay strictly inside the hostname, so no single segment
    // carries the complete name. With split_stride > 0 we place additional
    // boundaries through the whole SNI; this also cuts a blocked suffix that
    // sits at the end of a long hostname.
    std::size_t delta = sc.split_delta;
    if (info.sni_length <= 2) {
        delta = 1;
    } else {
        delta = std::clamp<std::size_t>(delta, 1, info.sni_length - 1);
    }

    const std::size_t sni_end = info.sni_offset + info.sni_length;
    std::size_t off = info.sni_offset + delta;
    if (off >= info.record_end || off >= sni_end) return d;
    d.boundaries.push_back(off);

    if (sc.split_stride > 0) {
        const std::size_t stride = std::max<std::size_t>(1, sc.split_stride);
        for (off += stride; off < sni_end && d.boundaries.size() < sc.split_max; off += stride) {
            if (off < info.record_end) d.boundaries.push_back(off);
        }
    }

    d.action = Decision::Action::Split;
    return d;
}

} // namespace dpi
