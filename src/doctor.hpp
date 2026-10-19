#pragma once

#include "config.hpp"

#include <string>

namespace dpi {

// Read-only diagnostics. Returns 0 = ok, 1 = error, 2 = warnings.
int run_doctor(const Config& cfg, const DomainSet& domains, const AddressSet& mss_targets,
               bool verbose);

bool nft_queue_conflicts(std::uint16_t queue_num, std::string& detail, std::string& error);

} // namespace dpi
