#pragma once

#include "config.hpp"

#include <string>

namespace dpi {

// Renders exactly the rules this tool owns. No foreign objects are referenced.
std::string render_ruleset(const Config& cfg, const AddressSet& mss_targets);

enum class TableState { Absent, Present, Unknown };

bool nft_available(std::string& version);
TableState nft_table_exists(std::string& error);
bool table_owned(std::string& error);
bool rules_apply(const Config& cfg, const AddressSet& mss_targets, bool dry_run, std::string& error);
bool rules_remove(bool dry_run, std::string& error);
bool rules_show(std::string& output, std::string& error);

} // namespace dpi
