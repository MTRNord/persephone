#pragma once

#include <chrono>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <trantor/utils/Logger.h>

namespace sync_utils {

/// Parse a sync token in format: ps_<event_nid>_<timestamp>
/// @return The event_nid if valid, nullopt if invalid token format
[[nodiscard]] inline std::optional<int64_t>
parse_sync_token(const std::string &token) {
  if (token.empty()) {
    return std::nullopt;
  }

  // Expected format: ps_<event_nid>_<timestamp>
  if (!token.starts_with("ps_")) {
    LOG_WARN << "Invalid sync token format (missing prefix): " << token;
    return std::nullopt;
  }

  const auto first_underscore = token.find('_', 3);
  if (first_underscore == std::string::npos) {
    LOG_WARN << "Invalid sync token format (missing second underscore): "
             << token;
    return std::nullopt;
  }

  try {
    return std::stoll(token.substr(3, first_underscore - 3));
  } catch (const std::exception &) {
    LOG_WARN << "Invalid sync token (failed to parse event_nid): " << token;
    return std::nullopt;
  }
}

/// Generate a sync token from event_nid
[[nodiscard]] inline std::string generate_sync_token(int64_t event_nid) {
  const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  return std::format("ps_{}_{}", event_nid, now);
}

} // namespace sync_utils
