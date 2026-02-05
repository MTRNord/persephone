#pragma once

#include <algorithm>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace room_version {

/// Supported room versions - currently only v11
inline const std::set<std::string> supported_versions = {"11"};

/// Default room version for new rooms
inline constexpr std::string_view default_version = "11";

/// Check if a room version is supported
[[nodiscard]] inline bool is_supported(std::string_view version) {
  return supported_versions.contains(std::string(version));
}

/// Get all supported versions as a vector (useful for make_join response)
[[nodiscard]] inline std::vector<std::string> get_supported_versions() {
  return {supported_versions.begin(), supported_versions.end()};
}

/// Check if version supports restricted joins (join_authorised_via_users_server)
/// Room versions 8, 9, 10, 11 support this feature
[[nodiscard]] inline bool supports_restricted_join(std::string_view version) {
  return version == "8" || version == "9" || version == "10" ||
         version == "11";
}

/// Check if the room version uses the reference hash format for event IDs
/// Room versions 4+ use this format (URL-safe base64 of SHA-256)
[[nodiscard]] inline bool uses_reference_hash(std::string_view version) {
  // Versions 1, 2, 3 use a different event ID format
  return version != "1" && version != "2" && version != "3";
}

} // namespace room_version
