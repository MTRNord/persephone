#pragma once
#include "nlohmann/json.hpp"
#include <cstddef>
#include <optional>
#include <string>
#include <vector>
#include <webserver/json.hpp>

using json = nlohmann::json;

struct [[nodiscard]] CreateRoomStateBuildData {
  client_server_json::CreateRoomBody createRoom_body;
  std::string room_id;
  std::string user_id;
  std::string room_version;
};

[[nodiscard]] std::vector<json>
build_createRoom_state(const CreateRoomStateBuildData &data);

[[nodiscard]] std::
    size_t constexpr calculate_assumed_createRoom_state_event_count(
        const bool has_alias_name, const bool has_name, const bool has_topic,
        const std::optional<std::size_t> &invites,
        const std::optional<std::size_t> &invites_3pid,
        const std::optional<std::size_t> &initial_state) {
  unsigned long expected_state_events = 1 + 1 + 1 + (has_alias_name ? 1 : 0) +
                                        3 + (has_name ? 1 : 0) +
                                        (has_topic ? 1 : 0);
  if (invites.has_value()) {
    expected_state_events += invites.value();
  }
  if (invites_3pid.has_value()) {
    expected_state_events += invites_3pid.value();
  }
  if (initial_state.has_value()) {
    expected_state_events += initial_state.value();
  }
  return expected_state_events;
}