
#include "nlohmann/json.hpp"
#include "utils/state_res.hpp"

#include <chrono>
#include <fstream>
#include <snitch/snitch.hpp>
#include <utils/errors.hpp>
#include <utils/json_utils.hpp>
#include <utils/room_utils.hpp>
#include <utils/utils.hpp>
#include <vector>

using json = nlohmann::json;

// Helper to set up config and signing keys for tests
namespace {
void write_test_config() {
  const auto *const config_file = R"(
---
database:
  host: localhost
  port: 5432
  database_name: postgres
  user: postgres
  password: mysecretpassword
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
webserver:
  ssl: false
  )";

  std::ofstream file("config.yaml");
  file << config_file;
  file.close();
}
} // namespace

// ============================================================================
// Tests verifying the complete PDU format that send_join would return
// ============================================================================

TEST_CASE("Room creation produces spec-compliant PDUs for federation",
          "[send_join][pdu_format]") {
  write_test_config();
  const Config config{};
  json_utils::ensure_server_keys(config);
  const auto key_data = get_verify_key_data(config);

  const CreateRoomStateBuildData data{
      .createRoom_body = {.creation_content = std::nullopt,
                          .initial_state = std::nullopt,
                          .invite = std::nullopt,
                          .invite_3pid = std::nullopt,
                          .name = "Test Room",
                          .power_level_content_override = std::nullopt,
                          .preset = std::nullopt,
                          .room_alias_name = std::nullopt,
                          .room_version = "11",
                          .topic = "Test Topic",
                          .visibility = std::nullopt,
                          .is_direct = std::nullopt},
      .room_id = "!testroom:localhost",
      .user_id = "@alice:localhost",
      .room_version = "11"};

  auto events = build_createRoom_state(data, "localhost");

  finalize_room_creation_events(events, "11",
                                config.matrix_config.server_name,
                                key_data.key_id, key_data.private_key);

  SECTION("All events have complete Room Version 11 PDU format") {
    // Per Matrix spec v1.17, Room Version 11 PDUs must have:
    // auth_events, content, depth, hashes, origin_server_ts,
    // prev_events, room_id, sender, signatures, type
    // state_key is required for state events
    for (size_t i = 0; i < events.size(); ++i) {
      const auto &event = events[i];

      REQUIRE(event.contains("auth_events"));
      REQUIRE(event["auth_events"].is_array());

      REQUIRE(event.contains("content"));
      REQUIRE(event["content"].is_object());

      REQUIRE(event.contains("depth"));
      REQUIRE(event["depth"].is_number_integer());
      REQUIRE(event["depth"].get<int64_t>() >= 1);

      REQUIRE(event.contains("hashes"));
      REQUIRE(event["hashes"].is_object());
      REQUIRE(event["hashes"].contains("sha256"));
      REQUIRE(event["hashes"]["sha256"].is_string());
      REQUIRE_FALSE(event["hashes"]["sha256"].get<std::string>().empty());

      REQUIRE(event.contains("origin_server_ts"));
      REQUIRE(event["origin_server_ts"].is_number_integer());

      REQUIRE(event.contains("prev_events"));
      REQUIRE(event["prev_events"].is_array());

      REQUIRE(event.contains("room_id"));
      REQUIRE(event["room_id"] == "!testroom:localhost");

      REQUIRE(event.contains("sender"));
      REQUIRE(event["sender"] == "@alice:localhost");

      REQUIRE(event.contains("signatures"));
      REQUIRE(event["signatures"].is_object());
      REQUIRE(event["signatures"].contains("localhost"));

      REQUIRE(event.contains("type"));
      REQUIRE(event["type"].is_string());

      // All room creation events are state events, must have state_key
      REQUIRE(event.contains("state_key"));

      // event_id must be present and start with $
      REQUIRE(event.contains("event_id"));
      REQUIRE(event["event_id"].get<std::string>().starts_with("$"));
    }
  }

  SECTION("Event ordering matches spec requirements") {
    // Room creation events must be in this order:
    // 1. m.room.create
    // 2. m.room.member (creator join)
    // 3. m.room.power_levels
    // Then optional events like name, topic, etc.
    REQUIRE(events.size() >= 3);
    REQUIRE(events[0]["type"] == "m.room.create");
    REQUIRE(events[1]["type"] == "m.room.member");
    REQUIRE(events[1]["content"]["membership"] == "join");
    REQUIRE(events[2]["type"] == "m.room.power_levels");
  }

  SECTION("m.room.create event is correctly structured") {
    const auto &create = events[0];

    REQUIRE(create["auth_events"] == json::array());
    REQUIRE(create["prev_events"] == json::array());
    REQUIRE(create["depth"] == 1);
    REQUIRE(create["content"].contains("creator"));
    REQUIRE(create["content"]["creator"] == "@alice:localhost");
    REQUIRE(create["content"].contains("room_version"));
    REQUIRE(create["content"]["room_version"] == "11");
    REQUIRE(create["state_key"] == "");
  }

  SECTION("DAG structure is correct (prev_events chain)") {
    // m.room.create: no prev_events
    REQUIRE(events[0]["prev_events"].empty());

    // Every subsequent event references the previous event
    for (size_t i = 1; i < events.size(); ++i) {
      REQUIRE(events[i]["prev_events"].size() == 1);
      REQUIRE(events[i]["prev_events"][0] ==
              events[i - 1]["event_id"]);
    }
  }

  SECTION("Content hashes are present and non-empty") {
    for (const auto &event : events) {
      REQUIRE(event.contains("hashes"));
      REQUIRE(event["hashes"].contains("sha256"));
      REQUIRE_FALSE(event["hashes"]["sha256"].get<std::string>().empty());
    }
  }

  SECTION("Event IDs are valid (recomputable from reference hash)") {
    for (const auto &event : events) {
      auto recomputed = event_id(event, "11");
      REQUIRE(recomputed == event["event_id"].get<std::string>());
    }
  }

  SECTION("Auth chain can be constructed from auth_events") {
    // Simulate what get_auth_chain would return:
    // For each event, all events referenced in auth_events should exist
    std::map<std::string, json> event_map;
    for (const auto &event : events) {
      event_map[event["event_id"].get<std::string>()] = event;
    }

    for (const auto &event : events) {
      for (const auto &auth_event_id : event["auth_events"]) {
        auto id = auth_event_id.get<std::string>();
        REQUIRE(event_map.contains(id));
      }
    }
  }

  SECTION("With name and topic, events contain expected content") {
    // We set name and topic in the test data
    bool found_name = false;
    bool found_topic = false;

    for (const auto &event : events) {
      if (event["type"] == "m.room.name") {
        found_name = true;
        REQUIRE(event["content"]["name"] == "Test Room");
      }
      if (event["type"] == "m.room.topic") {
        found_topic = true;
        REQUIRE(event["content"]["topic"] == "Test Topic");
      }
    }

    REQUIRE(found_name);
    REQUIRE(found_topic);
  }
}

TEST_CASE("Room creation with invites produces valid invite PDUs",
          "[send_join][pdu_format]") {
  write_test_config();
  const Config config{};
  json_utils::ensure_server_keys(config);
  const auto key_data = get_verify_key_data(config);

  std::vector<std::string> invites = {"@bob:localhost", "@charlie:remote.com"};

  const CreateRoomStateBuildData data{
      .createRoom_body = {.creation_content = std::nullopt,
                          .initial_state = std::nullopt,
                          .invite = invites,
                          .invite_3pid = std::nullopt,
                          .name = std::nullopt,
                          .power_level_content_override = std::nullopt,
                          .preset = std::nullopt,
                          .room_alias_name = std::nullopt,
                          .room_version = "11",
                          .topic = std::nullopt,
                          .visibility = std::nullopt,
                          .is_direct = std::nullopt},
      .room_id = "!inviteroom:localhost",
      .user_id = "@alice:localhost",
      .room_version = "11"};

  auto events = build_createRoom_state(data, "localhost");

  finalize_room_creation_events(events, "11",
                                config.matrix_config.server_name,
                                key_data.key_id, key_data.private_key);

  SECTION("Invite events have correct structure") {
    int invite_count = 0;
    for (const auto &event : events) {
      if (event["type"] == "m.room.member" &&
          event["content"]["membership"] == "invite") {
        invite_count++;

        // Must have all PDU fields
        REQUIRE(event.contains("hashes"));
        REQUIRE(event.contains("event_id"));
        REQUIRE(event.contains("signatures"));
        REQUIRE(event.contains("auth_events"));
        REQUIRE(event.contains("prev_events"));
        REQUIRE(event.contains("depth"));

        // state_key is the invited user
        auto state_key = event["state_key"].get<std::string>();
        REQUIRE((state_key == "@bob:localhost" ||
                 state_key == "@charlie:remote.com"));
      }
    }

    REQUIRE(invite_count == 2);
  }
}

TEST_CASE("Simulated send_join response contains valid state and auth_chain",
          "[send_join][response]") {
  write_test_config();
  const Config config{};
  json_utils::ensure_server_keys(config);
  const auto key_data = get_verify_key_data(config);

  const CreateRoomStateBuildData data{
      .createRoom_body = {.creation_content = std::nullopt,
                          .initial_state = std::nullopt,
                          .invite = std::nullopt,
                          .invite_3pid = std::nullopt,
                          .name = std::nullopt,
                          .power_level_content_override = std::nullopt,
                          .preset = std::nullopt,
                          .room_alias_name = std::nullopt,
                          .room_version = "11",
                          .topic = std::nullopt,
                          .visibility = std::nullopt,
                          .is_direct = std::nullopt},
      .room_id = "!simroom:localhost",
      .user_id = "@alice:localhost",
      .room_version = "11"};

  auto state_events = build_createRoom_state(data, "localhost");

  finalize_room_creation_events(state_events, "11",
                                config.matrix_config.server_name,
                                key_data.key_id, key_data.private_key);

  // Simulate what send_join returns: state (current state) + auth_chain
  // In a fresh room, auth_chain = all events, state = all state events

  SECTION("State contains m.room.create event") {
    bool found_create = false;
    for (const auto &event : state_events) {
      if (event["type"] == "m.room.create") {
        found_create = true;

        // This event must be parseable by remote servers
        REQUIRE(event.contains("hashes"));
        REQUIRE(event.contains("signatures"));
        REQUIRE(event.contains("event_id"));
        REQUIRE(event.contains("depth"));
        REQUIRE(event.contains("auth_events"));
        REQUIRE(event.contains("prev_events"));
      }
    }
    REQUIRE(found_create);
  }

  SECTION("State events can be used for state resolution") {
    // Verify that finalized events work with stateres_v2
    const std::vector<std::vector<StateEvent>> state_forks = {state_events};
    const auto resolved = stateres_v2(state_forks);

    // All state events should be in the resolved state
    REQUIRE(resolved.size() == state_events.size());

    for (const auto &event : state_events) {
      auto type = event["type"].get<std::string>();
      auto key = event["state_key"].get<std::string>();
      REQUIRE(resolved.contains(type));
      REQUIRE(resolved.at(type).contains(key));
    }
  }
}
