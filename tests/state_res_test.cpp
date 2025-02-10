
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

TEST_CASE("Matrix Protocol Room Version 11 Redaction", "[matrix_redaction]") {
  SECTION("Redact Event Based on v11 Rules") {
    auto event = R"(
      {
        "auth_events": [],
        "content": {
          "join_authorised_via_users_server": "@arbitrary:resident.example.com",
          "membership": "join"
        },
        "depth": 12,
        "hashes": {
          "sha256": "thishashcoversallfieldsincasethisisredacted"
        },
        "event_id": "$123535125:matrix.localhost",
        "origin": "example.com",
        "origin_server_ts": 1404838188000,
        "prev_events": [],
        "room_id": "!UcYsUzyxTGDxLBEvLy:example.org",
        "sender": "@alice:example.com",
        "signatures": {
          "example.com": {
            "ed25519:key_version": "these86bytesofbase64signaturecoveressentialfieldsincludinghashessocancheckredactedpdus"
          },
          "resident.example.com": {
            "ed25519:other_key_version": "a different signature"
          }
        },
        "state_key": "@alice:example.com",
        "type": "m.room.member",
        "unsigned": {
          "age": 4612
        }
      }
    )"_json;

    json redacted_event = redact(event, "11");

    // Verify the presence of specific keys that should be preserved
    REQUIRE(redacted_event.contains("event_id"));
    REQUIRE(redacted_event.contains("type"));
    REQUIRE(redacted_event.contains("room_id"));
    REQUIRE(redacted_event.contains("sender"));
    REQUIRE(redacted_event.contains("state_key"));
    REQUIRE(redacted_event.contains("hashes"));
    REQUIRE(redacted_event.contains("signatures"));
    REQUIRE(redacted_event.contains("depth"));
    REQUIRE(redacted_event.contains("prev_events"));
    REQUIRE(redacted_event.contains("auth_events"));
    REQUIRE(redacted_event.contains("origin_server_ts"));

    // Verify specific keys that should be redacted based on event type
    if (event["type"] == "m.room.member") {
      // Add assertions for redacting keys in 'content' based on 'm.room.member'
      REQUIRE(redacted_event.contains("content"));
      REQUIRE(redacted_event["content"].contains("membership"));
      REQUIRE(redacted_event["content"].contains(
          "join_authorised_via_users_server"));
      // Ensure other keys are redacted as specified for 'm.room.member'
    }
    // Add similar blocks for other event types as per your redaction rules

    // Add more test scenarios covering different event types and variations
    // Ensure keys are preserved or redacted correctly based on your v11
    // redaction rules
  }

  SECTION("Redact Updated Event Based on v11 Rules") {
    auto event = R"(
      {
        "auth_events": [
          {
            "type": "m.room.create",
            "content": {
              "creator": "@alice:example.com"
            },
            "state_key": "",
            "sender": "@alice:example.com",
            "origin_server_ts": 1609459200000,
            "event_id": "$creation_event_id",
            "room_id": "!myroomid:example.com",
            "unsigned": {
              "age": 100
            }
          }
        ],
        "content": {
          "membership": "join",
          "displayname": "Alice"
        },
        "depth": 12,
        "hashes": {
          "sha256": "thishashcoversallfieldsincasethisisredacted"
        },
        "event_id": "$123535125:matrix.localhost",
        "origin": "example.com",
        "origin_server_ts": 1609459200000,
        "prev_events": [
          {
            "type": "m.room.create",
            "content": {
              "creator": "@alice:example.com"
            },
            "state_key": "",
            "sender": "@alice:example.com",
            "origin_server_ts": 1609459200000,
            "event_id": "$creation_event_id",
            "room_id": "!myroomid:example.com",
            "unsigned": {
              "age": 100
            }
          }
        ],
        "room_id": "!UcYsUzyxTGDxLBEvLy:example.org",
        "sender": "@alice:example.com",
        "signatures": {
          "example.com": {
            "ed25519:key_version": "these86bytesofbase64signaturecoveressentialfieldsincludinghashessocancheckredactedpdus"
          },
          "resident.example.com": {
            "ed25519:other_key_version": "a different signature"
          }
        },
        "state_key": "@alice:example.com",
        "type": "m.room.member",
        "unsigned": {
          "age": 4612
        }
      }
    )"_json;

    json redacted_event = redact(event, "11");

    // Verify the presence of specific keys that should be preserved
    REQUIRE(redacted_event.contains("event_id"));
    REQUIRE(redacted_event.contains("type"));
    REQUIRE(redacted_event.contains("room_id"));
    REQUIRE(redacted_event.contains("sender"));
    REQUIRE(redacted_event.contains("state_key"));
    REQUIRE(redacted_event.contains("hashes"));
    REQUIRE(redacted_event.contains("signatures"));
    REQUIRE(redacted_event.contains("depth"));
    REQUIRE(redacted_event.contains("prev_events"));
    REQUIRE(redacted_event.contains("auth_events"));
    REQUIRE(redacted_event.contains("origin_server_ts"));

    // Verify specific keys that should be redacted based on event type
    if (event["type"] == "m.room.member") {
      // Add assertions for redacting keys in 'content' based on 'm.room.member'
      REQUIRE(redacted_event.contains("content"));
      REQUIRE(!redacted_event["content"].contains("displayname"));
      REQUIRE(redacted_event["content"].contains("membership"));
    }
  }
}

TEST_CASE("EventID", "[event_ids]") {
  SECTION("Test generating event_ids for a room_version 11 event") {
    const auto event = R"(
      {
        "auth_events": [],
        "content": {
          "join_authorised_via_users_server": "@arbitrary:resident.example.com",
          "membership": "join"
        },
        "depth": 12,
        "hashes": {
          "sha256": "thishashcoversallfieldsincasethisisredacted"
        },
        "origin": "example.com",
        "origin_server_ts": 1404838188000,
        "prev_events": [],
        "room_id": "!UcYsUzyxTGDxLBEvLy:example.org",
        "sender": "@alice:example.com",
        "state_key": "@alice:example.com",
        "type": "m.room.member",
        "unsigned": {
          "age": 4612
        }
      }
    )"_json;

    const json generated_event_id = event_id(event, "11");

    REQUIRE(generated_event_id ==
            "$9ofI-OZYoOSm7YdDRD0uv0UQ5zYsPJw59ffHmPX5jlU");
  }

  SECTION("Unsupported room_versions fail to generate an event_id") {
    auto event = R"(
      {
        "auth_events": [],
        "content": {
          "join_authorised_via_users_server": "@arbitrary:resident.example.com",
          "membership": "join"
        },
        "depth": 12,
        "hashes": {
          "sha256": "thishashcoversallfieldsincasethisisredacted"
        },
        "origin": "example.com",
        "origin_server_ts": 1404838188000,
        "prev_events": [],
        "room_id": "!UcYsUzyxTGDxLBEvLy:example.org",
        "sender": "@alice:example.com",
        "state_key": "@alice:example.com",
        "type": "m.room.member",
        "unsigned": {
          "age": 4612
        }
      }
    )"_json;

    REQUIRE_THROWS_MATCHES(event_id(event, "unknown"), MatrixRoomVersionError,
                           snitch::matchers::with_what_contains{
                               "Unsupported room version: unknown"});
  }

  SECTION("Different events of the same room_version will not produce the same "
          "event_id") {
    auto event_a = R"(
      {
        "auth_events": [],
        "content": {
          "join_authorised_via_users_server": "@arbitrary:resident.example.com",
          "membership": "join"
        },
        "depth": 12,
        "hashes": {
          "sha256": "thishashcoversallfieldsincasethisisredacted"
        },
        "origin": "example.com",
        "origin_server_ts": 1404838188000,
        "prev_events": [],
        "room_id": "!UcYsUzyxTGDxLBEvLy:example.org",
        "sender": "@alice:example.com",
        "state_key": "@alice:example.com",
        "type": "m.room.member",
        "unsigned": {
          "age": 4612
        }
      }
    )"_json;

    auto event_b = R"(
      {
        "auth_events": [],
        "content": {
          "join_authorised_via_users_server": "@another:resident.example.com",
          "membership": "join"
        },
        "depth": 12,
        "hashes": {
          "sha256": "thishashcoversallfieldsincasethisisredacted"
        },
        "origin": "example.com",
        "origin_server_ts": 1404838188000,
        "prev_events": [],
        "room_id": "!UcYsUzyxTGDxLBEvLy:example.org",
        "sender": "@alice:example.com",
        "state_key": "@alice:example.com",
        "type": "m.room.member",
        "unsigned": {
          "age": 4612
        }
      }
    )"_json;

    const json generated_event_id = event_id(event_a, "11");
    const json generated_event_id_b = event_id(event_b, "11");

    REQUIRE(generated_event_id != generated_event_id_b);
  }
}

TEST_CASE("Match Domain") {
  SECTION("Matching domains") {
    REQUIRE(matchDomain("@test:localhost", "@user:localhost"));
    REQUIRE(matchDomain("!test:localhost", "!room:localhost"));
    REQUIRE(matchDomain("#test:localhost", "#channel:localhost"));
  }

  SECTION("Non-matching domains") {
    REQUIRE_FALSE(matchDomain("@test:localhost", "@user:example.com"));
    REQUIRE_FALSE(matchDomain("!test:localhost", "!room:example.com"));
    REQUIRE_FALSE(matchDomain("#test:localhost", "#channel:example.com"));
  }

  SECTION("Different formats with matching domains") {
    REQUIRE(matchDomain("@test:localhost", "!room:localhost"));
    REQUIRE(matchDomain("!test:localhost", "#channel:localhost"));
    REQUIRE(matchDomain("#test:localhost", "@user:localhost"));
  }

  SECTION("Different formats with non-matching domains") {
    REQUIRE_FALSE(matchDomain("@test:localhost", "!room:example.com"));
    REQUIRE_FALSE(matchDomain("!test:localhost", "#channel:example.com"));
    REQUIRE_FALSE(matchDomain("#test:localhost", "@user:example.com"));
  }

  SECTION("Empty strings") {
    REQUIRE_FALSE(matchDomain("", ""));
    REQUIRE_FALSE(matchDomain("@test:localhost", ""));
    REQUIRE_FALSE(matchDomain("", "@user:localhost"));
  }
}

TEST_CASE("State res on room creation") {
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
rabbitmq:
  host: localhost
  port: 5672
  )";

  // Write file to disk for testing
  std::ofstream file("config.yaml");
  file << config_file;
  file.close();

  // Test loading the config
  const Config config{};

  // Generate basic room data
  const CreateRoomStateBuildData data{
      .createRoom_body = {.name = "Test Room",
                          .room_version = "11",
                          .topic = "Test Topic"},
      .room_id = "!test:localhost",
      .user_id = "@test:localhost",
      .room_version = "11"};

  auto room_state = build_createRoom_state(data);

  // Sign all the state events

  // Prepare loading the signing data
  const auto key_data = get_verify_key_data(config);

  find_auth_event_for_event_on_create(room_state, "11");
  for (auto &state_event : room_state) {
    state_event =
        json_utils::sign_json(config.matrix_config.server_name, key_data.key_id,
                              key_data.private_key, state_event);
  }

  // Convert the solved_state map to a `std::vector<std::vector<StateEvent>>`
  const std::vector<std::vector<StateEvent>> state_forks = {room_state};

  const std::map<EventType, std::map<StateKey, StateEvent>> state_res_result =
      stateres_v2(state_forks);

  // Ensure that it matches the expected state
  REQUIRE(state_res_result.size() == room_state.size());

  // Check we have all the expected state events with the correct content
  for (const auto &state_event : room_state) {
    const auto event_type = state_event["type"].get<std::string>();
    const auto state_key = state_event["state_key"].get<std::string>();

    REQUIRE(state_res_result.contains(event_type));
    REQUIRE(state_res_result.at(event_type).contains(state_key));

    const auto &state_event_result =
        state_res_result.at(event_type).at(state_key);

    REQUIRE(state_event_result["event_id"].get<std::string>() ==
            state_event["event_id"].get<std::string>());
    REQUIRE(state_event_result["type"].get<std::string>() ==
            state_event["type"].get<std::string>());
    REQUIRE(state_event_result["state_key"].get<std::string>() ==
            state_event["state_key"].get<std::string>());
    REQUIRE(state_event_result["content"] == state_event["content"]);
    REQUIRE(state_event_result["room_id"].get<std::string>() ==
            state_event["room_id"].get<std::string>());
    REQUIRE(state_event_result["sender"].get<std::string>() ==
            state_event["sender"].get<std::string>());
    REQUIRE(state_event_result["origin_server_ts"].get<std::time_t>() ==
            state_event["origin_server_ts"].get<std::time_t>());
    REQUIRE(state_event_result["signatures"] == state_event["signatures"]);
    REQUIRE(state_event_result["auth_events"] == state_event["auth_events"]);
    if (state_event.contains("unsigned")) {
      REQUIRE(state_event_result["unsigned"] == state_event["unsigned"]);
    }
  }
}