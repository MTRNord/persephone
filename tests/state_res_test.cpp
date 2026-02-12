
#include "nlohmann/json.hpp"
#include "snitch/snitch_matcher.hpp"
#include "utils/state_res.hpp"

#include <array>
#include <chrono>
#include <format>
#include <fstream>
#include <snitch/snitch.hpp>
#include <sodium/crypto_sign.h>
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
            "$P_kn3vgLwKkBMkNtD5snHOQhuCoQTv2K6wSiRtnqXVA");
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

  SECTION("Missing colon in strings") {
    REQUIRE_FALSE(matchDomain("testlocalhost", "@user:localhost"));
    REQUIRE_FALSE(matchDomain("@test:localhost", "userlocalhost"));
    REQUIRE_FALSE(matchDomain("nocolon", "alsonocolon"));
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
  )";

  // Write file to disk for testing
  std::ofstream file("config.yaml");
  file << config_file;
  file.close();

  // Test loading the config
  const Config config{};

  // Generate basic room data
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
      .room_id = "!test:localhost",
      .user_id = "@test:localhost",
      .room_version = "11"};

  auto room_state = build_createRoom_state(data, "localhost");

  // ensure the key exists
  json_utils::ensure_server_keys(config);

  // Finalize all state events (sets auth_events, prev_events, depth,
  // computes content hash, event_id, signs each event)
  const auto key_data = get_verify_key_data(config);

  finalize_room_creation_events(room_state, "11",
                                config.matrix_config.server_name,
                                key_data.key_id, key_data.private_key);

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

// ============================================================================
// reference_hash tests
// ============================================================================

TEST_CASE("reference_hash", "[reference_hash]") {
  SECTION("Produces consistent hash for same event") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:example.com",
      "sender": "@alice:example.com",
      "state_key": "@alice:example.com",
      "type": "m.room.member"
    })"_json;

    auto hash1 = reference_hash(event, "11");
    auto hash2 = reference_hash(event, "11");

    REQUIRE(hash1 == hash2);
    REQUIRE_FALSE(hash1.empty());
  }

  SECTION("Different events produce different hashes") {
    auto event_a = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:example.com",
      "sender": "@alice:example.com",
      "state_key": "@alice:example.com",
      "type": "m.room.member"
    })"_json;

    auto event_b = R"({
      "auth_events": [],
      "content": {"membership": "leave"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:example.com",
      "sender": "@alice:example.com",
      "state_key": "@alice:example.com",
      "type": "m.room.member"
    })"_json;

    auto hash_a = reference_hash(event_a, "11");
    auto hash_b = reference_hash(event_b, "11");

    REQUIRE(hash_a != hash_b);
  }

  SECTION("Ignores signatures and unsigned for hash") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:example.com",
      "sender": "@alice:example.com",
      "state_key": "@alice:example.com",
      "type": "m.room.member"
    })"_json;

    auto event_with_sig = event;
    event_with_sig["signatures"] = {{"example.com", {{"ed25519:key", "sig"}}}};
    event_with_sig["unsigned"] = {{"age", 1234}};

    auto hash_without = reference_hash(event, "11");
    auto hash_with = reference_hash(event_with_sig, "11");

    REQUIRE(hash_without == hash_with);
  }
}

// ============================================================================
// Redaction tests for more event types
// ============================================================================

TEST_CASE("Redact m.room.create event", "[matrix_redaction]") {
  auto event = R"({
    "auth_events": [],
    "content": {
      "creator": "@alice:example.com",
      "room_version": "11",
      "custom_field": "should_be_preserved"
    },
    "depth": 1,
    "event_id": "$create1",
    "hashes": {"sha256": "hash"},
    "origin_server_ts": 1000,
    "prev_events": [],
    "room_id": "!room:example.com",
    "sender": "@alice:example.com",
    "signatures": {"example.com": {"ed25519:key": "sig"}},
    "state_key": "",
    "type": "m.room.create"
  })"_json;

  auto redacted = redact(event, "11");

  // m.room.create preserves ALL content keys
  REQUIRE(redacted["content"].contains("creator"));
  REQUIRE(redacted["content"].contains("room_version"));
  REQUIRE(redacted["content"].contains("custom_field"));
  // "origin" top-level key should be removed
  REQUIRE_FALSE(redacted.contains("origin"));
}

TEST_CASE("Redact m.room.join_rules event", "[matrix_redaction]") {
  auto event = R"({
    "auth_events": [],
    "content": {
      "join_rule": "public",
      "allow": [{"type": "m.room_membership", "room_id": "!other:example.com"}],
      "extra_field": "should_be_removed"
    },
    "depth": 2,
    "event_id": "$jr1",
    "hashes": {"sha256": "hash"},
    "origin_server_ts": 1000,
    "prev_events": [],
    "room_id": "!room:example.com",
    "sender": "@alice:example.com",
    "signatures": {"example.com": {"ed25519:key": "sig"}},
    "state_key": "",
    "type": "m.room.join_rules"
  })"_json;

  auto redacted = redact(event, "11");

  REQUIRE(redacted["content"].contains("join_rule"));
  REQUIRE(redacted["content"].contains("allow"));
  REQUIRE_FALSE(redacted["content"].contains("extra_field"));
}

TEST_CASE("Redact m.room.power_levels event", "[matrix_redaction]") {
  auto event = R"({
    "auth_events": [],
    "content": {
      "ban": 50,
      "events": {"m.room.name": 50},
      "events_default": 0,
      "invite": 0,
      "kick": 50,
      "redact": 50,
      "state_default": 50,
      "users": {"@alice:example.com": 100},
      "users_default": 0,
      "notifications": {"room": 50},
      "custom_field": "should_be_removed"
    },
    "depth": 3,
    "event_id": "$pl1",
    "hashes": {"sha256": "hash"},
    "origin_server_ts": 1000,
    "prev_events": [],
    "room_id": "!room:example.com",
    "sender": "@alice:example.com",
    "signatures": {"example.com": {"ed25519:key": "sig"}},
    "state_key": "",
    "type": "m.room.power_levels"
  })"_json;

  auto redacted = redact(event, "11");

  REQUIRE(redacted["content"].contains("ban"));
  REQUIRE(redacted["content"].contains("events"));
  REQUIRE(redacted["content"].contains("events_default"));
  REQUIRE(redacted["content"].contains("invite"));
  REQUIRE(redacted["content"].contains("kick"));
  REQUIRE(redacted["content"].contains("redact"));
  REQUIRE(redacted["content"].contains("state_default"));
  REQUIRE(redacted["content"].contains("users"));
  REQUIRE(redacted["content"].contains("users_default"));
  REQUIRE_FALSE(redacted["content"].contains("notifications"));
  REQUIRE_FALSE(redacted["content"].contains("custom_field"));
}

TEST_CASE("Redact m.room.history_visibility event", "[matrix_redaction]") {
  auto event = R"({
    "auth_events": [],
    "content": {
      "history_visibility": "shared",
      "extra": "should_be_removed"
    },
    "depth": 4,
    "event_id": "$hv1",
    "hashes": {"sha256": "hash"},
    "origin_server_ts": 1000,
    "prev_events": [],
    "room_id": "!room:example.com",
    "sender": "@alice:example.com",
    "signatures": {"example.com": {"ed25519:key": "sig"}},
    "state_key": "",
    "type": "m.room.history_visibility"
  })"_json;

  auto redacted = redact(event, "11");

  REQUIRE(redacted["content"].contains("history_visibility"));
  REQUIRE_FALSE(redacted["content"].contains("extra"));
}

TEST_CASE("Redact m.room.redaction event", "[matrix_redaction]") {
  auto event = R"({
    "auth_events": [],
    "content": {
      "redacts": "$some_event_id",
      "reason": "should_be_removed"
    },
    "depth": 5,
    "event_id": "$red1",
    "hashes": {"sha256": "hash"},
    "origin_server_ts": 1000,
    "prev_events": [],
    "room_id": "!room:example.com",
    "sender": "@alice:example.com",
    "signatures": {"example.com": {"ed25519:key": "sig"}},
    "state_key": "",
    "type": "m.room.redaction"
  })"_json;

  auto redacted = redact(event, "11");

  REQUIRE(redacted["content"].contains("redacts"));
  REQUIRE_FALSE(redacted["content"].contains("reason"));
}

TEST_CASE("Redact unknown event type", "[matrix_redaction]") {
  auto event = R"({
    "auth_events": [],
    "content": {
      "body": "hello",
      "msgtype": "m.text"
    },
    "depth": 6,
    "event_id": "$msg1",
    "hashes": {"sha256": "hash"},
    "origin_server_ts": 1000,
    "prev_events": [],
    "room_id": "!room:example.com",
    "sender": "@alice:example.com",
    "signatures": {"example.com": {"ed25519:key": "sig"}},
    "type": "m.room.message"
  })"_json;

  auto redacted = redact(event, "11");

  // Unknown event type: content should be empty
  REQUIRE(redacted["content"].empty());
  // Core fields preserved
  REQUIRE(redacted.contains("event_id"));
  REQUIRE(redacted.contains("type"));
  REQUIRE(redacted.contains("room_id"));
  REQUIRE(redacted.contains("sender"));
}

// ============================================================================
// findAuthDifference tests
// ============================================================================

TEST_CASE("findAuthDifference", "[state_res]") {
  SECTION("Events present in all forks produce empty difference") {
    json event_a = {
        {"type", "m.room.create"}, {"state_key", ""}, {"event_id", "$a"}};
    json event_b = {{"type", "m.room.member"},
                    {"state_key", "@alice:example.com"},
                    {"event_id", "$b"}};

    std::vector<StateEvent> conflicted = {event_a, event_b};
    std::vector<std::vector<StateEvent>> forks = {{event_a, event_b},
                                                  {event_a, event_b}};

    auto diff = findAuthDifference(conflicted, forks);
    REQUIRE(diff.empty());
  }

  SECTION("Events missing from some forks appear in difference") {
    json event_a = {
        {"type", "m.room.create"}, {"state_key", ""}, {"event_id", "$a"}};
    json event_b = {{"type", "m.room.member"},
                    {"state_key", "@alice:example.com"},
                    {"event_id", "$b"}};

    std::vector<StateEvent> conflicted = {event_a, event_b};
    // Fork 2 is missing event_b
    std::vector<std::vector<StateEvent>> forks = {{event_a, event_b},
                                                  {event_a}};

    auto diff = findAuthDifference(conflicted, forks);
    REQUIRE(diff.size() == 1);
    REQUIRE(diff[0]["event_id"] == "$b");
  }
}

// ============================================================================
// content_hash tests
// ============================================================================

TEST_CASE("content_hash", "[content_hash]") {
  SECTION("Produces consistent hash for same event") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:example.com",
      "sender": "@alice:example.com",
      "state_key": "@alice:example.com",
      "type": "m.room.member"
    })"_json;

    auto hash1 = content_hash(event, "11");
    auto hash2 = content_hash(event, "11");

    REQUIRE(hash1 == hash2);
    REQUIRE_FALSE(hash1.empty());
  }

  SECTION("Strips unsigned, signatures, and hashes before hashing") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:example.com",
      "sender": "@alice:example.com",
      "state_key": "@alice:example.com",
      "type": "m.room.member"
    })"_json;

    auto event_with_extras = event;
    event_with_extras["unsigned"] = {{"age", 1234}};
    event_with_extras["signatures"] = {
        {"example.com", {{"ed25519:key", "sig"}}}};
    event_with_extras["hashes"] = {{"sha256", "oldhash"}};

    auto hash_clean = content_hash(event, "11");
    auto hash_extras = content_hash(event_with_extras, "11");

    REQUIRE(hash_clean == hash_extras);
  }

  SECTION("Different events produce different hashes") {
    auto event_a = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:example.com",
      "sender": "@alice:example.com",
      "state_key": "@alice:example.com",
      "type": "m.room.member"
    })"_json;

    auto event_b = R"({
      "auth_events": [],
      "content": {"membership": "leave"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:example.com",
      "sender": "@alice:example.com",
      "state_key": "@alice:example.com",
      "type": "m.room.member"
    })"_json;

    REQUIRE(content_hash(event_a, "11") != content_hash(event_b, "11"));
  }

  SECTION("Unsupported room version throws") {
    auto event = R"({"type": "m.room.create"})"_json;
    REQUIRE_THROWS_AS(content_hash(event, "unknown"), MatrixRoomVersionError);
  }

  SECTION("Null event throws") {
    REQUIRE_THROWS_AS(content_hash(json(nullptr), "11"), std::invalid_argument);
  }
}

// ============================================================================
// finalize_event tests
// ============================================================================

TEST_CASE("finalize_event", "[finalize_event]") {
  // Load signing keys from config
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

  const Config config{};
  json_utils::ensure_server_keys(config);
  const auto key_data = get_verify_key_data(config);

  SECTION("Produces a complete PDU with all required fields") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:localhost",
      "sender": "@alice:localhost",
      "state_key": "@alice:localhost",
      "type": "m.room.member"
    })"_json;

    auto finalized =
        finalize_event(event, "11", config.matrix_config.server_name,
                       key_data.key_id, key_data.private_key);

    // Must have hashes.sha256
    REQUIRE(finalized.contains("hashes"));
    REQUIRE(finalized["hashes"].contains("sha256"));
    REQUIRE_FALSE(finalized["hashes"]["sha256"].get<std::string>().empty());

    // Must have event_id starting with $
    REQUIRE(finalized.contains("event_id"));
    REQUIRE(finalized["event_id"].get<std::string>().starts_with("$"));

    // Must have signatures for our server
    REQUIRE(finalized.contains("signatures"));
    REQUIRE(finalized["signatures"].contains("localhost"));

    // Original fields preserved
    REQUIRE(finalized["type"] == "m.room.member");
    REQUIRE(finalized["content"]["membership"] == "join");
    REQUIRE(finalized["depth"] == 1);
  }

  SECTION("event_id is deterministic") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:localhost",
      "sender": "@alice:localhost",
      "state_key": "@alice:localhost",
      "type": "m.room.member"
    })"_json;

    auto finalized1 =
        finalize_event(event, "11", config.matrix_config.server_name,
                       key_data.key_id, key_data.private_key);
    auto finalized2 =
        finalize_event(event, "11", config.matrix_config.server_name,
                       key_data.key_id, key_data.private_key);

    REQUIRE(finalized1["event_id"] == finalized2["event_id"]);
    REQUIRE(finalized1["hashes"]["sha256"] == finalized2["hashes"]["sha256"]);
  }

  SECTION("event_id computed after hashes and signing") {
    // finalize_event order: content_hash -> sign_event -> event_id
    // Verify event_id is independent of signatures (reference_hash strips them)
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:localhost",
      "sender": "@alice:localhost",
      "state_key": "@alice:localhost",
      "type": "m.room.member"
    })"_json;

    auto finalized =
        finalize_event(event, "11", config.matrix_config.server_name,
                       key_data.key_id, key_data.private_key);

    // Manually compute: set hashes first, then compute event_id
    // (without signing -- event_id should still match since reference_hash
    // strips signatures)
    auto manual = event;
    manual["hashes"] = json::object({{"sha256", content_hash(manual, "11")}});
    auto manual_event_id = event_id(manual, "11");

    REQUIRE(finalized["event_id"] == manual_event_id);

    // Also verify the finalized event has signatures (was signed before event_id)
    REQUIRE(finalized.contains("signatures"));
    REQUIRE(finalized["signatures"].contains("localhost"));
  }
}

// ============================================================================
// finalize_room_creation_events tests
// ============================================================================

TEST_CASE("finalize_room_creation_events", "[finalize_room_creation_events]") {
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
      .room_id = "!test:localhost",
      .user_id = "@test:localhost",
      .room_version = "11"};

  auto events = build_createRoom_state(data, "localhost");

  finalize_room_creation_events(events, "11", config.matrix_config.server_name,
                                key_data.key_id, key_data.private_key);

  SECTION("m.room.create has correct structure") {
    const auto &create = events[0];

    REQUIRE(create["type"] == "m.room.create");
    REQUIRE(create["auth_events"] == json::array());
    REQUIRE(create["prev_events"] == json::array());
    REQUIRE(create["depth"] == 1);
    REQUIRE(create.contains("hashes"));
    REQUIRE(create["hashes"].contains("sha256"));
    REQUIRE(create.contains("event_id"));
    REQUIRE(create.contains("signatures"));
    REQUIRE(create["signatures"].contains("localhost"));
  }

  SECTION("Subsequent events reference previous event") {
    // m.room.member (index 1) should reference m.room.create (index 0)
    const auto &create = events[0];
    const auto &member = events[1];

    REQUIRE(member["prev_events"].size() == 1);
    REQUIRE(member["prev_events"][0] == create["event_id"]);
    REQUIRE(member["depth"] == 2);
  }

  SECTION("Depth increments for each event") {
    for (size_t i = 0; i < events.size(); ++i) {
      REQUIRE(events[i]["depth"] == static_cast<int64_t>(i + 1));
    }
  }

  SECTION("All events have required PDU fields") {
    for (const auto &event : events) {
      REQUIRE(event.contains("auth_events"));
      REQUIRE(event.contains("prev_events"));
      REQUIRE(event.contains("depth"));
      REQUIRE(event.contains("hashes"));
      REQUIRE(event["hashes"].contains("sha256"));
      REQUIRE(event.contains("event_id"));
      REQUIRE(event.contains("signatures"));
      REQUIRE(event.contains("type"));
      REQUIRE(event.contains("content"));
      REQUIRE(event.contains("sender"));
      REQUIRE(event.contains("room_id"));
      REQUIRE(event.contains("origin_server_ts"));
    }
  }

  SECTION("Auth events are correctly populated") {
    const auto &create = events[0];
    const auto &member = events[1];
    const auto &power_levels = events[2];

    // m.room.create has no auth events
    REQUIRE(create["auth_events"].empty());

    // m.room.member should have m.room.create in auth_events
    auto member_auth = member["auth_events"].get<std::vector<std::string>>();
    REQUIRE(std::find(member_auth.begin(), member_auth.end(),
                      create["event_id"].get<std::string>()) !=
            member_auth.end());

    // m.room.power_levels should have m.room.create and m.room.member
    auto pl_auth = power_levels["auth_events"].get<std::vector<std::string>>();
    REQUIRE(std::find(pl_auth.begin(), pl_auth.end(),
                      create["event_id"].get<std::string>()) != pl_auth.end());
    REQUIRE(std::find(pl_auth.begin(), pl_auth.end(),
                      member["event_id"].get<std::string>()) != pl_auth.end());
  }

  SECTION("Event IDs are verifiable by recomputing reference hash") {
    for (const auto &event : events) {
      auto recomputed_id = event_id(event, "11");
      REQUIRE(recomputed_id == event["event_id"].get<std::string>());
    }
  }
}

// ============================================================================
// sign_event tests
// ============================================================================

TEST_CASE("sign_event", "[sign_event]") {
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

  const Config config{};
  json_utils::ensure_server_keys(config);
  const auto key_data = get_verify_key_data(config);

  SECTION("Produces a signed event with valid signature") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:localhost",
      "sender": "@alice:localhost",
      "state_key": "@alice:localhost",
      "type": "m.room.member"
    })"_json;

    auto signed_ev = sign_event(event, "11", config.matrix_config.server_name,
                                key_data.key_id, key_data.private_key);

    // Must have signatures
    REQUIRE(signed_ev.contains("signatures"));
    REQUIRE(signed_ev["signatures"].contains("localhost"));

    // Original fields preserved
    REQUIRE(signed_ev["type"] == "m.room.member");
    REQUIRE(signed_ev["content"]["membership"] == "join");
  }

  SECTION("Signature is verifiable after redaction") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "hashes": {"sha256": "test_hash"},
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:localhost",
      "sender": "@alice:localhost",
      "state_key": "@alice:localhost",
      "type": "m.room.member"
    })"_json;

    auto signed_ev = sign_event(event, "11", config.matrix_config.server_name,
                                key_data.key_id, key_data.private_key);

    // Extract the signature
    auto sig_key =
        std::format("ed25519:{}", key_data.key_id);
    auto signature_b64 =
        signed_ev["signatures"]["localhost"][sig_key].get<std::string>();

    // To verify: redact, remove signatures + unsigned, canonical JSON
    auto redacted = redact(signed_ev, "11");
    redacted.erase("signatures");
    redacted.erase("unsigned");
    auto canonical = redacted.dump();

    // Get public key from the private key
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pub_key{};
    crypto_sign_ed25519_sk_to_pk(pub_key.data(), key_data.private_key.data());
    auto pub_key_b64 = json_utils::base64_std_unpadded(
        std::vector<unsigned char>(pub_key.begin(), pub_key.end()));

    REQUIRE(json_utils::verify_signature(pub_key_b64, signature_b64, canonical));
  }

  SECTION("Non-preserved fields do not affect signature") {
    // An event with an extra non-preserved field (like "origin")
    // should produce the same signature as without it, because
    // sign_event redacts before signing
    auto event_base = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:localhost",
      "sender": "@alice:localhost",
      "state_key": "@alice:localhost",
      "type": "m.room.member"
    })"_json;

    auto event_with_origin = event_base;
    event_with_origin["origin"] = "localhost";

    auto signed_base =
        sign_event(event_base, "11", config.matrix_config.server_name,
                   key_data.key_id, key_data.private_key);
    auto signed_origin =
        sign_event(event_with_origin, "11", config.matrix_config.server_name,
                   key_data.key_id, key_data.private_key);

    // Both should produce the same signature (redaction strips "origin")
    auto sig_key = std::format("ed25519:{}", key_data.key_id);
    REQUIRE(signed_base["signatures"]["localhost"][sig_key] ==
            signed_origin["signatures"]["localhost"][sig_key]);
  }

  SECTION("event_id is not included in signed content") {
    auto event = R"({
      "auth_events": [],
      "content": {"membership": "join"},
      "depth": 1,
      "event_id": "$fake_event_id",
      "origin_server_ts": 1000,
      "prev_events": [],
      "room_id": "!room:localhost",
      "sender": "@alice:localhost",
      "state_key": "@alice:localhost",
      "type": "m.room.member"
    })"_json;

    auto event_no_id = event;
    event_no_id.erase("event_id");

    auto signed_with_id =
        sign_event(event, "11", config.matrix_config.server_name,
                   key_data.key_id, key_data.private_key);
    auto signed_without_id =
        sign_event(event_no_id, "11", config.matrix_config.server_name,
                   key_data.key_id, key_data.private_key);

    // Signatures should be identical because redaction strips event_id
    auto sig_key = std::format("ed25519:{}", key_data.key_id);
    REQUIRE(signed_with_id["signatures"]["localhost"][sig_key] ==
            signed_without_id["signatures"]["localhost"][sig_key]);
  }

  SECTION("Rejects null event") {
    auto null_event = json{};
    REQUIRE_THROWS_AS(
        sign_event(null_event, "11", config.matrix_config.server_name,
                   key_data.key_id, key_data.private_key),
        std::invalid_argument);
  }
}
