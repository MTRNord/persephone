
#include "nlohmann/json.hpp"
#include "utils/state_res.hpp"
#include <snitch/snitch.hpp>
#include <utils/errors.hpp>
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

    REQUIRE_THROWS_AS(event_id(event, "unknown"), MatrixRoomVersionError);
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