#include "webserver/json.hpp"
#include "webserver/sync_utils.hpp"

#include <snitch/snitch.hpp>
#include <string>
#include <vector>

using json = nlohmann::json;
using namespace client_server_json;
using sync_utils::generate_sync_token;
using sync_utils::parse_sync_token;

// ============================================================================
// Sync token tests
// ============================================================================

TEST_CASE("Sync token parsing", "[sync][token]") {
  SECTION("Parses valid token") {
    auto result = parse_sync_token("ps_42_1700000000000");
    REQUIRE(result.has_value());
    REQUIRE(result.value() == 42);
  }

  SECTION("Parses token with large event_nid") {
    auto result = parse_sync_token("ps_999999_1700000000000");
    REQUIRE(result.has_value());
    REQUIRE(result.value() == 999999);
  }

  SECTION("Parses token with zero event_nid") {
    auto result = parse_sync_token("ps_0_1700000000000");
    REQUIRE(result.has_value());
    REQUIRE(result.value() == 0);
  }

  SECTION("Rejects empty token") {
    auto result = parse_sync_token("");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Rejects token without ps_ prefix") {
    auto result = parse_sync_token("invalid_42_1700000000000");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Rejects token missing second underscore") {
    auto result = parse_sync_token("ps_42");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Rejects token with non-numeric event_nid") {
    auto result = parse_sync_token("ps_abc_1700000000000");
    REQUIRE_FALSE(result.has_value());
  }

  SECTION("Rejects completely garbage input") {
    auto result = parse_sync_token("garbage");
    REQUIRE_FALSE(result.has_value());
  }
}

TEST_CASE("Sync token generation", "[sync][token]") {
  SECTION("Generated token has correct prefix and event_nid") {
    auto token = generate_sync_token(123);
    REQUIRE(token.starts_with("ps_123_"));
  }

  SECTION("Generated token round-trips through parser") {
    auto token = generate_sync_token(42);
    auto parsed = parse_sync_token(token);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed.value() == 42);
  }

  SECTION("Round-trip with zero") {
    auto token = generate_sync_token(0);
    auto parsed = parse_sync_token(token);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed.value() == 0);
  }

  SECTION("Round-trip with large value") {
    auto token = generate_sync_token(2147483647);
    auto parsed = parse_sync_token(token);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed.value() == 2147483647);
  }
}

// ============================================================================
// Sync response JSON serialization tests
// ============================================================================

TEST_CASE("SyncTimeline serialization", "[sync][json]") {
  SECTION("Serializes empty timeline") {
    SyncTimeline timeline;
    json j = timeline;

    REQUIRE(j["events"].is_array());
    REQUIRE(j["events"].empty());
    REQUIRE(j["limited"] == false);
    REQUIRE_FALSE(j.contains("prev_batch"));
  }

  SECTION("Serializes timeline with events") {
    SyncTimeline timeline;
    timeline.events = {json{{"type", "m.room.message"}}};
    timeline.limited = true;
    timeline.prev_batch = "ps_10_1700000000000";

    json j = timeline;

    REQUIRE(j["events"].size() == 1);
    REQUIRE(j["events"][0]["type"] == "m.room.message");
    REQUIRE(j["limited"] == true);
    REQUIRE(j["prev_batch"] == "ps_10_1700000000000");
  }

  SECTION("Round-trips through JSON") {
    SyncTimeline original;
    original.events = {json{{"type", "m.room.message"},
                            {"content", {{"body", "hello"}}}}};
    original.limited = true;
    original.prev_batch = "ps_5_123";

    json j = original;
    auto deserialized = j.get<SyncTimeline>();

    REQUIRE(deserialized.events.size() == 1);
    REQUIRE(deserialized.limited == true);
    REQUIRE(deserialized.prev_batch == "ps_5_123");
  }
}

TEST_CASE("SyncRoomState serialization", "[sync][json]") {
  SECTION("Serializes empty state") {
    SyncRoomState state;
    json j = state;

    REQUIRE(j["events"].is_array());
    REQUIRE(j["events"].empty());
  }

  SECTION("Serializes state with events") {
    SyncRoomState state;
    state.events = {json{{"type", "m.room.name"},
                         {"state_key", ""},
                         {"content", {{"name", "Test Room"}}}}};

    json j = state;

    REQUIRE(j["events"].size() == 1);
    REQUIRE(j["events"][0]["type"] == "m.room.name");
  }
}

TEST_CASE("SyncJoinedRoom serialization", "[sync][json]") {
  SECTION("Serializes minimal joined room") {
    SyncJoinedRoom joined;
    json j = joined;

    REQUIRE(j.contains("timeline"));
    REQUIRE(j.contains("state"));
    REQUIRE(j.contains("account_data"));
    REQUIRE(j.contains("ephemeral"));
    REQUIRE(j.contains("unread_notifications"));
    REQUIRE_FALSE(j.contains("summary"));
  }

  SECTION("Serializes joined room with summary") {
    SyncJoinedRoom joined;
    RoomSummary summary;
    summary.m_joined_member_count = 5;
    summary.m_invited_member_count = 2;
    summary.m_heroes = std::vector<std::string>{"@alice:example.com"};
    joined.summary = summary;

    json j = joined;

    REQUIRE(j.contains("summary"));
    REQUIRE(j["summary"]["m.joined_member_count"] == 5);
    REQUIRE(j["summary"]["m.invited_member_count"] == 2);
    REQUIRE(j["summary"]["m.heroes"].size() == 1);
  }
}

TEST_CASE("SyncInvitedRoom serialization", "[sync][json]") {
  SECTION("Serializes invited room with stripped state") {
    SyncInvitedRoom invited;
    invited.invite_state.events = {
        json{{"type", "m.room.name"},
             {"state_key", ""},
             {"content", {{"name", "Invite Room"}}},
             {"sender", "@inviter:example.com"}}};

    json j = invited;

    REQUIRE(j.contains("invite_state"));
    REQUIRE(j["invite_state"]["events"].size() == 1);
    REQUIRE(j["invite_state"]["events"][0]["type"] == "m.room.name");
  }
}

TEST_CASE("SyncLeftRoom serialization", "[sync][json]") {
  SECTION("Serializes left room") {
    SyncLeftRoom left;
    left.timeline.events = {json{{"type", "m.room.member"},
                                 {"content", {{"membership", "leave"}}}}};

    json j = left;

    REQUIRE(j.contains("timeline"));
    REQUIRE(j.contains("state"));
    REQUIRE(j.contains("account_data"));
    REQUIRE(j["timeline"]["events"].size() == 1);
  }
}

TEST_CASE("SyncRooms serialization", "[sync][json]") {
  SECTION("Serializes empty rooms") {
    SyncRooms rooms;
    json j = rooms;

    REQUIRE(j["join"].is_object());
    REQUIRE(j["join"].empty());
    REQUIRE(j["invite"].is_object());
    REQUIRE(j["invite"].empty());
    REQUIRE(j["leave"].is_object());
    REQUIRE(j["leave"].empty());
  }

  SECTION("Serializes rooms with entries") {
    SyncRooms rooms;

    SyncJoinedRoom joined;
    joined.timeline.events = {json{{"type", "m.room.message"}}};
    rooms.join["!room1:example.com"] = joined;

    SyncInvitedRoom invited;
    rooms.invite["!room2:example.com"] = invited;

    SyncLeftRoom left;
    rooms.leave["!room3:example.com"] = left;

    json j = rooms;

    REQUIRE(j["join"].size() == 1);
    REQUIRE(j["join"].contains("!room1:example.com"));
    REQUIRE(j["invite"].size() == 1);
    REQUIRE(j["invite"].contains("!room2:example.com"));
    REQUIRE(j["leave"].size() == 1);
    REQUIRE(j["leave"].contains("!room3:example.com"));
  }
}

TEST_CASE("DeviceLists serialization", "[sync][json]") {
  SECTION("Serializes empty device lists") {
    DeviceLists dl;
    json j = dl;

    REQUIRE(j["changed"].is_array());
    REQUIRE(j["changed"].empty());
    REQUIRE(j["left"].is_array());
    REQUIRE(j["left"].empty());
  }

  SECTION("Serializes device lists with entries") {
    DeviceLists dl;
    dl.changed = {"@alice:example.com", "@bob:example.com"};
    dl.left = {"@charlie:example.com"};

    json j = dl;

    REQUIRE(j["changed"].size() == 2);
    REQUIRE(j["left"].size() == 1);
  }
}

TEST_CASE("UnreadNotificationCounts serialization", "[sync][json]") {
  SECTION("Default values are zero") {
    UnreadNotificationCounts counts;
    json j = counts;

    REQUIRE(j["highlight_count"] == 0);
    REQUIRE(j["notification_count"] == 0);
  }

  SECTION("Serializes non-zero counts") {
    UnreadNotificationCounts counts;
    counts.highlight_count = 3;
    counts.notification_count = 10;

    json j = counts;

    REQUIRE(j["highlight_count"] == 3);
    REQUIRE(j["notification_count"] == 10);
  }
}

TEST_CASE("RoomSummary serialization", "[sync][json]") {
  SECTION("Serializes empty summary (all optional)") {
    RoomSummary summary;
    json j = summary;

    REQUIRE_FALSE(j.contains("m.heroes"));
    REQUIRE_FALSE(j.contains("m.joined_member_count"));
    REQUIRE_FALSE(j.contains("m.invited_member_count"));
  }

  SECTION("Serializes partial summary") {
    RoomSummary summary;
    summary.m_joined_member_count = 42;

    json j = summary;

    REQUIRE_FALSE(j.contains("m.heroes"));
    REQUIRE(j["m.joined_member_count"] == 42);
    REQUIRE_FALSE(j.contains("m.invited_member_count"));
  }

  SECTION("Round-trips through JSON") {
    RoomSummary original;
    original.m_heroes =
        std::vector<std::string>{"@alice:example.com", "@bob:example.com"};
    original.m_joined_member_count = 5;
    original.m_invited_member_count = 1;

    json j = original;
    auto deserialized = j.get<RoomSummary>();

    REQUIRE(deserialized.m_heroes.has_value());
    REQUIRE(deserialized.m_heroes->size() == 2);
    REQUIRE(deserialized.m_joined_member_count == 5);
    REQUIRE(deserialized.m_invited_member_count == 1);
  }
}

TEST_CASE("Full SyncResponse serialization", "[sync][json]") {
  SECTION("Serializes empty sync response") {
    SyncResponse response;
    response.next_batch = "ps_0_1700000000000";

    json j = response;

    REQUIRE(j["next_batch"] == "ps_0_1700000000000");
    REQUIRE(j["rooms"]["join"].empty());
    REQUIRE(j["rooms"]["invite"].empty());
    REQUIRE(j["rooms"]["leave"].empty());
    REQUIRE(j["account_data"]["events"].empty());
    REQUIRE(j["device_lists"]["changed"].empty());
    REQUIRE(j["device_lists"]["left"].empty());
    REQUIRE(j["device_one_time_keys_count"].is_object());
    REQUIRE(j["device_unused_fallback_key_types"].is_array());
  }

  SECTION("Serializes sync response with joined room") {
    SyncResponse response;
    response.next_batch = "ps_100_1700000000000";

    SyncJoinedRoom joined;
    joined.state.events = {json{{"type", "m.room.create"},
                                {"state_key", ""},
                                {"content", {{"creator", "@user:test.com"}}}}};
    joined.timeline.events = {
        json{{"type", "m.room.message"},
             {"content", {{"body", "Hello!"}, {"msgtype", "m.text"}}}}};
    joined.timeline.limited = false;
    response.rooms.join["!abc:test.com"] = joined;

    json j = response;

    REQUIRE(j["next_batch"] == "ps_100_1700000000000");
    REQUIRE(j["rooms"]["join"].contains("!abc:test.com"));

    const auto &room = j["rooms"]["join"]["!abc:test.com"];
    REQUIRE(room["state"]["events"].size() == 1);
    REQUIRE(room["timeline"]["events"].size() == 1);
    REQUIRE(room["timeline"]["limited"] == false);
  }

  SECTION("Round-trips through JSON") {
    SyncResponse original;
    original.next_batch = "ps_50_1700000000000";

    SyncJoinedRoom joined;
    joined.timeline.events = {json{{"type", "m.room.message"}}};
    joined.timeline.limited = true;
    joined.timeline.prev_batch = "ps_30_1700000000000";
    original.rooms.join["!room:test.com"] = joined;

    SyncInvitedRoom invited;
    invited.invite_state.events = {json{{"type", "m.room.name"}}};
    original.rooms.invite["!inv:test.com"] = invited;

    json j = original;
    auto deserialized = j.get<SyncResponse>();

    REQUIRE(deserialized.next_batch == "ps_50_1700000000000");
    REQUIRE(deserialized.rooms.join.size() == 1);
    REQUIRE(deserialized.rooms.join.contains("!room:test.com"));
    REQUIRE(deserialized.rooms.join["!room:test.com"].timeline.limited == true);
    REQUIRE(deserialized.rooms.join["!room:test.com"].timeline.prev_batch ==
            "ps_30_1700000000000");
    REQUIRE(deserialized.rooms.invite.size() == 1);
    REQUIRE(deserialized.rooms.invite.contains("!inv:test.com"));
  }

  SECTION("Has required top-level keys per Matrix spec") {
    SyncResponse response;
    response.next_batch = "ps_1_0";

    json j = response;

    // Required by spec
    REQUIRE(j.contains("next_batch"));
    REQUIRE(j.contains("rooms"));
    REQUIRE(j.contains("account_data"));

    // Rooms must contain join/invite/leave
    REQUIRE(j["rooms"].contains("join"));
    REQUIRE(j["rooms"].contains("invite"));
    REQUIRE(j["rooms"].contains("leave"));
  }
}
