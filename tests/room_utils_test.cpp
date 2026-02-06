#include "utils/room_utils.hpp"
#include <set>
#include <snitch/snitch.hpp>
#include <string_view>
#include <vector>

using json = nlohmann::json;
using namespace std::string_view_literals;

TEST_CASE("calculate_assumed_createRoom_state_event_count",
          "[room_utils]") {
  SECTION("Minimal room (no optional fields)") {
    // 1 create + 1 member + 1 power_levels + 3 preset = 6
    auto count =
        calculate_assumed_createRoom_state_event_count(false, false, false,
                                                       std::nullopt,
                                                       std::nullopt,
                                                       std::nullopt);
    REQUIRE(count == 6);
  }

  SECTION("With alias, name, and topic") {
    // 6 base + 1 alias + 1 name + 1 topic = 9
    auto count =
        calculate_assumed_createRoom_state_event_count(true, true, true,
                                                       std::nullopt,
                                                       std::nullopt,
                                                       std::nullopt);
    REQUIRE(count == 9);
  }

  SECTION("With invites") {
    // 6 base + 3 invites = 9
    auto count =
        calculate_assumed_createRoom_state_event_count(false, false, false,
                                                       std::size_t{3},
                                                       std::nullopt,
                                                       std::nullopt);
    REQUIRE(count == 9);
  }

  SECTION("With initial_state") {
    // 6 base + 2 initial_state = 8
    auto count =
        calculate_assumed_createRoom_state_event_count(false, false, false,
                                                       std::nullopt,
                                                       std::nullopt,
                                                       std::size_t{2});
    REQUIRE(count == 8);
  }

  SECTION("All options") {
    // 6 base + 1 alias + 1 name + 1 topic + 2 invites + 1 invite_3pid + 3
    // initial_state = 15
    auto count =
        calculate_assumed_createRoom_state_event_count(true, true, true,
                                                       std::size_t{2},
                                                       std::size_t{1},
                                                       std::size_t{3});
    REQUIRE(count == 15);
  }
}

TEST_CASE("build_createRoom_state minimal", "[room_utils]") {
  const CreateRoomStateBuildData data{
      .createRoom_body = {.room_version = "11"sv},
      .room_id = "!test:localhost"sv,
      .user_id = "@alice:localhost"sv,
      .room_version = "11"sv};

  auto events = build_createRoom_state(data);

  // Should have at least 3 events: create, member, power_levels
  REQUIRE(events.size() >= 3);

  // First event should be m.room.create
  REQUIRE(events[0]["type"] == "m.room.create");
  REQUIRE(events[0]["sender"] == "@alice:localhost");
  REQUIRE(events[0]["room_id"] == "!test:localhost");
  REQUIRE(events[0]["state_key"] == "");
  REQUIRE(events[0].contains("event_id"));
  REQUIRE(events[0].contains("origin_server_ts"));

  // Second event should be m.room.member (join)
  REQUIRE(events[1]["type"] == "m.room.member");
  REQUIRE(events[1]["content"]["membership"] == "join");
  REQUIRE(events[1]["state_key"] == "@alice:localhost");
  REQUIRE(events[1]["sender"] == "@alice:localhost");

  // Third event should be m.room.power_levels
  REQUIRE(events[2]["type"] == "m.room.power_levels");
  REQUIRE(events[2]["content"]["users"]["@alice:localhost"] == 100);
  REQUIRE(events[2]["content"]["ban"] == 50);
  REQUIRE(events[2]["content"]["kick"] == 50);
}

TEST_CASE("build_createRoom_state with name and topic", "[room_utils]") {
  const CreateRoomStateBuildData data{
      .createRoom_body = {.name = "Test Room"sv,
                          .room_version = "11"sv,
                          .topic = "A test topic"sv},
      .room_id = "!test:localhost"sv,
      .user_id = "@alice:localhost"sv,
      .room_version = "11"sv};

  auto events = build_createRoom_state(data);

  // Should have base 3 + name + topic = 5
  REQUIRE(events.size() >= 5);

  // Find name and topic events
  bool found_name = false;
  bool found_topic = false;
  for (const auto &event : events) {
    if (event["type"] == "m.room.name") {
      REQUIRE(event["content"]["name"] == "Test Room");
      found_name = true;
    }
    if (event["type"] == "m.room.topic") {
      REQUIRE(event["content"]["topic"] == "A test topic");
      found_topic = true;
    }
  }
  REQUIRE(found_name);
  REQUIRE(found_topic);
}

TEST_CASE("build_createRoom_state with room alias", "[room_utils]") {
  const CreateRoomStateBuildData data{
      .createRoom_body = {.room_alias_name = "#myroom:localhost"sv,
                          .room_version = "11"sv},
      .room_id = "!test:localhost"sv,
      .user_id = "@alice:localhost"sv,
      .room_version = "11"sv};

  auto events = build_createRoom_state(data);

  bool found_alias = false;
  for (const auto &event : events) {
    if (event["type"] == "m.room.canonical_alias") {
      REQUIRE(event["content"]["alias"] == "#myroom:localhost");
      REQUIRE(event["state_key"] == "");
      found_alias = true;
    }
  }
  REQUIRE(found_alias);
}

TEST_CASE("build_createRoom_state with initial_state", "[room_utils]") {
  std::vector<json> initial_state = {
      {{"type", "m.room.history_visibility"},
       {"content", {{"history_visibility", "shared"}}},
       {"state_key", ""}}};

  client_server_json::CreateRoomBody body;
  body.room_version = "11"sv;
  body.initial_state = initial_state;

  const CreateRoomStateBuildData data{
      .createRoom_body = body,
      .room_id = "!test:localhost"sv,
      .user_id = "@alice:localhost"sv,
      .room_version = "11"sv};

  auto events = build_createRoom_state(data);

  bool found_history = false;
  for (const auto &event : events) {
    if (event["type"] == "m.room.history_visibility") {
      REQUIRE(event["content"]["history_visibility"] == "shared");
      REQUIRE(event["sender"] == "@alice:localhost");
      REQUIRE(event["room_id"] == "!test:localhost");
      REQUIRE(event.contains("event_id"));
      found_history = true;
    }
  }
  REQUIRE(found_history);
}

TEST_CASE("build_createRoom_state with invites", "[room_utils]") {
  client_server_json::CreateRoomBody body;
  body.room_version = "11"sv;
  body.invite =
      std::vector<std::string_view>{"@bob:example.com"sv, "@carol:example.com"sv};

  const CreateRoomStateBuildData data{
      .createRoom_body = body,
      .room_id = "!test:localhost"sv,
      .user_id = "@alice:localhost"sv,
      .room_version = "11"sv};

  auto events = build_createRoom_state(data);

  int invite_count = 0;
  for (const auto &event : events) {
    if (event["type"] == "m.room.member" &&
        event["content"]["membership"] == "invite") {
      invite_count++;
      REQUIRE(event["sender"] == "@alice:localhost");
      // state_key should be the invited user
      auto sk = event["state_key"].get<std::string>();
      REQUIRE((sk == "@bob:example.com" || sk == "@carol:example.com"));
    }
  }
  REQUIRE(invite_count == 2);
}

TEST_CASE("build_createRoom_state with power_level_override", "[room_utils]") {
  client_server_json::CreateRoomBody body;
  body.room_version = "11"sv;

  client_server_json::PowerLevelEventContent pl;
  pl.ban = 100;
  pl.invite = 50;
  pl.users =
      std::map<std::string_view, int>{{"@superadmin:localhost"sv, 100}};
  body.power_level_content_override = pl;

  const CreateRoomStateBuildData data{
      .createRoom_body = body,
      .room_id = "!test:localhost"sv,
      .user_id = "@alice:localhost"sv,
      .room_version = "11"sv};

  auto events = build_createRoom_state(data);

  bool found_pl = false;
  for (const auto &event : events) {
    if (event["type"] == "m.room.power_levels") {
      REQUIRE(event["content"]["ban"] == 100);
      REQUIRE(event["content"]["invite"] == 50);
      // Creator should still be in users
      REQUIRE(event["content"]["users"].contains("@alice:localhost"));
      // Override user should also be present
      REQUIRE(event["content"]["users"].contains("@superadmin:localhost"));
      found_pl = true;
    }
  }
  REQUIRE(found_pl);
}

TEST_CASE("build_createRoom_state event_ids are unique", "[room_utils]") {
  const CreateRoomStateBuildData data{
      .createRoom_body = {.name = "Room"sv,
                          .room_version = "11"sv,
                          .topic = "Topic"sv},
      .room_id = "!test:localhost"sv,
      .user_id = "@alice:localhost"sv,
      .room_version = "11"sv};

  auto events = build_createRoom_state(data);

  // All event_ids should be unique
  std::set<std::string> event_ids;
  for (const auto &event : events) {
    REQUIRE(event.contains("event_id"));
    auto eid = event["event_id"].get<std::string>();
    REQUIRE_FALSE(eid.empty());
    auto inserted = event_ids.insert(eid).second;
    REQUIRE(inserted); // insertion should succeed (unique)
  }
}
