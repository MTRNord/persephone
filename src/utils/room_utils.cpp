#include "room_utils.hpp"

#include "state_res.hpp"

#include <trantor/utils/Logger.h>

namespace {
json get_powerlevels_pdu(
    const std::string &room_version, const std::string &sender,
    const std::string &room_id,
    const std::optional<client_server_json::PowerLevelEventContent>
        &power_level_override) {
  json power_level_event = {
      {"type", "m.room.power_levels"},
      {"state_key", ""},
      {"room_id", room_id},
      {"sender", sender},
      {"origin_server_ts",
       std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::system_clock::now().time_since_epoch())
           .count()},
      {"content",
       {
           {"ban", 50},
           {"events_default", 0},
           {"invite", 0},
           {"kick", 50},
           {"redact", 50},
           {"state_default", 50},
           {"users_default", 0},
           {"users",
            {
                {sender, 100},
            }},
           {"notifications",
            {
                {"room", 50},
            }},
       }}};

  // If power_level_override has a value we need to merge it with the default
  // power levels given above
  if (power_level_override.has_value()) {
    // We got a power level override, merge it with the default power levels.
    // The override takes precedence over the default defined in
    // `power_level_event`
    const auto &[ban, events, events_default, invite, kick, notifications,
                 redact, state_default, users, users_default] =
        power_level_override.value();

    if (ban.has_value()) {
      power_level_event["content"]["ban"] = ban.value();
    }
    if (events.has_value()) {
      for (const auto &[event_type, power_level] : events.value()) {
        power_level_event["content"]["events"][event_type] = power_level;
      }
    }
    if (events_default.has_value()) {
      power_level_event["content"]["events_default"] = events_default.value();
    }
    if (invite.has_value()) {
      power_level_event["content"]["invite"] = invite.value();
    }
    if (kick.has_value()) {
      power_level_event["content"]["kick"] = kick.value();
    }
    if (notifications.has_value()) {
      for (const auto &[notification_type, power_level] :
           notifications.value()) {
        power_level_event["content"]["notifications"][notification_type] =
            power_level;
      }
    }
    if (redact.has_value()) {
      power_level_event["content"]["redact"] = redact.value();
    }
    if (state_default.has_value()) {
      power_level_event["content"]["state_default"] = state_default.value();
    }
    if (users.has_value()) {
      for (const auto &[user_id, power_level] : users.value()) {
        power_level_event["content"]["users"][user_id] = power_level;
      }
    }
    if (users_default.has_value()) {
      power_level_event["content"]["users_default"] = users_default.value();
    }
  }

  power_level_event["event_id"] = event_id(power_level_event, room_version);

  return power_level_event;
}
} // namespace

std::vector<json> build_createRoom_state(const CreateRoomStateBuildData &data) {
  // Calculate the expected amount of state events based on the given data in
  // the request This is used to preallocate the state_events vector We expect
  // the following state events:
  // 1. The m.room.create event
  // 2. The m.room.member event for the user creating the room
  // 3. The m.room.power_levels event
  // 4. The m.room.canonical_alias event if room_alias_name is set
  // 5. Based on the preset rules we might have more state events (currently
  // m.room.join_rules, m.room.history_visibility and m.room.guest_access)
  // 6. state events for all initial_state events
  // 7. The m.room.name event if name is set
  // 8. The m.room.topic event if topic is set
  // 9. state events for all the invite and invite_3pid data (m.room.member
  // with membership invite and m.room.third_party_invite)
  std::size_t const expected_state_events =
      calculate_assumed_createRoom_state_event_count(
          data.createRoom_body.room_alias_name.has_value(),
          data.createRoom_body.name.has_value(),
          data.createRoom_body.topic.has_value(),
          data.createRoom_body.invite.has_value()
              ? data.createRoom_body.invite->size()
              : 0,
          data.createRoom_body.invite_3pid.has_value()
              ? data.createRoom_body.invite_3pid->size()
              : 0,
          data.createRoom_body.initial_state.has_value()
              ? data.createRoom_body.initial_state->size()
              : 0);

  std::vector<json> state_events;
  state_events.reserve(expected_state_events);

  // Create the m.room.create event
  json create_room_pdu = {
      {"type", "m.room.create"},
      {"content", data.createRoom_body.creation_content.value_or(json::object({
                      {"creator", data.user_id},
                      {"room_version", data.room_version},
                  }))},
      {"origin_server_ts",
       std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::system_clock::now().time_since_epoch())
           .count()},
      {"sender", data.user_id},
      {"state_key", ""},
      {"room_id", data.room_id},
  };

  // Calculate and add event_id
  try {
    create_room_pdu["event_id"] = event_id(create_room_pdu, data.room_version);
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to calculate event_id: " << e.what();
    throw std::runtime_error("Failed to calculate event_id");
  }

  state_events.push_back(create_room_pdu);

  // Create room membership event for sender of the create room request
  json membership_pdu = {
      {"type", "m.room.member"},
      {"content",
       {
           {"membership", "join"},
       }},
      {"origin_server_ts",
       std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::system_clock::now().time_since_epoch())
           .count()},
      {"sender", data.user_id},
      {"state_key", data.user_id},
      {"room_id", data.room_id},
  };

  // Calculate and add event_id
  try {
    membership_pdu["event_id"] = event_id(membership_pdu, data.room_version);
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to calculate event_id: " << e.what();
    throw std::runtime_error("Failed to calculate event_id");
  }

  state_events.push_back(membership_pdu);

  // Create the default power levels event
  try {
    auto power_levels_pdu =
        get_powerlevels_pdu(data.room_version, data.user_id, data.room_id,
                            data.createRoom_body.power_level_content_override);

    state_events.push_back(power_levels_pdu);
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to create power levels pdu: " << e.what();
    throw std::runtime_error("Failed to create power levels pdu");
  }

  // Check if room_alias_name is set and create the m.room.canonical_alias
  // event
  // TODO: record this on the DB for actual room directory logic
  if (data.createRoom_body.room_alias_name.has_value()) {
    auto canonical_alias_pdu = json{
        {"type", "m.room.canonical_alias"},
        {"content",
         {
             {"alias", data.createRoom_body.room_alias_name.value()},
         }},
        {"origin_server_ts",
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
             .count()},
        {"sender", data.user_id},
        {"state_key", ""},
        {"room_id", data.room_id},
    };

    // Calculate and add event_id
    try {
      canonical_alias_pdu["event_id"] =
          event_id(canonical_alias_pdu, data.room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      throw std::runtime_error("Failed to calculate event_id");
    }

    state_events.push_back(canonical_alias_pdu);
  }

  // TODO: here handle the preset

  // Add origin_server_ts, room_id, sender and event_id to each initial_state
  // event and add it to state_events
  for (auto &initial_state :
       data.createRoom_body.initial_state.value_or(std::vector<json>())) {
    initial_state["origin_server_ts"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    initial_state["room_id"] = data.room_id;
    initial_state["sender"] = data.user_id;

    // Calculate and add event_id
    try {
      initial_state["event_id"] = event_id(initial_state, data.room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      throw std::runtime_error("Failed to calculate event_id");
    }

    state_events.push_back(initial_state);
  }

  // If name is set create the m.room.name event
  if (data.createRoom_body.name.has_value()) {
    auto room_name_pdu = json{
        {"type", "m.room.name"},
        {"content",
         {
             {"name", data.createRoom_body.name.value()},
         }},
        {"origin_server_ts",
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
             .count()},
        {"sender", data.user_id},
        {"state_key", ""},
        {"room_id", data.room_id},
    };

    // Calculate and add event_id
    try {
      room_name_pdu["event_id"] = event_id(room_name_pdu, data.room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      throw std::runtime_error("Failed to calculate event_id");
    }

    state_events.push_back(room_name_pdu);
  }

  // If topic is set create the m.room.topic event
  if (data.createRoom_body.topic.has_value()) {
    auto room_topic_pdu = json{
        {"type", "m.room.topic"},
        {"content",
         {
             {"topic", data.createRoom_body.topic.value()},
         }},
        {"origin_server_ts",
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
             .count()},
        {"sender", data.user_id},
        {"state_key", ""},
        {"room_id", data.room_id},
    };

    // Calculate and add event_id
    try {
      room_topic_pdu["event_id"] = event_id(room_topic_pdu, data.room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      throw std::runtime_error("Failed to calculate event_id");
    }

    state_events.push_back(room_topic_pdu);
  }

  // Create invite memberhsip events
  // TODO: Do fed requests to actually invite the users
  // TODO: Deal with 3pid invites
  if (data.createRoom_body.invite.has_value()) {
    for (const auto &invite : data.createRoom_body.invite.value()) {
      auto invite_pdu = json{
          {"type", "m.room.member"},
          {"content",
           {
               {"membership", "invite"},
           }},
          {"origin_server_ts",
           std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
               .count()},
          {"sender", data.user_id},
          {"state_key", invite},
          {"room_id", data.room_id},
      };

      // Calculate and add event_id
      try {
        invite_pdu["event_id"] = event_id(invite_pdu, data.room_version);
      } catch (const std::exception &e) {
        LOG_ERROR << "Failed to calculate event_id: " << e.what();
        throw std::runtime_error("Failed to calculate event_id");
      }

      state_events.push_back(invite_pdu);
    }
  }

  return state_events;
}