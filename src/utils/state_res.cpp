#include "state_res.hpp"
#include "drogon/drogon.h"
#include "utils/errors.hpp"
#include <format>
#include <ranges>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/utils.h>
#include <stack>
#include <unordered_set>

// Define StateEvent as json::object_t
using StateEvent = json::object_t;

/**
 * @brief Redacts the provided JSON event object based on Matrix Protocol
 * version 11 rules.
 *
 * The function preserves specific keys as per Matrix Protocol v11 rules and
 * removes all other keys from the JSON event object. Special rules are applied
 * for different event types, maintaining required keys and deleting the rest.
 *
 * @param event The JSON object representing the event to be redacted.
 * @return A JSON object redacted according to Matrix Protocol version 11 rules.
 *
 * @details The function preserves specific keys such as "event_id", "type",
 * "room_id", "sender", "state_key", "hashes", "signatures", "depth",
 * "prev_events", "auth_events", and "origin_server_ts". It then inspects the
 * event type and applies specific rules for redacting keys from the "content"
 * section based on different event types such as "m.room.member",
 * "m.room.join_rules", "m.room.power_levels", "m.room.history_visibility",
 * "m.room.redaction", and others.
 */
json v11_redact(const json &event) {
  //  We copy here to (if needed) have the original still intact
  json event_copy(event);

  const std::unordered_set<std::string> preserved_keys{
      "event_id",    "type",        "room_id",    "sender",
      "state_key",   "hashes",      "signatures", "depth",
      "prev_events", "auth_events", "content",    "origin_server_ts"};

  for (auto it = event_copy.begin(); it != event_copy.end();) {
    const auto &key = it.key();
    if (preserved_keys.find(key) == preserved_keys.end()) {
      it = event_copy.erase(it);
    } else {
      ++it;
    }
  }

  // Special events have special allow rules for things in content
  if (event["type"] == "m.room.member") {
    for (auto &[key, val] : event["content"].items()) {
      if (key != "membership" && key != "join_authorised_via_users_server" &&
          key != "third_party_invite") {
        event_copy["content"].erase(key);
      }
    }

    if (event["content"].contains("third_party_invite")) {
      for (auto &[key, val] : event["content"]["third_party_invite"].items()) {
        if (key != "signed") {
          event_copy["content"]["third_party_invite"].erase(key);
        }
      }
    }
  } else if (event["type"] == "m.room.join_rules") {
    for (auto &[key, val] : event["content"].items()) {
      if (key != "join_rule" && key != "allow") {
        event_copy["content"].erase(key);
      }
    }
  } else if (event["type"] == "m.room.power_levels") {
    for (auto &[key, val] : event["content"].items()) {
      if (key != "ban" && key != "events" && key != "events_default" &&
          key != "invite" && key != "kick" && key != "redact" &&
          key != "state_default" && key != "users" && key != "users_default") {
        event_copy["content"].erase(key);
      }
    }
  } else if (event["type"] == "m.room.history_visibility") {
    for (auto &[key, val] : event["content"].items()) {
      if (key != "history_visibility") {
        event_copy["content"].erase(key);
      }
    }
  } else if (event["type"] == "m.room.redaction") {
    for (auto &[key, val] : event["content"].items()) {
      if (key != "redacts") {
        event_copy["content"].erase(key);
      }
    }
  } else {
    event_copy["content"] = json::object();
  }

  return event_copy;
}

json redact(const json &event, const std::string &room_version) {
  if (room_version == "11") {
    return v11_redact(event);
  }
  throw MatrixRoomVersionError(room_version);
}

std::string reference_hash_v11(const json &event) {
  //  We copy here to (if needed) have the original still intact
  json event_copy(event);

  event_copy.erase("signatures");
  event_copy.erase("unsigned");

  std::string input = event_copy.dump();

  std::vector<unsigned char> sha256_hash;
  crypto_hash_sha256(sha256_hash.data(),
                     reinterpret_cast<const unsigned char *>(input.c_str()),
                     input.size());

  std::string sha256_hash_string{sha256_hash.begin(), sha256_hash.end()};
  return sha256_hash_string;
}

std::string reference_hash(const json &event, const std::string &room_version) {
  if (room_version == "11") {
    return reference_hash_v11(event);
  }

  throw MatrixRoomVersionError(room_version);
}

std::string event_id(const json &event, const std::string &room_version) {
  auto hash = reference_hash(event, room_version);

  unsigned long long hash_len = hash.size();
  const size_t base64_max_len = sodium_base64_encoded_len(
      hash_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

  std::string base64_str(base64_max_len - 1, 0);
  auto encoded_str_char =
      sodium_bin2base64(base64_str.data(), base64_max_len,
                        reinterpret_cast<const unsigned char *>(hash.c_str()),
                        hash_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  if (encoded_str_char == nullptr) {
    throw std::runtime_error("Base64 Error: Failed to encode string");
  }

  return base64_str;
}

using EventType = std::string;
using StateKey = std::string;

// Function to create the partial state map from unconflicted events while
// preserving ordering
std::map<EventType, std::map<StateKey, StateEvent>>
createPartialState(const std::vector<StateEvent> &unconflictedEvents) {
  std::map<EventType, std::map<StateKey, StateEvent>> partialState;

  // Populate partial state with unconflicted events while preserving ordering
  for (const auto &event : unconflictedEvents) {
    std::string event_type = event.at("type").get<EventType>();
    std::string state_key = event.at("state_key").get<StateKey>();
    partialState[event_type][state_key] =
        event; // Add the event to partial state
  }

  return partialState;
}

// Custom struct to hold conflicted and unconflicted state sets
struct StateEventSets {
  std::vector<StateEvent> conflictedEvents;
  std::vector<StateEvent> unconflictedEvents;
};

StateEventSets splitEvents(const std::vector<std::vector<StateEvent>> &forks) {
  StateEventSets result;
  std::vector<std::map<std::pair<EventType, StateKey>, int>> stateTuples(
      forks.size());

  // Count occurrences of state tuples for each fork
  for (size_t i = 0; i < forks.size(); ++i) {
    for (const auto &event : forks[i]) {
      std::string event_type = event.at("type").get<EventType>();
      std::string state_key = event.at("state_key").get<StateKey>();
      stateTuples[i][{event_type, state_key}]++;
    }
  }

  // Iterate through events in each fork
  for (size_t i = 0; i < forks.size(); ++i) {
    for (const auto &event : forks[i]) {
      std::string event_type = event.at("type").get<EventType>();
      std::string state_key = event.at("state_key").get<StateKey>();

      bool isConflicted = false;

      // Check if the state tuple exists in another fork only once
      int appearingInOtherForks = 0;
      for (size_t j = 0; j < forks.size(); ++j) {
        if (j != i && stateTuples[j][{event_type, state_key}] == 1) {
          appearingInOtherForks++;
        }
      }

      if ((stateTuples[i][{event_type, state_key}] > 1 ||
           appearingInOtherForks > 1) ||
          (stateTuples[i][{event_type, state_key}] == 1 &&
           appearingInOtherForks == 0)) {
        isConflicted = true; // State tuple is conflicted in either fork or
                             // State tuple exists in only one other fork
      }

      // Add events to conflicted or unconflicted sets
      if (isConflicted) {
        result.conflictedEvents.push_back(event); // Add to conflicted set
      } else {
        result.unconflictedEvents.push_back(event); // Add to unconflicted set
      }
    }
  }

  return result;
}

using ForkID = int;

std::vector<StateEvent>
findAuthDifference(const std::vector<StateEvent> &conflictedEvents,
                   const std::vector<std::vector<StateEvent>> &forks) {
  std::vector<StateEvent> authDifference;

  for (const auto &e : conflictedEvents) {
    bool found = true;

    for (const auto &authSet : forks) {
      if (std::find(authSet.begin(), authSet.end(), e) == authSet.end()) {
        found = false;
        break;
      }
    }

    if (!found) {
      authDifference.push_back(e);
    }
  }

  return authDifference;
}

using EventID = std::string;

std::map<EventID, int>
sorted_incoming_edges(const std::map<EventID, int> &incoming_edges,
                      const std::map<EventID, StateEvent> &event_map) {
  auto comparator = [&](const EventID &x, const EventID &y) {
    const StateEvent &state_event_x = event_map.at(x);
    const StateEvent &state_event_y = event_map.at(y);
    int power_level_x = state_event_x.at("power_level").get<int>();
    int power_level_y = state_event_y.at("power_level").get<int>();

    time_t origin_server_ts_x =
        state_event_x.at("origin_server_ts").get<time_t>();
    time_t origin_server_ts_y =
        state_event_y.at("origin_server_ts").get<time_t>();

    std::string event_id_x = state_event_x.at("event_id").get<std::string>();
    std::string event_id_y = state_event_y.at("event_id").get<std::string>();

    return (power_level_x > power_level_y) ||
           (origin_server_ts_x < origin_server_ts_y) ||
           (event_id_x < event_id_y);
  };

  std::map<EventID, int> sorted_edges;
  std::vector<EventID> keys(incoming_edges.size());
  for (const auto &[id, _] : incoming_edges) {
    keys.push_back(id);
  }

  std::sort(keys.begin(), keys.end(), comparator);

  for (const auto &key : keys) {
    sorted_edges[key] = incoming_edges.at(key);
  }

  return sorted_edges;
}

std::vector<StateEvent>
kahns_algorithm(const std::vector<StateEvent> &full_conflicted_set) {
  std::vector<StateEvent> output_events;
  std::map<EventID, StateEvent> event_map;
  std::map<EventID, int> incoming_edges;

  for (const auto &e : full_conflicted_set) {
    auto event_id = e.at("event_id").get<std::string>();
    event_map[event_id] = e;
    incoming_edges[event_id] = 0;
  }

  auto incoming_edges_sorted = sorted_incoming_edges(incoming_edges, event_map);

  while (!incoming_edges.empty()) {
    for (const auto &[event_id, count] : incoming_edges_sorted) {
      if (count == 0) {

        output_events.insert(output_events.begin(), event_map[event_id]);
        auto auth_events = event_map[event_id]
                               .at("auth_events")
                               .get<std::vector<json::object_t>>();

        for (const auto &auth_event : auth_events) {
          auto auth_event_id = auth_event.at("event_id").get<std::string>();
          incoming_edges[auth_event_id] -= 1;
        }

        incoming_edges.erase(event_id);
      }
    }
  }

  return output_events;
}

bool matchDomain(std::string str1, std::string str2) {
  // Find the position of ':' in the strings
  size_t pos1 = str1.find(':');
  size_t pos2 = str2.find(':');

  // Extract the domain parts after ':'
  std::string domain1 = str1.substr(pos1 + 1);
  std::string domain2 = str2.substr(pos2 + 1);

  // Compare the domain parts
  return domain1 == domain2;
}

bool auth_against_partial_state_version_11(
    const std::map<EventType, std::map<StateKey, StateEvent>>
        &current_partial_state,
    StateEvent &e) {
  // If type is m.room.create
  if (e["type"].get<std::string>() == "m.room.create") {
    // If it has any prev_events, reject.
    if (e.contains("prev_events")) {
      return false;
    }
    // If the domain of the room_id does not match the domain of the sender,
    // reject.
    auto room_id = e["room_id"].get<std::string>();
    auto sender = e["sender"].get<std::string>();
    if (matchDomain(room_id, sender)) {
      return false;
    }

    // If content.room_version is present and is not a recognised version,
    // reject.

    if (e["content"]["room_version"].get<std::string>() == "11") {
      return false;
    }

    return true;
  }

  // Considering the event's auth_events:

  // If there are duplicate entries for a given type and state_key pair, reject.
  auto auth_events_ids = e["auth_events"].get<std::vector<std::string>>();

  std::map<EventType, std::map<StateKey, StateEvent>> auth_events_map;
  for (const auto &[event_type, inner_map] : current_partial_state) {
    for (const auto &[state_key, state_event] : inner_map) {
      auto state_event_pure = state_event;
      if (std::find(auth_events_ids.begin(), auth_events_ids.end(),
                    state_event_pure["event_id"].get<std::string>()) !=
          auth_events_ids.end()) {
        // Check if the (event_type, state_key) pair already exists
        if (auth_events_map[event_type].find(state_key) ==
            auth_events_map[event_type].end()) {
          // Add the matching state_event to auth_events_map
          auth_events_map[event_type][state_key] = state_event;
        } else {
          // Duplicate entry found, reject
          return false;
        }
      }
    }
  }

  // If there are entries whose type and state_key don’t match those specified
  // by the auth events selection algorithm described in the server
  // specification, reject.

  // Set of allowed EventType values
  std::set<std::string> allowedEventTypes = {
      "m.room.create", "m.room.power_levels", "m.room.member"};

  // Find invalid EventTypes using std::find_if
  auto invalidEventType = std::find_if(
      auth_events_map.begin(), auth_events_map.end(),
      [&allowedEventTypes](const auto &pair) {
        return allowedEventTypes.find(pair.first) == allowedEventTypes.end();
      });

  // Check if any invalid EventTypes were found
  if (invalidEventType != auth_events_map.end()) {
    return false;
  }
  // TODO: We need to check if the auth events are also correct according to
  // https://spec.matrix.org/v1.9/server-server-api/#auth-events-selection
  return true;
}

// This checks if the event is allowed by the auth checks
// These are defined in
// https://spec.matrix.org/v1.9/rooms/v11/#authorization-rules
bool auth_against_partial_state(
    std::map<EventType, std::map<StateKey, StateEvent>> &current_partial_state,
    StateEvent &e) {
  if (e["type"].get<std::string>() == "m.room.create") {
    if (!e["content"].contains("room_version")) {
      return false;
    }
    if (e["content"]["room_version"].get<std::string>() == "11") {
      return auth_against_partial_state_version_11(current_partial_state, e);
    }
  } else {
    auto create_event = current_partial_state["m.room.create"][""];
    if (!create_event["content"].contains("room_version")) {
      return false;
    }
    if (create_event["content"]["room_version"].get<std::string>() == "11") {
      return auth_against_partial_state_version_11(current_partial_state, e);
    }
  }

  return false;
}

void mainline_iterate(std::vector<StateEvent> &power_level_mainline,
                      StateEvent &event) {
  power_level_mainline.push_back(event);
  for (auto &auth_event : event["auth_events"]) {
    StateEvent auth_event_obj = auth_event.get<StateEvent>();
    if (auth_event_obj["event_type"] == "m.room.powerlevel") {
      mainline_iterate(power_level_mainline, auth_event_obj);
    }
  }
}

StateEvent
get_closest_mainline_event(std::vector<StateEvent> &power_level_mainline,
                           StateEvent &event) {
  StateEvent closest_mainline_event;
  std::stack<StateEvent> event_stack;
  event_stack.push(event);

  while (!event_stack.empty()) {
    StateEvent current_event = event_stack.top();
    event_stack.pop();

    auto search_iter = std::find(power_level_mainline.begin(),
                                 power_level_mainline.end(), current_event);
    if (search_iter != power_level_mainline.end()) {
      current_event["position_on_mainline"] =
          std::distance(power_level_mainline.begin(), search_iter);
      closest_mainline_event = current_event;
      break;
    } else {
      for (const auto &auth_event : current_event["auth_events"]) {
        StateEvent auth_event_obj = auth_event.get<StateEvent>();
        if (auth_event_obj["event_type"] == "m.room.powerlevel") {
          event_stack.push(auth_event_obj);
        }
      }
    }
  }

  return closest_mainline_event;
}

std::vector<StateEvent>
sorted_normal_state_events(std::vector<StateEvent> normal_events) {
  auto compare_events = [](StateEvent &x, StateEvent &y) {
    if (x["position_on_mainline"].get<std::string>() !=
        y["position_on_mainline"].get<std::string>()) {
      return x["position_on_mainline"].get<std::string>() <
             y["position_on_mainline"].get<std::string>();
    }
    if (x["origin_server_ts"].get<std::string>() !=
        y["origin_server_ts"].get<std::string>()) {
      return x["origin_server_ts"].get<std::string>() <
             y["origin_server_ts"].get<std::string>();
    }
    return x["event_id"].get<std::string>() < y["event_id"].get<std::string>();
  };

  std::sort(normal_events.begin(), normal_events.end(), compare_events);

  return normal_events;
}

std::map<EventType, std::map<StateKey, StateEvent>>
stateres_v2(const std::vector<std::vector<StateEvent>> &forks) {
  auto state_event_sets = splitEvents(forks);
  auto partial_state = createPartialState(state_event_sets.unconflictedEvents);

  auto auth_difference =
      findAuthDifference(state_event_sets.conflictedEvents, forks);

  std::vector<StateEvent> full_conflicted_set, conflicted_control_events,
      conflicted_others;
  full_conflicted_set.reserve(state_event_sets.conflictedEvents.size() +
                              auth_difference.size());
  full_conflicted_set.insert(full_conflicted_set.end(),
                             state_event_sets.conflictedEvents.begin(),
                             state_event_sets.conflictedEvents.end());
  full_conflicted_set.insert(full_conflicted_set.end(), auth_difference.begin(),
                             auth_difference.end());

  // is_control_event returns true if the event meets the criteria for being
  // classed as a "control" event for reverse topological sorting. If not then
  // the event will be mainline sorted.
  auto is_control_event = [](StateEvent event) {
    if (event["type"].get<std::string>() == "m.room.power_level") {
      // Power level events with an empty state key are control events.
      if (event["state_key"].get<std::string>() == "") {
        return true;
      }
    }
    if (event["type"].get<std::string>() == "m.room.join_rules") {
      // Join rule events with an empty state key are control events.
      if (event["state_key"].get<std::string>() == "") {
        return true;
      }
    }
    if (event["type"].get<std::string>() == "m.room.member") {
      // Membership events must not have an empty state key.
      if (event["state_key"].get<std::string>() == "") {
        return false;
      }
      // Membership events are only control events if the sender does not match
      // the state key, i.e. because the event is caused by an admin or
      // moderator.
      if (event["state_key"].get<std::string>() ==
          event["sender"].get<std::string>()) {
        return false;
      }
      // Membership events are only control events if the "membership" key in
      // the content is "leave" or "ban" so we need to extract the content.
      if (event["content"]["membership"].get<std::string>() == "leave" ||
          event["content"]["membership"].get<std::string>() == "ban") {
        return true;
      }
    }
    return false;
  };

  // Partition the vector based on the boolean condition
  auto partition_point = std::partition(
      full_conflicted_set.begin(), full_conflicted_set.end(), is_control_event);
  // Copy elements based on the partition point
  conflicted_control_events = std::vector<StateEvent>(
      std::make_move_iterator(full_conflicted_set.begin()),
      std::make_move_iterator(partition_point));
  conflicted_others = std::vector<StateEvent>(
      std::make_move_iterator(partition_point),
      std::make_move_iterator(full_conflicted_set.end()));

  auto conflicted_control_events_sorted =
      kahns_algorithm(conflicted_control_events);

  for (auto &e : conflicted_control_events_sorted) {
    if (auth_against_partial_state(partial_state, e)) {
      auto event_type = e["event_type"].get<EventType>();
      auto state_key = e["state_key"].get<StateKey>();
      partial_state[event_type][state_key] = e;
    }
  }

  auto resolved_power_level_event = partial_state["m.room.power_level"][""];
  std::vector<StateEvent> power_level_mainline = {resolved_power_level_event};

  mainline_iterate(power_level_mainline, resolved_power_level_event);

  auto sorted_others = sorted_normal_state_events(conflicted_others);
  for (auto &e : sorted_others) {
    if (auth_against_partial_state(partial_state, e)) {
      auto event_type = e["event_type"].get<EventType>();
      auto state_key = e["state_key"].get<StateKey>();
      partial_state[event_type][state_key] = e;
    }
  }

  for (auto &e : state_event_sets.unconflictedEvents) {
    auto event_type = e["event_type"].get<EventType>();
    auto state_key = e["state_key"].get<StateKey>();
    partial_state[event_type][state_key] = e;
  }

  return partial_state;
}
