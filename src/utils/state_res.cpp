#include "state_res.hpp"
#include "utils/errors.hpp"
#include <algorithm>
#include <cstddef>
#include <ctime>
#include <format>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <ranges>
#include <set>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/utils.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {
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
[[nodiscard]] json v11_redact(const json &event) {
  //  We copy here to (if needed) have the original still intact
  json event_copy(event);

  auto erase_unpreserved_keys = [](json &original_event) {
    const std::unordered_set<std::string_view> preserved_keys{
        "event_id",    "type",        "room_id",    "sender",
        "state_key",   "hashes",      "signatures", "depth",
        "prev_events", "auth_events", "content",    "origin_server_ts"};
    for (auto it = original_event.begin(); it != original_event.end();) {
      if (!preserved_keys.contains(it.key())) {
        it = original_event.erase(it);
      } else {
        ++it;
      }
    }
  };

  auto redact_content =
      [](json &content,
         const std::unordered_set<std::string_view> &allowed_keys) {
        for (auto it = content.begin(); it != content.end();) {
          if (!allowed_keys.contains(it.key())) {
            it = content.erase(it);
          } else {
            ++it;
          }
        }
      };

  auto redact_third_party_invite = [](json &content) {
    if (content.contains("third_party_invite")) {
      for (auto it = content["third_party_invite"].begin();
           it != content["third_party_invite"].end();) {
        if (it.key() != "signed") {
          it = content["third_party_invite"].erase(it);
        } else {
          ++it;
        }
      }
    }
  };

  erase_unpreserved_keys(event_copy);

  // Special events have special allow rules for things in content
  if (event["type"] == "m.room.member") {
    redact_content(event_copy["content"],
                   {"membership", "join_authorised_via_users_server",
                    "third_party_invite"});
    redact_third_party_invite(event_copy["content"]);
  } else if (event["type"] == "m.room.create") {
    // m.room.create allows all keys in content - do nothing
  } else if (event["type"] == "m.room.join_rules") {
    redact_content(event_copy["content"], {"join_rule", "allow"});
  } else if (event["type"] == "m.room.power_levels") {
    redact_content(event_copy["content"],
                   {"ban", "events", "events_default", "invite", "kick",
                    "redact", "state_default", "users", "users_default"});
  } else if (event["type"] == "m.room.history_visibility") {
    redact_content(event_copy["content"], {"history_visibility"});
  } else if (event["type"] == "m.room.redaction") {
    redact_content(event_copy["content"], {"redacts"});
  } else {
    event_copy["content"] = json::object();
  }

  return event_copy;
}

/**
 * @brief Computes the reference hash for a JSON event object according to
 * Matrix Room version 11 rules.
 *
 * This function takes a JSON object representing an event as input.
 * It first creates a copy of the JSON object and removes the "signatures" and
 * "unsigned" fields from the copy. Then, it converts the modified JSON object
 * to a string. The function computes the SHA-256 hash of the string using the
 * Sodium library's crypto_hash_sha256 function. The hash is represented as a
 * vector of unsigned characters. Finally, the function converts the hash to a
 * string and returns it.
 *
 * @param event The JSON object representing the event.
 * @return The SHA-256 hash of the event as a string.
 */
[[nodiscard]] std::vector<unsigned char> reference_hash_v11(const json &event) {
  if (event == nullptr) {
    throw std::invalid_argument("Event cannot be null");
  }

  // Step 1: Redact the event (strips non-preserved keys like "origin")
  json event_copy = v11_redact(event);

  // Step 2: Remove signatures (unsigned is already stripped by redaction)
  event_copy.erase("signatures");

  // Step 3: Canonical JSON and SHA256
  const auto input = event_copy.dump();

  unsigned char sha256_hash[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(sha256_hash,
                     reinterpret_cast<const unsigned char *>(input.c_str()),
                     input.size());

  return {sha256_hash, sha256_hash + crypto_hash_sha256_BYTES};
}

/**
 * @brief Creates a partial state map from a list of unconflicted events.
 *
 * This function takes a vector of unconflicted StateEvent objects as input.
 * It iterates over each StateEvent in the vector and extracts the event type
 * and state key. The function then adds the StateEvent to the partial state map
 * under the corresponding event type and state key. The partial state map is a
 * map of event types to maps of state keys to StateEvents. The function
 * preserves the ordering of the unconflicted events in the partial state map.
 *
 * @param unconflictedEvents A vector of unconflicted StateEvent objects.
 * @return A map of event types to maps of state keys to StateEvents
 * representing the partial state.
 */
[[nodiscard]] std::map<EventType, std::map<StateKey, StateEvent>>
createPartialState(const std::vector<StateEvent> &unconflictedEvents) {
  std::map<EventType, std::map<StateKey, StateEvent>> partialState;

  // Populate partial state with unconflicted events while preserving ordering
  for (const auto &event : unconflictedEvents) {
    auto event_type = event.at("type").get<EventType>();
    auto state_key = event.at("state_key").get<StateKey>();
    partialState[event_type][state_key] =
        event; // Add the event to partial state
  }

  return partialState;
}

/**
 * @brief Splits the given events into conflicted and unconflicted sets.
 *
 * This function takes a vector of vectors of StateEvent objects, where each
 * inner vector represents a fork of events. It counts the occurrences of each
 * state tuple (event type and state key pair) in each fork. Then, it iterates
 * over each event in each fork. If the state tuple of an event exists in
 * another fork only once, or if it is conflicted in its own fork, the event is
 * added to the conflicted set. Otherwise, the event is added to the
 * unconflicted set. The function returns a StateEventSets object containing the
 * conflicted and unconflicted sets of events.
 *
 * @param forks A vector of vectors of StateEvent objects representing the forks
 * of events.
 * @return A StateEventSets object containing the conflicted and unconflicted
 * sets of events.
 */
[[nodiscard]] StateEventSets
splitEvents(const std::vector<std::vector<StateEvent>> &forks) {
  StateEventSets result;

  // Build a map from (type, state_key) -> event_id for each fork
  // This allows us to check if the same event appears in all forks
  std::vector<std::map<std::pair<EventType, StateKey>, EventID>>
      fork_state_maps(forks.size());

  for (size_t i = 0; i < forks.size(); ++i) {
    for (const auto &event : forks[i]) {
      auto event_type = event.at("type").get<EventType>();
      auto state_key = event.at("state_key").get<StateKey>();
      auto event_id = event.at("event_id").get<EventID>();
      fork_state_maps[i][{event_type, state_key}] = event_id;
    }
  }

  // Collect all unique (type, state_key) pairs across all forks
  std::set<std::pair<EventType, StateKey>> all_state_keys;
  for (const auto &fork_map : fork_state_maps) {
    for (const auto &[key, _] : fork_map) {
      all_state_keys.insert(key);
    }
  }

  // For each state key, check if it's unconflicted (same event_id in ALL forks)
  // or conflicted (different event_ids or missing from some forks)
  std::set<std::pair<EventType, StateKey>> unconflicted_keys;

  for (const auto &state_key : all_state_keys) {
    bool is_unconflicted = true;
    std::optional<EventID> common_event_id = std::nullopt;

    for (const auto &fork_map : fork_state_maps) {
      auto it = fork_map.find(state_key);
      if (it == fork_map.end()) {
        // Key not present in this fork - conflicted
        is_unconflicted = false;
        break;
      }

      if (!common_event_id.has_value()) {
        common_event_id = it->second;
      } else if (common_event_id.value() != it->second) {
        // Different event_id in this fork - conflicted
        is_unconflicted = false;
        break;
      }
    }

    if (is_unconflicted) {
      unconflicted_keys.insert(state_key);
    }
  }

  // Now iterate through all events and classify them
  std::set<EventID> added_unconflicted;
  std::set<EventID> added_conflicted;

  for (const auto &fork : forks) {
    for (const auto &event : fork) {
      auto event_type = event.at("type").get<EventType>();
      auto state_key = event.at("state_key").get<StateKey>();
      auto event_id = event.at("event_id").get<EventID>();
      std::pair<EventType, StateKey> key = {event_type, state_key};

      if (unconflicted_keys.contains(key)) {
        // Unconflicted - only add once (same event appears in all forks)
        if (!added_unconflicted.contains(event_id)) {
          result.unconflictedEvents.push_back(event);
          added_unconflicted.insert(event_id);
        }
      } else {
        // Conflicted - add each unique event
        if (!added_conflicted.contains(event_id)) {
          result.conflictedEvents.push_back(event);
          added_conflicted.insert(event_id);
        }
      }
    }
  }

  return result;
}

constexpr int DEFAULT_USERS_POWERLEVEL = 0;

/**
 * @brief Gets the power level of a sender from a power_levels event.
 *
 * @param power_levels_event The m.room.power_levels event to look up from.
 * @param sender The user ID of the sender.
 * @return The power level of the sender.
 */
[[nodiscard]] int get_sender_power_level(const StateEvent &power_levels_event,
                                         const std::string &sender) {
  if (power_levels_event.is_null() || !power_levels_event.contains("content")) {
    return DEFAULT_USERS_POWERLEVEL;
  }

  const auto &content = power_levels_event.at("content");

  // Check if the sender is explicitly listed in users
  if (content.contains("users") && content.at("users").contains(sender)) {
    return content.at("users").at(sender).get<int>();
  }

  // Fall back to users_default
  if (content.contains("users_default")) {
    return content.at("users_default").get<int>();
  }

  return DEFAULT_USERS_POWERLEVEL;
}

/**
 * @brief Finds the power_levels event from an event's auth_events.
 *
 * According to the Matrix spec, power levels should be determined by looking
 * at the event's respective auth_events.
 *
 * @param event The event to find the power_levels auth event for.
 * @param event_map A map of all events by event_id.
 * @return The power_levels event if found, or a null json object.
 */
[[nodiscard]] StateEvent
find_power_levels_in_auth(const StateEvent &event,
                          const std::map<EventID, StateEvent> &event_map) {
  if (!event.contains("auth_events")) {
    return json();
  }

  for (const auto &auth_event_id :
       event.at("auth_events").get<std::vector<std::string>>()) {
    auto it = event_map.find(auth_event_id);
    if (it != event_map.end()) {
      const auto &auth_event = it->second;
      if (auth_event.contains("type") &&
          auth_event.at("type").get<std::string_view>() ==
              "m.room.power_levels") {
        return auth_event;
      }
    }
  }

  return json();
}

/**
 * @brief Sorts the incoming edges of events based on certain criteria.
 *
 * This function takes a map of incoming edges and a map of events as input.
 * It first defines a comparator function that compares two events based on
 * their power level, origin server timestamp, and event ID. The function then
 * creates a vector of keys from the incoming edges map. It sorts the keys using
 * the comparator function. The function then creates a new map of sorted edges
 * by iterating over the sorted keys and adding the corresponding values from
 * the incoming edges map. The function returns the map of sorted edges.
 *
 * According to the Matrix spec, for comparing events x and y:
 * - x's sender has greater power level than y's sender, when looking at their
 *   respective auth_events
 * - the senders have the same power level, but x's origin_server_ts is less
 *   than y's origin_server_ts
 * - the senders have the same power level and the events have the same
 *   origin_server_ts, but x's event_id is less than y's event_id
 *
 * @param incoming_edges A map of incoming edges, where the key is the event ID
 * and the value is the number of incoming edges.
 * @param event_map A map of events, where the key is the event ID and the value
 * is the event object.
 * @return A map of sorted edges.
 */
[[nodiscard]] std::map<EventID, int>
sorted_incoming_edges(const std::map<EventID, int> &incoming_edges,
                      const std::map<EventID, StateEvent> &event_map) {
  auto comparator = [&](const EventID &first, const EventID &second) {
    // Same event's are equal and not having a second event is always less
    if (first == second) {
      return false;
    }
    if (second.empty()) {
      return false;
    }

    const StateEvent &state_event_x = event_map.at(first);
    const StateEvent &state_event_y = event_map.at(second);

    const auto sender_x = state_event_x.at("sender").get<std::string>();
    const auto sender_y = state_event_y.at("sender").get<std::string>();

    // Find power level events from each event's auth_events per Matrix spec
    const auto power_levels_x =
        find_power_levels_in_auth(state_event_x, event_map);
    const auto power_levels_y =
        find_power_levels_in_auth(state_event_y, event_map);

    // Get power levels for each sender from their respective auth events
    const int sender_x_power_level =
        get_sender_power_level(power_levels_x, sender_x);
    const int sender_y_power_level =
        get_sender_power_level(power_levels_y, sender_y);

    const time_t origin_server_ts_x =
        state_event_x.at("origin_server_ts").get<time_t>();
    const time_t origin_server_ts_y =
        state_event_y.at("origin_server_ts").get<time_t>();

    const auto event_id_x = state_event_x.at("event_id").get<std::string>();
    const auto event_id_y = state_event_y.at("event_id").get<std::string>();

    // Cascading comparison: first by power level (greater is "less" in order),
    // then by timestamp, then by event_id
    if (sender_x_power_level != sender_y_power_level) {
      return sender_x_power_level > sender_y_power_level;
    }
    if (origin_server_ts_x != origin_server_ts_y) {
      return origin_server_ts_x < origin_server_ts_y;
    }
    return event_id_x < event_id_y;
  };

  std::map<EventID, int> sorted_edges;
  std::vector<EventID> keys;
  keys.reserve(incoming_edges.size());
  for (const auto &event_id : incoming_edges | std::views::keys) {
    keys.push_back(event_id);
  }

  if (!keys.empty() && keys.size() > 1) {
    std::ranges::sort(keys, comparator);
  }

  for (const auto &key : keys) {
    sorted_edges[key] = incoming_edges.at(key);
  }

  return sorted_edges;
}

/**
 * @brief Implements Kahn's algorithm to sort the given events based on their
 * dependencies.
 *
 * This function takes a vector of StateEvent objects, which represent the full
 * set of conflicted events. It creates a map of events and a map of incoming
 * edges, where the key is the event ID and the value is the number of incoming
 * edges. The function then sorts the incoming edges based on certain criteria.
 * It iterates over the sorted edges and for each edge with zero incoming edges,
 * it adds the corresponding event to the output events and decreases the count
 * of incoming edges for all its dependent events. The function continues this
 * process until all edges are processed. Finally, it returns the vector of
 * output events, which is a topological ordering of the given events.
 *
 * @param full_conflicted_set A vector of StateEvent objects representing the
 * full set of conflicted events.
 * @return A vector of StateEvent objects representing the topological ordering
 * of the given events.
 */
[[nodiscard]] std::vector<StateEvent>
kahns_algorithm(const std::vector<StateEvent> &full_conflicted_set) {
  std::vector<StateEvent> output_events;
  std::map<EventID, int> incoming_edge_count;
  std::map<EventID, StateEvent> event_map;
  // Map from event_id to list of events that depend on it (have it in their
  // auth_events)
  std::map<EventID, std::vector<EventID>> dependents;

  // Build the event map and initialize edge counts to 0
  for (const auto &event : full_conflicted_set) {
    auto event_id = event.at("event_id").get<std::string>();
    event_map[event_id] = event;
    incoming_edge_count[event_id] = 0;
  }

  // Count incoming edges: for each event, increment count for each auth_event
  // that is in our set. Also build the dependents map.
  for (const auto &event : full_conflicted_set) {
    auto event_id = event.at("event_id").get<std::string>();
    for (const auto &auth_event_id :
         event.at("auth_events").get<std::vector<std::string>>()) {
      // Only count edges within our set of events
      if (incoming_edge_count.contains(auth_event_id)) {
        // This event depends on auth_event_id, so increment this event's
        // incoming count
        incoming_edge_count[event_id] += 1;
        // Record that auth_event_id has this event as a dependent
        dependents[auth_event_id].push_back(event_id);
      }
    }
  }

  // Sort edges for deterministic ordering when selecting among candidates
  auto sorted_edges = sorted_incoming_edges(incoming_edge_count, event_map);

  // Process events with no incoming edges
  while (!sorted_edges.empty()) {
    // Find the first event with zero incoming edges (sorted_edges maintains
    // order)
    EventID next_event_id;
    bool found = false;
    for (const auto &[event_id, count] : sorted_edges) {
      if (count == 0) {
        next_event_id = event_id;
        found = true;
        break;
      }
    }

    if (!found) {
      // No event with zero incoming edges - there's a cycle or we're done
      break;
    }

    // Add the event to output (append for forward topological order)
    output_events.push_back(event_map.at(next_event_id));

    // For all events that depend on this event, decrement their incoming edge
    // count
    if (dependents.contains(next_event_id)) {
      for (const auto &dependent_id : dependents.at(next_event_id)) {
        if (sorted_edges.contains(dependent_id)) {
          sorted_edges[dependent_id] -= 1;
        }
      }
    }

    // Remove processed event from the map
    sorted_edges.erase(next_event_id);
  }

  return output_events;
}

/**
 * @brief Performs authorization checks against a partial state for a given
 * event based on Matrix Protocol version 11 rules.
 *
 * This function takes a map of the current partial state and a StateEvent
 * object as input. It performs various checks to determine if the event is
 * authorized according to the rules of Matrix Protocol version 11. The function
 * returns true if the event is authorized, and false otherwise.
 *
 * @param current_partial_state A map of the current partial state, where the
 * key is the event type and the value is a map of state keys to StateEvents.
 * @param event The StateEvent object to be checked.
 * @return A boolean value indicating whether the event is authorized.
 *
 * @details The function performs the following checks:
 * - If the event type is "m.room.create", it checks if the event has any
 * previous events, if the domain of the room ID matches the domain of the
 * sender, and if the room version is recognized. If any of these checks fail,
 * the function returns false.
 * - The function then considers the event's authorization events. It checks for
 * duplicate entries for a given type and state key pair, and for entries whose
 * type and state key don’t match those specified by the authorization events
 * selection algorithm described in the server specification. If any of these
 * checks fail, the function returns false.
 * - Finally, the function checks if the authorization events are also correct
 * according to the server specification. This check is currently marked as a
 * TODO.
 */
[[nodiscard]] bool auth_against_partial_state_version_11(
    const std::map<EventType, std::map<StateKey, StateEvent>>
        &current_partial_state,
    StateEvent &event) {
  // If type is m.room.create
  if (event["type"].get<std::string_view>() == "m.room.create") {
    // If it has any prev_events, reject.
    if (event.contains("prev_events")) {
      return false;
    }
    // If the domain of the room_id does not match the domain of the sender,
    // reject.
    const auto room_id = event["room_id"].get<std::string_view>();
    const auto sender = event["sender"].get<std::string_view>();
    if (!matchDomain(room_id, sender)) {
      return false;
    }

    // If content.room_version is present and is not a recognised version,
    // reject.
    if (event["content"]["room_version"].get<std::string_view>() != "11") {
      return false;
    }

    return true;
  }

  // Considering the event's auth_events:

  // If there are duplicate entries for a given type and state_key pair, reject.
  auto auth_events_ids =
      event["auth_events"].get<std::vector<std::string_view>>();

  std::map<EventType, std::map<StateKey, StateEvent>> auth_events_map;
  for (const auto &[event_type, inner_map] : current_partial_state) {
    for (const auto &[state_key, state_event] : inner_map) {
      if (auto state_event_pure = state_event;
          std::ranges::find(
              auth_events_ids,
              state_event_pure["event_id"].get<std::string_view>()) !=
          auth_events_ids.end()) {
        // Check if the (event_type, state_key) pair already exists
        if (!auth_events_map[event_type].contains(state_key)) {
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

  // Set of allowed EventType values according to the auth events selection
  // algorithm in the Matrix spec
  std::set<std::string_view> allowedEventTypes = {
      "m.room.create", "m.room.power_levels", "m.room.member",
      "m.room.join_rules", "m.room.third_party_invite"};

  // Find invalid EventTypes using std::find_if
  const auto invalidEventType = std::ranges::find_if(
      auth_events_map, [&allowedEventTypes](const auto &pair) {
        return !allowedEventTypes.contains(pair.first);
      });

  // Check if any invalid EventTypes were found
  if (invalidEventType != auth_events_map.end()) {
    return false;
  }
  // TODO: We need to check if the auth events are also correct according to
  // https://spec.matrix.org/v1.9/server-server-api/#auth-events-selection
  return true;
}

/**
 * @brief Checks if the event is allowed by the authorization rules defined in
 * Matrix Protocol version 11.
 *
 * This function takes a map of the current partial state and a StateEvent
 * object as input. It checks if the event type is "m.room.create". If it is,
 * the function checks if the event content contains the "room_version" field.
 * If the "room_version" field is not present or if its value is not "11", the
 * function returns false. If the "room_version" field is present and its value
 * is "11", the function calls the auth_against_partial_state_version_11
 * function to perform further authorization checks. If the event type is not
 * "m.room.create", the function retrieves the "m.room.create" event from the
 * current partial state and performs the same checks as above. If none of the
 * checks pass, the function returns false.
 *
 * @param current_partial_state A map of the current partial state, where the
 * key is the event type and the value is a map of state keys to StateEvents.
 * @param event The StateEvent object to be checked.
 * @return A boolean value indicating whether the event is authorized.
 */
[[nodiscard]] bool auth_against_partial_state(
    std::map<EventType, std::map<StateKey, StateEvent>> &current_partial_state,
    StateEvent &event) {
  if (event["type"].get<std::string_view>() == "m.room.create") {
    if (!event["content"].contains("room_version")) {
      return false;
    }
    if (event["content"]["room_version"].get<std::string_view>() == "11") {
      return auth_against_partial_state_version_11(current_partial_state,
                                                   event);
    }
  } else {
    auto create_event = current_partial_state["m.room.create"][""];
    if (!create_event["content"].contains("room_version")) {
      return false;
    }
    if (create_event["content"]["room_version"].get<std::string_view>() ==
        "11") {
      return auth_against_partial_state_version_11(current_partial_state,
                                                   event);
    }
  }

  return false;
}

/**
 * @brief Iteratively builds the power level mainline for a given event.
 *
 * This function takes a reference to a vector of StateEvent objects, which
 * represents the power level mainline, and a StateEvent object as input. It
 * adds the given event to the power level mainline. Then, it iterates over each
 * authorization event of the given event. If the event type of an authorization
 * event is "m.room.powerlevel", the function recursively calls itself with the
 * power level mainline and the authorization event. This process continues
 * until all authorization events have been processed, resulting in a power
 * level mainline that includes all power level events that are authorization
 * events of the given event or its authorization events.
 *
 * @param power_level_mainline A reference to a vector of StateEvent objects
 * representing the power level mainline.
 * @param event The StateEvent object to be processed.
 * @param event_id_map A map from event_id to StateEvent for O(1) lookups.
 * @param visited A set of visited event IDs for cycle detection.
 */
void mainline_iterate(std::vector<StateEvent> &power_level_mainline,
                      StateEvent &event,
                      const std::map<EventID, StateEvent> &event_id_map,
                      std::set<std::string> &visited) {
  if (event.is_null()) {
    throw std::invalid_argument("Event cannot be null");
  }

  // Cycle detection: check if we've already visited this event
  auto event_id = event.at("event_id").get<std::string>();
  if (visited.contains(event_id)) {
    return;
  }
  visited.insert(event_id);

  power_level_mainline.push_back(event);
  for (auto &auth_event_id : event["auth_events"]) {
    const auto actual_auth_event_id = auth_event_id.get<std::string>();

    // O(1) lookup using event_id_map
    auto it = event_id_map.find(actual_auth_event_id);
    if (it == event_id_map.end()) {
      continue;
    }

    const auto &auth_event_obj = it->second;
    if (auth_event_obj["type"] == "m.room.power_levels") {
      StateEvent auth_event_copy = auth_event_obj;
      mainline_iterate(power_level_mainline, auth_event_copy, event_id_map,
                       visited);
    }
  }
}

/**
 * @brief Finds the closest event on the power level mainline for a given event.
 *
 * @param power_level_mainline A reference to a vector of StateEvent objects
 * representing the power level mainline.
 * @param event The StateEvent object to be processed.
 * @param event_id_map A map from event_id to StateEvent for O(1) lookups.
 * @return The closest mainline event to the given event.
 */
[[nodiscard]] StateEvent
get_closest_mainline_event(std::vector<StateEvent> &power_level_mainline,
                           const StateEvent &event,
                           const std::map<EventID, StateEvent> &event_id_map) {
  auto closest_mainline_event = event;

  // Track visited events to prevent infinite recursion from cycles
  std::set<std::string> visited;

  std::function<void(const StateEvent &)> func_closest_iterate;

  func_closest_iterate = [&](const StateEvent &inner_event) {
    // Cycle detection
    if (inner_event.contains("event_id")) {
      auto event_id = inner_event.at("event_id").get<std::string>();
      if (visited.contains(event_id)) {
        return;
      }
      visited.insert(event_id);
    }

    // Check if event is in power level mainline
    if (const auto search_iter =
            std::ranges::find(power_level_mainline, inner_event);
        search_iter != power_level_mainline.end()) {
      closest_mainline_event = inner_event;
      return;
    }
    // For each auth event of the event if the auth event is of type
    // m.room.power_levels then call func_closest_iterate recursively
    for (const auto &auth_event_id : inner_event["auth_events"]) {
      const auto actual_auth_event_id = auth_event_id.get<std::string>();

      // O(1) lookup using event_id_map
      auto it = event_id_map.find(actual_auth_event_id);
      if (it == event_id_map.end()) {
        continue;
      }

      const auto &auth_event_obj = it->second;
      if (auth_event_obj["type"] == "m.room.power_levels") {
        func_closest_iterate(auth_event_obj);
      }
    }
  };

  func_closest_iterate(event);
  return closest_mainline_event;
}

/**
 * @brief Sorts the given normal state events based on their position on the
 * mainline, origin server timestamp, and event ID.
 *
 * This function takes a vector of normal StateEvent objects as input.
 * It defines a comparator function that compares two events based on their
 * position on the mainline, origin server timestamp, and event ID. The function
 * then sorts the normal events using the comparator function. Finally, it
 * returns the sorted normal events.
 *
 * @param normal_events A vector of normal StateEvent objects to be sorted.
 * @return A vector of sorted normal StateEvent objects.
 *
 * @details The comparator function works as follows:
 * - If the position on the mainline of the first event is not equal to that of
 * the second event, it returns true if the position of the first event is less
 * than that of the second event.
 * - If the positions on the mainline are equal, it checks the origin server
 * timestamps. If they are not equal, it returns true if the timestamp of the
 * first event is less than that of the second event.
 * - If the timestamps are also equal, it returns true if the event ID of the
 * first event is less than that of the second event.
 * - If all these conditions are false, it returns false.
 */
[[nodiscard]] std::vector<StateEvent>
sorted_normal_state_events(std::vector<StateEvent> normal_events) {
  auto compare_events = [](StateEvent &first, StateEvent &second) {
    if (first["position_on_mainline"].get<std::string_view>() !=
        second["position_on_mainline"].get<std::string_view>()) {
      return first["position_on_mainline"].get<std::string_view>() <
             second["position_on_mainline"].get<std::string_view>();
    }
    if (first["origin_server_ts"].get<time_t>() !=
        second["origin_server_ts"].get<time_t>()) {
      return first["origin_server_ts"].get<time_t>() <
             second["origin_server_ts"].get<time_t>();
    }
    return first["event_id"].get<std::string_view>() <
           second["event_id"].get<std::string_view>();
  };

  std::ranges::sort(normal_events, compare_events);

  return normal_events;
}
} // namespace

/**
 * @brief Redacts the provided JSON event object based on the room version.
 *
 * This function takes a JSON object representing an event and a room version as
 * input. If the room version is "11", it calls the v11_redact function to
 * redact the event according to Matrix Protocol version 11 rules. If the room
 * version is not "11", it throws a MatrixRoomVersionError.
 *
 * @param event The JSON object representing the event to be redacted.
 * @param room_version The version of the room.
 * @return A JSON object redacted according to the specified room version rules.
 * @throw MatrixRoomVersionError If the room version is not "11".
 */
[[nodiscard]] json redact(const json &event,
                          const std::string_view room_version) {
  if (room_version == "11") {
    return v11_redact(event);
  }
  throw MatrixRoomVersionError(std::string(room_version));
}

/**
 * @brief Computes the reference hash for a JSON event object based on the room
 * version.
 *
 * This function takes a JSON object representing an event and a room version as
 * input. If the room version is "11", it calls the reference_hash_v11 function
 * to compute the reference hash of the event according to Matrix Protocol
 * version 11 rules. If the room version is not "11", it throws a
 * MatrixRoomVersionError.
 *
 * @param event The JSON object representing the event.
 * @param room_version The version of the room.
 * @return The reference hash of the event as a string.
 * @throw MatrixRoomVersionError If the room version is not "11".
 */
[[nodiscard]] std::vector<unsigned char>
reference_hash(const json &event, const std::string_view room_version) {
  if (room_version == "11") {
    return reference_hash_v11(event);
  }

  throw MatrixRoomVersionError(std::string(room_version));
}

/**
 * @brief Computes the event ID for a JSON event object based on the room
 * version.
 *
 * This function takes a JSON object representing an event and a room version as
 * input. It first calls the reference_hash function to compute the reference
 * hash of the event. The hash is represented as a string. The function then
 * computes the length of the hash and the maximum length of the base64-encoded
 * string. It creates a string of the maximum length and fills it with zeros.
 * The function then converts the hash to a base64 string using the Sodium
 * library's sodium_bin2base64 function. The base64 string is represented as a
 * URL-safe string with no padding. If the base64 encoding fails, the function
 * throws a runtime error. Finally, the function returns the base64 string,
 * which is the event ID.
 *
 * @param event The JSON object representing the event.
 * @param room_version The version of the room.
 * @return The event ID as a base64 string.
 * @throw std::runtime_error If the base64 encoding fails.
 */
[[nodiscard]] std::string event_id(const json &event,
                                   const std::string_view room_version) {
  if (event == nullptr) {
    throw std::invalid_argument("Event cannot be null");
  }
  const auto hash = reference_hash(event, room_version);

  const unsigned long long hash_len = hash.size();
  const size_t base64_max_len = sodium_base64_encoded_len(
      hash_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

  std::string base64_str(base64_max_len - 1, 0);
  const auto *encoded_str_char =
      sodium_bin2base64(base64_str.data(), base64_max_len, hash.data(),
                        hash_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  if (encoded_str_char == nullptr) {
    throw std::runtime_error("Base64 Error: Failed to encode string");
  }

  return std::format("${}", base64_str);
}

/**
 * @brief Implements the state resolution algorithm version 2 (state_res_v2) as
 * per Matrix protocol.
 *
 * This function takes a vector of vectors of StateEvent objects, where each
 * inner vector represents a fork of events. It first splits the events into
 * conflicted and unconflicted sets. Then, it creates a partial state from the
 * unconflicted events. It also finds the difference between the conflicted
 * events and the authorization events of the forks. The function then
 * classifies the conflicted events into control events and other events.
 * Control events are those that affect the power level, join rules, or
 * membership of the room. The function sorts the control events using Kahn's
 * algorithm, which is a topological sorting algorithm. It then authorizes each
 * control event against the partial state and adds it to the partial state if
 * it is authorized. The function also builds the power level mainline, which is
 * a sequence of power level events that are authorization events of each other.
 * It then sorts the other events based on their position on the mainline,
 * origin server timestamp, and event ID. It authorizes each of these events
 * against the partial state and adds it to the partial state if it is
 * authorized. Finally, it adds the unconflicted events to the partial state and
 * returns the partial state.
 *
 * @param forks A vector of vectors of StateEvent objects representing the forks
 * of events.
 * @return A map of event types to maps of state keys to StateEvents
 * representing the resolved state.
 */
[[nodiscard]] std::map<EventType, std::map<StateKey, StateEvent>>
stateres_v2(const std::vector<std::vector<StateEvent>> &forks) {
  auto [conflictedEvents, unconflictedEvents] = splitEvents(forks);
  auto partial_state = createPartialState(unconflictedEvents);

  auto auth_difference = findAuthDifference(conflictedEvents, forks);

  std::vector<StateEvent> full_conflicted_set;
  std::vector<StateEvent> conflicted_control_events;
  std::vector<StateEvent> conflicted_others;
  full_conflicted_set.reserve(conflictedEvents.size() + auth_difference.size());
  full_conflicted_set.insert(full_conflicted_set.end(),
                             conflictedEvents.begin(), conflictedEvents.end());
  full_conflicted_set.insert(full_conflicted_set.end(), auth_difference.begin(),
                             auth_difference.end());

  // is_control_event returns true if the event meets the criteria for being
  // classed as a "control" event for reverse topological sorting. If not then
  // the event will be mainline sorted.
  auto is_control_event = [](StateEvent event) {
    if (event["type"].get<std::string_view>() == "m.room.power_levels") {
      // Power level events with an empty state key are control events.
      if (event["state_key"].get<std::string_view>().empty()) {
        return true;
      }
    }
    if (event["type"].get<std::string_view>() == "m.room.join_rules") {
      // Join rule events with an empty state key are control events.
      if (event["state_key"].get<std::string_view>().empty()) {
        return true;
      }
    }
    if (event["type"].get<std::string_view>() == "m.room.member") {
      // Membership events must not have an empty state key.
      if (event["state_key"].get<std::string_view>().empty()) {
        return false;
      }
      // Membership events are only control events if the sender does not match
      // the state key, i.e. because the event is caused by an admin or
      // moderator.
      if (event["state_key"].get<std::string_view>() ==
          event["sender"].get<std::string_view>()) {
        return false;
      }
      // Membership events are only control events if the "membership" key in
      // the content is "leave" or "ban" so we need to extract the content.
      if (event["content"]["membership"].get<std::string_view>() == "leave" ||
          event["content"]["membership"].get<std::string_view>() == "ban") {
        return true;
      }
    }
    return false;
  };

  // Copy the full_conflicted_set so we can partition it
  std::vector<StateEvent> full_conflicted_set_copy = full_conflicted_set;

  // Partition the vector based on the boolean condition
  auto partition_point =
      std::partition(full_conflicted_set_copy.begin(),
                     full_conflicted_set_copy.end(), is_control_event);
  // Copy elements based on the partition point
  conflicted_control_events = std::vector<StateEvent>(
      std::make_move_iterator(full_conflicted_set_copy.begin()),
      std::make_move_iterator(partition_point));
  conflicted_others = std::vector<StateEvent>(
      std::make_move_iterator(partition_point),
      std::make_move_iterator(full_conflicted_set_copy.end()));

  // Step 1 of state resolution algorithm:
  // Select the set X of all power events that appear in the full conflicted
  // set. For each such power event P, enlarge X by adding the events in the
  // auth chain of P which also belong to the full conflicted set. Sort X into a
  // list using the reverse topological power ordering.

  // Build a set of event IDs in the full conflicted set for quick lookup
  std::set<EventID> full_conflicted_event_ids;
  for (const auto &event : full_conflicted_set) {
    full_conflicted_event_ids.insert(event.at("event_id").get<EventID>());
  }

  // Build event map for auth chain lookups
  std::map<EventID, StateEvent> full_conflicted_event_map;
  for (const auto &event : full_conflicted_set) {
    full_conflicted_event_map[event.at("event_id").get<EventID>()] = event;
  }

  // Expand power events with their auth chain events that are also in the full
  // conflicted set
  std::set<EventID> power_events_expanded_ids;
  std::function<void(const EventID &)> expand_auth_chain =
      [&](const EventID &event_id) {
        if (!full_conflicted_event_ids.contains(event_id) ||
            power_events_expanded_ids.contains(event_id)) {
          return;
        }
        power_events_expanded_ids.insert(event_id);

        // Recursively add auth events that are in the full conflicted set
        const auto &event = full_conflicted_event_map.at(event_id);
        if (event.contains("auth_events")) {
          for (const auto &auth_event_id :
               event.at("auth_events").get<std::vector<std::string>>()) {
            if (full_conflicted_event_ids.contains(auth_event_id)) {
              expand_auth_chain(auth_event_id);
            }
          }
        }
      };

  // Start with power events (control events) and expand their auth chains
  for (const auto &event : conflicted_control_events) {
    expand_auth_chain(event.at("event_id").get<EventID>());
  }

  // Build the expanded power events vector
  std::vector<StateEvent> power_events_for_sorting;
  for (const auto &event_id : power_events_expanded_ids) {
    power_events_for_sorting.push_back(full_conflicted_event_map.at(event_id));
  }

  // Sort power events using reverse topological power ordering (Kahn's
  // algorithm)
  auto conflicted_control_events_sorted =
      kahns_algorithm(power_events_for_sorting);

  // Step 2: Apply iterative auth checks to get partially resolved state
  for (auto &event : conflicted_control_events_sorted) {
    if (auth_against_partial_state(partial_state, event)) {
      auto event_type = event["type"].get<EventType>();
      auto state_key = event["state_key"].get<StateKey>();
      partial_state[event_type][state_key] = event;
    }
  }

  // We might end up with a new room so we need to harvest the power level event
  // from the conflicted_control_events_sorted if resolved_power_level_event is
  // null.
  // TODO: Check if this is correct?
  auto resolved_power_level_event = partial_state["m.room.power_levels"][""];
  if (resolved_power_level_event.is_null()) {
    for (auto &event : conflicted_control_events_sorted) {
      if (event["type"].get<std::string_view>() == "m.room.power_levels") {
        resolved_power_level_event = event;
        break;
      }
    }
    if (resolved_power_level_event.is_null()) {
      throw std::runtime_error(
          "No power level event found in conflicted_control_events_sorted. "
          "This should not happen I think as we artificially always inject "
          "one.");
    }
  }
  std::vector<StateEvent> power_level_mainline = {resolved_power_level_event};

  // Build event_id -> StateEvent map for O(1) lookups in mainline functions
  std::map<EventID, StateEvent> event_id_lookup_map;
  for (const auto &[event_type, inner_map] : partial_state) {
    for (const auto &[state_key, state_event] : inner_map) {
      if (state_event.contains("event_id")) {
        event_id_lookup_map[state_event.at("event_id").get<EventID>()] =
            state_event;
      }
    }
  }

  std::set<std::string> mainline_visited;
  mainline_iterate(power_level_mainline, resolved_power_level_event,
                   event_id_lookup_map, mainline_visited);

  // Call get_closest_mainline_event for each event in conflicted_others so we
  // have the data required for the next step.
  for (auto &event : conflicted_others) {
    auto closest_mainline_event = get_closest_mainline_event(
        power_level_mainline, event, event_id_lookup_map);

    // Get the position of the closest mainline event on the mainline (partial
    // state) by using the distance to the create event from the closest
    // mainline event based on the ordering in the partial state vector.
    auto position_on_mainline = std::distance(
        power_level_mainline.begin(),
        std::ranges::find(power_level_mainline, closest_mainline_event));
    event["position_on_mainline"] = std::to_string(position_on_mainline);
  }

  for (auto sorted_others = sorted_normal_state_events(conflicted_others);
       auto &event : sorted_others) {
    if (auth_against_partial_state(partial_state, event)) {
      auto event_type = event["type"].get<EventType>();
      auto state_key = event["state_key"].get<StateKey>();
      partial_state[event_type][state_key] = event;
    }
  }

  for (auto &event : unconflictedEvents) {
    auto event_type = event["type"].get<EventType>();
    auto state_key = event["state_key"].get<StateKey>();
    partial_state[event_type][state_key] = event;
  }

  return partial_state;
}

std::vector<std::string> select_auth_events_for_join(
    const json &create_event, const std::optional<json> &power_levels,
    const std::optional<json> &join_rules,
    const std::optional<json> &target_membership,
    const std::optional<json> &auth_user_membership,
    std::string_view room_version) {

  std::vector<std::string> auth_events;

  // 1. Always include the m.room.create event
  if (!create_event.contains("event_id")) {
    throw std::runtime_error("create_event must have event_id");
  }
  auth_events.push_back(create_event["event_id"].get<std::string>());

  // 2. Include m.room.power_levels if present
  if (power_levels.has_value() && power_levels->contains("event_id")) {
    auth_events.push_back(power_levels.value()["event_id"].get<std::string>());
  }

  // 3. For join events, include m.room.join_rules if present
  if (join_rules.has_value() && join_rules->contains("event_id")) {
    auth_events.push_back(join_rules.value()["event_id"].get<std::string>());
  }

  // 4. Include target's current membership if they have one
  // (This is the target user's existing m.room.member event, if any)
  if (target_membership.has_value() &&
      target_membership->contains("event_id")) {
    auth_events.push_back(
        target_membership.value()["event_id"].get<std::string>());
  }

  // 5. For restricted room joins (room versions 8+), include the authorizing
  // user's membership if join_authorised_via_users_server will be used
  if (auth_user_membership.has_value() &&
      auth_user_membership->contains("event_id") &&
      (room_version == "8" || room_version == "9" || room_version == "10" ||
       room_version == "11")) {
    auth_events.push_back(
        auth_user_membership.value()["event_id"].get<std::string>());
  }

  return auth_events;
}
