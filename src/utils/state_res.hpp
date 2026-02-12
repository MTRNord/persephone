#pragma once

#include <map>
#ifdef __GNUC__
// Ignore false positives (see https://github.com/nlohmann/json/issues/3808)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "nlohmann/json.hpp"
#pragma GCC diagnostic pop
#else
#include <nlohmann/json.hpp>
#endif
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

using json = nlohmann::json;

// Define StateEvent as json::object_t
using StateEvent = json;
enum ForkID : int;
using EventID = std::string;
using EventType = std::string;
using StateKey = std::string;

/**
 * @brief A structure to hold sets of conflicted and unconflicted state events.
 *
 * This structure contains two vectors of StateEvent objects.
 * The conflictedEvents vector holds the state events that have conflicts, i.e.,
 * events that have the same state key but different event IDs. The
 * unconflictedEvents vector holds the state events that do not have any
 * conflicts, i.e., events that have unique state keys.
 *
 * @details The StateEventSets structure is used in the state resolution
 * algorithm to separate the events into conflicted and unconflicted sets before
 * processing them.
 */
struct [[nodiscard]] StateEventSets {
  std::vector<StateEvent> conflictedEvents;
  std::vector<StateEvent> unconflictedEvents;
};

[[nodiscard]] json redact(const json &event,
                          const std::string_view room_version);

[[nodiscard]] std::vector<unsigned char>
reference_hash(const json &event, const std::string_view room_version);

[[nodiscard]] std::string event_id(const json &event,
                                   const std::string_view room_version);

/// Compute the content hash for an event per the Matrix spec.
/// Removes unsigned, signatures, and hashes, then SHA-256 of canonical JSON.
/// Returns the hash as unpadded standard base64.
/// Dispatches to version-specific implementation based on room_version.
[[nodiscard]] std::string content_hash(const json &event,
                                       std::string_view room_version);

/// Sign an event per the Matrix spec: redact according to room version, remove
/// signatures + unsigned, sign the canonical JSON, then add the signature to the
/// original (non-redacted) event. Use this for signing Matrix events (not
/// general JSON like federation request auth headers -- use json_utils::sign_json
/// for those).
[[nodiscard]] json sign_event(json event, std::string_view room_version,
                              const std::string &server_name,
                              const std::string &key_id,
                              const std::vector<unsigned char> &private_key);

/// Finalize an event into a complete PDU: computes content hash, signs, and
/// computes event_id. The event must already have all semantic fields set
/// (type, content, sender, state_key, room_id, origin_server_ts, auth_events,
/// prev_events, depth).
[[nodiscard]] json finalize_event(json event, std::string_view room_version,
                                  const std::string &server_name,
                                  const std::string &key_id,
                                  const std::vector<unsigned char> &private_key);

/// Finalize all events for room creation. Sets auth_events, prev_events, depth,
/// computes content hash, event_id, and signs each event. Replaces
/// find_auth_event_for_event_on_create + separate signing loop.
void finalize_room_creation_events(
    std::vector<StateEvent> &events, std::string_view room_version,
    const std::string &server_name, const std::string &key_id,
    const std::vector<unsigned char> &private_key);

/**
 * @brief Compares the domain parts of two strings.
 *
 * This function takes two strings as input, each expected to contain a domain
 * part after a ':' character. It finds the position of ':' in each string and
 * extracts the domain part after ':'. It then compares the domain parts of the
 * two strings and returns true if they are equal, false otherwise.
 *
 * @param str1 The first string to be compared.
 * @param str2 The second string to be compared.
 * @return A boolean value indicating whether the domain parts of the two
 * strings are equal.
 */
[[nodiscard]] constexpr bool matchDomain(const std::string_view str1,
                                         const std::string_view str2) {
  // If they are empty there is no domain to compare
  if (str1.empty() || str2.empty()) {
    return false;
  }

  // Find the position of ':' in the strings
  const size_t pos1 = str1.find(':');
  const size_t pos2 = str2.find(':');

  // If either string doesn't contain a ':', there's no valid domain to compare
  if (pos1 == std::string_view::npos || pos2 == std::string_view::npos) {
    return false;
  }

  // Extract the domain parts after ':'
  const std::string_view domain1 = str1.substr(pos1 + 1);
  const std::string_view domain2 = str2.substr(pos2 + 1);

  // Compare the domain parts
  return domain1 == domain2;
}

/**
 * @brief Finds the difference between the conflicted events and the
 * authorization events of the forks.
 *
 * This function takes a vector of conflicted StateEvent objects and a vector of
 * vectors of StateEvent objects representing the forks as input. It iterates
 * over each conflicted event and checks if it is present in all the forks. If a
 * conflicted event is not found in any of the forks, it is considered as part
 * of the difference and is added to the authDifference vector. Finally, the
 * function returns the authDifference vector.
 *
 * @param conflictedEvents A vector of conflicted StateEvent objects.
 * @param forks A vector of vectors of StateEvent objects representing the
 * forks.
 * @return A vector of StateEvent objects representing the difference between
 * the conflicted events and the authorization events of the forks.
 */
[[nodiscard]] constexpr std::vector<StateEvent>
findAuthDifference(const std::vector<StateEvent> &conflictedEvents,
                   const std::vector<std::vector<StateEvent>> &forks) {
  std::vector<StateEvent> authDifference;

  for (const auto &event : conflictedEvents) {
    bool found = true;

    for (const auto &authSet : forks) {
      if (std::ranges::find(authSet, event) == authSet.end()) {
        found = false;
        break;
      }
    }

    if (!found) {
      authDifference.push_back(event);
    }
  }

  return authDifference;
}

[[nodiscard]] std::map<EventType, std::map<StateKey, StateEvent>>
stateres_v2(const std::vector<std::vector<StateEvent>> &forks);

/// Set of candidate state events for auth events selection.
/// Pass the relevant current state events; the selection algorithm will pick
/// which ones to include as auth_events based on the event being built.
struct [[nodiscard]] AuthEventSet {
  json create_event;
  std::optional<json> power_levels;
  std::optional<json> sender_membership;
  std::optional<json> target_membership;    // for member events (state_key != sender)
  std::optional<json> join_rules;           // for member join/invite
  std::optional<json> third_party_invite;   // for 3PID invites
  std::optional<json> auth_user_membership; // for restricted joins (room v8+)
};

/// Select auth_events for any event type per the Matrix spec auth events
/// selection algorithm.
/// @param event The event being built (needs type, sender, content, state_key)
/// @param state The candidate state events to select from
/// @param room_version The room version
/// @return Vector of event_ids to use as auth_events
[[nodiscard]] std::vector<std::string>
select_auth_events(const json &event, const AuthEventSet &state,
                   std::string_view room_version);

/// Get the power level of a sender from a power_levels event.
/// Checks content.users[sender] first, then falls back to
/// content.users_default, then 0.
[[nodiscard]] int get_sender_power_level(const json &power_levels_event,
                                         const std::string &sender);
