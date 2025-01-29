#pragma once

#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string>
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

[[nodiscard]] json redact(const json &event, const std::string &room_version);

[[nodiscard]] std::vector<unsigned char>
reference_hash(const json &event, const std::string &room_version);

[[nodiscard]] std::string event_id(const json &event,
                                   const std::string &room_version);

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
[[nodiscard]] constexpr bool matchDomain(const std::string &str1,
                                         const std::string &str2) {
  // Find the position of ':' in the strings
  const size_t pos1 = str1.find(':');
  const size_t pos2 = str2.find(':');

  // Extract the domain parts after ':'
  const std::string domain1 = str1.substr(pos1 + 1);
  const std::string domain2 = str2.substr(pos2 + 1);

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

// NOTE: THIS ONLY WORKS FOR THE ROOM CREATION CURRENTLY!
constexpr void
find_auth_event_for_event_on_create(std::vector<StateEvent> &events,
                                    const std::string &room_version) {
  // We need to linearly add events to the known_events. An event can never
  // reference itself or the event after it.
  std::vector<StateEvent> known_events;

  for (auto &outermost_event : events) {
    if (outermost_event["type"] == "m.room.create") {
      outermost_event["auth_events"] = json::array();
      known_events.push_back(outermost_event);
      continue;
    }

    std::vector<std::string> auth_events;

    // Add the m.room.create event_id from the events array to the auth events
    // array
    for (const auto &event : known_events) {
      if (event["type"] == "m.room.create") {
        auth_events.push_back(event["event_id"].get<std::string>());
      }
    }

    // If we didnt add the m.room.create event above -> throw an error. It
    // should always be present
    if (auth_events.empty()) {
      throw std::runtime_error("m.room.create event not found in events array");
    }

    // Add m.room.power_levels event_id to the auth events array, if any
    for (const auto &event : known_events) {
      if (event["type"] == "m.room.power_levels") {
        auth_events.push_back(event["event_id"].get<std::string>());
      }
    }

    // Add the sender's m.room.member event_id to the auth events array, if any
    std::optional<json> sender_membership = std::nullopt;
    for (const auto &event : known_events) {
      if (event["type"] == "m.room.member" &&
          event["state_key"] == outermost_event["sender"]) {
        sender_membership = event;
        auth_events.push_back(event["event_id"].get<std::string>());
      }
    }

    // If the type is m.room.member...
    if (outermost_event["type"] == "m.room.member") {
      // ... add the target's m.room.member event_id to the auth events array,
      // if any (also dont add it if target == sender)
      for (const auto &target : known_events) {
        if (target["type"] == "m.room.member" &&
            target["state_key"] == outermost_event["state_key"]) {
          // If we have sender_membership and the sender_membership state_key is
          // not the target's state_key
          if (sender_membership.has_value() &&
              sender_membership.value()["state_key"] != target["state_key"]) {
            auth_events.push_back(target["event_id"].get<std::string>());
          }
        }
      }

      // ... if joining or inviting
      if (outermost_event["content"]["membership"] == "join" ||
          outermost_event["content"]["membership"] == "invite") {
        // ... add the m.room.join_rules event_id to the auth events array, if
        // any
        for (const auto &event : known_events) {
          if (event["type"] == "m.room.join_rules") {
            auth_events.push_back(event["event_id"].get<std::string>());
          }
        }
      }

      // ... if inviting, and it's a third party invite...
      if (outermost_event["content"]["membership"] == "invite" &&
          outermost_event["content"].contains("third_party_invite")) {
        // ... the matching m.room.third_party_invite event
        // TODO:: if the token can't be found, the event is invalid. This should
        // be checked before this function. The event MUST also exist.
        const auto current_count = auth_events.size();
        for (const auto &event : known_events) {
          if (event["type"] == "m.room.third_party_invite") {
            auth_events.push_back(event["event_id"].get<std::string>());
          }
        }

        // If current_count didnt increase we did not find the invite. This
        // means that we need to throw an exception. This is invalid
        if (auth_events.size() == current_count) {
          throw std::runtime_error("Auth events selection failure: could not "
                                   "find matching third party invite");
        }
      }

      // ... if joining through another server and the room version supports it
      // (8, 9, 10, 11 at the time of writing)
      if (outermost_event["content"].contains(
              "join_authorised_via_users_server") &&
          (room_version == "8" || room_version == "9" || room_version == "10" ||
           room_version == "11")) {
        // ... the m.room.member event for the referenced user
        // (join_authorised_via_users_server) (if the user does not get found ->
        // throw an exception)
        const auto current_count = auth_events.size();
        for (const auto &event : known_events) {
          if (event["type"] == "m.room.member" &&
              event["state_key"] ==
                  outermost_event["content"]
                                 ["join_authorised_via_users_server"]) {
            auth_events.push_back(event["event_id"].get<std::string>());
          }
        }

        if (auth_events.size() == current_count) {
          throw std::runtime_error("Auth events selection failure: could not "
                                   "find matching  via membership event");
        }
      }
    }

    // Remove own event_id from the auth events array as that is not allowed
    std::erase(auth_events, outermost_event["event_id"].get<std::string>());

    // Add the auth events to the event
    outermost_event["auth_events"] = auth_events;
    known_events.push_back(outermost_event);
  }
}
