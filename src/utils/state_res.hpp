#pragma once
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Define StateEvent as json::object_t
using StateEvent = json::object_t;
enum ForkID : int;
using EventID = std::string;
using EventType = std::string;
using StateKey = std::string;

// Custom struct to hold conflicted and unconflicted state sets
struct [[nodiscard]] StateEventSets {
  std::vector<StateEvent> conflictedEvents;
  std::vector<StateEvent> unconflictedEvents;
};

[[nodiscard]] json redact(const json &event, const std::string &room_version);

[[nodiscard]] std::string reference_hash(const json &event,
                                         const std::string &room_version);

[[nodiscard]] std::string event_id(const json &event,
                                   const std::string &room_version);

[[nodiscard]] constexpr bool matchDomain(const std::string &str1,
                                         const std::string &str2) {
  // Find the position of ':' in the strings
  size_t pos1 = str1.find(':');
  size_t pos2 = str2.find(':');

  // Extract the domain parts after ':'
  std::string domain1 = str1.substr(pos1 + 1);
  std::string domain2 = str2.substr(pos2 + 1);

  // Compare the domain parts
  return domain1 == domain2;
}

[[nodiscard]] constexpr std::vector<StateEvent>
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
