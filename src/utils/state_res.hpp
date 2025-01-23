#pragma once
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Define StateEvent as json::object_t
using StateEvent = json::object_t;
enum ForkID : int;
using EventID = std::string;
using EventType = std::string;
using StateKey = std::string;

/**
 * @brief A structure to hold sets of conflicted and unconflicted state events.
 *
 * This structure contains two vectors of StateEvent objects.
 * The conflictedEvents vector holds the state events that have conflicts, i.e., events that have the same state key but different event IDs.
 * The unconflictedEvents vector holds the state events that do not have any conflicts, i.e., events that have unique state keys.
 *
 * @details The StateEventSets structure is used in the state resolution algorithm to separate the events into conflicted and unconflicted sets before processing them.
 */
struct [[nodiscard]] StateEventSets {
  std::vector<StateEvent> conflictedEvents;
  std::vector<StateEvent> unconflictedEvents;
};

[[nodiscard]] json redact(const json &event, const std::string &room_version);

[[nodiscard]] std::vector<unsigned char> reference_hash(const json &event,
                                         const std::string &room_version);

[[nodiscard]] std::string event_id(const json &event,
                                   const std::string &room_version);

/**
 * @brief Compares the domain parts of two strings.
 *
 * This function takes two strings as input, each expected to contain a domain part after a ':' character.
 * It finds the position of ':' in each string and extracts the domain part after ':'.
 * It then compares the domain parts of the two strings and returns true if they are equal, false otherwise.
 *
 * @param str1 The first string to be compared.
 * @param str2 The second string to be compared.
 * @return A boolean value indicating whether the domain parts of the two strings are equal.
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
 * @brief Finds the difference between the conflicted events and the authorization events of the forks.
 *
 * This function takes a vector of conflicted StateEvent objects and a vector of vectors of StateEvent objects representing the forks as input.
 * It iterates over each conflicted event and checks if it is present in all the forks.
 * If a conflicted event is not found in any of the forks, it is considered as part of the difference and is added to the authDifference vector.
 * Finally, the function returns the authDifference vector.
 *
 * @param conflictedEvents A vector of conflicted StateEvent objects.
 * @param forks A vector of vectors of StateEvent objects representing the forks.
 * @return A vector of StateEvent objects representing the difference between the conflicted events and the authorization events of the forks.
 */
[[nodiscard]] constexpr std::vector<StateEvent>
findAuthDifference(const std::vector<StateEvent> &conflictedEvents,
                   const std::vector<std::vector<StateEvent> > &forks) {
  std::vector<StateEvent> authDifference;

  for (const auto &e: conflictedEvents) {
    bool found = true;

    for (const auto &authSet: forks) {
      if (std::ranges::find(authSet, e) == authSet.end()) {
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
