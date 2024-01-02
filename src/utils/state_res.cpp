#include "state_res.hpp"
#include <format>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/utils.h>
#include <unordered_set>

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

json redact(const json &event, std::string room_version) {
  if (room_version == "11") {
    return v11_redact(event);
  }

  throw std::runtime_error(
      std::format("Unsupported room version: {}", room_version));
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

std::string reference_hash(const json &event, std::string room_version) {
  if (room_version == "11") {
    return reference_hash_v11(event);
  }

  throw std::runtime_error(
      std::format("Unsupported room version: {}", room_version));
}

std::string event_id(const json &event, std::string room_version) {
  auto hash = reference_hash(event, std::move(room_version));

  unsigned long long hash_len = hash.size();
  const size_t base64_max_len = sodium_base64_encoded_len(
      hash_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

  std::string base64_str(base64_max_len - 1, 0);
  auto encoded_str_char = sodium_bin2base64(
      base64_str.data(), base64_max_len, reinterpret_cast<const unsigned char *>(hash.c_str()),
      hash_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  if (encoded_str_char == nullptr) {
    throw std::runtime_error("Base64 Error: Failed to encode string");
  }

  return base64_str;
}
