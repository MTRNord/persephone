#pragma once

/// @file
/// @brief A wrapper for the database operations to ensure they are uniform.
#include "drogon/drogon.h"
#include <cstdint>
#include <memory>
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
#include <string>
#include <string_view>
#include <webserver/json.hpp>

using json = nlohmann::json;

/**
 * @brief A wrapper for database operations. This is intentionally stateless and
 * not a cache.
 */
class Database {
public:
  static void migrate();

  struct [[nodiscard]] UserCreationData {
    std::string matrix_id;
    std::optional<std::string> device_id;
    std::optional<std::string> device_name;
    std::string password;
  };

  struct [[nodiscard]] UserCreationResp {
    std::string access_token;
    std::string device_id;
  };

  struct [[nodiscard]] UserInfo {
    // Optional for appservices
    std::optional<std::string> device_id;
    bool is_guest;
    std::string user_id;
  };

  struct [[nodiscard]] LoginData {
    std::string matrix_id;
    std::string password;
    std::optional<std::string> initial_device_name;
    std::optional<std::string> device_id;
  };

  [[nodiscard]] static drogon::Task<Database::UserCreationResp>
  create_user(UserCreationData const data);

  [[nodiscard]] static drogon::Task<bool>
  user_exists(std::string_view matrix_id);

  [[nodiscard]] static drogon::Task<std::optional<Database::UserInfo>>
  get_user_info(const std::string_view auth_token);

  [[nodiscard]] static drogon::Task<bool>
  validate_access_token(std::string_view auth_token);

  [[nodiscard]] static drogon::Task<client_server_json::login_resp>
  login(LoginData login_data);

  [[nodiscard]] static drogon::Task<void>
  add_room(const std::shared_ptr<drogon::orm::Transaction> transaction,
           std::vector<json> events, const std::string_view room_id);

  [[nodiscard]] static drogon::Task<void>
  add_event(const std::shared_ptr<drogon::orm::Transaction> transaction,
            json event, const std::string_view room_id);

  [[nodiscard]] static drogon::Task<json>
  get_state_event(const std::string_view room_id,
                  const std::string_view event_type,
                  const std::string_view state_key);

  [[nodiscard]] static drogon::Task<json>
  get_pushrules_for_user(const std::string user_id);

  [[nodiscard]] static drogon::Task<std::optional<std::string>>
  set_filter(std::string user_id, json filter);

  [[nodiscard]] static drogon::Task<json> get_filter(std::string user_id,
                                                     std::string filter_id);

  // Room query methods for federation
  [[nodiscard]] static drogon::Task<bool> room_exists(std::string_view room_id);

  [[nodiscard]] static drogon::Task<std::optional<std::string>>
  get_room_version(std::string_view room_id);

  [[nodiscard]] static drogon::Task<std::optional<std::string>>
  get_membership(std::string_view room_id, std::string_view user_id);

  [[nodiscard]] static drogon::Task<std::optional<json>>
  get_join_rules(std::string_view room_id);

  /// Get events needed for auth_events in a join event
  /// Returns: create event, power_levels, join_rules, and optionally
  /// target membership
  struct AuthEventsForJoin {
    json create_event;
    std::optional<json> power_levels;
    std::optional<json> join_rules;
    std::optional<json> target_membership;
  };

  [[nodiscard]] static drogon::Task<std::optional<AuthEventsForJoin>>
  get_auth_events_for_join(std::string_view room_id, std::string_view user_id);

  /// Get the current room head events (latest events with no children)
  [[nodiscard]] static drogon::Task<std::vector<std::string>>
  get_room_heads(std::string_view room_id);

  /// Get the maximum depth of events in a room
  [[nodiscard]] static drogon::Task<int64_t>
  get_max_depth(std::string_view room_id);

  // Server key caching for federation signature verification
  struct CachedServerKey {
    std::string public_key;
    int64_t valid_until_ts;
    int64_t fetched_at;
  };

  /// Get a cached server signing key
  [[nodiscard]] static drogon::Task<std::optional<CachedServerKey>>
  get_cached_server_key(std::string_view server_name, std::string_view key_id);

  /// Store a server signing key in the cache
  [[nodiscard]] static drogon::Task<void>
  cache_server_key(std::string_view server_name, std::string_view key_id,
                   std::string_view public_key, int64_t valid_until_ts);

  /// Delete expired or stale server keys (valid_until_ts < now or fetched_at
  /// older than max_age_ms)
  [[nodiscard]] static drogon::Task<void>
  cleanup_expired_server_keys(int64_t max_age_ms);

  // ============================================================================
  // Sync API queries
  // ============================================================================

  /// Room membership info for sync
  struct [[nodiscard]] RoomMembership {
    std::string room_id;
    int room_nid;
    std::string membership; // "join", "invite", "leave", "ban", "knock"
    int64_t event_nid;
  };

  /// Get all rooms where user has a membership state event
  [[nodiscard]] static drogon::Task<std::vector<RoomMembership>>
  get_user_room_memberships(std::string_view user_id);

  /// Get current state for a room (all state events where end_index IS NULL)
  [[nodiscard]] static drogon::Task<std::vector<json>>
  get_current_room_state(int room_nid);

  /// Timeline query result
  struct [[nodiscard]] TimelineResult {
    std::vector<json> events;
    bool limited;
    std::optional<std::string> prev_batch;
  };

  /// Get timeline events for a room since a given event_nid
  /// @param room_nid The room's numeric ID
  /// @param since_event_nid Only return events after this nid (0 for all)
  /// @param limit Maximum number of events to return
  [[nodiscard]] static drogon::Task<TimelineResult>
  get_room_timeline(int room_nid, int64_t since_event_nid, int limit);

  /// Get state changes for a room between two event_nids (for incremental sync)
  [[nodiscard]] static drogon::Task<std::vector<json>>
  get_state_delta(int room_nid, int64_t from_event_nid, int64_t to_event_nid);

  /// Get global account data for a user
  [[nodiscard]] static drogon::Task<std::vector<json>>
  get_account_data(std::string_view user_id);

  /// Get room-specific account data for a user
  [[nodiscard]] static drogon::Task<std::vector<json>>
  get_room_account_data(std::string_view user_id, std::string_view room_id);

  /// Get the maximum event_nid across all rooms
  [[nodiscard]] static drogon::Task<int64_t> get_max_event_nid();

  /// Get the maximum event_nid for rooms the user is in since a given nid
  [[nodiscard]] static drogon::Task<int64_t>
  get_max_event_nid_for_user_rooms(std::string_view user_id,
                                   int64_t since_event_nid);

  /// Get stripped state for an invite (limited state for invited rooms)
  [[nodiscard]] static drogon::Task<std::vector<json>>
  get_invite_stripped_state(int room_nid, std::string_view invited_user_id);
};
