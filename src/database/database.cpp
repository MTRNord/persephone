#include "database.hpp"
#include "database/migrations/migrator.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <drogon/HttpAppFramework.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/utils/coroutine.h>
#include <exception>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

void Database::migrate() { Migrator::migrate(); }

static constexpr std::size_t DEVICE_ID_LENGTH = 7;
static constexpr int TOKEN_RANDOM_PART_LENGTH = 20;

[[nodiscard]] drogon::Task<Database::UserCreationResp>
Database::create_user(Database::UserCreationData const data) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  const auto transPtr = co_await sql->newTransactionCoro();
  if (transPtr == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  // TODO: If we have a guest registering we are required to always
  // generate this.
  auto device_id = data.device_id.value_or(random_string(DEVICE_ID_LENGTH));
  auto password_hash = hash_password(std::string(data.password));
  auto matrix_id = data.matrix_id;
  auto device_name = data.device_name.value_or(random_string(DEVICE_ID_LENGTH));

  // This token should have this pattern:
  // `persephone_<unpadded base64 local part of the matrix
  // id>_<random string (20 chars)>_<base62 crc32 check>`
  auto localpart_str = localpart(matrix_id);
  const std::vector<unsigned char> localpart_vec(localpart_str.begin(),
                                                 localpart_str.end());

  auto random_component = random_string(TOKEN_RANDOM_PART_LENGTH);
  auto access_token = std::format(
      "persephone_{}_{}_{}", json_utils::base64_urlencoded(localpart_vec),
      random_component,
      base62_encode(
          crc32_helper(std::format("{}_{}", matrix_id, random_component))));

  try {
    co_await transPtr->execSqlCoro(
        "INSERT INTO users(matrix_id, password_hash) VALUES($1, $2)", matrix_id,
        password_hash);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to create user due to database error");
  }

  // Create the default pushrules for the user
  try {
    const auto default_rules = get_default_pushrules(std::string(matrix_id));
    co_await transPtr->execSqlCoro(
        "INSERT INTO push_rules(user_id, json) VALUES($1, $2)", matrix_id,
        default_rules.dump());
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to create user due to database error");
  }

  try {
    co_await transPtr->execSqlCoro(
        "INSERT INTO devices(matrix_id, device_id, "
        "device_name, access_token) VALUES($1, $2, $3, $4)",
        matrix_id, device_id, device_name, access_token);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to create user due to database error");
  }

  Database::UserCreationResp resp_data{.access_token = access_token,
                                       .device_id = device_id};
  co_return resp_data;
}

[[nodiscard]] drogon::Task<bool>
Database::user_exists(std::string_view matrix_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    const auto query = co_await sql->execSqlCoro(
        "select exists(select 1 from users where matrix_id = $1) as exists",
        matrix_id);

    co_return query.at(0)["exists"].as<bool>();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();

    // We fail with user exists here to prevent further issues
    co_return true;
  }
}

[[nodiscard]] drogon::Task<std::optional<Database::UserInfo>>
Database::get_user_info(const std::string_view auth_token) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    const auto result = co_await sql->execSqlCoro(
        "select device_id, matrix_id from devices where access_token = $1",
        auth_token);

    std::optional<std::string> device_id;
    // TODO: track if the user is a guest in the database
    constexpr bool is_guest = false;

    if (result.empty()) {
      co_return std::nullopt;
    }

    const auto first_row = result.at(0);
    try {
      device_id = first_row["device_id"].as<std::string>();
    } catch (drogon::orm::RangeError &) {
      // No device_id set
      device_id = std::nullopt;
    }
    const auto matrix_id = first_row["matrix_id"].as<std::string>();
    UserInfo user_info{
        .device_id = device_id, .is_guest = is_guest, .user_id = matrix_id};

    co_return user_info;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return std::nullopt;
  }
}

[[nodiscard]] drogon::Task<bool>
Database::validate_access_token(std::string_view auth_token) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    const auto query =
        co_await sql->execSqlCoro("select exists(select 1 from devices "
                                  "where access_token = $1) as exists",
                                  auth_token);
    // TMP loging for complement debugging
    LOG_DEBUG << "Access token: " << auth_token;
    LOG_DEBUG << "Exists: " << query.at(0)["exists"].as<bool>();

    if (query.at(0)["exists"].as<bool>()) {
      // Check if push_rules has a rule for the user
      const auto push_rules_query = co_await sql->execSqlCoro(
          "select exists(select 1 from push_rules where user_id = "
          "(select matrix_id from devices where access_token = $1)) as exists",
          auth_token);

      if (!push_rules_query.at(0)["exists"].as<bool>()) {
        // Create the default pushrules for the user
        const auto matrix_id_query = co_await sql->execSqlCoro(
            "select matrix_id from devices where access_token = $1",
            auth_token);
        const auto matrix_id =
            matrix_id_query.at(0)["matrix_id"].as<std::string>();
        const auto default_rules = get_default_pushrules(matrix_id);
        co_await sql->execSqlCoro(
            "INSERT INTO push_rules(user_id, json) VALUES($1, $2)", matrix_id,
            default_rules.dump());
      }

      co_return true;
    }
    co_return false;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return false;
  }
}

[[nodiscard]] drogon::Task<client_server_json::login_resp>
Database::login(const LoginData login_data) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  const auto transaction = sql->newTransaction();
  try {
    // Check if user exists, check if password matches the hash we got and
    // return the access token if it does
    const auto query = co_await transaction->execSqlCoro(
        "select password_hash from users where matrix_id = $1",
        login_data.matrix_id);

    if (query.empty()) {
      throw std::runtime_error("User does not exist");
    }

    // Check if the password matches
    if (const auto password_hash =
            query.at(0)["password_hash"].as<std::string>();
        !verify_hashed_password(password_hash,
                                std::string(login_data.password))) {
      throw std::runtime_error("Password does not match");
    }

    // Create a new access token with initial_device_name if it is set
    auto device_name = login_data.initial_device_name.value_or(
        random_string(DEVICE_ID_LENGTH));

    // This token should have this pattern:
    // `persephone_<unpadded base64 local part of the matrix
    // id>_<random string (20 chars)>_<base62 crc32 check>`
    auto localpart_str = localpart(login_data.matrix_id);
    const std::vector<unsigned char> localpart_vec(localpart_str.begin(),
                                                   localpart_str.end());

    auto random_component = random_string(TOKEN_RANDOM_PART_LENGTH);
    auto access_token = std::format(
        "persephone_{}_{}_{}", json_utils::base64_urlencoded(localpart_vec),
        random_component,
        base62_encode(crc32_helper(
            std::format("{}_{}", login_data.matrix_id, random_component))));

    const auto safe_device_id = login_data.device_id.value_or(random_string(7));
    // Insert the device into the database
    co_await transaction->execSqlCoro(
        "INSERT INTO devices(matrix_id, device_id, device_name, access_token) "
        "VALUES($1, $2, $3, $4)",
        login_data.matrix_id, safe_device_id, device_name, access_token);

    // Return the access token
    co_return {.access_token = access_token,
               .device_id = safe_device_id,
               .expires_in_ms = std::nullopt,
               .home_server = std::nullopt,
               .refresh_token = std::nullopt,
               .user_id = login_data.matrix_id,
               .well_known = std::nullopt};
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to login due to database error");
  }
}

[[nodiscard]] drogon::Task<void>
Database::add_room(const std::shared_ptr<drogon::orm::Transaction> transaction,
                   std::vector<json> events, const std::string_view room_id) {
  try {
    for (const auto &event : events) {
      co_await Database::add_event(transaction, event, room_id);
    }
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to add room due to database error");
  }
}

/// Helper to format auth_events array for PostgreSQL TEXT[] insertion
static std::string format_auth_events_array(const json &event) {
  if (!event.contains("auth_events")) {
    return "{}";
  }
  const auto auth_events =
      event.at("auth_events").get<std::vector<std::string>>();
  std::string result = "{";
  for (const auto &auth_event : auth_events) {
    result += "\"" + auth_event + "\",";
  }
  if (!auth_events.empty()) {
    result.pop_back(); // Remove trailing comma
  }
  result += "}";
  return result;
}

/// SECURITY: Calculate depth locally from prev_events.
/// NEVER trust the depth field from external events to prevent depth-bomb
/// attacks.
static drogon::Task<int64_t> calculate_event_depth(
    const std::shared_ptr<drogon::orm::Transaction> &transaction,
    const json &event) {
  // Default depth for events with no prev_events (e.g., m.room.create)
  constexpr int64_t default_depth = 1;

  if (!event.contains("prev_events") || !event["prev_events"].is_array() ||
      event["prev_events"].empty()) {
    co_return default_depth;
  }

  // Extract prev_event IDs
  std::vector<std::string> prev_event_ids;
  for (const auto &prev : event["prev_events"]) {
    if (prev.is_string()) {
      prev_event_ids.push_back(prev.get<std::string>());
    }
  }

  if (prev_event_ids.empty()) {
    co_return default_depth;
  }

  // Build PostgreSQL array string for parameterized query
  std::string prev_events_array = "{";
  for (size_t i = 0; i < prev_event_ids.size(); i++) {
    if (i > 0) {
      prev_events_array += ",";
    }
    prev_events_array += "\"" + prev_event_ids[i] + "\"";
  }
  prev_events_array += "}";

  try {
    const auto depth_query = co_await transaction->execSqlCoro(
        "SELECT COALESCE(MAX(depth), 0) AS max_depth FROM events "
        "WHERE event_id = ANY($1::text[])",
        prev_events_array);
    if (!depth_query.empty()) {
      co_return depth_query.at(0)["max_depth"].as<int64_t>() + 1;
    }
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_WARN << "Could not query prev_events depths, using default: "
             << e.base().what();
  }

  co_return default_depth;
}

[[nodiscard]] drogon::Task<void>
Database::add_event(const std::shared_ptr<drogon::orm::Transaction> transaction,
                    json event, const std::string_view room_id) {
  const std::string auth_events_str = format_auth_events_array(event);
  LOG_DEBUG << "Auth events: " << auth_events_str;

  // If we got a state_key set it in the db otherwise use NULL
  std::optional<std::string> state_key = std::nullopt;
  if (event.contains("state_key")) {
    state_key = event.at("state_key").get<std::string>();
  }

  const int64_t calculated_depth =
      co_await calculate_event_depth(transaction, event);

  try {
    co_await transaction->execSqlCoro(
        "INSERT INTO events(event_id, room_id, depth, auth_events, "
        "rejected, state_key, type, json) VALUES($1, $2, $3, $4::text[], $5, "
        "$6, $7, $8)",
        event.at("event_id").get<std::string>(), room_id, calculated_depth,
        auth_events_str, false, state_key, event.at("type").get<std::string>(),
        event.dump());
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to add event due to database error");
  }

  // Update materialized views
  try {
    co_await transaction->execSqlCoro("SELECT room_view_update($1);", room_id);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to update materialized view due to "
                             "database error");
  }

  // If member event also update the user view
  if (event.at("type").get<std::string>() == "m.room.member") {
    try {
      co_await transaction->execSqlCoro(
          "SELECT user_view_update($1);",
          event.at("state_key").get<std::string>());
    } catch (const drogon::orm::DrogonDbException &e) {
      LOG_ERROR << e.base().what();
      throw std::runtime_error("Failed to update materialized view due to "
                               "database error");
    }
  }
}

/**
 * @brief Get a state event from the database
 *
 * @param room_id The room ID to get the state event from
 * @param event_type The event type to get
 * @param state_key The state key to get (this might be an empty string. This is
 * NOT the same as NULL)
 * @return The state event as a json object in it's client-server representation
 * and not as a full PDU
 */
[[nodiscard]] drogon::Task<json>
Database::get_state_event(const std::string_view room_id,
                          const std::string_view event_type,
                          const std::string_view state_key) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    // TODO: We do not respect state res ordering yet. We should do that in the
    // future
    // TODO: Use the materialized view for this
    const auto query =
        co_await sql->execSqlCoro("SELECT json FROM events WHERE room_id = $1 "
                                  "AND type = $2 AND state_key = $3",
                                  room_id, event_type, state_key);

    if (query.empty()) {
      throw std::runtime_error("State event not found");
    }

    auto json_data = json::parse(query.at(0)["json"].as<std::string>());
    // Remove the signatures from the state event
    json_data.erase("signatures");
    co_return json_data;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to get state event due to database error");
  }
}

[[nodiscard]] drogon::Task<json>
Database::get_pushrules_for_user(std::string user_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    const auto query = co_await sql->execSqlCoro(
        "SELECT json FROM push_rules WHERE user_id = $1", user_id);

    if (query.empty()) {
      throw std::runtime_error("Pushrules not found");
    }

    auto json_data = json::parse(query.at(0)["json"].as<std::string>());
    co_return json_data;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to get pushrules due to database error");
  }
}

[[nodiscard]] drogon::Task<std::optional<std::string>>
Database::set_filter(std::string user_id, json filter) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    // Get existing filter by content
    const auto query = co_await sql->execSqlCoro(
        "SELECT user_ids FROM filters WHERE json = $1", filter.dump());

    if (query.empty()) {
      // Insert a new filter
      const auto query_result = co_await sql->execSqlCoro(
          "INSERT INTO filters(user_ids, json) VALUES(ARRAY [$1], "
          "$2) RETURNING id",
          user_id, filter.dump());
      // Return the id as a string
      co_return query_result.at(0)["id"].as<std::string>();
    }

    // Check for all rows found if the user_id is already in the user_ids
    // array
    for (const auto &row : query) {
      const std::vector<std::shared_ptr<std::string>> user_ids =
          row["user_ids"].asArray<std::string>();
      const auto it = std::ranges::find_if(
          user_ids, [&user_id](const auto &id) { return *id == user_id; });
      if (it != user_ids.end()) {
        // Update the filter with the new user_id
        const auto query_result = co_await sql->execSqlCoro(
            "UPDATE filters SET user_ids = array_append(user_ids, $1) WHERE "
            "json = $2 RETURNING id",
            user_id, filter.dump());
        co_return query_result.at(0)["id"].as<std::string>();
      }
    }
    // If we reach here, the user_id is not in any of the user_ids arrays
    co_return std::nullopt;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to get filter due to database error");
  }
}

drogon::Task<json> Database::get_filter(std::string user_id,
                                        std::string filter_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    // Get filter by id. Also then check if the user id is in the user_ids
    // array. Otherwise throw.
    const auto query = co_await sql->execSqlCoro(
        "SELECT json, user_ids FROM filters WHERE id = $1", filter_id);

    if (query.empty()) {
      throw std::runtime_error("Filter not found");
    }

    // Check if the user_id is in the user_ids array
    const std::vector<std::shared_ptr<std::string>> user_ids =
        query.at(0)["user_ids"].asArray<std::string>();
    const auto it = std::ranges::find_if(
        user_ids, [&user_id](const auto &id) { return *id == user_id; });
    if (it == user_ids.end()) {
      throw std::runtime_error("User not allowed to access filter");
    }

    // Return the json filter
    co_return json::parse(query.at(0)["json"].as<std::string>());
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to get filter due to database error");
  }
}

[[nodiscard]] drogon::Task<bool>
Database::room_exists(std::string_view room_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    // Check if any events exist for this room (the room exists if we have its
    // create event)
    const auto query = co_await sql->execSqlCoro(
        "SELECT EXISTS(SELECT 1 FROM events WHERE room_id = $1 AND type = "
        "'m.room.create') AS exists",
        room_id);

    co_return query.at(0)["exists"].as<bool>();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return false;
  }
}

[[nodiscard]] drogon::Task<std::optional<std::string>>
Database::get_room_version(std::string_view room_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    // Get the m.room.create event and extract room_version from content
    const auto query = co_await sql->execSqlCoro(
        "SELECT json FROM events WHERE room_id = $1 AND type = 'm.room.create' "
        "LIMIT 1",
        room_id);

    if (query.empty()) {
      co_return std::nullopt;
    }

    const auto create_event =
        json::parse(query.at(0)["json"].as<std::string>());

    // Room version is in content.room_version
    // If not present, it's room version 1 or 2 (legacy)
    if (create_event.contains("content") &&
        create_event["content"].contains("room_version")) {
      co_return create_event["content"]["room_version"].get<std::string>();
    }

    // Default to version "1" if not specified (legacy behavior)
    co_return "1";
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return std::nullopt;
  }
}

[[nodiscard]] drogon::Task<std::optional<std::string>>
Database::get_membership(std::string_view room_id, std::string_view user_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    // Get the latest m.room.member event for this user in this room
    const auto query = co_await sql->execSqlCoro(
        "SELECT json FROM events WHERE room_id = $1 AND type = 'm.room.member' "
        "AND state_key = $2 ORDER BY depth DESC LIMIT 1",
        room_id, user_id);

    if (query.empty()) {
      co_return std::nullopt;
    }

    const auto member_event =
        json::parse(query.at(0)["json"].as<std::string>());

    if (member_event.contains("content") &&
        member_event["content"].contains("membership")) {
      co_return member_event["content"]["membership"].get<std::string>();
    }

    co_return std::nullopt;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return std::nullopt;
  }
}

[[nodiscard]] drogon::Task<std::optional<json>>
Database::get_join_rules(std::string_view room_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    // Get the latest m.room.join_rules event
    const auto query = co_await sql->execSqlCoro(
        "SELECT json FROM events WHERE room_id = $1 AND type = "
        "'m.room.join_rules' AND state_key = '' ORDER BY depth DESC LIMIT 1",
        room_id);

    if (query.empty()) {
      co_return std::nullopt;
    }

    co_return json::parse(query.at(0)["json"].as<std::string>());
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return std::nullopt;
  }
}

[[nodiscard]] drogon::Task<std::optional<Database::AuthEventsForJoin>>
Database::get_auth_events_for_join(std::string_view room_id,
                                   std::string_view user_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    AuthEventsForJoin result;

    // Get the m.room.create event (required)
    auto create_query = co_await sql->execSqlCoro(
        "SELECT json FROM events WHERE room_id = $1 AND type = 'm.room.create' "
        "LIMIT 1",
        room_id);
    if (create_query.empty()) {
      co_return std::nullopt;
    }
    result.create_event =
        json::parse(create_query.at(0)["json"].as<std::string>());

    // Get the m.room.power_levels event (optional)
    auto power_query = co_await sql->execSqlCoro(
        "SELECT json FROM events WHERE room_id = $1 AND type = "
        "'m.room.power_levels' AND state_key = '' ORDER BY depth DESC LIMIT 1",
        room_id);
    if (!power_query.empty()) {
      result.power_levels =
          json::parse(power_query.at(0)["json"].as<std::string>());
    }

    // Get the m.room.join_rules event (optional)
    auto join_rules_query = co_await sql->execSqlCoro(
        "SELECT json FROM events WHERE room_id = $1 AND type = "
        "'m.room.join_rules' AND state_key = '' ORDER BY depth DESC LIMIT 1",
        room_id);
    if (!join_rules_query.empty()) {
      result.join_rules =
          json::parse(join_rules_query.at(0)["json"].as<std::string>());
    }

    // Get the target user's current membership (optional)
    auto membership_query = co_await sql->execSqlCoro(
        "SELECT json FROM events WHERE room_id = $1 AND type = 'm.room.member' "
        "AND state_key = $2 ORDER BY depth DESC LIMIT 1",
        room_id, user_id);
    if (!membership_query.empty()) {
      result.target_membership =
          json::parse(membership_query.at(0)["json"].as<std::string>());
    }

    co_return result;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return std::nullopt;
  }
}

[[nodiscard]] drogon::Task<std::vector<std::string>>
Database::get_room_heads(std::string_view room_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    // Get events that are not referenced as prev_events by any other event
    // For now, just get the event with the highest depth
    // TODO: Implement proper DAG head tracking
    const auto query = co_await sql->execSqlCoro(
        "SELECT event_id FROM events WHERE room_id = $1 ORDER BY depth DESC "
        "LIMIT 1",
        room_id);

    std::vector<std::string> heads;
    for (const auto &row : query) {
      heads.push_back(row["event_id"].as<std::string>());
    }

    co_return heads;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return {};
  }
}

[[nodiscard]] drogon::Task<int64_t>
Database::get_max_depth(std::string_view room_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    const auto query = co_await sql->execSqlCoro(
        "SELECT COALESCE(MAX(depth), 0) AS max_depth FROM events WHERE room_id "
        "= $1",
        room_id);

    co_return query.at(0)["max_depth"].as<int64_t>();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return 0;
  }
}

[[nodiscard]] drogon::Task<std::optional<Database::CachedServerKey>>
Database::get_cached_server_key(std::string_view server_name,
                                std::string_view key_id) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    const auto query = co_await sql->execSqlCoro(
        "SELECT public_key, valid_until_ts, fetched_at FROM server_signing_keys "
        "WHERE server_name = $1 AND key_id = $2",
        server_name, key_id);

    if (query.empty()) {
      co_return std::nullopt;
    }

    CachedServerKey key;
    key.public_key = query.at(0)["public_key"].as<std::string>();
    key.valid_until_ts = query.at(0)["valid_until_ts"].as<int64_t>();
    key.fetched_at = query.at(0)["fetched_at"].as<int64_t>();
    co_return key;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return std::nullopt;
  }
}

[[nodiscard]] drogon::Task<void>
Database::cache_server_key(std::string_view server_name,
                           std::string_view key_id, std::string_view public_key,
                           int64_t valid_until_ts) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

    // Upsert the key
    co_await sql->execSqlCoro(
        "INSERT INTO server_signing_keys (server_name, key_id, public_key, "
        "valid_until_ts, fetched_at) "
        "VALUES ($1, $2, $3, $4, $5) "
        "ON CONFLICT (server_name, key_id) DO UPDATE SET "
        "public_key = EXCLUDED.public_key, "
        "valid_until_ts = EXCLUDED.valid_until_ts, "
        "fetched_at = EXCLUDED.fetched_at",
        server_name, key_id, public_key, valid_until_ts, now);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Failed to cache server key: " << e.base().what();
  }
  co_return;
}

[[nodiscard]] drogon::Task<void>
Database::cleanup_expired_server_keys(int64_t max_age_ms) {
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    const auto oldest_allowed = now - max_age_ms;

    // Delete keys that are either expired (valid_until_ts < now) or stale
    // (fetched_at < oldest_allowed)
    co_await sql->execSqlCoro(
        "DELETE FROM server_signing_keys WHERE valid_until_ts < $1 OR "
        "fetched_at < $2",
        now, oldest_allowed);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << "Failed to cleanup expired server keys: " << e.base().what();
  }
  co_return;
}