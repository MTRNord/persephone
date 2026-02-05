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
    // Single query with CTE to get device info and push_rules status
    const auto query = co_await sql->execSqlCoro(
        "WITH device_info AS ("
        "  SELECT matrix_id, device_id FROM devices WHERE access_token = $1"
        "), push_exists AS ("
        "  SELECT EXISTS("
        "    SELECT 1 FROM push_rules WHERE user_id = (SELECT matrix_id FROM "
        "device_info)"
        "  ) as has_rules"
        ") "
        "SELECT d.matrix_id, d.device_id, p.has_rules "
        "FROM device_info d, push_exists p",
        auth_token);

    // TMP logging for complement debugging
    LOG_DEBUG << "Access token: " << auth_token;
    LOG_DEBUG << "Query result size: " << query.size();

    if (query.empty()) {
      co_return false;
    }

    const auto matrix_id = query.at(0)["matrix_id"].as<std::string>();
    const bool has_rules = query.at(0)["has_rules"].as<bool>();

    if (!has_rules) {
      // Create the default pushrules for the user
      const auto default_rules = get_default_pushrules(matrix_id);
      co_await sql->execSqlCoro(
          "INSERT INTO push_rules(user_id, json) VALUES($1, $2)", matrix_id,
          default_rules.dump());
    }

    co_return true;
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

  const std::string event_type = event.at("type").get<std::string>();
  const std::string event_id = event.at("event_id").get<std::string>();

  try {
    // Ensure NID lookup entries exist (using v7 migration schema)
    // Insert room_nid if not exists
    co_await transaction->execSqlCoro(
        "INSERT INTO rooms(room_id) VALUES($1) ON CONFLICT DO NOTHING",
        room_id);

    // Insert event_type_nid if not exists
    co_await transaction->execSqlCoro(
        "INSERT INTO event_types(event_type) VALUES($1) ON CONFLICT DO NOTHING",
        event_type);

    // Insert state_key_nid if not exists (only for state events)
    if (state_key.has_value()) {
      co_await transaction->execSqlCoro(
          "INSERT INTO state_keys(state_key) VALUES($1) ON CONFLICT DO NOTHING",
          state_key.value());
    }

    // Get NID values for the insert
    const auto room_nid_query = co_await transaction->execSqlCoro(
        "SELECT room_nid FROM rooms WHERE room_id = $1", room_id);
    const int room_nid = room_nid_query.at(0)["room_nid"].as<int>();

    const auto type_nid_query = co_await transaction->execSqlCoro(
        "SELECT event_type_nid FROM event_types WHERE event_type = $1",
        event_type);
    const int event_type_nid = type_nid_query.at(0)["event_type_nid"].as<int>();

    std::optional<int> state_key_nid = std::nullopt;
    if (state_key.has_value()) {
      const auto state_key_nid_query = co_await transaction->execSqlCoro(
          "SELECT state_key_nid FROM state_keys WHERE state_key = $1",
          state_key.value());
      state_key_nid = state_key_nid_query.at(0)["state_key_nid"].as<int>();
    }

    // Build prev_events_nids array
    std::string prev_events_nids_str = "{}";
    if (event.contains("prev_events") && event["prev_events"].is_array() &&
        !event["prev_events"].empty()) {
      std::vector<std::string> prev_event_ids;
      for (const auto &prev : event["prev_events"]) {
        if (prev.is_string()) {
          prev_event_ids.push_back(prev.get<std::string>());
        }
      }
      if (!prev_event_ids.empty()) {
        std::string prev_events_array = "{";
        for (size_t i = 0; i < prev_event_ids.size(); i++) {
          if (i > 0)
            prev_events_array += ",";
          prev_events_array += "\"" + prev_event_ids[i] + "\"";
        }
        prev_events_array += "}";

        const auto prev_nids_query = co_await transaction->execSqlCoro(
            "SELECT ARRAY_AGG(event_nid) as nids FROM events "
            "WHERE event_id = ANY($1::text[])",
            prev_events_array);
        if (!prev_nids_query.empty() &&
            !prev_nids_query.at(0)["nids"].isNull()) {
          prev_events_nids_str =
              prev_nids_query.at(0)["nids"].as<std::string>();
        }
      }
    }

    // Insert into events table with NID columns (v7+ schema)
    const auto insert_result = co_await transaction->execSqlCoro(
        "INSERT INTO events(event_id, room_id, depth, auth_events, "
        "rejected, state_key, type, room_nid, event_type_nid, state_key_nid, "
        "prev_events_nids) "
        "VALUES($1, $2, $3, $4::text[], $5, $6, $7, $8, $9, $10, "
        "$11::integer[]) "
        "RETURNING event_nid",
        event_id, room_id, calculated_depth, auth_events_str, false, state_key,
        event_type, room_nid, event_type_nid, state_key_nid,
        prev_events_nids_str);

    const int event_nid = insert_result.at(0)["event_nid"].as<int>();

    // Insert JSON into separate event_json table (v8 migration)
    co_await transaction->execSqlCoro(
        "INSERT INTO event_json(event_nid, json) VALUES($1, $2::jsonb)",
        event_nid, event.dump());

    // Update temporal_state for state events (v9 migration)
    if (state_key.has_value()) {
      // Mark previous state as ended
      co_await transaction->execSqlCoro(
          "UPDATE temporal_state SET end_index = $1 "
          "WHERE room_nid = $2 AND event_type_nid = $3 AND state_key_nid = $4 "
          "AND end_index IS NULL",
          calculated_depth, room_nid, event_type_nid, state_key_nid.value());

      // Insert new current state
      co_await transaction->execSqlCoro(
          "INSERT INTO temporal_state(room_nid, event_type_nid, state_key_nid, "
          "event_nid, start_index) VALUES($1, $2, $3, $4, $5)",
          room_nid, event_type_nid, state_key_nid.value(), event_nid,
          calculated_depth);
    }
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to add event due to database error");
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
    // Uses temporal_state for efficient current state lookup (from v9
    // migration)
    const auto query = co_await sql->execSqlCoro(
        "SELECT ej.json FROM temporal_state ts "
        "JOIN event_json ej ON ej.event_nid = ts.event_nid "
        "JOIN rooms r ON r.room_nid = ts.room_nid "
        "JOIN event_types et ON et.event_type_nid = ts.event_type_nid "
        "JOIN state_keys sk ON sk.state_key_nid = ts.state_key_nid "
        "WHERE r.room_id = $1 AND et.event_type = $2 AND sk.state_key = $3 "
        "AND ts.end_index IS NULL",
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
    // Uses event_json table (from v8 migration)
    const auto query = co_await sql->execSqlCoro(
        "SELECT ej.json FROM events e "
        "JOIN event_json ej ON ej.event_nid = e.event_nid "
        "WHERE e.room_id = $1 AND e.type = 'm.room.create' "
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
    // Get the current m.room.member state for this user in this room
    // Uses temporal_state for efficient current state lookup (from v9
    // migration)
    const auto query = co_await sql->execSqlCoro(
        "SELECT ej.json FROM temporal_state ts "
        "JOIN event_json ej ON ej.event_nid = ts.event_nid "
        "JOIN rooms r ON r.room_nid = ts.room_nid "
        "JOIN event_types et ON et.event_type_nid = ts.event_type_nid "
        "JOIN state_keys sk ON sk.state_key_nid = ts.state_key_nid "
        "WHERE r.room_id = $1 AND et.event_type = 'm.room.member' "
        "AND sk.state_key = $2 AND ts.end_index IS NULL",
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
    // Get the current m.room.join_rules state
    // Uses temporal_state for efficient current state lookup (from v9
    // migration)
    const auto query = co_await sql->execSqlCoro(
        "SELECT ej.json FROM temporal_state ts "
        "JOIN event_json ej ON ej.event_nid = ts.event_nid "
        "JOIN rooms r ON r.room_nid = ts.room_nid "
        "JOIN event_types et ON et.event_type_nid = ts.event_type_nid "
        "JOIN state_keys sk ON sk.state_key_nid = ts.state_key_nid "
        "WHERE r.room_id = $1 AND et.event_type = 'm.room.join_rules' "
        "AND sk.state_key = '' AND ts.end_index IS NULL",
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

    // Single query to get all auth events
    // Uses event_json table (from v8 migration) and event_types table (from v7
    // migration)
    const auto query = co_await sql->execSqlCoro(
        "WITH room_info AS ("
        "  SELECT room_nid FROM rooms WHERE room_id = $1"
        ") "
        "SELECT ej.json, et.event_type, sk.state_key "
        "FROM events e "
        "JOIN event_json ej ON ej.event_nid = e.event_nid "
        "JOIN event_types et ON et.event_type_nid = e.event_type_nid "
        "LEFT JOIN state_keys sk ON sk.state_key_nid = e.state_key_nid "
        "WHERE e.room_nid = (SELECT room_nid FROM room_info) "
        "  AND ("
        "    (et.event_type = 'm.room.create') OR "
        "    (et.event_type = 'm.room.power_levels' AND sk.state_key = '') OR "
        "    (et.event_type = 'm.room.join_rules' AND sk.state_key = '') OR "
        "    (et.event_type = 'm.room.member' AND sk.state_key = $2)"
        "  ) "
        "ORDER BY e.depth DESC",
        room_id, user_id);

    // Process results - track which event types we've seen (take latest by
    // depth)
    bool found_create = false;
    bool found_power_levels = false;
    bool found_join_rules = false;
    bool found_membership = false;

    for (const auto &row : query) {
      const auto event_type = row["event_type"].as<std::string>();
      const auto json_str = row["json"].as<std::string>();

      if (event_type == "m.room.create" && !found_create) {
        result.create_event = json::parse(json_str);
        found_create = true;
      } else if (event_type == "m.room.power_levels" && !found_power_levels) {
        result.power_levels = json::parse(json_str);
        found_power_levels = true;
      } else if (event_type == "m.room.join_rules" && !found_join_rules) {
        result.join_rules = json::parse(json_str);
        found_join_rules = true;
      } else if (event_type == "m.room.member" && !found_membership) {
        result.target_membership = json::parse(json_str);
        found_membership = true;
      }
    }

    if (!found_create) {
      co_return std::nullopt;
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
    // Get all actual DAG heads: events not referenced as prev_events by any
    // other event Uses prev_events_nids column (from v12 migration) and rooms
    // table (from v7 migration)
    const auto query = co_await sql->execSqlCoro(
        "SELECT e.event_id "
        "FROM events e "
        "JOIN rooms r ON r.room_nid = e.room_nid "
        "WHERE r.room_id = $1 "
        "  AND NOT EXISTS ("
        "    SELECT 1 FROM events e2 "
        "    WHERE e2.room_nid = e.room_nid "
        "      AND e.event_nid = ANY(e2.prev_events_nids)"
        "  )",
        room_id);

    std::vector<std::string> heads;
    heads.reserve(query.size());
    for (const auto &row : query) {
      heads.push_back(row["event_id"].as<std::string>());
    }

    // If no heads found (shouldn't happen for a valid room), fall back to
    // highest depth
    if (heads.empty()) {
      const auto fallback_query = co_await sql->execSqlCoro(
          "SELECT e.event_id FROM events e "
          "JOIN rooms r ON r.room_nid = e.room_nid "
          "WHERE r.room_id = $1 ORDER BY e.depth DESC LIMIT 1",
          room_id);
      for (const auto &row : fallback_query) {
        heads.push_back(row["event_id"].as<std::string>());
      }
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
    const auto query =
        co_await sql->execSqlCoro("SELECT public_key, valid_until_ts, "
                                  "fetched_at FROM server_signing_keys "
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