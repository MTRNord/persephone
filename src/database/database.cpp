#include "database.hpp"
#include "database/migrations/migrator.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
#include <cassert>
#include <cstddef>
#include <drogon/HttpAppFramework.h>
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Exception.h>
#include <drogon/utils/coroutine.h>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
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
  auto access_token =
      std::format("persephone_{}_{}_{}", json_utils::base64_key(localpart_vec),
                  random_component,
                  base62_encode(crc32_helper(
                      std::format("{}_{}", matrix_id, random_component))));

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
    auto access_token =
        std::format("persephone_{}_{}_{}",
                    json_utils::base64_key(localpart_vec), random_component,
                    base62_encode(crc32_helper(std::format(
                        "{}_{}", login_data.matrix_id, random_component))));

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

[[nodiscard]] drogon::Task<void>
Database::add_event(const std::shared_ptr<drogon::orm::Transaction> transaction,
                    json event, const std::string_view room_id) {
  std::string auth_events_str = "{}";
  if (event.contains("auth_events")) {
    // We need the auth_events as TEXT[] so we need to map the json array to a
    // string array
    const auto auth_events =
        event.at("auth_events").get<std::vector<std::string>>();
    // We also need to form a single string from it which is of form
    // '{"a","b","c"}'. We only store the event_id of the auth events
    auth_events_str = "{";
    for (const auto &auth_event : auth_events) {
      auth_events_str += "\"" + auth_event + "\",";
    }
    // Remove the trailing comma if present
    if (!auth_events.empty()) {
      auth_events_str.pop_back();
    }
    auth_events_str += "}";
  }

  LOG_DEBUG << "Auth events: " << auth_events_str;

  // If we got a state_key set it in the db otherwise use NULL
  std::optional<std::string> state_key = std::nullopt;
  if (event.contains("state_key")) {
    state_key = event.at("state_key").get<std::string>();
  }

  try {
    co_await transaction->execSqlCoro(
        "INSERT INTO events(event_id, room_id, depth, auth_events, "
        "rejected, state_key, type, json) VALUES($1, $2, 0, $3::text[], $4, "
        "$5, $6, $7)",
        event.at("event_id").get<std::string>(), room_id, auth_events_str,
        false, state_key, event.at("type").get<std::string>(), event.dump());
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