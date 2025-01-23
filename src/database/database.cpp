#include "database.hpp"
#include "database/migrations/migrator.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include <drogon/utils/coroutine.h>
#include <format>
#include <stdexcept>

void Database::migrate() const {
  constexpr Migrator migrator;
  migrator.migrate();
}

[[nodiscard]] drogon::Task<Database::UserCreationResp>
Database::create_user(Database::UserCreationData const &data) const {
  const auto sql = drogon::app().getDbClient();

  const auto transPtr = co_await sql->newTransactionCoro();
  assert(transPtr);

  // TODO: If we have a guest registering we are required to always
  // generate this.
  auto device_id = data.device_id.value_or(random_string(7));
  auto password_hash = hash_password(data.password);
  auto matrix_id = data.matrix_id;
  auto device_name = data.device_name.value_or(random_string(7));

  // This token should have this pattern:
  // `persephone_<unpadded base64 local part of the matrix
  // id>_<random string (20 chars)>_<base62 crc32 check>`
  auto localpart_str = localpart(matrix_id);
  const std::vector<unsigned char> localpart_vec(localpart_str.begin(),
                                                 localpart_str.end());

  auto random_component = random_string(20);
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

  try {
    co_await transPtr->execSqlCoro(
      "INSERT INTO devices(matrix_id, device_id, "
      "device_name, access_token) VALUES($1, $2, $3, $4)",
      matrix_id, device_id, device_name, access_token);
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to create user due to database error");
  }

  Database::UserCreationResp resp_data{access_token, device_id};
  co_return resp_data;
}

[[nodiscard]] drogon::Task<bool>
Database::user_exists(std::string matrix_id) const {
  const auto sql = drogon::app().getDbClient();
  try {
    const auto f = co_await sql->execSqlCoro(
      "select exists(select 1 from users where matrix_id = $1) as exists",
      matrix_id);

    co_return f.at(0)["exists"].as<bool>();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();

    // We fail with user exists here to prevent further issues
    co_return true;
  }
}

[[nodiscard]] drogon::Task<std::optional<Database::UserInfo> >
Database::get_user_info(std::string auth_token) const {
  const auto sql = drogon::app().getDbClient();
  try {
    const auto result = co_await sql->execSqlCoro(
      "select device_id, matrix_id from devices where access_token = $1",
      auth_token);

    std::optional<std::string> device_id;
    // TODO: track if the user is a guest in the database
    constexpr bool is_guest = false;

    if (result.size() == 0) {
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
    UserInfo user_info{device_id, is_guest, matrix_id};

    co_return user_info;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return std::nullopt;
  }
}

[[nodiscard]] drogon::Task<bool>
Database::validate_access_token(std::string auth_token) const {
  const auto sql = drogon::app().getDbClient();
  try {
    const auto f = co_await sql->execSqlCoro("select exists(select 1 from devices "
                                             "where access_token = $1) as exists",
                                             auth_token);

    co_return f.at(0)["exists"].as<bool>();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return false;
  }
}

[[nodiscard]] drogon::Task<void>
Database::add_room(std::vector<json> events, const std::string &room_id) const {
  const auto sql = drogon::app().getDbClient();
  try {
    for (const auto &event: events) {
      co_await this->add_event(event, room_id);
    }
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to add room due to database error");
  }
}

[[nodiscard]] drogon::Task<void>
Database::add_event(json event, const std::string &room_id) const {
  const auto sql = drogon::app().getDbClient();
  std::string auth_events_str = "{}";
  if (event.contains("auth_events")) {
    // We need the auth_events as TEXT[] so we need to map the json array to a string array
    const auto auth_events = event.at("auth_events").get<std::vector<std::string> >();
    // We also need to form a single string from it which is of form '{"a","b","c"}'. We only store the event_id of the auth events
    auth_events_str = "{";
    for (const auto &auth_event: auth_events) {
      auth_events_str += "\"" + auth_event + "\",";
    }
    // Remove the trailing comma
    auth_events_str.pop_back();
    auth_events_str += "}";
  }

  // If we got a state_key set it in the db otherwise use NULL
  std::optional<std::string> state_key = std::nullopt;
  if (event.contains("state_key")) {
    state_key = event.at("state_key").get<std::string>();
  }

  try {
    co_await sql->execSqlCoro(
      "INSERT INTO events(event_id, room_id, depth, auth_events, "
      "rejected, state_key, type, json) VALUES($1, $2, 0, $3::text[], $4, $5, $6, $7)",
      event.at("event_id").get<std::string>(), room_id,
      auth_events_str, false, state_key,
      event.at("type").get<std::string>(), event.dump());
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    throw std::runtime_error("Failed to add event due to database error");
  }
}

[[nodiscard]] drogon::Task<void>
Database::add_state_events(std::vector<client_server_json::StateEvent> events, const std::string &room_id) const {
  const auto sql = drogon::app().getDbClient();

  for (const auto &event: events) {
    const auto event_string = to_string(static_cast<json>(event));

    if (event.event_id == std::nullopt) {
      throw std::invalid_argument("Event ID cannot be null");
    }

    try {
      co_await sql->execSqlCoro(
        "INSERT INTO events(event_id, room_id, depth, auth_events, "
        "rejected, state_key, type, json) VALUES($1, $2, 0, $3::text[], $4, $5, $6, $7)",
        event.event_id.value(), room_id, "{}", false, event.state_key, event.type, event_string);
    } catch (const drogon::orm::DrogonDbException &e) {
      LOG_ERROR << e.base().what();
      throw std::runtime_error("Failed to add state event due to database error");
    }
  }
}
