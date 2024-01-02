#include "database.hpp"
#include "database/migrations/migrator.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include <format>
#include <stdexcept>
#include <zlib.h>

void Database::migrate() {
  Migrator migrator;
  migrator.migrate();
}

drogon::Task<Database::UserCreationResp>
Database::create_user(Database::UserCreationData const &data) const {
  auto sql = drogon::app().getDbClient();

  auto transPtr = co_await sql->newTransactionCoro();
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
  std::vector<unsigned char> localpart_vec(localpart_str.begin(),
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

drogon::Task<bool> Database::user_exists(std::string matrix_id) const {
  auto sql = drogon::app().getDbClient();
  try {
    auto f = co_await sql->execSqlCoro(
        "select exists(select 1 from users where matrix_id = $1) as exists",
        matrix_id);

    co_return f.at(0)["exists"].as<bool>();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();

    // We fail with user exists here to prevent further issues
    co_return true;
  }
}

drogon::Task<std::optional<Database::UserInfo>>
Database::get_user_info(std::string auth_token) const {
  auto sql = drogon::app().getDbClient();
  try {
    auto result = co_await sql->execSqlCoro(
        "select device_id, matrix_id from devices where access_token = $1",
        auth_token);

    std::optional<std::string> device_id;
    // TODO: track if the user is a guest in the database
    bool is_guest = false;

    if (result.size() == 0) {
      co_return std::nullopt;
    }

    auto first_row = result.at(0);
    try {
      device_id = first_row["device_id"].as<std::string>();
    } catch (drogon::orm::RangeError &) {
      // No device_id set
      device_id = std::nullopt;
    }
    auto matrix_id = first_row["matrix_id"].as<std::string>();
    UserInfo user_info{device_id, is_guest, matrix_id};

    co_return user_info;
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return std::nullopt;
  }
}

drogon::Task<bool>
Database::validate_access_token(std::string auth_token) const {
  auto sql = drogon::app().getDbClient();
  try {
    auto f = co_await sql->execSqlCoro("select exists(select 1 from devices "
                                       "where access_token = $1) as exists",
                                       auth_token);

    co_return f.at(0)["exists"].as<bool>();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    co_return false;
  }
}
