#pragma once

/// @file
/// @brief A wrapper for the database operations to ensure they are uniform.
#include "drogon/drogon.h"
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
    std::string_view matrix_id;
    std::string_view password;
    std::optional<std::string_view> initial_device_name;
    std::optional<std::string_view> device_id;
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

  [[nodiscard]] static drogon::Task<std::string>
  set_filter(const std::string &user_id, const json &filter);

  [[nodiscard]] static drogon::Task<json>
  get_filter(const std::string &user_id, const std::string &filter_id);
};
