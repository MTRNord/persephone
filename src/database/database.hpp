#pragma once

/// @file
/// @brief A wrapper for the database operations to ensure they are uniform.

#include "drogon/drogon.h"
#include <coroutine>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <nlohmann/json.hpp>
#include <webserver/json.hpp>

using json = nlohmann::json;

void prepare_statements();

/**
 * @brief A wrapper for database operations. This is intentionally stateless and
 * not a cache.
 */
class Database {
public:
  void migrate() const;

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

  [[nodiscard]] drogon::Task<Database::UserCreationResp>
  create_user(UserCreationData const &data) const;

  [[nodiscard]] drogon::Task<bool> user_exists(std::string matrix_id) const;

  [[nodiscard]] drogon::Task<std::optional<Database::UserInfo> >
  get_user_info(std::string auth_token) const;

  [[nodiscard]] drogon::Task<bool>
  validate_access_token(std::string auth_token) const;

  [[nodiscard]] drogon::Task<client_server_json::login_resp> login(const std::string &matrix_id,
                                                                   const std::string &password,
                                                                   const std::optional<std::string> &
                                                                   initial_device_name,
                                                                   const std::optional<std::string> &device_id)
  const;

  [[nodiscard]] drogon::Task<void> add_room(const std::shared_ptr<drogon::orm::Transaction> transaction,
                                            std::vector<json> events,
                                            const std::string &room_id) const;

  [[nodiscard]] drogon::Task<void> add_event(const std::shared_ptr<drogon::orm::Transaction> transaction, json event,
                                             const std::string &room_id) const;

  [[nodiscard]] drogon::Task<void> add_state_events(const std::shared_ptr<drogon::orm::Transaction> transaction,
                                                    std::vector<client_server_json::StateEvent> events,
                                                    const std::string &room_id) const;
};
