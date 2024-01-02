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

/**
 * @brief A wrapper for database operations. This is intentionally stateless and
 * not a cache.
 */
class Database {
public:
  void migrate();

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
  [[nodiscard]] drogon::Task<std::optional<Database::UserInfo>>
  get_user_info(std::string auth_token) const;
  [[nodiscard]] drogon::Task<bool>
  validate_access_token(std::string auth_token) const;
};
