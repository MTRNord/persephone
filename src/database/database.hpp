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
  Database::UserCreationResp create_user(UserCreationData const &data) const;
  bool user_exists(std::string matrix_id) const;
  struct UserInfo {
    // Optional for appservices
    std::optional<std::string> device_id;
    bool is_guest;
    std::string user_id;
  };
  std::optional<Database::UserInfo> get_user_info(std::string auth_token) const;

private:
  void migration_v0();
  void migration_v1();
  void migration_v2();
};