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
  void
  create_user(UserCreationData const &data,
              std::function<void(const UserCreationResp &)> &&callback) const;
  void user_exists(std::string matrix_id,
                   std::function<void(bool)> &&callback) const;
  struct UserInfo {
    // Optional for appservices
    std::optional<std::string> device_id;
    bool is_guest;
    std::string user_id;
  };
  void
  get_user_info(std::string auth_token,
                std::function<void(std::optional<UserInfo>)> &&callback) const;

private:
  void migration_v1();
  void migration_v2();
};