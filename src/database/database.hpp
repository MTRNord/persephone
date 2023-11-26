#pragma once

/// @file
/// @brief A wrapper for the database operations to ensure they are uniform.

#include "soci/connection-pool.h"
#include "soci/session.h"
#include "soci/soci-platform.h"
#include <cstddef>
#include <functional>
#include <memory>
#include <string>

using namespace soci;

extern "C" void register_factory_postgresql();

/**
 * @brief A wrapper for database operations. This is intentionally stateless and
 * not a cache.
 */
class Database {
private:
  std::shared_ptr<connection_pool> pool = nullptr;

public:
  Database(std::string const &db_url, std::size_t pool_size) {
    register_factory_postgresql();
    this->pool = std::make_shared<connection_pool>(pool_size);

    for (std::size_t i = 0; i != pool_size; ++i) {
      session &sql = this->pool->at(i);

      sql.open(db_url);
    }
  }

  void migrate();

private:
  void migration_v1();
  void listen(std::string channel, std::function<void()> const &callback);
};