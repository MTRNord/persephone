#pragma once

#include "soci/postgresql/soci-postgresql.h"
#include "soci/soci.h"

using namespace soci;

/**
 * @brief A wrapper for database ops. This is intentionally stateless and not a
 * cache.
 */
class Database {
private:
  connection_pool pool;

public:
  Database(std::string db_url, const size_t pool_size) : pool(pool_size) {
    for (size_t i = 0; i != pool_size; ++i) {
      session &sql = this->pool.at(i);

      sql.open(db_url);
    }
  }
};