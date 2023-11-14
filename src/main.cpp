#include "utils/config.hpp"
#include "webserver/webserver.hpp"
#include <database/database.hpp>

int main() {
  Config config;
  Database database(config.db_config.url, config.db_config.pool_size);
  Webserver webserver(config, database);

  webserver.start();

  return 0;
}