#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "webserver/webserver.hpp"
#include "yaml-cpp/exceptions.h"
#include <database/database.hpp>
#include <iostream>
#include <sodium/core.h>
#include <stdexcept>

int main() {
  // Libsodium init
  if (sodium_init() < 0) {
    std::cout << "Failed to init libsodium\n";
    return 1;
  }

  // Actual startup
  try {
    Config config;

    try {
      json_utils::ensure_server_keys(config);
    } catch (std::runtime_error &error) {
      std::cout << "Failed to ensure_server_keys: " << error.what() << '\n';
      return 1;
    }

    Database database(config.db_config.url, config.db_config.pool_size);
    Webserver webserver(config, database);

    webserver.start();
  } catch (YAML::BadFile &error) {
    std::cout << "Missing or invalid config.yaml file. Make sure to create it "
                 "prior to running persephone \n";
    return 1;
  } catch (std::runtime_error &error) {
    std::cout << error.what() << "\n";
    return 1;
  }

  return 0;
}