#include "utils/config.hpp"
#include "utils/utils.hpp"
#include "webserver/webserver.hpp"
#include <database/database.hpp>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sodium.h>
#include <vector>

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
      ensure_server_keys(config);
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