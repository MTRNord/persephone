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

void write_server_key(Config const &config,
                      std::vector<unsigned char> private_key) {
  const std::string algo = "ed25519";

  auto base64_str = json_utils::base64_key(std::move(private_key));

  std::string version = std::format("a_{}", random_string(4));
  std::ofstream keyfile(config.matrix_config.server_key_location);
  if (keyfile.is_open()) {
    keyfile << std::format("{} {} {}", algo, version, base64_str);
    keyfile.close();
  }
}

void ensure_server_keys(Config const &config) {
  if (!std::filesystem::exists(config.matrix_config.server_key_location)) {
    auto server_key = json_utils::generate_server_key();
    auto private_key = std::get<1>(server_key);
    std::vector<unsigned char> private_key_vector(std::begin(private_key),
                                                  std::end(private_key));
    write_server_key(config, private_key_vector);
  }
}

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