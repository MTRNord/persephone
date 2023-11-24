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

  unsigned long long private_key_len = private_key.size();
  const size_t base64_max_len = sodium_base64_encoded_len(
      private_key_len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

  std::string base64_str(base64_max_len - 1, 0);
  char *encoded_str_char = sodium_bin2base64(
      base64_str.data(), base64_max_len, private_key.data(), private_key_len,
      sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  if (encoded_str_char == nullptr) {
    throw std::runtime_error("Base64 Error: Failed to encode string");
  }

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
  Config config;

  try {
    ensure_server_keys(config);
  } catch (std::runtime_error error) {
    std::cout << "Failed to ensure_server_keys: " << error.what() << '\n';
    std::abort();
  }

  Database database(config.db_config.url, config.db_config.pool_size);
  Webserver webserver(config, database);

  webserver.start();

  return 0;
}