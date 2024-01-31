#include "json_utils.hpp"
#include "utils/config.hpp"
#include "utils/utils.hpp"
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <map>
#include <nlohmann/detail/value_t.hpp>
#include <nlohmann/json.hpp>
#include <sodium/utils.h>
#include <stdexcept>

namespace json_utils {
std::vector<unsigned char> unbase64_key(const std::string &input) {
  size_t b64_str_len = input.size();
  size_t bin_len = b64_str_len * (static_cast<size_t>(4) * 3);
  std::vector<unsigned char> bin_str(bin_len);

  int status = sodium_base642bin(bin_str.data(), bin_len, input.data(),
                                 b64_str_len, nullptr, &bin_len, nullptr,
                                 sodium_base64_VARIANT_URLSAFE_NO_PADDING);

  if (status < 0) {
    throw std::runtime_error("Base64 String decode failed to decode");
  }

  return bin_str;
}

std::string base64_key(const std::vector<unsigned char> &input) {
  unsigned long long private_key_len = input.size();
  const size_t base64_max_len = sodium_base64_encoded_len(
      private_key_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

  std::string base64_str(base64_max_len - 1, 0);
  auto encoded_str_char = sodium_bin2base64(
      base64_str.data(), base64_max_len, input.data(), private_key_len,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  if (encoded_str_char == nullptr) {
    throw std::runtime_error("Base64 Error: Failed to encode string");
  }

  return base64_str;
}

json sign_json(const std::string &server_name, const std::string &key_id,
               const std::vector<unsigned char> &secret_key, json json_data) {
  // Get existing (or not yet existing) signatures and unsigned fields
  auto signatures = json_data.value("signatures", json(json::value_t::object));
  auto unsigned_value = json_data.value("unsigned", json{});

  json_data.erase("signatures");
  json_data.erase("unsigned");

  // Sign canonical json
  std::string canonical_json = json_data.dump();
  std::vector<unsigned char> signed_message(crypto_sign_BYTES +
                                            canonical_json.size());
  unsigned long long signed_message_len = 0;

  auto result = crypto_sign(
      signed_message.data(), &signed_message_len,
      reinterpret_cast<const unsigned char *>(canonical_json.c_str()),
      canonical_json.size(), secret_key.data());
  if (result < 0) {
    throw std::runtime_error("Signing the json failed");
  }

  // Encode signature as UNPADDED base64
  auto base64_str = json_utils::base64_key(signed_message);
  // Add signature to json
  signatures[server_name][std::format("ed25519:{}", key_id)] = base64_str;
  json_data["signatures"] = signatures;

  // Add unsigned back
  if (!unsigned_value.is_null()) {
    json_data["unsigned"] = unsigned_value;
  }
  return json_data;
}

std::tuple<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>,
           std::array<unsigned char, crypto_sign_SECRETKEYBYTES>>
generate_server_key() {
  std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pk;
  std::array<unsigned char, crypto_sign_SECRETKEYBYTES> sk;
  crypto_sign_keypair(pk.data(), sk.data());

  return {pk, sk};
}

void write_server_key(const Config &config,
                      const std::vector<unsigned char> &private_key) {
  const std::string algo = "ed25519";

  auto base64_str = json_utils::base64_key(private_key);

  auto version = std::format("a_{}", random_string(4));
  std::ofstream keyfile(config.matrix_config.server_key_location);
  if (keyfile.is_open()) {
    keyfile << std::format("{} {} {}", algo, version, base64_str);
    keyfile.close();
  }
}

void ensure_server_keys(const Config &config) {
  if (!std::filesystem::exists(config.matrix_config.server_key_location)) {
    auto server_key = json_utils::generate_server_key();
    auto private_key = std::get<1>(server_key);
    std::vector<unsigned char> private_key_vector(std::begin(private_key),
                                                  std::end(private_key));
    write_server_key(config, private_key_vector);
  }
}
} // namespace json_utils
