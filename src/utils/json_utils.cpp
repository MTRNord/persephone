#include "json_utils.hpp"
#include "utils/config.hpp"
#include "utils/utils.hpp"
#include <array>
#include <cstddef>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <optional>
#include <sodium/crypto_sign.h>
#include <sodium/utils.h>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

namespace json_utils {
/**
 * @brief Decodes a base64 string to a binary string.
 *
 * This function takes a base64 string as input and decodes it to a binary
 * string. The binary string is represented as a vector of unsigned characters.
 * The function uses the sodium_base642bin function from the Sodium library to
 * perform the decoding. If the decoding fails, the function throws a runtime
 * error.
 *
 * @param input The base64 string to decode.
 * @return The decoded binary string as a vector of unsigned characters.
 * @throw std::runtime_error If the decoding fails.
 */
[[nodiscard]] std::vector<unsigned char>
unbase64_key(const std::string &input) {
  const size_t b64_str_len = input.size();
  // Allocate max possible size (base64 expands by ~4/3)
  size_t bin_len = b64_str_len * 3 / 4 + 4;
  std::vector<unsigned char> bin_str(bin_len);

  const int status = sodium_base642bin(
      bin_str.data(), bin_len, input.data(), b64_str_len, nullptr, &bin_len,
      nullptr, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

  if (status < 0) {
    throw std::runtime_error("Base64 String decode failed to decode");
  }

  // Resize to actual decoded length
  bin_str.resize(bin_len);
  return bin_str;
}

/**
 * @brief Encodes a binary string to a base64 string.
 *
 * This function takes a binary string as input and encodes it to a base64
 * string. The binary string is represented as a vector of unsigned characters.
 * The function uses the sodium_bin2base64 function from the Sodium library to
 * perform the encoding. If the encoding fails, the function throws a runtime
 * error.
 *
 * @param input The binary string to encode.
 * @return The encoded base64 string.
 * @throw std::runtime_error If the encoding fails.
 */
[[nodiscard]] std::string
base64_urlencoded(const std::vector<unsigned char> &input) {
  const unsigned long long private_key_len = input.size();
  const size_t base64_max_len = sodium_base64_encoded_len(
      private_key_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

  std::string base64_str(base64_max_len - 1, 0);
  const auto *encoded_str_char = sodium_bin2base64(
      base64_str.data(), base64_max_len, input.data(), private_key_len,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  if (encoded_str_char == nullptr) {
    throw std::runtime_error("Base64 Error: Failed to encode string");
  }

  return base64_str;
}

[[nodiscard]] std::string
base64_std_unpadded(const std::vector<unsigned char> &input) {
  const unsigned long long private_key_len = input.size();
  const size_t base64_max_len = sodium_base64_encoded_len(
      private_key_len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

  std::string base64_str(base64_max_len - 1, 0);
  const auto *encoded_str_char = sodium_bin2base64(
      base64_str.data(), base64_max_len, input.data(), private_key_len,
      sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  if (encoded_str_char == nullptr) {
    throw std::runtime_error("Base64 Error: Failed to encode string");
  }

  return base64_str;
}

/**
 * @brief Signs a JSON object with a server's secret key.
 *
 * This function takes a server name, a key ID, a secret key, and a JSON object
 * as input. It first extracts any existing signatures and unsigned fields from
 * the JSON object. Then, it signs the canonical form of the JSON object using
 * the secret key. The signature is encoded as an unpadded base64 string and
 * added to the JSON object. If the signing fails, the function throws a runtime
 * error. Finally, it adds back any unsigned fields and returns the signed JSON
 * object.
 *
 * @param server_name The name of the server.
 * @param key_id The ID of the key.
 * @param secret_key The secret key as a vector of unsigned characters.
 * @param json_data The JSON object to sign.
 * @return The signed JSON object.
 * @throw std::runtime_error If the signing fails.
 */
[[nodiscard]] json sign_json(const std::string &server_name,
                             const std::string &key_id,
                             const std::vector<unsigned char> &secret_key,
                             json json_data) {
  if (json_data.is_null()) {
    throw std::runtime_error(
        "Json data is null which is impossible for an event");
  }
  if (secret_key.empty()) {
    throw std::runtime_error("Secret key is empty");
  }

  // Get existing (or not yet existing) signatures and unsigned fields
  auto signatures = json_data.value("signatures", json(json::value_t::object));
  const auto unsigned_value = json_data.value("unsigned", json{});

  json_data.erase("signatures");
  json_data.erase("unsigned");

  // Sign canonical json using detached signature (Matrix spec requires only
  // the 64-byte signature, not the combined signature+message)
  const std::string canonical_json = json_data.dump();
  std::vector<unsigned char> signature(crypto_sign_BYTES);

  const auto *const unsigned_char_canonical_json =
      reinterpret_cast<const unsigned char *>(canonical_json.c_str());

  const auto result = crypto_sign_detached(
      signature.data(), nullptr, unsigned_char_canonical_json,
      canonical_json.size(), secret_key.data());
  if (result < 0) {
    throw std::runtime_error("Signing the json failed");
  }

  // Encode signature as UNPADDED base64
  auto base64_str = json_utils::base64_std_unpadded(signature);
  // Add signature to json
  signatures[server_name][std::format("ed25519:{}", key_id)] = base64_str;
  json_data["signatures"] = signatures;

  // Add unsigned back
  if (!unsigned_value.is_null()) {
    json_data["unsigned"] = unsigned_value;
  }
  return json_data;
}

/**
 * @brief Generates a new server key pair.
 *
 * This function generates a new server key pair using the Sodium library's
 * crypto_sign_keypair function. The key pair consists of a public key and a
 * secret key. The public key is an array of unsigned characters of size
 * crypto_sign_PUBLICKEYBYTES. The secret key is an array of unsigned characters
 * of size crypto_sign_SECRETKEYBYTES. The function returns the key pair as a
 * tuple.
 *
 * @return A tuple containing the public key and the secret key.
 */
[[nodiscard]] std::tuple<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>,
                         std::array<unsigned char, crypto_sign_SECRETKEYBYTES>>
generate_server_key() {
  std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> public_key{};
  std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key{};
  crypto_sign_keypair(public_key.data(), secret_key.data());

  return {public_key, secret_key};
}

/**
 * @brief Writes the server's private key to a file.
 *
 * This function takes a Config object and a private key as input.
 * The Config object contains the location where the server's private key should
 * be written. The private key is represented as a vector of unsigned
 * characters. The function first encodes the private key to a base64 string.
 * Then, it generates a version string in the format "a_<random_string>".
 * Finally, it writes the algorithm name, the version string, and the base64
 * string to the file. If the file cannot be opened, the function does nothing.
 *
 * @param config The Config object containing the server key location.
 * @param private_key The private key as a vector of unsigned characters.
 */
void write_server_key(const Config &config,
                      const std::vector<unsigned char> &private_key) {
  const std::string algo = "ed25519";

  auto base64_str = json_utils::base64_urlencoded(private_key);

  auto version = std::format("a_{}", random_string(4));
  if (std::ofstream keyfile(config.matrix_config.server_key_location);
      keyfile.is_open()) {
    keyfile << std::format("{} {} {}", algo, version, base64_str);
    keyfile.close();
  }
}

/**
 * @brief Ensures the server keys exist.
 *
 * This function takes a Config object as input.
 * The Config object contains the location where the server's private key should
 * be stored. The function first checks if the server's private key already
 * exists at the specified location. If the private key does not exist, the
 * function generates a new server key pair. The private key from the key pair
 * is then written to the specified location. If the private key already exists,
 * the function does nothing.
 *
 * @param config The Config object containing the server key location.
 */
void ensure_server_keys(const Config &config) {
  if (!std::filesystem::exists(config.matrix_config.server_key_location)) {
    const auto server_key = json_utils::generate_server_key();
    auto private_key = std::get<1>(server_key);
    const std::vector<unsigned char> private_key_vector(std::begin(private_key),
                                                        std::end(private_key));
    write_server_key(config, private_key_vector);
  }
}

[[nodiscard]] std::optional<std::vector<unsigned char>>
decode_base64(const std::string &input) {
  if (input.empty()) {
    return std::nullopt;
  }

  const size_t b64_str_len = input.size();
  // Allocate max possible size (base64 expands by ~4/3)
  size_t bin_len = (b64_str_len * 3 / 4) + 4;
  std::vector<unsigned char> bin_str(bin_len);

  // Try URL-safe variant first
  int status = sodium_base642bin(bin_str.data(), bin_len, input.data(),
                                 b64_str_len, nullptr, &bin_len, nullptr,
                                 sodium_base64_VARIANT_URLSAFE_NO_PADDING);

  if (status < 0) {
    // Try standard variant
    bin_len = (b64_str_len * 3 / 4) + 4;
    status = sodium_base642bin(bin_str.data(), bin_len, input.data(),
                               b64_str_len, nullptr, &bin_len, nullptr,
                               sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  }

  if (status < 0) {
    return std::nullopt;
  }

  bin_str.resize(bin_len);
  return bin_str;
}

[[nodiscard]] bool verify_signature(const std::string &public_key_base64,
                                    const std::string &signature_base64,
                                    const std::string &message) {
  // Decode the public key
  const auto public_key_opt = decode_base64(std::string(public_key_base64));
  if (!public_key_opt.has_value() ||
      public_key_opt->size() != crypto_sign_PUBLICKEYBYTES) {
    LOG_WARN << "[verify_signature] Failed to decode public key or invalid key "
                "length";
    return false;
  }

  // Decode the signature
  const auto signature_opt = decode_base64(std::string(signature_base64));
  if (!signature_opt.has_value() ||
      signature_opt->size() != crypto_sign_BYTES) {
    LOG_WARN << "[verify_signature] Failed to decode signature or invalid "
                "signature length";
    return false;
  }

  // Verify the signature using Ed25519
  // crypto_sign creates: signature || message
  // crypto_sign_verify_detached verifies just the detached signature
  const auto result = crypto_sign_verify_detached(
      signature_opt->data(),
      reinterpret_cast<const unsigned char *>(message.data()), message.size(),
      public_key_opt->data());

  return result == 0;
}

void strip_federation_fields(json &event) {
  event.erase("auth_events");
  event.erase("prev_events");
  event.erase("depth");
  event.erase("hashes");
  event.erase("signatures");
}

} // namespace json_utils
