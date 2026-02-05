#pragma once

#include <array>
#ifdef __GNUC__
// Ignore false positives (see https://github.com/nlohmann/json/issues/3808)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "nlohmann/json.hpp"
#pragma GCC diagnostic pop
#else
#include <nlohmann/json.hpp>
#endif
#include <optional>
#include <sodium/crypto_sign.h>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
struct Config;
using json = nlohmann::json;

namespace json_utils {
[[nodiscard]] std::tuple<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>,
                         std::array<unsigned char, crypto_sign_SECRETKEYBYTES>>
generate_server_key();

[[nodiscard]] json sign_json(const std::string_view server_name,
                             const std::string_view key_id,
                             const std::vector<unsigned char> &secret_key,
                             json json_data);

[[nodiscard]] std::vector<unsigned char> unbase64_key(const std::string &input);

[[nodiscard]] std::string
base64_urlencoded(const std::vector<unsigned char> &input);

[[nodiscard]] std::string
base64_std_unpadded(const std::vector<unsigned char> &input);

void write_server_key(const Config &config,
                      const std::vector<unsigned char> &private_key);

void ensure_server_keys(const Config &config);

/// Verify a signature against a message using Ed25519
/// @param public_key The public key as base64-encoded string (URL-safe,
/// unpadded)
/// @param signature The signature as base64-encoded string (standard, unpadded)
/// @param message The message that was signed
/// @return true if signature is valid, false otherwise
[[nodiscard]] bool verify_signature(std::string_view public_key_base64,
                                    std::string_view signature_base64,
                                    std::string_view message);

/// Decode a base64 string (supports both URL-safe and standard variants)
[[nodiscard]] std::optional<std::vector<unsigned char>>
decode_base64(const std::string &input);
} // namespace json_utils
