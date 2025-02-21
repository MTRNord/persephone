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
#include <sodium/crypto_sign.h>
#include <string>
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

[[nodiscard]] std::string base64_key(const std::vector<unsigned char> &input);

void write_server_key(const Config &config,
                      const std::vector<unsigned char> &private_key);

void ensure_server_keys(const Config &config);
} // namespace json_utils
