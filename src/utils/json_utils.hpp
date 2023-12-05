#pragma once
#include <array>
#include <nlohmann/json_fwd.hpp>
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
[[nodiscard]] json sign_json(const std::string &server_name,
                             const std::string &key_id,
                             const std::vector<unsigned char> &secret_key,
                             json json_data);
[[nodiscard]] std::vector<unsigned char> unbase64_key(std::string input);
[[nodiscard]] std::string base64_key(std::vector<unsigned char> input);

void write_server_key(const Config &config,
                      const std::vector<unsigned char> &private_key);
void ensure_server_keys(const Config &config);
} // namespace json_utils