#pragma once
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "utils/config.hpp"
#include <sodium.h>

using json = nlohmann::json;
using namespace httplib;

std::string dump_headers(const Headers &headers);
std::string log(const Request &req, const Response &res);

void return_error(Response &res, std::string errorcode, std::string error);

namespace json_utils {
std::tuple<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>,
           std::array<unsigned char, crypto_sign_SECRETKEYBYTES>>
generate_server_key();
json sign_json(std::string const &server_name, std::string const &key_id,
               std::vector<unsigned char> secret_key, json &json_data);
std::vector<unsigned char> unbase64_key(std::string input);
std::string base64_key(std::vector<unsigned char> input);
} // namespace json_utils

std::string random_string(const unsigned long len);
void write_server_key(Config const &config,
                      std::vector<unsigned char> private_key);
void ensure_server_keys(Config const &config);