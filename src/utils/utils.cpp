#include "utils.hpp"
#include "webserver/json.hpp"
#include <format>

std::string dump_headers(const Headers &headers) {
  std::string s;

  for (const auto &x : headers) {
    s += std::format("{}: {}\n", x.first, x.second);
  }

  return s;
}

std::string log(const Request &req, const Response &res) {
  std::string s;

  s += "================================\n";
  s += std::format("{} {} {}\n", req.method, req.version, req.path);

  std::string query;
  for (auto it = req.params.begin(); it != req.params.end(); ++it) {
    const auto &x = *it;
    query += std::format("{}{}={}\n", (it == req.params.begin()) ? '?' : '&',
                         x.first, x.second);
  }

  s += std::format("{}\n", query);
  s += dump_headers(req.headers);

  s += "--------------------------------\n";
  s += std::format("{} {}\n", res.status, res.version);

  s += dump_headers(res.headers);
  s += "\n";

  if (!res.body.empty()) {
    s += res.body;
  }

  s += "\n";
  return s;
}

void return_error(Response &res, std::string errorcode, std::string error) {
  generic_json::generic_json_error json_error{std::move(errorcode),
                                              std::move(error)};
  json j = json_error;
  res.set_content(j.dump(), "application/json");
  res.status = 500;
}

namespace json_utils {
json sign_json(std::string const &server_name, std::string const &key_id,
               std::array<unsigned char, crypto_sign_SECRETKEYBYTES> secret_key,
               json &json_data) {
  // Get existing (or not yet existing) signatures and unsigned fields
  auto signatures = json_data.value("signatures", json{});
  auto unsigned_value = json_data.at("unsigned");
  json_data.erase("signatures");
  json_data.erase("unsigned");

  // Sign canonical json
  auto canonical_json = json_data.dump();
  unsigned long canonical_json_len = canonical_json.size();
  std::vector<unsigned char> signed_message;
  unsigned long long signed_message_len;
  crypto_sign(signed_message.data(), &signed_message_len,
              reinterpret_cast<const unsigned char *>(canonical_json.c_str()),
              canonical_json_len, secret_key.data());

  // Encode signature as UNPADDED base64
  const size_t base64_max_len = sodium_base64_encoded_len(
      signed_message_len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

  std::string base64_str(base64_max_len - 1, 0);
  char *encoded_str_char = sodium_bin2base64(
      base64_str.data(), base64_max_len, signed_message.data(),
      signed_message_len, sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
  if (encoded_str_char == nullptr) {
    throw std::runtime_error("Base64 Error: Failed to encode string");
  }
  // Add signature to json
  signatures.value(server_name, json{}).at(key_id) = base64_str;
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

  return std::make_tuple(pk, sk);
}
} // namespace json_utils

std::string random_string(const unsigned long len) {
  static const char alphanum[] = "0123456789"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz";
  std::string tmp_s;
  tmp_s.reserve(len);

  for (unsigned long i = 0; i < len; ++i) {
    tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  return tmp_s;
}