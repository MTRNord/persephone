#include "ServerServerCtrl.hpp"
#include "nlohmann/json.hpp"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "webserver/json.hpp"
#include <fstream>
#include <iostream>

using namespace server_server_api;
using json = nlohmann::json;

void ServerServerCtrl::version(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback) const {

  static constexpr server_server_json::version version = {
      .server = {.name = "persephone", .version = "0.1.0"}};
  json j = version;

  auto resp = HttpResponse::newHttpResponse();
  resp->setBody(j.dump());
  resp->setExpiredTime(0);
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ServerServerCtrl::server_key(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  Config config;
  auto server_name = config.matrix_config.server_name;
  long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
  long tomorrow = now + static_cast<long>(24 * 60 * 60 * 1000); // 24h

  std::ifstream t(config.matrix_config.server_key_location);
  std::string server_key((std::istreambuf_iterator<char>(t)),
                         std::istreambuf_iterator<char>());
  std::istringstream buffer(server_key);
  std::vector<std::string> splitted_data{
      std::istream_iterator<std::string>(buffer),
      std::istream_iterator<std::string>()};

  auto private_key = json_utils::unbase64_key(splitted_data[2]);
  std::vector<unsigned char> public_key(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(public_key.data(), private_key.data());
  auto public_key_base64 = json_utils::base64_key(public_key);

  server_server_json::keys keys = {
      .server_name = server_name,
      .valid_until_ts = tomorrow,
      .old_verify_keys = {},
      .verify_keys = {{std::format("{}:{}", splitted_data[0], splitted_data[1]),
                       {.key = public_key_base64}}},
  };
  json j = keys;
  auto signed_j = json_utils::sign_json(server_name, splitted_data[1], private_key, j);

  auto resp = HttpResponse::newHttpResponse();
  resp->setBody(signed_j.dump());
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}
