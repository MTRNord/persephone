#include "ServerServerCtrl.hpp"
#include "nlohmann/json.hpp"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "webserver/json.hpp"

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
  auto server_name = _config.matrix_config.server_name;
  long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
  long tomorrow = now + static_cast<long>(24 * 60 * 60 * 1000); // 24h

  server_server_json::keys keys = {
      .server_name = server_name,
      .valid_until_ts = tomorrow,
      .old_verify_keys = {},
      .verify_keys = {{std::format("{}:{}", _verify_key_data.key_type,
                                   _verify_key_data.key_id),
                       {.key = _verify_key_data.public_key_base64}}},
  };
  json j = keys;
  auto signed_j = json_utils::sign_json(server_name, _verify_key_data.key_id,
                                        _verify_key_data.private_key, j);

  auto resp = HttpResponse::newHttpResponse();
  resp->setBody(signed_j.dump());
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}
