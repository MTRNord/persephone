#include "ServerServerCtrl.hpp"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "webserver/json.hpp"
#include <chrono>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <format>
#include <functional>

using namespace server_server_api;
using json = nlohmann::json;

/**
 * @brief Handles the version request of the server-server API.
 *
 * This function is a part of the ServerServerCtrl class and is used to handle
 * the version request of the server-server API. It creates a version object
 * with the server name and version number. It then creates a new HTTP response,
 * sets the body of the response to the JSON representation of the version
 * object, sets the expired time to 0, and sets the content type to
 * application/json. Finally, it calls the callback function with the response.
 *
 * @param callback A callback function that takes an HTTP response pointer as
 * input. This function is called with the response.
 */
void ServerServerCtrl::version(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback) {
  static constexpr server_server_json::version version = {
      .server = {.name = "persephone", .version = "0.1.0"}};
  const json json_data = version;

  const auto resp = HttpResponse::newHttpResponse();
  resp->setBody(json_data.dump());
  resp->setExpiredTime(0);
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ServerServerCtrl::server_key(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  const auto server_name = _config.matrix_config.server_name;
  const long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  const long tomorrow = now + static_cast<long>(24 * 60 * 60 * 1000); // 24h

  const server_server_json::keys keys = {
      .server_name = server_name,
      .valid_until_ts = tomorrow,
      .old_verify_keys = {},
      .verify_keys = {{std::format("{}:{}", _verify_key_data.key_type,
                                   _verify_key_data.key_id),
                       {.key = _verify_key_data.public_key_base64}}},
      .signatures = {}};
  const json json_data = keys;
  const auto signed_j =
      json_utils::sign_json(server_name, _verify_key_data.key_id,
                            _verify_key_data.private_key, json_data);

  const auto resp = HttpResponse::newHttpResponse();
  resp->setBody(signed_j.dump());
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}
