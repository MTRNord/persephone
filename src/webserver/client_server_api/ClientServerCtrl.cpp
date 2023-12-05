#include "ClientServerCtrl.hpp"
#include "database/database.hpp"
#include "nlohmann/json.hpp"
#include "utils/config.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"

using namespace client_server_api;
using json = nlohmann::json;

void ClientServerCtrl::versions(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback) const {

  // We only support v1.8. However due to
  // https://github.com/matrix-org/matrix-js-sdk/issues/3915 we need
  // to also claim v1.1 support. Note that any issues due to this are
  // not considered bugs in persephone.
  static constexpr client_server_json::versions versions = {
      .versions = {"v1.1", "v1.8"}};
  json j = versions;

  auto resp = HttpResponse::newHttpResponse();
  resp->setBody(j.dump());
  resp->setExpiredTime(0);
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ClientServerCtrl::whoami(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  // Get the access token from the Authorization header
  auto auth_header = req->getHeader("Authorization");
  if (auth_header.empty()) {
    return_error(callback, "M_MISSING_TOKEN", "Missing Authorization header",
                 401);
    return;
  }
  Database db{};
  // Remove the "Bearer " prefix
  auto access_token = auth_header.substr(7);

  auto resp = HttpResponse::newHttpResponse();

  // Check if we have the access token in the database
  auto user_info = db.get_user_info(access_token);

  if (!user_info) {
    return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token", 401);
    return;
  }

  // Return the user id, if the user is a guest and the
  // device id if its set as json
  client_server_json::whoami_resp j_resp = {
      .user_id = user_info->user_id,
      .is_guest = user_info->is_guest,
      .device_id = user_info->device_id,
  };
  json j = j_resp;

  resp->setBody(j.dump());
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ClientServerCtrl::user_available(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &username) const {

  // FIXME: Can I prevent the io here somehow?
  Config config;
  auto server_name = config.matrix_config.server_name;

  // Check if the username is valid
  auto fixed_username = migrate_localpart(username);
  if (!is_valid_localpart(fixed_username, server_name)) {
    return_error(callback, "M_INVALID_USERNAME", "Invalid username", 400);
    return;
  }

  Database db{};
  auto resp = HttpResponse::newHttpResponse();
  // Check if the username is already taken
  auto user_exists =
      db.user_exists(std::format("@{}:{}", fixed_username, server_name));

  if (user_exists) {
    return_error(callback, "M_USER_IN_USE", "Username already taken", 400);
    return;
  }

  // Check if the username is in a namespace exclusively
  // claimed by an application service.
  // TODO: Implement this

  // Return 200 OK with empty json body
  const auto json_data = []() {
    auto j = json::object();
    j["available"] = true;
    return j.dump();
  }();

  resp->setBody(json_data);
  resp->setExpiredTime(0);
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ClientServerCtrl::login(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback) const {

  const auto login = []() {
    client_server_json::LoginFlow password_flow = {.type = "m.login.password"};
    client_server_json::GetLogin login{.flows = {password_flow}};
    json j = login;
    return j.dump();
  }();

  auto resp = HttpResponse::newHttpResponse();
  resp->setBody(login);
  resp->setExpiredTime(0);
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ClientServerCtrl::register_user(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  // Get the request body as json
  json body = json::parse(req->body());
  auto reg_body = body.get<client_server_json::registration_body>();

  // Do registration. If the db fails we return an error 400.
  // This can be M_USER_IN_USE if the user already exists
  // M_INVALID_USERNAME if the username is invalid
  // M_EXCLUSIVE if the user is in a namespace exclusively claimed by an
  // application service.
  //
  // If the auth data is incomplete we return status code 401 instead.

  // Check type of registration via the optional query parameter `kind`
  // If the parameter is not set, we default to "user"
  auto kind_param = req->getOptionalParameter<std::string>("kind");
  std::string kind = kind_param.value_or("user");

  // TODO: Remove this if we support guests:
  if (kind == "guest") {
    return_error(callback, "M_UNKNOWN", "Guests are not supported yet", 403);
    return;
  }

  // Check for session in auth object
  if (!reg_body.auth.has_value() || !reg_body.password.has_value()) {
    // we need to return flows and a session id.
    // TODO: Keep track of running sessions
    client_server_json::FlowInformation dummy_flow = {
        .stages = {"m.login.dummy"}};
    client_server_json::incomplete_registration_resp reg_resp = {
        .session = random_string(25),
        .flows = {dummy_flow},
    };
    json j = reg_resp;

    auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(k401Unauthorized);
    resp->setBody(j.dump());
    resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
    callback(resp);
    return;
  }

  // FIXME: Can I prevent the io here somehow?
  Config config;
  auto server_name = config.matrix_config.server_name;

  // Check if the username is valid. Note that `username` means localpart in
  // matrix terms.
  auto username = reg_body.username.value_or(random_string(25));
  auto fixed_username = migrate_localpart(username);
  auto user_id = std::format("@{}:{}", fixed_username, server_name);
  if (!is_valid_localpart(fixed_username, server_name)) {
    return_error(callback, "M_INVALID_USERNAME", "Invalid username", 400);
    return;
  }

  Database db{};
  auto resp = HttpResponse::newHttpResponse();
  auto user_exists = db.user_exists(user_id);

  // Check if the username is already taken
  if (user_exists) {
    return_error(callback, "M_USER_IN_USE", "Username already taken", 400);
    return;
  }
  auto initial_device_display_name = reg_body.initial_device_display_name;
  auto device_id = reg_body.device_id;

  // If we have no initial_device_display_name, we set it to the
  // device_id
  if (!initial_device_display_name) {
    initial_device_display_name = device_id;
  }

  if (!reg_body.username.has_value() || !reg_body.password.has_value()) {
    return_error(callback, "M_UNKNOWN",
                 "Invalid input. You are missing either username or password",
                 500);
    return;
  }

  // Try to register the user
  Database::UserCreationData data{user_id, device_id,
                                  initial_device_display_name,
                                  reg_body.password.value()};
  auto device_data = db.create_user(data);

  auto access_token = std::make_optional<std::string>();
  auto device_id_opt = std::make_optional<std::string>();
  if (!reg_body.inhibit_login) {
    access_token = device_data.access_token;
    device_id_opt = device_data.device_id;
  }

  client_server_json::registration_resp reg_resp = {
      .access_token = access_token,
      .device_id = device_id_opt,
      .user_id = user_id,
  };
  json j = reg_resp;
  resp->setBody(j.dump());
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}