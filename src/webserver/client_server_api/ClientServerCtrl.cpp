#include "ClientServerCtrl.hpp"
#include "database/database.hpp"
#include "nlohmann/json.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
#include <fstream>
#include <iostream>

using namespace client_server_api;
using json = nlohmann::json;

void AccessTokenFilter::doFilter(const HttpRequestPtr &req, FilterCallback &&cb,
                                 FilterChainCallback &&ccb) {
  drogon::async_run([req, ccb = std::move(ccb),
      cb = std::move(cb)]() -> drogon::Task<> {
      // Get the access token from the Authorization header
      const auto auth_header = req->getHeader("Authorization");
      if (auth_header.empty()) {
        return_error(cb, "M_MISSING_TOKEN", "Missing Authorization header", 401);
        co_return;
      }
      constexpr Database db{};
      // Remove the "Bearer " prefix

      if (const auto access_token = auth_header.substr(7); co_await db.validate_access_token(access_token)) {
        ccb();
        co_return;
      }
      return_error(cb, "M_UNKNOWN_TOKEN", "Unrecognised access token.", 401);
      co_return;
    });
}

void ClientServerCtrl::versions(
  const HttpRequestPtr &,
  std::function<void(const HttpResponsePtr &)> &&callback) const {
  // We only support v1.8. However due to
  // https://github.com/matrix-org/matrix-js-sdk/issues/3915 we need
  // to also claim v1.1 support. Note that any issues due to this are
  // not considered bugs in persephone.
  static const client_server_json::versions_obj versions = {
    .versions = {"v1.1", "v1.13"}
  };
  const json j = versions;

  const auto resp = HttpResponse::newHttpResponse();
  resp->setBody(j.dump());
  resp->setExpiredTime(0);
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ClientServerCtrl::whoami(
  const HttpRequestPtr &req,
  std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback),
      this]() -> drogon::Task<> {
      // Get the access token from the Authorization header
      const auto auth_header = req->getHeader("Authorization");
      if (auth_header.empty()) {
        return_error(callback, "M_MISSING_TOKEN", "Missing Authorization header",
                     401);
        co_return;
      }
      // Remove the "Bearer " prefix
      const auto access_token = auth_header.substr(7);

      const auto resp = HttpResponse::newHttpResponse();

      // Check if we have the access token in the database
      const auto user_info = co_await _db.get_user_info(access_token);

      if (!user_info) {
        return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token", 401);
        co_return;
      }

      // Return the user id, if the user is a guest and the
      // device id if its set as json
      client_server_json::whoami_resp j_resp = {
        .user_id = user_info->user_id,
        .is_guest = user_info->is_guest,
        .device_id = user_info->device_id,
      };
      const json j = j_resp;

      resp->setBody(j.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      callback(resp);
    });
}

void ClientServerCtrl::user_available(
  const HttpRequestPtr &,
  std::function<void(const HttpResponsePtr &)> &&callback,
  const std::string &username) const {
  drogon::async_run([username, callback = std::move(callback),
      this]() -> drogon::Task<> {
      auto server_name = _config.matrix_config.server_name;

      // Check if the username is valid
      auto fixed_username = migrate_localpart(username);
      if (!is_valid_localpart(fixed_username, server_name)) {
        return_error(callback, "M_INVALID_USERNAME", "Invalid username", 400);
        co_return;
      }

      const auto resp = HttpResponse::newHttpResponse();
      // Check if the username is already taken
      const auto user_exists = co_await _db.user_exists(
        std::format("@{}:{}", fixed_username, server_name));

      if (user_exists) {
        return_error(callback, "M_USER_IN_USE", "Username already taken", 400);
        co_return;
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
    });
}

void ClientServerCtrl::login(
  const HttpRequestPtr &,
  std::function<void(const HttpResponsePtr &)> &&callback) const {
  const auto login_flow = []() {
    const client_server_json::LoginFlow password_flow = {.type = "m.login.password"};
    client_server_json::GetLogin login{.flows = {password_flow}};
    const json j = login;
    return j.dump();
  }();

  const auto resp = HttpResponse::newHttpResponse();
  resp->setBody(login_flow);
  resp->setExpiredTime(0);
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ClientServerCtrl::register_user(
  const HttpRequestPtr &req,
  std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback),
      this]() -> drogon::Task<> {
      // Get the request body as json
      json body;
      try {
        body = json::parse(req->body());
      } catch (json::parse_error &ex) {
        LOG_WARN << "Failed to parse json in register_user: " << ex.what()
            << '\n';
        return_error(callback, "M_NOT_JSON",
                     "Unable to parse json. Is this valid json?", 500);
        co_return;
      }

      client_server_json::registration_body reg_body;
      try {
        reg_body = body.get<client_server_json::registration_body>();
      } catch (...) {
        auto ex_re = std::current_exception();
        try {
          std::rethrow_exception(ex_re);
        } catch (std::bad_exception const &ex) {
          LOG_WARN
              << "Failed to parse json as registration_body in register_user: "
              << ex.what() << '\n';
        }
        return_error(
          callback, "M_BAD_JSON",
          "Unable to parse json. Ensure all required fields are present?", 500);
        co_return;
      }

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

      // TODO: Remove this if we support guests:
      if (std::string kind = kind_param.value_or("user"); kind == "guest") {
        return_error(callback, "M_UNKNOWN", "Guests are not supported yet", 403);
        co_return;
      }

      // Check for session in auth object
      if (!reg_body.auth.has_value() || !reg_body.password.has_value()) {
        // we need to return flows and a session id.
        // TODO: Keep track of running sessions
        client_server_json::FlowInformation dummy_flow = {
          .stages = {"m.login.dummy"}
        };
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
        co_return;
      }

      auto server_name = _config.matrix_config.server_name;

      // Check if the username is valid. Note that `username` means localpart in
      // matrix terms.
      auto username = reg_body.username.value_or(random_string(25));
      auto fixed_username = migrate_localpart(username);
      auto user_id = std::format("@{}:{}", fixed_username, server_name);
      if (!is_valid_localpart(fixed_username, server_name)) {
        return_error(callback, "M_INVALID_USERNAME", "Invalid username", 400);
        co_return;
      }

      auto resp = HttpResponse::newHttpResponse();

      // Check if the username is already taken
      if (co_await _db.user_exists(user_id)) {
        return_error(callback, "M_USER_IN_USE", "Username already taken", 400);
        co_return;
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
        co_return;
      }

      // Try to register the user
      Database::UserCreationData data{
        user_id, device_id,
        initial_device_display_name,
        reg_body.password.value()
      };
      auto device_data = co_await _db.create_user(data);

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
    });
}

void client_server_api::ClientServerCtrl::joinRoomIdOrAlias(
  const drogon::HttpRequestPtr &req,
  std::function<void(const HttpResponsePtr &)> &&callback,
  const std::string &roomIdOrAlias) const {
  drogon::async_run([req, roomIdOrAlias, callback = std::move(callback),
      this]() -> drogon::Task<> {
      // Get the access token from the Authorization header
      auto req_auth_header = req->getHeader("Authorization");
      if (req_auth_header.empty()) {
        return_error(callback, "M_MISSING_TOKEN", "Missing Authorization header",
                     401);
        co_return;
      }
      // Remove the "Bearer " prefix
      auto access_token = req_auth_header.substr(7);
      // Check if we have the access token in the database
      auto user_info = co_await _db.get_user_info(access_token);

      if (!user_info) {
        return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token", 401);
        co_return;
      }

      // Get the request body as json
      json body;
      try {
        body = json::parse(req->body());
      } catch (json::parse_error &ex) {
        LOG_WARN << "Failed to parse json in joinRoomIdOrAlias: " << ex.what()
            << '\n';
        return_error(callback, "M_NOT_JSON",
                     "Unable to parse json. Is this valid json?", 500);
        co_return;
      }

      client_server_json::JoinBody join_body;
      try {
        join_body = body.get<client_server_json::JoinBody>();
      } catch (...) {
        std::exception_ptr ex_re = std::current_exception();
        try {
          std::rethrow_exception(ex_re);
        } catch (std::bad_exception const &ex) {
          LOG_WARN << "Failed to parse json as JoinBody in joinRoomIdOrAlias: "
              << ex.what() << '\n';
        }
        return_error(
          callback, "M_BAD_JSON",
          "Unable to parse json. Ensure all required fields are present?", 500);
        co_return;
      }

      auto server_names =
          req->getOptionalParameter<std::vector<std::string> >("server_name");

      auto server_name = get_serverpart(roomIdOrAlias);
      auto server_address = co_await discover_server(server_name);
      auto address = std::format("https://{}", server_address.address);
      if (server_address.port) {
        address = std::format("https://{}:{}", server_address.address,
                              server_address.port);
      }
      auto client = HttpClient::newHttpClient(address);
      client->setUserAgent(UserAgent);

      std::string room_id;

      std::ifstream t(_config.matrix_config.server_key_location);
      std::string server_key((std::istreambuf_iterator<char>(t)),
                             std::istreambuf_iterator<char>());
      std::istringstream buffer(server_key);
      std::vector<std::string> splitted_data{
        std::istream_iterator<std::string>(buffer),
        std::istream_iterator<std::string>()
      };
      auto private_key = json_utils::unbase64_key(splitted_data[2]);

      if (roomIdOrAlias.starts_with("#")) {
        //  We first need to lookup the room alias
        auto resp = co_await federation_request(
          {
            .client = client,
            .method = drogon::Get,
            .path = std::format(
              "/_matrix/federation/v1/query/directory?room_alias={}",
              roomIdOrAlias),
            .key_id = splitted_data[1],
            .secret_key = private_key,
            .origin = _config.matrix_config.server_name,
            .target = server_address.server_name,
            .content = nullptr,
            .timeout = 10
          });

        if (resp->statusCode() != 200) {
          return_error(callback, "M_NOT_FOUND", "Room alias not found.", 404);
          co_return;
        }

        // Next we parse the alias to fetch the server
        // Get the response body as json
        json resp_body = json::parse(resp->body());
        auto directory_query = resp_body.get<server_server_json::directory_query>();

        room_id = directory_query.room_id;
      } else {
        //  We can directly use the room id but we will need to have server_name's
        if (!server_names.has_value()) {
          return_error(callback, "M_MISSING_PARAM",
                       "Missing server_name parameter", 500);
        }
        if (server_names.value().empty()) {
          return_error(callback, "M_INVALID_PARAM",
                       "server_name parameter can't be empty if using a room_id",
                       500);
        }

        auto param_server_name = server_names.value();
        // TODO: Try all possible servers
        auto param_server_address =
            co_await discover_server(param_server_name[0]);
        auto param_address = std::format("https://{}", server_address.address);
        if (param_server_address.port) {
          param_address = std::format("https://{}:{}", server_address.address,
                                      server_address.port);
        }
        client = HttpClient::newHttpClient(param_address);
        client->setUserAgent(UserAgent);

        room_id = roomIdOrAlias;
      }

      //  TODO: Join via another server or locally if possible
      //  TODO: Check if we can do this locally because we have someone in the
      //  room already (How?)

      //  Due to drogon we cant use the param handler and need this in the path :/
      auto version_query = generateQueryParamString("ver", {"11"});
      auto path = std::format("/_matrix/federation/v1/make_join/{}/{}{}", room_id,
                              user_info->user_id, version_query);

      auto make_join_resp = co_await federation_request(
        {
          .client = client,
          .method = drogon::Get,
          .path = path,
          .key_id = splitted_data[1],
          .secret_key = private_key,
          .origin = _config.matrix_config.server_name,
          .target = server_address.server_name,
          .content = nullptr,
          .timeout = 30
        });

      if (make_join_resp->statusCode() == 404) {
        return_error(callback, "M_NOT_FOUND",
                     "The remote server doesn't know the room.", 404);
      }
      if (make_join_resp->statusCode() == 403) {
        json resp_body = json::parse(make_join_resp->body());
        auto json_error = resp_body.get<generic_json::generic_json_error>();
        return_error(callback, json_error.errcode, json_error.error, 403);
      }
      if (make_join_resp->statusCode() == 400) {
        json resp_body = json::parse(make_join_resp->body());
        auto incompatible_room_version_error =
            resp_body
            .get<server_server_json::incompatible_room_version_error>();
        return_error(callback, "M_UNSUPPORTED_ROOM_VERSION",
                     std::format("The room version of this room is {} but your "
                                 "Homeserver does not support that version yet.",
                                 incompatible_room_version_error.room_version),
                     400);
      }

      if (make_join_resp->statusCode() != 200) {
        return_error(callback, "M_UNKNOWN",
                     "The remote server returned an error thats not known to us.",
                     500);
      }
      json resp_body = json::parse(make_join_resp->body());
      auto make_join_resp_json = resp_body.get<server_server_json::MakeJoinResp>();

      //  TODO: Update origin, origin_server_ts and event_id
      //  TODO: Sign
      //  TODO: Sendjoin

      co_return;
    });
}

void ClientServerCtrl::createRoom(
  const HttpRequestPtr &req,
  std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback),
      this]() -> drogon::Task<> {
      // Get the access token from the Authorization header
      auto req_auth_header = req->getHeader("Authorization");
      if (req_auth_header.empty()) {
        return_error(callback, "M_MISSING_TOKEN", "Missing Authorization header",
                     401);
        co_return;
      }
      // Remove the "Bearer " prefix
      auto access_token = req_auth_header.substr(7);
      // Check if we have the access token in the database
      auto user_info = co_await _db.get_user_info(access_token);

      if (!user_info) {
        return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token", 401);
        co_return;
      }

      // Get the request body as json
      json body;
      try {
        body = json::parse(req->body());
      } catch (json::parse_error &ex) {
        LOG_WARN << "Failed to parse json in createRoom: " << ex.what() << '\n';
        return_error(callback, "M_NOT_JSON",
                     "Unable to parse json. Is this valid json?", 500);
        co_return;
      }

      client_server_json::CreateRoomBody createRoom_body;
      try {
        createRoom_body = body.get<client_server_json::CreateRoomBody>();
      } catch (...) {
        std::exception_ptr ex_re = std::current_exception();
        try {
          std::rethrow_exception(ex_re);
        } catch (std::bad_exception const &ex) {
          LOG_WARN << "Failed to parse json as CreateRoomBody in createRoom: "
              << ex.what() << '\n';
        }
        return_error(
          callback, "M_BAD_JSON",
          "Unable to parse json. Ensure all required fields are present?", 500);
        co_return;
      }

      if (createRoom_body.room_version) {
        if (createRoom_body.room_version == "11") {
          return_error(
            callback, "M_UNSUPPORTED_ROOM_VERSION",
            std::format(
              "The requested room version of this room is {} but your "
              "Homeserver does not support that version yet.",
              createRoom_body.room_version.value()),
            400);
        }
      }
    });
}
