#include "ClientServerCtrl.hpp"
#include "database/database.hpp"
#include "nlohmann/json.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
#include <fstream>
#include <iostream>
#include <utils/state_res.hpp>
#include <unicode/locid.h>
#include <unicode/unistr.h>

using namespace client_server_api;
using json = nlohmann::json;

void AccessTokenFilter::doFilter(const HttpRequestPtr &req, FilterCallback &&cb,
                                 FilterChainCallback &&ccb) {
  drogon::async_run([req, ccb = std::move(ccb),
      cb = std::move(cb)]() -> drogon::Task<> {
      // If this is an OPTIONS request, we can skip the filter
      if (req->method() == drogon::Options) {
        ccb();
        co_return;
      }

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
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      callback(resp);
    });
}

void ClientServerCtrl::login(
  const HttpRequestPtr &req,
  std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback),
      this]() -> drogon::Task<> {
      if (req->method() == drogon::Get) {
        const auto login_flow = []() {
          const client_server_json::LoginFlow password_flow = {.type = "m.login.password"};
          client_server_json::GetLogin login{.flows = {password_flow}};
          const json j = login;
          return j.dump();
        }();

        const auto resp = HttpResponse::newHttpResponse();
        resp->setBody(login_flow);
        resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
        callback(resp);
      } else if (req->method() == drogon::Post) {
        // Print body for debugging
        LOG_DEBUG << "Body: " << req->body();
        LOG_DEBUG << "Content type: " << req->getHeader("Content-Type");
        // Parse body as login_body json
        json body;
        try {
          body = json::parse(req->body());
        } catch (json::parse_error &ex) {
          LOG_WARN << "Failed to parse json in login: " << ex.what() << '\n';
          return_error(callback, "M_NOT_JSON",
                       "Unable to parse json. Is this valid json?", 500);
          co_return;
        }

        client_server_json::login_body login_body;
        try {
          login_body = body.get<client_server_json::login_body>();
        } catch (...) {
          const auto ex_re = std::current_exception();
          try {
            std::rethrow_exception(ex_re);
          } catch (std::bad_exception const &ex) {
            LOG_WARN << "Failed to parse json as login_body in login: " << ex.what()
                << '\n';
          }
          return_error(callback, "M_BAD_JSON",
                       "Unable to parse json. Ensure all required fields are present?",
                       500);
          co_return;
        }

        // We for now only support type "m.login.password"
        if (login_body.type != "m.login.password") {
          return_error(callback, "M_UNKNOWN", "Unknown login type", 400);
          co_return;
        }

        // If identifier is not set, we return 400
        if (!login_body.identifier.has_value()) {
          return_error(callback, "M_UNKNOWN", "Missing identifier", 400);
          co_return;
        }

        // Use the database login function to check if the user exists and create an access token
        try {
          const auto supplied_user_id = login_body.identifier->user.value();
          // Convert the user id to a icu compatible char16_t/UChar string
          icu_74::UnicodeString user_id_icu(supplied_user_id.c_str());
          // Get the english locale
          const auto locale = icu_74::Locale::getEnglish();

          // Ensure the user id is lowercase using icu library's u_strToLower
          const auto user_id_lower_uci = user_id_icu.toLower(locale);

          // Convert the user id to a std::string again
          std::string user_id_lower;
          user_id_lower_uci.toUTF8String(user_id_lower);
          // If the user id does not start with @, we assume it is a localpart and append the server name
          const std::string user_id = user_id_lower[0] == '@'
                                        ? user_id_lower
                                        : std::format("@{}:{}", user_id_lower,
                                                      _config.matrix_config.server_name);

          const auto login_resp = co_await _db.login(
            user_id, login_body.password.value(),
            login_body.initial_device_display_name,
            login_body.device_id);

          // If the login was successful, return the response as json
          const auto resp = HttpResponse::newHttpResponse();
          resp->setBody(json(login_resp).dump());
          resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
          resp->setStatusCode(k200OK);
          callback(resp);
        } catch (const std::exception &e) {
          // Return 403 M_FORBIDDEN if the login failed
          return_error(callback, "M_FORBIDDEN", e.what(), 403);
          co_return;
        }
      } else {
        const auto resp = HttpResponse::newHttpResponse();
        resp->setBody("{}");
        resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
        resp->setStatusCode(k200OK);
        callback(resp);
      }
    });
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
        .matrix_id = user_id, .device_id = device_id,
        .device_name = initial_device_display_name,
        .password = reg_body.password.value()
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

      // TODO: We got this but do we use it somehow?
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
      std::vector<std::string> split_data{
        std::istream_iterator<std::string>(buffer),
        std::istream_iterator<std::string>()
      };
      auto private_key = json_utils::unbase64_key(split_data[2]);

      if (roomIdOrAlias.starts_with("#")) {
        //  We first need to lookup the room alias
        auto resp = co_await federation_request(
          {
            .client = client,
            .method = drogon::Get,
            .path = std::format(
              "/_matrix/federation/v1/query/directory?room_alias={}",
              roomIdOrAlias),
            .key_id = split_data[1],
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

        const auto &param_server_name = server_names.value();
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
          .key_id = split_data[1],
          .secret_key = private_key,
          .origin = _config.matrix_config.server_name,
          .target = server_address.server_name,
          .content = nullptr,
          .timeout = 30
        });

      if (make_join_resp->statusCode() == 404) {
        return_error(callback, "M_NOT_FOUND",
                     "The remote server doesn't know the room.", 404);
        co_return;
      }
      if (make_join_resp->statusCode() == 403) {
        json resp_body = json::parse(make_join_resp->body());
        auto [errcode, error] = resp_body.get<generic_json::generic_json_error>();
        return_error(callback, errcode, error, 403);
        co_return;
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
        co_return;
      }

      if (make_join_resp->statusCode() != 200) {
        return_error(callback, "M_UNKNOWN",
                     "The remote server returned an error thats not known to us.",
                     500);
        co_return;
      }
      json resp_body = json::parse(make_join_resp->body());
      auto [event, room_version] = resp_body.get<server_server_json::MakeJoinResp>();

      // If we dont get a room_version we assume its either version 1 or 2 which means we do NOT support this and break
      if (!room_version) {
        return_error(callback, "M_UNKNOWN",
                     "The remote server did not return a room version which means we don't support it.", 500);
        co_return;
      }

      //  Update origin, origin_server_ts and event_id
      event["origin"] = _config.matrix_config.server_name;
      event["origin_server_ts"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

      event["event_id"] = event_id(event, room_version.value());
      // Sign the make_join response as this is now the event
      auto signed_event = json_utils::sign_json(
        _config.matrix_config.server_name, split_data[1], private_key,
        event);

      // Send the signed event to the remote server on the v2/send_join endpoint
      auto send_join_resp = co_await federation_request(
        {
          .client = client,
          .method = drogon::Put,
          .path = std::format("/_matrix/federation/v2/send_join/{}/{}?omit_members=false", room_id,
                              event["event_id"].get<std::string>()),
          .key_id = split_data[1],
          .secret_key = private_key,
          .origin = _config.matrix_config.server_name,
          .target = server_address.server_name,
          .content = signed_event,
          .timeout = 30
        });

      if (send_join_resp->statusCode() == 400) {
        // Event was invalid in some way
        return_error(callback, "M_UNKNOWN",
                     "The remote server considers the join event invalid.",
                     500);
        co_return;
      }

      if (send_join_resp->statusCode() == 403) {
        json error_resp_body = json::parse(send_join_resp->body());
        auto [errcode, error] = error_resp_body.get<generic_json::generic_json_error>();
        return_error(callback, errcode, error, 403);
        co_return;
      }

      if (send_join_resp->statusCode() != 200) {
        return_error(callback, "M_UNKNOWN",
                     "The remote server returned an error thats not known to us.",
                     500);
        co_return;
      }
      json send_join_resp_body = json::parse(send_join_resp->body());
      auto [auth_chain,membership_event,members_omitted,origin,servers_in_room,state] =
          send_join_resp_body.get<server_server_json::SendJoinResp>();

      // TODO: We probably should do state res here first but for now lets just dumb the state with the membership event appended into the db
      std::vector<json> state_with_membership = state;
      state_with_membership.push_back(membership_event);

      const auto sql = drogon::app().getDbClient();
      const auto transaction = sql->newTransaction();
      co_await _db.add_room(transaction, state_with_membership, room_id);


      // TODO: Walk the auth_chain, get our signed membership event, use the resolved current room state prior to join
      // TODO: In the future consider faster room joins here


      const auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k200OK);
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      // TODO: Generate the response body
      callback(resp);

      co_return;
    });
}

void ClientServerCtrl::createRoom(
  const HttpRequestPtr &req,
  std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback),
      this]() -> drogon::Task<> {
      // Get the access token from the Authorization header
      const auto req_auth_header = req->getHeader("Authorization");
      if (req_auth_header.empty()) {
        return_error(callback, "M_MISSING_TOKEN", "Missing Authorization header",
                     401);
        co_return;
      }
      // Remove the "Bearer " prefix
      const auto access_token = req_auth_header.substr(7);
      // Check if we have the access token in the database
      const auto user_info = co_await _db.get_user_info(access_token);
      if (!user_info) {
        return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token", 401);
        co_return;
      }

      LOG_DEBUG << "User " << user_info->user_id << " is creating a room";
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
        const std::exception_ptr ex_re = std::current_exception();
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

      LOG_DEBUG << "Checking if room version is supported";

      if (createRoom_body.room_version.has_value()) {
        if (createRoom_body.room_version.value() == "11") {
          return_error(
            callback, "M_UNSUPPORTED_ROOM_VERSION",
            std::format(
              "The requested room version of this room is {} but your "
              "Homeserver does not support that version yet.",
              createRoom_body.room_version.value()),
            400);
        }
      }

      LOG_DEBUG << "Creating room with room version: "
          << createRoom_body.room_version.value_or("11");


      // Generate room_id
      auto room_id = generate_room_id(_config.matrix_config.server_name);


      // Create the actual PDU from the supplied data
      json pdu = {
        {"type", "m.room.create"},
        {
          "content", createRoom_body.creation_content.value_or(json::object({
            {"creator", user_info->user_id},
            {"room_version", createRoom_body.room_version.value_or("11")},
          }))
        },
        {
          "origin_server_ts", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()
        },
        {"sender", user_info->user_id},
        {"state_key", ""},
        {"room_id", room_id},
      };

      // TODO: Properly apply the preset rules and all the powerlevel events and friends

      // Calculate and add event_id
      try {
        pdu["event_id"] = event_id(pdu, createRoom_body.room_version.value_or("11"));
      } catch (const std::exception &e) {
        LOG_ERROR << "Failed to calculate event_id: " << e.what();
        return_error(callback, "M_UNKNOWN", "Failed to calculate event_id", 500);
        co_return;
      }

      LOG_DEBUG << "Created PDU: " << pdu.dump();

      // Sign the pdu
      std::ifstream t(_config.matrix_config.server_key_location);
      std::string server_key((std::istreambuf_iterator<char>(t)),
                             std::istreambuf_iterator<char>());
      std::istringstream buffer(server_key);
      std::vector<std::string> split_data{
        std::istream_iterator<std::string>(buffer),
        std::istream_iterator<std::string>()
      };
      auto private_key = json_utils::unbase64_key(split_data[2]);
      auto signed_event = json_utils::sign_json(
        _config.matrix_config.server_name, split_data[1], private_key,
        pdu);
      // create room in db
      const auto sql = drogon::app().getDbClient();
      const auto transaction = sql->newTransaction();
      try {
        co_await _db.add_room(transaction, {signed_event}, room_id);
      } catch (const std::exception &e) {
        LOG_ERROR << "Failed to add room to db: " << e.what();
        return_error(callback, "M_UNKNOWN", "Failed to add room to db", 500);
        co_return;
      }

      // TODO: state res?!

      // Add initial state to db
      if (createRoom_body.initial_state.has_value()) {
        // Generate event_ids for all state events
        for (auto &state_event: createRoom_body.initial_state.value()) {
          state_event.event_id = event_id(state_event, createRoom_body.room_version.value_or("11"));
        }

        try {
          co_await _db.add_state_events(transaction, createRoom_body.initial_state.value(),
                                        room_id);
        } catch (const std::exception &e) {
          LOG_ERROR << "Failed to add initial state to db: " << e.what();
          return_error(callback, "M_UNKNOWN", "Failed to add initial state to db", 500);
          co_return;
        }
      }

      // TODO: Invites

      // Return the room_id as a json response
      json resp_body = {
        {"room_id", room_id},
      };

      const auto resp = HttpResponse::newHttpResponse();
      resp->setBody(resp_body.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      resp->setStatusCode(k200OK);
      callback(resp);
      co_return;
    }
  );
}
