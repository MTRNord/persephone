#include "ClientServerCtrl.hpp"
#include "database/database.hpp"
#include "database/state_ordering.hpp"
#include "federation/federation_sender.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
#include "webserver/sync_utils.hpp"
#include <algorithm>
#include <chrono>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpClient.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <drogon/drogon_callbacks.h>
#include <drogon/utils/coroutine.h>
#include <exception>
#include <format>
#include <functional>
#include <map>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <ranges>
#include <string>
#include <trantor/net/EventLoop.h>
#include <trantor/utils/Logger.h>
#include <utils/room_utils.hpp>
#include <utils/state_res.hpp>
#include <vector>

using namespace client_server_api;
using json = nlohmann::json;

/// Extract access token from Authorization header or deprecated query
/// parameter. The query parameter method (?access_token=...) was deprecated in
/// Matrix v1.11.
/// @return The access token if found, or empty string if not present.
[[nodiscard]] static std::string
extract_access_token(const HttpRequestPtr &req) {
  // First, try the Authorization header (preferred method)
  if (const auto auth_header = req->getHeader("Authorization");
      !auth_header.empty() && auth_header.starts_with("Bearer ")) {
    return auth_header.substr(7);
  }

  // Fall back to deprecated query parameter (deprecated in v1.11)
  // See: https://spec.matrix.org/v1.11/client-server-api/#using-access-tokens
  if (const auto &query_token = req->getParameter("access_token");
      !query_token.empty()) {
    const auto user_agent = req->getHeader("User-Agent");
    LOG_WARN << "Client using deprecated access_token query parameter "
             << "(deprecated in Matrix v1.11). User-Agent: "
             << (user_agent.empty() ? "(not provided)" : user_agent);
    return query_token;
  }

  return "";
}

void AccessTokenFilter::doFilter(const HttpRequestPtr &req,
                                 FilterCallback &&callback,
                                 FilterChainCallback &&chain_callback) {
  drogon::async_run([req, chain_callback = std::move(chain_callback),
                     callback = std::move(callback)]() -> drogon::Task<> {
    // If this is an OPTIONS request, we can skip the filter
    if (req->method() == drogon::Options) {
      chain_callback();
      co_return;
    }

    // Get the access token from header or query parameter
    const auto access_token = extract_access_token(req);
    if (access_token.empty()) {
      return_error(callback, "M_MISSING_TOKEN",
                   "Missing access token. Provide via Authorization header "
                   "(Bearer token) or access_token query parameter.",
                   k401Unauthorized);
      co_return;
    }

    // Check if the token is valid
    if (co_await Database::validate_access_token(access_token)) {
      chain_callback();
      co_return;
    }
    return_error(callback, "M_UNKNOWN_TOKEN", "Unrecognised access token.",
                 k401Unauthorized);
    co_return;
  });
}

drogon::Task<UserValidData> ClientServerCtrl::getUserInfo(
    const HttpRequestPtr &req,
    const std::function<void(const HttpResponsePtr &)> &callback) const {
  const auto access_token = extract_access_token(req);
  if (access_token.empty()) {
    return_error(callback, "M_MISSING_TOKEN",
                 "Missing access token. Provide via Authorization header "
                 "(Bearer token) or access_token query parameter.",
                 k401Unauthorized);
    co_return {
        .isValid = false,
        .userInfo = std::nullopt,
    };
  }
  // Check if we have the access token in the database
  const auto user_info = co_await Database::get_user_info(access_token);
  if (!user_info) {
    return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token",
                 k401Unauthorized);
    co_return {
        .isValid = false,
        .userInfo = std::nullopt,
    };
  }
  co_return {
      .isValid = true,
      .userInfo = user_info,
  };
}

void ClientServerCtrl::versions(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  // We only support v1.8. However due to
  // https://github.com/matrix-org/matrix-js-sdk/issues/3915 we need
  // to also claim v1.1 support. Note that any issues due to this are
  // not considered bugs in persephone.
  static constexpr client_server_json::versions_obj versions = {
      .versions = {"v1.1", "v1.13"}};
  const json j = versions;

  const auto resp = HttpResponse::newHttpResponse();
  resp->setBody(j.dump());
  resp->setContentTypeString(JSON_CONTENT_TYPE);
  callback(resp);
}

void ClientServerCtrl ::capabilities(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  const auto resp = HttpResponse::newHttpResponse();
  static const client_server_json::room_versions_capability room_versions = {
      .default_ = "11", .available = {{"11", "Unstable"}}};

  static const client_server_json::capabilities_obj capabilities_obj = {
      .third_pid_changes =
          client_server_json::boolean_capability{.enabled = false},
      // TODO: Activate once supported
      .change_password =
          client_server_json::boolean_capability{.enabled = false},
      // TODO: Activate once supported
      .get_login_token =
          client_server_json::boolean_capability{.enabled = false},
      // TODO: Activate once supported
      .set_avatar_url =
          client_server_json::boolean_capability{.enabled = false},
      // TODO: Activate once supported
      .set_displayname =
          client_server_json::boolean_capability{.enabled = false},
      // TODO: Activate once supported
      .profile_fields =
          client_server_json::profile_field_capability{
              .enabled = false, .allowed = {}, .disallowed = {}},
      .room_versions = room_versions,
  };

  static const client_server_json::capabilities_resp capabilities_resp = {
      .capabilities = capabilities_obj};

  const json j = capabilities_resp;

  resp->setBody(j.dump());
  resp->setContentTypeString(JSON_CONTENT_TYPE);
  callback(resp);
}

void ClientServerCtrl::whoami(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback)]() -> drogon::Task<> {
    // Get the access token from the Authorization header or query parameter
    const auto access_token = extract_access_token(req);
    if (access_token.empty()) {
      return_error(callback, "M_MISSING_TOKEN",
                   "Missing access token", k401Unauthorized);
      co_return;
    }

    const auto resp = HttpResponse::newHttpResponse();

    // Check if we have the access token in the database
    const auto user_info = co_await Database::get_user_info(access_token);

    if (!user_info) {
      return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token",
                   k401Unauthorized);
      co_return;
    }

    // Return the user id, if the user is a guest and the
    // device id if its set as json
    client_server_json::whoami_resp const j_resp = {
        .user_id = user_info->user_id,
        .is_guest = user_info->is_guest,
        .device_id = user_info->device_id,
    };
    const json json_data = j_resp;

    resp->setBody(json_data.dump());
    resp->setContentTypeString(JSON_CONTENT_TYPE);
    callback(resp);
  });
}

void ClientServerCtrl::user_available(
    const HttpRequestPtr &,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &username) const {
  drogon::async_run(
      [username, callback = std::move(callback), this]() -> drogon::Task<> {
        auto server_name = _config.matrix_config.server_name;

        // Check if the username is valid
        auto fixed_username = migrate_localpart(username);
        if (!is_valid_localpart(fixed_username, server_name)) {
          return_error(callback, "M_INVALID_USERNAME", "Invalid username",
                       k400BadRequest);
          co_return;
        }

        const auto resp = HttpResponse::newHttpResponse();
        // Check if the username is already taken.
        // Check both the migrated form (for new registrations) and the
        // lowercased form (for usernames already stored after migration,
        // e.g. when the client sends back a localpart extracted from a
        // user_id that was already migrated during registration).
        auto lowered_username = to_lower(username);
        const auto migrated_exists = co_await Database::user_exists(
            std::format("@{}:{}", fixed_username, server_name));
        const auto lowered_exists =
            (lowered_username != fixed_username)
                ? co_await Database::user_exists(
                      std::format("@{}:{}", lowered_username, server_name))
                : false;
        const auto user_exists = migrated_exists || lowered_exists;

        if (user_exists) {
          return_error(callback, "M_USER_IN_USE", "Username already taken",
                       k400BadRequest);
          co_return;
        }

        // Check if the username is in a namespace exclusively
        // claimed by an application service.
        // TODO: Implement this

        // Return 200 OK with empty json body
        const auto json_data = []() {
          auto json_data_inner = json::object();
          json_data_inner["available"] = true;
          return json_data_inner.dump();
        }();

        resp->setBody(json_data);
        resp->setContentTypeString(JSON_CONTENT_TYPE);
        callback(resp);
      });
}

void ClientServerCtrl::login_get(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback)]() -> drogon::Task<> {
    const auto login_flow = []() {
      const client_server_json::LoginFlow password_flow = {
          .type = "m.login.password"};
      client_server_json::GetLogin const login{.flows = {password_flow}};
      const json json_data = login;
      return json_data.dump();
    }();

    const auto resp = HttpResponse::newHttpResponse();
    resp->setBody(login_flow);
    resp->setContentTypeString(JSON_CONTENT_TYPE);
    callback(resp);
    co_return;
  });
}

void ClientServerCtrl::login_post(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback),
                     this]() -> drogon::Task<> {
    // Parse body as login_body json
    json body;
    try {
      body = json::parse(req->body());
    } catch (json::parse_error &ex) {
      LOG_WARN << "Failed to parse json in login: " << ex.what() << '\n';
      return_error(callback, "M_NOT_JSON",
                   "Unable to parse json. Is this valid json?", k400BadRequest);
      co_return;
    }

    client_server_json::login_body login_body;
    try {
      login_body = body.get<client_server_json::login_body>();
    } catch (const std::exception &ex) {
      LOG_WARN << "Failed to parse json as login_body in login: " << ex.what()
               << '\n';
      return_error(
          callback, "M_BAD_JSON",
          "Unable to parse json. Ensure all required fields are present?",
          k400BadRequest);
      co_return;
    }

    // We for now only support type "m.login.password"
    if (login_body.type != "m.login.password") {
      return_error(callback, "M_UNKNOWN", "Unknown login type", k400BadRequest);
      co_return;
    }

    // If identifier is not set, we return 400
    if (!login_body.identifier.has_value()) {
      return_error(callback, "M_UNKNOWN", "Missing identifier", k400BadRequest);
      co_return;
    }

    // Use the database login function to check if the user exists and
    // create an access token
    try {
      const auto supplied_user_id = login_body.identifier->user.value();
      const auto user_id_lower = to_lower(std::string(supplied_user_id));
      // If the user id does not start with @, we assume it is a localpart
      // and append the server name
      const std::string user_id =
          user_id_lower[0] == '@'
              ? user_id_lower
              : std::format("@{}:{}", user_id_lower,
                            _config.matrix_config.server_name);

      const Database::LoginData login_data{
          .matrix_id = user_id,
          .password = login_body.password.value(),
          .initial_device_name = login_body.initial_device_display_name,
          .device_id = login_body.device_id,
      };
      // Note: login_body fields are now std::string (not string_view) to
      // ensure proper ownership and prevent UTF-8 encoding issues
      const auto login_resp = co_await Database::login(login_data);

      // If the login was successful, return the response as json
      const auto resp = HttpResponse::newHttpResponse();
      resp->setBody(json(login_resp).dump());
      resp->setContentTypeString(JSON_CONTENT_TYPE);
      resp->setStatusCode(k200OK);
      callback(resp);
    } catch (const std::exception &e) {
      // Return 403 M_FORBIDDEN if the login failed
      return_error(callback, "M_FORBIDDEN", e.what(), k403Forbidden);
      co_return;
    }
    co_return;
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
                   "Unable to parse json. Is this valid json?", k400BadRequest);
      co_return;
    }

    client_server_json::registration_body reg_body;
    try {
      reg_body = body.get<client_server_json::registration_body>();
    } catch (const std::exception &ex) {
      LOG_WARN
          << "Failed to parse json as registration_body in register_user: "
          << ex.what() << '\n';
      return_error(
          callback, "M_BAD_JSON",
          "Unable to parse json. Ensure all required fields are present?",
          k400BadRequest);
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
    if (std::string const kind = kind_param.value_or("user"); kind == "guest") {
      return_error(callback, "M_UNKNOWN", "Guests are not supported yet",
                   k403Forbidden);
      co_return;
    }

    // Check for session in auth object
    if (!reg_body.auth.has_value() || !reg_body.password.has_value()) {
      // we need to return flows and a session id.
      // TODO: Keep track of running sessions
      client_server_json::FlowInformation dummy_flow = {
          .stages = {"m.login.password"}};
      client_server_json::incomplete_registration_resp const reg_resp = {
          .session = random_string(25),
          .flows = {dummy_flow},
      };
      json const json_data = reg_resp;

      auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k401Unauthorized);
      resp->setBody(json_data.dump());
      resp->setContentTypeString(JSON_CONTENT_TYPE);
      callback(resp);
      co_return;
    }

    auto server_name = _config.matrix_config.server_name;

    if (!reg_body.username.has_value() || !reg_body.password.has_value()) {
      return_error(callback, "M_UNKNOWN",
                   "Invalid input. You are missing either username or password",
                   k400BadRequest);
      co_return;
    }

    // Check if the username is valid. Note that `username` means localpart in
    // matrix terms.
    // TODO: Add a comment why we do a random string fallback?!
    auto username = reg_body.username.value_or(random_string(25));
    auto fixed_username = migrate_localpart(username);
    auto user_id = std::format("@{}:{}", fixed_username, server_name);
    if (!is_valid_localpart(fixed_username, server_name)) {
      return_error(callback, "M_INVALID_USERNAME", "Invalid username",
                   k400BadRequest);
      co_return;
    }

    auto resp = HttpResponse::newHttpResponse();

    // Check if the username is already taken
    if (co_await Database::user_exists(user_id)) {
      return_error(callback, "M_USER_IN_USE", "Username already taken",
                   k400BadRequest);
      co_return;
    }
    auto initial_device_display_name = reg_body.initial_device_display_name;
    auto device_id = reg_body.device_id;

    // If we have no initial_device_display_name, we set it to the
    // device_id
    if (!initial_device_display_name) {
      initial_device_display_name = device_id;
    }

    // Try to register the user
    Database::UserCreationData const data{
        .matrix_id = user_id,
        .device_id = device_id,
        .device_name = initial_device_display_name,
        .password = reg_body.password.value()};
    auto device_data = co_await Database::create_user(data);

    auto access_token = std::make_optional<std::string>();
    auto device_id_opt = std::make_optional<std::string>();
    if (!reg_body.inhibit_login) {
      access_token = device_data.access_token;
      device_id_opt = device_data.device_id;
    }

// Optionals cause diagnostic false positives here
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
    client_server_json::registration_resp const reg_resp = {
        .access_token = access_token,
        .device_id = device_id_opt,
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
        .expires_in_ms = {},
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
        .refresh_token = {},
        .user_id = user_id,
    };
#pragma GCC diagnostic pop
    const json json_data = reg_resp;
    resp->setBody(json_data.dump());
    resp->setContentTypeString(JSON_CONTENT_TYPE);
    callback(resp);
  });
}

void client_server_api::ClientServerCtrl::getPushrules(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run(
      [req, callback = std::move(callback), this]() -> drogon::Task<> {
        const auto [isValid, userInfo] = co_await getUserInfo(req, callback);
        if (!isValid) {
          co_return;
        }

        // Fetch pushrules from the database
        const auto pushrules =
            co_await Database::get_pushrules_for_user(userInfo->user_id);

        // Respond with the pushrules
        const auto resp = HttpResponse::newHttpResponse();
        resp->setBody(pushrules.dump());
        resp->setContentTypeString(JSON_CONTENT_TYPE);
        resp->setStatusCode(k200OK);
        callback(resp);
        co_return;
      });
}

void client_server_api::ClientServerCtrl::directoryLookupRoomAlias(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &roomAlias) const {
  drogon::async_run([req, roomAlias, callback = std::move(callback),
                     this]() -> drogon::Task<> {
    // TODO: Cache this data in the db and use it if possible

    // Request the room alias from the server it is registered on

    // split off the server name from the room alias
    const auto server_name = get_serverpart(roomAlias);

    // If we are the server requested then we can directly query the database
    // for the alias
    if (server_name == _config.matrix_config.server_name) {
      // TODO: Move this to a util since we need it on server-server api as well
      const auto room_id_opt =
          co_await Database::room_exists_by_alias(roomAlias);
      if (!room_id_opt.has_value()) {
        return_error(callback, "M_NOT_FOUND", "Room alias not found.",
                     k404NotFound);
        co_return;
      }
      const auto &room_id = room_id_opt.value();
      const server_server_json::DirectoryQueryResp directory_query_resp{
          // TODO: Figure out also the other servers
          .room_id = room_id,
          .servers = {server_name}};

      const json json_resp = directory_query_resp;

      const auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k200OK);
      resp->setContentTypeString(JSON_CONTENT_TYPE);
      resp->setBody(json_resp.dump());
      callback(resp);
      co_return;
    }

    const auto server_address = co_await discover_server(server_name);
    const auto client = create_http_client_for_resolved(server_address);
    client->setUserAgent(UserAgent);

    const auto key_data = get_verify_key_data(_config);

    LOG_DEBUG << "Requesting room alias \"" << roomAlias
              << "\" from server: " << server_address.address
              << " with port: " << server_address.port.value_or(0);

    // Do the request
    const auto resp = co_await federation_request(
        {.client = client,
         .method = drogon::Get,
         .path = std::format(
             "/_matrix/federation/v1/query/directory?room_alias={}",
             drogon::utils::urlEncodeComponent(roomAlias)),
         .key_id = key_data.key_id,
         .secret_key = key_data.private_key,
         .origin = _config.matrix_config.server_name,
         .target = server_address.server_name,
         // Ensure Host header follows any delegation (delegated host/IP),
         // by explicitly setting the host header to the discovered server_name.
         .host_header = build_host_header(server_address),
         .content = nullptr,
         .timeout = DEFAULT_FEDERATION_TIMEOUT});

    // Pass the response back as the response to the client without
    // modifications
    callback(resp);
    co_return;
  });
}

void client_server_api::ClientServerCtrl::joinRoomIdOrAlias(
    const drogon::HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &roomIdOrAlias) const {
  drogon::async_run([req, roomIdOrAlias, callback = std::move(callback),
                     this]() -> drogon::Task<> {
    const auto [isValid, userInfo] = co_await getUserInfo(req, callback);
    if (!isValid) {
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
                   "Unable to parse json. Is this valid json?", k400BadRequest);
      co_return;
    }

    // TODO: We got this but do we use it somehow?
    client_server_json::JoinBody join_body;
    try {
      join_body = body.get<client_server_json::JoinBody>();
    } catch (...) {
      std::exception_ptr const ex_re = std::current_exception();
      try {
        std::rethrow_exception(ex_re);
      } catch (std::bad_exception const &ex) {
        LOG_WARN << "Failed to parse json as JoinBody in joinRoomIdOrAlias: "
                 << ex.what() << '\n';
      }
      return_error(
          callback, "M_BAD_JSON",
          "Unable to parse json. Ensure all required fields are present?",
          k400BadRequest);
      co_return;
    }

    // Parse server_name query parameters (can appear multiple times)
    const auto query_string = req->getQuery();
    const auto parsed_params = parseQueryParamString(query_string);
    std::optional<std::vector<std::string>> server_names;
    if (auto it = parsed_params.find("server_name");
        it != parsed_params.end()) {
      server_names = it->second;
    }

    const auto server_name = get_serverpart(roomIdOrAlias);
    auto server_address = co_await discover_server(server_name);
    auto client = create_http_client_for_resolved(server_address);
    client->setUserAgent(UserAgent);

    std::string room_id;

    const auto key_data = get_verify_key_data(_config);

    if (roomIdOrAlias.starts_with("#")) {
      //  We first need to lookup the room alias
      auto resp = co_await federation_request(
          {.client = client,
           .method = drogon::Get,
           .path = std::format(
               "/_matrix/federation/v1/query/directory?room_alias={}",
               drogon::utils::urlEncodeComponent(roomIdOrAlias)),
           .key_id = key_data.key_id,
           .secret_key = key_data.private_key,
           .origin = _config.matrix_config.server_name,
           .target = server_address.server_name,
           // Ensure Host header follows any delegation (delegated host/IP),
           // by explicitly setting the host header to the discovered
           // server_name.
           .host_header = build_host_header(server_address),
           .content = nullptr,
           .timeout = DEFAULT_FEDERATION_TIMEOUT});

      if (resp->statusCode() != k200OK) {
        return_error(callback, "M_NOT_FOUND", "Room alias not found.",
                     k404NotFound);
        co_return;
      }

      // Next we parse the alias to fetch the server
      // Get the response body as json
      json const resp_body = json::parse(resp->body());
      const auto directory_query =
          resp_body.get<server_server_json::directory_query>();

      room_id = directory_query.room_id;
    } else {
      //  We can directly use the room id but we will need to have server_name's
      if (!server_names.has_value()) {
        return_error(callback, "M_MISSING_PARAM",
                     "Missing server_name parameter", k500InternalServerError);
        co_return;
      }
      if (server_names.value().empty()) {
        return_error(callback, "M_INVALID_PARAM",
                     "server_name parameter can't be empty if using a room_id",
                     k500InternalServerError);
        co_return;
      }

      const auto &param_server_name = server_names.value();
      // TODO: Try all possible servers
      auto param_server_address =
          co_await discover_server(param_server_name[0]);
      client = create_http_client_for_resolved(param_server_address);
      client->setUserAgent(UserAgent);
      // Use the discovered param server address for subsequent federation
      // requests in this flow so targets/Host headers are correct.
      server_address = param_server_address;

      room_id = roomIdOrAlias;
    }

    //  TODO: Join via another server or locally if possible
    //  TODO: Check if we can do this locally because we have someone in the
    //  room already (How?)

    //  Due to drogon we cant use the param handler and need this in the path :/
    auto version_query =
        generateQueryParamString("ver", {default_room_version});
    auto path = std::format("/_matrix/federation/v1/make_join/{}/{}{}", room_id,
                            userInfo->user_id, version_query);

    auto make_join_resp = co_await federation_request(
        {.client = client,
         .method = drogon::Get,
         .path = path,
         .key_id = key_data.key_id,
         .secret_key = key_data.private_key,
         .origin = _config.matrix_config.server_name,
         .target = server_address.server_name,
         // Ensure Host header follows any delegation (delegated host/IP),
         // by explicitly setting the host header to the discovered server_name.
         .host_header = build_host_header(server_address),
         .content = nullptr,
         .timeout = DEFAULT_FEDERATION_TIMEOUT});

    if (make_join_resp->statusCode() == k404NotFound) {
      return_error(callback, "M_NOT_FOUND",
                   "The remote server doesn't know the room.", k404NotFound);
      co_return;
    }
    if (make_join_resp->statusCode() == k403Forbidden) {
      json const resp_body = json::parse(make_join_resp->body());
      auto [errcode, error] = resp_body.get<generic_json::generic_json_error>();
      return_error(callback, errcode, error, k403Forbidden);
      co_return;
    }
    if (make_join_resp->statusCode() == k400BadRequest) {
      json const resp_body = json::parse(make_join_resp->body());
      auto incompatible_room_version_error =
          resp_body.get<server_server_json::incompatible_room_version_error>();
      return_error(callback, "M_UNSUPPORTED_ROOM_VERSION",
                   std::format("The room version of this room is {} but your "
                               "Homeserver does not support that version yet.",
                               incompatible_room_version_error.room_version),
                   k400BadRequest);
      co_return;
    }

    if (make_join_resp->statusCode() != k200OK) {
      return_error(callback, "M_UNKNOWN",
                   "The remote server returned an error thats not known to us.",
                   k500InternalServerError);
      co_return;
    }
    json const resp_body = json::parse(make_join_resp->body());
    auto [event, room_version] =
        resp_body.get<server_server_json::MakeJoinResp>();

    // If we dont get a room_version we assume its either version 1 or 2 which
    // means we do NOT support this and break
    if (!room_version) {
      return_error(callback, "M_UNKNOWN",
                   "The remote server did not return a room version which "
                   "means we don't support it.",
                   k500InternalServerError);
      co_return;
    }

    //  Update origin_server_ts, compute content hash, sign, then event_id
    event["origin_server_ts"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();

    // Compute content hash before signing
    event["hashes"] = json::object(
        {{"sha256", content_hash(event, room_version.value())}});

    // Sign using spec-correct redaction-based signing (without event_id)
    auto signed_event =
        sign_event(event, room_version.value(),
                   _config.matrix_config.server_name, key_data.key_id,
                   key_data.private_key);

    // Compute event_id AFTER signing
    signed_event["event_id"] = event_id(signed_event, room_version.value());

    // Send the signed event to the remote server on the v2/send_join endpoint
    auto send_join_resp = co_await federation_request(
        {.client = client,
         .method = drogon::Put,
         .path = std::format(
             "/_matrix/federation/v2/send_join/{}/{}?omit_members=false",
             room_id, signed_event["event_id"].get<std::string>()),
         .key_id = key_data.key_id,
         .secret_key = key_data.private_key,
         .origin = _config.matrix_config.server_name,
         .target = server_address.server_name,
         // Ensure Host header follows any delegation (delegated host/IP),
         // by explicitly setting the host header to the discovered server_name.
         .host_header = build_host_header(server_address),
         .content = signed_event,
         .timeout = DEFAULT_FEDERATION_TIMEOUT});

    if (send_join_resp->statusCode() == k400BadRequest) {
      // Event was invalid in some way
      return_error(callback, "M_UNKNOWN",
                   "The remote server considers the join event invalid.",
                   k500InternalServerError);
      co_return;
    }

    if (send_join_resp->statusCode() == k403Forbidden) {
      json const error_resp_body = json::parse(send_join_resp->body());
      auto [errcode, error] =
          error_resp_body.get<generic_json::generic_json_error>();
      return_error(callback, errcode, error, k403Forbidden);
      co_return;
    }

    if (send_join_resp->statusCode() != k200OK) {
      return_error(callback, "M_UNKNOWN",
                   "The remote server returned an error thats not known to us.",
                   k500InternalServerError);
      co_return;
    }
    json const send_join_resp_body = json::parse(send_join_resp->body());
    auto [auth_chain, membership_event, members_omitted, origin,
          servers_in_room, state] =
        send_join_resp_body.get<server_server_json::SendJoinResp>();

    // TODO: We probably should do state res here first but for now lets just
    // dumb the state with the membership event appended into the db
    std::vector<json> state_with_membership = state;
    state_with_membership.push_back(membership_event);

    // Sort by depth to ensure events are inserted in DAG order so that
    // prev_events and auth_events references resolve correctly.
    std::sort(state_with_membership.begin(), state_with_membership.end(),
              [](const json &a, const json &b) {
                return a.value("depth", static_cast<int64_t>(0)) <
                       b.value("depth", static_cast<int64_t>(0));
              });

    const auto sql = drogon::app().getDbClient();
    const auto transaction = sql->newTransaction();
    co_await Database::add_room(transaction, state_with_membership, room_id);

    // Trigger state ordering for the newly joined room
    // This is important for compression efficiency when receiving state from
    // federation in potentially suboptimal order (from v9 migration schema)
    const auto room_nid_query = co_await sql->execSqlCoro(
        "SELECT room_nid FROM rooms WHERE room_id = $1", room_id);
    if (!room_nid_query.empty()) {
      const int room_nid = room_nid_query.at(0)["room_nid"].as<int>();
      co_await StateOrdering::reorder_room(room_nid);
    }

    // TODO: Walk the auth_chain, get our signed membership event, use the
    // resolved current room state prior to join
    // TODO: In the future consider faster room joins here

    const auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(k200OK);
    resp->setContentTypeString(JSON_CONTENT_TYPE);
    json json_resp = {{"room_id", room_id}};
    resp->setBody(json_resp.dump());
    callback(resp);

    co_return;
  });
}

void ClientServerCtrl::createRoom(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback),
                     this]() -> drogon::Task<> {
    const auto [isValid, userInfo] = co_await getUserInfo(req, callback);
    if (!isValid) {
      co_return;
    }

    LOG_DEBUG << "User " << userInfo->user_id << " is creating a room";
    // Get the request body as json
    json body;
    try {
      body = json::parse(req->body());
    } catch (json::parse_error &ex) {
      LOG_WARN << "Failed to parse json in createRoom: " << ex.what() << '\n';
      return_error(callback, "M_NOT_JSON",
                   "Unable to parse json. Is this valid json?", k400BadRequest);
      co_return;
    }

    client_server_json::CreateRoomBody createRoom_body;
    try {
      createRoom_body = body.get<client_server_json::CreateRoomBody>();
    } catch (const json::type_error &ex) {
      LOG_WARN << "Failed to parse json as CreateRoomBody in createRoom: "
               << ex.what() << '\n';
      return_error(
          callback, "M_BAD_JSON",
          "Unable to parse json. Ensure all required fields are present?",
          k400BadRequest);
      co_return;
    }

    LOG_DEBUG << "Checking if room version is supported";

    if (createRoom_body.room_version.has_value()) {
      if (createRoom_body.room_version.value() != default_room_version) {
        return_error(
            callback, "M_UNSUPPORTED_ROOM_VERSION",
            std::format(
                "The requested room version of this room is {} but your "
                "Homeserver does not support that version yet.",
                createRoom_body.room_version.value()),
            k400BadRequest);
        co_return;
      }
    }

    const auto room_version =
        createRoom_body.room_version.value_or(default_room_version);

    LOG_DEBUG << "Creating room with room version: " << room_version;

    // Generate room_id
    auto room_id = generate_room_id(_config.matrix_config.server_name);
    std::vector<json> state_events;
    try {
      state_events = build_createRoom_state({.createRoom_body = createRoom_body,
                                             .room_id = room_id,
                                             .user_id = userInfo->user_id,
                                             .room_version = room_version},
                                            _config.matrix_config.server_name);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to build room state: " << e.what();
      return_error(callback, "M_UNKNOWN", e.what(), k500InternalServerError);
      co_return;
    }

    // Finalize all state events: sets auth_events, prev_events, depth,
    // computes content hash, event_id, and signs each event.
    const auto key_data = get_verify_key_data(_config);
    LOG_DEBUG << "Finalizing state events";

    finalize_room_creation_events(state_events, room_version,
                                  _config.matrix_config.server_name,
                                  key_data.key_id, key_data.private_key);

    LOG_DEBUG << "Doing state resolution";
    // Call stateres_v2 to get the current state of the room.
    std::vector<std::vector<json>> const state_forks = {state_events};
    std::map<EventType, std::map<StateKey, StateEvent>> solved_state;

    try {
      solved_state = stateres_v2(state_forks);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to resolve state: " << e.what();
      return_error(callback, "M_UNKNOWN", "Failed to resolve state",
                   k500InternalServerError);
      co_return;
    }

    // Convert the solved_state map to a vector of json objects.
    // Sort by depth to ensure correct insertion order -- the map is ordered
    // by event type (alphabetical), but events must be inserted in DAG order
    // so that prev_events and auth_events references resolve correctly.
    std::vector<json> state_events_vector;
    for (const auto &state_event : solved_state | std::views::values) {
      for (const auto &event : state_event | std::views::values) {
        state_events_vector.push_back(event);
      }
    }
    std::sort(state_events_vector.begin(), state_events_vector.end(),
              [](const json &a, const json &b) {
                return a.value("depth", static_cast<int64_t>(0)) <
                       b.value("depth", static_cast<int64_t>(0));
              });

    // create room in db
    LOG_DEBUG << "Adding room to db";
    const auto sql = drogon::app().getDbClient();
    const auto transaction = sql->newTransaction();
    try {
      co_await Database::add_room(transaction, state_events_vector, room_id);

      // Trigger state ordering for the newly created room (for consistency)
      const auto room_nid_query = co_await sql->execSqlCoro(
          "SELECT room_nid FROM rooms WHERE room_id = $1", room_id);
      if (!room_nid_query.empty()) {
        const int room_nid = room_nid_query.at(0)["room_nid"].as<int>();
        co_await StateOrdering::reorder_room(room_nid);
      }
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to add room to db: " << e.what();
      return_error(callback, "M_UNKNOWN", "Failed to add room to db",
                   k500InternalServerError);
      co_return;
    }

    // Return the room_id as a json response
    LOG_DEBUG << "Returning room_id as response";
    json const resp_body = {
        {"room_id", room_id},
    };

    const auto resp = HttpResponse::newHttpResponse();
    resp->setBody(resp_body.dump());
    resp->setContentTypeString(JSON_CONTENT_TYPE);
    resp->setStatusCode(k200OK);
    callback(resp);
    co_return;
  }

  );
}
void ClientServerCtrl::state(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &roomId, const std::string &eventType,
    const std::optional<std::string> &stateKey) const {
  drogon::async_run([req, callback = std::move(callback), roomId, eventType,
                     stateKey]() -> drogon::Task<> {
    // Check that the authenticated user is a member of the room
    const auto access_token = extract_access_token(req);
    const auto user_info = co_await Database::get_user_info(access_token);
    if (!user_info) {
      return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token",
                   k401Unauthorized);
      co_return;
    }

    const auto membership =
        co_await Database::get_membership(roomId, user_info->user_id);
    if (!membership || *membership != "join") {
      return_error(callback, "M_FORBIDDEN",
                   "You are not a member of this room", k403Forbidden);
      co_return;
    }

    try {
      const json json_data = co_await Database::get_state_event(
          roomId, eventType, stateKey.value_or(""));

      // Per spec, GET /rooms/{roomId}/state/{eventType}/{stateKey} returns
      // only the event content, not the full event envelope
      const auto &content =
          json_data.contains("content") ? json_data["content"] : json_data;

      const auto resp = HttpResponse::newHttpResponse();
      resp->setBody(content.dump());
      resp->setContentTypeString(JSON_CONTENT_TYPE);
      resp->setStatusCode(k200OK);
      callback(resp);
      co_return;
    } catch (const std::exception &e) {
      return_error(callback, "M_NOT_FOUND", "State event not found",
                   k404NotFound);
      co_return;
    }
  });
}
void ClientServerCtrl::setFilter(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &userId) const {
  drogon::async_run(
      [req, callback = std::move(callback), userId]() -> drogon::Task<> {
        // Verify the authenticated user matches the userId parameter
        const auto access_token = extract_access_token(req);
        const auto user_info = co_await Database::get_user_info(access_token);
        if (!user_info || user_info->user_id != userId) {
          return_error(callback, "M_FORBIDDEN",
                       "Cannot set filters for other users", k403Forbidden);
          co_return;
        }

        try {
          // Parse body as filter json
          const auto filter = json::parse(req->body());

          // Put the data in the db
          const auto filter_id = co_await Database::set_filter(userId, filter);

          // Return the filter id as json with a single key "filter_id"
          const auto resp = HttpResponse::newHttpResponse();
          resp->setBody(json({{"filter_id", filter_id}}).dump());
          resp->setContentTypeString(JSON_CONTENT_TYPE);
          resp->setStatusCode(k200OK);
          callback(resp);
          co_return;
        } catch (const std::exception &e) {
          return_error(callback, "M_UNKNOWN", "Failed to set filter",
                       k500InternalServerError);
          co_return;
        }
      });
}

void ClientServerCtrl::getFilter(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &userId, const std::string &filterId) const {
  drogon::async_run([req, callback = std::move(callback), userId,
                     filterId]() -> drogon::Task<> {
    // Verify the authenticated user matches the userId parameter
    const auto access_token = extract_access_token(req);
    const auto user_info = co_await Database::get_user_info(access_token);
    if (!user_info || user_info->user_id != userId) {
      return_error(callback, "M_FORBIDDEN",
                   "Cannot get filters for other users", k403Forbidden);
      co_return;
    }

    try {
      const auto filter = co_await Database::get_filter(userId, filterId);

      // Return the filter as json
      const auto resp = HttpResponse::newHttpResponse();
      resp->setBody(filter.dump());
      resp->setContentTypeString(JSON_CONTENT_TYPE);
      resp->setStatusCode(k200OK);
      callback(resp);
      co_return;
    } catch (const std::exception &e) {
      return_error(callback, "M_NOT_FOUND", "Failed to get filter",
                   k404NotFound);
      co_return;
    }
  });
}

using sync_utils::generate_sync_token;
using sync_utils::parse_sync_token;

// ============================================================================
// Sync implementation
// ============================================================================

/// Perform initial sync (no since token)
[[nodiscard]] static drogon::Task<client_server_json::SyncResponse>
perform_initial_sync(const std::string &user_id,
                     [[maybe_unused]] const std::optional<json> &filter) {
  client_server_json::SyncResponse response;

  // Get all room memberships for user
  const auto memberships =
      co_await Database::get_user_room_memberships(user_id);

  for (const auto &membership : memberships) {
    if (membership.membership == "join") {
      constexpr int timeline_limit = 20;
      // Joined room: full current state + recent timeline
      client_server_json::SyncJoinedRoom joined;

      // Get current state
      auto state_events =
          co_await Database::get_current_room_state(membership.room_nid);
      joined.state.events = std::move(state_events);

      // Get timeline (last N events)
      auto timeline = co_await Database::get_room_timeline(membership.room_nid,
                                                           0, timeline_limit);
      joined.timeline.events = std::move(timeline.events);
      joined.timeline.limited = timeline.limited;
      joined.timeline.prev_batch = timeline.prev_batch;

      // Get room account data (currently empty)
      joined.account_data.events =
          co_await Database::get_room_account_data(user_id, membership.room_id);

      response.rooms.join[membership.room_id] = std::move(joined);

    } else if (membership.membership == "invite") {
      // Invited: stripped state only
      client_server_json::SyncInvitedRoom invited;
      invited.invite_state.events =
          co_await Database::get_invite_stripped_state(membership.room_nid,
                                                       user_id);
      response.rooms.invite[membership.room_id] = std::move(invited);

    } else if (membership.membership == "leave" ||
               membership.membership == "ban") {
      // For initial sync, we skip left rooms
      // They are included on incremental sync when the leave event is new
    }
  }

  // Get global account data
  response.account_data.events = co_await Database::get_account_data(user_id);

  // Generate next_batch token
  const int64_t max_nid = co_await Database::get_max_event_nid();
  response.next_batch = generate_sync_token(max_nid);

  co_return response;
}

/// Perform incremental sync (with since token)
[[nodiscard]] static drogon::Task<client_server_json::SyncResponse>
perform_incremental_sync(const std::string &user_id,
                         const int64_t since_event_nid, const bool full_state,
                         [[maybe_unused]] const std::optional<json> &filter) {
  client_server_json::SyncResponse response;

  // Get all room memberships for user
  const auto memberships =
      co_await Database::get_user_room_memberships(user_id);

  // Get current max event_nid
  const int64_t current_max = co_await Database::get_max_event_nid();

  for (const auto &membership : memberships) {
    constexpr int timeline_limit = 20;
    if (membership.membership == "join") {
      client_server_json::SyncJoinedRoom joined;

      if (full_state) {
        // Full state requested
        joined.state.events =
            co_await Database::get_current_room_state(membership.room_nid);
      } else {
        // State delta only
        joined.state.events = co_await Database::get_state_delta(
            membership.room_nid, since_event_nid, current_max);
      }

      // Timeline since token
      auto timeline = co_await Database::get_room_timeline(
          membership.room_nid, since_event_nid, timeline_limit);
      joined.timeline.events = std::move(timeline.events);
      joined.timeline.limited = timeline.limited;
      joined.timeline.prev_batch = timeline.prev_batch;

      // Only include room if there are changes
      if (!joined.state.events.empty() || !joined.timeline.events.empty()) {
        response.rooms.join[membership.room_id] = std::move(joined);
      }

    } else if (membership.membership == "invite") {
      // Only include if membership changed since token
      if (membership.event_nid > since_event_nid) {
        client_server_json::SyncInvitedRoom invited;
        invited.invite_state.events =
            co_await Database::get_invite_stripped_state(membership.room_nid,
                                                         user_id);
        response.rooms.invite[membership.room_id] = std::move(invited);
      }

    } else if (membership.membership == "leave" ||
               membership.membership == "ban") {
      // User left/banned since last sync
      if (membership.event_nid > since_event_nid) {
        client_server_json::SyncLeftRoom left;
        // Include the leave event in timeline
        auto timeline = co_await Database::get_room_timeline(
            membership.room_nid, since_event_nid, timeline_limit);
        left.timeline.events = std::move(timeline.events);
        left.timeline.limited = timeline.limited;
        left.timeline.prev_batch = timeline.prev_batch;
        response.rooms.leave[membership.room_id] = std::move(left);
      }
    }
  }

  // Generate next_batch token
  response.next_batch = generate_sync_token(current_max);

  co_return response;
}

/// Check if sync response has any data
[[nodiscard]] static bool
sync_response_has_data(const client_server_json::SyncResponse &response) {
  return !response.rooms.join.empty() || !response.rooms.invite.empty() ||
         !response.rooms.leave.empty() || !response.account_data.events.empty();
}

void ClientServerCtrl::sync(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run([req, callback = std::move(callback),
                     this]() -> drogon::Task<> {
    // 1. Authenticate
    const auto [isValid, userInfo] = co_await getUserInfo(req, callback);
    if (!isValid) {
      co_return;
    }

    // 2. Parse query parameters
    const auto since_token = req->getOptionalParameter<std::string>("since");
    const auto filter_param = req->getOptionalParameter<std::string>("filter");
    const bool full_state = req->getOptionalParameter<std::string>("full_state")
                                .value_or("false") == "true";
    auto timeout_ms = req->getOptionalParameter<int64_t>("timeout").value_or(0);
    // Ignored for now: set_presence

    // Per spec, timeout=0 means respond immediately (no long-polling).
    // Cap at 5 minutes to avoid holding connections too long.
    if (constexpr int64_t max_timeout_ms = 300000;
        timeout_ms > max_timeout_ms) {
      timeout_ms = max_timeout_ms;
    }

    // 3. Parse since token
    std::optional<int64_t> since_event_nid;
    if (since_token.has_value() && !since_token->empty()) {
      since_event_nid = parse_sync_token(*since_token);
      if (!since_event_nid.has_value()) {
        // Invalid token format - return error rather than treating as initial
        // sync
        return_error(callback, "M_INVALID_PARAM", "Invalid since token format",
                     k400BadRequest);
        co_return;
      }
    }

    // 4. Parse or load filter
    std::optional<json> filter;
    if (filter_param.has_value() && !filter_param->empty()) {
      if (filter_param->starts_with("{")) {
        // Inline filter JSON
        try {
          filter = json::parse(*filter_param);
        } catch (const json::parse_error &e) {
          return_error(callback, "M_BAD_JSON", "Invalid filter JSON",
                       k400BadRequest);
          co_return;
        }
      } else {
        // Filter ID - load from database
        try {
          filter =
              co_await Database::get_filter(userInfo->user_id, *filter_param);
        } catch (const std::exception &e) {
          return_error(callback, "M_UNKNOWN", "Filter not found", k404NotFound);
          co_return;
        }
      }
    }

    // 5. Perform sync
    client_server_json::SyncResponse sync_result;

    if (!since_event_nid.has_value()) {
      // Initial sync - return immediately
      sync_result = co_await perform_initial_sync(userInfo->user_id, filter);
    } else {
      // Incremental sync with long-polling
      const int64_t since_nid = *since_event_nid;
      const auto deadline = std::chrono::steady_clock::now() +
                            std::chrono::milliseconds(timeout_ms);
      constexpr auto poll_interval_ms = std::chrono::milliseconds(500);

      // First check if data is immediately available
      sync_result = co_await perform_incremental_sync(
          userInfo->user_id, since_nid, full_state, filter);

      if (!sync_response_has_data(sync_result)) {
        // No data available - block until new events or timeout
        while (std::chrono::steady_clock::now() < deadline) {
          // Wait for poll interval or remaining time, whichever is smaller
          const auto remaining =
              std::chrono::duration_cast<std::chrono::milliseconds>(
                  deadline - std::chrono::steady_clock::now());
          const auto sleep_time = std::min(poll_interval_ms, remaining);

          if (sleep_time.count() <= 0) {
            break;
          }

          co_await drogon::sleepCoro(
              trantor::EventLoop::getEventLoopOfCurrentThread(), sleep_time);

          // Check for new events
          const int64_t current_max =
              co_await Database::get_max_event_nid_for_user_rooms(
                  userInfo->user_id, since_nid);

          if (current_max > since_nid) {
            // New events available
            sync_result = co_await perform_incremental_sync(
                userInfo->user_id, since_nid, full_state, filter);
            break;
          }
        }
      }

      // If still no data after timeout, return empty response with same token
      if (!sync_response_has_data(sync_result)) {
        sync_result.next_batch = generate_sync_token(since_nid);
      }
    }

    // 6. Strip federation-only fields from events before returning to client
    for (auto &val : sync_result.rooms.join | std::views::values) {
      for (auto &event : val.state.events) {
        json_utils::strip_federation_fields(event);
      }
      for (auto &event : val.timeline.events) {
        json_utils::strip_federation_fields(event);
      }
    }
    for (auto &[invite_state] : sync_result.rooms.invite | std::views::values) {
      for (auto &event : invite_state.events) {
        json_utils::strip_federation_fields(event);
      }
    }
    for (auto &val : sync_result.rooms.leave | std::views::values) {
      for (auto &event : val.state.events) {
        json_utils::strip_federation_fields(event);
      }
      for (auto &event : val.timeline.events) {
        json_utils::strip_federation_fields(event);
      }
    }

    // 7. Return response
    const auto resp = HttpResponse::newHttpResponse();
    resp->setBody(json(sync_result).dump());
    resp->setContentTypeString(JSON_CONTENT_TYPE);
    resp->setStatusCode(k200OK);
    callback(resp);
    co_return;
  });
}

void ClientServerCtrl::sendEvent(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &roomId, const std::string &eventType,
    const std::string &txnId) const {
  drogon::async_run([req, callback = std::move(callback), roomId, eventType,
                     txnId, this]() -> drogon::Task<> {
    // 1. Authenticate user
    const auto [isValid, userInfo] = co_await getUserInfo(req, callback);
    if (!isValid) {
      co_return;
    }

    // 2. Parse request body
    json body;
    try {
      body = json::parse(req->body());
    } catch (const json::parse_error &) {
      return_error(callback, "M_NOT_JSON",
                   "Unable to parse json. Is this valid json?", k400BadRequest);
      co_return;
    }

    // 3. Check transaction ID idempotency
    if (userInfo->device_id.has_value()) {
      const auto cached_event_id = co_await Database::get_txn_event_id(
          userInfo->user_id, userInfo->device_id.value(), txnId, roomId);
      if (cached_event_id.has_value()) {
        const json resp_body = {{"event_id", cached_event_id.value()}};
        const auto resp = HttpResponse::newHttpResponse();
        resp->setBody(resp_body.dump());
        resp->setContentTypeString(JSON_CONTENT_TYPE);
        resp->setStatusCode(k200OK);
        callback(resp);
        co_return;
      }
    }

    // 4. Check room exists
    const bool exists = co_await Database::room_exists(roomId);
    if (!exists) {
      return_error(callback, "M_NOT_FOUND", "Room not found", k404NotFound);
      co_return;
    }

    // 5. Check room version
    const auto room_version = co_await Database::get_room_version(roomId);
    if (!room_version.has_value()) {
      return_error(callback, "M_NOT_FOUND", "Could not determine room version",
                   k404NotFound);
      co_return;
    }

    // 6. Check membership - user must be joined
    const auto membership =
        co_await Database::get_membership(roomId, userInfo->user_id);
    if (!membership.has_value() || membership.value() != "join") {
      return_error(callback, "M_FORBIDDEN", "You are not joined to this room",
                   k403Forbidden);
      co_return;
    }

    // 7. Get auth events for the event
    const auto auth_data =
        co_await Database::get_auth_events_for_event(roomId, userInfo->user_id);
    if (!auth_data.has_value()) {
      return_error(callback, "M_UNKNOWN", "Could not retrieve room state",
                   k500InternalServerError);
      co_return;
    }

    // 8. Power level check
    if (auth_data->power_levels.has_value()) {
      const auto &pl = auth_data->power_levels.value();
      const int sender_pl = get_sender_power_level(pl, userInfo->user_id);

      // Get required power level for this event type
      int required_pl = 0;
      if (pl.contains("content")) {
        const auto &content = pl.at("content");
        if (content.contains("events") &&
            content.at("events").contains(eventType)) {
          required_pl = content.at("events").at(eventType).get<int>();
        } else if (content.contains("events_default")) {
          required_pl = content.at("events_default").get<int>();
        }
      }

      if (sender_pl < required_pl) {
        return_error(
            callback, "M_FORBIDDEN",
            std::format(
                "You need power level {} to send {} events, but you have {}",
                required_pl, eventType, sender_pl),
            k403Forbidden);
        co_return;
      }
    }

    // 9. Get prev_events and depth
    const auto prev_events = co_await Database::get_room_heads(roomId);
    const auto max_depth = co_await Database::get_max_depth(roomId);

    // 10. Build auth_events using select_auth_events
    const AuthEventSet auth_set{
        .create_event = auth_data->create_event,
        .power_levels = auth_data->power_levels,
        .sender_membership = auth_data->sender_membership,
        // TODO: Fix this properly
        .target_membership = {},
        .join_rules = {},
        .third_party_invite = {},
        .auth_user_membership = {},
    };

    json proto_event = {
        {"type", eventType},
        {"content", body},
        {"sender", userInfo->user_id},
        {"room_id", roomId},
        {"origin_server_ts",
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
             .count()},
        {"prev_events", prev_events},
        {"depth", max_depth + 1}};

    const auto auth_event_ids =
        select_auth_events(proto_event, auth_set, room_version.value());
    proto_event["auth_events"] = auth_event_ids;

    // 11. Finalize event (content hash, event_id, signature)
    const auto key_data = get_verify_key_data(_config);
    json finalized =
        finalize_event(std::move(proto_event), room_version.value(),
                       _config.matrix_config.server_name, key_data.key_id,
                       key_data.private_key);

    const auto final_event_id = finalized["event_id"].get<std::string>();

    // 12. Store event and transaction ID in a transaction
    try {
      const auto sql = drogon::app().getDbClient();
      const auto transaction = sql->newTransaction();

      co_await Database::add_event(transaction, finalized, roomId);

      if (userInfo->device_id.has_value()) {
        co_await Database::store_txn_id(transaction, userInfo->user_id,
                                        userInfo->device_id.value(), txnId,
                                        roomId, final_event_id);
      }
    } catch (const std::exception &e) {
      LOG_ERROR << "sendEvent: Failed to store event: " << e.what();
      return_error(callback, "M_UNKNOWN", "Failed to store event",
                   k500InternalServerError);
      co_return;
    }

    // 13. Broadcast to federated servers
    LOG_DEBUG << "sendEvent: Broadcasting event " << final_event_id
              << " type=" << eventType << " to room " << roomId;
    FederationSender::broadcast_pdu(finalized, roomId,
                                    _config.matrix_config.server_name,
                                    room_version.value());

    // 14. Return event_id
    const json resp_body = {{"event_id", final_event_id}};
    const auto resp = HttpResponse::newHttpResponse();
    resp->setBody(resp_body.dump());
    resp->setContentTypeString(JSON_CONTENT_TYPE);
    resp->setStatusCode(k200OK);
    callback(resp);
    co_return;
  });
}
