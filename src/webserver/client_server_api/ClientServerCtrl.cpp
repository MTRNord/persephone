#include "ClientServerCtrl.hpp"
#include "database/database.hpp"
#include "nlohmann/json.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
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
#include <optional>
#include <ranges>
#include <stdexcept>
#include <string>
#include <trantor/utils/Logger.h>
#include <unicode/locid.h>
#include <unicode/unistr.h>
#include <utils/state_res.hpp>
#include <vector>

using namespace client_server_api;
using json = nlohmann::json;

namespace {
json get_powerlevels_pdu(
    const std::string &room_version, const std::string &sender,
    const std::string &room_id,
    const std::optional<client_server_json::PowerLevelEventContent>
        &power_level_override) {
  json power_level_event = {
      {"type", "m.room.power_levels"},
      {"state_key", ""},
      {"room_id", room_id},
      {"sender", sender},
      {"origin_server_ts",
       std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::system_clock::now().time_since_epoch())
           .count()},
      {"content",
       {
           {"ban", 50},
           {"events_default", 0},
           {"invite", 0},
           {"kick", 50},
           {"redact", 50},
           {"state_default", 50},
           {"users_default", 0},
           {"users",
            {
                {sender, 100},
            }},
           {"notifications",
            {
                {"room", 50},
            }},
       }}};

  // If power_level_override has a value we need to merge it with the default
  // power levels given above
  if (power_level_override.has_value()) {
    // We got a power level override, merge it with the default power levels.
    // The override takes precedence over the default defined in
    // `power_level_event`
    const auto &[ban, events, events_default, invite, kick, notifications,
                 redact, state_default, users, users_default] =
        power_level_override.value();

    if (ban.has_value()) {
      power_level_event["content"]["ban"] = ban.value();
    }
    if (events.has_value()) {
      for (const auto &[event_type, power_level] : events.value()) {
        power_level_event["content"]["events"][event_type] = power_level;
      }
    }
    if (events_default.has_value()) {
      power_level_event["content"]["events_default"] = events_default.value();
    }
    if (invite.has_value()) {
      power_level_event["content"]["invite"] = invite.value();
    }
    if (kick.has_value()) {
      power_level_event["content"]["kick"] = kick.value();
    }
    if (notifications.has_value()) {
      for (const auto &[notification_type, power_level] :
           notifications.value()) {
        power_level_event["content"]["notifications"][notification_type] =
            power_level;
      }
    }
    if (redact.has_value()) {
      power_level_event["content"]["redact"] = redact.value();
    }
    if (state_default.has_value()) {
      power_level_event["content"]["state_default"] = state_default.value();
    }
    if (users.has_value()) {
      for (const auto &[user_id, power_level] : users.value()) {
        power_level_event["content"]["users"][user_id] = power_level;
      }
    }
    if (users_default.has_value()) {
      power_level_event["content"]["users_default"] = users_default.value();
    }
  }

  power_level_event["event_id"] = event_id(power_level_event, room_version);

  return power_level_event;
}

std::vector<json> build_createRoom_state(
    const client_server_json::CreateRoomBody &createRoom_body,
    const std::string &room_id, const std::string &user_id,
    const std::string &room_version) {
  // Calculate the expected amount of state events based on the given data in
  // the request This is used to preallocate the state_events vector We expect
  // the following state events:
  // 1. The m.room.create event
  // 2. The m.room.member event for the user creating the room
  // 3. The m.room.power_levels event
  // 4. The m.room.canonical_alias event if room_alias_name is set
  // 5. Based on the preset rules we might have more state events (currently
  // m.room.join_rules, m.room.history_visibility and m.room.guest_access)
  // 6. state events for all initial_state events
  // 7. The m.room.name event if name is set
  // 8. The m.room.topic event if topic is set
  // 9. state events for all the invite and invite_3pid data (m.room.member
  // with membership invite and m.room.third_party_invite)
  std::size_t const expected_state_events =
      calculate_assumed_createRoom_state_event_count(
          createRoom_body.room_alias_name.has_value(),
          createRoom_body.name.has_value(), createRoom_body.topic.has_value(),
          createRoom_body.invite.has_value() ? createRoom_body.invite->size()
                                             : 0,
          createRoom_body.invite_3pid.has_value()
              ? createRoom_body.invite_3pid->size()
              : 0,
          createRoom_body.initial_state.has_value()
              ? createRoom_body.initial_state->size()
              : 0);

  std::vector<json> state_events;
  state_events.reserve(expected_state_events);

  // Create the m.room.create event
  json create_room_pdu = {
      {"type", "m.room.create"},
      {"content", createRoom_body.creation_content.value_or(json::object({
                      {"creator", user_id},
                      {"room_version", room_version},
                  }))},
      {"origin_server_ts",
       std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::system_clock::now().time_since_epoch())
           .count()},
      {"sender", user_id},
      {"state_key", ""},
      {"room_id", room_id},
  };

  // Calculate and add event_id
  try {
    create_room_pdu["event_id"] = event_id(create_room_pdu, room_version);
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to calculate event_id: " << e.what();
    throw std::runtime_error("Failed to calculate event_id");
  }

  state_events.push_back(create_room_pdu);

  // Create room membership event for sender of the create room request
  json membership_pdu = {
      {"type", "m.room.member"},
      {"content",
       {
           {"membership", "join"},
       }},
      {"origin_server_ts",
       std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::system_clock::now().time_since_epoch())
           .count()},
      {"sender", user_id},
      {"state_key", user_id},
      {"room_id", room_id},
  };

  // Calculate and add event_id
  try {
    membership_pdu["event_id"] = event_id(membership_pdu, room_version);
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to calculate event_id: " << e.what();
    throw std::runtime_error("Failed to calculate event_id");
  }

  state_events.push_back(membership_pdu);

  // Create the default power levels event
  try {
    auto power_levels_pdu =
        get_powerlevels_pdu(room_version, user_id, room_id,
                            createRoom_body.power_level_content_override);

    state_events.push_back(power_levels_pdu);
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to create power levels pdu: " << e.what();
    throw std::runtime_error("Failed to create power levels pdu");
  }

  // Check if room_alias_name is set and create the m.room.canonical_alias
  // event
  // TODO: record this on the DB for actual room directory logic
  if (createRoom_body.room_alias_name.has_value()) {
    auto canonical_alias_pdu = json{
        {"type", "m.room.canonical_alias"},
        {"content",
         {
             {"alias", createRoom_body.room_alias_name.value()},
         }},
        {"origin_server_ts",
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
             .count()},
        {"sender", user_id},
        {"state_key", ""},
        {"room_id", room_id},
    };

    // Calculate and add event_id
    try {
      canonical_alias_pdu["event_id"] =
          event_id(canonical_alias_pdu, room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      throw std::runtime_error("Failed to calculate event_id");
    }

    state_events.push_back(canonical_alias_pdu);
  }

  // TODO: here handle the preset

  // Add origin_server_ts, room_id, sender and event_id to each initial_state
  // event and add it to state_events
  for (auto &initial_state :
       createRoom_body.initial_state.value_or(std::vector<json>())) {
    initial_state["origin_server_ts"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();
    initial_state["room_id"] = room_id;
    initial_state["sender"] = user_id;

    // Calculate and add event_id
    try {
      initial_state["event_id"] = event_id(initial_state, room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      throw std::runtime_error("Failed to calculate event_id");
    }

    state_events.push_back(initial_state);
  }

  // If name is set create the m.room.name event
  if (createRoom_body.name.has_value()) {
    auto room_name_pdu = json{
        {"type", "m.room.name"},
        {"content",
         {
             {"name", createRoom_body.name.value()},
         }},
        {"origin_server_ts",
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
             .count()},
        {"sender", user_id},
        {"state_key", ""},
        {"room_id", room_id},
    };

    // Calculate and add event_id
    try {
      room_name_pdu["event_id"] = event_id(room_name_pdu, room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      throw std::runtime_error("Failed to calculate event_id");
    }

    state_events.push_back(room_name_pdu);
  }

  // If topic is set create the m.room.topic event
  if (createRoom_body.topic.has_value()) {
    auto room_topic_pdu = json{
        {"type", "m.room.topic"},
        {"content",
         {
             {"topic", createRoom_body.topic.value()},
         }},
        {"origin_server_ts",
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
             .count()},
        {"sender", user_id},
        {"state_key", ""},
        {"room_id", room_id},
    };

    // Calculate and add event_id
    try {
      room_topic_pdu["event_id"] = event_id(room_topic_pdu, room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      LOG_ERROR << "Failed to calculate event_id: " << e.what();
      throw std::runtime_error("Failed to calculate event_id");
    }

    state_events.push_back(room_topic_pdu);
  }

  // Create invite memberhsip events
  // TODO: Do fed requests to actually invite the users
  // TODO: Deal with 3pid invites
  if (createRoom_body.invite.has_value()) {
    for (const auto &invite : createRoom_body.invite.value()) {
      auto invite_pdu = json{
          {"type", "m.room.member"},
          {"content",
           {
               {"membership", "invite"},
           }},
          {"origin_server_ts",
           std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
               .count()},
          {"sender", user_id},
          {"state_key", invite},
          {"room_id", room_id},
      };

      // Calculate and add event_id
      try {
        invite_pdu["event_id"] = event_id(invite_pdu, room_version);
      } catch (const std::exception &e) {
        LOG_ERROR << "Failed to calculate event_id: " << e.what();
        throw std::runtime_error("Failed to calculate event_id");
      }

      state_events.push_back(invite_pdu);
    }
  }

  return state_events;
}
} // namespace

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

    // Get the access token from the Authorization header
    const auto auth_header = req->getHeader("Authorization");
    if (auth_header.empty()) {
      return_error(callback, "M_MISSING_TOKEN", "Missing Authorization header",
                   k401Unauthorized);
      co_return;
    }
    // TMP loging for complement debugging
    LOG_DEBUG << "Access token: " << auth_header;

    // Remove the "Bearer " prefix and check if the token is valid;
    if (const auto access_token = auth_header.substr(7);
        co_await Database::validate_access_token(access_token)) {
      chain_callback();
      co_return;
    }
    return_error(callback, "M_UNKNOWN_TOKEN", "Unrecognised access token.",
                 k401Unauthorized);
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
      .versions = {"v1.1", "v1.13"}};
  const json j = versions;

  const auto resp = HttpResponse::newHttpResponse();
  resp->setBody(j.dump());
  resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
  callback(resp);
}

void ClientServerCtrl::whoami(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run(
      [req, callback = std::move(callback), this]() -> drogon::Task<> {
        // Get the access token from the Authorization header
        const auto auth_header = req->getHeader("Authorization");
        if (auth_header.empty()) {
          return_error(callback, "M_MISSING_TOKEN",
                       "Missing Authorization header", k401Unauthorized);
          co_return;
        }
        // Remove the "Bearer " prefix
        const auto access_token = auth_header.substr(7);

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
        resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
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
        // Check if the username is already taken
        const auto user_exists = co_await Database::user_exists(
            std::format("@{}:{}", fixed_username, server_name));

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
          auto json_data = json::object();
          json_data["available"] = true;
          return json_data.dump();
        }();

        resp->setBody(json_data);
        resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
        callback(resp);
      });
}

void ClientServerCtrl::login_get(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback) const {
  drogon::async_run(
      [req, callback = std::move(callback), this]() -> drogon::Task<> {
        const auto login_flow = []() {
          const client_server_json::LoginFlow password_flow = {
              .type = "m.login.password"};
          client_server_json::GetLogin const login{.flows = {password_flow}};
          const json json_data = login;
          return json_data.dump();
        }();

        const auto resp = HttpResponse::newHttpResponse();
        resp->setBody(login_flow);
        resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
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
                   "Unable to parse json. Is this valid json?",
                   k500InternalServerError);
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
      return_error(
          callback, "M_BAD_JSON",
          "Unable to parse json. Ensure all required fields are present?",
          k500InternalServerError);
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
      // Convert the user id to a icu compatible char16_t/UChar string
      icu::UnicodeString user_id_icu(supplied_user_id.c_str());
      // Get the english locale
      const auto locale = icu::Locale::getEnglish();

      // Ensure the user id is lowercase using icu library's u_strToLower
      const auto user_id_lower_uci = user_id_icu.toLower(locale);

      // Convert the user id to a std::string again
      std::string user_id_lower;
      user_id_lower_uci.toUTF8String(user_id_lower);
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
      const auto login_resp = co_await Database::login(login_data);

      // If the login was successful, return the response as json
      const auto resp = HttpResponse::newHttpResponse();
      resp->setBody(json(login_resp).dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
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
                   "Unable to parse json. Is this valid json?",
                   k500InternalServerError);
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
          "Unable to parse json. Ensure all required fields are present?",
          k500InternalServerError);
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
          .stages = {"m.login.dummy"}};
      client_server_json::incomplete_registration_resp const reg_resp = {
          .session = random_string(25),
          .flows = {dummy_flow},
      };
      json const json_data = reg_resp;

      auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k401Unauthorized);
      resp->setBody(json_data.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      callback(resp);
      co_return;
    }

    auto server_name = _config.matrix_config.server_name;

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

    if (!reg_body.username.has_value() || !reg_body.password.has_value()) {
      return_error(callback, "M_UNKNOWN",
                   "Invalid input. You are missing either username or password",
                   k500InternalServerError);
      co_return;
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

    client_server_json::registration_resp const reg_resp = {
        .access_token = access_token,
        .device_id = device_id_opt,
        .user_id = user_id,
    };
    json json_data = reg_resp;
    resp->setBody(json_data.dump());
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
                   k401Unauthorized);
      co_return;
    }
    // Remove the "Bearer " prefix
    auto access_token = req_auth_header.substr(7);
    // Check if we have the access token in the database
    auto user_info = co_await Database::get_user_info(access_token);

    if (!user_info) {
      return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token",
                   k401Unauthorized);
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
                   "Unable to parse json. Is this valid json?",
                   k500InternalServerError);
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
          k500InternalServerError);
      co_return;
    }

    auto server_names =
        req->getOptionalParameter<std::vector<std::string>>("server_name");

    const auto server_name = get_serverpart(roomIdOrAlias);
    const auto server_address = co_await discover_server(server_name);
    auto address = std::format("https://{}", server_address.address);
    if (server_address.port) {
      address = std::format("https://{}:{}", server_address.address,
                            server_address.port);
    }
    auto client = HttpClient::newHttpClient(address);
    client->setUserAgent(UserAgent);

    std::string room_id;

    const auto [key_id, private_key] =
        load_signing_key(_config.matrix_config.server_key_location);

    if (roomIdOrAlias.starts_with("#")) {
      //  We first need to lookup the room alias
      auto resp = co_await federation_request(
          {.client = client,
           .method = drogon::Get,
           .path = std::format(
               "/_matrix/federation/v1/query/directory?room_alias={}",
               roomIdOrAlias),
           .key_id = key_id,
           .secret_key = private_key,
           .origin = _config.matrix_config.server_name,
           .target = server_address.server_name,
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
      }
      if (server_names.value().empty()) {
        return_error(callback, "M_INVALID_PARAM",
                     "server_name parameter can't be empty if using a room_id",
                     k500InternalServerError);
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
    auto version_query =
        generateQueryParamString("ver", {default_room_version});
    auto path = std::format("/_matrix/federation/v1/make_join/{}/{}{}", room_id,
                            user_info->user_id, version_query);

    auto make_join_resp = co_await federation_request(
        {.client = client,
         .method = drogon::Get,
         .path = path,
         .key_id = key_id,
         .secret_key = private_key,
         .origin = _config.matrix_config.server_name,
         .target = server_address.server_name,
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

    //  Update origin, origin_server_ts and event_id
    event["origin"] = _config.matrix_config.server_name;
    event["origin_server_ts"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();

    event["event_id"] = event_id(event, room_version.value());
    // Sign the make_join response as this is now the event
    auto signed_event = json_utils::sign_json(_config.matrix_config.server_name,
                                              key_id, private_key, event);

    // Send the signed event to the remote server on the v2/send_join endpoint
    auto send_join_resp = co_await federation_request(
        {.client = client,
         .method = drogon::Put,
         .path = std::format(
             "/_matrix/federation/v2/send_join/{}/{}?omit_members=false",
             room_id, event["event_id"].get<std::string>()),
         .key_id = key_id,
         .secret_key = private_key,
         .origin = _config.matrix_config.server_name,
         .target = server_address.server_name,
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

    const auto sql = drogon::app().getDbClient();
    const auto transaction = sql->newTransaction();
    co_await Database::add_room(transaction, state_with_membership, room_id);

    // TODO: Walk the auth_chain, get our signed membership event, use the
    // resolved current room state prior to join
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
                   k401Unauthorized);
      co_return;
    }
    // Remove the "Bearer " prefix
    const auto access_token = req_auth_header.substr(7);
    // Check if we have the access token in the database
    const auto user_info = co_await Database::get_user_info(access_token);
    if (!user_info) {
      return_error(callback, "M_UNKNOWN_TOKEN", "Unknown access token",
                   k401Unauthorized);
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
                   "Unable to parse json. Is this valid json?",
                   k500InternalServerError);
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
      state_events = build_createRoom_state(createRoom_body, room_id,
                                            user_info->user_id, room_version);
    } catch (const std::exception &e) {
      LOG_ERROR << "Failed to build room state: " << e.what();
      return_error(callback, "M_UNKNOWN", e.what(), k500InternalServerError);
      co_return;
    }

    // Sign all the state events

    // Prepare loading the signing data
    const auto [key_id, private_key] =
        load_signing_key(_config.matrix_config.server_key_location);
    LOG_DEBUG << "Signing state events";

    find_auth_event_for_event_on_create(state_events, room_version);
    for (auto &state_event : state_events) {
      state_event = json_utils::sign_json(_config.matrix_config.server_name,
                                          key_id, private_key, state_event);
    }

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

    // Convert the solved_state map to a vector of json objects
    std::vector<json> state_events_vector;
    for (const auto &state_event : solved_state | std::views::values) {
      for (const auto &event : state_event | std::views::values) {
        state_events_vector.push_back(event);
      }
    }

    // create room in db
    LOG_DEBUG << "Adding room to db";
    const auto sql = drogon::app().getDbClient();
    const auto transaction = sql->newTransaction();
    try {
      co_await Database::add_room(transaction, state_events_vector, room_id);
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
    resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
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
  drogon::async_run([req, callback = std::move(callback), this, roomId,
                     eventType, stateKey]() -> drogon::Task<> {
    // TODO: Look up the latest state in the db

    try {
      const json json_data = co_await Database::get_state_event(
          roomId, eventType, stateKey.value_or(""));

      // Return the state event as json
      const auto resp = HttpResponse::newHttpResponse();
      resp->setBody(json_data.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      resp->setStatusCode(k200OK);
      callback(resp);
      co_return;
    } catch (const std::exception &e) {
      return_error(callback, "M_UNKNOWN", "Failed to get state event",
                   k404NotFound);
      co_return;
    }
  });
}