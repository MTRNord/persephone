#include "ServerServerCtrl.hpp"
#include "database/database.hpp"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "utils/room_version.hpp"
#include "utils/state_res.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
#include <chrono>
#include <cstdint>
#include <drogon/HttpClient.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <exception>
#include <format>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace server_server_api;
using json = nlohmann::json;

// Maximum age for cached server keys (24 hours in milliseconds)
static constexpr int64_t SERVER_KEY_CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/// Fetch a server's signing keys from the remote server
/// Returns the keys JSON response, or nullopt on failure
static drogon::Task<std::optional<json>>
fetch_server_keys(const std::string_view server_name) {
  try {
    // Resolve the server
    const auto resolved = co_await discover_server(server_name);

    // Create HTTP client
    const bool use_ssl = resolved.port == MATRIX_SSL_PORT;
    const std::string url =
        std::format("{}://{}:{}", use_ssl ? "https" : "http", resolved.address,
                    resolved.port);

    const auto client = drogon::HttpClient::newHttpClient(url);
    client->enableCookies(false);

    const auto req = drogon::HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/_matrix/key/v2/server");
    req->addHeader("Host", std::string(server_name));
    req->addHeader("User-Agent", UserAgent);

    const auto resp =
        co_await client->sendRequestCoro(req, DEFAULT_FEDERATION_TIMEOUT);

    if (resp->getStatusCode() != drogon::k200OK) {
      LOG_ERROR << "Failed to fetch server keys from " << server_name
                << ": HTTP " << resp->getStatusCode();
      co_return std::nullopt;
    }

    co_return json::parse(resp->getBody());
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to fetch server keys from " << server_name << ": "
              << e.what();
    co_return std::nullopt;
  }
}

/// Get a server's signing public key, using cache if available
static drogon::Task<std::optional<std::string>>
get_server_signing_key(const std::string_view server_name,
                       const std::string_view key_id) {
  const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();

  // Check cache first
  auto cached = co_await Database::get_cached_server_key(server_name, key_id);
  if (cached.has_value()) {
    // Check if key is still valid
    if (cached->valid_until_ts > now) {
      co_return cached->public_key;
    }
    // Key expired, will refetch below
  }

  // Fetch fresh keys from the server
  const auto keys_json = co_await fetch_server_keys(server_name);
  if (!keys_json.has_value()) {
    // If we have a cached but expired key, use it as fallback
    if (cached.has_value()) {
      LOG_WARN << "Using expired cached key for " << server_name
               << " as fresh fetch failed";
      co_return cached->public_key;
    }
    co_return std::nullopt;
  }

  const auto &keys = *keys_json;

  // Extract valid_until_ts
  int64_t valid_until_ts = now + 24 * 60 * 60 * 1000; // Default 24h
  if (keys.contains("valid_until_ts")) {
    valid_until_ts = keys["valid_until_ts"].get<int64_t>();
  }

  // Find the requested key
  if (!keys.contains("verify_keys") || !keys["verify_keys"].is_object()) {
    co_return std::nullopt;
  }

  const auto &verify_keys = keys["verify_keys"];
  if (!verify_keys.contains(std::string(key_id))) {
    // Check old_verify_keys as fallback
    if (keys.contains("old_verify_keys") &&
        keys["old_verify_keys"].contains(std::string(key_id))) {
      if (const auto &old_key = keys["old_verify_keys"][std::string(key_id)];
          old_key.contains("key")) {
        const std::string public_key = old_key["key"].get<std::string>();
        // Cache with the old key's expired_ts if available
        int64_t key_valid_until = valid_until_ts;
        if (old_key.contains("expired_ts")) {
          key_valid_until = old_key["expired_ts"].get<int64_t>();
        }
        co_await Database::cache_server_key(server_name, key_id, public_key,
                                            key_valid_until);
        co_return public_key;
      }
    }
    co_return std::nullopt;
  }

  const auto &key_obj = verify_keys[std::string(key_id)];
  if (!key_obj.contains("key")) {
    co_return std::nullopt;
  }

  const std::string public_key = key_obj["key"].get<std::string>();

  // Cache the key
  co_await Database::cache_server_key(server_name, key_id, public_key,
                                      valid_until_ts);

  co_return public_key;
}

/// Build the content to be signed for request verification
/// Per Matrix spec, this is the canonical JSON representation of:
/// { method, uri, origin, destination, content (optional) }
static std::string build_signed_content(const std::string_view method,
                                        const std::string_view uri,
                                        const std::string_view origin,
                                        const std::string_view destination,
                                        const std::optional<json> &content) {
  json to_sign;
  to_sign["method"] = std::string(method);
  to_sign["uri"] = std::string(uri);
  to_sign["origin"] = std::string(origin);
  to_sign["destination"] = std::string(destination);
  if (content.has_value()) {
    to_sign["content"] = *content;
  }
  return to_sign.dump();
}

// Static member definition
std::string FederationAuthFilter::_server_name;

void FederationAuthFilter::setServerName(std::string name) {
  _server_name = std::move(name);
}

void FederationAuthFilter::doFilter(const HttpRequestPtr &req,
                                    FilterCallback &&callback,
                                    FilterChainCallback &&chain_callback) {
  drogon::async_run([req, chain_callback = std::move(chain_callback),
                     callback = std::move(callback),
                     server_name = _server_name]() mutable -> drogon::Task<> {
    // Get Authorization header
    const auto auth_header = req->getHeader("Authorization");
    if (auth_header.empty()) {
      return_error(callback, "M_UNAUTHORIZED", "Missing Authorization header",
                   k401Unauthorized);
      co_return;
    }

    // Parse X-Matrix header
    const auto parsed = parse_xmatrix_header(auth_header);
    if (!parsed.has_value()) {
      return_error(callback, "M_UNAUTHORIZED",
                   "Invalid Authorization header format", k401Unauthorized);
      co_return;
    }

    // Verify destination matches our server
    if (parsed->destination != server_name) {
      LOG_WARN << "Authorization header destination mismatch: expected "
               << server_name << ", got " << parsed->destination;
      return_error(callback, "M_UNAUTHORIZED",
                   "Destination does not match this server", k401Unauthorized);
      co_return;
    }

    // Get the signing key for the origin server
    const auto public_key_opt =
        co_await get_server_signing_key(parsed->origin, parsed->key_id);
    if (!public_key_opt.has_value()) {
      LOG_WARN << "Could not fetch signing key " << parsed->key_id << " from "
               << parsed->origin;
      return_error(callback, "M_UNAUTHORIZED",
                   "Could not verify signature: unable to fetch signing key",
                   k401Unauthorized);
      co_return;
    }

    // Build the content that was signed
    std::optional<json> content;
    if (!req->body().empty()) {
      try {
        content = json::parse(req->body());
      } catch (const std::exception &e) {
        // Body might not be JSON, that's ok for some requests
      }
    }

    const std::string method = drogon_to_string_method(req->method()).data();
    const std::string uri = req->path();

    const auto signed_content = build_signed_content(
        method, uri, parsed->origin, parsed->destination, content);

    // Verify the signature
    if (!json_utils::verify_signature(*public_key_opt, parsed->signature,
                                      signed_content)) {
      LOG_WARN << "Signature verification failed for request from "
               << parsed->origin;
      return_error(callback, "M_UNAUTHORIZED", "Invalid signature",
                   k401Unauthorized);
      co_return;
    }

    // Signature valid, proceed with the request
    chain_callback();
    co_return;
  });
}

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
  const std::string server_name(_config.matrix_config.server_name);
  const long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
  const long tomorrow = now + static_cast<long>(24 * 60 * 60 * 1000); // 24h

  const std::string key_id =
      std::format("{}:{}", _verify_key_data.key_type, _verify_key_data.key_id);

  const server_server_json::keys keys = {
      .server_name = server_name,
      .valid_until_ts = tomorrow,
      .old_verify_keys = {},
      .verify_keys = {{key_id,
                       {.key =
                            std::string(_verify_key_data.public_key_base64)}}},
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

void ServerServerCtrl::make_join(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &roomId, const std::string &userId) const {
  // Get the optional `ver` query parameter which can be a string array (as in
  // it can be defined multiple times)
  // Due to the way drogon handles query parameters in an std::unordered_map we
  // must parse the path instead ourself here. Otherwise we only get one ver
  const auto query_string = req->getQuery();
  const auto parsed_query_params = parseQueryParamString(query_string);
  const auto ver_values = parsed_query_params.find("ver");
  std::vector<std::string> ver_params;
  if (ver_values != parsed_query_params.end()) {
    ver_params = ver_values->second;
  }

  drogon::async_run([roomId, userId, ver_params,
                     callback = std::move(callback)]() -> drogon::Task<> {
    // 1. Check if the room exists
    if (const bool room_exists = co_await Database::room_exists(roomId);
        !room_exists) {
      const auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k404NotFound);
      const json error_body = generic_json::generic_json_error{
          .errcode = "M_NOT_FOUND", .error = "Unknown room"};
      resp->setBody(error_body.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      callback(resp);
      co_return;
    }

    // 2. Get room version
    const auto room_version_opt = co_await Database::get_room_version(roomId);
    if (!room_version_opt.has_value()) {
      const auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k500InternalServerError);
      const json error_body = generic_json::generic_json_error{
          .errcode = "M_UNKNOWN", .error = "Could not determine room version"};
      resp->setBody(error_body.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      callback(resp);
      co_return;
    }
    const std::string &room_version = room_version_opt.value();

    // 3. Check if the room version is supported
    if (!room_version::is_supported(room_version)) {
      const auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k400BadRequest);
      const json error_body = {
          {"errcode", "M_INCOMPATIBLE_ROOM_VERSION"},
          {"error", "Your homeserver does not support the features required to "
                    "join this room"},
          {"room_version", room_version}};
      resp->setBody(error_body.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      callback(resp);
      co_return;
    }

    // 4. If ver params are provided, check that the room version is in the list
    if (!ver_params.empty()) {
      bool version_supported = false;
      for (const auto &v : ver_params) {
        if (v == room_version) {
          version_supported = true;
          break;
        }
      }
      if (!version_supported) {
        const auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k400BadRequest);
        const json error_body = {
            {"errcode", "M_INCOMPATIBLE_ROOM_VERSION"},
            {"error", "Your homeserver does not support the features required "
                      "to join this room"},
            {"room_version", room_version}};
        resp->setBody(error_body.dump());
        resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
        callback(resp);
        co_return;
      }
    }

    // 5. Check the user's current membership state
    const auto membership_opt =
        co_await Database::get_membership(roomId, userId);
    if (membership_opt.has_value() && membership_opt.value() == "ban") {
      const auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k403Forbidden);
      const json error_body = generic_json::generic_json_error{
          .errcode = "M_FORBIDDEN", .error = "User is banned from the room"};
      resp->setBody(error_body.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      callback(resp);
      co_return;
    }

    // 6. Check join rules
    if (const auto join_rules_event = co_await Database::get_join_rules(roomId);
        join_rules_event.has_value()) {
      if (const auto &join_rules = join_rules_event.value();
          join_rules.contains("content") &&
          join_rules["content"].contains("join_rule")) {
        const auto join_rule =
            join_rules["content"]["join_rule"].get<std::string>();

        // For invite-only rooms, check if user is invited
        if (join_rule == "invite") {
          if (!membership_opt.has_value() ||
              membership_opt.value() != "invite") {
            const auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k403Forbidden);
            const json error_body = generic_json::generic_json_error{
                .errcode = "M_FORBIDDEN",
                .error = "User is not invited to this room"};
            resp->setBody(error_body.dump());
            resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
            callback(resp);
            co_return;
          }
        }
        // TODO: Handle restricted/knock join rules
      }
    }

    // 7. Get auth events for the join
    const auto auth_events_data =
        co_await Database::get_auth_events_for_join(roomId, userId);
    if (!auth_events_data.has_value()) {
      const auto resp = HttpResponse::newHttpResponse();
      resp->setStatusCode(k500InternalServerError);
      const json error_body = generic_json::generic_json_error{
          .errcode = "M_UNKNOWN", .error = "Could not retrieve room state"};
      resp->setBody(error_body.dump());
      resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
      callback(resp);
      co_return;
    }

    // Select auth events using the helper
    const auto auth_event_ids = select_auth_events_for_join(
        auth_events_data->create_event, auth_events_data->power_levels,
        auth_events_data->join_rules, auth_events_data->target_membership,
        std::nullopt, // No auth_user_membership for non-restricted joins
        room_version);

    // 8. Get prev_events and depth
    const auto prev_events = co_await Database::get_room_heads(roomId);
    const auto max_depth = co_await Database::get_max_depth(roomId);

    // 9. Build the proto-event (unsigned template)
    const long origin_server_ts =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count();

    // Extract origin server from userId (@user:server.name)
    const auto colon_pos = userId.find(':');
    const std::string origin =
        colon_pos != std::string::npos ? userId.substr(colon_pos + 1) : "";

    const json proto_event = {{"type", "m.room.member"},
                              {"sender", userId},
                              {"state_key", userId},
                              {"room_id", roomId},
                              {"origin", origin},
                              {"origin_server_ts", origin_server_ts},
                              {"depth", max_depth + 1},
                              {"content", {{"membership", "join"}}},
                              {"auth_events", auth_event_ids},
                              {"prev_events", prev_events}};

    // 10. Return the response
    const server_server_json::MakeJoinResp response{
        .event = proto_event.get<json::object_t>(),
        .room_version = room_version};
    const json response_json = response;

    const auto resp = HttpResponse::newHttpResponse();
    resp->setBody(response_json.dump());
    resp->setContentTypeCode(ContentType::CT_APPLICATION_JSON);
    callback(resp);
    co_return;
  });
}