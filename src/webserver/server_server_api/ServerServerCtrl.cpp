#include "ServerServerCtrl.hpp"
#include "database/database.hpp"
#include "federation/federation_sender.hpp"
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
#include <trantor/utils/Logger.h>
#include <utility>
#include <vector>

using namespace server_server_api;
using json = nlohmann::json;

/// Fetch a server's signing keys from the remote server
/// Returns the keys JSON response, or nullopt on failure
static drogon::Task<std::optional<json>>
fetch_server_keys(const std::string server_name) {
  try {
    // Resolve the server
    const auto resolved = co_await discover_server(server_name);

    drogon::HttpClientPtr client;
    // Try to construct the HttpClient using the canonical server URL. If that
    // for some reason fails (e.g. library-side URL validation), we error.
    try {
      client = drogon::HttpClient::newHttpClient(build_server_url(resolved));
    } catch (const std::exception &e) {
      LOG_ERROR << "build_server_url() client creation failed for "
                << server_name << ": " << e.what()
                << " — falling back to resolved.server_name";
      co_return std::nullopt;
    }
    client->enableCookies(false);

    // Use the shared federation_request helper for consistent signing/headers.
    // The key endpoint is public and does not require X-Matrix auth, so request
    // skip_auth = true.
    const auto resp = co_await federation_request(
        HTTPRequest{.client = client,
                    .method = drogon::Get,
                    .path = "/_matrix/key/v2/server",
                    .key_id = {},
                    .secret_key = {},
                    .origin = server_name,
                    .target = resolved.server_name,
                    .host_header = build_host_header(resolved),
                    .content = std::nullopt,
                    .timeout = DEFAULT_FEDERATION_TIMEOUT,
                    .skip_auth = true});

    // Defensive checks and fallback: federation_request may return null or a
    // non-200 response for various reasons (network, TLS/SNI, Host header
    // mismatches). If that happens, log helpful debug information and attempt
    // a direct client->sendRequestCoro() as a fallback before giving up.
    if (!resp) {
      LOG_DEBUG << "fetch_server_keys: federation_request returned nullptr for "
                   "server="
                << server_name << " resolved.address=" << resolved.address
                << " resolved.port=" << resolved.port.value_or(0)
                << " resolved.server_name=" << resolved.server_name;
      co_return std::nullopt;
    } else if (resp->getStatusCode() != drogon::k200OK) {
      LOG_WARN << "fetch_server_keys: federation_request returned HTTP "
               << resp->getStatusCode() << " for server=" << server_name
               << " resolved.address=" << resolved.address
               << " resolved.port=" << resolved.port.value_or(0)
               << " resolved.server_name=" << resolved.server_name;
      co_return std::nullopt;
    }

    if (resp && resp->getStatusCode() == drogon::k200OK) {
      co_return json::parse(resp->getBody());
    }
    co_return std::nullopt;
  } catch (const std::exception &e) {
    LOG_ERROR << "Failed to fetch server keys from " << server_name << ": "
              << e.what();
    co_return std::nullopt;
  }
}

/// Get a server's signing public key, using cache if available
static drogon::Task<std::optional<std::string>>
get_server_signing_key(const std::string server_name,
                       const std::string key_id) {
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
    try {
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
                     "Destination does not match this server",
                     k401Unauthorized);
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
        } catch (const std::exception &) {
          // Body might not be JSON, that's ok for some requests
        }
      }

      const std::string method = drogon_to_string_method(req->method()).data();
      // Use the original percent-encoded path + query string for signature
      // verification. The spec requires the raw request target, not the decoded
      // path.
      std::string uri = std::string(req->getOriginalPath());
      if (const auto &query = req->getQuery(); !query.empty()) {
        uri += "?" + std::string(query);
      }

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
    } catch (const std::exception &e) {
      LOG_ERROR << "FederationAuthFilter: Exception during authentication: "
                << e.what();
      return_error(callback, "M_UNKNOWN",
                   "Internal error during request authentication",
                   k500InternalServerError);
    } catch (...) {
      LOG_ERROR
          << "FederationAuthFilter: Unknown exception during authentication";
      return_error(callback, "M_UNKNOWN",
                   "Internal error during request authentication",
                   k500InternalServerError);
    }
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
  resp->setContentTypeString(JSON_CONTENT_TYPE);
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
  resp->setContentTypeString(JSON_CONTENT_TYPE);
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
    try {
      // 1. Check if the room exists
      if (const bool room_exists = co_await Database::room_exists(roomId);
          !room_exists) {
        return_error(callback, "M_NOT_FOUND", "Unknown room", k404NotFound);
        co_return;
      }

      // 2. Get room version
      const auto room_version_opt = co_await Database::get_room_version(roomId);
      if (!room_version_opt.has_value()) {
        return_error(callback, "M_UNKNOWN", "Could not determine room version",
                     k500InternalServerError);
        co_return;
      }
      const std::string &room_version = room_version_opt.value();

      // 3. Check if the room version is supported
      if (!room_version::is_supported(room_version)) {
        const auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k400BadRequest);
        const json error_body = {
            {"errcode", "M_INCOMPATIBLE_ROOM_VERSION"},
            {"error",
             "Your homeserver does not support the features required to "
             "join this room"},
            {"room_version", room_version}};
        resp->setBody(error_body.dump());
        resp->setContentTypeString(JSON_CONTENT_TYPE);
        callback(resp);
        co_return;
      }

      // 4. If ver params are provided, check that the room version is in the
      // list
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
              {"error",
               "Your homeserver does not support the features required "
               "to join this room"},
              {"room_version", room_version}};
          resp->setBody(error_body.dump());
          resp->setContentTypeString(JSON_CONTENT_TYPE);
          callback(resp);
          co_return;
        }
      }

      // 5. Check the user's current membership state
      const auto membership_opt =
          co_await Database::get_membership(roomId, userId);
      if (membership_opt.has_value() && membership_opt.value() == "ban") {
        return_error(callback, "M_FORBIDDEN", "User is banned from the room",
                     k403Forbidden);
        co_return;
      }

      // 6. Check join rules
      if (const auto join_rules_event =
              co_await Database::get_join_rules(roomId);
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
              return_error(callback, "M_FORBIDDEN",
                           "User is not invited to this room", k403Forbidden);
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
        return_error(callback, "M_UNKNOWN", "Could not retrieve room state",
                     k500InternalServerError);
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
      resp->setContentTypeString(JSON_CONTENT_TYPE);
      callback(resp);
      co_return;
    } catch (const std::exception &e) {
      LOG_ERROR << "make_join: Exception: " << e.what();
      return_error(callback, "M_UNKNOWN", "Internal server error",
                   k500InternalServerError);
    } catch (...) {
      LOG_ERROR << "make_join: Unknown exception";
      return_error(callback, "M_UNKNOWN", "Internal server error",
                   k500InternalServerError);
    }
  });
}

void ServerServerCtrl::send_join(
    const HttpRequestPtr &req,
    std::function<void(const HttpResponsePtr &)> &&callback,
    const std::string &roomId, const std::string &eventId) const {
  const auto config = _config;
  const auto verify_key_data = _verify_key_data;

  drogon::async_run([req, roomId, eventId, config, verify_key_data,
                     callback = std::move(callback)]() -> drogon::Task<> {
    try {
      // 1. Parse body as JSON
      json body;
      try {
        body = json::parse(req->body());
      } catch (const std::exception &) {
        return_error(callback, "M_NOT_JSON", "Request body is not valid JSON",
                     k400BadRequest);
        co_return;
      }

      // 2. Validate type is m.room.member
      if (!body.contains("type") ||
          body["type"].get<std::string>() != "m.room.member") {
        return_error(callback, "M_BAD_JSON", "Event type must be m.room.member",
                     k400BadRequest);
        co_return;
      }

      // 3. Validate content.membership is join
      if (!body.contains("content") ||
          !body["content"].contains("membership") ||
          body["content"]["membership"].get<std::string>() != "join") {
        return_error(callback, "M_BAD_JSON",
                     "Event content.membership must be 'join'", k400BadRequest);
        co_return;
      }

      // 4. Validate state_key == sender
      if (!body.contains("state_key") || !body.contains("sender") ||
          body["state_key"].get<std::string>() !=
              body["sender"].get<std::string>()) {
        return_error(callback, "M_BAD_JSON",
                     "Event state_key must match sender", k400BadRequest);
        co_return;
      }

      // 5. Validate room_id matches path parameter
      if (!body.contains("room_id") ||
          body["room_id"].get<std::string>() != roomId) {
        return_error(callback, "M_BAD_JSON",
                     "Event room_id does not match path parameter",
                     k400BadRequest);
        co_return;
      }

      // 6. Check room exists
      if (const bool exists = co_await Database::room_exists(roomId); !exists) {
        return_error(callback, "M_NOT_FOUND", "Unknown room", k404NotFound);
        co_return;
      }

      // 7. Get room version
      const auto room_version_opt = co_await Database::get_room_version(roomId);
      if (!room_version_opt.has_value()) {
        return_error(callback, "M_UNKNOWN", "Could not determine room version",
                     k500InternalServerError);
        co_return;
      }
      const auto &room_version = room_version_opt.value();

      // 8. Verify event ID matches computed event_id
      try {
        if (const auto computed_event_id = event_id(body, room_version);
            computed_event_id != eventId) {
          return_error(
              callback, "M_BAD_JSON",
              std::format("Event ID mismatch: path has {}, computed {}",
                          eventId, computed_event_id),
              k400BadRequest);
          co_return;
        }
      } catch (const std::exception &e) {
        return_error(callback, "M_BAD_JSON",
                     std::format("Failed to compute event ID: {}", e.what()),
                     k400BadRequest);
        co_return;
      }

      // 9. Verify event signature
      const auto sender = body["sender"].get<std::string>();
      const auto colon_pos = sender.find(':');
      if (colon_pos == std::string::npos) {
        return_error(callback, "M_BAD_JSON", "Invalid sender format",
                     k400BadRequest);
        co_return;
      }
      const auto origin_server = sender.substr(colon_pos + 1);

      if (!body.contains("signatures") ||
          !body["signatures"].contains(origin_server)) {
        return_error(callback, "M_UNAUTHORIZED",
                     "Event is not signed by the origin server", k403Forbidden);
        co_return;
      }

      // Verify at least one signature from the origin server
      bool signature_valid = false;
      const auto &origin_sigs = body["signatures"][origin_server];
      for (auto it = origin_sigs.begin(); it != origin_sigs.end(); ++it) {
        const auto &sig_key_id = it.key();
        const auto sig_value = it.value().get<std::string>();

        // Fetch the public key for this key_id
        const auto pub_key =
            co_await get_server_signing_key(origin_server, sig_key_id);
        if (!pub_key.has_value()) {
          LOG_WARN << "Could not fetch signing key " << sig_key_id << " from "
                   << origin_server << " for event signature verification";
          // Should we fail here instead?
          continue;
        }

        // Build canonical JSON without signatures and unsigned
        auto canonical = body;
        canonical.erase("signatures");
        canonical.erase("unsigned");
        const auto canonical_str = canonical.dump();

        if (json_utils::verify_signature(*pub_key, sig_value, canonical_str)) {
          signature_valid = true;
          break;
        }
      }

      if (!signature_valid) {
        return_error(callback, "M_UNAUTHORIZED",
                     "Could not verify event signature", k403Forbidden);
        co_return;
      }

      // 10. Check user is not banned
      const auto membership_opt =
          co_await Database::get_membership(roomId, sender);
      if (membership_opt.has_value() && membership_opt.value() == "ban") {
        return_error(callback, "M_FORBIDDEN", "User is banned from this room",
                     k403Forbidden);
        co_return;
      }

      // 11. Check join rules
      if (const auto join_rules_event =
              co_await Database::get_join_rules(roomId);
          join_rules_event.has_value()) {
        if (const auto &join_rules = join_rules_event.value();
            join_rules.contains("content") &&
            join_rules["content"].contains("join_rule")) {
          const auto join_rule =
              join_rules["content"]["join_rule"].get<std::string>();

          if (join_rule == "invite") {
            if (!membership_opt.has_value() ||
                membership_opt.value() != "invite") {
              return_error(callback, "M_FORBIDDEN",
                           "User is not invited to this room", k403Forbidden);
              co_return;
            }
          }
        }
      }

      // === Response construction (order matters!) ===

      // A. Get room_nid for state queries
      const auto room_nid_opt = co_await Database::get_room_nid(roomId);
      if (!room_nid_opt.has_value()) {
        return_error(callback, "M_UNKNOWN", "Could not find room",
                     k500InternalServerError);
        co_return;
      }
      const auto room_nid = room_nid_opt.value();

      // B. Fetch state BEFORE persisting (spec: state prior to the join)
      const auto state_events =
          co_await Database::get_current_room_state(room_nid);
      const auto auth_chain = co_await Database::get_auth_chain(roomId);

      // C. Co-sign the event
      const auto server_name = std::string(config.matrix_config.server_name);
      const auto key_id_str = verify_key_data.key_id;
      const auto signed_event = json_utils::sign_json(
          server_name, key_id_str, verify_key_data.private_key, body);

      // D. Persist the event
      try {
        const auto sql = drogon::app().getDbClient();
        const auto transaction = co_await sql->newTransactionCoro();
        co_await Database::add_event(transaction, signed_event, roomId);
      } catch (const std::exception &e) {
        LOG_ERROR << "send_join: Failed to persist event: " << e.what();
        return_error(callback, "M_UNKNOWN", "Failed to persist event",
                     k500InternalServerError);
        co_return;
      }

      // E. Broadcast to other servers (async, non-blocking)
      FederationSender::broadcast_pdu(signed_event, roomId, origin_server);

      // F. Get servers in room for response
      const auto servers_in_room =
          co_await Database::get_servers_in_room(roomId);

      // G. Build and return response
      // Convert auth_chain to vector<json::object_t>
      std::vector<json::object_t> auth_chain_objects;
      auth_chain_objects.reserve(auth_chain.size());
      for (const auto &event : auth_chain) {
        auth_chain_objects.push_back(event.get<json::object_t>());
      }

      const server_server_json::SendJoinResp response{
          .auth_chain = std::move(auth_chain_objects),
          .event = signed_event,
          .members_omitted = false,
          .origin = server_name,
          .servers_in_room = servers_in_room,
          .state = state_events};
      const json response_json = response;

      const auto resp = HttpResponse::newHttpResponse();
      resp->setBody(response_json.dump());
      resp->setContentTypeString(JSON_CONTENT_TYPE);
      callback(resp);
      co_return;
    } catch (const std::exception &e) {
      LOG_ERROR << "send_join: Exception: " << e.what();
      return_error(callback, "M_UNKNOWN", "Internal server error",
                   k500InternalServerError);
    } catch (...) {
      LOG_ERROR << "send_join: Unknown exception";
      return_error(callback, "M_UNKNOWN", "Internal server error",
                   k500InternalServerError);
    }
  });
}
