#pragma once

/// @file
/// @brief This header contains all struct definitions of json response and
/// request types

#include <map>
#include <optional>
#include <string>
#ifdef __GNUC__
// Ignore false positives (see https://github.com/nlohmann/json/issues/3808)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "nlohmann/json.hpp"
#pragma GCC diagnostic pop
#else
#include <nlohmann/json.hpp>
#endif

using json = nlohmann::json;

/**
 * @brief Json types shared between C-S and S-S API
 */
namespace generic_json {
/**
 * @brief The structure of generic errors for most return values
 */
struct [[nodiscard]] generic_json_error {
  std::string_view errcode;
  std::string_view error;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(generic_json_error, errcode, error)
} // namespace generic_json

/**
 * @brief Json types for the S-S API
 */
namespace server_server_json {
struct [[nodiscard]] MakeJoinResp {
  json::object_t event;
  std::optional<std::string_view> room_version;
};

void from_json(const json &obj, MakeJoinResp &data_type);

void to_json(json &obj, const MakeJoinResp &data_type);

struct [[nodiscard]] SendJoinResp {
  // TODO: Have a type for the basic PDU structure
  std::vector<json::object_t> auth_chain;
  json event;
  bool members_omitted;
  std::string_view origin;
  std::vector<std::string_view> servers_in_room;
  std::vector<json> state;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SendJoinResp, auth_chain, event,
                                   members_omitted, origin, servers_in_room,
                                   state);

struct incompatible_room_version_error
    : public generic_json::generic_json_error {
  std::string_view room_version;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(incompatible_room_version_error, errcode,
                                   error, room_version)

/**
 * @brief JSON Object for the Matrix Server Version
 *
 * See:
 * https://spec.matrix.org/v1.8/server-server-api/#get_matrixfederationv1version
 */
struct [[nodiscard]] server_version {
  std::string_view name;
  std::string_view version;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(server_version, name, version)

/**
 * @brief JSON Object for the Matrix Server Version
 *
 * See:
 * https://spec.matrix.org/v1.8/server-server-api/#get_matrixfederationv1version
 */
struct [[nodiscard]] version {
  server_server_json::server_version server;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(version, server)

/**
 * @brief JSON object for old keys
 *
 * See: https://spec.matrix.org/v1.8/server-server-api/#publishing-keys
 */
struct [[nodiscard]] old_verify_key {
  std::string key;
  int expired_ts;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(old_verify_key, key, expired_ts)

/**
 * @brief JSON object for active keys
 *
 * See: https://spec.matrix.org/v1.8/server-server-api/#publishing-keys
 */
struct [[nodiscard]] verify_key {
  std::string key;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(verify_key, key)

/**
 * @brief JSON object for the published keys
 *
 * See: https://spec.matrix.org/v1.8/server-server-api/#publishing-keys
 */
struct [[nodiscard]] keys {
  std::string server_name;
  long valid_until_ts;
  std::map<std::string, server_server_json::old_verify_key> old_verify_keys;
  std::map<std::string, server_server_json::verify_key> verify_keys;
  // Optional as we init it later
  std::map<std::string, std::map<std::string, std::string>> signatures;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(keys, server_name, valid_until_ts,
                                   old_verify_keys, verify_keys, signatures)

struct [[nodiscard]] well_known {
  std::optional<std::string_view> m_server;
};

void from_json(const json &obj, well_known &data_type);

void to_json(json &obj, const well_known &data_type);

struct [[nodiscard]] directory_query {
  std::string_view room_id;
  std::vector<std::string_view> servers;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(directory_query, room_id, servers)
} // namespace server_server_json

/**
 * @brief Json types for the C-S API
 */
namespace client_server_json {
struct [[nodiscard]] StateEvent {
  json::object_t content;

  // Optional as it might be not yet created
  std::optional<std::string_view> event_id;

  // Optional as it might not be yet created
  std::optional<int> origin_server_ts;

  // Optional as it might not be yet created
  std::optional<std::string_view> room_id;

  // Optional as it might not be yet created
  std::optional<std::string_view> sender;

  // Optional but at parsing defaults to an empty string as per spec
  // This is different from "normal" staste events
  std::string_view state_key;

  std::string_view type;
};

void from_json(const json &obj, StateEvent &data_type);

void to_json(json &obj, const StateEvent &data_type);

struct [[nodiscard]] PowerLevelEventContent {
  std::optional<int> ban;
  std::optional<std::map<std::string_view, int>> events;
  std::optional<int> events_default;
  std::optional<int> invite;
  std::optional<int> kick;
  std::optional<std::map<std::string_view, int>> notifications;
  std::optional<int> redact;
  std::optional<int> state_default;
  std::optional<std::map<std::string_view, int>> users;
  std::optional<int> users_default;
};

void from_json(const json &obj, PowerLevelEventContent &data_type);

void to_json(json &obj, const PowerLevelEventContent &data_type);

struct [[nodiscard]] Invite3pid {
  std::string_view address;
  std::string_view id_access_token;
  std::string_view id_server;
  std::string_view medium;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Invite3pid, address, id_access_token,
                                   id_server, medium)

struct [[nodiscard]] CreateRoomBody {
  std::optional<json::object_t> creation_content;
  std::optional<std::vector<json>> initial_state;
  std::optional<std::vector<std::string_view>> invite;
  std::optional<std::vector<Invite3pid>> invite_3pid;
  std::optional<std::string_view> name;
  std::optional<PowerLevelEventContent> power_level_content_override;
  std::optional<std::string_view> preset;
  std::optional<std::string_view> room_alias_name;
  std::optional<std::string_view> room_version;
  std::optional<std::string_view> topic;
  std::optional<std::string_view> visibility;
  std::optional<bool> is_direct;
};

void from_json(const json &obj, CreateRoomBody &data_type);

void to_json(json &obj, const CreateRoomBody &data_type);

struct [[nodiscard]] AuthenticationData {
  std::optional<std::string_view> session;
  std::string_view type;
};

void from_json(const json &obj, AuthenticationData &data_type);

void to_json(json &obj, const AuthenticationData &data_type);

struct [[nodiscard]] registration_body {
  std::optional<AuthenticationData> auth;
  std::optional<std::string> device_id;
  std::optional<bool> inhibit_login;
  std::optional<std::string> initial_device_display_name;
  std::optional<std::string> password;
  std::optional<bool> refresh_token;
  std::optional<std::string> username;
};

void from_json(const json &obj, registration_body &data_type);

void to_json(json &obj, const registration_body &data_type);

struct [[nodiscard]] login_identifier {
  std::string_view type;
  // Union depending on the type for different keys
  // Either m.id.user with a value of "user" or m.id.thirdparty with a value of
  // "medium" and "address" or m.id.phone with a value of "country" and "phone"
  std::optional<std::string_view> user;
  std::optional<std::string_view> medium;
  std::optional<std::string_view> address;
  std::optional<std::string_view> country;
  std::optional<std::string_view> phone;
};

void from_json(const json &obj, login_identifier &data_type);

void to_json(json &obj, const login_identifier &data_type);

struct [[nodiscard]] login_body {
  std::optional<std::string_view> address;
  std::optional<std::string_view> device_id;
  std::optional<login_identifier> identifier;
  std::optional<std::string_view> initial_device_display_name;
  std::optional<std::string_view> medium;
  // Password is stored as std::string (not string_view) to ensure it owns the
  // data, preventing potential UTF-8 issues with dangling references.
  std::optional<std::string> password;
  std::optional<bool> refresh_token;
  std::optional<std::string_view> token;
  std::string_view type;
  std::optional<std::string_view> user;
};

void from_json(const json &obj, login_body &data_type);

void to_json(json &obj, const login_body &data_type);

struct [[nodiscard]] well_known_m_homeserver {
  std::string_view base_url;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(well_known_m_homeserver, base_url)

struct [[nodiscard]] well_known_identity_server {
  std::string_view base_url;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(well_known_identity_server, base_url)

struct [[nodiscard]] well_known {
  std::optional<well_known_m_homeserver> m_homeserver;
  std::optional<well_known_identity_server> m_identity_server;
};

void from_json(const json &obj, well_known &data_type);

void to_json(json &obj, const well_known &data_type);

struct [[nodiscard]] login_resp {
  std::string_view access_token;
  std::string_view device_id;
  std::optional<int> expires_in_ms;
  std::optional<std::string_view> home_server;
  std::optional<std::string_view> refresh_token;
  std::string_view user_id;
  std::optional<client_server_json::well_known> well_known;
};

void from_json(const json &obj, login_resp &data_type);

void to_json(json &obj, const login_resp &data_type);

/**
 * @brief JSON Object for the 200 response of the /register endpoint
 * See:
 * https://spec.matrix.org/v1.8/client-server-api/#post_matrixclientv3register
 */
struct [[nodiscard]] registration_resp {
  std::optional<std::string_view> access_token;
  std::optional<std::string_view> device_id;
  std::optional<long> expires_in_ms;
  std::optional<std::string_view> refresh_token;
  std::string_view user_id;
};

void from_json(const json &obj, registration_resp &data_type);

void to_json(json &obj, const registration_resp &data_type);

struct [[nodiscard]] FlowInformation {
  std::array<std::string_view, 1> stages;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(FlowInformation, stages)

struct [[nodiscard]] incomplete_registration_resp {
  std::string session;
  std::array<FlowInformation, 1> flows;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(incomplete_registration_resp, session, flows)

/**
 * @brief JSON Object for the 200 response of the /v3/account/whoami endpoint
 * See:
 * https://spec.matrix.org/v1.8/client-server-api/#current-account-information
 */
struct [[nodiscard]] whoami_resp {
  std::string_view user_id;
  bool is_guest;
  std::optional<std::string_view> device_id;
};

void from_json(const json &obj, whoami_resp &data_type);

void to_json(json &obj, const whoami_resp &data_type);

/**
 * @brief JSON Object for the 200 response of the /versions endpoint
 * See:
 * https://spec.matrix.org/v1.8/client-server-api/#get_matrixclientversions
 */
struct [[nodiscard]] versions_obj {
  std::array<std::string_view, 2> versions;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(versions_obj, versions)

struct [[nodiscard]] LoginFlow {
  std::string_view type;
  bool get_login_token = false;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LoginFlow, get_login_token, type)

struct [[nodiscard]] GetLogin {
  std::array<LoginFlow, 1> flows;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(GetLogin, flows)

struct [[nodiscard]] ThirdPartySigned {
  std::string_view mxid;
  std::string_view sender;
  std::string_view token;
  std::map<std::string_view, std::map<std::string_view, std::string_view>>
      signatures;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ThirdPartySigned, mxid, sender, token)

struct [[nodiscard]] JoinBody {
  std::optional<std::string_view> reason;
  std::optional<ThirdPartySigned> third_party_signed;
};

void from_json(const json &obj, JoinBody &data_type);

void to_json(json &obj, const JoinBody &data_type);
} // namespace client_server_json
