#pragma once

/// @file
/// @brief This header contains all struct definitions of json response and
/// request types

#include "nlohmann/json.hpp"
#include <map>
#include <optional>

using json = nlohmann::json;

/**
 * @brief Json types shared between C-S and S-S API
 */
namespace generic_json {
/**
 * @brief The structure of generic errors for most return values
 */
struct generic_json_error {
  std::string errcode;
  std::string error;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(generic_json_error, errcode, error)
} // namespace generic_json

/**
 * @brief Json types for the S-S API
 */
namespace server_server_json {
struct MakeJoinResp {
  json::object_t event;
  std::optional<std::string> room_version;
};
void from_json(const json &obj, MakeJoinResp &p);
void to_json(json &obj, const MakeJoinResp &p);

struct incompatible_room_version_error
    : public generic_json::generic_json_error {
  std::string room_version;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(incompatible_room_version_error, errcode,
                                   error, room_version)

/**
 * @brief JSON Object for the Matrix Server Version
 *
 * See:
 * https://spec.matrix.org/v1.8/server-server-api/#get_matrixfederationv1version
 */
struct server_version {
  std::string name;
  std::string version;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(server_version, name, version)

/**
 * @brief JSON Object for the Matrix Server Version
 *
 * See:
 * https://spec.matrix.org/v1.8/server-server-api/#get_matrixfederationv1version
 */
struct version {
  server_server_json::server_version server;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(version, server)

/**
 * @brief JSON object for old keys
 *
 * See: https://spec.matrix.org/v1.8/server-server-api/#publishing-keys
 */
struct old_verify_key {
  std::string key;
  int expired_ts;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(old_verify_key, key, expired_ts)

/**
 * @brief JSON object for active keys
 *
 * See: https://spec.matrix.org/v1.8/server-server-api/#publishing-keys
 */
struct verify_key {
  std::string key;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(verify_key, key)

/**
 * @brief JSON object for the published keys
 *
 * See: https://spec.matrix.org/v1.8/server-server-api/#publishing-keys
 */
struct keys {
  std::string server_name;
  long valid_until_ts;
  std::map<std::string, server_server_json::old_verify_key> old_verify_keys;
  std::map<std::string, server_server_json::verify_key> verify_keys;
  // Optional as we init it later
  std::map<std::string, std::map<std::string, std::string>> signatures;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(keys, server_name, valid_until_ts,
                                   old_verify_keys, verify_keys, signatures)

struct well_known {
  std::optional<std::string> m_server;
};
void from_json(const json &obj, well_known &p);
void to_json(json &obj, const well_known &p);

struct directory_query {
  std::string room_id;
  std::vector<std::string> servers;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(directory_query, room_id, servers)

} // namespace server_server_json

/**
 * @brief Json types for the C-S API
 */
namespace client_server_json {
struct AuthenticationData {
  std::optional<std::string> session;
  std::string type;
};
void from_json(const json &obj, AuthenticationData &p);
void to_json(json &obj, const AuthenticationData &p);

struct registration_body {
  std::optional<AuthenticationData> auth;
  std::optional<std::string> device_id;
  std::optional<bool> inhibit_login;
  std::optional<std::string> initial_device_display_name;
  std::optional<std::string> password;
  std::optional<bool> refresh_token;
  std::optional<std::string> username;
};
void from_json(const json &obj, registration_body &p);
void to_json(json &obj, const registration_body &p);

/**
 * @brief JSON Object for the 200 response of the /register endpoint
 * See:
 * https://spec.matrix.org/v1.8/client-server-api/#post_matrixclientv3register
 */
struct registration_resp {
  std::optional<std::string> access_token;
  std::optional<std::string> device_id;
  std::optional<long> expires_in_ms;
  std::optional<std::string> refresh_token;
  std::string user_id;
};
void from_json(const json &obj, registration_resp &p);
void to_json(json &obj, const registration_resp &p);

struct FlowInformation {
  std::array<std::string, 1> stages;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(FlowInformation, stages)

struct incomplete_registration_resp {
  std::string session;
  std::array<FlowInformation, 1> flows;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(incomplete_registration_resp, session, flows)

/**
 * @brief JSON Object for the 200 response of the /v3/account/whoami endpoint
 * See:
 * https://spec.matrix.org/v1.8/client-server-api/#current-account-information
 */
struct whoami_resp {
  std::string user_id;
  bool is_guest;
  std::optional<std::string> device_id;
};
void from_json(const json &obj, whoami_resp &p);
void to_json(json &obj, const whoami_resp &p);

/**
 * @brief JSON Object for the 200 response of the /versions endpoint
 * See:
 * https://spec.matrix.org/v1.8/client-server-api/#get_matrixclientversions
 */
struct versions {
  std::array<std::string, 2> versions;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(versions, versions)

struct LoginFlow {
  bool get_login_token = false;
  std::string type;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LoginFlow, get_login_token, type)

struct GetLogin {
  std::array<LoginFlow, 1> flows;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(GetLogin, flows)

struct ThirdPartySigned {
  std::string mxid;
  std::string sender;
  std::string token;
  std::map<std::string, std::map<std::string, std::string>> signatures;
};
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ThirdPartySigned, mxid, sender, token)

struct JoinBody {
  std::optional<std::string> reason;
  std::optional<ThirdPartySigned> third_party_signed;
};
void from_json(const json &obj, JoinBody &p);
void to_json(json &obj, const JoinBody &p);

} // namespace client_server_json
