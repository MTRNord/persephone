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
  struct [[nodiscard]] generic_json_error {
    std::string errcode;
    std::string error;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(generic_json_error, errcode, error)
} // namespace generic_json

/**
 * @brief Json types for the S-S API
 */
namespace server_server_json {
  struct [[nodiscard]] MakeJoinResp {
    json::object_t event;
    std::optional<std::string> room_version;
  };

  void from_json(const json &obj, MakeJoinResp &p);

  void to_json(json &obj, const MakeJoinResp &p);

  struct [[nodiscard]] SendJoinResp {
    // TODO: Have a type for the basic PDU structure
    std::vector<json::object_t> auth_chain;
    json event;
    bool members_omitted;
    std::string origin;
    std::vector<std::string> servers_in_room;
    std::vector<json> state;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(SendJoinResp, auth_chain, event,
                                     members_omitted, origin, servers_in_room,
                                     state);

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
  struct [[nodiscard]] server_version {
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
    std::map<std::string, std::map<std::string, std::string> > signatures;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(keys, server_name, valid_until_ts,
                                     old_verify_keys, verify_keys, signatures)

  struct [[nodiscard]] well_known {
    std::optional<std::string> m_server;
  };

  void from_json(const json &obj, well_known &p);

  void to_json(json &obj, const well_known &p);

  struct [[nodiscard]] directory_query {
    std::string room_id;
    std::vector<std::string> servers;
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
    std::optional<std::string> event_id;

    // Optional as it might not be yet created
    std::optional<int> origin_server_ts;

    // Optional as it might not be yet created
    std::optional<std::string> room_id;

    // Optional as it might not be yet created
    std::optional<std::string> sender;

    // Optional but at parsing defaults to an empty string as per spec
    // This is different from "normal" staste events
    std::string state_key;

    std::string type;
  };

  void from_json(const json &obj, StateEvent &p);

  void to_json(json &obj, const StateEvent &p);

  struct [[nodiscard]] PowerLevelEventContent {
    std::optional<int> ban;
    std::optional<std::map<std::string, int> > events;
    std::optional<int> events_default;
    std::optional<int> invite;
    std::optional<int> kick;
    std::optional<std::map<std::string, int> > notifications;
    std::optional<int> redact;
    std::optional<int> state_default;
    std::optional<std::map<std::string, int> > users;
    std::optional<int> users_default;
  };

  void from_json(const json &obj, PowerLevelEventContent &p);

  void to_json(json &obj, const PowerLevelEventContent &p);

  struct [[nodiscard]] Invite3pid {
    std::string address;
    std::string id_access_token;
    std::string id_server;
    std::string medium;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Invite3pid, address, id_access_token,
                                     id_server, medium)

  struct [[nodiscard]] CreateRoomBody {
    std::optional<json::object_t> creation_content;
    std::optional<std::vector<StateEvent> > initial_state;
    std::optional<std::vector<std::string> > invite;
    std::optional<std::vector<Invite3pid> > invite_3pid;
    std::optional<std::string> name;
    std::optional<PowerLevelEventContent> power_level_content_override;
    std::optional<std::string> preset;
    std::optional<std::string> room_alias_name;
    std::optional<std::string> room_version;
    std::optional<std::string> topic;
    std::optional<std::string> visibility;
    std::optional<bool> is_direct;
  };

  void from_json(const json &obj, CreateRoomBody &p);

  void to_json(json &obj, const CreateRoomBody &p);

  struct [[nodiscard]] AuthenticationData {
    std::optional<std::string> session;
    std::string type;
  };

  void from_json(const json &obj, AuthenticationData &p);

  void to_json(json &obj, const AuthenticationData &p);

  struct [[nodiscard]] registration_body {
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

  struct [[nodiscard]] login_identifier {
    std::string type;
    // Union depending on the type for different keys
    // Either m.id.user with a value of "user" or m.id.thirdparty with a value of "medium" and "address"
    // or m.id.phone with a value of "country" and "phone"
    std::optional<std::string> user;
    std::optional<std::string> medium;
    std::optional<std::string> address;
    std::optional<std::string> country;
    std::optional<std::string> phone;
  };

  void from_json(const json &obj, login_identifier &p);

  void to_json(json &obj, const login_identifier &p);

  struct [[nodiscard]] login_body {
    std::optional<std::string> address;
    std::optional<std::string> device_id;
    std::optional<login_identifier> identifier;
    std::optional<std::string> initial_device_display_name;
    std::optional<std::string> medium;
    std::optional<std::string> password;
    std::optional<bool> refresh_token;
    std::optional<std::string> token;
    std::string type;
    std::optional<std::string> user;
  };

  void from_json(const json &obj, login_body &p);

  void to_json(json &obj, const login_body &p);

  struct [[nodiscard]] well_known_m_homeserver {
    std::string base_url;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(well_known_m_homeserver, base_url)

  struct [[nodiscard]] well_known_identity_server {
    std::string base_url;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(well_known_identity_server, base_url)

  struct [[nodiscard]] well_known {
    std::optional<well_known_m_homeserver> m_homeserver;
    std::optional<well_known_identity_server> m_identity_server;
  };

  void from_json(const json &obj, well_known &p);

  void to_json(json &obj, const well_known &p);

  struct [[nodiscard]] login_resp {
    std::string access_token;
    std::string device_id;
    std::optional<int> expires_in_ms;
    std::optional<std::string> home_server;
    std::optional<std::string> refresh_token;
    std::string user_id;
    std::optional<client_server_json::well_known> well_known;
  };

  void from_json(const json &obj, login_resp &p);

  void to_json(json &obj, const login_resp &p);

  /**
   * @brief JSON Object for the 200 response of the /register endpoint
   * See:
   * https://spec.matrix.org/v1.8/client-server-api/#post_matrixclientv3register
   */
  struct [[nodiscard]] registration_resp {
    std::optional<std::string> access_token;
    std::optional<std::string> device_id;
    std::optional<long> expires_in_ms;
    std::optional<std::string> refresh_token;
    std::string user_id;
  };

  void from_json(const json &obj, registration_resp &p);

  void to_json(json &obj, const registration_resp &p);

  struct [[nodiscard]] FlowInformation {
    std::array<std::string, 1> stages;
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
  struct [[nodiscard]] versions_obj {
    std::array<std::string, 2> versions;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(versions_obj, versions)

  struct [[nodiscard]] LoginFlow {
    std::string type;
    bool get_login_token = false;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LoginFlow, get_login_token, type)

  struct [[nodiscard]] GetLogin {
    std::array<LoginFlow, 1> flows;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(GetLogin, flows)

  struct [[nodiscard]] ThirdPartySigned {
    std::string mxid;
    std::string sender;
    std::string token;
    std::map<std::string, std::map<std::string, std::string> > signatures;
  };

  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ThirdPartySigned, mxid, sender, token)

  struct [[nodiscard]] JoinBody {
    std::optional<std::string> reason;
    std::optional<ThirdPartySigned> third_party_signed;
  };

  void from_json(const json &obj, JoinBody &p);

  void to_json(json &obj, const JoinBody &p);
} // namespace client_server_json
