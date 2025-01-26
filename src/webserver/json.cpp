#include "json.hpp"

namespace server_server_json {
  void from_json(const json &obj, MakeJoinResp &p) {
    if (obj.contains("room_version")) {
      p.room_version = obj["room_version"].get<std::string>();
    }
    p.event = obj["event"].get<json::object_t>();
  }

  void to_json(json &obj, const MakeJoinResp &p) {
    obj = nlohmann::json::object();
    if (p.room_version) {
      obj["room_version"] = p.room_version.value();
    }
    obj["event"] = p.event;
  }

  void from_json(const json &obj, well_known &p) {
    if (obj.contains("m.server")) {
      p.m_server = obj["m.server"].get<std::string>();
    }
  }

  void to_json(json &obj, const well_known &p) {
    obj = nlohmann::json::object();
    if (p.m_server) {
      obj["m.server"] = p.m_server.value();
    }
  }
} // namespace server_server_json

namespace client_server_json {
  void from_json(const json &obj, StateEvent &p) {
    p.content = obj["content"].get<json::object_t>();
    if (obj.contains("state_key")) {
      p.state_key = obj["state_key"].get<std::string>();
    } else {
      p.state_key = "";
    }

    if (obj.contains("event_id")) {
      p.event_id = obj["event_id"].get<std::string>();
    }

    p.type = obj["type"].get<std::string>();
  }

  void to_json(json &obj, const StateEvent &p) {
    obj = nlohmann::json::object();

    obj["content"] = p.content;
    obj["state_key"] = p.state_key;
    obj["type"] = p.type;
    if (p.event_id) {
      obj["event_id"] = p.event_id.value();
    }
  }

  void from_json(const json &obj, PowerLevelEventContent &p) {
    if (obj.contains("ban")) {
      p.ban = obj["ban"].get<int>();
    }
    if (obj.contains("events")) {
      p.events = obj["events"].get<std::map<std::string, int> >();
    }
    if (obj.contains("events_default")) {
      p.events_default = obj["events_default"].get<int>();
    }
    if (obj.contains("invite")) {
      p.invite = obj["invite"].get<int>();
    }
    if (obj.contains("kick")) {
      p.kick = obj["kick"].get<int>();
    }
    if (obj.contains("notifications")) {
      p.notifications = obj["notifications"].get<std::map<std::string, int> >();
    }
    if (obj.contains("redact")) {
      p.redact = obj["redact"].get<int>();
    }
    if (obj.contains("state_default")) {
      p.state_default = obj["state_default"].get<int>();
    }
    if (obj.contains("users")) {
      p.users = obj["users"].get<std::map<std::string, int> >();
    }
    if (obj.contains("users_default")) {
      p.users_default = obj["users_default"].get<int>();
    }
  }

  void to_json(json &obj, const PowerLevelEventContent &p) {
    obj = nlohmann::json::object();

    if (p.ban) {
      obj["ban"] = p.ban.value();
    }
    if (p.events) {
      obj["events"] = p.events.value();
    }
    if (p.events_default) {
      obj["events_default"] = p.events_default.value();
    }
    if (p.invite) {
      obj["invite"] = p.invite.value();
    }
    if (p.kick) {
      obj["kick"] = p.kick.value();
    }
    if (p.notifications) {
      obj["notifications"] = p.notifications.value();
    }
    if (p.redact) {
      obj["redact"] = p.redact.value();
    }
    if (p.state_default) {
      obj["state_default"] = p.state_default.value();
    }
    if (p.users) {
      obj["users"] = p.users.value();
    }
    if (p.users_default) {
      obj["users_default"] = p.users_default.value();
    }
  }

  void from_json(const json &obj, CreateRoomBody &p) {
    if (obj.contains("creation_content")) {
      p.creation_content = obj["creation_content"].get<json::object_t>();
    }

    if (obj.contains("initial_state")) {
      p.initial_state = obj["initial_state"].get<std::vector<StateEvent> >();
    }

    if (obj.contains("invite")) {
      p.invite = obj["invite"].get<std::vector<std::string> >();
    }

    if (obj.contains("invite_3pid")) {
      p.invite_3pid = obj["invite_3pid"].get<std::vector<Invite3pid> >();
    }

    if (obj.contains("is_direct")) {
      p.is_direct = obj["is_direct"].get<bool>();
    }

    if (obj.contains("name")) {
      p.name = obj["name"].get<std::string>();
    }

    if (obj.contains("power_level_content_override")) {
      p.power_level_content_override =
          obj["power_level_content_override"].get<PowerLevelEventContent>();
    }

    if (obj.contains("preset")) {
      p.preset = obj["preset"].get<std::string>();
    }

    if (obj.contains("room_alias_name")) {
      p.room_alias_name = obj["room_alias_name"].get<std::string>();
    }

    if (obj.contains("room_version")) {
      p.room_version = obj["room_version"].get<std::string>();
    }

    if (obj.contains("topic")) {
      p.topic = obj["topic"].get<std::string>();
    }

    if (obj.contains("visibility")) {
      p.visibility = obj["visibility"].get<std::string>();
    }
  }

  void to_json(json &obj, const CreateRoomBody &p) {
    obj = nlohmann::json::object();

    if (p.creation_content) {
      obj["creation_content"] = p.creation_content.value();
    }
    if (p.initial_state) {
      obj["initial_state"] = p.initial_state.value();
    }
    if (p.invite) {
      obj["invite"] = p.invite.value();
    }
    if (p.invite_3pid) {
      obj["invite_3pid"] = p.invite_3pid.value();
    }
    if (p.is_direct) {
      obj["is_direct"] = p.is_direct.value();
    }
    if (p.name) {
      obj["name"] = p.name.value();
    }
    if (p.power_level_content_override) {
      obj["power_level_content_override"] =
          p.power_level_content_override.value();
    }
    if (p.preset) {
      obj["preset"] = p.preset.value();
    }
    if (p.room_alias_name) {
      obj["room_alias_name"] = p.room_alias_name.value();
    }
    if (p.room_version) {
      obj["room_version"] = p.room_version.value();
    }
    if (p.topic) {
      obj["topic"] = p.topic.value();
    }
    if (p.visibility) {
      obj["visibility"] = p.visibility.value();
    }
  }

  void from_json(const json &obj, AuthenticationData &p) {
    if (obj.contains("session")) {
      p.session = obj["session"].get<std::string>();
    }
    p.type = obj["type"].get<std::string>();
  }

  void to_json(json &obj, const AuthenticationData &p) {
    obj = nlohmann::json::object();
    if (p.session) {
      obj["session"] = p.session.value();
    }
    obj["type"] = p.type;
  }

  void from_json(const json &obj, registration_body &p) {
    if (obj.contains("auth")) {
      p.auth = obj["auth"].get<AuthenticationData>();
    }
    if (obj.contains("device_id")) {
      p.device_id = obj["device_id"].get<std::string>();
    }
    if (obj.contains("inhibit_login")) {
      p.inhibit_login = obj["inhibit_login"].get<bool>();
    }
    if (obj.contains("initial_device_display_name")) {
      p.initial_device_display_name =
          obj["initial_device_display_name"].get<std::string>();
    }
    if (obj.contains("password")) {
      p.password = obj["password"].get<std::string>();
    }
    if (obj.contains("refresh_token")) {
      p.refresh_token = obj["refresh_token"].get<bool>();
    }
    if (obj.contains("username")) {
      p.username = obj["username"].get<std::string>();
    }
  }

  void to_json(json &obj, const registration_body &p) {
    obj = nlohmann::json::object();
    if (p.auth) {
      obj["auth"] = p.auth.value();
    }
    if (p.device_id) {
      obj["device_id"] = p.device_id.value();
    }
    if (p.inhibit_login) {
      obj["inhibit_login"] = p.inhibit_login.value();
    }
    if (p.initial_device_display_name) {
      obj["initial_device_display_name"] = p.initial_device_display_name.value();
    }
    if (p.password) {
      obj["password"] = p.password.value();
    }
    if (p.refresh_token) {
      obj["refresh_token"] = p.refresh_token.value();
    }
    if (p.username) {
      obj["username"] = p.username.value();
    }
  }

  void from_json(const json &obj, login_identifier &p) {
    p.type = obj["type"].get<std::string>();
    if (obj.contains("user")) {
      p.user = obj["user"].get<std::string>();
    }
    if (obj.contains("medium")) {
      p.medium = obj["medium"].get<std::string>();
    }
    if (obj.contains("address")) {
      p.address = obj["address"].get<std::string>();
    }
    if (obj.contains("country")) {
      p.country = obj["country"].get<std::string>();
    }
    if (obj.contains("phone")) {
      p.phone = obj["phone"].get<std::string>();
    }
  }

  void to_json(json &obj, const login_identifier &p) {
    obj = nlohmann::json::object();
    obj["type"] = p.type;
    if (p.user) {
      obj["user"] = p.user.value();
    }
    if (p.medium) {
      obj["medium"] = p.medium.value();
    }
    if (p.address) {
      obj["address"] = p.address.value();
    }
    if (p.country) {
      obj["country"] = p.country.value();
    }
    if (p.phone) {
      obj["phone"] = p.phone.value();
    }
  }

  void from_json(const json &obj, login_body &p) {
    if (obj.contains("address")) {
      p.address = obj["address"].get<std::string>();
    }
    if (obj.contains("device_id")) {
      p.device_id = obj["device_id"].get<std::string>();
    }
    if (obj.contains("identifier")) {
      p.identifier = obj["identifier"].get<login_identifier>();
    }
    if (obj.contains("initial_device_display_name")) {
      p.initial_device_display_name = obj["initial_device_display_name"].get<std::string>();
    }
    if (obj.contains("medium")) {
      p.medium = obj["medium"].get<std::string>();
    }
    if (obj.contains("password")) {
      p.password = obj["password"].get<std::string>();
    }
    if (obj.contains("refresh_token")) {
      p.refresh_token = obj["refresh_token"].get<bool>();
    }
    if (obj.contains("token")) {
      p.token = obj["token"].get<std::string>();
    }
    p.type = obj["type"].get<std::string>();
    if (obj.contains("user")) {
      p.user = obj["user"].get<std::string>();
    }
  }

  void to_json(json &obj, const login_body &p) {
    obj = nlohmann::json::object();
    if (p.address) {
      obj["address"] = p.address.value();
    }
    if (p.device_id) {
      obj["device_id"] = p.device_id.value();
    }
    if (p.identifier) {
      obj["identifier"] = p.identifier.value();
    }
    if (p.initial_device_display_name) {
      obj["initial_device_display_name"] = p.initial_device_display_name.value();
    }
    if (p.medium) {
      obj["medium"] = p.medium.value();
    }
    if (p.password) {
      obj["password"] = p.password.value();
    }
    if (p.refresh_token) {
      obj["refresh_token"] = p.refresh_token.value();
    }
    if (p.token) {
      obj["token"] = p.token.value();
    }
    obj["type"] = p.type;
    if (p.user) {
      obj["user"] = p.user.value();
    }
  }

  void from_json(const json &obj, well_known &p) {
    p.m_homeserver = obj["m.homeserver"].get<well_known_m_homeserver>();
    p.m_identity_server = obj["m.identity_server"].get<well_known_identity_server>();
  }

  void to_json(json &obj, const well_known &p) {
    obj = nlohmann::json::object();
    if (p.m_homeserver) {
      obj["m.homeserver"] = p.m_homeserver.value();
    }
    if (p.m_identity_server) {
      obj["m.identity_server"] = p.m_identity_server.value();
    }
  }

  void from_json(const json &obj, login_resp &p) {
    p.access_token = obj["access_token"].get<std::string>();
    p.device_id = obj["device_id"].get<std::string>();
    p.expires_in_ms = obj["expires_in_ms"].get<long>();
    p.home_server = obj["home_server"].get<std::string>();
    p.refresh_token = obj["refresh_token"].get<std::string>();
    p.user_id = obj["user_id"].get<std::string>();
    p.well_known = obj["well_known"].get<well_known>();
  }

  void to_json(json &obj, const login_resp &p) {
    obj = nlohmann::json::object();
    obj["access_token"] = p.access_token;
    obj["device_id"] = p.device_id;
    if (p.expires_in_ms) {
      obj["expires_in_ms"] = p.expires_in_ms.value();
    }
    if (p.home_server) {
      obj["home_server"] = p.home_server.value();
    }
    if (p.refresh_token) {
      obj["refresh_token"] = p.refresh_token.value();
    }
    obj["user_id"] = p.user_id;
    if (p.well_known) {
      obj["well_known"] = p.well_known.value();
    }
  }

  void from_json(const json &obj, registration_resp &p) {
    if (obj.contains("access_token")) {
      p.access_token = obj["access_token"].get<std::string>();
    }
    if (obj.contains("device_id")) {
      p.device_id = obj["device_id"].get<std::string>();
    }
    if (obj.contains("expires_in_ms")) {
      p.expires_in_ms = obj["expires_in_ms"].get<long>();
    }
    if (obj.contains("refresh_token")) {
      p.refresh_token = obj["refresh_token"].get<std::string>();
    }
    p.user_id = obj["user_id"].get<std::string>();
  }

  void to_json(json &obj, const registration_resp &p) {
    obj = nlohmann::json::object();
    if (p.access_token) {
      obj["access_token"] = p.access_token.value();
    }
    if (p.device_id) {
      obj["device_id"] = p.device_id.value();
    }
    if (p.expires_in_ms) {
      obj["expires_in_ms"] = p.expires_in_ms.value();
    }
    if (p.refresh_token) {
      obj["refresh_token"] = p.refresh_token.value();
    }
    obj["user_id"] = p.user_id;
  }

  void from_json(const json &obj, whoami_resp &p) {
    p.user_id = obj["user_id"].get<std::string>();
    p.is_guest = obj["is_guest"].get<bool>();
    if (obj.contains("device_id")) {
      p.device_id = obj["device_id"].get<std::string>();
    }
  }

  void to_json(json &obj, const whoami_resp &p) {
    obj = nlohmann::json::object();
    obj["user_id"] = p.user_id;
    obj["is_guest"] = p.is_guest;
    if (p.device_id) {
      obj["device_id"] = p.device_id.value();
    }
  }

  void from_json(const json &obj, JoinBody &p) {
    if (obj.contains("reason")) {
      p.reason = obj["reason"].get<std::string>();
    }
    if (obj.contains("third_party_signed")) {
      p.third_party_signed = obj["third_party_signed"].get<ThirdPartySigned>();
    }
  }

  void to_json(json &obj, const JoinBody &p) {
    obj = nlohmann::json::object();
    if (p.reason) {
      obj["reason"] = p.reason.value();
    }
    if (p.third_party_signed) {
      obj["third_party_signed"] = p.third_party_signed.value();
    }
  }
} // namespace client_server_json
