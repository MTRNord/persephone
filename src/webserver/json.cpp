#include "json.hpp"
#include "nlohmann/json.hpp"
#include <map>
#include <string>
#include <vector>

namespace server_server_json {
void from_json(const json &obj, MakeJoinResp &data_type) {
  if (obj.contains("room_version")) {
    data_type.room_version = obj["room_version"].get<std::string_view>();
  }
  data_type.event = obj["event"].get<json::object_t>();
}

void to_json(json &obj, const MakeJoinResp &data_type) {
  obj = nlohmann::json::object();
  if (data_type.room_version) {
    obj["room_version"] = data_type.room_version.value();
  }
  obj["event"] = data_type.event;
}

void from_json(const json &obj, well_known &data_type) {
  if (obj.contains("m.server")) {
    data_type.m_server = obj["m.server"].get<std::string_view>();
  }
}

void to_json(json &obj, const well_known &data_type) {
  obj = nlohmann::json::object();
  if (data_type.m_server) {
    obj["m.server"] = data_type.m_server.value();
  }
}
} // namespace server_server_json

namespace client_server_json {
void from_json(const json &obj, StateEvent &data_type) {
  data_type.content = obj["content"].get<json::object_t>();
  if (obj.contains("state_key")) {
    data_type.state_key = obj["state_key"].get<std::string_view>();
  } else {
    data_type.state_key = "";
  }

  if (obj.contains("event_id")) {
    data_type.event_id = obj["event_id"].get<std::string_view>();
  }

  data_type.type = obj["type"].get<std::string_view>();
}

void to_json(json &obj, const StateEvent &data_type) {
  obj = nlohmann::json::object();

  obj["content"] = data_type.content;
  obj["state_key"] = data_type.state_key;
  obj["type"] = data_type.type;
  if (data_type.event_id) {
    obj["event_id"] = data_type.event_id.value();
  }
}

void from_json(const json &obj, PowerLevelEventContent &data_type) {
  if (obj.contains("ban")) {
    data_type.ban = obj["ban"].get<int>();
  }
  if (obj.contains("events")) {
    data_type.events = obj["events"].get<std::map<std::string_view, int>>();
  }
  if (obj.contains("events_default")) {
    data_type.events_default = obj["events_default"].get<int>();
  }
  if (obj.contains("invite")) {
    data_type.invite = obj["invite"].get<int>();
  }
  if (obj.contains("kick")) {
    data_type.kick = obj["kick"].get<int>();
  }
  if (obj.contains("notifications")) {
    data_type.notifications =
        obj["notifications"].get<std::map<std::string_view, int>>();
  }
  if (obj.contains("redact")) {
    data_type.redact = obj["redact"].get<int>();
  }
  if (obj.contains("state_default")) {
    data_type.state_default = obj["state_default"].get<int>();
  }
  if (obj.contains("users")) {
    data_type.users = obj["users"].get<std::map<std::string_view, int>>();
  }
  if (obj.contains("users_default")) {
    data_type.users_default = obj["users_default"].get<int>();
  }
}

void to_json(json &obj, const PowerLevelEventContent &data_type) {
  obj = nlohmann::json::object();

  if (data_type.ban) {
    obj["ban"] = data_type.ban.value();
  }
  if (data_type.events) {
    obj["events"] = data_type.events.value();
  }
  if (data_type.events_default) {
    obj["events_default"] = data_type.events_default.value();
  }
  if (data_type.invite) {
    obj["invite"] = data_type.invite.value();
  }
  if (data_type.kick) {
    obj["kick"] = data_type.kick.value();
  }
  if (data_type.notifications) {
    obj["notifications"] = data_type.notifications.value();
  }
  if (data_type.redact) {
    obj["redact"] = data_type.redact.value();
  }
  if (data_type.state_default) {
    obj["state_default"] = data_type.state_default.value();
  }
  if (data_type.users) {
    obj["users"] = data_type.users.value();
  }
  if (data_type.users_default) {
    obj["users_default"] = data_type.users_default.value();
  }
}

void from_json(const json &obj, CreateRoomBody &data_type) {
  if (obj.contains("creation_content")) {
    data_type.creation_content = obj["creation_content"].get<json::object_t>();
  }

  if (obj.contains("initial_state")) {
    data_type.initial_state = obj["initial_state"].get<std::vector<json>>();
  }

  if (obj.contains("invite")) {
    data_type.invite = obj["invite"].get<std::vector<std::string_view>>();
  }

  if (obj.contains("invite_3pid")) {
    data_type.invite_3pid = obj["invite_3pid"].get<std::vector<Invite3pid>>();
  }

  if (obj.contains("is_direct")) {
    data_type.is_direct = obj["is_direct"].get<bool>();
  }

  if (obj.contains("name")) {
    data_type.name = obj["name"].get<std::string_view>();
  }

  if (obj.contains("power_level_content_override")) {
    data_type.power_level_content_override =
        obj["power_level_content_override"].get<PowerLevelEventContent>();
  }

  if (obj.contains("preset")) {
    data_type.preset = obj["preset"].get<std::string_view>();
  }

  if (obj.contains("room_alias_name")) {
    data_type.room_alias_name = obj["room_alias_name"].get<std::string_view>();
  }

  if (obj.contains("room_version")) {
    data_type.room_version = obj["room_version"].get<std::string_view>();
  }

  if (obj.contains("topic")) {
    data_type.topic = obj["topic"].get<std::string_view>();
  }

  if (obj.contains("visibility")) {
    data_type.visibility = obj["visibility"].get<std::string_view>();
  }
}

void to_json(json &obj, const CreateRoomBody &data_type) {
  obj = nlohmann::json::object();

  if (data_type.creation_content) {
    obj["creation_content"] = data_type.creation_content.value();
  }
  if (data_type.initial_state) {
    obj["initial_state"] = data_type.initial_state.value();
  }
  if (data_type.invite) {
    obj["invite"] = data_type.invite.value();
  }
  if (data_type.invite_3pid) {
    obj["invite_3pid"] = data_type.invite_3pid.value();
  }
  if (data_type.is_direct) {
    obj["is_direct"] = data_type.is_direct.value();
  }
  if (data_type.name) {
    obj["name"] = data_type.name.value();
  }
  if (data_type.power_level_content_override) {
    obj["power_level_content_override"] =
        data_type.power_level_content_override.value();
  }
  if (data_type.preset) {
    obj["preset"] = data_type.preset.value();
  }
  if (data_type.room_alias_name) {
    obj["room_alias_name"] = data_type.room_alias_name.value();
  }
  if (data_type.room_version) {
    obj["room_version"] = data_type.room_version.value();
  }
  if (data_type.topic) {
    obj["topic"] = data_type.topic.value();
  }
  if (data_type.visibility) {
    obj["visibility"] = data_type.visibility.value();
  }
}

void from_json(const json &obj, AuthenticationData &data_type) {
  if (obj.contains("session")) {
    data_type.session = obj["session"].get<std::string_view>();
  }
  data_type.type = obj["type"].get<std::string_view>();
}

void to_json(json &obj, const AuthenticationData &data_type) {
  obj = nlohmann::json::object();
  if (data_type.session) {
    obj["session"] = data_type.session.value();
  }
  obj["type"] = data_type.type;
}

void from_json(const json &obj, registration_body &data_type) {
  if (obj.contains("auth")) {
    data_type.auth = obj["auth"].get<AuthenticationData>();
  }
  if (obj.contains("device_id")) {
    data_type.device_id = obj["device_id"].get<std::string_view>();
  }
  if (obj.contains("inhibit_login")) {
    data_type.inhibit_login = obj["inhibit_login"].get<bool>();
  }
  if (obj.contains("initial_device_display_name")) {
    data_type.initial_device_display_name =
        obj["initial_device_display_name"].get<std::string_view>();
  }
  if (obj.contains("password")) {
    data_type.password = obj["password"].get<std::string_view>();
  }
  if (obj.contains("refresh_token")) {
    data_type.refresh_token = obj["refresh_token"].get<bool>();
  }
  if (obj.contains("username")) {
    data_type.username = obj["username"].get<std::string_view>();
  }
}

void to_json(json &obj, const registration_body &data_type) {
  obj = nlohmann::json::object();
  if (data_type.auth) {
    obj["auth"] = data_type.auth.value();
  }
  if (data_type.device_id) {
    obj["device_id"] = data_type.device_id.value();
  }
  if (data_type.inhibit_login) {
    obj["inhibit_login"] = data_type.inhibit_login.value();
  }
  if (data_type.initial_device_display_name) {
    obj["initial_device_display_name"] =
        data_type.initial_device_display_name.value();
  }
  if (data_type.password) {
    obj["password"] = data_type.password.value();
  }
  if (data_type.refresh_token) {
    obj["refresh_token"] = data_type.refresh_token.value();
  }
  if (data_type.username) {
    obj["username"] = data_type.username.value();
  }
}

void from_json(const json &obj, login_identifier &data_type) {
  data_type.type = obj["type"].get<std::string_view>();
  if (obj.contains("user")) {
    data_type.user = obj["user"].get<std::string_view>();
  }
  if (obj.contains("medium")) {
    data_type.medium = obj["medium"].get<std::string_view>();
  }
  if (obj.contains("address")) {
    data_type.address = obj["address"].get<std::string_view>();
  }
  if (obj.contains("country")) {
    data_type.country = obj["country"].get<std::string_view>();
  }
  if (obj.contains("phone")) {
    data_type.phone = obj["phone"].get<std::string_view>();
  }
}

void to_json(json &obj, const login_identifier &data_type) {
  obj = nlohmann::json::object();
  obj["type"] = data_type.type;
  if (data_type.user) {
    obj["user"] = data_type.user.value();
  }
  if (data_type.medium) {
    obj["medium"] = data_type.medium.value();
  }
  if (data_type.address) {
    obj["address"] = data_type.address.value();
  }
  if (data_type.country) {
    obj["country"] = data_type.country.value();
  }
  if (data_type.phone) {
    obj["phone"] = data_type.phone.value();
  }
}

void from_json(const json &obj, login_body &data_type) {
  if (obj.contains("address")) {
    data_type.address = obj["address"].get<std::string_view>();
  }
  if (obj.contains("device_id")) {
    data_type.device_id = obj["device_id"].get<std::string_view>();
  }
  if (obj.contains("identifier")) {
    data_type.identifier = obj["identifier"].get<login_identifier>();
  }
  if (obj.contains("initial_device_display_name")) {
    data_type.initial_device_display_name =
        obj["initial_device_display_name"].get<std::string_view>();
  }
  if (obj.contains("medium")) {
    data_type.medium = obj["medium"].get<std::string_view>();
  }
  if (obj.contains("password")) {
    data_type.password = obj["password"].get<std::string_view>();
  }
  if (obj.contains("refresh_token")) {
    data_type.refresh_token = obj["refresh_token"].get<bool>();
  }
  if (obj.contains("token")) {
    data_type.token = obj["token"].get<std::string_view>();
  }
  data_type.type = obj["type"].get<std::string_view>();
  if (obj.contains("user")) {
    data_type.user = obj["user"].get<std::string_view>();
  }
}

void to_json(json &obj, const login_body &data_type) {
  obj = nlohmann::json::object();
  if (data_type.address) {
    obj["address"] = data_type.address.value();
  }
  if (data_type.device_id) {
    obj["device_id"] = data_type.device_id.value();
  }
  if (data_type.identifier) {
    obj["identifier"] = data_type.identifier.value();
  }
  if (data_type.initial_device_display_name) {
    obj["initial_device_display_name"] =
        data_type.initial_device_display_name.value();
  }
  if (data_type.medium) {
    obj["medium"] = data_type.medium.value();
  }
  if (data_type.password) {
    obj["password"] = data_type.password.value();
  }
  if (data_type.refresh_token) {
    obj["refresh_token"] = data_type.refresh_token.value();
  }
  if (data_type.token) {
    obj["token"] = data_type.token.value();
  }
  obj["type"] = data_type.type;
  if (data_type.user) {
    obj["user"] = data_type.user.value();
  }
}

void from_json(const json &obj, well_known &data_type) {
  data_type.m_homeserver = obj["m.homeserver"].get<well_known_m_homeserver>();
  data_type.m_identity_server =
      obj["m.identity_server"].get<well_known_identity_server>();
}

void to_json(json &obj, const well_known &data_type) {
  obj = nlohmann::json::object();
  if (data_type.m_homeserver) {
    obj["m.homeserver"] = data_type.m_homeserver.value();
  }
  if (data_type.m_identity_server) {
    obj["m.identity_server"] = data_type.m_identity_server.value();
  }
}

void from_json(const json &obj, login_resp &data_type) {
  data_type.access_token = obj["access_token"].get<std::string_view>();
  data_type.device_id = obj["device_id"].get<std::string_view>();
  data_type.expires_in_ms = obj["expires_in_ms"].get<long>();
  data_type.home_server = obj["home_server"].get<std::string_view>();
  data_type.refresh_token = obj["refresh_token"].get<std::string_view>();
  data_type.user_id = obj["user_id"].get<std::string_view>();
  data_type.well_known = obj["well_known"].get<well_known>();
}

void to_json(json &obj, const login_resp &data_type) {
  obj = nlohmann::json::object();
  obj["access_token"] = data_type.access_token;
  obj["device_id"] = data_type.device_id;
  if (data_type.expires_in_ms) {
    obj["expires_in_ms"] = data_type.expires_in_ms.value();
  }
  if (data_type.home_server) {
    obj["home_server"] = data_type.home_server.value();
  }
  if (data_type.refresh_token) {
    obj["refresh_token"] = data_type.refresh_token.value();
  }
  obj["user_id"] = data_type.user_id;
  if (data_type.well_known) {
    obj["well_known"] = data_type.well_known.value();
  }
}

void from_json(const json &obj, registration_resp &data_type) {
  if (obj.contains("access_token")) {
    data_type.access_token = obj["access_token"].get<std::string_view>();
  }
  if (obj.contains("device_id")) {
    data_type.device_id = obj["device_id"].get<std::string_view>();
  }
  if (obj.contains("expires_in_ms")) {
    data_type.expires_in_ms = obj["expires_in_ms"].get<long>();
  }
  if (obj.contains("refresh_token")) {
    data_type.refresh_token = obj["refresh_token"].get<std::string_view>();
  }
  data_type.user_id = obj["user_id"].get<std::string_view>();
}

void to_json(json &obj, const registration_resp &data_type) {
  obj = nlohmann::json::object();
  if (data_type.access_token) {
    obj["access_token"] = data_type.access_token.value();
  }
  if (data_type.device_id) {
    obj["device_id"] = data_type.device_id.value();
  }
  if (data_type.expires_in_ms) {
    obj["expires_in_ms"] = data_type.expires_in_ms.value();
  }
  if (data_type.refresh_token) {
    obj["refresh_token"] = data_type.refresh_token.value();
  }
  obj["user_id"] = data_type.user_id;
}

void from_json(const json &obj, whoami_resp &data_type) {
  data_type.user_id = obj["user_id"].get<std::string_view>();
  data_type.is_guest = obj["is_guest"].get<bool>();
  if (obj.contains("device_id")) {
    data_type.device_id = obj["device_id"].get<std::string_view>();
  }
}

void to_json(json &obj, const whoami_resp &data_type) {
  obj = nlohmann::json::object();
  obj["user_id"] = data_type.user_id;
  obj["is_guest"] = data_type.is_guest;
  if (data_type.device_id) {
    obj["device_id"] = data_type.device_id.value();
  }
}

void from_json(const json &obj, JoinBody &data_type) {
  if (obj.contains("reason")) {
    data_type.reason = obj["reason"].get<std::string_view>();
  }
  if (obj.contains("third_party_signed")) {
    data_type.third_party_signed =
        obj["third_party_signed"].get<ThirdPartySigned>();
  }
}

void to_json(json &obj, const JoinBody &data_type) {
  obj = nlohmann::json::object();
  if (data_type.reason) {
    obj["reason"] = data_type.reason.value();
  }
  if (data_type.third_party_signed) {
    obj["third_party_signed"] = data_type.third_party_signed.value();
  }
}
} // namespace client_server_json
