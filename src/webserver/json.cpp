#include "json.hpp"
#include <map>
#include <string>
#include <vector>

namespace server_server_json {
void from_json(const json &obj, MakeJoinResp &data_type) {
  if (obj.contains("room_version")) {
    data_type.room_version = obj["room_version"].get<std::string>();
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
    data_type.m_server = obj["m.server"].get<std::string>();
  }
}

void to_json(json &obj, const well_known &data_type) {
  obj = nlohmann::json::object();
  if (data_type.m_server) {
    obj["m.server"] = data_type.m_server.value();
  }
}
void from_json(const json &obj, SendJoinResp &data_type) {
  data_type.auth_chain = obj["auth_chain"].get<std::vector<json::object_t>>();
  data_type.event = obj["event"];
  data_type.members_omitted =
      obj.contains("members_omitted") && obj["members_omitted"].get<bool>();
  if (obj.contains("origin")) {
    data_type.origin = obj["origin"].get<std::string>();
  }
  if (obj.contains("servers_in_room")) {
    data_type.servers_in_room =
        obj["servers_in_room"].get<std::vector<std::string>>();
  }
  data_type.state = obj["state"].get<std::vector<json>>();
}

void to_json(json &obj, const SendJoinResp &data_type) {
  obj = nlohmann::json::object();
  obj["auth_chain"] = data_type.auth_chain;
  obj["event"] = data_type.event;
  obj["members_omitted"] = data_type.members_omitted;
  obj["origin"] = data_type.origin;
  obj["servers_in_room"] = data_type.servers_in_room;
  obj["state"] = data_type.state;
}

void from_json(const json &obj, DirectoryQueryResp &data_type) {
  data_type.room_id = obj["room_id"].get<std::string>();
  data_type.servers = obj["servers"].get<std::vector<std::string>>();
}

void to_json(json &obj, const DirectoryQueryResp &data_type) {
  obj = nlohmann::json::object();
  obj["room_id"] = data_type.room_id;
  obj["servers"] = data_type.servers;
}

} // namespace server_server_json

namespace client_server_json {
void from_json(const json &obj, StateEvent &data_type) {
  data_type.content = obj["content"].get<json::object_t>();
  if (obj.contains("state_key")) {
    data_type.state_key = obj["state_key"].get<std::string>();
  } else {
    data_type.state_key = "";
  }

  if (obj.contains("event_id")) {
    data_type.event_id = obj["event_id"].get<std::string>();
  }

  data_type.type = obj["type"].get<std::string>();
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
    data_type.events = obj["events"].get<std::map<std::string, int>>();
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
        obj["notifications"].get<std::map<std::string, int>>();
  }
  if (obj.contains("redact")) {
    data_type.redact = obj["redact"].get<int>();
  }
  if (obj.contains("state_default")) {
    data_type.state_default = obj["state_default"].get<int>();
  }
  if (obj.contains("users")) {
    data_type.users = obj["users"].get<std::map<std::string, int>>();
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
    data_type.invite = obj["invite"].get<std::vector<std::string>>();
  }

  if (obj.contains("invite_3pid")) {
    data_type.invite_3pid = obj["invite_3pid"].get<std::vector<Invite3pid>>();
  }

  if (obj.contains("is_direct")) {
    data_type.is_direct = obj["is_direct"].get<bool>();
  }

  if (obj.contains("name")) {
    data_type.name = obj["name"].get<std::string>();
  }

  if (obj.contains("power_level_content_override")) {
    data_type.power_level_content_override =
        obj["power_level_content_override"].get<PowerLevelEventContent>();
  }

  if (obj.contains("preset")) {
    data_type.preset = obj["preset"].get<std::string>();
  }

  if (obj.contains("room_alias_name")) {
    data_type.room_alias_name = obj["room_alias_name"].get<std::string>();
  }

  if (obj.contains("room_version")) {
    data_type.room_version = obj["room_version"].get<std::string>();
  }

  if (obj.contains("topic")) {
    data_type.topic = obj["topic"].get<std::string>();
  }

  if (obj.contains("visibility")) {
    data_type.visibility = obj["visibility"].get<std::string>();
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
    data_type.session = obj["session"].get<std::string>();
  }
  if (obj.contains("type")) {
    data_type.type = obj["type"].get<std::string>();
  }
}

void to_json(json &obj, const AuthenticationData &data_type) {
  obj = nlohmann::json::object();
  if (data_type.session) {
    obj["session"] = data_type.session.value();
  }
  if (data_type.type) {
    obj["type"] = data_type.type.value();
  }
}

void from_json(const json &obj, registration_body &data_type) {
  if (obj.contains("auth")) {
    data_type.auth = obj["auth"].get<AuthenticationData>();
  }
  if (obj.contains("device_id")) {
    data_type.device_id = obj["device_id"].get<std::string>();
  }
  if (obj.contains("inhibit_login")) {
    data_type.inhibit_login = obj["inhibit_login"].get<bool>();
  }
  if (obj.contains("initial_device_display_name")) {
    data_type.initial_device_display_name =
        obj["initial_device_display_name"].get<std::string>();
  }
  if (obj.contains("password")) {
    data_type.password = obj["password"].get<std::string>();
  }
  if (obj.contains("refresh_token")) {
    data_type.refresh_token = obj["refresh_token"].get<bool>();
  }
  if (obj.contains("username")) {
    data_type.username = obj["username"].get<std::string>();
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
  data_type.type = obj["type"].get<std::string>();
  if (obj.contains("user")) {
    data_type.user = obj["user"].get<std::string>();
  }
  if (obj.contains("medium")) {
    data_type.medium = obj["medium"].get<std::string>();
  }
  if (obj.contains("address")) {
    data_type.address = obj["address"].get<std::string>();
  }
  if (obj.contains("country")) {
    data_type.country = obj["country"].get<std::string>();
  }
  if (obj.contains("phone")) {
    data_type.phone = obj["phone"].get<std::string>();
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
    data_type.address = obj["address"].get<std::string>();
  }
  if (obj.contains("device_id")) {
    data_type.device_id = obj["device_id"].get<std::string>();
  }
  if (obj.contains("identifier")) {
    data_type.identifier = obj["identifier"].get<login_identifier>();
  }
  if (obj.contains("initial_device_display_name")) {
    data_type.initial_device_display_name =
        obj["initial_device_display_name"].get<std::string>();
  }
  if (obj.contains("medium")) {
    data_type.medium = obj["medium"].get<std::string>();
  }
  if (obj.contains("password")) {
    data_type.password = obj["password"].get<std::string>();
  }
  if (obj.contains("refresh_token")) {
    data_type.refresh_token = obj["refresh_token"].get<bool>();
  }
  if (obj.contains("token")) {
    data_type.token = obj["token"].get<std::string>();
  }
  data_type.type = obj["type"].get<std::string>();
  if (obj.contains("user")) {
    data_type.user = obj["user"].get<std::string>();
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
  data_type.m_server = obj["m.server"].get<well_known_m_server>();
  data_type.m_identity_server =
      obj["m.identity_server"].get<well_known_identity_server>();
}

void to_json(json &obj, const well_known &data_type) {
  obj = nlohmann::json::object();
  if (data_type.m_server) {
    obj["m.server"] = data_type.m_server.value();
  }
  if (data_type.m_identity_server) {
    obj["m.identity_server"] = data_type.m_identity_server.value();
  }
}

void from_json(const json &obj, login_resp &data_type) {
  data_type.access_token = obj["access_token"].get<std::string>();
  data_type.device_id = obj["device_id"].get<std::string>();
  if (obj.contains("expires_in_ms")) {
    data_type.expires_in_ms = obj["expires_in_ms"].get<int>();
  }
  if (obj.contains("home_server")) {
    data_type.home_server = obj["home_server"].get<std::string>();
  }
  if (obj.contains("refresh_token")) {
    data_type.refresh_token = obj["refresh_token"].get<std::string>();
  }
  data_type.user_id = obj["user_id"].get<std::string>();
  if (obj.contains("well_known")) {
    data_type.well_known = obj["well_known"].get<well_known>();
  }
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
    data_type.access_token = obj["access_token"].get<std::string>();
  }
  if (obj.contains("device_id")) {
    data_type.device_id = obj["device_id"].get<std::string>();
  }
  if (obj.contains("expires_in_ms")) {
    data_type.expires_in_ms = obj["expires_in_ms"].get<long>();
  }
  if (obj.contains("refresh_token")) {
    data_type.refresh_token = obj["refresh_token"].get<std::string>();
  }
  data_type.user_id = obj["user_id"].get<std::string>();
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
  data_type.user_id = obj["user_id"].get<std::string>();
  data_type.is_guest = obj["is_guest"].get<bool>();
  if (obj.contains("device_id")) {
    data_type.device_id = obj["device_id"].get<std::string>();
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

void from_json(const json &obj, room_versions_capability &data_type) {
  data_type.default_ = obj["default"].get<std::string>();
  data_type.available =
      obj["available"].get<std::map<std::string, std::string>>();
}

void to_json(json &obj, const room_versions_capability &data_type) {
  obj = nlohmann::json::object();
  obj["default"] = data_type.default_;
  obj["available"] = data_type.available;
}

void from_json(const json &obj, capabilities_obj &data_type) {
  if (obj.contains("m.3pid_changes")) {
    data_type.third_pid_changes =
        obj["m.3pid_changes"].get<boolean_capability>();
  }
  if (obj.contains("m.change_password")) {
    data_type.change_password =
        obj["m.change_password"].get<boolean_capability>();
  }
  if (obj.contains("m.get_login_token")) {
    data_type.get_login_token =
        obj["m.get_login_token"].get<boolean_capability>();
  }
  if (obj.contains("m.set_avatar_url")) {
    data_type.set_avatar_url =
        obj["m.set_avatar_url"].get<boolean_capability>();
  }
  if (obj.contains("m.set_displayname")) {
    data_type.set_displayname =
        obj["m.set_displayname"].get<boolean_capability>();
  }
  if (obj.contains("m.profile_fields")) {
    data_type.profile_fields =
        obj["m.profile_fields"].get<profile_field_capability>();
  }
  if (obj.contains("m.room_versions")) {
    data_type.room_versions =
        obj["m.room_versions"].get<room_versions_capability>();
  }
}

void to_json(json &obj, const capabilities_obj &data_type) {
  obj = nlohmann::json::object();
  if (data_type.third_pid_changes) {
    obj["m.3pid_changes"] = data_type.third_pid_changes.value();
  }
  if (data_type.change_password) {
    obj["m.change_password"] = data_type.change_password.value();
  }
  if (data_type.get_login_token) {
    obj["m.get_login_token"] = data_type.get_login_token.value();
  }
  if (data_type.set_avatar_url) {
    obj["m.set_avatar_url"] = data_type.set_avatar_url.value();
  }
  if (data_type.set_displayname) {
    obj["m.set_displayname"] = data_type.set_displayname.value();
  }
  if (data_type.profile_fields) {
    obj["m.profile_fields"] = data_type.profile_fields.value();
  }
  if (data_type.room_versions) {
    obj["m.room_versions"] = data_type.room_versions.value();
  }
}

void from_json(const json &obj, JoinBody &data_type) {
  if (obj.contains("reason")) {
    data_type.reason = obj["reason"].get<std::string>();
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

// ============================================================================
// Sync API serialization
// ============================================================================

void from_json(const json &obj, SyncTimeline &data_type) {
  if (obj.contains("events")) {
    data_type.events = obj["events"].get<std::vector<json>>();
  }
  if (obj.contains("limited")) {
    data_type.limited = obj["limited"].get<bool>();
  }
  if (obj.contains("prev_batch")) {
    data_type.prev_batch = obj["prev_batch"].get<std::string>();
  }
}

void to_json(json &obj, const SyncTimeline &data_type) {
  obj = nlohmann::json::object();
  obj["events"] = data_type.events;
  obj["limited"] = data_type.limited;
  if (data_type.prev_batch) {
    obj["prev_batch"] = data_type.prev_batch.value();
  }
}

void from_json(const json &obj, SyncRoomState &data_type) {
  if (obj.contains("events")) {
    data_type.events = obj["events"].get<std::vector<json>>();
  }
}

void to_json(json &obj, const SyncRoomState &data_type) {
  obj = nlohmann::json::object();
  obj["events"] = data_type.events;
}

void from_json(const json &obj, SyncAccountData &data_type) {
  if (obj.contains("events")) {
    data_type.events = obj["events"].get<std::vector<json>>();
  }
}

void to_json(json &obj, const SyncAccountData &data_type) {
  obj = nlohmann::json::object();
  obj["events"] = data_type.events;
}

void from_json(const json &obj, SyncEphemeral &data_type) {
  if (obj.contains("events")) {
    data_type.events = obj["events"].get<std::vector<json>>();
  }
}

void to_json(json &obj, const SyncEphemeral &data_type) {
  obj = nlohmann::json::object();
  obj["events"] = data_type.events;
}

void from_json(const json &obj, UnreadNotificationCounts &data_type) {
  if (obj.contains("highlight_count")) {
    data_type.highlight_count = obj["highlight_count"].get<int64_t>();
  }
  if (obj.contains("notification_count")) {
    data_type.notification_count = obj["notification_count"].get<int64_t>();
  }
}

void to_json(json &obj, const UnreadNotificationCounts &data_type) {
  obj = nlohmann::json::object();
  obj["highlight_count"] = data_type.highlight_count;
  obj["notification_count"] = data_type.notification_count;
}

void from_json(const json &obj, RoomSummary &data_type) {
  if (obj.contains("m.heroes")) {
    data_type.m_heroes = obj["m.heroes"].get<std::vector<std::string>>();
  }
  if (obj.contains("m.joined_member_count")) {
    data_type.m_joined_member_count =
        obj["m.joined_member_count"].get<int64_t>();
  }
  if (obj.contains("m.invited_member_count")) {
    data_type.m_invited_member_count =
        obj["m.invited_member_count"].get<int64_t>();
  }
}

void to_json(json &obj, const RoomSummary &data_type) {
  obj = nlohmann::json::object();
  if (data_type.m_heroes) {
    obj["m.heroes"] = data_type.m_heroes.value();
  }
  if (data_type.m_joined_member_count) {
    obj["m.joined_member_count"] = data_type.m_joined_member_count.value();
  }
  if (data_type.m_invited_member_count) {
    obj["m.invited_member_count"] = data_type.m_invited_member_count.value();
  }
}

void from_json(const json &obj, SyncJoinedRoom &data_type) {
  if (obj.contains("summary")) {
    data_type.summary = obj["summary"].get<RoomSummary>();
  }
  if (obj.contains("timeline")) {
    data_type.timeline = obj["timeline"].get<SyncTimeline>();
  }
  if (obj.contains("state")) {
    data_type.state = obj["state"].get<SyncRoomState>();
  }
  if (obj.contains("account_data")) {
    data_type.account_data = obj["account_data"].get<SyncAccountData>();
  }
  if (obj.contains("ephemeral")) {
    data_type.ephemeral = obj["ephemeral"].get<SyncEphemeral>();
  }
  if (obj.contains("unread_notifications")) {
    data_type.unread_notifications =
        obj["unread_notifications"].get<UnreadNotificationCounts>();
  }
}

void to_json(json &obj, const SyncJoinedRoom &data_type) {
  obj = nlohmann::json::object();
  if (data_type.summary) {
    obj["summary"] = data_type.summary.value();
  }
  obj["timeline"] = data_type.timeline;
  obj["state"] = data_type.state;
  obj["account_data"] = data_type.account_data;
  obj["ephemeral"] = data_type.ephemeral;
  obj["unread_notifications"] = data_type.unread_notifications;
}

void from_json(const json &obj, SyncInviteState &data_type) {
  if (obj.contains("events")) {
    data_type.events = obj["events"].get<std::vector<json>>();
  }
}

void to_json(json &obj, const SyncInviteState &data_type) {
  obj = nlohmann::json::object();
  obj["events"] = data_type.events;
}

void from_json(const json &obj, SyncInvitedRoom &data_type) {
  if (obj.contains("invite_state")) {
    data_type.invite_state = obj["invite_state"].get<SyncInviteState>();
  }
}

void to_json(json &obj, const SyncInvitedRoom &data_type) {
  obj = nlohmann::json::object();
  obj["invite_state"] = data_type.invite_state;
}

void from_json(const json &obj, SyncLeftRoom &data_type) {
  if (obj.contains("timeline")) {
    data_type.timeline = obj["timeline"].get<SyncTimeline>();
  }
  if (obj.contains("state")) {
    data_type.state = obj["state"].get<SyncRoomState>();
  }
  if (obj.contains("account_data")) {
    data_type.account_data = obj["account_data"].get<SyncAccountData>();
  }
}

void to_json(json &obj, const SyncLeftRoom &data_type) {
  obj = nlohmann::json::object();
  obj["timeline"] = data_type.timeline;
  obj["state"] = data_type.state;
  obj["account_data"] = data_type.account_data;
}

void from_json(const json &obj, SyncRooms &data_type) {
  if (obj.contains("join")) {
    data_type.join = obj["join"].get<std::map<std::string, SyncJoinedRoom>>();
  }
  if (obj.contains("invite")) {
    data_type.invite =
        obj["invite"].get<std::map<std::string, SyncInvitedRoom>>();
  }
  if (obj.contains("leave")) {
    data_type.leave = obj["leave"].get<std::map<std::string, SyncLeftRoom>>();
  }
}

void to_json(json &obj, const SyncRooms &data_type) {
  obj = nlohmann::json::object();
  obj["join"] = data_type.join;
  obj["invite"] = data_type.invite;
  obj["leave"] = data_type.leave;
}

void from_json(const json &obj, DeviceLists &data_type) {
  if (obj.contains("changed")) {
    data_type.changed = obj["changed"].get<std::vector<std::string>>();
  }
  if (obj.contains("left")) {
    data_type.left = obj["left"].get<std::vector<std::string>>();
  }
}

void to_json(json &obj, const DeviceLists &data_type) {
  obj = nlohmann::json::object();
  obj["changed"] = data_type.changed;
  obj["left"] = data_type.left;
}

void from_json(const json &obj, SyncResponse &data_type) {
  if (obj.contains("next_batch")) {
    data_type.next_batch = obj["next_batch"].get<std::string>();
  }
  if (obj.contains("account_data")) {
    data_type.account_data = obj["account_data"].get<SyncAccountData>();
  }
  if (obj.contains("rooms")) {
    data_type.rooms = obj["rooms"].get<SyncRooms>();
  }
  if (obj.contains("device_lists")) {
    data_type.device_lists = obj["device_lists"].get<DeviceLists>();
  }
  if (obj.contains("device_one_time_keys_count")) {
    data_type.device_one_time_keys_count =
        obj["device_one_time_keys_count"].get<std::map<std::string, int64_t>>();
  }
  if (obj.contains("device_unused_fallback_key_types")) {
    data_type.device_unused_fallback_key_types =
        obj["device_unused_fallback_key_types"].get<std::vector<std::string>>();
  }
}

void to_json(json &obj, const SyncResponse &data_type) {
  obj = nlohmann::json::object();
  obj["next_batch"] = data_type.next_batch;
  obj["account_data"] = data_type.account_data;
  obj["rooms"] = data_type.rooms;
  obj["device_lists"] = data_type.device_lists;
  obj["device_one_time_keys_count"] = data_type.device_one_time_keys_count;
  obj["device_unused_fallback_key_types"] =
      data_type.device_unused_fallback_key_types;
}

} // namespace client_server_json
