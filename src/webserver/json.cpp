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
