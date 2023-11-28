#include "json.hpp"

namespace client_server_json {

void from_json(const json &obj, client_server_json::registration_body &p) {
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

void to_json(json &obj, const client_server_json::registration_body &p) {
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

void from_json(const json &obj, client_server_json::registration_resp &p) {
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

void to_json(json &obj, const client_server_json::registration_resp &p) {
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

void from_json(const json &obj, client_server_json::whoami_resp &p) {
  p.user_id = obj["user_id"].get<std::string>();
  p.is_guest = obj["is_guest"].get<bool>();
  if (obj.contains("device_id")) {
    p.device_id = obj["device_id"].get<std::string>();
  }
}

void to_json(json &obj, const client_server_json::whoami_resp &p) {
  obj = nlohmann::json::object();
  obj["user_id"] = p.user_id;
  obj["is_guest"] = p.is_guest;
  if (p.device_id) {
    obj["device_id"] = p.device_id.value();
  }
}
} // namespace client_server_json