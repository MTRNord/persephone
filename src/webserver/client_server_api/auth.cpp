#include "auth.hpp"
#include "nlohmann/json.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
#include <format>
#include <optional>

using json = nlohmann::json;

namespace client_server_api {
void register_user(const Database &db, const Config &config, const Request &req,
                   Response &res) {
  // Get the request body as json
  json body = json::parse(req.body);
  auto reg_body = body.get<client_server_json::registration_body>();

  // Do registration. If the db fails we return an error 400.
  // This can be M_USER_IN_USE if the user already exists
  // M_INVALID_USERNAME if the username is invalid
  // M_EXCLUSIVE if the user is in a namespace exclusively claimed by an
  // application service.
  //
  // If the auth data is incomplete we return status code 401 instead.

  // Check type of registration via the optional query parameter `kind`
  // If the parameter is not set, we default to "user"
  std::string kind = "user";
  if (req.has_param("kind")) {
    kind = req.get_param_value("kind");
  }

  // TODO: Remove this if we support guests:
  if (kind == "guest") {
    return_error(res, "M_UNKNOWN", "Guests are not supported yet", 403);
    return;
  }

  // Check if the username is valid. Note that `username` means localpart in
  // matrix terms.
  auto username = reg_body.username.value_or(random_string(25));
  if (!client_server_api::is_valid_localpart(username, config)) {
    return_error(res, "M_INVALID_USERNAME", "Invalid username", 400);
    return;
  }

  // Check if the username is already taken
  if (db.user_exists(
          std::format("@{}:{}", username, config.matrix_config.server_name))) {
    return_error(res, "M_USER_IN_USE", "Username already taken", 400);
    return;
  }

  // If we have no initial_device_display_name, we set it to the device_id
  if (!reg_body.initial_device_display_name) {
    reg_body.initial_device_display_name = reg_body.device_id;
  }

  // Try to register the user
  auto access_token = std::make_optional<std::string>();
  auto device_id = std::make_optional<std::string>();
  try {
    Database::UserCreationData data{
        reg_body.username.value(), reg_body.device_id,
        reg_body.initial_device_display_name.value(), reg_body.password};
    auto device_data = db.create_user(data);

    if (!reg_body.inhibit_login) {
      access_token = device_data.access_token;
      device_id = device_data.device_id;
    }
  } catch (std::exception &e) {
    return_error(res, "M_UNKNOWN", e.what(), 500);
    return;
  }

  client_server_json::registration_resp resp = {
      .access_token = access_token,
      .device_id = device_id,
      .user_id =
          std::format("@{}:{}", username, config.matrix_config.server_name),
  };
  json j = resp;
  res.set_content(j.dump(), "application/json");
}

/**
 * Check if a localpard is valid according to
 * https://spec.matrix.org/v1.8/appendices/#user-identifiers
 *
 * ```
 * user_id_localpart = 1*user_id_char
 * user_id_char = DIGIT
 *              / %x61-7A                   ; a-z
 *              / "-" / "." / "=" / "_" / "/" / "+"
 * ```
 *
 * We also need to check that it not exceeds 255 chars when containing `@`, a
 * colon and the domain.
 *
 * @param localpart The localpart to check
 * @return true if the localpart is valid, false otherwise
 */
bool is_valid_localpart(std::string const &localpart, Config const &config) {
  for (auto const &c : localpart) {
    if (std::isdigit(c)) {
      continue;
    }
    if (c >= 'a' && c <= 'z') {
      continue;
    }
    if (c == '-' || c == '.' || c == '=' || c == '_' || c == '/' || c == '+') {
      continue;
    }
    return false;
  }

  // Check if the localpart is too long
  if (std::format("@{}:{}", localpart, config.matrix_config.server_name)
          .length() > 255) {
    return false;
  }

  return true;
}
void check_available(const Database &db, const Config &config,
                     const Request &req, Response &res) {
  // Get the username request query parameter
  if (!req.has_param("username")) {
    return_error(res, "M_MISSING_PARAM", "Missing username parameter", 500);
    return;
  }
  auto username = req.get_param_value("username");

  // Check if the username is valid
  if (!client_server_api::is_valid_localpart(username, config)) {
    return_error(res, "M_INVALID_USERNAME", "Invalid username", 400);
    return;
  }

  // Check if the username is already taken
  if (db.user_exists(
          std::format("@{}:{}", username, config.matrix_config.server_name))) {
    return_error(res, "M_USER_IN_USE", "Username already taken", 400);
    return;
  }

  // Check if the username is in a namespace exclusively claimed by an
  // application service.
  // TODO: Implement this

  // Return 200 OK with empty json body
  res.set_content("{}", "application/json");
  res.status = 200;
}

void whoami(const Database &db, const Config &config, const Request &req,
            Response &res) {
  // Get the access token from the Authorization header
  if (!req.has_header("Authorization")) {
    return_error(res, "M_MISSING_TOKEN", "Missing Authorization header", 401);
    return;
  }
  auto auth_header = req.get_header_value("Authorization");
  // Remove the "Bearer " prefix
  auto access_token = auth_header.substr(7);

  // Check if we have the access token in the database
  auto user_info = db.get_user_info(access_token);
  if (!user_info) {
    return_error(res, "M_UNKNOWN_TOKEN", "Unknown access token", 401);
    return;
  }

  // Return the user id, if the user is a guest and the device id if its set as
  // json
  client_server_json::whoami_resp resp = {
      .user_id = user_info->user_id,
      .is_guest = user_info->is_guest,
      .device_id = user_info->device_id,
  };
  json j = resp;
  res.set_content(j.dump(), "application/json");
  res.status = 200;
}
} // namespace client_server_api