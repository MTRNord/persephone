#pragma once

/// @file
/// @brief This header contains all struct definitions of json response and
/// request types

#include "nlohmann/json.hpp"
#include <map>

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

} // namespace server_server_json