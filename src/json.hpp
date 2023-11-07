#pragma once

/// @file
/// @brief This header contains all struct definitions of json response and
/// request types

#include "nlohmann/json.hpp"

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
} // namespace server_server_json