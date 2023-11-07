#pragma once
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace matrix_json {
struct generic_json_error {
  std::string errcode;
  std::string error;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(generic_json_error, errcode, error)

namespace version {
struct server {
  std::string name;
  std::string version;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(server, name, version)

struct json {
  matrix_json::version::server server;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(json, server)
} // namespace version
} // namespace matrix_json