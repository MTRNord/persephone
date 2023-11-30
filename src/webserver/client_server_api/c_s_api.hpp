#pragma once

#include "database/database.hpp"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include "utils/config.hpp"
#include "webserver/client_server_api/auth.hpp"
#include "webserver/json.hpp"
#include "webserver/webserver.hpp"

using json = nlohmann::json;

using namespace httplib;

namespace client_server_api {
void setup_client_server_api(Server &svr, Database const &database,
                             Config const &config) {

  // Register user
  svr.Post("/_matrix/client/v3/register",
           [&](const Request &req, Response &res) {
             client_server_api::register_user(database, config, req, res);
           });
  svr.Get("/_matrix/client/v3/register/available",
          [&](const Request &req, Response &res) {
            client_server_api::check_available(database, config, req, res);
          });

  // Login
  svr.Get("/_matrix/client/v3/login",
          [&](const Request & /*req*/, Response &res) {
            client_server_json::LoginFlow password_flow = {
                .type = "m.login.password"};
            client_server_json::GetLogin login{.flows = {password_flow}};
            json j = login;
            set_json_response(res, j);
          });

  // Whoami
  svr.Get("/_matrix/client/v3/account/whoami",
          [&](const Request &req, Response &res) {
            client_server_api::whoami(database, req, res);
          });

  // Versions
  svr.Get("/_matrix/client/versions",
          [&](const Request & /*req*/, Response &res) {
            // We only support v1.8. However due to
            // https://github.com/matrix-org/matrix-js-sdk/issues/3915 we need
            // to also claim v1.1 support. Note that any issues due to this are
            // not considered bugs in persephone.
            static constexpr client_server_json::versions versions = {
                .versions = {"v1.1", "v1.8"}};
            json j = versions;
            set_json_response(res, j);
          });
}
} // namespace client_server_api