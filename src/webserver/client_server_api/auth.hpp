#pragma once
#include "database/database.hpp"
#include "httplib.h"
#include "utils/config.hpp"

using namespace httplib;

namespace client_server_api {
bool is_valid_localpart(std::string const &localpart, Config const &config);
void register_user(const Database &db, const Config &config, const Request &req,
                   Response &res);
void check_available(const Database &db, const Config &config,
                     const Request &req, Response &res);
void whoami(const Database &db, const Config &config, const Request &req,
            Response &res);
} // namespace client_server_api