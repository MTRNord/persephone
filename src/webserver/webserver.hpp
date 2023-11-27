#pragma once

#include "database/database.hpp"
#include "httplib.h"
#include "utils/config.hpp"
#include <exception>

using namespace httplib;

class Webserver {
private:
  // #ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  //   SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
  // #else
  Server svr;
  // #endif
  Config config;

  static void handle_exceptions(const Request & /*req*/, Response &res,
                                std::exception_ptr ep);
  static void get_root(const Request & /*req*/, Response &res);
  static void get_server_version(const Request & /*req*/, Response &res);
  void get_server_key(const Request & /*req*/, Response &res);

public:
  Webserver(Config config, Database const &database);
  void start();
};