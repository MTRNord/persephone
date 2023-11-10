#pragma once

#include "database/database.hpp"
#include "httplib.h"
using namespace httplib;

class Webserver {
private:
  // #ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  //   SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
  // #else
  Server svr;
  // #endif

  static void handle_exceptions(const Request & /*req*/, Response &res,
                                std::exception_ptr ep);
  static void get_root(const Request & /*req*/, Response &res);
  static void get_server_version(const Request & /*req*/, Response &res);

public:
  Webserver();
  void start();
};