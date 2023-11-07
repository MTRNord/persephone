#include "httplib.h"
#include "utils/utils.hpp"

using namespace httplib;

int main(void) {
  // #ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  //   SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
  // #else
  Server svr;
  // #endif

  if (!svr.is_valid()) {
    printf("server has an error...\n");
    return -1;
  }

  svr.Get("/", [=](const Request & /*req*/, Response &res) {
    res.set_redirect("/hi");
  });

  svr.Get("/hi", [](const Request & /*req*/, Response &res) {
    res.set_content("Hello World!\n", "text/plain");
  });

  svr.set_logger([](const Request &req, const Response &res) {
    std::cout << log(req, res);
  });
  svr.listen("localhost", 8080);

  return 0;
}