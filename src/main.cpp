#define JSON_DIAGNOSTICS 1
#define JSON_USE_IMPLICIT_CONVERSIONS 0

#include "httplib.h"
#include "json.hpp"
#include "nlohmann/json.hpp"
#include "utils/utils.hpp"
#include <format>

using namespace httplib;
using json = nlohmann::json;

int main(void) {
  // #ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  //   SSLServer svr(SERVER_CERT_FILE, SERVER_PRIVATE_KEY_FILE);
  // #else
  Server svr;
  // #endif

  if (!svr.is_valid()) {
    std::cout << "server has an error..." << std::endl;
    return -1;
  }

  svr.Get("/", [=](const Request & /*req*/, Response &res) {
    res.set_redirect("/_matrix/federation/v1/version");
  });

  svr.Get("/_matrix/federation/v1/version",
          [](const Request & /*req*/, Response &res) {
            matrix_json::version::server server = {.name = "persephone",
                                                   .version = "0.1.0"};
            matrix_json::version::json version = {.server = server};

            json j = version;
            res.set_content(j.dump(), "application/json");
          });

  svr.set_logger([](const Request &req, const Response &res) {
    std::cout << log(req, res) << std::endl;
  });

  svr.set_exception_handler(
      [](const Request & /*req*/, Response &res, std::exception_ptr ep) {
        std::string error;

        // Get exception or rethrow
        try {
          std::rethrow_exception(ep);
        } catch (std::exception &e) {
          error = e.what();
        } catch (...) { // See the following NOTE
          error = "Unknown Exception";
        }

        return_error(res, "M_UNKNOWN", error);
      });

  std::cout << "Listening on 8080" << std::endl;
  svr.listen("localhost", 8080);

  return 0;
}