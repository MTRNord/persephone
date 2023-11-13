#include "webserver.hpp"
#include "nlohmann/json.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"

using json = nlohmann::json;

Webserver::Webserver(Config config) {
  if (!this->svr.is_valid()) {
    throw std::runtime_error("server has an error...");
  }

  this->svr.set_logger([](const Request &req, const Response &res) {
    std::cout << log(req, res) << std::endl;
  });

  this->svr.set_exception_handler(this->handle_exceptions);

  this->svr.Get("/", this->get_root);

  this->svr.Get("/_matrix/federation/v1/version", this->get_server_version);
}

void Webserver::handle_exceptions(const Request & /*req*/, Response &res,
                                  std::exception_ptr ep) {
  std::string error;

  // Get exception or rethrow
  try {
    std::rethrow_exception(std::move(ep));
  } catch (std::exception &e) {
    error = e.what();
  } catch (...) { // See the following NOTE
    error = "Unknown Exception";
  }

  return_error(res, "M_UNKNOWN", error);
}

void Webserver::get_root(const Request & /*req*/, Response &res) {
  res.set_redirect("/_matrix/federation/v1/version");
}

void Webserver::get_server_version(const Request & /*req*/, Response &res) {
  server_server_json::version version = {
      .server = {.name = "persephone", .version = "0.1.0"}};

  json j = version;
  res.set_content(j.dump(), "application/json");
}

void Webserver::start() {
  std::cout << "Listening on 8080" << std::endl;
  this->svr.listen("localhost", 8080);
}