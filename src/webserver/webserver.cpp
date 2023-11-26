#include "webserver.hpp"
#include "database/database.hpp"
#include "nlohmann/json.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/json.hpp"
#include <bits/chrono.h>
#include <filesystem>
#include <format>
#include <iostream>
#include <iterator>
#include <map>
#include <nlohmann/json_fwd.hpp>
#include <sodium/crypto_sign.h>
#include <sodium/crypto_sign_ed25519.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using json = nlohmann::json;

Webserver::Webserver(Config config, Database const &database) {
  this->config = config;
  if (!this->svr.is_valid()) {
    throw std::runtime_error("server has an error...");
  }

  std::cout << std::format("Starting server as {}",
                           config.matrix_config.server_name)
            << '\n';

  this->svr.set_logger([](const Request &req, const Response &res) {
    std::cout << log(req, res) << '\n';
  });

  this->svr.set_exception_handler(this->handle_exceptions);

  this->svr.Get("/", this->get_root);

  this->svr.Get("/_matrix/federation/v1/version", this->get_server_version);
  this->svr.Get("/_matrix/key/v2/server",
                [this](const httplib::Request &req, httplib::Response &res) {
                  this->get_server_key(req, res);
                });
}

void Webserver::handle_exceptions(const Request & /*req*/, Response &res,
                                  std::exception_ptr ep) {
  std::string error;

  // Get exception or rethrow
  try {
    std::rethrow_exception(std::move(ep));
  } catch (std::exception &e) {
    error = e.what();
  } catch (char const *e) {
    error = std::string(e);
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

void Webserver::get_server_key(const Request & /*req*/, Response &res) {
  auto server_name = this->config.matrix_config.server_name;
  long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();
  long tomorrow = now + static_cast<long>(24 * 60 * 60 * 1000); // 24h

  std::ifstream t(this->config.matrix_config.server_key_location);
  std::string server_key((std::istreambuf_iterator<char>(t)),
                         std::istreambuf_iterator<char>());
  std::istringstream buffer(server_key);
  std::vector<std::string> splitted_data{
      std::istream_iterator<std::string>(buffer),
      std::istream_iterator<std::string>()};

  auto private_key = json_utils::unbase64_key(splitted_data[2]);
  std::vector<unsigned char> public_key(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(public_key.data(), private_key.data());
  auto public_key_base64 = json_utils::base64_key(public_key);

  server_server_json::keys keys = {
      .server_name = server_name,
      .valid_until_ts = tomorrow,
      .old_verify_keys = {},
      .verify_keys = {{std::format("{}:{}", splitted_data[0], splitted_data[1]),
                       {.key = public_key_base64}}},
  };
  json j = keys;
  json signed_j =
      json_utils::sign_json(server_name, splitted_data[1], private_key, j);
  res.set_content(signed_j.dump(), "application/json");
}

void Webserver::start() {
  std::cout << "Listening on 8080\n";
  this->svr.listen("localhost", 8080);
}