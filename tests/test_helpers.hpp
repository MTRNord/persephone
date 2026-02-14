#pragma once

/// @file
/// @brief Shared test utilities for integration tests requiring PostgreSQL.

#include <cstdlib>
#include <drogon/HttpClient.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <fstream>
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#include "nlohmann/json.hpp"
#pragma GCC diagnostic pop
#else
#include <nlohmann/json.hpp>
#endif
#include <optional>
#include <string>

using json = nlohmann::json;

namespace test_helpers {

/// Database connection config from environment variables.
struct TestDbConfig {
  std::string host;
  uint16_t port;
  std::string user;
  std::string password;
  std::string database;
};

/// Get test database config from environment variables.
/// Returns nullopt if PERSEPHONE_TEST_DB_HOST is not set.
inline std::optional<TestDbConfig> get_test_db_config() {
  const char *host = std::getenv("PERSEPHONE_TEST_DB_HOST");
  if (host == nullptr) {
    return std::nullopt;
  }

  const char *port_str = std::getenv("PERSEPHONE_TEST_DB_PORT");
  const uint16_t port =
      port_str != nullptr ? static_cast<uint16_t>(std::stoi(port_str)) : 5432;

  const char *user = std::getenv("PERSEPHONE_TEST_DB_USER");
  const char *password = std::getenv("PERSEPHONE_TEST_DB_PASSWORD");
  const char *database = std::getenv("PERSEPHONE_TEST_DB_NAME");

  return TestDbConfig{
      .host = host,
      .port = port,
      .user = user != nullptr ? user : "postgres",
      .password = password != nullptr ? password : "",
      .database = database != nullptr ? database : "persephone_test",
  };
}

/// Write a config.yaml file for the test server pointing at the test database.
/// Returns the path to the written config file.
inline std::string
write_test_config(const TestDbConfig &db,
                  const std::string &server_name = "localhost",
                  uint16_t client_port = 0, uint16_t fed_port = 0) {
  // Use provided ports or default test ports
  const uint16_t cp = client_port != 0 ? client_port : 18008;
  const uint16_t fp = fed_port != 0 ? fed_port : 18448;

  const std::string config = std::format(
      R"(---
database:
  host: "{}"
  port: {}
  database_name: "{}"
  user: "{}"
  password: "{}"
matrix:
  server_name: "{}"
  server_key_location: ./test_server_key.key
webserver:
  ssl: false
  port: {}
  federation_port: {}
log_level: "debug"
)",
      db.host, db.port, db.database, db.user, db.password, server_name, cp,
      fp);

  const std::string path = "test_config.yaml";
  std::ofstream file(path);
  file << config;
  file.close();
  return path;
}

/// Create a Drogon HttpClient pointing at localhost on the given port.
inline drogon::HttpClientPtr create_test_client(uint16_t port) {
  const auto url = std::format("http://127.0.0.1:{}", port);
  return drogon::HttpClient::newHttpClient(url);
}

/// Register a test user via POST /_matrix/client/v3/register.
/// Returns {access_token, user_id, device_id} on success, or throws.
struct RegisterResult {
  std::string access_token;
  std::string user_id;
  std::string device_id;
};

inline drogon::Task<RegisterResult>
register_test_user(const drogon::HttpClientPtr &client,
                   const std::string &username,
                   const std::string &password = "testpassword") {
  auto req = drogon::HttpRequest::newHttpRequest();
  req->setMethod(drogon::Post);
  req->setPath("/_matrix/client/v3/register");
  req->setContentTypeString("application/json");

  json body = {{"username", username},
               {"password", password},
               {"auth", {{"type", "m.login.dummy"}}}};
  req->setBody(body.dump());

  auto resp = co_await client->sendRequestCoro(req, 10);
  if (resp->statusCode() != drogon::k200OK) {
    throw std::runtime_error(
        std::format("Registration failed: {} {}",
                    static_cast<int>(resp->statusCode()),
                    std::string(resp->body())));
  }

  auto resp_json = json::parse(resp->body());
  co_return RegisterResult{
      .access_token = resp_json["access_token"].get<std::string>(),
      .user_id = resp_json["user_id"].get<std::string>(),
      .device_id = resp_json["device_id"].get<std::string>(),
  };
}

/// Create an authenticated HTTP request with the given method, path, and token.
inline drogon::HttpRequestPtr
make_authenticated_request(drogon::HttpMethod method, const std::string &path,
                           const std::string &access_token) {
  auto req = drogon::HttpRequest::newHttpRequest();
  req->setMethod(method);
  req->setPath(path);
  req->addHeader("Authorization",
                 std::format("Bearer {}", access_token));
  return req;
}

} // namespace test_helpers
