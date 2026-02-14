/// Integration tests using Drogon's test framework.
/// Requires PostgreSQL (ENABLE_INTEGRATION_TESTS=ON).
/// Set PERSEPHONE_TEST_DB_HOST, PERSEPHONE_TEST_DB_PORT, PERSEPHONE_TEST_DB_USER,
/// PERSEPHONE_TEST_DB_PASSWORD, PERSEPHONE_TEST_DB_NAME environment variables.

#include <future>
#define DROGON_TEST_MAIN
#include "database/database.hpp"
#include "test_helpers.hpp"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/client_server_api/ClientServerCtrl.hpp"
#include "webserver/server_server_api/ServerServerCtrl.hpp"
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpClient.h>
#include <drogon/HttpRequest.h>
#include <drogon/drogon_test.h>
#include <drogon/orm/DbConfig.h>
#include <drogon/utils/coroutine.h>
#include <sodium/core.h>
#include <string_view>
#include <thread>

using namespace drogon;
using namespace std::string_view_literals;

static constexpr uint16_t TEST_PORT = 18008;

// ============================================================================
// Unauthenticated endpoints
// ============================================================================

DROGON_TEST(VersionsEndpoint) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);
    auto req = HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/_matrix/client/versions");

    auto resp = co_await client->sendRequestCoro(req, 10);
    CO_REQUIRE(resp->statusCode() == k200OK);

    auto body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(body.contains("versions"));
    CO_REQUIRE(body["versions"].is_array());
    CO_REQUIRE(body["versions"].size() > 0);
    co_return;
  };
  drogon::sync_wait(test_coro());
}

DROGON_TEST(LoginGetEndpoint) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);
    auto req = HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/_matrix/client/v3/login");

    auto resp = co_await client->sendRequestCoro(req, 10);
    CO_REQUIRE(resp->statusCode() == k200OK);

    auto body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(body.contains("flows"));
    CO_REQUIRE(body["flows"].is_array());
    co_return;
  };
  drogon::sync_wait(test_coro());
}

// ============================================================================
// Registration
// ============================================================================

DROGON_TEST(RegisterUser) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);
    auto req = HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setPath("/_matrix/client/v3/register");
    req->setContentTypeString("application/json");

    nlohmann::json body = {{"username", "integrationtestuser"},
                           {"password", "testpassword123"},
                           {"auth", {{"type", "m.login.dummy"}}}};
    req->setBody(body.dump());

    auto resp = co_await client->sendRequestCoro(req, 10);
    CO_REQUIRE(resp->statusCode() == k200OK);

    auto resp_body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(resp_body.contains("user_id"));
    CO_REQUIRE(resp_body.contains("access_token"));
    CO_REQUIRE(resp_body.contains("device_id"));
    CO_REQUIRE(resp_body["user_id"] == "@integrationtestuser:localhost");
    co_return;
  };
  drogon::sync_wait(test_coro());
}

DROGON_TEST(RegisterDuplicateUser) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);

    // First registration
    auto req1 = HttpRequest::newHttpRequest();
    req1->setMethod(drogon::Post);
    req1->setPath("/_matrix/client/v3/register");
    req1->setContentTypeString("application/json");
    nlohmann::json body1 = {{"username", "dupuser"},
                            {"password", "pass123"},
                            {"auth", {{"type", "m.login.dummy"}}}};
    req1->setBody(body1.dump());
    co_await client->sendRequestCoro(req1, 10);

    // Second registration with same username
    auto req2 = HttpRequest::newHttpRequest();
    req2->setMethod(drogon::Post);
    req2->setPath("/_matrix/client/v3/register");
    req2->setContentTypeString("application/json");
    nlohmann::json body2 = {{"username", "dupuser"},
                            {"password", "pass456"},
                            {"auth", {{"type", "m.login.dummy"}}}};
    req2->setBody(body2.dump());

    auto resp2 = co_await client->sendRequestCoro(req2, 10);
    CO_REQUIRE(resp2->statusCode() == k400BadRequest);

    auto resp_body = nlohmann::json::parse(resp2->body());
    CO_REQUIRE(resp_body["errcode"] == "M_USER_IN_USE");
    co_return;
  };
  drogon::sync_wait(test_coro());
}

// ============================================================================
// Login
// ============================================================================

DROGON_TEST(LoginWithPassword) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);

    // Register first
    auto reg_req = HttpRequest::newHttpRequest();
    reg_req->setMethod(drogon::Post);
    reg_req->setPath("/_matrix/client/v3/register");
    reg_req->setContentTypeString("application/json");
    nlohmann::json reg_body = {{"username", "loginuser"},
                               {"password", "loginpass"},
                               {"auth", {{"type", "m.login.dummy"}}}};
    reg_req->setBody(reg_body.dump());
    co_await client->sendRequestCoro(reg_req, 10);

    // Login
    auto login_req = HttpRequest::newHttpRequest();
    login_req->setMethod(drogon::Post);
    login_req->setPath("/_matrix/client/v3/login");
    login_req->setContentTypeString("application/json");
    nlohmann::json login_body = {
        {"type", "m.login.password"},
        {"identifier", {{"type", "m.id.user"}, {"user", "loginuser"}}},
        {"password", "loginpass"}};
    login_req->setBody(login_body.dump());

    auto resp = co_await client->sendRequestCoro(login_req, 10);
    CO_REQUIRE(resp->statusCode() == k200OK);

    auto resp_body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(resp_body.contains("access_token"));
    CO_REQUIRE(resp_body.contains("user_id"));
    CO_REQUIRE(resp_body["user_id"] == "@loginuser:localhost");
    co_return;
  };
  drogon::sync_wait(test_coro());
}

DROGON_TEST(LoginWrongPassword) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);

    // Register first
    auto reg_req = HttpRequest::newHttpRequest();
    reg_req->setMethod(drogon::Post);
    reg_req->setPath("/_matrix/client/v3/register");
    reg_req->setContentTypeString("application/json");
    nlohmann::json reg_body = {{"username", "wrongpassuser"},
                               {"password", "correctpass"},
                               {"auth", {{"type", "m.login.dummy"}}}};
    reg_req->setBody(reg_body.dump());
    co_await client->sendRequestCoro(reg_req, 10);

    // Login with wrong password
    auto login_req = HttpRequest::newHttpRequest();
    login_req->setMethod(drogon::Post);
    login_req->setPath("/_matrix/client/v3/login");
    login_req->setContentTypeString("application/json");
    nlohmann::json login_body = {
        {"type", "m.login.password"},
        {"identifier", {{"type", "m.id.user"}, {"user", "wrongpassuser"}}},
        {"password", "wrongpass"}};
    login_req->setBody(login_body.dump());

    auto resp = co_await client->sendRequestCoro(login_req, 10);
    CO_REQUIRE(resp->statusCode() == k403Forbidden);

    auto resp_body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(resp_body["errcode"] == "M_FORBIDDEN");
    co_return;
  };
  drogon::sync_wait(test_coro());
}

// ============================================================================
// Authenticated endpoints
// ============================================================================

DROGON_TEST(WhoamiWithValidToken) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);

    // Register and get token
    auto result = co_await test_helpers::register_test_user(
        client, "whoamiuser");

    auto req = test_helpers::make_authenticated_request(
        drogon::Get, "/_matrix/client/v3/account/whoami",
        result.access_token);

    auto resp = co_await client->sendRequestCoro(req, 10);
    CO_REQUIRE(resp->statusCode() == k200OK);

    auto body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(body["user_id"] == "@whoamiuser:localhost");
    co_return;
  };
  drogon::sync_wait(test_coro());
}

DROGON_TEST(WhoamiWithoutToken) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);
    auto req = HttpRequest::newHttpRequest();
    req->setMethod(drogon::Get);
    req->setPath("/_matrix/client/v3/account/whoami");

    auto resp = co_await client->sendRequestCoro(req, 10);
    CO_REQUIRE(resp->statusCode() == k401Unauthorized);

    auto body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(body["errcode"] == "M_MISSING_TOKEN");
    co_return;
  };
  drogon::sync_wait(test_coro());
}

DROGON_TEST(WhoamiWithBadToken) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);
    auto req = test_helpers::make_authenticated_request(
        drogon::Get, "/_matrix/client/v3/account/whoami",
        "invalid_token_12345");

    auto resp = co_await client->sendRequestCoro(req, 10);
    CO_REQUIRE(resp->statusCode() == k401Unauthorized);

    auto body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(body["errcode"] == "M_UNKNOWN_TOKEN");
    co_return;
  };
  drogon::sync_wait(test_coro());
}

// ============================================================================
// Room creation
// ============================================================================

DROGON_TEST(CreateRoom) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);
    auto result = co_await test_helpers::register_test_user(
        client, "roomcreator");

    auto req = test_helpers::make_authenticated_request(
        drogon::Post, "/_matrix/client/v3/createRoom", result.access_token);
    req->setContentTypeString("application/json");
    nlohmann::json body = {{"name", "Test Room"}, {"preset", "private_chat"}};
    req->setBody(body.dump());

    auto resp = co_await client->sendRequestCoro(req, 10);
    CO_REQUIRE(resp->statusCode() == k200OK);

    auto resp_body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(resp_body.contains("room_id"));
    // Room ID should start with '!' and contain server name
    auto room_id = resp_body["room_id"].get<std::string>();
    CO_REQUIRE(room_id.starts_with("!"));
    CO_REQUIRE(room_id.find("localhost") != std::string::npos);
    co_return;
  };
  drogon::sync_wait(test_coro());
}

// ============================================================================
// Sync
// ============================================================================

DROGON_TEST(SyncBasic) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);
    auto result = co_await test_helpers::register_test_user(
        client, "syncuser");

    auto req = test_helpers::make_authenticated_request(
        drogon::Get, "/_matrix/client/v3/sync?timeout=0",
        result.access_token);

    auto resp = co_await client->sendRequestCoro(req, 15);
    CO_REQUIRE(resp->statusCode() == k200OK);

    auto body = nlohmann::json::parse(resp->body());
    CO_REQUIRE(body.contains("next_batch"));
    CO_REQUIRE(body.contains("rooms"));
    co_return;
  };
  drogon::sync_wait(test_coro());
}

// ============================================================================
// Filters
// ============================================================================

DROGON_TEST(SetAndGetFilter) {
  auto test_coro = [TEST_CTX]() -> drogon::Task<> {
    auto client = test_helpers::create_test_client(TEST_PORT);
    auto result = co_await test_helpers::register_test_user(
        client, "filteruser");

    // Set filter
    auto set_req = test_helpers::make_authenticated_request(
        drogon::Post,
        "/_matrix/client/v3/user/" + result.user_id + "/filter",
        result.access_token);
    set_req->setContentTypeString("application/json");
    nlohmann::json filter = {{"room", {{"timeline", {{"limit", 10}}}}}};
    set_req->setBody(filter.dump());

    auto set_resp = co_await client->sendRequestCoro(set_req, 10);
    CO_REQUIRE(set_resp->statusCode() == k200OK);

    auto set_body = nlohmann::json::parse(set_resp->body());
    CO_REQUIRE(set_body.contains("filter_id"));
    auto filter_id = set_body["filter_id"].get<std::string>();

    // Get filter
    auto get_req = test_helpers::make_authenticated_request(
        drogon::Get,
        "/_matrix/client/v3/user/" + result.user_id + "/filter/" + filter_id,
        result.access_token);

    auto get_resp = co_await client->sendRequestCoro(get_req, 10);
    CO_REQUIRE(get_resp->statusCode() == k200OK);

    auto get_body = nlohmann::json::parse(get_resp->body());
    CO_REQUIRE(get_body.contains("room"));
    co_return;
  };
  drogon::sync_wait(test_coro());
}

// ============================================================================
// Main: Start Drogon with test DB, register controllers, run tests
// ============================================================================

int main(int argc, char **argv) {
  // Check for test database config
  auto db_config = test_helpers::get_test_db_config();
  if (!db_config.has_value()) {
    LOG_ERROR << "PERSEPHONE_TEST_DB_HOST not set. Skipping integration tests.";
    return 0;
  }

  // Init libsodium
  if (sodium_init() < 0) {
    LOG_ERROR << "Failed to init libsodium";
    return 1;
  }

  // Write test config and initialize
  test_helpers::write_test_config(db_config.value());

  // Write a config.yaml for Config{} constructor
  {
    std::ofstream f("config.yaml");
    f << std::format(
        R"(---
database:
  host: "{}"
  port: {}
  database_name: "{}"
  user: "{}"
  password: "{}"
matrix:
  server_name: localhost
  server_key_location: ./test_server_key.key
webserver:
  ssl: false
  port: {}
log_level: "debug"
)",
        db_config->host, db_config->port, db_config->database, db_config->user,
        db_config->password, TEST_PORT);
    f.close();
  }

  const Config config{};
  json_utils::ensure_server_keys(config);
  auto verify_key_data = get_verify_key_data(config);

  // Configure Drogon
  app()
      .addListener("127.0.0.1", TEST_PORT)
      .setThreadNum(2)
      .setLogLevel(trantor::Logger::kWarn)
      .addDbClient(drogon::orm::PostgresConfig{
          .host = db_config->host,
          .port = db_config->port,
          .databaseName = db_config->database,
          .username = db_config->user,
          .password = db_config->password,
          .connectionNumber = 4,
          .name = "default",
          .isFast = false,
          .characterSet = "",
          .timeout = 30,
          .autoBatch = true,
          .connectOptions = {}})
      .registerBeginningAdvice([]() { Database::migrate(); });

  // Register controllers
  const auto client_ctrl =
      std::make_shared<client_server_api::ClientServerCtrl>(config);
  app().registerController(client_ctrl);

  // Start the main loop on another thread
  std::promise<void> p1;
  std::future<void> f1 = p1.get_future();

  std::thread thr([&]() {
    app().getLoop()->queueInLoop([&p1]() { p1.set_value(); });
    app().run();
  });

  // Wait for event loop to start
  f1.get();

  // Give the database a moment to connect and run migrations
  std::this_thread::sleep_for(std::chrono::seconds(2));

  int status = test::run(argc, argv);

  // Shutdown
  app().getLoop()->queueInLoop([]() { app().quit(); });
  thr.join();
  return status;
}
