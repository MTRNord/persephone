/// Database method tests.
/// Requires PostgreSQL (ENABLE_INTEGRATION_TESTS=ON).
/// Set PERSEPHONE_TEST_DB_HOST, PERSEPHONE_TEST_DB_PORT, PERSEPHONE_TEST_DB_USER,
/// PERSEPHONE_TEST_DB_PASSWORD, PERSEPHONE_TEST_DB_NAME environment variables.

#include "database/database.hpp"
#include "test_helpers.hpp"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include <chrono>
#include <drogon/HttpAppFramework.h>
#include <drogon/orm/DbConfig.h>
#include <drogon/utils/coroutine.h>
#include <snitch/snitch.hpp>
#include <sodium/core.h>
#include <thread>

using json = nlohmann::json;

// ============================================================================
// Test fixtures / helpers
// ============================================================================

/// Unique suffix for test isolation
static std::string unique_suffix() { return random_string(8); }

// ============================================================================
// User operations
// ============================================================================

TEST_CASE("Database::create_user and user_exists", "[database][user]") {
  auto test = []() -> drogon::Task<> {
    const auto suffix = unique_suffix();
    const auto matrix_id = "@dbtest_" + suffix + ":localhost";

    // User should not exist yet
    auto exists_before = co_await Database::user_exists(matrix_id);
    REQUIRE_FALSE(exists_before);

    // Create user
    auto result = co_await Database::create_user({
        .matrix_id = matrix_id,
        .device_id = std::nullopt,
        .device_name = "Test Device",
        .password = hash_password("testpassword"),
    });
    REQUIRE(!result.access_token.empty());
    REQUIRE(!result.device_id.empty());

    // User should exist now
    auto exists_after = co_await Database::user_exists(matrix_id);
    REQUIRE(exists_after);

    co_return;
  };
  drogon::sync_wait(test());
}

TEST_CASE("Database::validate_access_token", "[database][auth]") {
  auto test = []() -> drogon::Task<> {
    const auto suffix = unique_suffix();
    const auto matrix_id = "@valtoken_" + suffix + ":localhost";

    auto result = co_await Database::create_user({
        .matrix_id = matrix_id,
        .device_id = std::nullopt,
        .device_name = "Test",
        .password = hash_password("pass"),
    });

    // Valid token
    auto valid = co_await Database::validate_access_token(result.access_token);
    REQUIRE(valid);

    // Invalid token
    auto invalid = co_await Database::validate_access_token("bogus_token_xyz");
    REQUIRE_FALSE(invalid);

    co_return;
  };
  drogon::sync_wait(test());
}

TEST_CASE("Database::get_user_info", "[database][auth]") {
  auto test = []() -> drogon::Task<> {
    const auto suffix = unique_suffix();
    const auto matrix_id = "@userinfo_" + suffix + ":localhost";

    auto result = co_await Database::create_user({
        .matrix_id = matrix_id,
        .device_id = std::nullopt,
        .device_name = "Test",
        .password = hash_password("pass"),
    });

    auto info = co_await Database::get_user_info(result.access_token);
    REQUIRE(info.has_value());
    REQUIRE(info->user_id == matrix_id);
    REQUIRE(info->device_id.has_value());
    REQUIRE(info->device_id.value() == result.device_id);

    // Invalid token returns nullopt
    auto no_info = co_await Database::get_user_info("invalid_token");
    REQUIRE_FALSE(no_info.has_value());

    co_return;
  };
  drogon::sync_wait(test());
}

TEST_CASE("Database::login", "[database][auth]") {
  auto test = []() -> drogon::Task<> {
    const auto suffix = unique_suffix();
    const auto matrix_id = "@logintest_" + suffix + ":localhost";
    const auto password = "loginpassword";

    co_await Database::create_user({
        .matrix_id = matrix_id,
        .device_id = std::nullopt,
        .device_name = "Test",
        .password = hash_password(password),
    });

    // Successful login
    auto login_resp = co_await Database::login({
        .matrix_id = matrix_id,
        .password = password,
        .initial_device_name = "Login Device",
        .device_id = std::nullopt,
    });
    REQUIRE(!login_resp.access_token.empty());
    REQUIRE(login_resp.user_id == matrix_id);

    // Wrong password
    bool threw = false;
    try {
      co_await Database::login({
          .matrix_id = matrix_id,
          .password = "wrongpassword",
          .initial_device_name = std::nullopt,
          .device_id = std::nullopt,
      });
    } catch (const std::exception &) {
      threw = true;
    }
    REQUIRE(threw);

    co_return;
  };
  drogon::sync_wait(test());
}

// ============================================================================
// Filter operations
// ============================================================================

TEST_CASE("Database::set_filter and get_filter", "[database][filter]") {
  auto test = []() -> drogon::Task<> {
    const auto suffix = unique_suffix();
    const auto user_id = "@filtertest_" + suffix + ":localhost";

    // Create user first
    co_await Database::create_user({
        .matrix_id = user_id,
        .device_id = std::nullopt,
        .device_name = "Test",
        .password = hash_password("pass"),
    });

    json filter = {{"room", {{"timeline", {{"limit", 20}}}}}};

    auto filter_id = co_await Database::set_filter(user_id, filter);
    REQUIRE(filter_id.has_value());

    auto retrieved = co_await Database::get_filter(user_id, filter_id.value());
    REQUIRE(retrieved.contains("room"));
    REQUIRE(retrieved["room"]["timeline"]["limit"] == 20);

    co_return;
  };
  drogon::sync_wait(test());
}

// ============================================================================
// Server key caching
// ============================================================================

TEST_CASE("Database::cache_server_key and get_cached_server_key",
          "[database][federation]") {
  auto test = []() -> drogon::Task<> {
    const auto suffix = unique_suffix();
    const auto server_name = "test_" + suffix + ".example.com";
    const auto key_id = "ed25519:test_" + suffix;
    const auto public_key = "testpublickey" + suffix;
    const int64_t valid_until =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            (std::chrono::system_clock::now() + std::chrono::hours(24))
                .time_since_epoch())
            .count();

    // Should not exist yet
    auto before = co_await Database::get_cached_server_key(server_name, key_id);
    REQUIRE_FALSE(before.has_value());

    // Cache it
    co_await Database::cache_server_key(server_name, key_id, public_key,
                                        valid_until);

    // Should exist now
    auto after = co_await Database::get_cached_server_key(server_name, key_id);
    REQUIRE(after.has_value());
    REQUIRE(after->public_key == public_key);
    REQUIRE(after->valid_until_ts == valid_until);

    co_return;
  };
  drogon::sync_wait(test());
}

// ============================================================================
// Main: Set up Drogon with test DB, run migrations, then run snitch tests
// ============================================================================

int main(int argc, char *argv[]) {
  // Check for test database config
  auto db_config = test_helpers::get_test_db_config();
  if (!db_config.has_value()) {
    // NOLINTNEXTLINE(misc-include-cleaner)
    fprintf(stderr, "PERSEPHONE_TEST_DB_HOST not set. Skipping database "
                    "tests.\n");
    return 0;
  }

  // Init libsodium
  if (sodium_init() < 0) {
    fprintf(stderr, "Failed to init libsodium\n");
    return 1;
  }

  // Write config.yaml for Config{} constructor
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
log_level: "warn"
)",
        db_config->host, db_config->port, db_config->database, db_config->user,
        db_config->password);
    f.close();
  }

  const Config config{};
  json_utils::ensure_server_keys(config);

  // Configure Drogon (no HTTP listener needed, just DB)
  drogon::app()
      .setThreadNum(1)
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

  // Start the event loop
  std::promise<void> p1;
  std::future<void> f1 = p1.get_future();

  std::thread thr([&]() {
    drogon::app().getLoop()->queueInLoop([&p1]() { p1.set_value(); });
    drogon::app().run();
  });

  f1.get();

  // Wait for migrations
  std::this_thread::sleep_for(std::chrono::seconds(2));

  // Run snitch tests
  // snitch uses argc/argv automatically via its main
  snitch::cli::input const args(argc, argv);
  snitch::tests.configure(args);
  const bool success = snitch::tests.run_tests(args);

  // Shutdown
  drogon::app().getLoop()->queueInLoop([]() { drogon::app().quit(); });
  thr.join();

  return success ? 0 : 1;
}
