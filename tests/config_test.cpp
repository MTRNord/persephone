#include <fstream>
#include <snitch/snitch.hpp>
#include <utils/config.hpp>
TEST_CASE("Loading Config", "[config]") {
  SECTION("Loads valid config file") {
    const auto *const config_file = R"(
---
database:
  host: localhost
  port: 5432
  database_name: postgres
  user: postgres
  password: mysecretpassword
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
webserver:
  ssl: false
rabbitmq:
  host: localhost
  port: 5672
  )";

    // Write file to disk for testing
    std::ofstream file("config.yaml");
    file << config_file;
    file.close();

    // Test loading the config
    const Config config{};

    REQUIRE(config.db_config.host == "localhost");
    REQUIRE(config.db_config.port == 5432);
    REQUIRE(config.db_config.database_name == "postgres");
    REQUIRE(config.db_config.user == "postgres");
    REQUIRE(config.db_config.password == "mysecretpassword");

    REQUIRE(config.matrix_config.server_name == "localhost");
    REQUIRE(config.matrix_config.server_key_location == "./server_key.key");

    REQUIRE(config.webserver_config.ssl == false);

    REQUIRE(config.rabbitmq_config.host == "localhost");
    REQUIRE(config.rabbitmq_config.port == 5672);
    REQUIRE(!config.rabbitmq_config.user.has_value());
    REQUIRE(!config.rabbitmq_config.password.has_value());
  }

  SECTION("Missing database section") {
    const auto *const config_file = R"(
---
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
webserver:
  ssl: false
rabbitmq:
  host: localhost
  port: 5672
  )";

    // Write file to disk for testing
    std::ofstream file("config.yaml");
    file << config_file;
    file.close();

    // Test loading the config
    REQUIRE_THROWS_AS(Config{}, std::runtime_error);

    // Check that no config was loaded into the struct
    try {
      Config const config{};

      REQUIRE(config.db_config.host.empty());
      REQUIRE(config.db_config.port == 0);
      REQUIRE(config.db_config.database_name.empty());
      REQUIRE(config.db_config.user.empty());
      REQUIRE(config.db_config.password.empty());

      REQUIRE(config.matrix_config.server_name.empty());
      REQUIRE(config.matrix_config.server_key_location.empty());

      REQUIRE(config.webserver_config.ssl == false);

      REQUIRE(config.rabbitmq_config.host.empty());
      REQUIRE(config.rabbitmq_config.port == 0);
      REQUIRE(!config.rabbitmq_config.user.has_value());
      REQUIRE(!config.rabbitmq_config.password.has_value());
    } catch (const std::runtime_error &e) {
      // No-op
    }
  }

  SECTION("Missing matrix section") {
    const auto *const config_file = R"(
---
database:
  host: localhost
  port: 5432
  database_name: postgres
  user: postgres
  password: mysecretpassword
webserver:
  ssl: false
rabbitmq:
  host: localhost
  port: 5672
  )";

    // Write file to disk for testing
    std::ofstream file("config.yaml");
    file << config_file;
    file.close();

    // Test loading the config
    REQUIRE_THROWS_AS(Config{}, std::runtime_error);

    // Check that no config was loaded into the struct except for the database
    try {
      Config const config{};

      REQUIRE(config.db_config.host == "localhost");
      REQUIRE(config.db_config.port == 5432);
      REQUIRE(config.db_config.database_name == "postgres");
      REQUIRE(config.db_config.user == "postgres");
      REQUIRE(config.db_config.password == "mysecretpassword");

      REQUIRE(config.matrix_config.server_name.empty());
      REQUIRE(config.matrix_config.server_key_location.empty());

      REQUIRE(config.webserver_config.ssl == false);

      REQUIRE(config.rabbitmq_config.host.empty());
      REQUIRE(config.rabbitmq_config.port == 0);
      REQUIRE(!config.rabbitmq_config.user.has_value());
      REQUIRE(!config.rabbitmq_config.password.has_value());
    } catch (const std::runtime_error &e) {
      // No-op
    }
  }
}