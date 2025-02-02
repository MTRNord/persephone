#include <fstream>
#include <snitch/snitch.hpp>
#include <utils/config.hpp>
#include <utils/errors.hpp>
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

  SECTION("Fails if the matrix server_name value is too long") {
    const auto *const config_file = R"(
---
database:
  host: localhost
  port: 5432
  database_name: postgres
  user: postgres
  password: mysecretpassword
matrix:
  server_name: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
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
    REQUIRE_THROWS_MATCHES(Config{}, ConfigError,
                           snitch::matchers::with_what_contains{
                               "The server_name is too long. The server_name "
                               "should be less than 250 "
                               "characters."});

    try {
      const Config config{};
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
    } catch (const ConfigError &e) {
      // No-op
    }
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
    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing 'database' field. Unable to start. Make sure you set the "
            "database configuration."});

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
    } catch (const ConfigError &e) {
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
    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing 'matrix' field. Unable to start. Make sure you set the "
            "Matrix configuration."});

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
    } catch (const ConfigError &e) {
      // No-op
    }
  }

  SECTION("Missing webserver section") {
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
rabbitmq:
  host: localhost
  port: 5672
  )";

    // Write file to disk for testing
    std::ofstream file("config.yaml");
    file << config_file;
    file.close();

    // Check that the config was loaded with default values of the webserver
    Config const config{};

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

  SECTION("Missing rabbitmq section") {
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
  )";

    // Write file to disk for testing
    std::ofstream file("config.yaml");
    file << config_file;
    file.close();

    // Test loading the config
    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing 'rabbitmq' field. Unable to start. Make sure you set the "
            "RabbitMQ configuration."});

    // Check that no config was loaded into the struct except for the
    // rabbitmq
    try {
      Config const config{};

      REQUIRE(config.db_config.host == "localhost");
      REQUIRE(config.db_config.port == 5432);
      REQUIRE(config.db_config.database_name == "postgres");
      REQUIRE(config.db_config.user == "postgres");
      REQUIRE(config.db_config.password == "mysecretpassword");

      REQUIRE(config.matrix_config.server_name == "localhost");
      REQUIRE(config.matrix_config.server_key_location == "./server_key.key");

      REQUIRE(config.webserver_config.ssl == false);

      REQUIRE(config.rabbitmq_config.host.empty());
      REQUIRE(config.rabbitmq_config.port == 0);
      REQUIRE(!config.rabbitmq_config.user.has_value());
      REQUIRE(!config.rabbitmq_config.password.has_value());
    } catch (const ConfigError &e) {
      // No-op
    }
  }

  SECTION("Fail when config file is missing") {
    // Ensure the config file does not exist
    std::remove("config.yaml");

    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing or invalid config.yaml file. Make sure to "
            "create it prior to running persephone"});
  }
}