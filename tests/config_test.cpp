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
  }

  SECTION("Loads config file with missing ssl settings") {
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
webserver: {}
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
    } catch (const ConfigError &e) {
      // No-op
    }

    const auto *const config_without_host = R"(
---
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
database:
  password: mysecretpassword
  database_name: postgres
  user: postgres
webserver:
  ssl: false
  )";

    // Write file to disk for testing
    std::ofstream file_config_without_host("config.yaml");
    file_config_without_host << config_without_host;
    file_config_without_host.close();

    // Test loading the config
    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing 'database.host' field. Unable to start. Make sure you set "
            "the database host for postgres."});

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
    } catch (const ConfigError &e) {
      // No-op
    }

    const auto *const config_without_password = R"(
---
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
database:
  host: woof
  database_name: postgres
  user: postgres
webserver:
  ssl: false
  )";

    // Write file to disk for testing
    std::ofstream file_config_without_password("config.yaml");
    file_config_without_password << config_without_password;
    file_config_without_password.close();

    // Test loading the config
    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing 'database.password' field. Unable "
            "to start. Make sure you set the database password."});

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
    } catch (const ConfigError &e) {
      // No-op
    }

    const auto *const config_without_database_name = R"(
---
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
database:
  host: woof
  password: postgres
  user: postgres
webserver:
  ssl: false
  )";

    // Write file to disk for testing
    std::ofstream file_config_without_database_name("config.yaml");
    file_config_without_database_name << config_without_database_name;
    file_config_without_database_name.close();

    // Test loading the config
    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing 'database.database_name' field. Unable "
            "to start. Make sure you set the database name."});

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
    } catch (const ConfigError &e) {
      // No-op
    }

    const auto *const config_without_user = R"(
---
matrix:
  server_name: localhost
  server_key_location: ./server_key.key
database:
  host: woof
  password: postgres
  database_name: postgres
webserver:
  ssl: false
  )";

    // Write file to disk for testing
    std::ofstream file_config_without_user("config.yaml");
    file_config_without_user << config_without_user;
    file_config_without_user.close();

    // Test loading the config
    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing 'database.user' field. Unable "
            "to start. Make sure you set the database user."});

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
    } catch (const ConfigError &e) {
      // No-op
    }

    const auto *const config_file_missing_server_name = R"(
---
database:
  host: localhost
  port: 5432
  database_name: postgres
  user: postgres
  password: mysecretpassword
matrix:
  server_key_location: ./server_key.key
webserver:
  ssl: false
  )";

    // Write file to disk for testing
    std::ofstream file_missing_server_name("config.yaml");
    file_missing_server_name << config_file_missing_server_name;
    file_missing_server_name.close();

    // Test loading the config
    REQUIRE_THROWS_MATCHES(
        Config{}, ConfigError,
        snitch::matchers::with_what_contains{
            "Missing 'matrix.server_name'. Unable to start. Make sure you set "
            "the server_name of the homeserver. This usually is a domain "
            "WITHOUT "
            "the matrix subdomain. It is used in the user id."});

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
    } catch (const ConfigError &e) {
      // No-op
    }

    const auto *const config_file_missing_server_key_location = R"(
---
database:
  host: localhost
  port: 5432
  database_name: postgres
  user: postgres
  password: mysecretpassword
matrix:
  server_name: localhost
webserver:
  ssl: false
  )";

    // Write file to disk for testing
    std::ofstream file_missing_server_key_location("config.yaml");
    file_missing_server_key_location << config_file_missing_server_key_location;
    file_missing_server_key_location.close();

    // Test loading the config
    REQUIRE_THROWS_MATCHES(Config{}, ConfigError,
                           snitch::matchers::with_what_contains{
                               "Missing 'matrix.server_key_location'. Unable "
                               "to start. Make sure you "
                               "set the location where the server key should "
                               "be stored. This should "
                               "be an absolute path to a file."});

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
  }
}
