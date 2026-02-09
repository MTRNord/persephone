#pragma once

/// @file
/// @brief The Configuration of the application.
/// This allows to have a nice structure as a struct instead of using brackets.

#include "errors.hpp"

#include "yaml-cpp/yaml.h"
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <trantor/utils/Logger.h>
#include <yaml-cpp/node/node.h>

/**
 * @brief A struct representing the database configuration.
 *
 * This struct holds the configuration for the database connection. It includes
 * the host, database name, user, password, and port. The host, database name,
 * user, and password are represented as strings, while the port is an unsigned
 * short.
 *
 * @note The [[nodiscard]] attribute indicates that the compiler will warn if
 * the return value is discarded.
 */
struct [[nodiscard]] DBConfig {
  std::string host;
  std::string database_name;
  std::string user;
  std::string password;
  unsigned short port{};
  std::optional<int>
      pool_size; // Connection pool size (defaults to max(4, num_cores))
};

/**
 * @brief A struct representing the webserver configuration.
 *
 * This struct holds the configuration for the webserver. It includes the SSL
 * setting and port configuration. The SSL setting is represented as a boolean.
 * If true, SSL is enabled for the webserver. If false, SSL is disabled.
 *
 * @note The [[nodiscard]] attribute indicates that the compiler will warn if
 * the return value is discarded.
 */
struct [[nodiscard]] WebserverConfig {
  bool ssl;
  unsigned short port{8008};            // Client-Server API port
  unsigned short federation_port{8448}; // Server-Server API (federation) port
  std::string bind_host{"0.0.0.0"};     // Address to bind to
};

/**
 * @brief A struct representing the Matrix configuration.
 *
 * This struct holds the configuration for the Matrix server. It includes the
 * server name and the server key location. The server name is represented as a
 * string, and the server key location is represented as a filesystem path.
 *
 * @note The [[nodiscard]] attribute indicates that the compiler will warn if
 * the return value is discarded.
 */
struct [[nodiscard]] MatrixConfig {
  std::string server_name;
  std::filesystem::path server_key_location;
};

/**
 * @brief A struct representing the overall configuration.
 *
 * This struct holds the configurations for the database, Matrix server, and
 * webserver. It includes a DBConfig object, a MatrixConfig object, and a
 * WebserverConfig object. The constructor for this struct loads the
 * configurations from a YAML file.
 *
 * @note The [[nodiscard]] attribute indicates that the compiler will warn if
 * the return value is discarded.
 * @throws ConfigError if the config file is missing or invalid.
 */
struct [[nodiscard]] Config {
  DBConfig db_config{}; // NOLINT(*-non-private-member-variables-in-classes)
  MatrixConfig
      matrix_config{}; // NOLINT(*-non-private-member-variables-in-classes)
  WebserverConfig
      webserver_config{}; // NOLINT(*-non-private-member-variables-in-classes)

  std::string log_level;

  /**
   * @brief Constructs a new Config object.
   *
   * This constructor loads the configurations from a YAML file named
   * "config.yaml". It calls the load_db, load_matrix, and load_webserver
   * methods to load the respective configurations.
   *
   * @note The [[nodiscard]] attribute indicates that the compiler will warn if
   * the return value is discarded.
   */
  [[nodiscard]] explicit Config() {
    LOG_INFO << "Loading config file\n";

    // Check if the "PERSEPHONE_CONFIG" environment variable is set and use that
    // as path if it is set
    const char *raw_env_var = std::getenv("PERSEPHONE_CONFIG");
    const std::string env_var = raw_env_var == nullptr ? "" : raw_env_var;
    const std::string path = env_var.empty() ? "./config.yaml" : env_var;

    if (!std::filesystem::exists(path)) {
      throw ConfigError(
          "Missing or invalid config.yaml file at \"" + path +
          "\". Make sure to create it prior to running persephone");
    }

    const YAML::Node config = YAML::LoadFile(path);
    LOG_INFO << "Config file loaded\n";
    LOG_INFO << "Loading log_level configuration\n";
    if (config["log_level"].IsDefined()) {
      log_level = config["log_level"].as<std::string>();
    } else {
      log_level = "info";
    }
    LOG_INFO << "Loading database configuration\n";
    this->load_db(config);
    LOG_INFO << "Database configuration loaded\n";
    LOG_INFO << "Loading Matrix configuration\n";
    this->load_matrix(config);
    LOG_INFO << "Matrix configuration loaded\n";
    LOG_INFO << "Loading webserver configuration\n";
    this->load_webserver(config);
    LOG_INFO << "Webserver configuration loaded\n";
  }

private:
  void load_db(const YAML::Node &config);

  void load_matrix(const YAML::Node &config);

  void load_webserver(const YAML::Node &config);
};
