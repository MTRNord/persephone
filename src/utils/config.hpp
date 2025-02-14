#pragma once

/// @file
/// @brief The Configuration of the application.
/// This allows to have a nice structure as a struct instead of using brackets.

#include "errors.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <trantor/utils/Logger.h>
#include <yaml-cpp/node/node.h>
#include <yaml-cpp/node/parse.h>

struct [[nodiscard]] RabbitMQConfig {
  std::string host;
  std::optional<std::string> user;
  std::optional<std::string> password;
  unsigned short port{};

  [[nodiscard]] constexpr std::string get_rabbitmq_url() const {
    if (user.has_value() && password.has_value()) {
      return "amqp://" + user.value() + ":" + password.value() + "@" + host +
             ":" + std::to_string(port);
    }
    return "amqp://" + host + ":" + std::to_string(port);
  }
};

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
};

/**
 * @brief A struct representing the webserver configuration.
 *
 * This struct holds the configuration for the webserver. It includes the SSL
 * setting. The SSL setting is represented as a boolean. If true, SSL is enabled
 * for the webserver. If false, SSL is disabled.
 *
 * @note The [[nodiscard]] attribute indicates that the compiler will warn if
 * the return value is discarded.
 */
struct [[nodiscard]] WebserverConfig {
  bool ssl;
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
  RabbitMQConfig
      rabbitmq_config{}; // NOLINT(*-non-private-member-variables-in-classes)

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
    LOG_INFO << "Loading config file";
    auto constexpr path = "./config.yaml";
    if (!std::filesystem::exists(path)) {
      throw ConfigError("Missing or invalid config.yaml file. Make sure "
                        "to create it prior to running persephone");
    }

    const YAML::Node config = YAML::LoadFile(path);
    LOG_DEBUG << "Config file loaded";
    LOG_DEBUG << "Loading log_level configuration";
    if (config["log_level"].IsDefined()) {
      log_level = config["log_level"].as<std::string>();
    } else {
      log_level = "info";
    }
    LOG_DEBUG << "Loading database configuration";
    this->load_db(config);
    LOG_DEBUG << "Database configuration loaded";
    LOG_DEBUG << "Loading Matrix configuration";
    this->load_matrix(config);
    LOG_DEBUG << "Matrix configuration loaded";
    LOG_DEBUG << "Loading webserver configuration";
    this->load_webserver(config);
    LOG_DEBUG << "Webserver configuration loaded";
    LOG_DEBUG << "Loading RabbitMQ configuration";
    this->load_rabbitmq(config);
    LOG_DEBUG << "RabbitMQ configuration loaded";
  }

private:
  void load_db(const YAML::Node &config);

  void load_matrix(const YAML::Node &config);

  void load_webserver(const YAML::Node &config);

  void load_rabbitmq(const YAML::Node &config);
};
