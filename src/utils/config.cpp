#include "utils/config.hpp"

#include "errors.hpp"
#include "yaml-cpp/yaml.h"
#include <yaml-cpp/node/node.h>

static constexpr unsigned short DEFAULT_POSTGRES_PORT = 5432;

/**
 * @brief Loads the database configuration from a YAML node.
 *
 * This function takes a YAML node as input and extracts the database
 * configuration from it. The database configuration includes the host, port,
 * database name, user, and password. The port defaults to 5432 if not provided
 * in the YAML node. If the password, host, database name, or user is not
 * defined in the YAML node, it throws a runtime error.
 *
 * @param config The YAML node from which to load the database configuration.
 * @throws ConfigError If the password, host, database name, or user is
 * not defined in the YAML node.
 */
void Config::load_db(const YAML::Node &config) {
  if (!config["database"].IsDefined()) {
    throw ConfigError(
        "Missing 'database' field. Unable to start. Make sure you set the "
        "database configuration.");
  }

  if (!config["database"]["host"].IsDefined()) {
    throw ConfigError(
        "Missing 'database.host' field. Unable to start. Make sure you set "
        "the database host for postgres.");
  }

  if (!config["database"]["database_name"].IsDefined()) {
    throw ConfigError("Missing 'database.database_name' field. Unable "
                      "to start. Make sure you set the database name.");
  }

  if (!config["database"]["user"].IsDefined()) {
    throw ConfigError("Missing 'database.user' field. Unable "
                      "to start. Make sure you set the database user.");
  }
  if (!config["database"]["password"].IsDefined()) {
    throw ConfigError("Missing 'database.password' field. Unable "
                      "to start. Make sure you set the database password.");
  }
  db_config.host = config["database"]["host"].as<std::string>();
  // Default to 5432 if not provided
  db_config.port =
      config["database"]["port"].as<unsigned short>(DEFAULT_POSTGRES_PORT);
  db_config.database_name =
      config["database"]["database_name"].as<std::string>();
  db_config.user = config["database"]["user"].as<std::string>();
  db_config.password = config["database"]["password"].as<std::string>();
}

/**
 * @brief Loads the Matrix configuration from a YAML node.
 *
 * This function takes a YAML node as input and extracts the Matrix
 * configuration from it. The Matrix configuration includes the server name and
 * the server key location. If the server name or server key location is not
 * defined in the YAML node, it throws a runtime error.
 *
 * @param config The YAML node from which to load the Matrix configuration.
 * @throws ConfigError If the server name or server key location is not
 * defined in the YAML node.
 */
void Config::load_matrix(const YAML::Node &config) {
  if (!config["matrix"].IsDefined()) {
    throw ConfigError(
        "Missing 'matrix' field. Unable to start. Make sure you set the "
        "Matrix configuration.");
  }

  if (!config["matrix"]["server_name"].IsDefined()) {
    throw ConfigError(
        "Missing 'matrix.server_name'. Unable to start. Make sure you set "
        "the server_name of the homeserver. This usually is a domain WITHOUT "
        "the matrix subdomain. It is used in the user id.");
  }

  // This is a check to make sure we don't crash on weird room id or user id
  // stuff due to their size limits
  if (config["matrix"]["server_name"].as<std::string>().length() >= 250) {
    throw ConfigError(
        "The server_name is too long. The server_name should be less than 250 "
        "characters.");
  }

  // The code can never hit this which is fine. This is just to conform matrix
  // spec. We run into issues before that
  if (config["matrix"]["server_name"].as<std::string>().length() >= 255) {
    throw ConfigError(
        "The server_name is too long. The server_name should be less than 255 "
        "characters.");
  }

  if (!config["matrix"]["server_key_location"].IsDefined()) {
    throw ConfigError(
        "Missing 'matrix.server_key_location'. Unable to start. Make sure you "
        "set the location where the server key should be stored. This should "
        "be an absolute path to a file.");
  }

  matrix_config.server_name = config["matrix"]["server_name"].as<std::string>();
  matrix_config.server_key_location =
      config["matrix"]["server_key_location"].as<std::string>();
}

/**
 * @brief Loads the webserver configuration from a YAML node.
 *
 * This function takes a YAML node as input and extracts the webserver
 * configuration from it. The webserver configuration includes the SSL setting.
 * If the SSL setting is defined in the YAML node, it is set to the provided
 * value. If the SSL setting is not defined in the YAML node, it defaults to
 * false.
 *
 * @param config The YAML node from which to load the webserver configuration.
 */
void Config::load_webserver(const YAML::Node &config) {
  if (!config["webserver"].IsDefined()) {
    this->webserver_config.ssl = false;
    return;
  }

  if (config["webserver"]["ssl"]) {
    this->webserver_config.ssl = config["webserver"]["ssl"].as<bool>();
  } else {
    this->webserver_config.ssl = false;
  }
}

void Config::load_rabbitmq(const YAML::Node &config) {
  if (!config["rabbitmq"].IsDefined()) {
    throw ConfigError(
        "Missing 'rabbitmq' field. Unable to start. Make sure you set the "
        "RabbitMQ configuration.");
  }
  if (!config["rabbitmq"]["host"].IsDefined()) {
    throw ConfigError(
        "Missing 'rabbitmq.host' field. Unable to start. Make sure you set "
        "the RabbitMQ host.");
  }
  rabbitmq_config.host = config["rabbitmq"]["host"].as<std::string>();
  if (!config["rabbitmq"]["port"].IsDefined()) {
    throw ConfigError(
        "Missing 'rabbitmq.port' field. Unable to start. Make sure you set "
        "the RabbitMQ port.");
  }
  rabbitmq_config.port = config["rabbitmq"]["port"].as<unsigned short>();
  // Optional username password
  if (config["rabbitmq"]["username"].IsDefined()) {
    rabbitmq_config.user = config["rabbitmq"]["username"].as<std::string>();
  }
  if (config["rabbitmq"]["password"].IsDefined()) {
    rabbitmq_config.password = config["rabbitmq"]["password"].as<std::string>();
  }
}