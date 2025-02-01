#include "utils/config.hpp"
#include "yaml-cpp/yaml.h"
#include <stdexcept>
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
 * @throws std::runtime_error If the password, host, database name, or user is
 * not defined in the YAML node.
 */
void Config::load_db(const YAML::Node &config) {
  db_config.host = config["database"]["host"].as<std::string>();
  // Default to 5432 if not provided
  db_config.port =
      config["database"]["port"].as<unsigned short>(DEFAULT_POSTGRES_PORT);
  db_config.database_name =
      config["database"]["database_name"].as<std::string>();
  db_config.user = config["database"]["user"].as<std::string>();
  if (!config["database"]["password"].IsDefined()) {
    throw std::runtime_error(
        "Missing 'database.password' field. Unable "
        "to start. Make sure you set the database password.");
  }
  db_config.password = config["database"]["password"].as<std::string>();

  if (db_config.host.empty()) {
    throw std::runtime_error(
        "Missing 'database.host' field. Unable to start. Make sure you set "
        "the database host for postgres.");
  }

  if (db_config.database_name.empty()) {
    throw std::runtime_error("Missing 'database.database_name' field. Unable "
                             "to start. Make sure you set the database name.");
  }

  if (db_config.user.empty()) {
    throw std::runtime_error("Missing 'database.user' field. Unable "
                             "to start. Make sure you set the database user.");
  }
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
 * @throws std::runtime_error If the server name or server key location is not
 * defined in the YAML node.
 */
void Config::load_matrix(const YAML::Node &config) {
  matrix_config.server_name = config["matrix"]["server_name"].as<std::string>();
  matrix_config.server_key_location =
      config["matrix"]["server_key_location"].as<std::string>();

  if (matrix_config.server_name.empty()) {
    throw std::runtime_error(
        "Missing 'matrix.server_name'. Unable to start. Make sure you set "
        "the server_name of the homeserver. This usually is a domain WITHOUT "
        "the matrix subdomain. It is used in the user id.");
  }

  if (matrix_config.server_key_location.empty()) {
    throw std::runtime_error(
        "Missing 'matrix.server_key_location'. Unable to start. Make sure you "
        "set the location where the server key should be stored. This should "
        "be an absolute path to a file.");
  }
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
  if (config["webserver"]["ssl"]) {
    this->webserver_config.ssl = config["webserver"]["ssl"].as<bool>();
  } else {
    this->webserver_config.ssl = false;
  }
}

void Config::load_rabbitmq(const YAML::Node &config) {
  if (!config["rabbitmq"].IsDefined()) {
    throw std::runtime_error(
        "Missing 'rabbitmq' field. Unable to start. Make sure you set the "
        "RabbitMQ configuration.");
  }
  if (!config["rabbitmq"]["host"].IsDefined()) {
    throw std::runtime_error(
        "Missing 'rabbitmq.host' field. Unable to start. Make sure you set "
        "the RabbitMQ host.");
  }
  rabbitmq_config.host = config["rabbitmq"]["host"].as<std::string>();
  if (!config["rabbitmq"]["port"].IsDefined()) {
    throw std::runtime_error(
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