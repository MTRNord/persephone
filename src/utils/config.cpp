#include "utils/config.hpp"
#include "drogon/drogon.h"
#include "yaml-cpp/node/impl.h"
#include "yaml-cpp/node/node.h"
#include "yaml-cpp/node/parse.h"
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <stdexcept>

Config::Config() {
  LOG_INFO << "Loading config file";
  YAML::Node config = YAML::LoadFile("config.yaml");
  this->load_db(config);
  this->load_matrix(config);
  this->load_webserver(config);
}

void Config::load_db(const YAML::Node &config) {
  db_config.host = config["database"]["host"].as<std::string>();
  // Default to 5432 if not provided
  db_config.port = config["database"]["port"].as<unsigned short>(
      static_cast<unsigned short>(5432));
  db_config.database_name =
      config["database"]["database_name"].as<std::string>();
  db_config.user = config["database"]["user"].as<std::string>();
  if (!config["database"].contains("password")) {
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

void Config::load_webserver(const YAML::Node &config) {
  if (config["webserver"]["ssl"]) {
    this->webserver_config.ssl = config["webserver"]["ssl"].as<bool>();
  } else {
    this->webserver_config.ssl = false;
  }
}
