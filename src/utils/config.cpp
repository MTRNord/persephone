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
}

void Config::load_db(YAML::Node config) {
  if (!config["database"]) {
    throw std::runtime_error("Missing 'database' section. Unable to start.");
  }
  if (!config["database"]["host"]) {
    throw std::runtime_error(
        "Missing 'database.host' field. Unable to start. Make sure you set "
        "the database host for postgres.");
  }
  this->db_config.host = config["database"]["host"].as<std::string>();

  if (!config["database"]["port"]) {
    throw std::runtime_error("'database.port' not set. Defaulting to port 5432 "
                             "for the database port.\n");
    this->db_config.port = 5432;
  } else {
    this->db_config.port = config["database"]["port"].as<unsigned short>();
  }

  if (!config["database"]["database_name"]) {
    throw std::runtime_error("Missing 'database.database_name' field. Unable "
                             "to start. Make sure you set the database name.");
  }
  this->db_config.database_name =
      config["database"]["database_name"].as<std::string>();

  if (!config["database"]["user"]) {
    throw std::runtime_error("Missing 'database.user' field. Unable "
                             "to start. Make sure you set the database user.");
  }
  this->db_config.user = config["database"]["user"].as<std::string>();

  if (!config["database"]["password"]) {
    throw std::runtime_error(
        "Missing 'database.password' field. Unable "
        "to start. Make sure you set the database password.");
  }
  this->db_config.password = config["database"]["password"].as<std::string>();
}

void Config::load_matrix(YAML::Node config) {
  if (!config["matrix"]) {
    throw std::runtime_error("Missing 'matrix' section. Unable to start.");
  }

  if (!config["matrix"]["server_name"]) {
    throw std::runtime_error(
        "Missing 'matrix.server_name'. Unable to start. Make sure you set "
        "the server_name of the homeserver. This usually is a domain WITHOUT "
        "the matrix subdomain. It is used in the user id.");
  }
  this->matrix_config.server_name =
      config["matrix"]["server_name"].as<std::string>();

  if (!config["matrix"]["server_key_location"]) {
    throw std::runtime_error(
        "Missing 'matrix.server_key_location'. Unable to start. Make sure you "
        "set the location where the server key should be stored. This should "
        "be an absolute path to a file.");
  }
  auto server_key_location =
      config["matrix"]["server_key_location"].as<std::string>();
  this->matrix_config.server_key_location = server_key_location;
}