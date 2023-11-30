#include "utils/config.hpp"
#include "yaml-cpp/node/impl.h"
#include "yaml-cpp/node/node.h"
#include "yaml-cpp/node/parse.h"
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <stdexcept>

Config::Config() {
  YAML::Node config = YAML::LoadFile("config.yaml");
  this->load_db(config);
  this->load_matrix(config);
}

void Config::load_db(YAML::Node config) {
  if (!config["database"]) {
    throw std::runtime_error("Missing 'database' section. Unable to start.");
  }
  if (!config["database"]["url"]) {
    throw std::runtime_error(
        "Missing 'database.url' section. Unable to start. Make sure you set "
        "the database url for postgres.");
  }
  this->db_config.url = config["database"]["url"].as<std::string>();

  if (!config["database"]["pool_size"]) {
    std::cout << "'database.pool_size' not set. defaulting to a size of 10 for "
                 "the database pool.\n";
    this->db_config.pool_size = 10;
  } else {
    this->db_config.pool_size = config["database"]["pool_size"].as<size_t>();
  }
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