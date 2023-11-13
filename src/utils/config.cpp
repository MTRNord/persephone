#include "utils/config.hpp"
#include <iostream>

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
  ;
  if (!config["database"]["pool_size"]) {
    std::cout << "'database.pool_size' not set. defaulting to a size of 10 for "
                 "the database pool."
              << std::endl;
    this->db_config.pool_size = 10;
  } else {
    this->db_config.pool_size = config["database"]["pool_size"].as<size_t>();
    ;
  }
}

void Config::load_matrix(YAML::Node config) {
  if (!config["matrix"]) {
    throw std::runtime_error("Missing 'matrix' section. Unable to start.");
  }

  if (!config["matrix"]["server_name"]) {
    throw std::runtime_error(
        "Missing 'matrix.url' server_name. Unable to start. Make sure you set "
        "the server_name of the homeserver. This usually is a domain WITHOUT "
        "the matrix subdomain. It is used in the user id.");
  }
  this->matrix_config.server_name =
      config["matrix"]["server_name"].as<std::string>();
}