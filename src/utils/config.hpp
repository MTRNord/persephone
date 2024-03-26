#pragma once

/// @file
/// @brief The Configuration of the application.
/// This allows to have a nice structure as a struct instead of using brackets.

#include "drogon/drogon.h"
#include "yaml-cpp/yaml.h"
#include <cstddef>
#include <filesystem>
#include <string>

struct [[nodiscard]] DBConfig {
  std::string host;
  std::string database_name;
  std::string user;
  std::string password;
  unsigned short port;
};

struct [[nodiscard]] WebserverConfig {
  bool ssl;
};

struct [[nodiscard]] MatrixConfig {
  std::string server_name;
  std::filesystem::path server_key_location;
};

struct [[nodiscard]] Config {
  DBConfig db_config;
  MatrixConfig matrix_config;
  WebserverConfig webserver_config;

  explicit Config() {
    LOG_INFO << "Loading config file";
    YAML::Node config = YAML::LoadFile("config.yaml");
    this->load_db(config);
    this->load_matrix(config);
    this->load_webserver(config);
  }

private:
  void load_db(const YAML::Node &config);
  void load_matrix(const YAML::Node &config);
  void load_webserver(const YAML::Node &config);
};
