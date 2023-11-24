#pragma once

/// @file
/// @brief The Configuration of the application.
/// This allows to have a nice structure as a struct instead of using brackets.

#include "yaml-cpp/yaml.h"
#include <filesystem>
#include <string>

struct DBConfig {
  std::string url;
  std::size_t pool_size;
};

struct MatrixConfig {
  std::string server_name;
  std::filesystem::path server_key_location;
};

struct Config {
  DBConfig db_config;
  MatrixConfig matrix_config;

  Config();

private:
  void load_db(YAML::Node config);
  void load_matrix(YAML::Node config);
};