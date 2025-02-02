#pragma once
#include "string"
#include <exception>
#include <utility>

/**
 * @brief Constructs a new Config object.
 *
 * This constructor loads the configurations from a YAML file named
 * "config.yaml". It calls the load_db, load_matrix, and load_webserver methods
 * to load the respective configurations.
 *
 * @note The [[nodiscard]] attribute indicates that the compiler will warn if
 * the return value is discarded.
 */
class MatrixRoomVersionError final : public std::exception {
private:
  std::string _room_version;

public:
  /**
   * @brief Constructs a new MatrixRoomVersionError object.
   *
   * This constructor initializes the MatrixRoomVersionError object with the
   * unsupported room version.
   *
   * @param room_version The unsupported Matrix room version.
   */
  explicit MatrixRoomVersionError(std::string room_version)
      : _room_version(std::move(room_version)) {}

  /**
   * @brief Returns a pointer to the error message string.
   *
   * This method overrides the "what" method of the standard exception class. It
   * returns a pointer to a string that describes the error ("Unsupported room
   * version").
   *
   * @return A pointer to the error message string.
   */
  [[nodiscard]] const char *what() const noexcept override {
    return "Unsupported room version";
  }
};

/**
 * @brief Exception class for configuration errors.
 *
 * This class represents an error that occurs when there is a problem with the
 * configuration. It inherits from the standard exception class.
 */
class ConfigError final : public std::exception {
private:
  std::string _message; ///< The error message.

public:
  /**
   * @brief Constructs a new ConfigError object.
   *
   * This constructor initializes the ConfigError object with the provided error
   * message.
   *
   * @param message The error message.
   */
  explicit ConfigError(std::string message) : _message(std::move(message)) {}

  /**
   * @brief Returns a pointer to the error message string.
   *
   * This method overrides the "what" method of the standard exception class. It
   * returns a pointer to a string that describes the error.
   *
   * @return A pointer to the error message string.
   */
  [[nodiscard]] const char *what() const noexcept override {
    return _message.c_str();
  }
};