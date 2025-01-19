#pragma once
#include "string"
#include <exception>

/**
   * @brief Constructs a new Config object.
   *
   * This constructor loads the configurations from a YAML file named "config.yaml".
   * It calls the load_db, load_matrix, and load_webserver methods to load the respective configurations.
   *
   * @note The [[nodiscard]] attribute indicates that the compiler will warn if the return value is discarded.
 */
class MatrixRoomVersionError final : public std::exception {
private:
  std::string _room_version;

public:
  /**
   * @brief Constructs a new MatrixRoomVersionError object.
   *
   * This constructor initializes the MatrixRoomVersionError object with the unsupported room version.
   *
   * @param room_version The unsupported Matrix room version.
   */
  explicit MatrixRoomVersionError(std::string room_version)
    : _room_version(std::move(room_version)) {
  }

  /**
   * @brief Returns a pointer to the error message string.
   *
   * This method overrides the what method of the standard exception class. It returns a pointer to a string that
   * describes the error ("Unsupported room version").
   *
   * @return A pointer to the error message string.
   */
  [[nodiscard]] const char *what() const noexcept override {
    return "Unsupported room version";
  }
};
