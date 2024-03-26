#pragma once
#include "string"
#include <exception>

class MatrixRoomVersionError : public std::exception {
private:
  std::string room_version;

public:
  explicit MatrixRoomVersionError(std::string room_version)
      : room_version(std::move(room_version)) {}

  [[nodiscard]] const char *what() const noexcept override {
    return "Unsupported room version";
  }
};
