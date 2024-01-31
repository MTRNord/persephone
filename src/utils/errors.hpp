#include <exception>
#include "string"

class MatrixRoomVersionError : public std::exception {
  private:
    std::string room_version;

  public:
    MatrixRoomVersionError(std::string room_version) : room_version(std::move(room_version)) {}

    [[nodiscard]] const char * what() const noexcept override {
      return "Unsupported room version";
    }
};
