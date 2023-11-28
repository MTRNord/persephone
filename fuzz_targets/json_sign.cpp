#include "utils/json_utils.hpp"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    return 1;
  }

  while (__AFL_LOOP(10000)) {
    // TODO: Json signing
  }

  return 0;
}