#define JSON_DIAGNOSTICS 1
#define JSON_USE_IMPLICIT_CONVERSIONS 0

#include "webserver/webserver.hpp"

int main() {
  Webserver webserver;

  webserver.start();

  return 0;
}