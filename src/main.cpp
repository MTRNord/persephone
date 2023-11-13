#include "utils/config.hpp"
#include "webserver/webserver.hpp"

int main() {
  Config config;
  Webserver webserver(config);

  webserver.start();

  return 0;
}