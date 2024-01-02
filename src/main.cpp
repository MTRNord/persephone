#include "database/database.hpp"
#include "drogon/drogon.h"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/client_server_api/ClientServerCtrl.hpp"
#include "webserver/server_server_api/ServerServerCtrl.hpp"
#include "yaml-cpp/exceptions.h"
#include <ares.h>
#include <iostream>
#include <sodium/core.h>
#include <stdexcept>

int main() {
#ifdef CARES_HAVE_ARES_LIBRARY_INIT
  // C-Ares (DNS resolver) init
  auto ares_result = ares_library_init(ARES_LIB_INIT_ALL);
  if (ares_result != 0) {
    auto ares_error = ares_strerror(ares_result);
    LOG_ERROR << "Failed to init c-ares dns resolver library: " << ares_error
              << '\n';

    return 1;
  }
#endif

  // Libsodium init
  if (sodium_init() < 0) {
    LOG_ERROR << "Failed to init libsodium";
    return 1;
  }

  // Actual startup
  try {
    Config config;

    try {
      json_utils::ensure_server_keys(config);
    } catch (std::runtime_error &error) {
      LOG_ERROR << "Failed to ensure_server_keys: " << error.what();
      return 1;
    }
    auto verify_key_data = get_verify_key_data(config);

    LOG_INFO << "Server running on 127.0.0.1:8008";
    drogon::app()
        .addListener("0.0.0.0", 8008)
        .setThreadNum(0)
        .setLogLevel(trantor::Logger::LogLevel::kDebug)
        .createDbClient("postgresql", config.db_config.host,
                        config.db_config.port, config.db_config.database_name,
                        config.db_config.user, config.db_config.password, 10)
        .enableGzip(true)
        .registerPostHandlingAdvice([](const drogon::HttpRequestPtr &,
                                       const drogon::HttpResponsePtr &resp) {
          resp->addHeader("Access-Control-Allow-Origin", "*");
        })
        .registerBeginningAdvice([]() {
          Database db{};
          db.migrate();
        });

    auto srv_srv_ctrlPtr =
        std::make_shared<server_server_api::ServerServerCtrl>(config,
                                                              verify_key_data);
    Database db{};
    auto client_srv_ctrlPtr =
        std::make_shared<client_server_api::ClientServerCtrl>(config, db);
    drogon::app()
        .registerController(client_srv_ctrlPtr)
        .registerController(srv_srv_ctrlPtr);

    if (config.webserver_config.ssl) {
      drogon::app().addListener("0.0.0.0", 8448, true, "./server.crt",
                                "./server.key", false);
    }

    drogon::app().run();
  } catch (YAML::BadFile &error) {
    LOG_ERROR << "Missing or invalid config.yaml file. Make sure to create it "
                 "prior to running persephone";
    return 1;
  } catch (std::runtime_error &error) {
    LOG_ERROR << error.what();
    return 1;
  }

  return 0;
}
