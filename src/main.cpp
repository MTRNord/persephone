#include "database/database.hpp"
#include "drogon/drogon.h"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/client_server_api/ClientServerCtrl.hpp"
#include "webserver/server_server_api/ServerServerCtrl.hpp"
#include "yaml-cpp/exceptions.h"
#include <sodium/core.h>
#include <stdexcept>

int main() {
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
        .addDbClient(orm::PostgresConfig{
          .host = config.db_config.host,
          .port = config.db_config.port,
          .databaseName = config.db_config.database_name,
          .username = config.db_config.user,
          .password = config.db_config.password,
          .connectionNumber = 10,
          .name = "default",
        })
        .enableGzip(true)
        .registerPostHandlingAdvice([](const drogon::HttpRequestPtr &,
                                       const drogon::HttpResponsePtr &resp) {
          resp->addHeader("Access-Control-Allow-Origin", "*");
        })
        .registerBeginningAdvice([]() {
          constexpr Database db{};
          db.migrate();
        });

    const auto srv_srv_ctrlPtr =
        std::make_shared<server_server_api::ServerServerCtrl>(config,
                                                              verify_key_data);
    Database db{};
    const auto client_srv_ctrlPtr =
        std::make_shared<client_server_api::ClientServerCtrl>(config, db);
    drogon::app()
        .registerController(client_srv_ctrlPtr)
        .registerController(srv_srv_ctrlPtr);

    if (config.webserver_config.ssl) {
      drogon::app().addListener("0.0.0.0", 8448, true, "./server.crt",
                                "./server.key", false);
    }

    drogon::app().run();
  } catch (const YAML::BadFile &error) {
    LOG_ERROR << "Missing or invalid config.yaml file. Make sure to create it "
        "prior to running persephone";
    LOG_ERROR << error.what();
    return 1;
  } catch (std::runtime_error &error) {
    LOG_ERROR << error.what();
    return 1;
  }

  return 0;
}
