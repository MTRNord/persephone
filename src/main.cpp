#include "database/database.hpp"
#include "federation/federation_sender.hpp"
#include "utils/config.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include "webserver/client_server_api/ClientServerCtrl.hpp"
#include "webserver/server_server_api/ServerServerCtrl.hpp"
#include "yaml-cpp/exceptions.h"
#include <algorithm>
#include <cstddef>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/orm/DbConfig.h>
#include <memory>
#include <sodium/core.h>
#include <stdexcept>
#include <thread>
#include <trantor/utils/Logger.h>

// Default connection pool size if not configured
static constexpr int DEFAULT_DATABASE_CONNECTIONS = 10;

trantor::Logger::LogLevel logLevelFromStr(const std::string_view level) {
  const auto lowered_level = to_lower(std::string(level));
  if (level == "trace") {
    return trantor::Logger::LogLevel::kTrace;
  }
  if (level == "debug") {
    return trantor::Logger::LogLevel::kDebug;
  }
  if (level == "info") {
    return trantor::Logger::LogLevel::kInfo;
  }
  if (level == "warn") {
    return trantor::Logger::LogLevel::kWarn;
  }
  if (level == "error") {
    return trantor::Logger::LogLevel::kError;
  }
  if (level == "fatal") {
    return trantor::Logger::LogLevel::kFatal;
  }
  throw std::runtime_error("Invalid log level: " + std::string(level));
}

int main() {
  // Libsodium init
  if (sodium_init() < 0) {
    LOG_ERROR << "Failed to init libsodium";
    return 1;
  }

  // Actual startup
  try {
    const Config config{};

    const auto log_level = logLevelFromStr(config.log_level);

    try {
      json_utils::ensure_server_keys(config);
    } catch (std::runtime_error &error) {
      LOG_ERROR << "Failed to ensure_server_keys: " << error.what();
      return 1;
    }
    auto verify_key_data = get_verify_key_data(config);

    // Determine connection pool size: use config value, or default to
    // max(4, hardware_concurrency) for good performance
    const size_t database_connections = config.db_config.pool_size.value_or(
        std::max(4, static_cast<int>(std::thread::hardware_concurrency())));
    LOG_INFO << "Database connection pool size: " << database_connections;

    LOG_INFO << "Server running on " << config.webserver_config.bind_host << ":"
             << config.webserver_config.port;
    drogon::app()
        .addListener(config.webserver_config.bind_host,
                     config.webserver_config.port)
        .setThreadNum(0)
        .setLogLevel(log_level)
        .addDbClient(
            drogon::orm::PostgresConfig{.host = config.db_config.host,
                                .port = config.db_config.port,
                                .databaseName = config.db_config.database_name,
                                .username = config.db_config.user,
                                .password = config.db_config.password,
                                .connectionNumber = database_connections,
                                .name = "default",
                                .isFast = false,
                                .characterSet = "",
                                .timeout = 30,
                                .autoBatch = true,
                                .connectOptions = {}})
        .enableGzip(true)
        .registerPostHandlingAdvice([](const drogon::HttpRequestPtr &,
                                       const drogon::HttpResponsePtr &resp) {
          resp->addHeader("Access-Control-Allow-Origin", "*");
          resp->addHeader("Access-Control-Allow-Methods",
                          "GET, POST, PUT, DELETE, OPTIONS");
          resp->addHeader("Access-Control-Allow-Headers",
                          "X-Requested-With, Content-Type, Authorization");
        })
        .registerBeginningAdvice([&verify_key_data, &config]() {
          Database::migrate();
          FederationSender::start(
              std::string(config.matrix_config.server_name),
              verify_key_data.key_id, verify_key_data.private_key);
        });

    // Initialize the federation auth filter with our server name
    server_server_api::FederationAuthFilter::setServerName(
        std::string(config.matrix_config.server_name));

    const auto srv_srv_ctrlPtr =
        std::make_shared<server_server_api::ServerServerCtrl>(config,
                                                              verify_key_data);
    const auto client_srv_ctrlPtr =
        std::make_shared<client_server_api::ClientServerCtrl>(config);
    drogon::app()
        .registerController(client_srv_ctrlPtr)
        .registerController(srv_srv_ctrlPtr);

    if (config.webserver_config.ssl) {
      drogon::app().addListener(config.webserver_config.bind_host,
                                config.webserver_config.federation_port, true,
                                "./server.crt", "./server.key", false);
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
