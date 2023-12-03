#include "database.hpp"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include <format>
#include <stdexcept>
#include <zlib.h>

void Database::migrate() {
  LOG_INFO << "Starting database migration";
  this->migration_v0([this]() {
    this->migration_v1([this]() { this->migration_v2([]() {}); });
  });

  LOG_INFO << "Finished database migration";
}

void Database::migration_v0(std::function<void()> &&callback) {
  auto sql = drogon::app().getFastDbClient("default");
  assert(sql);
  sql->execSqlAsync(
      "CREATE TABLE IF NOT EXISTS migrations (version INTEGER NOT NULL)",
      [=](const drogon::orm::Result &) { callback(); },
      [&, callback](const drogon::orm::DrogonDbException &e) {
        LOG_ERROR << "Error:" << e.base().what();
        callback();
      });
}

void Database::migration_v1(std::function<void()> &&callback) {
  LOG_INFO << "Starting database migration v0->v1";
  auto sql = drogon::app().getFastDbClient("default");
  assert(sql);

  sql->execSqlAsync(
      "select exists(select 1 from migrations where version = 1) as exists",
      [=](const drogon::orm::Result &result) {
        if (result.at(0)["exists"].as<bool>()) {
          LOG_INFO << "Migration v0->v1 already ran";
          callback();
          return;
        }
        LOG_DEBUG << "First time migrating to v1";
        sql->newTransactionAsync(
            [&, callback](
                const std::shared_ptr<drogon::orm::Transaction> &transPtr) {
              assert(transPtr);

              auto x = 0; // NOLINT(clang-diagnostic-unused-but-set-variable)
              auto query = (
#include "database/migrations/v1.sql"
              );

              transPtr->execSqlAsync(
                  query,
                  [=](const drogon::orm::Result &) {
                    LOG_INFO << "Finished database migration v0->v1";
                    callback();
                  },
                  [&, callback](const drogon::orm::DrogonDbException &e) {
                    LOG_ERROR << "Error:" << e.base().what();
                    callback();
                  });
            });
      },
      [&, callback](const drogon::orm::DrogonDbException &e) {
        LOG_ERROR << "Error:" << e.base().what();
        callback();
      });
}

void Database::migration_v2(std::function<void()> &&callback) {
  LOG_INFO << "Starting database migration v1->v2";
  auto sql = drogon::app().getFastDbClient();
  assert(sql);

  sql->execSqlAsync(
      "select exists(select 1 from migrations where version = 2) as exists",
      [=](const drogon::orm::Result &result) {
        if (result.at(0)["exists"].as<bool>()) {
          LOG_INFO << "Migration v1->v2 already ran";
          callback();
          return;
        }

        sql->newTransactionAsync(
            [&, callback](
                const std::shared_ptr<drogon::orm::Transaction> &transPtr) {
              assert(transPtr);

              auto x = 0; // NOLINT(clang-diagnostic-unused-but-set-variable)
              auto query = (
#include "database/migrations/v2.sql"
              );

              transPtr->execSqlAsync(
                  query,
                  [=](const drogon::orm::Result &) {
                    LOG_INFO << "Finished database migration v1->v2";
                    callback();
                  },
                  [&, callback](const drogon::orm::DrogonDbException &e) {
                    LOG_ERROR << "Error:" << e.base().what();
                    callback();
                  });
            });
      },
      [&, callback](const drogon::orm::DrogonDbException &e) {
        LOG_ERROR << "Error:" << e.base().what();
        callback();
      });
}

void Database::create_user(
    Database::UserCreationData const &data,
    std::function<void(const Database::UserCreationResp &)> &&callback) const {
  auto sql = drogon::app().getFastDbClient();

  sql->newTransactionAsync(
      [&, callback,
       data](const std::shared_ptr<drogon::orm::Transaction> &transPtr) {
        assert(transPtr);

        // TODO: If we have a guest registering we are required to always
        // generate this.
        auto device_id = data.device_id.value_or(random_string(7));
        auto password_hash = hash_password(data.password);
        auto matrix_id = data.matrix_id;
        auto device_name = data.device_name.value_or(random_string(7));

        // This token should have this pattern:
        // `persephone_<unpadded base64 local part of the matrix
        // id>_<random string (20 chars)>_<base62 crc32 check>`
        auto localpart_str = localpart(matrix_id);
        std::vector<unsigned char> localpart_vec(localpart_str.begin(),
                                                 localpart_str.end());
        auto access_token = std::format(
            "persephone_{}_{}_{}", json_utils::base64_key(localpart_vec),
            random_string(20), base62_encode(crc32_helper(matrix_id)));

        transPtr->execSqlAsync(
            "INSERT INTO users(matrix_id, password_hash) VALUES($1, $2)",
            [&, callback, transPtr, matrix_id, device_id, device_name,
             access_token](const drogon::orm::Result &) {
              assert(transPtr);
              transPtr->execSqlAsync(
                  "INSERT INTO devices(matrix_id, device_id, "
                  "device_name, access_token) VALUES($1, $2, $3, $4)",
                  [&, callback, access_token,
                   device_id](const drogon::orm::Result &) {
                    Database::UserCreationResp data{access_token, device_id};
                    callback(data);
                  },
                  [](const drogon::orm::DrogonDbException &e) {
                    LOG_ERROR << "Error:" << e.base().what();
                  },
                  matrix_id, device_id, device_name, access_token);
            },
            [](const drogon::orm::DrogonDbException &e) {
              LOG_ERROR << "Error:" << e.base().what();
            },
            matrix_id, password_hash);
      });
}

void Database::user_exists(std::string matrix_id,
                           std::function<void(bool)> &&callback) const {
  auto sql = drogon::app().getFastDbClient();
  sql->execSqlAsync(
      "select exists(select 1 from users where matrix_id = $1) as exists",
      [=](const drogon::orm::Result &result) {
        callback(result.at(0)["exists"].as<bool>());
      },
      [](const drogon::orm::DrogonDbException &e) {
        LOG_ERROR << "Error:" << e.base().what();
      },
      matrix_id);
}

void Database::get_user_info(
    std::string auth_token,
    std::function<void(std::optional<Database::UserInfo>)> &&callback) const {
  auto sql = drogon::app().getFastDbClient();

  sql->execSqlAsync(
      "select device_id, matrix_id from devices where access_token = $1",
      [=](const drogon::orm::Result &result) {
        std::optional<std::string> device_id;
        // TODO: track if the user is a guest in the database
        bool is_guest = false;

        if (result.size() == 0) {
          callback(std::nullopt);
        }

        auto first_row = result.at(0);
        try {
          device_id = first_row["device_id"].as<std::string>();
        } catch (drogon::orm::RangeError &) {
          // No device_id set
          device_id = std::nullopt;
        }
        auto matrix_id = first_row["matrix_id"].as<std::string>();
        UserInfo user_info{device_id, is_guest, matrix_id};

        callback(user_info);
      },
      [](const drogon::orm::DrogonDbException &e) {
        LOG_ERROR << "Error:" << e.base().what();
      },
      auth_token);
}