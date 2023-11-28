#include "database.hpp"
#include "libpq-fe.h"
#include "soci/postgresql/soci-postgresql.h"
#include "soci/transaction.h"
#include "utils/json_utils.hpp"
#include "utils/utils.hpp"
#include <cerrno>
#include <cstring>
#include <format>
#include <poll.h>
#include <stdexcept>
#include <zlib.h>

void Database::migrate() {
  this->migration_v1();
  this->migration_v2();
}

void Database::migration_v1() {
  session sql(*this->pool.get());

  int exists = 0;
  sql << "select exists(select 1 from migrations where version = 1) as "
         "exists",
      into(exists);

  if (exists == 1) {
    return;
  }

  transaction tr(sql);

  auto x = 0; // NOLINT(clang-diagnostic-unused-but-set-variable)
  const char *query = (
#include "database/migrations/v1.sql"
  );
  sql << query;
  tr.commit();
}

void Database::migration_v2() {
  session sql(*this->pool.get());

  int exists = 0;
  sql << "select exists(select 1 from migrations where version = 2) as "
         "exists",
      into(exists);

  if (exists == 1) {
    return;
  }

  transaction tr(sql);

  auto x = 0; // NOLINT(clang-diagnostic-unused-but-set-variable)
  const char *query = (
#include "database/migrations/v2.sql"
  );
  sql << query;
  tr.commit();
}

Database::UserCreationResp
Database::create_user(Database::UserCreationData const &data) const {
  session sql(*this->pool.get());

  // TODO: If we have a guest registering we are required to always generate
  // this.
  auto device_id = data.device_id.value_or(random_string(7));
  auto hashed_password = hash_password(data.password);

  transaction tr(sql);
  sql << "INSERT INTO users(matrix_id, password_hash) VALUES(:matrix_id, "
         ":password_hash)",
      use(data.matrix_id), use(hashed_password);

  // This token should have this pattern:
  // `persephone_<unpadded base64 local part of the matrix id>_<random string
  // (20 chars)>_<base62 crc32 check>`
  auto localpart_str = localpart(data.matrix_id);
  std::vector<unsigned char> localpart_vec(localpart_str.begin(),
                                           localpart_str.end());
  auto token = std::format(
      "persephone_{}_{}_{}", json_utils::base64_key(localpart_vec),
      random_string(20), base62_encode(crc32_helper(data.matrix_id)));

  sql << "INSERT INTO devices(matrix_id, device_id, device_name, access_token) "
         "VALUES(:matrix_id, :device_id, :device_name, :access_token)",
      use(data.matrix_id), use(device_id), use(data.device_name), use(token);

  tr.commit();
  return {token, device_id};
}

bool Database::user_exists(std::string matrix_id) const {
  session sql(*this->pool.get());

  int exists = 0;
  sql << "select exists(select 1 from users where matrix_id = :matrix_id) as "
         "exists",
      use(matrix_id), into(exists);

  return exists == 1;
}

std::optional<Database::UserInfo>
Database::get_user_info(std::string auth_token) const {
  session sql(*this->pool.get());

  std::optional<std::string> device_id;
  std::string device_id_temp;
  std::string matrix_id;
  indicator ind;
  // TODO: track if the user is a guest in the database
  bool is_guest = false;

  sql << "select (device_id, matrix_id) from devices where access_token = "
         ":access_token",
      use(auth_token), into(device_id_temp, ind), into(matrix_id);

  if (!sql.got_data()) {
    return std::nullopt;
  }

  if (ind == i_null) {
    device_id = std::nullopt;
  } else {
    device_id = device_id_temp;
  }

  return UserInfo{device_id, is_guest, matrix_id};
}

void Database::listen(std::string channel,
                      std::function<void()> const &callback) {
  session sql(*this->pool.get());

  sql << std::format("Listen {}", channel);

  postgresql_session_backend *sessionBackEnd =
      static_cast<postgresql_session_backend *>(sql.get_backend());

  auto conn = sessionBackEnd->conn_;

  /*
   * Sleep until something happens on the connection.  We use
   * poll(2) to wait for input.
   */
  int sock;

  sock = PQsocket(conn);

  if (sock < 0)
    throw std::runtime_error("Unable to open PQSocket"); /* shouldn't happen */

  while (true) {
    pollfd poll_struct;
    // This is a C struct.
    memset(&poll_struct, 0, sizeof(poll_struct));
    poll_struct.fd = sock;
    poll_struct.events = POLLIN | POLLHUP | POLLERR | POLLNVAL;

    if (poll(&poll_struct, 1, 5000) < 0) {
      throw std::runtime_error(std::format("poll() failed: {}\n", errno));
    }

    if (poll_struct.revents & POLLIN) {
      PGnotify *notify;
      PQconsumeInput(conn);

      while ((notify = PQnotifies(conn)) != nullptr) {
        if (notify->relname == channel) {
          callback();
        }
        PQfreemem(notify);
        PQconsumeInput(conn);
      }
    }
  }
}