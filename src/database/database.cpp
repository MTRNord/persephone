#include "database.hpp"
#include "libpq-fe.h"
#include "soci/postgresql/soci-postgresql.h"
#include "soci/transaction.h"
#include <errno.h>
#include <format>
#include <poll.h>
#include <stdexcept>
#include <string.h>

void Database::migrate() { this->migration_v1(); }

void Database::migration_v1() {
  // TODO: Check if we already did this migration
  session sql(*this->pool.get());

  int version = 1;
  int exists = 0;
  sql << "select exists(select 1 from migrations where version = :version) as "
         "exists",
      into(exists), use(version, "version");

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