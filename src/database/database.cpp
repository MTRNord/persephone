#include "database.hpp"

#include "libpq-fe.h"
#include <format>

void Database::migrate() { this->migration_v1(); }

void Database::migration_v1() {
  // TODO: Check if we already did this migration
  session sql(this->pool);
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
  session sql(this->pool);
  // TODO: Invoke listen

  sql << std::format("Listen {}", channel);

  postgresql_session_backend *sessionBackEnd =
      static_cast<postgresql_session_backend *>(sql.get_backend());

  auto conn = sessionBackEnd->conn_;

  /*
   * Sleep until something happens on the connection.  We use
   * select(2) to wait for input, but you could also use poll() or
   * similar facilities.
   */
  int sock;
  fd_set input_mask;

  sock = PQsocket(conn);

  if (sock < 0)
    throw std::runtime_error("Unable to open PQSocket"); /* shouldn't happen */

  FD_ZERO(&input_mask);
  FD_SET(sock, &input_mask);

  if (select(sock + 1, &input_mask, nullptr, nullptr, nullptr) < 0) {
    throw std::runtime_error(std::format("select() failed: {}\n", errno));
  }

  PGnotify *notify;
  PQconsumeInput(conn);
  while ((notify = PQnotifies(conn)) != nullptr) {
    sock = PQsocket(conn);

    if (sock < 0)
      throw std::runtime_error(
          "Unable to open PQSocket"); /* shouldn't happen */

    FD_ZERO(&input_mask);
    FD_SET(sock, &input_mask);

    if (select(sock + 1, &input_mask, nullptr, nullptr, nullptr) < 0) {
      throw std::runtime_error(std::format("select() failed: {}\n", errno));
    }

    // FIXME: Check which channel was notified here
    callback();
    PQfreemem(notify);
    PQconsumeInput(conn);
  }
}