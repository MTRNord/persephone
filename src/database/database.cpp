#include "database.hpp"

void Database::migrate() { this->migration_v1(); }

void Database::migration_v1() {
  // TODO: Check if we already did this migration
  session sql(this->pool);
  transaction tr(sql);

  auto x = 0;
  const char *query = (
#include "database/migrations/v1.sql"
  );
  sql << query;
  tr.commit();
}