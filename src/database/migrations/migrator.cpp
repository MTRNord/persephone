#include "migrator.hpp"

void Migrator::migrate() const {
  LOG_INFO << "Starting database migration";
  this->migration_v0();
  this->migration_v1();
  this->migration_v2();
  this->migration_v3();

  LOG_INFO << "Finished database migration";
}

void Migrator::migration_v0() const {
  auto sql = drogon::app().getDbClient("default");
  assert(sql);
  try {
    LOG_DEBUG << "Creating v0 table as needed";
    auto f =
        sql->execSqlAsyncFuture("CREATE TABLE IF NOT EXISTS public.migrations "
                                "(version INTEGER NOT NULL)");
    f.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    exit(EXIT_FAILURE);
  }
}

void Migrator::migration_v1() const {
  LOG_INFO << "Starting database migration v0->v1";
  auto sql = drogon::app().getDbClient("default");
  assert(sql);

  try {
    auto f = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 1) as exists");

    if (f.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v0->v1 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v1";
    auto transPtr = sql->newTransaction();
    assert(transPtr);

    /* Global events table
       This is meant to be accompanied with various views for per-room data */
    auto f1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS events ( "
        "event_id TEXT NOT NULL CONSTRAINT event_id_unique UNIQUE, "
        "room_id TEXT NOT NULL, depth BIGINT NOT NULL, "
        "auth_events TEXT[] NOT NULL, rejected BOOLEAN NOT NULL DEFAULT FALSE, "
        "state_key TEXT, type TEXT NOT NULL, json TEXT NOT NULL "
        ")");
    f1.wait();

    /* Index for membership events (helps also to create the user specific
     * views) */
    auto f2 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX IF NOT EXISTS events_idx ON events (room_id, state_key) "
        "WHERE type = 'm.room.member'");
    f2.wait();

    /* Create materialized views on insert -- Sadly formating is broken. See
     * migration sql files for readable versions */
    auto f3 = transPtr->execSqlAsyncFuture(
        "CREATE OR REPLACE FUNCTION new_room_view() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE room_cleared text; "
        "BEGIN "
        "    room_cleared := REPLACE(REPLACE(REPLACE(NEW.room_id, '.', '_'), "
        "':', '_'), '!', ''); "
        "    EXECUTE 'CREATE MATERIALIZED VIEW IF NOT EXISTS ' || "
        "quote_ident('room_' || room_cleared) || ' AS SELECT * FROM events "
        "WHERE room_id = ' || quote_literal(NEW.room_id); "
        "    EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS ' || "
        "quote_ident('room_' || room_cleared || '_idx') || ' ON ' || "
        "quote_ident('room_' || room_cleared) || ' (event_id);'; "
        "    RETURN NULL; "
        "END; "
        "$$");
    f3.wait();

    /* Create trigger to create the room view */
    auto f4 = transPtr->execSqlAsyncFuture(
        "CREATE TRIGGER tg_room_view_create AFTER INSERT ON events FOR EACH "
        "ROW EXECUTE FUNCTION new_room_view()");
    f4.wait();

    /* Create update fn which needs to be called manually as we can batch this
     * in the app logic */
    auto f5 = transPtr->execSqlAsyncFuture(
        "CREATE OR REPLACE FUNCTION room_view_update(room_id text) "
        "RETURNS void "
        "LANGUAGE plpgsql AS $$ "
        "DECLARE room_cleared text; "
        "BEGIN "
        "    room_cleared := REPLACE(REPLACE(REPLACE(room_id, '.', '_'), ':', "
        "'_'), '!', ''); "
        "    EXECUTE 'REFRESH MATERIALIZED VIEW CONCURRENTLY ' || "
        "quote_ident('room_' || room_cleared); "
        "END; "
        "$$;");
    f5.wait();

    /* User View - Create materialized view on insert. This view only contains
     * for each user the membership events */
    auto f6 = transPtr->execSqlAsyncFuture(
        "CREATE OR REPLACE FUNCTION new_user_view() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ "
        "DECLARE state_key_cleared text; "
        "BEGIN "
        "    CASE "
        "        WHEN NEW.state_key IS NOT NULL THEN "
        "            state_key_cleared := "
        "REPLACE(REPLACE(REPLACE(NEW.state_key, '.', '_'), ':', '_'), '@', "
        "''); "
        "            EXECUTE 'CREATE MATERIALIZED VIEW IF NOT EXISTS ' || "
        "quote_ident('user_' || state_key_cleared) || ' AS SELECT * FROM "
        "events WHERE type = ''m.room.member'' AND state_key = ' || "
        "quote_literal(NEW.state_key); "
        "            EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS ' || "
        "quote_ident('user_' || state_key_cleared || '_idx') || ' ON ' || "
        "quote_ident('user_' || state_key_cleared) || ' (event_id);'; "
        "        ELSE "
        "            /* Do nothing */ "
        "    END CASE; "
        "    RETURN NULL; "
        "END; "
        "$$;");
    f6.wait();

    auto f7 = transPtr->execSqlAsyncFuture(
        "CREATE TRIGGER tg_user_view_create AFTER INSERT ON events FOR EACH "
        "ROW EXECUTE FUNCTION new_user_view();");
    f7.wait();

    auto f8 = transPtr->execSqlAsyncFuture(
        "CREATE OR REPLACE FUNCTION user_view_update(state_key text) "
        "RETURNS void "
        "LANGUAGE plpgsql AS $$ "
        "DECLARE state_key_cleared text; "
        "BEGIN "
        "    state_key_cleared := REPLACE(REPLACE(REPLACE(state_key, '.', "
        "'_'), ':', '_'), '@', ''); "
        "    EXECUTE 'REFRESH MATERIALIZED VIEW CONCURRENTLY ' ||  "
        "quote_ident('user_' || state_key_cleared); "
        "END; "
        "$$;");
    f8.wait();

    /* Mark the migration as completed */
    auto f9 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (1);");
    f9.wait();

  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    exit(EXIT_FAILURE);
  }
}

void Migrator::migration_v2() const {
  LOG_INFO << "Starting database migration v1->v2";
  auto sql = drogon::app().getDbClient();
  assert(sql);

  try {
    auto f = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 2) as exists");

    if (f.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v1->v2 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v2";
    auto transPtr = sql->newTransaction();
    assert(transPtr);

    /* Used to generate the users table
     These are LOCAL users only.*/
    auto f1 =
        transPtr->execSqlAsyncFuture("CREATE TABLE IF NOT EXISTS users ( "
                                     "matrix_id TEXT PRIMARY KEY, "
                                     "password_hash TEXT NOT NULL, "
                                     "avatar_url TEXT, display_name TEXT); ");
    f1.wait();

    auto f2 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS devices ( "
        "matrix_id TEXT NOT NULL references users(matrix_id), "
        "device_id TEXT NOT NULL, device_name TEXT NOT NULL, "
        "access_token TEXT NOT NULL UNIQUE, PRIMARY KEY(matrix_id, "
        "device_id));");
    f2.wait();

    /* Mark the migration as completed */
    auto f3 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (2);");
    f3.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    exit(EXIT_FAILURE);
  }
}

void Migrator::migration_v3() const {
  LOG_INFO << "Starting database migration v2->v3";
  auto sql = drogon::app().getDbClient();
  assert(sql);

  try {
    auto f = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 3) as exists");

    if (f.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v2->v3 already ran\n";
      return;
    }
    LOG_DEBUG << "First time migrating to v3\n";
    auto transPtr = sql->newTransaction();
    assert(transPtr);

    /*Create an index for state events*/
    auto f1 =
        transPtr->execSqlAsyncFuture("CREATE INDEX ON events (room_id, type, "
                                     "state_key) WHERE state_key IS NOT NULL;");
    f1.wait();

    /* Mark the migration as completed */
    auto f3 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (3);");
    f3.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    exit(EXIT_FAILURE);
  }
}
