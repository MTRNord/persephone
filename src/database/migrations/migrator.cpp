#include "migrator.hpp"
#include <cassert>
#include <drogon/HttpAppFramework.h>
#include <drogon/orm/Exception.h>
#include <exception>
#include <trantor/utils/Logger.h>

void Migrator::migrate() {
  LOG_INFO << "Starting database migration";
  migration_v0();
  migration_v1();
  migration_v2();
  migration_v3();
  migration_v4();

  LOG_INFO << "Finished database migration";
}

void Migrator::migration_v0() {
  const auto sql = drogon::app().getDbClient("default");
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }
  try {
    LOG_DEBUG << "Creating v0 table as needed";
    const auto query =
        sql->execSqlAsyncFuture("CREATE TABLE IF NOT EXISTS public.migrations "
                                "(version INTEGER NOT NULL)");
    query.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v1() {
  LOG_INFO << "Starting database migration v0->v1";
  const auto sql = drogon::app().getDbClient("default");
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 1) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v0->v1 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v1";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Global events table
       This is meant to be accompanied by various views for per-room data */
    auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS events ( "
        "event_id TEXT NOT NULL CONSTRAINT event_id_unique UNIQUE, "
        "room_id TEXT NOT NULL, depth BIGINT NOT NULL, "
        "auth_events TEXT[] NOT NULL, rejected BOOLEAN NOT NULL DEFAULT FALSE, "
        "state_key TEXT, type TEXT NOT NULL, json TEXT NOT NULL "
        ")");
    query_1.wait();

    /* Index for membership events (helps also to create the user specific
     * views) */
    const auto query_2 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX IF NOT EXISTS events_idx ON events (room_id, state_key) "
        "WHERE type = 'm.room.member'");
    query_2.wait();

    /* Create materialized views on insert -- Sadly formating is broken. See
     * migration sql files for readable versions */
    const auto query_3 = transPtr->execSqlAsyncFuture(
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
    query_3.wait();

    /* Create trigger to create the room view */
    const auto query_4 = transPtr->execSqlAsyncFuture(
        "CREATE TRIGGER tg_room_view_create AFTER INSERT ON events FOR EACH "
        "ROW EXECUTE FUNCTION new_room_view()");
    query_4.wait();

    /* Create update fn which needs to be called manually as we can batch this
     * in the app logic */
    const auto query_5 = transPtr->execSqlAsyncFuture(
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
    query_5.wait();

    /* User View - Create materialized view on insert. This view only contains
     * for each user the membership events */
    const auto query_6 = transPtr->execSqlAsyncFuture(
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
    query_6.wait();

    const auto query_7 = transPtr->execSqlAsyncFuture(
        "CREATE TRIGGER tg_user_view_create AFTER INSERT ON events FOR EACH "
        "ROW EXECUTE FUNCTION new_user_view();");
    query_7.wait();

    const auto query_8 = transPtr->execSqlAsyncFuture(
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
    query_8.wait();

    /* Mark the migration as completed */
    const auto query_9 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (1);");
    query_9.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v2() {
  LOG_INFO << "Starting database migration v1->v2";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 2) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v1->v2 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v2";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Used to generate the users table
     These are LOCAL users only.*/
    const auto query_1 =
        transPtr->execSqlAsyncFuture("CREATE TABLE IF NOT EXISTS users ( "
                                     "matrix_id TEXT PRIMARY KEY, "
                                     "password_hash TEXT NOT NULL, "
                                     "avatar_url TEXT, display_name TEXT); ");
    query_1.wait();

    const auto query_2 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS devices ( "
        "matrix_id TEXT NOT NULL references users(matrix_id), "
        "device_id TEXT NOT NULL, device_name TEXT NOT NULL, "
        "access_token TEXT NOT NULL UNIQUE, PRIMARY KEY(matrix_id, "
        "device_id));");
    query_2.wait();

    /* Mark the migration as completed */
    const auto query_3 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (2);");
    query_3.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v3() {
  LOG_INFO << "Starting database migration v2->v3";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 3) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v2->v3 already ran\n";
      return;
    }
    LOG_DEBUG << "First time migrating to v3\n";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /*Create an index for state events*/
    const auto query_1 =
        transPtr->execSqlAsyncFuture("CREATE INDEX ON events (room_id, type, "
                                     "state_key) WHERE state_key IS NOT NULL;");
    query_1.wait();

    /* Mark the migration as completed */
    const auto query_2 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (3);");
    query_2.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v4() {
  LOG_INFO << "Starting database migration v3->v4";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 4) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v3->v4 already ran\n";
      return;
    }
    LOG_DEBUG << "First time migrating to v4\n";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /*Create an account data table*/
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS public.account_data(id SERIAL PRIMARY KEY, "
        "user_id TEXT NOT NULL references users (matrix_id), type TEXT NOT "
        "NULL, json TEXT NOT NULL);");
    query_1.wait();

    /*Create an account data table*/
    const auto query_2 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS push_rules(id SERIAL PRIMARY KEY, user_id "
        "TEXT NOT NULL references users (matrix_id), json TEXT NOT NULL);");
    query_2.wait();

    /* Mark the migration as completed */
    const auto query_3 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (4);");
    query_3.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}
