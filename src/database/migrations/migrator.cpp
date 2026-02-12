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
  migration_v5();
  migration_v6();
  migration_v7();
  migration_v8();
  migration_v9();
  migration_v10();
  migration_v11();
  migration_v12();
  migration_v13();
  migration_v14();
  migration_v15();

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
    const auto query_1 = transPtr->execSqlAsyncFuture(
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
        "        WHEN NEW.state_key IS NOT NULL AND NEW.type = 'm.room.member' "
        "THEN "
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
      LOG_INFO << "Migration v2->v3 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v3";
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
      LOG_INFO << "Migration v3->v4 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v4";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /*Create an account data table*/
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS public.account_data(id SERIAL PRIMARY KEY, "
        "user_id TEXT NOT NULL references public.users (matrix_id) UNIQUE, "
        "type TEXT NOT NULL, json JSONB NOT NULL);");
    query_1.wait();

    /*Create a push_rules data table*/
    const auto query_2 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS push_rules(id SERIAL PRIMARY KEY, user_id "
        "TEXT NOT NULL references public.users (matrix_id) UNIQUE, json JSONB "
        "NOT NULL);");
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

void Migrator::migration_v5() {
  LOG_INFO << "Starting database migration v4->v5";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 5) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v4->v5 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v4";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Migrate the events table */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ADD COLUMN json2 JSONB;");
    query_1.wait();

    const auto query_2 = transPtr->execSqlAsyncFuture(
        "UPDATE events SET json2 = to_json(json) WHERE LEFT(json, 1) = 'p' OR "
        "LEFT(json, 1) = '{';");
    query_2.wait();

    const auto query_3 = transPtr->execSqlAsyncFuture(
        "UPDATE events SET json2 = to_json(json::numeric) WHERE LEFT(json, 1) "
        "!= 'p' AND LEFT(json, 1) != '{';");
    query_3.wait();

    const auto query_4 =
        transPtr->execSqlAsyncFuture("ALTER TABLE events DROP COLUMN json;");
    query_4.wait();

    const auto query_5 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events RENAME COLUMN json2 TO json;");
    query_5.wait();

    const auto query_6 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS filters(id SERIAL PRIMARY KEY, user_ids "
        "TEXT[] NOT NULL UNIQUE, json JSONB NOT NULL UNIQUE);");
    query_6.wait();

    /* Mark the migration as completed */
    const auto query_7 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (5);");
    query_7.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v6() {
  LOG_INFO << "Starting database migration v5->v6";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 6) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v5->v6 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v6";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Create table for caching remote server signing keys */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS server_signing_keys ("
        "server_name TEXT NOT NULL, "
        "key_id TEXT NOT NULL, "
        "public_key TEXT NOT NULL, "
        "valid_until_ts BIGINT NOT NULL, "
        "fetched_at BIGINT NOT NULL, "
        "PRIMARY KEY (server_name, key_id));");
    query_1.wait();

    /* Create index for cleanup queries (expired keys) */
    const auto query_2 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX IF NOT EXISTS server_signing_keys_valid_until_idx "
        "ON server_signing_keys (valid_until_ts);");
    query_2.wait();

    /* Mark the migration as completed */
    const auto query_3 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (6);");
    query_3.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v7() {
  LOG_INFO << "Starting database migration v6->v7";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 7) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v6->v7 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v7";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Create lookup table for event types */
    const auto query_1 =
        transPtr->execSqlAsyncFuture("CREATE TABLE IF NOT EXISTS event_types ("
                                     "event_type_nid SERIAL PRIMARY KEY, "
                                     "event_type TEXT NOT NULL UNIQUE);");
    query_1.wait();

    /* Create lookup table for state keys */
    const auto query_2 =
        transPtr->execSqlAsyncFuture("CREATE TABLE IF NOT EXISTS state_keys ("
                                     "state_key_nid SERIAL PRIMARY KEY, "
                                     "state_key TEXT NOT NULL UNIQUE);");
    query_2.wait();

    /* Create lookup table for rooms */
    const auto query_3 =
        transPtr->execSqlAsyncFuture("CREATE TABLE IF NOT EXISTS rooms ("
                                     "room_nid SERIAL PRIMARY KEY, "
                                     "room_id TEXT NOT NULL UNIQUE);");
    query_3.wait();

    /* Pre-populate common event types */
    const auto query_4 = transPtr->execSqlAsyncFuture(
        "INSERT INTO event_types (event_type) VALUES "
        "('m.room.create'), ('m.room.member'), ('m.room.message'), "
        "('m.room.power_levels'), ('m.room.join_rules'), ('m.room.name'), "
        "('m.room.topic'), ('m.room.avatar'), ('m.room.canonical_alias'), "
        "('m.room.history_visibility'), ('m.room.guest_access'), "
        "('m.room.encryption'), ('m.room.server_acl'), ('m.room.tombstone'), "
        "('m.room.pinned_events'), ('m.room.third_party_invite'), "
        "('m.reaction'), ('m.room.redaction') "
        "ON CONFLICT DO NOTHING;");
    query_4.wait();

    /* Add event_nid as the new primary identifier for events */
    const auto query_5 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ADD COLUMN event_nid SERIAL;");
    query_5.wait();

    /* Add NID reference columns to events table */
    const auto query_6 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ADD COLUMN room_nid INTEGER, "
        "ADD COLUMN event_type_nid INTEGER, "
        "ADD COLUMN state_key_nid INTEGER;");
    query_6.wait();

    /* Populate rooms lookup from existing events */
    const auto query_7 = transPtr->execSqlAsyncFuture(
        "INSERT INTO rooms (room_id) "
        "SELECT DISTINCT room_id FROM events ON CONFLICT DO NOTHING;");
    query_7.wait();

    /* Populate event_types lookup from existing events */
    const auto query_8 = transPtr->execSqlAsyncFuture(
        "INSERT INTO event_types (event_type) "
        "SELECT DISTINCT type FROM events ON CONFLICT DO NOTHING;");
    query_8.wait();

    /* Populate state_keys lookup from existing events */
    const auto query_9 = transPtr->execSqlAsyncFuture(
        "INSERT INTO state_keys (state_key) "
        "SELECT DISTINCT state_key FROM events "
        "WHERE state_key IS NOT NULL ON CONFLICT DO NOTHING;");
    query_9.wait();

    /* Update events with NID references */
    const auto query_10 = transPtr->execSqlAsyncFuture(
        "UPDATE events e SET "
        "room_nid = (SELECT room_nid FROM rooms WHERE room_id = e.room_id), "
        "event_type_nid = (SELECT event_type_nid FROM event_types WHERE "
        "event_type = e.type), "
        "state_key_nid = (SELECT state_key_nid FROM state_keys WHERE "
        "state_key = e.state_key);");
    query_10.wait();

    /* Make room_nid NOT NULL after population */
    const auto query_11 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ALTER COLUMN room_nid SET NOT NULL;");
    query_11.wait();

    /* Make event_type_nid NOT NULL after population */
    const auto query_12 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ALTER COLUMN event_type_nid SET NOT NULL;");
    query_12.wait();

    /* Add foreign key constraints */
    const auto query_13 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ADD CONSTRAINT events_room_nid_fk "
        "FOREIGN KEY (room_nid) REFERENCES rooms (room_nid);");
    query_13.wait();

    const auto query_14 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ADD CONSTRAINT events_event_type_nid_fk "
        "FOREIGN KEY (event_type_nid) REFERENCES event_types "
        "(event_type_nid);");
    query_14.wait();

    const auto query_15 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ADD CONSTRAINT events_state_key_nid_fk "
        "FOREIGN KEY (state_key_nid) REFERENCES state_keys (state_key_nid);");
    query_15.wait();

    /* Create indexes on NID columns */
    const auto query_16 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX events_room_nid_idx ON events (room_nid);");
    query_16.wait();

    const auto query_17 =
        transPtr->execSqlAsyncFuture("CREATE INDEX events_room_nid_depth_idx "
                                     "ON events (room_nid, depth DESC);");
    query_17.wait();

    const auto query_18 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX events_type_nid_idx ON events (event_type_nid);");
    query_18.wait();

    const auto query_19 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX events_state_key_nid_idx ON events (state_key_nid) "
        "WHERE state_key_nid IS NOT NULL;");
    query_19.wait();

    /* Create unique index on event_nid */
    const auto query_20 = transPtr->execSqlAsyncFuture(
        "CREATE UNIQUE INDEX events_event_nid_idx ON events (event_nid);");
    query_20.wait();

    /* Mark the migration as completed */
    const auto query_21 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (7);");
    query_21.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v8() {
  LOG_INFO << "Starting database migration v7->v8";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 8) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v7->v8 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v8";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Create separate table for event JSON content */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS event_json ("
        "event_nid INTEGER PRIMARY KEY REFERENCES events (event_nid), "
        "json JSONB NOT NULL);");
    query_1.wait();

    /* Migrate existing JSON data from events table */
    const auto query_2 =
        transPtr->execSqlAsyncFuture("INSERT INTO event_json (event_nid, json) "
                                     "SELECT event_nid, json FROM events;");
    query_2.wait();

    /* Drop the json column from events table */
    const auto query_3 =
        transPtr->execSqlAsyncFuture("ALTER TABLE events DROP COLUMN json;");
    query_3.wait();

    /* Mark the migration as completed */
    const auto query_4 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (8);");
    query_4.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v9() {
  LOG_INFO << "Starting database migration v8->v9";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 9) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v8->v9 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v9";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Create temporal state tracking table */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS temporal_state ("
        "room_nid INTEGER NOT NULL REFERENCES rooms (room_nid), "
        "event_type_nid INTEGER NOT NULL REFERENCES event_types "
        "(event_type_nid), "
        "state_key_nid INTEGER NOT NULL REFERENCES state_keys (state_key_nid), "
        "event_nid INTEGER NOT NULL REFERENCES events (event_nid), "
        "start_index BIGINT NOT NULL, "
        "end_index BIGINT, "
        "ordering INTEGER, "
        "PRIMARY KEY (room_nid, event_type_nid, state_key_nid, start_index));");
    query_1.wait();

    /* Partial index for current state (fast lookups) */
    const auto query_2 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX temporal_state_current_idx "
        "ON temporal_state (room_nid) WHERE end_index IS NULL;");
    query_2.wait();

    /* Index for historical state queries */
    const auto query_3 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX temporal_state_historical_idx "
        "ON temporal_state (room_nid, start_index, end_index);");
    query_3.wait();

    /* Index for ordering-based scans (compression) */
    const auto query_4 =
        transPtr->execSqlAsyncFuture("CREATE INDEX temporal_state_ordering_idx "
                                     "ON temporal_state (room_nid, ordering);");
    query_4.wait();

    /* Populate from existing state events */
    const auto query_5 = transPtr->execSqlAsyncFuture(
        "INSERT INTO temporal_state (room_nid, event_type_nid, state_key_nid, "
        "event_nid, start_index) "
        "SELECT e.room_nid, e.event_type_nid, e.state_key_nid, e.event_nid, "
        "e.depth "
        "FROM events e WHERE e.state_key_nid IS NOT NULL "
        "ORDER BY e.room_nid, e.event_type_nid, e.state_key_nid, e.depth;");
    query_5.wait();

    /* Update end_index for superseded state using window function */
    const auto query_6 = transPtr->execSqlAsyncFuture(
        "WITH ranked AS ("
        "SELECT room_nid, event_type_nid, state_key_nid, start_index, "
        "LEAD(start_index) OVER ("
        "PARTITION BY room_nid, event_type_nid, state_key_nid "
        "ORDER BY start_index) as next_start "
        "FROM temporal_state) "
        "UPDATE temporal_state ts SET end_index = r.next_start "
        "FROM ranked r "
        "WHERE ts.room_nid = r.room_nid "
        "AND ts.event_type_nid = r.event_type_nid "
        "AND ts.state_key_nid = r.state_key_nid "
        "AND ts.start_index = r.start_index "
        "AND r.next_start IS NOT NULL;");
    query_6.wait();

    /* Mark the migration as completed */
    const auto query_7 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (9);");
    query_7.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v10() {
  LOG_INFO << "Starting database migration v9->v10";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 10) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v9->v10 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v10";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Remove materialized view triggers */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "DROP TRIGGER IF EXISTS tg_room_view_create ON events;");
    query_1.wait();

    const auto query_2 = transPtr->execSqlAsyncFuture(
        "DROP TRIGGER IF EXISTS tg_user_view_create ON events;");
    query_2.wait();

    /* Drop the trigger functions */
    const auto query_3 = transPtr->execSqlAsyncFuture(
        "DROP FUNCTION IF EXISTS new_room_view();");
    query_3.wait();

    const auto query_4 = transPtr->execSqlAsyncFuture(
        "DROP FUNCTION IF EXISTS room_view_update(text);");
    query_4.wait();

    const auto query_5 = transPtr->execSqlAsyncFuture(
        "DROP FUNCTION IF EXISTS new_user_view();");
    query_5.wait();

    const auto query_6 = transPtr->execSqlAsyncFuture(
        "DROP FUNCTION IF EXISTS user_view_update(text);");
    query_6.wait();

    /* Drop all dynamically created materialized views */
    const auto query_7 = transPtr->execSqlAsyncFuture(
        "DO $$ "
        "DECLARE view_name TEXT; "
        "BEGIN "
        "FOR view_name IN SELECT matviewname FROM pg_matviews "
        "WHERE schemaname = 'public' "
        "AND (matviewname LIKE 'room_%' OR matviewname LIKE 'user_%') "
        "LOOP "
        "EXECUTE 'DROP MATERIALIZED VIEW IF EXISTS ' || quote_ident(view_name) "
        "|| ' CASCADE'; "
        "END LOOP; "
        "END $$;");
    query_7.wait();

    /* Mark the migration as completed */
    const auto query_8 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (10);");
    query_8.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v11() {
  LOG_INFO << "Starting database migration v10->v11";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 11) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v10->v11 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v11";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Index on event_id for direct lookups */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX IF NOT EXISTS events_event_id_idx ON events (event_id);");
    query_1.wait();

    /* Index on devices.matrix_id for FK lookups */
    const auto query_2 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX IF NOT EXISTS devices_matrix_id_idx ON devices "
        "(matrix_id);");
    query_2.wait();

    /* Composite index for state event lookups using NIDs */
    const auto query_3 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX IF NOT EXISTS events_state_lookup_nid_idx "
        "ON events (room_nid, event_type_nid, state_key_nid) "
        "WHERE state_key_nid IS NOT NULL;");
    query_3.wait();

    /* Mark the migration as completed */
    const auto query_4 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (11);");
    query_4.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v12() {
  LOG_INFO << "Starting database migration v11->v12";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 12) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v11->v12 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v12";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Add prev_events as queryable array column (using NIDs for efficiency) */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "ALTER TABLE events ADD COLUMN prev_events_nids INTEGER[] NOT NULL "
        "DEFAULT '{}';");
    query_1.wait();

    /* GIN index for efficient array containment queries */
    const auto query_2 =
        transPtr->execSqlAsyncFuture("CREATE INDEX events_prev_events_gin_idx "
                                     "ON events USING GIN (prev_events_nids);");
    query_2.wait();

    /* Populate from existing event JSON */
    const auto query_3 = transPtr->execSqlAsyncFuture(
        "UPDATE events e SET prev_events_nids = COALESCE("
        "(SELECT ARRAY_AGG(e2.event_nid) FROM events e2 "
        "WHERE e2.event_id = ANY ("
        "SELECT jsonb_array_elements_text(ej.json -> 'prev_events') "
        "FROM event_json ej WHERE ej.event_nid = e.event_nid)), '{}');");
    query_3.wait();

    /* Mark the migration as completed */
    const auto query_4 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (12);");
    query_4.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v13() {
  LOG_INFO << "Starting database migration v12->v13";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 13) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v12->v13 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v13";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Foreign key on devices.matrix_id (if not already exists) */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints "
        "WHERE constraint_name = 'devices_matrix_id_fk' AND table_name = "
        "'devices') THEN "
        "ALTER TABLE devices ADD CONSTRAINT devices_matrix_id_fk "
        "FOREIGN KEY (matrix_id) REFERENCES users (matrix_id) ON DELETE "
        "CASCADE; "
        "END IF; END $$;");
    query_1.wait();

    /* Foreign key on account_data.user_id */
    const auto query_2 = transPtr->execSqlAsyncFuture(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints "
        "WHERE constraint_name = 'account_data_user_id_fk' AND table_name = "
        "'account_data') THEN "
        "ALTER TABLE account_data ADD CONSTRAINT account_data_user_id_fk "
        "FOREIGN KEY (user_id) REFERENCES users (matrix_id) ON DELETE CASCADE; "
        "END IF; END $$;");
    query_2.wait();

    /* Foreign key on push_rules.user_id */
    const auto query_3 = transPtr->execSqlAsyncFuture(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints "
        "WHERE constraint_name = 'push_rules_user_id_fk' AND table_name = "
        "'push_rules') THEN "
        "ALTER TABLE push_rules ADD CONSTRAINT push_rules_user_id_fk "
        "FOREIGN KEY (user_id) REFERENCES users (matrix_id) ON DELETE CASCADE; "
        "END IF; END $$;");
    query_3.wait();

    /* Foreign key on temporal_state.event_nid with RESTRICT */
    const auto query_4 = transPtr->execSqlAsyncFuture(
        "DO $$ BEGIN "
        "IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints "
        "WHERE constraint_name = 'temporal_state_event_exists' AND table_name "
        "= 'temporal_state') THEN "
        "ALTER TABLE temporal_state ADD CONSTRAINT temporal_state_event_exists "
        "FOREIGN KEY (event_nid) REFERENCES events (event_nid) ON DELETE "
        "RESTRICT; "
        "END IF; END $$;");
    query_4.wait();

    /* Trigger to prevent deleting events referenced as prev_events */
    const auto query_5 = transPtr->execSqlAsyncFuture(
        "CREATE OR REPLACE FUNCTION check_event_not_referenced() "
        "RETURNS TRIGGER AS $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM events WHERE OLD.event_nid = ANY "
        "(prev_events_nids)) THEN "
        "RAISE EXCEPTION 'Cannot delete event % - referenced by other events "
        "as prev_events', OLD.event_id; "
        "END IF; RETURN OLD; END; $$ LANGUAGE plpgsql;");
    query_5.wait();

    const auto query_6 = transPtr->execSqlAsyncFuture(
        "DROP TRIGGER IF EXISTS prevent_referenced_event_delete ON events;");
    query_6.wait();

    const auto query_7 = transPtr->execSqlAsyncFuture(
        "CREATE TRIGGER prevent_referenced_event_delete "
        "BEFORE DELETE ON events FOR EACH ROW "
        "EXECUTE FUNCTION check_event_not_referenced();");
    query_7.wait();

    /* Mark the migration as completed */
    const auto query_8 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (13);");
    query_8.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v14() {
  LOG_INFO << "Starting database migration v13->v14";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 14) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v13->v14 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v14";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Server destination health tracking for federation */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS federation_destinations ("
        "server_name TEXT PRIMARY KEY, "
        "last_successful_ts BIGINT, "
        "last_failure_ts BIGINT, "
        "failure_count INTEGER NOT NULL DEFAULT 0, "
        "retry_after_ts BIGINT NOT NULL DEFAULT 0);");
    query_1.wait();

    /* Persistent federation event queue */
    const auto query_2 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS federation_event_queue ("
        "queue_id SERIAL PRIMARY KEY, "
        "destination TEXT NOT NULL, "
        "event_id TEXT NOT NULL, "
        "event_json JSONB NOT NULL, "
        "created_at BIGINT NOT NULL, "
        "retry_count INTEGER NOT NULL DEFAULT 0, "
        "UNIQUE(destination, event_id));");
    query_2.wait();

    /* Index for efficient per-destination queries */
    const auto query_3 = transPtr->execSqlAsyncFuture(
        "CREATE INDEX federation_queue_destination_idx "
        "ON federation_event_queue (destination);");
    query_3.wait();

    /* Mark the migration as completed */
    const auto query_4 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (14);");
    query_4.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}

void Migrator::migration_v15() {
  LOG_INFO << "Starting database migration v14->v15";
  const auto sql = drogon::app().getDbClient();
  if (sql == nullptr) {
    LOG_FATAL << "No database connection available";
    std::terminate();
  }

  try {
    auto query = sql->execSqlAsyncFuture(
        "select exists(select 1 from migrations where version = 15) as exists");

    if (query.get().at(0)["exists"].as<bool>()) {
      LOG_INFO << "Migration v14->v15 already ran";
      return;
    }
    LOG_DEBUG << "First time migrating to v15";
    const auto transPtr = sql->newTransaction();
    if (transPtr == nullptr) {
      LOG_FATAL << "No database connection available";
      std::terminate();
    }

    /* Transaction ID idempotency table for /send endpoint */
    const auto query_1 = transPtr->execSqlAsyncFuture(
        "CREATE TABLE IF NOT EXISTS transaction_ids ("
        "user_id TEXT NOT NULL, "
        "device_id TEXT NOT NULL, "
        "txn_id TEXT NOT NULL, "
        "room_id TEXT NOT NULL, "
        "event_id TEXT NOT NULL, "
        "created_at BIGINT NOT NULL, "
        "PRIMARY KEY (user_id, device_id, txn_id, room_id));");
    query_1.wait();

    /* Mark the migration as completed */
    const auto query_2 =
        transPtr->execSqlAsyncFuture("INSERT INTO migrations VALUES (15);");
    query_2.wait();
  } catch (const drogon::orm::DrogonDbException &e) {
    LOG_ERROR << e.base().what();
    std::terminate();
  }
}
