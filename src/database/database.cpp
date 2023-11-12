#include "database.hpp"

void Database::migrate() { this->migration_v1(); }

void Database::migration_v1() {
  session sql(this->pool);
  transaction tr(sql);

  // Table for migration tracking
  sql << "CREATE TABLE IF NOT EXISTS migrations (version INTEGER NOT NULL);";

  // Global events table
  // This is meant to be accompanied with various views for per-room data
  sql << "CREATE TABLE IF NOT EXISTS events (event_id TEXT NOT NULL CONSTRAINT "
         "event_id_unique UNIQUE, room_id TEXT NOT NULL, depth BIGINT NOT "
         "NULL, auth_events TEXT[] NOT NULL, rejected BOOLEAN NOT NULL DEFAULT "
         "FALSE, state_key TEXT, type TEXT NOT NULL);";

  // Index for membership events (helps also to create the user specific views)
  sql << "CREATE INDEX IF NOT EXISTS events_idx ON events (room_id, state_key) "
         "WHERE type = 'm.room.member';";

  // Create materialized views on insert
  sql << "CREATE OR REPLACE FUNCTION new_room_view() "
         "RETURNS trigger LANGUAGE plpgsql AS $$ "
         "BEGIN "
         "    CREATE MATERIALIZED VIEW IF NOT EXISTS 'room_' || NEW.room_id AS "
         "        SELECT * WHERE room_id = NEW.room_id; "
         "    RETURN NULL; "
         "END; "
         "$$;";
  // Create trigger to call function
  sql << "CREATE TRIGGER tg_room_view_create AFTER INSERT "
         "ON events "
         "FOR EACH STATEMENT EXECUTE FUNCTION new_room_view();";

  // Create update fn which needs to be called manually as we can batch this in
  // the app logic
  sql << "CREATE OR REPLACE FUNCTION new_room_view_update() "
         "RETURNS trigger LANGUAGE plpgsql AS $$ "
         "BEGIN "
         "    REFRESH MATERIALIZED VIEW CONCURRENTLY 'room_' || OLD.room_id; "
         "    RETURN NULL; "
         "END; "
         "$$;";

  // User View
  // Create materialized views on insert
  // This view only contains for each room the latest membership event
  sql << "CREATE OR REPLACE FUNCTION new_user_view() "
         "RETURNS trigger LANGUAGE plpgsql AS $$ "
         "BEGIN "
         "    CREATE MATERIALIZED VIEW IF NOT EXISTS 'membership_' || "
         "        NEW.state_key AS SELECT * WHERE room_id = NEW.room_id AND "
         "        type = 'm.room.member' AND state_key = NEW.state_key; "
         "    RETURN NULL; "
         "END; "
         "$$;";

  // Mark the migration as completed
  sql << "INSERT INTO migrations VALUES (1);";
  tr.commit();
}