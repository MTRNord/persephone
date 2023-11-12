--x, R"(--
/* Table for migration tracking */
CREATE TABLE IF NOT EXISTS migrations (version INTEGER NOT NULL);

/* Global events table 
   This is meant to be accompanied with various views for per-room data */
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT NOT NULL CONSTRAINT event_id_unique UNIQUE,
    room_id TEXT NOT NULL, depth BIGINT NOT NULL,
    auth_events TEXT[] NOT NULL,
    rejected BOOLEAN NOT NULL DEFAULT FALSE,
    state_key TEXT,
    type TEXT NOT NULL,
    json TEXT NOT NULL
);

/* Index for membership events (helps also to create the user specific views) */
CREATE INDEX IF NOT EXISTS events_idx ON events (room_id, state_key) WHERE type = 'm.room.member';

/* Create materialized views on insert */
CREATE OR REPLACE FUNCTION new_room_view()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE room_cleared text;
BEGIN
    room_cleared := REPLACE(REPLACE(REPLACE(NEW.room_id, '.', '_'), ':', '_'), '!', '');
    EXECUTE format('CREATE MATERIALIZED VIEW IF NOT EXISTS room_%s AS SELECT * FROM events WHERE room_id = ''%s'';', room_cleared, NEW.room_id);
    EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS room_%s_idx ON room_%s (event_id);', room_cleared, room_cleared);
    RETURN NULL;
END;
$$; 

/* Create trigger to create the room view */
CREATE TRIGGER tg_room_view_create AFTER INSERT ON events FOR EACH ROW EXECUTE FUNCTION new_room_view();

/* Create update fn which needs to be called manually as we can batch this in the app logic */
CREATE OR REPLACE FUNCTION room_view_update(room_id text)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE room_cleared text;
BEGIN
    room_cleared := REPLACE(REPLACE(REPLACE(room_id, '.', '_'), ':', '_'), '!', '');
    EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY room_%s;', room_cleared);
END;
$$;

/* User View - Create materialized view on insert. This view only contains for each user the membership events */
CREATE OR REPLACE FUNCTION new_user_view()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state_key_cleared text;
BEGIN
    CASE 
        WHEN NEW.state_key IS NOT NULL THEN
            state_key_cleared := REPLACE(REPLACE(REPLACE(NEW.state_key, '.', '_'), ':', '_'), '@', '');
            EXECUTE format('CREATE MATERIALIZED VIEW IF NOT EXISTS user_%s AS SELECT * FROM events WHERE type = ''m.room.member'' AND state_key = ''%s'';', state_key_cleared, NEW.state_key);
            EXECUTE format('CREATE UNIQUE INDEX IF NOT EXISTS user_%s_idx ON user_%s (event_id);', state_key_cleared, state_key_cleared);
        ELSE
            -- Do nothing
    END CASE;
    RETURN NULL;
END;
$$;

CREATE TRIGGER tg_user_view_create AFTER INSERT ON events FOR EACH ROW EXECUTE FUNCTION new_user_view();

CREATE OR REPLACE FUNCTION user_view_update(state_key text)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE state_key_cleared text;
BEGIN
    state_key_cleared := REPLACE(REPLACE(REPLACE(state_key, '.', '_'), ':', '_'), '@', '');
    EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY user_%s;', state_key_cleared);
END;
$$;

/* Mark the migration as completed */
INSERT INTO migrations VALUES (1);
--)"