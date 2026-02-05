-- Migration v7: Numeric ID (NID) lookup tables for storage efficiency
--
-- This implements Dendrite-style NIDs to reduce storage overhead.
-- Instead of storing full text strings (event_id, room_id, event_type)
-- repeatedly, we store them once and reference by integer.

-- Create lookup table for event types
CREATE TABLE IF NOT EXISTS event_types
(
    event_type_nid SERIAL PRIMARY KEY,
    event_type     TEXT NOT NULL UNIQUE
);

-- Create lookup table for state keys
CREATE TABLE IF NOT EXISTS state_keys
(
    state_key_nid SERIAL PRIMARY KEY,
    state_key     TEXT NOT NULL UNIQUE
);

-- Create lookup table for rooms
CREATE TABLE IF NOT EXISTS rooms
(
    room_nid SERIAL PRIMARY KEY,
    room_id  TEXT NOT NULL UNIQUE
);

-- Pre-populate common event types for efficiency
INSERT INTO event_types (event_type)
VALUES ('m.room.create'),
       ('m.room.member'),
       ('m.room.message'),
       ('m.room.power_levels'),
       ('m.room.join_rules'),
       ('m.room.name'),
       ('m.room.topic'),
       ('m.room.avatar'),
       ('m.room.canonical_alias'),
       ('m.room.history_visibility'),
       ('m.room.guest_access'),
       ('m.room.encryption'),
       ('m.room.server_acl'),
       ('m.room.tombstone'),
       ('m.room.pinned_events'),
       ('m.room.third_party_invite'),
       ('m.reaction'),
       ('m.room.redaction')
ON CONFLICT DO NOTHING;

-- Add event_nid as the new primary identifier for events
ALTER TABLE events
    ADD COLUMN event_nid SERIAL;

-- Add NID reference columns to events table
ALTER TABLE events
    ADD COLUMN room_nid       INTEGER,
    ADD COLUMN event_type_nid INTEGER,
    ADD COLUMN state_key_nid  INTEGER;

-- Populate rooms lookup from existing events
INSERT INTO rooms (room_id)
SELECT DISTINCT room_id
FROM events
ON CONFLICT DO NOTHING;

-- Populate event_types lookup from existing events
INSERT INTO event_types (event_type)
SELECT DISTINCT type
FROM events
ON CONFLICT DO NOTHING;

-- Populate state_keys lookup from existing events (non-null only)
INSERT INTO state_keys (state_key)
SELECT DISTINCT state_key
FROM events
WHERE state_key IS NOT NULL
ON CONFLICT DO NOTHING;

-- Update events with NID references
UPDATE events e
SET room_nid       = (SELECT room_nid FROM rooms WHERE room_id = e.room_id),
    event_type_nid = (SELECT event_type_nid FROM event_types WHERE event_type = e.type),
    state_key_nid  = (SELECT state_key_nid FROM state_keys WHERE state_key = e.state_key);

-- Make room_nid NOT NULL after population
ALTER TABLE events
    ALTER COLUMN room_nid SET NOT NULL;

-- Make event_type_nid NOT NULL after population
ALTER TABLE events
    ALTER COLUMN event_type_nid SET NOT NULL;

-- Add foreign key constraints
ALTER TABLE events
    ADD CONSTRAINT events_room_nid_fk
        FOREIGN KEY (room_nid) REFERENCES rooms (room_nid);

ALTER TABLE events
    ADD CONSTRAINT events_event_type_nid_fk
        FOREIGN KEY (event_type_nid) REFERENCES event_types (event_type_nid);

ALTER TABLE events
    ADD CONSTRAINT events_state_key_nid_fk
        FOREIGN KEY (state_key_nid) REFERENCES state_keys (state_key_nid);

-- Create indexes on NID columns for efficient lookups
CREATE INDEX events_room_nid_idx ON events (room_nid);
CREATE INDEX events_room_nid_depth_idx ON events (room_nid, depth DESC);
CREATE INDEX events_type_nid_idx ON events (event_type_nid);
CREATE INDEX events_state_key_nid_idx ON events (state_key_nid) WHERE state_key_nid IS NOT NULL;

-- Create unique index on event_nid
CREATE UNIQUE INDEX events_event_nid_idx ON events (event_nid);
