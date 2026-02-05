-- Migration v8: Separate event JSON storage
--
-- This separates event JSON content from event metadata for:
-- 1. Smaller events table = faster scans and index updates
-- 2. JSON only fetched when needed
-- 3. Easier to compress/archive old event content

-- Create separate table for event JSON content
CREATE TABLE IF NOT EXISTS event_json
(
    event_nid INTEGER PRIMARY KEY REFERENCES events (event_nid),
    json      JSONB NOT NULL
);

-- Migrate existing JSON data from events table
INSERT INTO event_json (event_nid, json)
SELECT event_nid, json
FROM events;

-- Drop the json column from events table
ALTER TABLE events DROP COLUMN json;
