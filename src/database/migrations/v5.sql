-- Migrate to jsonb

-- Migrate the events table field "json" to jsonb
ALTER TABLE events
    ADD COLUMN json2 JSONB;
UPDATE events
SET json2 = to_json(json)
WHERE LEFT(json, 1) = 'p'
   OR LEFT(json, 1) = '{';
UPDATE events
SET json2 = to_json(json::numeric)
WHERE LEFT(json, 1) != 'p'
  AND LEFT(json, 1) != '{';
ALTER TABLE events
    DROP COLUMN json;
ALTER TABLE events
    RENAME COLUMN json2 TO json;

-- Create table for filters where we deduplicate by filter content
CREATE TABLE IF NOT EXISTS filters
(
    id       SERIAL PRIMARY KEY,
    user_ids TEXT[] NOT NULL UNIQUE,
    json     JSONB  NOT NULL UNIQUE
);