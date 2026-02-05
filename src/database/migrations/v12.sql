-- Migration v12: Add prev_events column for DAG tracking
--
-- The prev_events field is critical for proper DAG (directed acyclic graph) tracking.
-- Currently it only exists inside the JSON blob, making it impossible to efficiently
-- query the DAG structure or find room heads.

-- Add prev_events as queryable array column (using NIDs for efficiency)
ALTER TABLE events
    ADD COLUMN prev_events_nids INTEGER[] NOT NULL DEFAULT '{}';

-- GIN index for efficient array containment queries
CREATE INDEX events_prev_events_gin_idx ON events USING GIN (prev_events_nids);

-- Populate from existing event JSON
-- Note: This requires joining with event_json table since json was moved there
UPDATE events e
SET prev_events_nids = COALESCE(
        (SELECT ARRAY_AGG(e2.event_nid)
         FROM events e2
         WHERE e2.event_id = ANY (
             SELECT jsonb_array_elements_text(ej.json -> 'prev_events')
             FROM event_json ej
             WHERE ej.event_nid = e.event_nid
         )),
        '{}'
                        );
