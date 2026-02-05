-- Migration v9: Temporal state table (Matthew Hodgson's approach)
--
-- Instead of storing full state snapshots or delta chains, track state event lifetimes.
-- Each state event has a start_index (when it became active) and end_index (when replaced).
-- This enables efficient queries for both current and historical state.

-- Create temporal state tracking table
CREATE TABLE IF NOT EXISTS temporal_state
(
    room_nid       INTEGER NOT NULL REFERENCES rooms (room_nid),
    event_type_nid INTEGER NOT NULL REFERENCES event_types (event_type_nid),
    state_key_nid  INTEGER NOT NULL REFERENCES state_keys (state_key_nid),
    event_nid      INTEGER NOT NULL REFERENCES events (event_nid),
    start_index    BIGINT  NOT NULL, -- ordering/depth when state became active
    end_index      BIGINT,           -- NULL = current, value = when replaced
    ordering       INTEGER,          -- for BFS-ordered compression
    PRIMARY KEY (room_nid, event_type_nid, state_key_nid, start_index)
);

-- Partial index for current state (fast lookups)
CREATE INDEX temporal_state_current_idx
    ON temporal_state (room_nid) WHERE end_index IS NULL;

-- Index for historical state queries
CREATE INDEX temporal_state_historical_idx
    ON temporal_state (room_nid, start_index, end_index);

-- Index for ordering-based scans (compression)
CREATE INDEX temporal_state_ordering_idx
    ON temporal_state (room_nid, ordering);

-- Populate from existing state events
INSERT INTO temporal_state (room_nid, event_type_nid, state_key_nid, event_nid, start_index)
SELECT e.room_nid, e.event_type_nid, e.state_key_nid, e.event_nid, e.depth
FROM events e
WHERE e.state_key_nid IS NOT NULL
ORDER BY e.room_nid, e.event_type_nid, e.state_key_nid, e.depth;

-- Update end_index for superseded state using window function
WITH ranked AS (SELECT room_nid,
                       event_type_nid,
                       state_key_nid,
                       start_index,
                       LEAD(start_index) OVER (
                           PARTITION BY room_nid, event_type_nid, state_key_nid
                           ORDER BY start_index
                           ) as next_start
                FROM temporal_state)
UPDATE temporal_state ts
SET end_index = r.next_start
FROM ranked r
WHERE ts.room_nid = r.room_nid
  AND ts.event_type_nid = r.event_type_nid
  AND ts.state_key_nid = r.state_key_nid
  AND ts.start_index = r.start_index
  AND r.next_start IS NOT NULL;
