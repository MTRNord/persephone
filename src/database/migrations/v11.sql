-- Migration v11: Add missing indexes
--
-- These indexes improve query performance for common operations.

-- Index on event_id for direct lookups
CREATE INDEX IF NOT EXISTS events_event_id_idx ON events (event_id);

-- Index on devices.matrix_id for FK lookups
CREATE INDEX IF NOT EXISTS devices_matrix_id_idx ON devices (matrix_id);

-- Composite index for state event lookups using NIDs
CREATE INDEX IF NOT EXISTS events_state_lookup_nid_idx
    ON events (room_nid, event_type_nid, state_key_nid)
    WHERE state_key_nid IS NOT NULL;
