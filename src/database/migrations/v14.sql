-- v14: Federation event queue and server destination tracking

-- Tracks per-server health for backoff decisions
CREATE TABLE IF NOT EXISTS federation_destinations (
    server_name TEXT PRIMARY KEY,
    last_successful_ts BIGINT,
    last_failure_ts BIGINT,
    failure_count INTEGER NOT NULL DEFAULT 0,
    retry_after_ts BIGINT NOT NULL DEFAULT 0
);

-- Persistent queue of events to deliver to remote servers
CREATE TABLE IF NOT EXISTS federation_event_queue (
    queue_id SERIAL PRIMARY KEY,
    destination TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_json JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(destination, event_id)
);

CREATE INDEX federation_queue_destination_idx
    ON federation_event_queue (destination);
