-- Migration v6: Server signing key cache for federation
--
-- This table caches public signing keys from remote Matrix servers
-- to avoid repeatedly fetching them during signature verification.

-- Create table for caching remote server signing keys
CREATE TABLE IF NOT EXISTS server_signing_keys
(
    server_name    TEXT   NOT NULL,
    key_id         TEXT   NOT NULL,
    public_key     TEXT   NOT NULL,
    valid_until_ts BIGINT NOT NULL,
    fetched_at     BIGINT NOT NULL,
    PRIMARY KEY (server_name, key_id)
);

-- Create index for cleanup queries (find expired keys efficiently)
CREATE INDEX IF NOT EXISTS server_signing_keys_valid_until_idx
    ON server_signing_keys (valid_until_ts);
