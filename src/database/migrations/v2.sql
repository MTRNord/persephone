--x, R"(--
-- Used to generate the users table
-- These are LOCAL users only.
CREATE TABLE IF NOT EXISTS users (
    matrix_id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    avatar_url TEXT,
    display_name TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    matrix_id TEXT NOT NULL references users(matrix_id),
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    access_token TEXT NOT NULL,
    PRIMARY KEY (matrix_id, device_id)
);

/* Mark the migration as completed */
INSERT INTO migrations VALUES (2);
--)"