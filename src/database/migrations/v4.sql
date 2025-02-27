--- Matrix account data table which references the users table user

CREATE TABLE IF NOT EXISTS account_data
(
    id      SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL references public.users (matrix_id) UNIQUE,
    type    TEXT NOT NULL,
    json    TEXT NOT NULL
);

--- Push rules table which references the users table user

CREATE TABLE IF NOT EXISTS push_rules
(
    id      SERIAL PRIMARY KEY,
    user_id TEXT NOT NULL references public.users (matrix_id) UNIQUE,
    json    TEXT NOT NULL
);

--- Mark the migration as completed

INSERT INTO migrations
VALUES (4);