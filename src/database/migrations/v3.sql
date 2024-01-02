--x, R"(--
/*Create an index for state events*/
CREATE INDEX ON events (room_id, type, state_key) WHERE state_key IS NOT NULL;

/* Mark the migration as completed */
INSERT INTO migrations VALUES (3);
--)"
