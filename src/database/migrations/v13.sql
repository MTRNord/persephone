-- Migration v13: Add referential integrity constraints
--
-- These constraints prevent data corruption by ensuring referential integrity.
-- Lessons learned from Matrix.org Postgres corruption incident (July 2025).

-- Foreign key on devices.matrix_id (if not already exists)
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM information_schema.table_constraints
                       WHERE constraint_name = 'devices_matrix_id_fk'
                         AND table_name = 'devices') THEN
            ALTER TABLE devices
                ADD CONSTRAINT devices_matrix_id_fk
                    FOREIGN KEY (matrix_id) REFERENCES users (matrix_id) ON DELETE CASCADE;
        END IF;
    END
$$;

-- Foreign key on account_data.user_id (if not already exists)
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM information_schema.table_constraints
                       WHERE constraint_name = 'account_data_user_id_fk'
                         AND table_name = 'account_data') THEN
            ALTER TABLE account_data
                ADD CONSTRAINT account_data_user_id_fk
                    FOREIGN KEY (user_id) REFERENCES users (matrix_id) ON DELETE CASCADE;
        END IF;
    END
$$;

-- Foreign key on push_rules.user_id (if not already exists)
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM information_schema.table_constraints
                       WHERE constraint_name = 'push_rules_user_id_fk'
                         AND table_name = 'push_rules') THEN
            ALTER TABLE push_rules
                ADD CONSTRAINT push_rules_user_id_fk
                    FOREIGN KEY (user_id) REFERENCES users (matrix_id) ON DELETE CASCADE;
        END IF;
    END
$$;

-- Foreign key on temporal_state.event_nid with RESTRICT (prevent deleting active state)
DO
$$
    BEGIN
        IF NOT EXISTS (SELECT 1
                       FROM information_schema.table_constraints
                       WHERE constraint_name = 'temporal_state_event_exists'
                         AND table_name = 'temporal_state') THEN
            ALTER TABLE temporal_state
                ADD CONSTRAINT temporal_state_event_exists
                    FOREIGN KEY (event_nid) REFERENCES events (event_nid) ON DELETE RESTRICT;
        END IF;
    END
$$;

-- Trigger to prevent deleting events that are referenced as prev_events
-- (Array FKs are not natively supported in PostgreSQL)
CREATE OR REPLACE FUNCTION check_event_not_referenced()
    RETURNS TRIGGER AS
$$
BEGIN
    IF EXISTS (SELECT 1 FROM events WHERE OLD.event_nid = ANY (prev_events_nids)) THEN
        RAISE EXCEPTION 'Cannot delete event % - referenced by other events as prev_events', OLD.event_id;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS prevent_referenced_event_delete ON events;
CREATE TRIGGER prevent_referenced_event_delete
    BEFORE DELETE
    ON events
    FOR EACH ROW
EXECUTE FUNCTION check_event_not_referenced();
