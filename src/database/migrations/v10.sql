-- Migration v10: Remove materialized views
--
-- The per-room and per-user materialized views are being removed because:
-- 1. REFRESH MATERIALIZED VIEW CONCURRENTLY on every insert is expensive
-- 2. With proper indexes, direct queries are fast enough
-- 3. temporal_state table now provides efficient state lookups

-- Remove materialized view triggers
DROP TRIGGER IF EXISTS tg_room_view_create ON events;
DROP TRIGGER IF EXISTS tg_user_view_create ON events;

-- Drop the trigger functions
DROP FUNCTION IF EXISTS new_room_view();
DROP FUNCTION IF EXISTS room_view_update(text);
DROP FUNCTION IF EXISTS new_user_view();
DROP FUNCTION IF EXISTS user_view_update(text);

-- Drop all dynamically created materialized views
-- (room_* and user_* views created by the triggers)
DO
$$
    DECLARE
        view_name TEXT;
    BEGIN
        FOR view_name IN
            SELECT matviewname
            FROM pg_matviews
            WHERE schemaname = 'public'
              AND (matviewname LIKE 'room_%' OR matviewname LIKE 'user_%')
            LOOP
                EXECUTE 'DROP MATERIALIZED VIEW IF EXISTS ' || quote_ident(view_name) || ' CASCADE';
            END LOOP;
    END
$$;
