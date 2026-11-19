-- The account's North Star: one line, written by the account holder,
-- naming what all of their missions are for. Shown above the missions
-- on the dashboard.
--
-- NULL means none. Validated by the application
-- (`crate::missions::validate::north_star`) before it is stored; the
-- CHECK is the second line. `users` is STRICT, and ADD COLUMN keeps
-- it so.

ALTER TABLE users ADD COLUMN north_star TEXT
    CHECK (north_star IS NULL OR length(north_star) BETWEEN 1 AND 200);

UPDATE schema_info SET schema_version = 9 WHERE id = 1;
