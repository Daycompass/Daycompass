-- A time zone per account, for where a day starts and ends in stats
-- and on the dashboard.
--
-- An IANA name such as 'Europe/Berlin', validated by the application
-- (`crate::timezone`) before it is stored. Existing accounts get 'UTC',
-- which is what their stats were already grouped by, so nothing changes
-- for them until they pick a zone. `users` is STRICT, and ADD COLUMN
-- keeps it so.
--
-- Events are untouched: they stay UTC Unix seconds, and the zone is
-- applied at query time only.

ALTER TABLE users ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC';

UPDATE schema_info SET schema_version = 7 WHERE id = 1;
