-- An index on `events.start_ts` alone, for the retention sweep (M4).
--
-- The sweep deletes every event older than a cutoff across all devices
-- at once. The existing `(device_id, start_ts)` index leads with the
-- device, so it cannot answer "everything before this time" without a
-- full table scan - which the sweep would otherwise pay hourly, even
-- on the many runs where there is nothing to delete.
--
-- Only an index: no table, no column, no data changes.

CREATE INDEX events_start_ts_idx ON events (start_ts);

UPDATE schema_info SET schema_version = 6 WHERE id = 1;
