-- A single-row table recording which Screenward schema version this
-- database is at. This is distinct from sqlx's own `_sqlx_migrations`
-- bookkeeping table: that one tracks which migration files have run,
-- this one lets the application itself read its schema version at
-- runtime. No user or device tables yet - those come later.

CREATE TABLE schema_info (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT INTO schema_info (id, schema_version) VALUES (1, 1);
