-- First domain tables: accounts, their login sessions, and the one-shot
-- tokens used to create the very first admin.
--
-- Two conventions that differ from 0001 on purpose:
--
--   * Timestamps are INTEGER Unix seconds (UTC), not ISO-8601 TEXT.
--     Every timestamp here feeds an expiry comparison, and integers make
--     that comparison timezone-proof and format-proof in both SQL and
--     Rust. Read them back with datetime(col, 'unixepoch') when poking
--     at the database by hand.
--   * The tables are STRICT, so SQLite rejects a value whose type does
--     not match the column instead of silently coercing it.
--
-- Only hashes of secrets are stored. There is deliberately no column
-- anywhere below that could hold a plaintext password or token.

CREATE TABLE users (
    id            TEXT    NOT NULL PRIMARY KEY,
    -- Always stored lowercase; the application normalizes before any
    -- insert or lookup, so this UNIQUE constraint is case-correct.
    username      TEXT    NOT NULL UNIQUE,
    -- Argon2id PHC string ("$argon2id$v=19$m=...,t=...,p=...$salt$hash").
    -- The parameters are part of the string, which is what lets a login
    -- notice that a stored hash is weaker than the current settings.
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'user')),
    created_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE sessions (
    id           TEXT    NOT NULL PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the full session token, prefix included. The token
    -- itself only ever exists in the response that created it and in the
    -- client's cookie.
    token_hash   BLOB    NOT NULL UNIQUE,
    -- There is no csrf_hash column: the per-session CSRF token is
    -- derived from the session token by hashing it with a fixed
    -- domain-separation prefix, so it needs no storage and is identical
    -- across reloads and tabs.
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
) STRICT;

-- Looking up every session of one user (session management, cascade).
CREATE INDEX sessions_user_id_idx ON sessions (user_id);

-- The cleanup task sweeps absolute and idle expiry separately, one
-- indexed DELETE each, rather than a single OR that could use neither.
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_last_used_at_idx ON sessions (last_used_at);

CREATE TABLE setup_tokens (
    id         TEXT    NOT NULL PRIMARY KEY,
    token_hash BLOB    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    -- NULL until redeemed. Set on use so the token is single-use even
    -- before it expires.
    used_at    INTEGER
) STRICT;

UPDATE schema_info SET schema_version = 2 WHERE id = 1;
