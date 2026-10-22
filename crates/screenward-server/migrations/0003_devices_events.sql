-- Devices, the one-shot codes that pair them, and the screen time
-- events they report.
--
-- Same two conventions as 0002: timestamps are INTEGER Unix seconds
-- (UTC) and every table is STRICT, so SQLite rejects a value of the
-- wrong type instead of coercing it.
--
-- Only hashes of secrets are stored. A device token and a pairing code
-- exist in plaintext exactly once, in the response that hands them out.
--
-- Two things are deliberately absent from `events`, and must stay
-- absent: there is no category column (categories are assigned at query
-- time, from rules, in M3), and there is no column that could hold a
-- window title or a URL. `domain` is a bare hostname and nothing else -
-- no scheme, no path, no query - which is what keeps browser tracking
-- from becoming a browsing history.

CREATE TABLE devices (
    id           TEXT    NOT NULL PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- A display name the owner chose. Normalized by the application
    -- (trimmed, control characters and bidirectional overrides
    -- rejected) before it ever gets here.
    name         TEXT    NOT NULL,
    platform     TEXT    NOT NULL CHECK (
                     platform IN ('android', 'windows', 'macos', 'linux', 'ios')
                 ),
    -- SHA-256 of the full device token, prefix included - the same
    -- scheme as `sessions.token_hash`, with a different token prefix so
    -- the two can never be confused for one another.
    token_hash   BLOB    NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    -- Written at most once a minute per device, not on every request.
    last_seen_at INTEGER NOT NULL,
    -- NULL while the device is live. Set on revocation, which keeps the
    -- row and every event it ever reported.
    revoked_at   INTEGER
) STRICT;

-- Listing one owner's devices, and the cascade from `users`.
CREATE INDEX devices_user_id_idx ON devices (user_id);

CREATE TABLE pairing_codes (
    id         TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the canonical (dash-free, uppercase) code.
    code_hash  BLOB    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    -- NULL until redeemed. Set inside the same transaction that creates
    -- the device, so a code cannot be redeemed twice.
    used_at    INTEGER
) STRICT;

-- Counting one owner's live codes, which is what caps them at five.
CREATE INDEX pairing_codes_user_id_idx ON pairing_codes (user_id);

-- The sweep that deletes spent and expired codes.
CREATE INDEX pairing_codes_expires_at_idx ON pairing_codes (expires_at);

CREATE TABLE events (
    id            TEXT    NOT NULL PRIMARY KEY,
    device_id     TEXT    NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    -- Client-generated, 32 lowercase hex characters. A canonical UUID
    -- is accepted on the wire and stored with its dashes removed, so
    -- the two spellings of one id deduplicate against each other.
    event_id      TEXT    NOT NULL,
    start_ts      INTEGER NOT NULL,
    duration_secs INTEGER NOT NULL,
    app_id        TEXT    NOT NULL,
    label         TEXT,
    -- A bare hostname. Never a URL.
    domain        TEXT,
    received_at   INTEGER NOT NULL,

    -- These bounds are enforced in Rust before an event is ever
    -- inserted; repeating them here is the second line. The insert uses
    -- ON CONFLICT (device_id, event_id) DO NOTHING, which suppresses
    -- exactly the duplicate - every other constraint still raises, so a
    -- disagreement between the validator and this schema fails loudly
    -- instead of silently dropping events.
    --
    -- SQLite's length() counts characters on a TEXT value, which is the
    -- same unit the validator counts in.
    CHECK (duration_secs BETWEEN 1 AND 86400),
    CHECK (length(app_id) BETWEEN 1 AND 256),
    CHECK (label IS NULL OR length(label) <= 128),
    CHECK (domain IS NULL OR length(domain) <= 253)
) STRICT;

-- Idempotent ingest: a resent batch inserts nothing new.
CREATE UNIQUE INDEX events_device_id_event_id_idx ON events (device_id, event_id);

-- The access pattern every later query has: one device, a time range.
CREATE INDEX events_device_id_start_ts_idx ON events (device_id, start_ts);

UPDATE schema_info SET schema_version = 3 WHERE id = 1;
