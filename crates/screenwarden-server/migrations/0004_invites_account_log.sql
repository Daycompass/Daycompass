-- Invite-based onboarding, and the account log that makes an admin
-- password reset visible to the account it happened to.
--
-- `users.status` replaces "an admin always sets a real password": a
-- pending account has no usable password at all (`password_hash = ''`,
-- not a PHC string), and the Rust type at the service layer
-- (`auth::store::Credential`) forces every reader to say what happens
-- for one rather than falling through to a real hash comparison.
--
-- `password_hash` stays `NOT NULL` rather than becoming nullable: the
-- column is typed `TEXT NOT NULL` since 0002, and SQLite has no way to
-- widen that in place without rebuilding the table, which would risk
-- cascading away every session, device and event via `ON DELETE
-- CASCADE` - `PRAGMA foreign_keys` has no effect inside sqlx's
-- migration transaction. An empty string is the sentinel instead; it
-- can never verify as a password (`auth::password::Hasher::verify`
-- rejects `""` as malformed), but no code path reaches that check for a
-- pending account in the first place.
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'pending'));

CREATE TABLE invite_tokens (
    id         TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256 of the full token, prefix included - same scheme as every
    -- other token hash in this schema.
    token_hash BLOB    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    -- NULL until redeemed. Set on use so the token is single-use even
    -- before it expires.
    used_at    INTEGER
) STRICT;

-- Looking up and clearing one account's invites (account creation
-- deletes none yet, but a password reset replaces every earlier one).
CREATE INDEX invite_tokens_user_id_idx ON invite_tokens (user_id);

-- The cleanup sweep's indexed DELETE for spent and expired tokens.
CREATE INDEX invite_tokens_expires_at_idx ON invite_tokens (expires_at);

CREATE TABLE account_log (
    id       TEXT    NOT NULL PRIMARY KEY,
    user_id  TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind     TEXT    NOT NULL CHECK (kind IN
                 ('invite_redeemed', 'password_reset_by_admin',
                  'password_changed')),
    -- The acting admin for `password_reset_by_admin`; NULL for the
    -- other two kinds, which are the account acting on itself.
    --
    -- Deliberately not a foreign key: deleting the acting admin's
    -- account must not be able to rewrite or erase this entry. The
    -- `user_id` column above *is* a cascade, but deleting the subject
    -- account takes its own log with it, which is deletion of the
    -- account, not editing of the log.
    actor_id TEXT,
    at       INTEGER NOT NULL
) STRICT;

-- One account's log, newest first - the only access pattern this table
-- has, since only the account itself may read it.
CREATE INDEX account_log_user_id_at_idx ON account_log (user_id, at);

UPDATE schema_info SET schema_version = 4 WHERE id = 1;
