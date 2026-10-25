-- An account's own rules for turning an event's `app_id` or `domain`
-- into a category, read at query time (see migration `0003`'s note on
-- why `events` itself carries no category column, and
-- `crate::categories` for the matching semantics).
--
-- Same conventions as every table before this one: STRICT, and
-- `created_at` is an INTEGER Unix second.
--
-- `UNIQUE (user_id, kind, pattern)` is the whole uniqueness rule: an
-- account may not hold two rules of the same kind for the same
-- pattern, whatever category each names. Scoped by `user_id` rather
-- than instance-wide, because a rule is one account's own
-- categorization preference, not a shared taxonomy - same ownership
-- model as `devices` and the one read path into `events`.
--
-- The two `CHECK`s mirror the Rust-side bounds in `categories::kind`
-- and `categories::label` as a second line of defense, the same
-- reasoning as the `CHECK`s on `events` in migration `0003`.

CREATE TABLE category_rules (
    id         TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('app_id', 'domain')),
    pattern    TEXT    NOT NULL,
    category   TEXT    NOT NULL,
    created_at INTEGER NOT NULL,

    CHECK (length(pattern) BETWEEN 1 AND 253),
    CHECK (length(category) BETWEEN 1 AND 64)
) STRICT;

-- The uniqueness rule, and the lookup a duplicate insert relies on to
-- fail loudly rather than being pre-checked by a separate SELECT.
CREATE UNIQUE INDEX category_rules_user_id_kind_pattern_idx
    ON category_rules (user_id, kind, pattern);

-- Listing and counting one owner's rules, and the cascade from `users`.
CREATE INDEX category_rules_user_id_idx ON category_rules (user_id);

UPDATE schema_info SET schema_version = 5 WHERE id = 1;
