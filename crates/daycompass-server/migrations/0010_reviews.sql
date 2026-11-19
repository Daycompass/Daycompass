-- Weekly reviews: what the account holder wrote about one ISO week,
-- and the weekly goals that week was measured against.
--
-- Synced like the three missions tables (`0008_missions.sql`): last
-- write wins on `updated_at`, a tombstone keeps no text, and `rev`
-- takes the next value of the shared `users.missions_rev`.
--
-- # Key
--
-- `(user_id, week_start)`, not a client-generated id: one week has one
-- review, so two devices that review the same week offline write the
-- same record and last write wins between them, instead of leaving two.
-- `week_start` is the week's Monday, TEXT 'YYYY-MM-DD' in the account's
-- time zone, like `tasks.day`.
--
-- # Goal snapshot
--
-- `goals` is a JSON array of `{"mission_id", "weekly_goal_secs"}`,
-- taken when the review is first written, so a goal changed afterwards
-- does not rewrite how that week is judged. Only ids and numbers: a
-- mission's title stays on the mission, and goes when it is deleted.
-- Validated by the application (`crate::missions::validate::review`);
-- the CHECKs are the second line.

CREATE TABLE reviews (
    user_id     TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    week_start  TEXT    NOT NULL,
    went_well   TEXT,
    went_badly  TEXT,
    change_next TEXT,
    goals       TEXT    NOT NULL,
    deleted     INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    rev         INTEGER NOT NULL,

    PRIMARY KEY (user_id, week_start),
    CHECK (length(week_start) = 10),
    CHECK (json_valid(goals) AND json_type(goals) = 'array'),
    CHECK (deleted IN (0, 1)),
    CHECK (went_well IS NULL OR length(went_well) <= 2000),
    CHECK (went_badly IS NULL OR length(went_badly) <= 2000),
    CHECK (change_next IS NULL OR length(change_next) <= 2000),
    CHECK (deleted = 0
           OR (went_well IS NULL AND went_badly IS NULL AND change_next IS NULL))
) STRICT;

CREATE UNIQUE INDEX reviews_user_id_rev_idx ON reviews (user_id, rev);

-- The weekday the dashboard asks for a review on, ISO numbered
-- (1 = Monday, 7 = Sunday). Dashboard-only, not synced. `users` is
-- STRICT, and ADD COLUMN keeps it so.
ALTER TABLE users ADD COLUMN review_day INTEGER NOT NULL DEFAULT 7
    CHECK (review_day BETWEEN 1 AND 7);

UPDATE schema_info SET schema_version = 10 WHERE id = 1;
