-- Screen time on the Missions pages: whether the account wants it at
-- all, and which of its categories count as distraction.
--
-- Settings only. Events are untouched and still carry no category: the
-- marked names are matched against each event's category at query
-- time, like everything else about categories. A name no rule or
-- built-in entry produces any more simply matches nothing.

-- 1: Today, Log and Review read the account's own screen time. 0: they
-- read none. `users` is STRICT, and ADD COLUMN keeps it so.
ALTER TABLE users ADD COLUMN missions_screen_time INTEGER NOT NULL DEFAULT 1
    CHECK (missions_screen_time IN (0, 1));

-- No rows: nothing counts as distraction, and no distraction number is
-- shown.
CREATE TABLE distraction_categories (
    user_id  TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Same bounds as a category rule's label.
    category TEXT NOT NULL CHECK (length(category) BETWEEN 1 AND 64),

    PRIMARY KEY (user_id, category)
) STRICT;

UPDATE schema_info SET schema_version = 11 WHERE id = 1;
