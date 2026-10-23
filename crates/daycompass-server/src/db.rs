//! SQLite pool setup, hardening, and embedded migrations.
//!
//! Migrations live in `migrations/` and are embedded into the binary at
//! compile time. No device or event tables exist yet.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Database filename inside the data directory.
pub const DB_FILE_NAME: &str = "daycompass.sqlite3";

/// The filename used before the Screenward -> Screenwarden rename. Only
/// checked for at startup, to refuse an upgrade that would otherwise
/// silently start from an empty database under the new name.
const LEGACY_DB_FILE_NAME: &str = "screenward.sqlite3";

/// SQLite's WAL auxiliary files, under the legacy name. `connect` below
/// opens every database - old name or new - in WAL mode, so these are
/// not incidental: recent commits can live in `-wal` and not yet be in
/// the main file at all, and `-shm` is the index a reader needs to make
/// sense of it.
const LEGACY_WAL_FILE_NAME: &str = "screenward.sqlite3-wal";
const LEGACY_SHM_FILE_NAME: &str = "screenward.sqlite3-shm";

/// How long a connection waits on a lock before giving up.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Database setup/connection failures. Messages describe what failed,
/// not with what value, so they are safe to log or print directly.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("failed to create the data directory")]
    CreateDataDir(#[source] std::io::Error),

    #[error("failed to set permissions on the data directory")]
    SetDataDirPermissions(#[source] std::io::Error),

    #[error("failed to create the database file")]
    CreateDbFile(#[source] std::io::Error),

    #[error("failed to set permissions on the database file")]
    SetDbFilePermissions(#[source] std::io::Error),

    #[error("failed to connect to the database")]
    Connect(#[source] sqlx::Error),

    #[error("failed to run database migrations")]
    Migrate(#[source] sqlx::migrate::MigrateError),

    /// The new main file does not exist yet, so renaming every legacy
    /// file onto its matching new name is safe - there is nothing
    /// there to overwrite.
    #[error(
        "found a legacy screenward.sqlite3* file in the data directory; \
         stop the server cleanly, then rename every file named \
         screenward.sqlite3* - including -wal and -shm - to the matching \
         daycompass.sqlite3* name, and restart"
    )]
    LegacyDatabaseFile,

    /// The new main file already exists - this is the case
    /// `LegacyDatabaseFile`'s blanket "rename every file" instruction
    /// must never be given for, since a rename that lands on an
    /// existing `daycompass.sqlite3*` overwrites it and can destroy
    /// live data.
    #[error(
        "found a non-empty legacy screenward.sqlite3-wal next to an \
         existing daycompass.sqlite3; stop the server cleanly, and \
         never overwrite daycompass.sqlite3* by renaming a legacy \
         file onto it. If daycompass.sqlite3 was only just created \
         by renaming the old main file, rename screenward.sqlite3-wal \
         (and -shm, if present) to match it the same way; if \
         daycompass.sqlite3 already held live data, move the legacy \
         files out of the data directory instead"
    )]
    LegacyWalAlongsideNewFile,

    /// Checking for a legacy file failed for a reason other than it not
    /// being there - most likely a permissions problem. Names the path
    /// and nothing else: no directory listing, no error text from
    /// anywhere but this one `io::Error`.
    #[error("failed to check for a legacy database file at {}", path.display())]
    CheckLegacyDatabaseFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Where the database lives.
pub enum DbTarget {
    /// A real SQLite file inside `data_dir`, hardened to 0600/0700.
    File { data_dir: PathBuf },
    /// A private in-memory database. For tests only.
    Memory,
}

/// Opens a connection pool for `target`, applying WAL mode, foreign key
/// enforcement, and a busy timeout. For [`DbTarget::File`], also creates
/// the data directory (0700) and the database file (0600) if missing.
pub async fn connect(target: &DbTarget) -> Result<SqlitePool, DbError> {
    let (connect_options, pool_options) = match target {
        DbTarget::File { data_dir } => {
            check_for_legacy_db_files(data_dir)?;

            harden_data_dir(data_dir)?;
            let db_path = data_dir.join(DB_FILE_NAME);
            harden_db_file(&db_path)?;

            let options = SqliteConnectOptions::new()
                .filename(&db_path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .foreign_keys(true)
                .busy_timeout(BUSY_TIMEOUT);
            (options, SqlitePoolOptions::new().max_connections(5))
        }
        DbTarget::Memory => {
            let options = SqliteConnectOptions::new()
                .filename(":memory:")
                .foreign_keys(true)
                .busy_timeout(BUSY_TIMEOUT);
            // More than one pooled connection to ":memory:" would each get
            // their own, separate, empty database. A single connection
            // makes the whole pool share the one in-memory database.
            (options, SqlitePoolOptions::new().max_connections(1))
        }
    };

    pool_options
        .connect_with(connect_options)
        .await
        .map_err(DbError::Connect)
}

/// Runs the embedded migrations against `pool`. Safe to call more than
/// once: already-applied migrations are skipped.
pub async fn migrate(pool: &SqlitePool) -> Result<(), DbError> {
    sqlx::migrate!().run(pool).await.map_err(DbError::Migrate)
}

/// Checks the database is reachable with a trivial query.
pub async fn check_reachable(pool: &SqlitePool) -> Result<(), DbError> {
    sqlx::query("SELECT 1")
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Connect)
}

/// Refuses to start if the data directory shows the Screenward ->
/// Screenwarden rename was missed or only partly done - or shows a
/// stray legacy WAL it would be dangerous to advise renaming onto an
/// already-present new file.
///
/// Two independent checks, returning one of two errors depending on
/// whether the new main file already exists - that is what decides
/// whether "just rename everything" is safe advice to give:
///
///   * A non-empty `screenward.sqlite3-wal` is refused **regardless**
///     of whether `daycompass.sqlite3` already exists. A WAL file is
///     only ever read by a connection to the exact main-file name it
///     was created next to, so a connection to the new name never
///     looks at the old one's `-wal` at all - any commits still
///     sitting in it are not stale, they are permanently orphaned. An
///     empty one (just past a clean checkpoint) has nothing left to
///     lose, so it does not trip this; otherwise a leftover from a
///     *completed* rename, long since harmless, would block every
///     later start forever. This is [`DbError::LegacyWalAlongsideNewFile`]
///     if the new main file exists already - where a blanket rename
///     would overwrite it - or the ordinary [`DbError::LegacyDatabaseFile`]
///     if it does not.
///   * Otherwise, if the new main file is missing, any legacy file at
///     all - the main one or either auxiliary - means the rename was
///     never done, or was done only for some of the files:
///     [`DbError::LegacyDatabaseFile`], since nothing exists yet at the
///     new name for a rename to clobber.
fn check_for_legacy_db_files(data_dir: &Path) -> Result<(), DbError> {
    let new_main_file_exists = path_exists(&data_dir.join(DB_FILE_NAME))?;

    if wal_is_non_empty(&data_dir.join(LEGACY_WAL_FILE_NAME))? {
        return Err(if new_main_file_exists {
            DbError::LegacyWalAlongsideNewFile
        } else {
            DbError::LegacyDatabaseFile
        });
    }

    if new_main_file_exists {
        return Ok(());
    }

    for name in [
        LEGACY_DB_FILE_NAME,
        LEGACY_WAL_FILE_NAME,
        LEGACY_SHM_FILE_NAME,
    ] {
        if path_exists(&data_dir.join(name))? {
            return Err(DbError::LegacyDatabaseFile);
        }
    }

    Ok(())
}

/// `Path::exists` swallows every error - a permissions problem looks
/// exactly like "not there" - which is the wrong default for a check
/// whose whole point is not to be fooled into starting from an empty
/// database. `try_exists` is the same check with that one difference:
/// a real I/O error is reported instead of silently read as `false`.
fn path_exists(path: &Path) -> Result<bool, DbError> {
    path.try_exists()
        .map_err(|source| DbError::CheckLegacyDatabaseFile {
            path: path.to_owned(),
            source,
        })
}

/// Whether `path` is a legacy WAL file that is not empty.
///
/// Non-empty does not *prove* there are writes SQLite would still
/// need to checkpoint: the default `PASSIVE` checkpoint mode copies
/// frames into the main file without truncating the WAL back to
/// zero, so a fully checkpointed WAL can sit at a nonzero size
/// indefinitely. This is a deliberately conservative proxy - "might
/// still matter, treat it as live" - not a certificate that it does.
///
/// A missing file is `false`, not an error - there is nothing to lose
/// if it was never there - but any other failure to read its size
/// (most likely a permissions problem) is propagated rather than
/// treated as "empty".
fn wal_is_non_empty(path: &Path) -> Result<bool, DbError> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(meta.len() > 0),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(DbError::CheckLegacyDatabaseFile {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(unix)]
fn harden_data_dir(dir: &Path) -> Result<(), DbError> {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(dir).map_err(DbError::CreateDataDir)?;
    std::fs::set_permissions(dir, Permissions::from_mode(0o700))
        .map_err(DbError::SetDataDirPermissions)
}

#[cfg(not(unix))]
fn harden_data_dir(dir: &Path) -> Result<(), DbError> {
    std::fs::create_dir_all(dir).map_err(DbError::CreateDataDir)
}

#[cfg(unix)]
fn harden_db_file(path: &Path) -> Result<(), DbError> {
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::PermissionsExt;

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false) // never discard an existing database file
        .open(path)
        .map_err(DbError::CreateDbFile)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(DbError::SetDbFilePermissions)
}

#[cfg(not(unix))]
fn harden_db_file(_path: &Path) -> Result<(), DbError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn memory_pool() -> SqlitePool {
        connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect")
    }

    #[tokio::test]
    async fn migrations_record_the_current_schema_version() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");

        let (version,): (i64,) = sqlx::query_as("SELECT schema_version FROM schema_info")
            .fetch_one(&pool)
            .await
            .expect("schema_info must have exactly one row");
        assert_eq!(version, 4);
    }

    /// The auth tables must exist and be STRICT, so a value of the wrong
    /// type is rejected rather than silently coerced.
    #[tokio::test]
    async fn migrations_create_strict_auth_tables() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");

        for table in [
            "users",
            "sessions",
            "setup_tokens",
            "devices",
            "pairing_codes",
            "events",
            "invite_tokens",
            "account_log",
        ] {
            let (strict,): (i64,) = sqlx::query_as(
                "SELECT strict FROM pragma_table_list WHERE schema = 'main' AND name = ?1",
            )
            .bind(table)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|_| panic!("table {table} must exist"));
            assert_eq!(strict, 1, "table {table} must be STRICT");
        }
    }

    /// `ON DELETE CASCADE` on `sessions.user_id` only actually fires
    /// because the pool enables `foreign_keys`. Verify both together.
    #[tokio::test]
    async fn deleting_a_user_cascades_to_their_sessions() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");

        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES ('u1', 'alice', 'not-a-real-hash', 'user', 0)",
        )
        .execute(&pool)
        .await
        .expect("inserting a user must succeed");
        sqlx::query(
            "INSERT INTO sessions
                 (id, user_id, token_hash, created_at, last_used_at, expires_at)
             VALUES ('s1', 'u1', x'00', 0, 0, 0)",
        )
        .execute(&pool)
        .await
        .expect("inserting a session must succeed");

        sqlx::query("DELETE FROM users WHERE id = 'u1'")
            .execute(&pool)
            .await
            .expect("deleting the user must succeed");

        let (sessions,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .expect("counting sessions must succeed");
        assert_eq!(sessions, 0, "the session must have been cascaded away");
    }

    /// Seeds a user, a device, a pairing code and an event, so the
    /// cascade and constraint tests below have the whole chain.
    async fn seed_device_chain(pool: &SqlitePool) {
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES ('u1', 'alice', 'not-a-real-hash', 'user', 0)",
        )
        .execute(pool)
        .await
        .expect("inserting a user must succeed");
        sqlx::query(
            "INSERT INTO devices
                 (id, user_id, name, platform, token_hash, created_at, last_seen_at)
             VALUES ('d1', 'u1', 'laptop', 'linux', x'00', 0, 0)",
        )
        .execute(pool)
        .await
        .expect("inserting a device must succeed");
        sqlx::query(
            "INSERT INTO pairing_codes (id, user_id, code_hash, created_at, expires_at)
             VALUES ('p1', 'u1', x'01', 0, 600)",
        )
        .execute(pool)
        .await
        .expect("inserting a pairing code must succeed");
        sqlx::query(
            "INSERT INTO events
                 (id, device_id, event_id, start_ts, duration_secs, app_id, received_at)
             VALUES ('e1', 'd1', 'aa', 0, 60, 'org.example.app', 0)",
        )
        .execute(pool)
        .await
        .expect("inserting an event must succeed");
    }

    async fn count(pool: &SqlitePool, table: &str) -> i64 {
        let sql = match table {
            "devices" => "SELECT COUNT(*) FROM devices",
            "pairing_codes" => "SELECT COUNT(*) FROM pairing_codes",
            "events" => "SELECT COUNT(*) FROM events",
            other => panic!("unexpected table {other}"),
        };
        let (count,): (i64,) = sqlx::query_as(sql)
            .fetch_one(pool)
            .await
            .expect("counting must succeed");
        count
    }

    /// Deleting an account must take its devices, its outstanding
    /// pairing codes and every event those devices reported with it.
    /// The events hang off `devices`, not off `users`, so this is a
    /// two-step cascade and only works because foreign keys are on.
    #[tokio::test]
    async fn deleting_a_user_cascades_to_devices_codes_and_events() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");
        seed_device_chain(&pool).await;

        assert_eq!(count(&pool, "devices").await, 1);
        assert_eq!(count(&pool, "pairing_codes").await, 1);
        assert_eq!(count(&pool, "events").await, 1);

        sqlx::query("DELETE FROM users WHERE id = 'u1'")
            .execute(&pool)
            .await
            .expect("deleting the user must succeed");

        assert_eq!(count(&pool, "devices").await, 0, "devices must cascade");
        assert_eq!(count(&pool, "pairing_codes").await, 0, "codes must cascade");
        assert_eq!(
            count(&pool, "events").await,
            0,
            "events must cascade through devices"
        );
    }

    #[tokio::test]
    async fn devices_reject_an_unknown_platform() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");
        sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES ('u1', 'alice', 'not-a-real-hash', 'user', 0)",
        )
        .execute(&pool)
        .await
        .expect("inserting a user must succeed");

        let result = sqlx::query(
            "INSERT INTO devices
                 (id, user_id, name, platform, token_hash, created_at, last_seen_at)
             VALUES ('d1', 'u1', 'laptop', 'freebsd', x'00', 0, 0)",
        )
        .execute(&pool)
        .await;
        assert!(result.is_err(), "the platform CHECK must be enforced");
    }

    /// Idempotent ingest rests on this index, so it is worth asserting
    /// directly rather than only through the service layer.
    #[tokio::test]
    async fn one_event_id_may_appear_once_per_device() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");
        seed_device_chain(&pool).await;

        let duplicate = sqlx::query(
            "INSERT INTO events
                 (id, device_id, event_id, start_ts, duration_secs, app_id, received_at)
             VALUES ('e2', 'd1', 'aa', 0, 60, 'org.example.app', 0)",
        )
        .execute(&pool)
        .await;
        assert!(duplicate.is_err(), "the same id twice must be refused");

        // The same id reported by a *different* device is a different
        // event, and must be accepted: two devices legitimately observe
        // overlapping activity.
        sqlx::query(
            "INSERT INTO devices
                 (id, user_id, name, platform, token_hash, created_at, last_seen_at)
             VALUES ('d2', 'u1', 'phone', 'android', x'02', 0, 0)",
        )
        .execute(&pool)
        .await
        .expect("a second device must be insertable");
        sqlx::query(
            "INSERT INTO events
                 (id, device_id, event_id, start_ts, duration_secs, app_id, received_at)
             VALUES ('e3', 'd2', 'aa', 0, 60, 'org.example.app', 0)",
        )
        .execute(&pool)
        .await
        .expect("the same id on another device must be accepted");
    }

    /// The bounds the validator enforces are repeated as CHECKs. Each
    /// one has to actually bite, or the second line is decoration.
    #[tokio::test]
    async fn the_event_bounds_are_enforced_by_the_schema() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");
        seed_device_chain(&pool).await;

        let too_long_app_id = "x".repeat(257);
        let too_long_label = "x".repeat(129);
        let too_long_domain = "x".repeat(254);

        let cases: [(&str, String); 6] = [
            ("zero duration", "0".to_owned()),
            ("duration over a day", "86401".to_owned()),
            ("empty app_id", String::new()),
            ("app_id over 256", too_long_app_id),
            ("label over 128", too_long_label),
            ("domain over 253", too_long_domain),
        ];

        for (index, (label, value)) in cases.iter().enumerate() {
            let id = format!("bad-{index}");
            let event_id = format!("b{index}");
            let result = match *label {
                "zero duration" | "duration over a day" => {
                    sqlx::query(
                        "INSERT INTO events
                         (id, device_id, event_id, start_ts, duration_secs, app_id, received_at)
                     VALUES (?1, 'd1', ?2, 0, ?3, 'org.example.app', 0)",
                    )
                    .bind(&id)
                    .bind(&event_id)
                    .bind(value.parse::<i64>().expect("a number"))
                    .execute(&pool)
                    .await
                }
                "empty app_id" | "app_id over 256" => {
                    sqlx::query(
                        "INSERT INTO events
                         (id, device_id, event_id, start_ts, duration_secs, app_id, received_at)
                     VALUES (?1, 'd1', ?2, 0, 60, ?3, 0)",
                    )
                    .bind(&id)
                    .bind(&event_id)
                    .bind(value)
                    .execute(&pool)
                    .await
                }
                "label over 128" => {
                    sqlx::query(
                        "INSERT INTO events
                         (id, device_id, event_id, start_ts, duration_secs, app_id, label,
                          received_at)
                     VALUES (?1, 'd1', ?2, 0, 60, 'org.example.app', ?3, 0)",
                    )
                    .bind(&id)
                    .bind(&event_id)
                    .bind(value)
                    .execute(&pool)
                    .await
                }
                _ => {
                    sqlx::query(
                        "INSERT INTO events
                         (id, device_id, event_id, start_ts, duration_secs, app_id, domain,
                          received_at)
                     VALUES (?1, 'd1', ?2, 0, 60, 'org.example.app', ?3, 0)",
                    )
                    .bind(&id)
                    .bind(&event_id)
                    .bind(value)
                    .execute(&pool)
                    .await
                }
            };
            assert!(result.is_err(), "{label} must be refused by the schema");
        }
    }

    /// The reason ingest uses ON CONFLICT ... DO NOTHING rather than
    /// INSERT OR IGNORE: the former suppresses exactly the duplicate,
    /// while the latter would swallow a CHECK violation too and report
    /// a dropped event as a duplicate.
    #[tokio::test]
    async fn on_conflict_do_nothing_suppresses_only_the_duplicate() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");
        seed_device_chain(&pool).await;

        // The duplicate is absorbed, and reports no affected row.
        let duplicate = sqlx::query(
            "INSERT INTO events
                 (id, device_id, event_id, start_ts, duration_secs, app_id, received_at)
             VALUES ('e9', 'd1', 'aa', 0, 60, 'org.example.app', 0)
             ON CONFLICT (device_id, event_id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("a duplicate must not be an error");
        assert_eq!(duplicate.rows_affected(), 0);

        // A CHECK violation still raises, even with the same clause.
        let invalid = sqlx::query(
            "INSERT INTO events
                 (id, device_id, event_id, start_ts, duration_secs, app_id, received_at)
             VALUES ('e10', 'd1', 'bb', 0, 0, 'org.example.app', 0)
             ON CONFLICT (device_id, event_id) DO NOTHING",
        )
        .execute(&pool)
        .await;
        assert!(
            invalid.is_err(),
            "a CHECK violation must not be silently swallowed"
        );

        // And a fresh row still reports one affected, which is how the
        // ingest path tells "accepted" from "duplicate".
        let accepted = sqlx::query(
            "INSERT INTO events
                 (id, device_id, event_id, start_ts, duration_secs, app_id, received_at)
             VALUES ('e11', 'd1', 'cc', 0, 60, 'org.example.app', 0)
             ON CONFLICT (device_id, event_id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("a fresh event must insert");
        assert_eq!(accepted.rows_affected(), 1);
    }

    /// A session row may not reference a user that does not exist.
    #[tokio::test]
    async fn sessions_require_an_existing_user() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");

        let result = sqlx::query(
            "INSERT INTO sessions
                 (id, user_id, token_hash, created_at, last_used_at, expires_at)
             VALUES ('s1', 'nobody', x'00', 0, 0, 0)",
        )
        .execute(&pool)
        .await;
        assert!(result.is_err(), "the foreign key must be enforced");
    }

    #[tokio::test]
    async fn users_reject_an_unknown_role() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");

        let result = sqlx::query(
            "INSERT INTO users (id, username, password_hash, role, created_at)
             VALUES ('u1', 'alice', 'not-a-real-hash', 'superadmin', 0)",
        )
        .execute(&pool)
        .await;
        assert!(
            result.is_err(),
            "the role CHECK constraint must be enforced"
        );
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("first run must apply");
        migrate(&pool)
            .await
            .expect("second run must be a no-op, not an error");

        let (row_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM schema_info")
            .fetch_one(&pool)
            .await
            .expect("schema_info must still be queryable");
        assert_eq!(
            row_count, 1,
            "re-running migrations must not duplicate rows"
        );
    }

    #[tokio::test]
    async fn check_reachable_succeeds_against_a_live_pool() {
        let pool = memory_pool().await;
        check_reachable(&pool)
            .await
            .expect("a fresh pool must be reachable");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_target_hardens_directory_and_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "daycompass-db-test-{}-{unique}",
            std::process::id()
        ));
        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let pool = connect(&target).await.expect("file pool must connect");
        migrate(&pool).await.expect("migrations must apply");
        pool.close().await;

        let dir_mode = std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);

        let db_path = data_dir.join(DB_FILE_NAME);
        let file_mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// Only the legacy filename is present: startup must refuse rather
    /// than silently create a fresh, empty database under the new name.
    #[tokio::test]
    async fn file_target_refuses_a_legacy_only_data_dir() {
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "screenwarden-db-legacy-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join(LEGACY_DB_FILE_NAME), b"").unwrap();

        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let result = connect(&target).await;

        assert!(matches!(result, Err(DbError::LegacyDatabaseFile)));

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// Both files present (an upgrade already completed once, or a
    /// deliberate copy): the current filename wins and startup proceeds.
    #[tokio::test]
    async fn file_target_succeeds_when_both_files_are_present() {
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "screenwarden-db-both-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join(LEGACY_DB_FILE_NAME), b"").unwrap();
        std::fs::write(data_dir.join(DB_FILE_NAME), b"").unwrap();

        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let pool = connect(&target)
            .await
            .expect("the current filename must win when both are present");
        pool.close().await;

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// Only the legacy WAL file is present - the main legacy file was
    /// already removed or renamed, but the rename was not completed -
    /// and the new main file does not exist either: still a refusal,
    /// not a fresh empty database under the new name.
    #[tokio::test]
    async fn file_target_refuses_when_only_a_legacy_wal_exists() {
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "screenwarden-db-legacy-wal-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join(LEGACY_WAL_FILE_NAME), b"").unwrap();

        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let result = connect(&target).await;

        assert!(matches!(result, Err(DbError::LegacyDatabaseFile)));

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// Same as above, for the `-shm` file.
    #[tokio::test]
    async fn file_target_refuses_when_only_a_legacy_shm_exists() {
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "screenwarden-db-legacy-shm-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join(LEGACY_SHM_FILE_NAME), b"").unwrap();

        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let result = connect(&target).await;

        assert!(matches!(result, Err(DbError::LegacyDatabaseFile)));

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// A non-empty legacy WAL is refused even when the new main file
    /// already exists and is in active use: it names commits that a
    /// connection to the new file will never read, because SQLite only
    /// ever associates a `-wal` with the exact main-file name it was
    /// created next to. The dangerous case, so it gets the error that
    /// warns against overwriting rather than the ordinary one that
    /// says to rename everything.
    #[tokio::test]
    async fn file_target_refuses_a_non_empty_legacy_wal_even_when_the_new_file_exists() {
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "screenwarden-db-stray-wal-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join(DB_FILE_NAME), b"").unwrap();
        std::fs::write(data_dir.join(LEGACY_WAL_FILE_NAME), b"not actually empty").unwrap();

        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let result = connect(&target).await;

        assert!(matches!(result, Err(DbError::LegacyWalAlongsideNewFile)));

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// A non-empty legacy WAL with neither the new main file nor the
    /// legacy main file present: the new main file is missing, so this
    /// must take the safe-to-rename-everything branch and return
    /// `LegacyDatabaseFile`, not `LegacyWalAlongsideNewFile` - that
    /// error is reserved for when a rename would overwrite an existing
    /// new file, which is not the case here.
    #[tokio::test]
    async fn file_target_refuses_a_non_empty_legacy_wal_when_the_new_file_is_missing() {
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "screenwarden-db-non-empty-wal-no-new-file-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join(LEGACY_WAL_FILE_NAME), b"not actually empty").unwrap();

        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let result = connect(&target).await;

        assert!(matches!(result, Err(DbError::LegacyDatabaseFile)));

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// The flip side of the test above: an *empty* legacy WAL - the
    /// ordinary leftover of a rename that already finished cleanly -
    /// must not block every later start of an otherwise working
    /// instance forever.
    #[tokio::test]
    async fn file_target_tolerates_an_empty_legacy_wal_when_the_new_file_exists() {
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "screenwarden-db-empty-stray-wal-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join(DB_FILE_NAME), b"").unwrap();
        std::fs::write(data_dir.join(LEGACY_WAL_FILE_NAME), b"").unwrap();

        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let pool = connect(&target)
            .await
            .expect("an empty legacy WAL must not block startup");
        pool.close().await;

        std::fs::remove_dir_all(&data_dir).ok();
    }

    /// `LegacyDatabaseFile` - the new main file is missing, so a
    /// blanket rename is safe - names both auxiliary files and tells
    /// the operator to stop the server first, not just to rename
    /// something while it might still be writing to it.
    #[test]
    fn the_legacy_database_file_message_covers_wal_and_shm_and_stopping_first() {
        let message = DbError::LegacyDatabaseFile.to_string();
        assert!(message.contains("-wal"), "{message}");
        assert!(message.contains("-shm"), "{message}");
        assert!(message.contains("stop the server"), "{message}");
    }

    /// `LegacyWalAlongsideNewFile` - the new main file already exists -
    /// must never give the same unconditional "rename every file"
    /// instruction as `LegacyDatabaseFile` above: landing a rename on
    /// an existing `screenwarden.sqlite3*` overwrites it. It must
    /// instead say explicitly not to overwrite.
    #[test]
    fn the_legacy_wal_alongside_new_file_message_warns_against_overwriting() {
        let message = DbError::LegacyWalAlongsideNewFile.to_string();
        assert!(
            !message.contains("rename every file named screenward.sqlite3*"),
            "must not give the same unconditional rename-everything \
             instruction as the main-file-missing case: {message}"
        );
        assert!(
            message.contains("never") && message.contains("overwrite"),
            "must explicitly warn against overwriting: {message}"
        );
    }

    /// A permissions problem reading a legacy file must be reported,
    /// not silently read as "not there" the way `Path::exists` would -
    /// the whole point of this check is to never fall through to a
    /// fresh empty database by mistake.
    ///
    /// Skips itself under root (or anything else bypassing file
    /// permission bits): `#![forbid(unsafe_code)]` applies to this
    /// whole crate, including this test module, so checking the
    /// effective uid directly would need `libc::getuid` behind
    /// `unsafe` - not available here. Detected behaviourally instead:
    /// if the lockdown below does not actually block a read, whatever
    /// is running this suite is not constrained by permission bits,
    /// and the assertion below cannot be made true in this
    /// environment.
    #[cfg(unix)]
    #[tokio::test]
    async fn file_target_reports_a_permission_error_rather_than_ignoring_it() {
        use std::os::unix::fs::PermissionsExt;
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "screenwarden-db-permission-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join(LEGACY_WAL_FILE_NAME), b"not actually empty").unwrap();
        // No read, write or execute for anyone: traversing into the
        // directory to stat a file inside it must fail.
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let permissions_are_enforced =
            std::fs::metadata(data_dir.join(LEGACY_WAL_FILE_NAME)).is_err();

        if !permissions_are_enforced {
            std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::remove_dir_all(&data_dir).ok();
            eprintln!(
                "skipping file_target_reports_a_permission_error_rather_than_ignoring_it: \
                 running with privileges that bypass file permission bits (root?)"
            );
            return;
        }

        let target = DbTarget::File {
            data_dir: data_dir.clone(),
        };
        let result = connect(&target).await;

        // Restore permissions before cleanup, or remove_dir_all cannot
        // read the directory either.
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            matches!(result, Err(DbError::CheckLegacyDatabaseFile { .. })),
            "{result:?}"
        );

        std::fs::remove_dir_all(&data_dir).ok();
    }
}
