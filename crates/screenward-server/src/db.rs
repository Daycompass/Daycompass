//! SQLite pool setup, hardening, and embedded migrations.
//!
//! Migrations live in `migrations/` and are embedded into the binary at
//! compile time. No device or event tables exist yet.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

/// Database filename inside the data directory.
pub const DB_FILE_NAME: &str = "screenward.sqlite3";

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
        assert_eq!(version, 3);
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
            "screenward-db-test-{}-{unique}",
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
}
