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
        assert_eq!(version, 2);
    }

    /// The auth tables must exist and be STRICT, so a value of the wrong
    /// type is rejected rather than silently coerced.
    #[tokio::test]
    async fn migrations_create_strict_auth_tables() {
        let pool = memory_pool().await;
        migrate(&pool).await.expect("migrations must apply");

        for table in ["users", "sessions", "setup_tokens"] {
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
