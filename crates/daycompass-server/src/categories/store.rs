//! Every SQL statement that may name `category_rules`.
//!
//! Same arrangement as [`crate::devices::store`]: the queries live
//! here so [`super::service`] stays readable, and bound parameters
//! only - no value is ever formatted into SQL. Rows are validated on
//! the way out, same as everywhere else: a `kind` that does not parse
//! is [`StoreError::CorruptRow`] rather than guessed at.
//!
//! One operation takes `BEGIN IMMEDIATE`:
//!
//!   * [`insert_rule_guarded`] - count the account's existing rules,
//!     then insert, so two concurrent creates cannot both see room
//!     under the cap and both succeed.
//!
//! [`delete_rule`] needs no transaction of its own: `DELETE ...
//! RETURNING` is one statement, and there is no prior read whose
//! result the delete has to still be true for.

use sqlx::error::DatabaseError;
use sqlx::{Row, SqlitePool};

use super::kind::RuleKind;
use crate::auth::store::StoreError;
use crate::auth::time::UnixTime;

/// How many category rules one account may hold.
///
/// Compiled in, not configurable - unlike the rate limits in
/// `CLAUDE.md`, this is not a security boundary, just a bound on how
/// large the table and one [`super::resolve`] pass can grow. 500 is
/// far more than a real taxonomy needs (a student sorting apps and
/// sites into a handful of categories), while still nowhere near
/// where the per-request matching cost in [`super::resolve`] would
/// become noticeable.
pub const MAX_RULES_PER_USER: usize = 500;

/// A row from `category_rules`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryRuleRecord {
    pub id: String,
    pub user_id: String,
    pub kind: RuleKind,
    pub pattern: String,
    pub category: String,
    pub created_at: UnixTime,
}

fn rule_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<CategoryRuleRecord, StoreError> {
    let id: String = row.try_get("id")?;
    let user_id: String = row.try_get("user_id")?;
    let kind: String = row.try_get("kind")?;
    let pattern: String = row.try_get("pattern")?;
    let category: String = row.try_get("category")?;
    let created_at: i64 = row.try_get("created_at")?;

    Ok(CategoryRuleRecord {
        id,
        user_id,
        // Stored kinds have already been through the policy, so this
        // must succeed; if it does not, the row was written by
        // something that bypassed it.
        kind: RuleKind::parse(&kind).ok_or(StoreError::CorruptRow)?,
        pattern,
        category,
        created_at: UnixTime::from_secs(created_at),
    })
}

/// Outcome of creating a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NewRuleOutcome {
    Created,
    /// This account already has a rule of the same kind for the same
    /// pattern. Reported from the `UNIQUE` constraint rather than a
    /// prior `SELECT`, for the same race reason
    /// [`crate::auth::store::insert_user`] reports a taken username
    /// that way: a check followed by an insert is a race two
    /// concurrent creates would both pass.
    Duplicate,
    /// The account already holds [`MAX_RULES_PER_USER`] rules.
    TooMany,
}

/// A new rule's already-validated, already-generated fields.
///
/// Bundled into one type rather than five separate parameters on
/// [`insert_rule_guarded`], which clippy's `too_many_arguments` would
/// otherwise flag - and because the fields travel together anyway,
/// all sourced from one request.
pub struct NewRule<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub kind: RuleKind,
    pub pattern: &'a str,
    pub category: &'a str,
}

/// Stores `rule`, capped at `max_rules` existing rows for its owner.
///
/// The count and the insert are one transaction, or two parallel
/// requests could both see room and both insert, overshooting the cap
/// by however many requests raced.
///
/// Every field of `rule` is taken as already-validated and already
/// generated rather than built here, so the caller already has
/// everything it needs to answer with the created row without a
/// second `RETURNING` round trip.
pub async fn insert_rule_guarded(
    pool: &SqlitePool,
    rule: NewRule<'_>,
    now: UnixTime,
    max_rules: usize,
) -> Result<NewRuleOutcome, StoreError> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let (existing,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM category_rules WHERE user_id = ?1")
            .bind(rule.user_id)
            .fetch_one(&mut *tx)
            .await?;

    if existing >= i64::try_from(max_rules).unwrap_or(i64::MAX) {
        tx.rollback().await?;
        return Ok(NewRuleOutcome::TooMany);
    }

    let result = sqlx::query(
        "INSERT INTO category_rules (id, user_id, kind, pattern, category, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(rule.id)
    .bind(rule.user_id)
    .bind(rule.kind.as_str())
    .bind(rule.pattern)
    .bind(rule.category)
    .bind(now.as_secs())
    .execute(&mut *tx)
    .await;

    match result {
        Ok(_) => {
            tx.commit().await?;
            Ok(NewRuleOutcome::Created)
        }
        Err(err) => {
            if err
                .as_database_error()
                .is_some_and(DatabaseError::is_unique_violation)
            {
                tx.rollback().await?;
                return Ok(NewRuleOutcome::Duplicate);
            }
            Err(err.into())
        }
    }
}

/// One account's rules, oldest first.
pub async fn list_rules_for_user(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<CategoryRuleRecord>, StoreError> {
    let rows = sqlx::query(
        "SELECT id, user_id, kind, pattern, category, created_at
         FROM category_rules WHERE user_id = ?1 ORDER BY created_at, id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.iter().map(rule_from_row).collect()
}

/// Deletes a rule scoped to `user_id`, returning the deleted row.
///
/// `None` covers both "no such rule" and "that rule is somebody
/// else's" - distinguishing them would turn this into an oracle for
/// which rule ids exist on other accounts, the same reasoning as
/// [`crate::devices::store::rename_device`].
pub async fn delete_rule(
    pool: &SqlitePool,
    user_id: &str,
    rule_id: &str,
) -> Result<Option<CategoryRuleRecord>, StoreError> {
    let row = sqlx::query(
        "DELETE FROM category_rules WHERE id = ?1 AND user_id = ?2
         RETURNING id, user_id, kind, pattern, category, created_at",
    )
    .bind(rule_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(rule_from_row).transpose()
}
