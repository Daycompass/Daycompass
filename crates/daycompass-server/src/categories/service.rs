//! Validating input, then creating, listing or deleting category
//! rules for one account.
//!
//! Thin wrappers over [`super::store`], mirroring
//! [`crate::devices::service`]'s shape: validate first, which costs no
//! database access and echoes nothing a caller sent, and only then
//! talk to the store.

use sqlx::SqlitePool;

use super::kind::{self, PatternError, RuleKind};
use super::label::{CategoryLabel, CategoryLabelError};
use super::store::{self, CategoryRuleRecord, NewRule, NewRuleOutcome, MAX_RULES_PER_USER};
use crate::auth::store::{new_id, StoreError};
use crate::auth::time::UnixTime;

/// Why a rule could not be created.
#[derive(Debug, thiserror::Error)]
pub enum CreateRuleError {
    #[error("the kind must be either app_id or domain")]
    UnknownKind,
    #[error("the pattern is not valid for this kind")]
    InvalidPattern(PatternError),
    #[error("the category is not valid")]
    InvalidLabel(CategoryLabelError),
    /// This account already has a rule of the same kind for the same
    /// pattern.
    #[error("a rule with this kind and pattern already exists")]
    Duplicate,
    /// The account already holds [`MAX_RULES_PER_USER`] rules.
    #[error("the account already holds the maximum number of category rules")]
    TooMany,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Validates `raw_kind`/`raw_pattern`/`raw_category`, then creates the
/// rule for `user_id`.
///
/// Validation runs before any database access: a malformed request
/// costs no query, and checking in this order - kind, then pattern,
/// then label - is what keeps "the kind is wrong" from being reported
/// as a pattern or label problem just because one of those happened
/// to be checked first.
pub async fn create_rule(
    pool: &SqlitePool,
    user_id: &str,
    raw_kind: &str,
    raw_pattern: &str,
    raw_category: &str,
    now: UnixTime,
) -> Result<CategoryRuleRecord, CreateRuleError> {
    let kind = RuleKind::parse(raw_kind).ok_or(CreateRuleError::UnknownKind)?;
    let pattern =
        kind::normalize_pattern(kind, raw_pattern).map_err(CreateRuleError::InvalidPattern)?;
    let category = CategoryLabel::parse(raw_category).map_err(CreateRuleError::InvalidLabel)?;

    let id = new_id();
    let new_rule = NewRule {
        id: &id,
        user_id,
        kind,
        pattern: &pattern,
        category: category.as_str(),
    };
    match store::insert_rule_guarded(pool, new_rule, now, MAX_RULES_PER_USER).await? {
        NewRuleOutcome::Created => {
            // Ids and the kind only - never the free-text pattern or
            // category. Both are text a person wrote, same spirit as
            // "never log usernames" in `CLAUDE.md`, and an id is all
            // a log should ever need to say which rule it was.
            tracing::info!(
                user_id = %user_id,
                rule_id = %id,
                kind = %kind,
                "category rule created"
            );
            Ok(CategoryRuleRecord {
                id,
                user_id: user_id.to_owned(),
                kind,
                pattern,
                category: category.as_str().to_owned(),
                created_at: now,
            })
        }
        NewRuleOutcome::Duplicate => Err(CreateRuleError::Duplicate),
        NewRuleOutcome::TooMany => Err(CreateRuleError::TooMany),
    }
}

/// One account's own rules.
pub async fn list_own_rules(
    pool: &SqlitePool,
    user_id: &str,
) -> Result<Vec<CategoryRuleRecord>, StoreError> {
    store::list_rules_for_user(pool, user_id).await
}

/// Deletes one of the caller's own rules.
///
/// `None` covers both "no such rule" and "that rule is somebody
/// else's" - see [`store::delete_rule`].
pub async fn delete_rule(
    pool: &SqlitePool,
    user_id: &str,
    rule_id: &str,
) -> Result<Option<CategoryRuleRecord>, StoreError> {
    let deleted = store::delete_rule(pool, user_id, rule_id).await?;
    if let Some(rule) = &deleted {
        tracing::info!(user_id = %user_id, rule_id = %rule.id, "category rule deleted");
    }
    Ok(deleted)
}
