//! A single JSON error shape for every non-2xx response this server
//! sends.
//!
//! The guarantee is structural, not a matter of discipline: a
//! client-facing error is a value of [`ErrorKind`], and its status, code
//! and message are all `const fn`s returning `&'static str`. There is no
//! constructor that takes a `String`, so no request field, SQL error,
//! file path or panic message can reach a client through this type -
//! not because every call site remembered to be careful, but because
//! the type cannot carry such a thing in the first place.
//!
//! Adding a new client-facing error therefore means adding a variant
//! here, which is a small reviewable diff in one file, rather than
//! inventing a message at a call site that nobody reviews again.

use std::time::Duration;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: &'static str,
}

/// Every error this server will show a client.
///
/// The generic variants at the top exist so [`ApiError::from_status`]
/// can answer for a response produced by infrastructure - a rejected
/// body, a method mismatch - without inventing text. The rest are
/// deliberate outcomes of this server's own logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    // Generic, keyed to a status code.
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    RequestTimeout,
    PayloadTooLarge,
    UnsupportedMediaType,
    UnprocessableEntity,
    InternalError,
    ServiceUnavailable,

    // Authentication.
    /// No usable session. One message for every cause, since the
    /// distinction would say whether a token was ever valid.
    Unauthenticated,
    /// A failed login. Identical for a wrong password, an unknown
    /// account, and input that could not name one.
    InvalidCredentials,
    /// A setup token that was unknown, expired, redeemed or malformed.
    InvalidSetupToken,
    /// An invite token that was unknown, expired, redeemed or malformed.
    InvalidInviteToken,
    CsrfTokenMissing,
    CsrfTokenInvalid,
    /// Authenticated, but not allowed to do this.
    NotPermitted,
    OriginMismatch,
    RateLimited,
    /// Shed rather than refused: hashing capacity was exhausted.
    ServerBusy,

    // Account management.
    /// The requested username already belongs to an account. Only ever
    /// returned to an admin, who can list the accounts anyway.
    UsernameTaken,
    /// Deleting or demoting this account would leave the instance with
    /// no admin at all.
    LastAdminProtected,
    /// A password change presented the wrong current password. A 403
    /// rather than a 401: the session is valid, so a client must not be
    /// pushed into treating itself as logged out.
    CurrentPasswordInvalid,
    /// Another request changed the password first. The caller verified
    /// against a hash that is no longer stored, so applying its change
    /// would silently undo the one that won.
    PasswordChangeConflict,

    // Devices and pairing.
    /// A pairing code that was unknown, expired, already redeemed, or
    /// malformed. One kind for all four, so the response cannot say
    /// which - an unauthenticated caller must not learn whether a code
    /// ever existed.
    InvalidPairingCode,
    /// A valid code whose owner is already at the device cap. Distinct
    /// from the above on purpose: reaching it requires a valid code,
    /// so it is not an oracle, and the person pairing needs to know
    /// why it failed.
    DeviceLimitReached,
    /// The account already holds the maximum number of live pairing
    /// codes. Only ever returned to the owner, who can see their own.
    PairingCodeLimitReached,
    /// The platform field named something outside the known set.
    PlatformUnknown,
    /// The batch carried more events than one request may.
    BatchTooLarge,
    /// `end_ts` on an event query was not strictly after `start_ts`.
    EventRangeInverted,
    /// The span between `start_ts` and `end_ts` on an event query was
    /// wider than the server allows in one request.
    EventRangeTooWide,

    // Category rules.
    /// The `kind` field named something other than `app_id` or
    /// `domain`.
    CategoryRuleKindUnknown,
    /// An `app_id` pattern that was empty or only whitespace.
    CategoryPatternBlank,
    /// A pattern longer than its kind allows.
    CategoryPatternLength,
    /// A `domain` pattern not shaped like a bare hostname.
    CategoryPatternMalformed,
    /// A control character or text-direction override in the pattern.
    CategoryPatternCharset,
    /// The category label was blank once trimmed, or longer than
    /// allowed.
    CategoryLabelLength,
    /// A control character or text-direction override in the category
    /// label.
    CategoryLabelCharset,
    /// A rule with this account's chosen kind and pattern already
    /// exists.
    CategoryRuleDuplicate,
    /// The account already holds the maximum number of category
    /// rules.
    CategoryRuleLimitReached,

    // Input policies. These describe public rules and never echo what
    // was sent.
    UsernameLength,
    UsernameCharset,
    PasswordBlank,
    PasswordLength,
    /// The role field named something other than the two known roles.
    RoleUnknown,
    DeviceNameLength,
    DeviceNameCharset,
}

impl ErrorKind {
    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadRequest
            | Self::UsernameLength
            | Self::UsernameCharset
            | Self::PasswordBlank
            | Self::PasswordLength
            | Self::RoleUnknown
            | Self::DeviceNameLength
            | Self::DeviceNameCharset
            | Self::PlatformUnknown
            | Self::EventRangeInverted
            | Self::EventRangeTooWide
            | Self::CategoryRuleKindUnknown
            | Self::CategoryPatternBlank
            | Self::CategoryPatternLength
            | Self::CategoryPatternMalformed
            | Self::CategoryPatternCharset
            | Self::CategoryLabelLength
            | Self::CategoryLabelCharset => StatusCode::BAD_REQUEST,
            Self::Unauthorized
            | Self::Unauthenticated
            | Self::InvalidCredentials
            | Self::InvalidSetupToken
            | Self::InvalidInviteToken
            | Self::InvalidPairingCode => StatusCode::UNAUTHORIZED,
            Self::Forbidden
            | Self::CsrfTokenMissing
            | Self::CsrfTokenInvalid
            | Self::NotPermitted
            | Self::OriginMismatch
            | Self::CurrentPasswordInvalid => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::UsernameTaken
            | Self::LastAdminProtected
            | Self::PasswordChangeConflict
            | Self::DeviceLimitReached
            | Self::PairingCodeLimitReached
            | Self::CategoryRuleDuplicate
            | Self::CategoryRuleLimitReached => StatusCode::CONFLICT,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::PayloadTooLarge | Self::BatchTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::UnprocessableEntity => StatusCode::UNPROCESSABLE_ENTITY,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ServiceUnavailable | Self::ServerBusy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The stable machine-readable code in the response body.
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::RequestTimeout => "request_timeout",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::UnprocessableEntity => "unprocessable_entity",
            Self::InternalError => "internal_server_error",
            Self::ServiceUnavailable => "service_unavailable",
            Self::Unauthenticated => "unauthenticated",
            Self::InvalidCredentials => "invalid_credentials",
            Self::InvalidSetupToken => "invalid_setup_token",
            Self::InvalidInviteToken => "invalid_invite_token",
            Self::CsrfTokenMissing => "csrf_token_missing",
            Self::CsrfTokenInvalid => "csrf_token_invalid",
            Self::NotPermitted => "forbidden",
            Self::OriginMismatch => "origin_mismatch",
            Self::RateLimited => "rate_limited",
            Self::ServerBusy => "server_busy",
            Self::UsernameTaken => "username_taken",
            Self::LastAdminProtected => "last_admin_protected",
            Self::CurrentPasswordInvalid => "invalid_current_password",
            Self::PasswordChangeConflict => "password_change_conflict",
            Self::UsernameLength | Self::UsernameCharset => "invalid_username",
            Self::PasswordBlank | Self::PasswordLength => "invalid_password",
            Self::RoleUnknown => "invalid_role",
            Self::InvalidPairingCode => "invalid_pairing_code",
            Self::DeviceLimitReached => "device_limit_reached",
            Self::PairingCodeLimitReached => "pairing_code_limit_reached",
            Self::PlatformUnknown => "invalid_platform",
            Self::BatchTooLarge => "batch_too_large",
            Self::DeviceNameLength | Self::DeviceNameCharset => "invalid_device_name",
            Self::EventRangeInverted | Self::EventRangeTooWide => "invalid_event_range",
            Self::CategoryRuleKindUnknown => "invalid_category_rule_kind",
            Self::CategoryPatternBlank
            | Self::CategoryPatternLength
            | Self::CategoryPatternMalformed
            | Self::CategoryPatternCharset => "invalid_category_pattern",
            Self::CategoryLabelLength | Self::CategoryLabelCharset => "invalid_category_label",
            Self::CategoryRuleDuplicate => "category_rule_duplicate",
            Self::CategoryRuleLimitReached => "category_rule_limit_reached",
        }
    }

    /// The human-readable message in the response body.
    ///
    /// A compile-time constant in every case. The numbers in the policy
    /// messages are checked against the policy constants by a test
    /// below, since they cannot be interpolated into a `&'static str`.
    pub const fn message(self) -> &'static str {
        match self {
            Self::BadRequest => "bad request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not found",
            Self::MethodNotAllowed => "method not allowed",
            Self::RequestTimeout => "request timeout",
            Self::PayloadTooLarge => "payload too large",
            Self::UnsupportedMediaType => "unsupported media type",
            Self::UnprocessableEntity => "unprocessable entity",
            Self::InternalError => "internal server error",
            Self::ServiceUnavailable => "service unavailable",
            Self::Unauthenticated => "authentication is required",
            Self::InvalidCredentials => "the username or password is incorrect",
            Self::InvalidSetupToken => "the setup token is not valid",
            Self::InvalidInviteToken => "the invite token is not valid",
            Self::CsrfTokenMissing => "this request requires an X-CSRF-Token header",
            Self::CsrfTokenInvalid => "the CSRF token does not match this session",
            Self::NotPermitted => "this account may not perform this action",
            Self::OriginMismatch => "this request did not come from an allowed origin",
            Self::RateLimited => "too many requests; please try again later",
            Self::ServerBusy => "the server is too busy to process this request",
            Self::UsernameLength => "the username must be between 3 and 32 characters long",
            Self::UsernameCharset => {
                "the username may only contain a-z, 0-9, and the characters _ . -"
            }
            Self::PasswordBlank => "the password must not be empty or only whitespace",
            Self::PasswordLength => "the password must be between 12 and 128 characters long",
            Self::UsernameTaken => "that username is already taken",
            Self::LastAdminProtected => {
                "the last remaining admin account may not be deleted or demoted"
            }
            Self::CurrentPasswordInvalid => "the current password is incorrect",
            Self::PasswordChangeConflict => {
                "the password was changed by another request; please try again"
            }
            Self::RoleUnknown => "the role must be either admin or user",
            Self::InvalidPairingCode => "the pairing code is not valid",
            Self::DeviceLimitReached => "this account has reached the maximum number of devices",
            Self::PairingCodeLimitReached => {
                "this account already has the maximum number of active pairing codes"
            }
            Self::PlatformUnknown => {
                "the platform must be one of android, windows, macos, linux or ios"
            }
            Self::BatchTooLarge => "this request carries too many events",
            Self::DeviceNameLength => "the device name must be between 1 and 64 characters long",
            Self::DeviceNameCharset => {
                "the device name may not contain control or text-direction characters"
            }
            Self::EventRangeInverted => {
                "end_ts must be strictly after start_ts"
            }
            Self::EventRangeTooWide => {
                "the time range between start_ts and end_ts is wider than this server allows in one request"
            }
            Self::CategoryRuleKindUnknown => "the kind must be either app_id or domain",
            Self::CategoryPatternBlank => "the pattern must not be empty or only whitespace",
            Self::CategoryPatternLength => {
                "the pattern is longer than this server allows for its kind"
            }
            Self::CategoryPatternMalformed => {
                "a domain pattern must be a bare hostname, not a URL"
            }
            Self::CategoryPatternCharset => {
                "the pattern may not contain control or text-direction characters"
            }
            Self::CategoryLabelLength => "the category must be between 1 and 64 characters long",
            Self::CategoryLabelCharset => {
                "the category may not contain control or text-direction characters"
            }
            Self::CategoryRuleDuplicate => "a rule with this kind and pattern already exists",
            Self::CategoryRuleLimitReached => {
                "this account already has the maximum number of category rules"
            }
        }
    }
}

/// Every variant, so the tests below can sweep the whole set and so the
/// constant assertion underneath has something to evaluate.
pub(crate) const ALL_ERROR_KINDS: &[ErrorKind] = &[
    ErrorKind::BadRequest,
    ErrorKind::Unauthorized,
    ErrorKind::Forbidden,
    ErrorKind::NotFound,
    ErrorKind::MethodNotAllowed,
    ErrorKind::RequestTimeout,
    ErrorKind::PayloadTooLarge,
    ErrorKind::UnsupportedMediaType,
    ErrorKind::UnprocessableEntity,
    ErrorKind::InternalError,
    ErrorKind::ServiceUnavailable,
    ErrorKind::Unauthenticated,
    ErrorKind::InvalidCredentials,
    ErrorKind::InvalidSetupToken,
    ErrorKind::InvalidInviteToken,
    ErrorKind::CsrfTokenMissing,
    ErrorKind::CsrfTokenInvalid,
    ErrorKind::NotPermitted,
    ErrorKind::OriginMismatch,
    ErrorKind::RateLimited,
    ErrorKind::ServerBusy,
    ErrorKind::UsernameTaken,
    ErrorKind::LastAdminProtected,
    ErrorKind::CurrentPasswordInvalid,
    ErrorKind::PasswordChangeConflict,
    ErrorKind::UsernameLength,
    ErrorKind::UsernameCharset,
    ErrorKind::PasswordBlank,
    ErrorKind::PasswordLength,
    ErrorKind::RoleUnknown,
    ErrorKind::InvalidPairingCode,
    ErrorKind::DeviceLimitReached,
    ErrorKind::PairingCodeLimitReached,
    ErrorKind::PlatformUnknown,
    ErrorKind::BatchTooLarge,
    ErrorKind::DeviceNameLength,
    ErrorKind::DeviceNameCharset,
    ErrorKind::EventRangeInverted,
    ErrorKind::EventRangeTooWide,
    ErrorKind::CategoryRuleKindUnknown,
    ErrorKind::CategoryPatternBlank,
    ErrorKind::CategoryPatternLength,
    ErrorKind::CategoryPatternMalformed,
    ErrorKind::CategoryPatternCharset,
    ErrorKind::CategoryLabelLength,
    ErrorKind::CategoryLabelCharset,
    ErrorKind::CategoryRuleDuplicate,
    ErrorKind::CategoryRuleLimitReached,
];

/// Compile-time proof that every code and message is a constant.
///
/// A `const` cannot hold a heap allocation, so if either accessor were
/// ever changed to return a `String` - or to interpolate a request
/// value - this item would stop compiling. It is the structural half of
/// the guarantee the tests below check behaviourally.
const _: () = {
    let mut index = 0;
    while index < ALL_ERROR_KINDS.len() {
        let kind = ALL_ERROR_KINDS[index];
        let code: &'static str = kind.code();
        let message: &'static str = kind.message();
        assert!(!code.is_empty());
        assert!(!message.is_empty());
        index += 1;
    }
};

/// Marks a response built by [`ApiError`].
///
/// Its one job is to keep such a response's **headers** - `Retry-After`
/// above all - from being thrown away by the normalizing middleware,
/// which rebuilds everything else from the status code alone and so
/// would drop them.
///
/// It is deliberately not a general "trust this body" escape hatch. The
/// body of a marked response is safe because [`ErrorKind`] cannot carry
/// anything but a constant, not because the marker vouches for it.
#[derive(Clone, Copy)]
pub struct Deliberate;

/// A client-facing error: one [`ErrorKind`] plus an optional
/// `Retry-After`.
///
/// Note what is absent: any way to supply a status, code or message
/// directly. All three come from the kind, so they cannot drift apart
/// and cannot be sourced from a request or an internal error.
pub struct ApiError {
    kind: ErrorKind,
    retry_after: Option<Duration>,
}

impl ApiError {
    pub const fn of(kind: ErrorKind) -> Self {
        Self {
            kind,
            retry_after: None,
        }
    }

    /// Adds a `Retry-After` header, for a request that was shed rather
    /// than refused: a rate limit, or hashing capacity running out.
    pub const fn retry_after(mut self, after: Duration) -> Self {
        self.retry_after = Some(after);
        self
    }

    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The safe fallback for a response this server did not construct
    /// itself - a rejected request body, a method mismatch, a layer
    /// returning a bare status.
    ///
    /// An unmapped status collapses to a generic client or server error
    /// rather than being described from its reason phrase, because
    /// deriving text at runtime is the thing this type exists to
    /// prevent.
    pub fn from_status(status: StatusCode) -> Self {
        let kind = match status {
            StatusCode::BAD_REQUEST => ErrorKind::BadRequest,
            StatusCode::UNAUTHORIZED => ErrorKind::Unauthorized,
            StatusCode::FORBIDDEN => ErrorKind::Forbidden,
            StatusCode::NOT_FOUND => ErrorKind::NotFound,
            StatusCode::METHOD_NOT_ALLOWED => ErrorKind::MethodNotAllowed,
            StatusCode::REQUEST_TIMEOUT => ErrorKind::RequestTimeout,
            StatusCode::PAYLOAD_TOO_LARGE => ErrorKind::PayloadTooLarge,
            StatusCode::UNSUPPORTED_MEDIA_TYPE => ErrorKind::UnsupportedMediaType,
            StatusCode::UNPROCESSABLE_ENTITY => ErrorKind::UnprocessableEntity,
            StatusCode::TOO_MANY_REQUESTS => ErrorKind::RateLimited,
            StatusCode::SERVICE_UNAVAILABLE => ErrorKind::ServiceUnavailable,
            other if other.is_client_error() => ErrorKind::BadRequest,
            _ => ErrorKind::InternalError,
        };
        Self::of(kind)
    }
}

impl From<ErrorKind> for ApiError {
    fn from(kind: ErrorKind) -> Self {
        Self::of(kind)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.kind.code(),
                message: self.kind.message(),
            },
        };

        let mut response = (self.kind.status(), Json(body)).into_response();
        response.extensions_mut().insert(Deliberate);

        if let Some(after) = self.retry_after {
            // Whole seconds, and at least one: "Retry-After: 0" invites
            // an immediate retry, which defeats the point of shedding.
            let seconds = after.as_secs().max(1);
            if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }

        response
    }
}

impl IntoResponse for ErrorKind {
    fn into_response(self) -> Response {
        ApiError::of(self).into_response()
    }
}

/// Router fallback for any request that matches no route.
pub async fn not_found() -> ApiError {
    ApiError::of(ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The behavioural half of the guarantee: nothing in the set looks
    /// like it was built from a request or from an internal error.
    #[test]
    fn no_message_looks_dynamically_built() {
        for kind in ALL_ERROR_KINDS {
            let message = kind.message();
            let code = kind.code();

            assert!(!message.is_empty(), "{kind:?} has no message");
            assert!(!code.is_empty(), "{kind:?} has no code");

            // Leftover format placeholders would mean someone tried to
            // interpolate and it silently did not happen.
            for marker in ['{', '}'] {
                assert!(
                    !message.contains(marker),
                    "{kind:?} message contains a format placeholder: {message}"
                );
            }

            // Shapes that only appear when internal text leaks in.
            for marker in [
                "Error",
                "error:",
                "sqlx",
                "SQL",
                "panicked",
                "unwrap",
                "/home/",
                "src/",
                "Os {",
                "No such file",
            ] {
                assert!(
                    !message.contains(marker),
                    "{kind:?} message looks like internal text: {message}"
                );
            }

            // Codes stay machine-readable: lowercase, underscores only.
            assert!(
                code.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{kind:?} code is not a plain identifier: {code}"
            );
        }
    }

    /// No two kinds may share a code while disagreeing about the status,
    /// or a client could not act on the code.
    #[test]
    fn a_shared_code_implies_a_shared_status() {
        for first in ALL_ERROR_KINDS {
            for second in ALL_ERROR_KINDS {
                if first.code() == second.code() {
                    assert_eq!(
                        first.status(),
                        second.status(),
                        "{first:?} and {second:?} share a code but not a status"
                    );
                }
            }
        }
    }

    #[test]
    fn every_kind_carries_an_error_status() {
        for kind in ALL_ERROR_KINDS {
            let status = kind.status();
            assert!(
                status.is_client_error() || status.is_server_error(),
                "{kind:?} is not an error status: {status}"
            );
        }
    }

    /// The policy messages state numbers that live in the policy
    /// modules as constants. They cannot be interpolated into a
    /// `&'static str`, so this is what keeps them from drifting apart.
    #[test]
    fn the_policy_messages_agree_with_the_policy_constants() {
        use crate::auth::{password, username};

        let message = ErrorKind::UsernameLength.message();
        assert!(
            message.contains(&username::MIN_CHARS.to_string())
                && message.contains(&username::MAX_CHARS.to_string()),
            "the username length message disagrees with the policy: {message}"
        );

        let message = ErrorKind::PasswordLength.message();
        assert!(
            message.contains(&password::MIN_CHARS.to_string())
                && message.contains(&password::MAX_CHARS.to_string()),
            "the password length message disagrees with the policy: {message}"
        );

        let message = ErrorKind::DeviceNameLength.message();
        assert!(
            message.contains(&crate::devices::name::MIN_CHARS.to_string())
                && message.contains(&crate::devices::name::MAX_CHARS.to_string()),
            "the device name length message disagrees with the policy: {message}"
        );

        let message = ErrorKind::CategoryLabelLength.message();
        assert!(
            message.contains(&crate::categories::label::MIN_CHARS.to_string())
                && message.contains(&crate::categories::label::MAX_CHARS.to_string()),
            "the category label length message disagrees with the policy: {message}"
        );
    }

    /// Unlike the category label, a pattern's length bound depends on
    /// its kind (`app_id` or `domain`), so no single number here could
    /// be correct for both - same reasoning as the batch cap and the
    /// event range width below.
    #[test]
    fn the_category_pattern_length_message_states_no_number() {
        let message = ErrorKind::CategoryPatternLength.message();
        assert!(
            !message.chars().any(|c| c.is_ascii_digit()),
            "a number here would be correct for at most one kind: {message}"
        );
    }

    /// The platform message spells out the whole set, which cannot be
    /// interpolated into a `&'static str`. A platform added to the
    /// enum and not to the message would leave a client told to send
    /// something the server no longer considers exhaustive.
    #[test]
    fn the_platform_message_names_every_known_platform() {
        let message = ErrorKind::PlatformUnknown.message();
        for platform in crate::devices::platform::ALL_PLATFORMS {
            assert!(
                message.contains(platform.as_str()),
                "{platform} is missing from: {message}"
            );
        }
    }

    /// The batch cap is stated in the wire documentation rather than
    /// in this message, so the message must not claim a number that
    /// could drift from the constant.
    #[test]
    fn the_batch_message_states_no_number() {
        let message = ErrorKind::BatchTooLarge.message();
        assert!(
            !message.chars().any(|c| c.is_ascii_digit()),
            "a number here would be a constant waiting to drift: {message}"
        );
    }

    /// Same reasoning as the batch cap: the maximum query width lives
    /// in `events::query` as a constant, not duplicated here.
    #[test]
    fn the_event_range_too_wide_message_states_no_number() {
        let message = ErrorKind::EventRangeTooWide.message();
        assert!(
            !message.chars().any(|c| c.is_ascii_digit()),
            "a number here would be a constant waiting to drift: {message}"
        );
    }

    #[test]
    fn from_status_maps_the_statuses_that_reach_it() {
        let cases = [
            (StatusCode::NOT_FOUND, "not_found", "not found"),
            (StatusCode::BAD_REQUEST, "bad_request", "bad request"),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "service unavailable",
            ),
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "payload too large",
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_server_error",
                "internal server error",
            ),
        ];
        for (status, code, message) in cases {
            let error = ApiError::from_status(status);
            assert_eq!(error.kind().status(), status);
            assert_eq!(error.kind().code(), code);
            assert_eq!(error.kind().message(), message);
        }
    }

    /// An exotic status must still produce a generic answer rather than
    /// describing itself from its reason phrase.
    #[test]
    fn an_unmapped_status_collapses_to_a_generic_error() {
        let teapot = ApiError::from_status(StatusCode::IM_A_TEAPOT);
        assert_eq!(teapot.kind(), ErrorKind::BadRequest);

        let gateway = ApiError::from_status(StatusCode::BAD_GATEWAY);
        assert_eq!(gateway.kind(), ErrorKind::InternalError);
    }

    #[test]
    fn retry_after_is_at_least_one_second() {
        let response = ApiError::of(ErrorKind::RateLimited)
            .retry_after(Duration::from_millis(1))
            .into_response();
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("1"),
            "Retry-After: 0 would invite an immediate retry"
        );
    }

    #[test]
    fn a_response_without_retry_after_sets_no_such_header() {
        let response = ApiError::of(ErrorKind::NotFound).into_response();
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
    }

    #[test]
    fn every_error_response_carries_the_deliberate_marker() {
        for kind in ALL_ERROR_KINDS {
            let response = ApiError::of(*kind).into_response();
            assert!(
                response.extensions().get::<Deliberate>().is_some(),
                "{kind:?} must be marked so its headers survive normalization"
            );
        }
    }
}
