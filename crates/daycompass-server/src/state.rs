//! Shared application state.
//!
//! Handlers receive this and nothing else. It holds the database pool
//! and the long-lived values built from configuration at startup, so
//! nothing security-relevant is re-derived per request and nothing reads
//! the environment after startup.

use std::sync::Arc;

use axum::extract::FromRef;
use sqlx::SqlitePool;

use crate::auth::invite::InvitePolicy;
use crate::auth::password::{HashError, Hasher};
use crate::auth::session::SessionPolicy;
use crate::clientip::ClientKey;
use crate::config::{Config, PublicUrl, TrustedProxies};
use crate::devices::service::DevicePolicy;
use crate::events::validate::EventWindow;
use crate::ratelimit::{DeviceKey, GlobalKey, RateLimiter, SessionKey, UsernameKey};

/// Cloned once per request by axum. Every field is cheap to clone: the
/// pool and the hasher are handles to shared state rather than copies of
/// it, which is what keeps the Argon2 concurrency cap global.
#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub hasher: Hasher,
    pub session_policy: SessionPolicy,
    /// How long a freshly issued invite token remains redeemable.
    pub invite_policy: InvitePolicy,
    pub public_url: PublicUrl,
    /// A hash of a random password that was discarded, verified against
    /// when a login names an account that does not exist, so that path
    /// costs the same as a real one. Built once at startup: doing it per
    /// request would double the work of every failed login.
    pub decoy_password_hash: Arc<String>,
    pub trusted_proxies: TrustedProxies,
    pub limits: Limits,
    /// The device cap a pairing is subject to.
    pub device_policy: DevicePolicy,
    /// How far back a reported event may be dated.
    pub event_window: EventWindow,
}

/// The rate limiters, one per bucket.
///
/// Separate limiters rather than one shared map, so pressure on one
/// bucket cannot evict another's entries - invented usernames must not
/// be able to flush the per-address counters.
#[derive(Clone)]
pub struct Limits {
    pub login_ip: Arc<RateLimiter<ClientKey>>,
    pub login_username: Arc<RateLimiter<UsernameKey>>,
    pub setup_ip: Arc<RateLimiter<ClientKey>>,
    /// Password changes, keyed by session. See [`SessionKey`] for why
    /// the session and not the account or the address.
    pub pw_change: Arc<RateLimiter<SessionKey>>,
    /// Pairing attempts, per client address.
    pub pair_ip: Arc<RateLimiter<ClientKey>>,
    /// Pairing attempts across the whole instance. One shared key, so
    /// this is a ceiling on the endpoint rather than a per-caller
    /// limit; see the default in [`crate::config`] for the
    /// denial-of-service trade-off that comes with that.
    pub pair_global: Arc<RateLimiter<GlobalKey>>,
    /// Ingest requests, per device. Keyed on the device the access
    /// layer resolved, so an unauthenticated caller never reaches it.
    pub ingest_device: Arc<RateLimiter<DeviceKey>>,
    /// *Failed* device authentications, per client address.
    ///
    /// The only limiter consulted before authentication, and so the
    /// only one bounding an anonymous caller on the device routes. It
    /// is peeked before the lookup and charged only on failure, which
    /// the shared rate-limit layer cannot express - see
    /// [`crate::routes::LimitKey::PeerBeforeAuth`].
    pub device_auth_fail: Arc<RateLimiter<ClientKey>>,
    /// Invite redemption attempts, per client address.
    pub invite_ip: Arc<RateLimiter<ClientKey>>,
    /// Invite redemption attempts across the whole instance. Same
    /// shape and the same trade-off as [`Self::pair_global`]: a ceiling
    /// on total work, not a guessing defence.
    pub invite_global: Arc<RateLimiter<GlobalKey>>,
    /// Account exports, keyed by session - same reasoning as
    /// [`Self::pw_change`].
    pub export: Arc<RateLimiter<SessionKey>>,
}

impl Limits {
    fn new(config: &Config) -> Self {
        Self {
            login_ip: Arc::new(RateLimiter::new(
                config.rate_limit_login_ip,
                config.rate_limit_max_entries,
            )),
            login_username: Arc::new(RateLimiter::new(
                config.rate_limit_login_username,
                config.rate_limit_max_entries,
            )),
            setup_ip: Arc::new(RateLimiter::new(
                config.rate_limit_setup_ip,
                config.rate_limit_max_entries,
            )),
            pw_change: Arc::new(RateLimiter::new(
                config.rate_limit_pw_change,
                config.rate_limit_max_entries,
            )),
            pair_ip: Arc::new(RateLimiter::new(
                config.rate_limit_pair_ip,
                config.rate_limit_max_entries,
            )),
            // One key ever, so one entry. The bound is still passed
            // for uniformity; it can never be reached.
            pair_global: Arc::new(RateLimiter::new(config.rate_limit_pair_global, 1)),
            ingest_device: Arc::new(RateLimiter::new(
                config.rate_limit_ingest_device,
                config.rate_limit_max_entries,
            )),
            // Bounded by the same `max_entries` as every other keyed
            // limiter. That bound is what keeps this one from being a
            // memory vector despite being reachable unauthenticated:
            // `RateLimiter::peek` never inserts, and the charge path
            // goes through `check`, which reclaims ended windows and
            // then evicts before exceeding the cap.
            device_auth_fail: Arc::new(RateLimiter::new(
                config.rate_limit_device_auth_fail,
                config.rate_limit_max_entries,
            )),
            invite_ip: Arc::new(RateLimiter::new(
                config.rate_limit_invite_ip,
                config.rate_limit_max_entries,
            )),
            // One key ever, so one entry - same reasoning as
            // `pair_global` above.
            invite_global: Arc::new(RateLimiter::new(config.rate_limit_invite_global, 1)),
            export: Arc::new(RateLimiter::new(
                config.rate_limit_export,
                config.rate_limit_max_entries,
            )),
        }
    }
}

impl AppState {
    /// Builds the state, including the decoy hash.
    ///
    /// Fallible and async because of that hash. Failing here means
    /// Argon2 cannot run at all, which is worth refusing to start over
    /// rather than discovering at the first login.
    pub async fn new(pool: SqlitePool, config: &Config) -> Result<Self, HashError> {
        let hasher = Hasher::new(
            config.argon2,
            config.argon2_max_concurrent,
            config.argon2_wait_timeout,
        );
        let decoy_password_hash = Arc::new(hasher.decoy_hash().await?);

        Ok(Self {
            pool,
            hasher,
            session_policy: SessionPolicy {
                idle_timeout: config.session_idle_timeout,
                absolute_timeout: config.session_absolute_timeout,
            },
            invite_policy: InvitePolicy {
                ttl: config.invite_ttl,
            },
            public_url: config.public_url.clone(),
            decoy_password_hash,
            trusted_proxies: config.trusted_proxies.clone(),
            limits: Limits::new(config),
            device_policy: DevicePolicy {
                max_devices_per_user: config.max_devices_per_user,
            },
            event_window: EventWindow {
                max_age: config.event_max_age,
            },
        })
    }
}

/// Lets a handler ask for just the pool with `State<SqlitePool>`.
impl FromRef<AppState> for SqlitePool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}
