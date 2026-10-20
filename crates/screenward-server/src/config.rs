//! Configuration loaded from `SCREENWARD_*` environment variables.
//!
//! Every variable also accepts a `_FILE` suffix (e.g.
//! `SCREENWARD_BIND_ADDR_FILE`) whose content is read as the value. This
//! convention exists so that, once a sensitive setting is introduced, it
//! can be supplied via a mounted secret file instead of a plaintext
//! environment variable, without changing the loading mechanism.
//!
//! No field here is currently sensitive, but [`Config`] implements
//! [`std::fmt::Debug`] by hand (not `#[derive(Debug)]`) on purpose: adding
//! a field later means deliberately deciding how (or whether) it is shown,
//! instead of it leaking into logs by default.
//!
//! Everything security-relevant - the bind address, the public URL, the
//! trusted proxy ranges, the rate limits and the Argon2 parameters - is
//! settable only here, never through the API or the dashboard, per
//! `CLAUDE.md`. Anything invalid fails at startup rather than at the
//! first request that depends on it.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use ipnet::IpNet;

use crate::auth::password::{HashingParams, ParamsError};

const VAR_BIND_ADDR: &str = "SCREENWARD_BIND_ADDR";
const VAR_DATA_DIR: &str = "SCREENWARD_DATA_DIR";
const VAR_LOG: &str = "SCREENWARD_LOG";
const VAR_PUBLIC_URL: &str = "SCREENWARD_PUBLIC_URL";
const VAR_TRUSTED_PROXIES: &str = "SCREENWARD_TRUSTED_PROXIES";
const VAR_SESSION_IDLE: &str = "SCREENWARD_SESSION_IDLE_SECS";
const VAR_SESSION_ABSOLUTE: &str = "SCREENWARD_SESSION_ABSOLUTE_SECS";
const VAR_ARGON2_M_COST: &str = "SCREENWARD_ARGON2_M_COST_KIB";
const VAR_ARGON2_T_COST: &str = "SCREENWARD_ARGON2_T_COST";
const VAR_ARGON2_P_COST: &str = "SCREENWARD_ARGON2_P_COST";
const VAR_ARGON2_MAX_CONCURRENT: &str = "SCREENWARD_ARGON2_MAX_CONCURRENT";
const VAR_ARGON2_WAIT_TIMEOUT: &str = "SCREENWARD_ARGON2_WAIT_TIMEOUT_SECS";
const VAR_RATE_LIMIT_LOGIN_IP: &str = "SCREENWARD_RATE_LIMIT_LOGIN_IP";
const VAR_RATE_LIMIT_LOGIN_USERNAME: &str = "SCREENWARD_RATE_LIMIT_LOGIN_USERNAME";
const VAR_RATE_LIMIT_SETUP_IP: &str = "SCREENWARD_RATE_LIMIT_SETUP_IP";
const VAR_RATE_LIMIT_MAX_ENTRIES: &str = "SCREENWARD_RATE_LIMIT_MAX_ENTRIES";

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_DATA_DIR: &str = "./data";
const DEFAULT_LOG_LEVEL: &str = "info";

/// Seven days. Long enough that a student is not logged out between
/// school days, short enough that a forgotten session on a shared
/// machine does not live forever.
const DEFAULT_SESSION_IDLE_SECS: u64 = 7 * 24 * 60 * 60;

/// Thirty days. A session is re-authenticated monthly no matter how
/// actively it is used.
const DEFAULT_SESSION_ABSOLUTE_SECS: u64 = 30 * 24 * 60 * 60;

/// Two concurrent hashes at the default memory cost is about 38 MiB of
/// transient Argon2 memory, which fits the "minimal RAM" goal.
const DEFAULT_ARGON2_MAX_CONCURRENT: usize = 2;

/// How long a request may wait for a hashing permit before it is shed.
const DEFAULT_ARGON2_WAIT_TIMEOUT_SECS: u64 = 5;

/// Ten login attempts per five minutes from one client address.
const DEFAULT_RATE_LIMIT_LOGIN_IP: &str = "10/300";

/// Five login attempts per five minutes against one username, from
/// anywhere. Lower than the per-address limit because a distributed
/// guessing attack on one account is the case this is for.
const DEFAULT_RATE_LIMIT_LOGIN_USERNAME: &str = "5/300";

/// Five setup attempts per hour from one client address. The setup
/// token is unguessable, so this only bounds the noise.
const DEFAULT_RATE_LIMIT_SETUP_IP: &str = "5/3600";

/// Upper bound on tracked rate-limit keys, so the limiter cannot be
/// used to exhaust memory.
const DEFAULT_RATE_LIMIT_MAX_ENTRIES: usize = 10_000;

const VALID_LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];

/// Backend configuration. Construct with [`Config::from_env`].
pub struct Config {
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub log_level: String,
    /// Origin this instance is reached at, checked against the `Origin`
    /// header on state-changing requests.
    pub public_url: PublicUrl,
    /// Peers allowed to speak for a client through `X-Forwarded-For`.
    pub trusted_proxies: TrustedProxies,
    pub session_idle_timeout: Duration,
    pub session_absolute_timeout: Duration,
    pub argon2: HashingParams,
    pub argon2_max_concurrent: usize,
    pub argon2_wait_timeout: Duration,
    pub rate_limit_login_ip: RateLimitRule,
    pub rate_limit_login_username: RateLimitRule,
    pub rate_limit_setup_ip: RateLimitRule,
    pub rate_limit_max_entries: usize,
}

/// Failed to load configuration. Messages name the offending variable but
/// never its value, so a startup failure can be logged or printed safely.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{var} is set both directly and via {var}_FILE; set only one")]
    AmbiguousSource { var: &'static str },

    #[error("failed to read the file referenced by {var}_FILE")]
    FileRead { var: &'static str },

    #[error("{var}_FILE does not contain valid UTF-8")]
    FileNotUtf8 { var: &'static str },

    #[error("{var} has an invalid value")]
    Invalid { var: &'static str },

    #[error("{var} is required unless {other} is a loopback address")]
    Required {
        var: &'static str,
        other: &'static str,
    },

    #[error("{var} is below the minimum this server accepts")]
    BelowMinimum { var: &'static str },

    #[error("{var} must not be greater than {other}")]
    OutOfOrder {
        var: &'static str,
        other: &'static str,
    },
}

/// Where configuration values are looked up from. Production code uses
/// [`ProcessEnv`]; tests provide an in-memory fake instead of mutating the
/// real process environment (which Rust requires `unsafe` for, and this
/// crate forbids).
trait VarSource {
    fn get(&self, name: &str) -> Option<String>;
}

struct ProcessEnv;

impl VarSource for ProcessEnv {
    fn get(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// A source where nothing is set, so every default applies.
struct NoEnv;

impl VarSource for NoEnv {
    fn get(&self, _name: &str) -> Option<String> {
        None
    }
}

impl Config {
    /// Loads configuration from the real process environment. Fails on the
    /// first invalid or ambiguous variable; never includes any value in
    /// the returned error.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::load(&ProcessEnv)
    }

    /// Configuration with every value at its compiled-in default.
    ///
    /// Exists so tests can build an app without reading the real
    /// process environment, where a stray `SCREENWARD_*` variable in a
    /// developer's shell would otherwise change what the test exercises.
    pub fn defaults() -> Self {
        Self::load(&NoEnv).expect("the compiled-in defaults must be valid")
    }

    fn load(source: &impl VarSource) -> Result<Self, ConfigError> {
        let bind_addr = match resolve(source, VAR_BIND_ADDR)? {
            Some(value) => value
                .parse::<SocketAddr>()
                .map_err(|_| ConfigError::Invalid { var: VAR_BIND_ADDR })?,
            None => DEFAULT_BIND_ADDR
                .parse::<SocketAddr>()
                .expect("default bind address is valid"),
        };

        let data_dir = match resolve(source, VAR_DATA_DIR)? {
            Some(value) if value.trim().is_empty() => {
                return Err(ConfigError::Invalid { var: VAR_DATA_DIR });
            }
            Some(value) => PathBuf::from(value),
            None => PathBuf::from(DEFAULT_DATA_DIR),
        };

        let log_level = match resolve(source, VAR_LOG)? {
            Some(value) => {
                let normalized = value.trim().to_ascii_lowercase();
                if !VALID_LOG_LEVELS.contains(&normalized.as_str()) {
                    return Err(ConfigError::Invalid { var: VAR_LOG });
                }
                normalized
            }
            None => DEFAULT_LOG_LEVEL.to_string(),
        };

        // The Origin check is only as good as the origin it compares
        // against, so a non-loopback bind must say what it is reachable
        // at rather than silently inherit a guess.
        let public_url = match resolve(source, VAR_PUBLIC_URL)? {
            Some(value) => PublicUrl::parse(&value).ok_or(ConfigError::Invalid {
                var: VAR_PUBLIC_URL,
            })?,
            None if bind_addr.ip().is_loopback() => PublicUrl::loopback_default(bind_addr),
            None => {
                return Err(ConfigError::Required {
                    var: VAR_PUBLIC_URL,
                    other: VAR_BIND_ADDR,
                })
            }
        };

        // Empty by default: with no trusted range, X-Forwarded-For is
        // ignored outright and the peer address is always the client.
        let trusted_proxies = match resolve(source, VAR_TRUSTED_PROXIES)? {
            Some(value) => TrustedProxies::parse(&value).ok_or(ConfigError::Invalid {
                var: VAR_TRUSTED_PROXIES,
            })?,
            None => TrustedProxies::default(),
        };

        let session_idle_timeout = seconds(source, VAR_SESSION_IDLE, DEFAULT_SESSION_IDLE_SECS)?;
        let session_absolute_timeout =
            seconds(source, VAR_SESSION_ABSOLUTE, DEFAULT_SESSION_ABSOLUTE_SECS)?;
        if session_idle_timeout > session_absolute_timeout {
            // An idle window longer than the absolute lifetime would
            // never be the binding constraint, which is a sign the
            // operator meant something else.
            return Err(ConfigError::OutOfOrder {
                var: VAR_SESSION_IDLE,
                other: VAR_SESSION_ABSOLUTE,
            });
        }

        let floor = HashingParams::owasp_minimum();
        let argon2 = HashingParams::new(
            parsed(source, VAR_ARGON2_M_COST, floor.m_cost_kib())?,
            parsed(source, VAR_ARGON2_T_COST, floor.t_cost())?,
            parsed(source, VAR_ARGON2_P_COST, floor.p_cost())?,
        )
        .map_err(|err| match err {
            ParamsError::MemoryTooLow => ConfigError::BelowMinimum {
                var: VAR_ARGON2_M_COST,
            },
            ParamsError::IterationsTooLow => ConfigError::BelowMinimum {
                var: VAR_ARGON2_T_COST,
            },
            ParamsError::ParallelismTooLow => ConfigError::BelowMinimum {
                var: VAR_ARGON2_P_COST,
            },
            // Argon2 rejected the combination rather than one value.
            ParamsError::Rejected => ConfigError::Invalid {
                var: VAR_ARGON2_M_COST,
            },
        })?;

        let argon2_max_concurrent = at_least_one(
            source,
            VAR_ARGON2_MAX_CONCURRENT,
            DEFAULT_ARGON2_MAX_CONCURRENT,
        )?;
        let argon2_wait_timeout = seconds(
            source,
            VAR_ARGON2_WAIT_TIMEOUT,
            DEFAULT_ARGON2_WAIT_TIMEOUT_SECS,
        )?;

        let rate_limit_login_ip =
            rule(source, VAR_RATE_LIMIT_LOGIN_IP, DEFAULT_RATE_LIMIT_LOGIN_IP)?;
        let rate_limit_login_username = rule(
            source,
            VAR_RATE_LIMIT_LOGIN_USERNAME,
            DEFAULT_RATE_LIMIT_LOGIN_USERNAME,
        )?;
        let rate_limit_setup_ip =
            rule(source, VAR_RATE_LIMIT_SETUP_IP, DEFAULT_RATE_LIMIT_SETUP_IP)?;
        let rate_limit_max_entries = at_least_one(
            source,
            VAR_RATE_LIMIT_MAX_ENTRIES,
            DEFAULT_RATE_LIMIT_MAX_ENTRIES,
        )?;

        Ok(Config {
            bind_addr,
            data_dir,
            log_level,
            public_url,
            trusted_proxies,
            session_idle_timeout,
            session_absolute_timeout,
            argon2,
            argon2_max_concurrent,
            argon2_wait_timeout,
            rate_limit_login_ip,
            rate_limit_login_username,
            rate_limit_setup_ip,
            rate_limit_max_entries,
        })
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every field is listed explicitly and is currently non-sensitive.
        // Do not switch this to `#[derive(Debug)]`: that would make a
        // future sensitive field show up here by accident.
        f.debug_struct("Config")
            .field("bind_addr", &self.bind_addr)
            .field("data_dir", &self.data_dir)
            .field("log_level", &self.log_level)
            .field("public_url", &self.public_url)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("session_idle_timeout", &self.session_idle_timeout)
            .field("session_absolute_timeout", &self.session_absolute_timeout)
            .field("argon2", &self.argon2)
            .field("argon2_max_concurrent", &self.argon2_max_concurrent)
            .field("argon2_wait_timeout", &self.argon2_wait_timeout)
            .field("rate_limit_login_ip", &self.rate_limit_login_ip)
            .field("rate_limit_login_username", &self.rate_limit_login_username)
            .field("rate_limit_setup_ip", &self.rate_limit_setup_ip)
            .field("rate_limit_max_entries", &self.rate_limit_max_entries)
            .finish()
    }
}

/// Resolves one `SCREENWARD_*` variable, honoring the `_FILE` convention.
///
/// - Only the plain variable set: returns its value.
/// - Only `_FILE` set: reads and returns the referenced file's content,
///   trimmed of surrounding whitespace/newline.
/// - Both set: an error (ambiguous).
/// - Neither set: `Ok(None)`, caller applies its default.
fn resolve(source: &impl VarSource, var: &'static str) -> Result<Option<String>, ConfigError> {
    let file_var = format!("{var}_FILE");
    let direct = source.get(var);
    let file_path = source.get(&file_var);

    match (direct, file_path) {
        (Some(_), Some(_)) => Err(ConfigError::AmbiguousSource { var }),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => {
            let bytes = std::fs::read(path).map_err(|_| ConfigError::FileRead { var })?;
            let content = String::from_utf8(bytes).map_err(|_| ConfigError::FileNotUtf8 { var })?;
            Ok(Some(content.trim().to_string()))
        }
        (None, None) => Ok(None),
    }
}

/// Parses one variable through [`FromStr`], or returns `default`.
fn parsed<T: FromStr>(
    source: &impl VarSource,
    var: &'static str,
    default: T,
) -> Result<T, ConfigError> {
    match resolve(source, var)? {
        Some(value) => value
            .trim()
            .parse::<T>()
            .map_err(|_| ConfigError::Invalid { var }),
        None => Ok(default),
    }
}

/// A duration in whole seconds. Zero is rejected: every setting that
/// uses this would disable itself at zero, which is never what an
/// operator means by writing it.
fn seconds(
    source: &impl VarSource,
    var: &'static str,
    default_secs: u64,
) -> Result<Duration, ConfigError> {
    let secs: u64 = parsed(source, var, default_secs)?;
    if secs == 0 {
        return Err(ConfigError::Invalid { var });
    }
    Ok(Duration::from_secs(secs))
}

/// A count that must be at least one.
fn at_least_one(
    source: &impl VarSource,
    var: &'static str,
    default: usize,
) -> Result<usize, ConfigError> {
    let value: usize = parsed(source, var, default)?;
    if value == 0 {
        return Err(ConfigError::BelowMinimum { var });
    }
    Ok(value)
}

/// A rate limit, falling back to a compiled-in default that goes through
/// the same parser as operator input.
fn rule(
    source: &impl VarSource,
    var: &'static str,
    default: &str,
) -> Result<RateLimitRule, ConfigError> {
    let fallback = default
        .parse::<RateLimitRule>()
        .expect("the compiled-in default rate limit must be valid");
    parsed(source, var, fallback)
}

/// The externally reachable origin of this instance, used to check the
/// `Origin` header on state-changing requests.
///
/// Stored normalized: lowercase scheme and host, with the port dropped
/// when it is the scheme's default, so `https://example.org:443` and
/// `https://example.org` compare equal.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicUrl(String);

impl PublicUrl {
    /// Parses an absolute `http`/`https` origin with no path, query,
    /// fragment, or userinfo. A single trailing slash is tolerated,
    /// because it is what people paste.
    fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        let lower_scheme = trimmed.get(..8).map(str::to_ascii_lowercase);
        let (scheme, rest) = match lower_scheme.as_deref() {
            Some(s) if s.starts_with("https://") => ("https", &trimmed[8..]),
            _ => match trimmed.get(..7).map(str::to_ascii_lowercase).as_deref() {
                Some(s) if s.starts_with("http://") => ("http", &trimmed[7..]),
                _ => return None,
            },
        };

        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            // Credentials in a URL are never right here, and accepting
            // them would make the comparison below read the wrong part
            // of the string as the host.
            || authority.contains('@')
            || authority.chars().any(char::is_whitespace)
        {
            return None;
        }

        let (host, port) = split_authority(authority)?;
        let default_port = if scheme == "https" { 443 } else { 80 };
        let host = host.to_ascii_lowercase();
        Some(Self(match port {
            Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
            _ => format!("{scheme}://{host}"),
        }))
    }

    /// The origin to assume when the bind address is loopback and no
    /// public URL was configured.
    fn loopback_default(bind_addr: SocketAddr) -> Self {
        let host = match bind_addr.ip() {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        Self::parse(&format!("http://{host}:{}", bind_addr.port()))
            .expect("a loopback socket address always forms a valid origin")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True if `origin_header` names exactly this origin.
    ///
    /// The header goes through the same parser, so an equivalent
    /// spelling (an explicit default port, different case) still
    /// matches, while anything unparseable - `null`, an opaque origin, a
    /// URL carrying a path - does not.
    pub fn matches_origin_header(&self, origin_header: &str) -> bool {
        Self::parse(origin_header).is_some_and(|candidate| candidate == *self)
    }
}

impl fmt::Debug for PublicUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not a secret: it is the address clients already connect to.
        write!(f, "{:?}", self.0)
    }
}

/// Splits an authority into host and optional port, accepting
/// `host`, `host:port`, `[v6]` and `[v6]:port`.
fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        // Must be a real IPv6 literal, not arbitrary text in brackets.
        inner.parse::<std::net::Ipv6Addr>().ok()?;
        // Keep the brackets so the normalized form stays a usable origin.
        let bracketed = &authority[..inner.len() + 2];
        return match after {
            "" => Some((bracketed, None)),
            _ => Some((bracketed, Some(after.strip_prefix(':')?.parse().ok()?))),
        };
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
        None => (authority, None),
    };

    // A bare IPv6 address is ambiguous with host:port, so it must be
    // bracketed to be accepted; rejecting a colon here is what makes
    // that unambiguous. The rest of the charset check keeps a malformed
    // host from being compared against an Origin header later.
    if host.is_empty()
        || host.contains(':')
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return None;
    }
    Some((host, port))
}

/// One rate limit: at most `max` requests per `window`.
///
/// Configured as `<max>/<window-seconds>`, for instance `10/300` for ten
/// attempts per five minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitRule {
    pub max: u32,
    pub window: Duration,
}

impl FromStr for RateLimitRule {
    type Err = ();

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (max, window) = raw.trim().split_once('/').ok_or(())?;
        let max = max.trim().parse::<u32>().map_err(|_| ())?;
        let window = window.trim().parse::<u64>().map_err(|_| ())?;
        // A zero limit would deny every request forever, and a zero
        // window would never expire. Both are mistakes, not settings.
        if max == 0 || window == 0 {
            return Err(());
        }
        Ok(Self {
            max,
            window: Duration::from_secs(window),
        })
    }
}

/// CIDR ranges whose peers may speak for a client through
/// `X-Forwarded-For`. Empty by default, which means the header is
/// ignored entirely.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<IpNet>);

impl TrustedProxies {
    /// Parses a comma-separated list. A bare address is accepted as a
    /// single-host range, since writing `192.0.2.1` rather than
    /// `192.0.2.1/32` is a likely and harmless slip.
    fn parse(raw: &str) -> Option<Self> {
        let mut ranges = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let net = entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                .ok()?;
            ranges.push(net);
        }
        Some(Self(ranges))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True if `addr` falls inside any configured range.
    ///
    /// The address is unmapped first, so a proxy listed as
    /// `192.0.2.1/32` is still recognized when its peer address arrives
    /// as `::ffff:192.0.2.1` from a dual-stack listener.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let addr = unmap_v4(addr);
        self.0.iter().any(|net| net.contains(&addr))
    }
}

/// Turns an IPv4-mapped IPv6 address into the IPv4 address it wraps.
///
/// A dual-stack listener reports IPv4 peers this way. Treating the two
/// spellings as different addresses would break both proxy matching and
/// per-address rate limiting - in the latter case by putting every IPv4
/// client into one shared `::ffff:0:0/64` bucket.
pub fn unmap_v4(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// In-memory stand-in for the process environment, so tests never
    /// mutate real env vars (which would need `unsafe`, forbidden here)
    /// and can run concurrently without interfering with each other.
    #[derive(Default)]
    struct FakeEnv(HashMap<String, String>);

    impl FakeEnv {
        fn with(mut self, key: &str, value: impl Into<String>) -> Self {
            self.0.insert(key.to_string(), value.into());
            self
        }
    }

    impl VarSource for FakeEnv {
        fn get(&self, name: &str) -> Option<String> {
            self.0.get(name).cloned()
        }
    }

    /// A temp file holding `content`, cleaned up on drop.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn with_content(content: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "screenward-config-test-{}-{:p}",
                std::process::id(),
                content.as_ptr()
            ));
            std::fs::write(&path, content).unwrap();
            TempFile { path }
        }

        fn path_str(&self) -> String {
            self.path.to_str().unwrap().to_string()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.path).ok();
        }
    }

    #[test]
    fn defaults_apply_when_nothing_is_set() {
        let config = Config::load(&FakeEnv::default()).expect("defaults must be valid");
        assert_eq!(config.bind_addr, DEFAULT_BIND_ADDR.parse().unwrap());
        assert_eq!(config.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        assert_eq!(config.log_level, DEFAULT_LOG_LEVEL);
        // The default bind address is loopback, so the public URL is
        // derived rather than required.
        assert_eq!(config.public_url.as_str(), "http://127.0.0.1:8080");
        assert!(
            config.trusted_proxies.is_empty(),
            "X-Forwarded-For must be ignored until a proxy is configured"
        );
        assert_eq!(config.session_idle_timeout, Duration::from_secs(604_800));
        assert_eq!(
            config.session_absolute_timeout,
            Duration::from_secs(2_592_000)
        );
        assert_eq!(config.argon2, HashingParams::owasp_minimum());
        assert_eq!(config.argon2_max_concurrent, 2);
        assert_eq!(config.argon2_wait_timeout, Duration::from_secs(5));
        assert_eq!(config.rate_limit_login_ip.max, 10);
        assert_eq!(config.rate_limit_login_ip.window, Duration::from_secs(300));
        assert_eq!(config.rate_limit_login_username.max, 5);
        assert_eq!(config.rate_limit_setup_ip.max, 5);
        assert_eq!(
            config.rate_limit_setup_ip.window,
            Duration::from_secs(3_600)
        );
        assert_eq!(config.rate_limit_max_entries, 10_000);
    }

    // --- public URL ---------------------------------------------------

    /// The Origin check is only meaningful against a known origin, so a
    /// bind address that is reachable from elsewhere has to say what it
    /// is reachable at.
    #[test]
    fn public_url_is_required_when_the_bind_address_is_not_loopback() {
        for bind in ["0.0.0.0:8080", "192.0.2.10:8080", "[::]:8080"] {
            let env = FakeEnv::default().with(VAR_BIND_ADDR, bind);
            let err =
                Config::load(&env).expect_err("a non-loopback bind must require the public URL");
            assert!(
                matches!(err, ConfigError::Required { var, .. } if var == VAR_PUBLIC_URL),
                "{bind} produced {err:?}"
            );
        }
    }

    #[test]
    fn public_url_is_optional_for_a_loopback_bind_and_tracks_the_port() {
        let env = FakeEnv::default().with(VAR_BIND_ADDR, "127.0.0.1:9999");
        let config = Config::load(&env).expect("loopback needs no public URL");
        assert_eq!(config.public_url.as_str(), "http://127.0.0.1:9999");

        let env = FakeEnv::default().with(VAR_BIND_ADDR, "[::1]:3000");
        let config = Config::load(&env).expect("IPv6 loopback needs no public URL");
        assert_eq!(config.public_url.as_str(), "http://[::1]:3000");
    }

    #[test]
    fn a_configured_public_url_is_used_for_any_bind_address() {
        let env = FakeEnv::default()
            .with(VAR_BIND_ADDR, "0.0.0.0:8080")
            .with(VAR_PUBLIC_URL, "https://example.org");
        let config = Config::load(&env).expect("an explicit public URL must be accepted");
        assert_eq!(config.public_url.as_str(), "https://example.org");
    }

    #[test]
    fn public_url_is_normalized() {
        let cases = [
            ("https://example.org", "https://example.org"),
            // A default port is dropped, so both spellings compare equal.
            ("https://example.org:443", "https://example.org"),
            ("http://example.org:80", "http://example.org"),
            // A non-default port is kept.
            ("https://example.org:8443", "https://example.org:8443"),
            // Case folds, and one trailing slash is tolerated.
            ("HTTPS://Example.ORG/", "https://example.org"),
            ("http://EXAMPLE.org:8080/", "http://example.org:8080"),
            ("  https://example.org  ", "https://example.org"),
            ("http://[::1]:8080", "http://[::1]:8080"),
        ];
        for (raw, expected) in cases {
            let parsed = PublicUrl::parse(raw).unwrap_or_else(|| panic!("{raw} must parse"));
            assert_eq!(parsed.as_str(), expected, "{raw}");
        }
    }

    #[test]
    fn an_invalid_public_url_is_rejected() {
        for raw in [
            "",
            "example.org",                   // no scheme
            "ftp://example.org",             // wrong scheme
            "https://",                      // no host
            "https://example.org/dashboard", // a path is not an origin
            "https://example.org?x=1",
            "https://example.org#fragment",
            "https://alice@example.org", // userinfo
            "https://example.org:99999", // port out of range
            "https://example.org:abc",
            "https://exa mple.org",
            "https://::1", // a bare IPv6 address must be bracketed
            "null",
        ] {
            assert!(PublicUrl::parse(raw).is_none(), "{raw:?} must be rejected");
            let env = FakeEnv::default().with(VAR_PUBLIC_URL, raw);
            let err = Config::load(&env).expect_err("an invalid public URL must fail");
            assert!(matches!(err, ConfigError::Invalid { var } if var == VAR_PUBLIC_URL));
        }
    }

    #[test]
    fn origin_header_matching_accepts_only_the_same_origin() {
        let public = PublicUrl::parse("https://example.org").unwrap();

        for origin in [
            "https://example.org",
            "https://example.org:443", // the default port is equivalent
            "HTTPS://EXAMPLE.ORG",
        ] {
            assert!(public.matches_origin_header(origin), "{origin} must match");
        }

        for origin in [
            "http://example.org",       // different scheme
            "https://example.com",      // different host
            "https://sub.example.org",  // different host
            "https://example.org:8443", // different port
            "null",                     // an opaque origin
            "",
            "https://example.org/path",
        ] {
            assert!(
                !public.matches_origin_header(origin),
                "{origin:?} must not match"
            );
        }
    }

    // --- trusted proxies ----------------------------------------------

    #[test]
    fn trusted_proxies_accept_cidrs_and_bare_addresses() {
        let env =
            FakeEnv::default().with(VAR_TRUSTED_PROXIES, "192.0.2.0/24, 192.0.2.200, ::1/128");
        let config = Config::load(&env).expect("a valid proxy list must parse");
        let proxies = &config.trusted_proxies;

        assert!(!proxies.is_empty());
        assert!(proxies.contains("192.0.2.7".parse().unwrap()));
        assert!(proxies.contains("192.0.2.200".parse().unwrap()));
        assert!(proxies.contains("::1".parse().unwrap()));
        assert!(!proxies.contains("198.51.100.1".parse().unwrap()));
    }

    /// A dual-stack listener reports an IPv4 peer as `::ffff:a.b.c.d`.
    /// That must still match a range written in IPv4 form, or a proxy
    /// would silently stop being trusted.
    #[test]
    fn trusted_proxies_match_an_ipv4_mapped_peer() {
        let env = FakeEnv::default().with(VAR_TRUSTED_PROXIES, "192.0.2.0/24");
        let config = Config::load(&env).expect("valid");
        assert!(config
            .trusted_proxies
            .contains("::ffff:192.0.2.7".parse().unwrap()));
    }

    #[test]
    fn an_empty_proxy_list_trusts_nobody() {
        for raw in ["", "   ", ",", " , , "] {
            let env = FakeEnv::default().with(VAR_TRUSTED_PROXIES, raw);
            let config = Config::load(&env).expect("an empty list is valid");
            assert!(config.trusted_proxies.is_empty(), "{raw:?}");
            assert!(!config
                .trusted_proxies
                .contains("192.0.2.1".parse().unwrap()));
        }
    }

    #[test]
    fn an_invalid_proxy_list_fails_at_startup() {
        for raw in [
            "not-an-address",
            "192.0.2.0/33",
            "192.0.2.0/24, garbage",
            "192.0.2.256",
        ] {
            let env = FakeEnv::default().with(VAR_TRUSTED_PROXIES, raw);
            let err = Config::load(&env).expect_err("an invalid proxy list must fail");
            assert!(
                matches!(err, ConfigError::Invalid { var } if var == VAR_TRUSTED_PROXIES),
                "{raw:?} produced {err:?}"
            );
        }
    }

    // --- rate limits --------------------------------------------------

    #[test]
    fn rate_limits_parse_from_max_over_window() {
        let env = FakeEnv::default()
            .with(VAR_RATE_LIMIT_LOGIN_IP, "3/60")
            .with(VAR_RATE_LIMIT_LOGIN_USERNAME, " 2 / 30 ")
            .with(VAR_RATE_LIMIT_SETUP_IP, "1/120")
            .with(VAR_RATE_LIMIT_MAX_ENTRIES, "500");
        let config = Config::load(&env).expect("valid limits must parse");

        assert_eq!(config.rate_limit_login_ip.max, 3);
        assert_eq!(config.rate_limit_login_ip.window, Duration::from_secs(60));
        assert_eq!(config.rate_limit_login_username.max, 2);
        assert_eq!(
            config.rate_limit_login_username.window,
            Duration::from_secs(30)
        );
        assert_eq!(config.rate_limit_setup_ip.max, 1);
        assert_eq!(config.rate_limit_max_entries, 500);
    }

    #[test]
    fn an_invalid_rate_limit_is_rejected() {
        for raw in ["", "10", "10/", "/300", "0/300", "10/0", "-1/300", "a/b"] {
            let env = FakeEnv::default().with(VAR_RATE_LIMIT_LOGIN_IP, raw);
            let err = Config::load(&env).expect_err("an invalid rate limit must fail");
            assert!(
                matches!(err, ConfigError::Invalid { var } if var == VAR_RATE_LIMIT_LOGIN_IP),
                "{raw:?} produced {err:?}"
            );
        }
    }

    /// Zero tracked entries would mean the limiter holds no state and
    /// therefore enforces nothing.
    #[test]
    fn zero_rate_limit_entries_is_rejected() {
        let env = FakeEnv::default().with(VAR_RATE_LIMIT_MAX_ENTRIES, "0");
        let err = Config::load(&env).expect_err("zero entries must fail");
        assert!(
            matches!(err, ConfigError::BelowMinimum { var } if var == VAR_RATE_LIMIT_MAX_ENTRIES)
        );
    }

    // --- Argon2 -------------------------------------------------------

    #[test]
    fn argon2_parameters_below_the_floor_are_rejected_by_name() {
        let cases = [
            (VAR_ARGON2_M_COST, "19455"),
            (VAR_ARGON2_T_COST, "1"),
            (VAR_ARGON2_P_COST, "0"),
        ];
        for (var, value) in cases {
            let env = FakeEnv::default().with(var, value);
            let err = Config::load(&env).expect_err("below the floor must fail");
            assert!(
                matches!(err, ConfigError::BelowMinimum { var: named } if named == var),
                "{var} produced {err:?}"
            );
        }
    }

    #[test]
    fn argon2_parameters_above_the_floor_are_accepted() {
        let env = FakeEnv::default()
            .with(VAR_ARGON2_M_COST, "65536")
            .with(VAR_ARGON2_T_COST, "3")
            .with(VAR_ARGON2_P_COST, "2")
            .with(VAR_ARGON2_MAX_CONCURRENT, "4")
            .with(VAR_ARGON2_WAIT_TIMEOUT, "9");
        let config = Config::load(&env).expect("stronger parameters must be accepted");
        assert_eq!(config.argon2.m_cost_kib(), 65_536);
        assert_eq!(config.argon2.t_cost(), 3);
        assert_eq!(config.argon2.p_cost(), 2);
        assert_eq!(config.argon2_max_concurrent, 4);
        assert_eq!(config.argon2_wait_timeout, Duration::from_secs(9));
    }

    /// Zero concurrent hashes would wedge every login attempt.
    #[test]
    fn zero_concurrent_hashes_is_rejected() {
        let env = FakeEnv::default().with(VAR_ARGON2_MAX_CONCURRENT, "0");
        let err = Config::load(&env).expect_err("zero must fail");
        assert!(
            matches!(err, ConfigError::BelowMinimum { var } if var == VAR_ARGON2_MAX_CONCURRENT)
        );
    }

    // --- session timeouts ---------------------------------------------

    #[test]
    fn session_timeouts_are_configurable() {
        let env = FakeEnv::default()
            .with(VAR_SESSION_IDLE, "60")
            .with(VAR_SESSION_ABSOLUTE, "120");
        let config = Config::load(&env).expect("valid timeouts must parse");
        assert_eq!(config.session_idle_timeout, Duration::from_secs(60));
        assert_eq!(config.session_absolute_timeout, Duration::from_secs(120));
    }

    #[test]
    fn an_idle_timeout_longer_than_the_absolute_one_is_rejected() {
        let env = FakeEnv::default()
            .with(VAR_SESSION_IDLE, "200")
            .with(VAR_SESSION_ABSOLUTE, "100");
        let err = Config::load(&env).expect_err("an unreachable idle window must fail");
        assert!(matches!(
            err,
            ConfigError::OutOfOrder { var, other }
                if var == VAR_SESSION_IDLE && other == VAR_SESSION_ABSOLUTE
        ));
    }

    #[test]
    fn a_zero_or_unparseable_duration_is_rejected() {
        for var in [
            VAR_SESSION_IDLE,
            VAR_SESSION_ABSOLUTE,
            VAR_ARGON2_WAIT_TIMEOUT,
        ] {
            for value in ["0", "-5", "forever", ""] {
                let env = FakeEnv::default().with(var, value);
                let err = Config::load(&env).expect_err("must fail");
                assert!(
                    matches!(err, ConfigError::Invalid { var: named } if named == var),
                    "{var}={value:?} produced {err:?}"
                );
            }
        }
    }

    #[test]
    fn plain_variable_overrides_default() {
        let env = FakeEnv::default().with(VAR_LOG, "DEBUG");
        let config = Config::load(&env).expect("DEBUG is a valid level");
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn file_variant_is_read_and_trimmed() {
        let file = TempFile::with_content("warn\n");
        let env = FakeEnv::default().with(&format!("{VAR_LOG}_FILE"), file.path_str());
        let config = Config::load(&env).expect("file-provided value must be valid");
        assert_eq!(config.log_level, "warn");
    }

    #[test]
    fn setting_both_plain_and_file_is_ambiguous() {
        let file = TempFile::with_content("warn");
        let env = FakeEnv::default()
            .with(VAR_LOG, "info")
            .with(&format!("{VAR_LOG}_FILE"), file.path_str());
        let err = Config::load(&env).expect_err("ambiguous source must fail");
        assert!(matches!(err, ConfigError::AmbiguousSource { var } if var == VAR_LOG));
    }

    #[test]
    fn invalid_bind_addr_is_rejected() {
        let env = FakeEnv::default().with(VAR_BIND_ADDR, "not-an-address");
        let err = Config::load(&env).expect_err("invalid bind addr must fail");
        assert!(matches!(err, ConfigError::Invalid { var } if var == VAR_BIND_ADDR));
    }

    #[test]
    fn invalid_log_level_is_rejected() {
        let env = FakeEnv::default().with(VAR_LOG, "verbose");
        let err = Config::load(&env).expect_err("unknown level must fail");
        assert!(matches!(err, ConfigError::Invalid { var } if var == VAR_LOG));
    }

    #[test]
    fn empty_data_dir_is_rejected() {
        let env = FakeEnv::default().with(VAR_DATA_DIR, "   ");
        let err = Config::load(&env).expect_err("blank data dir must fail");
        assert!(matches!(err, ConfigError::Invalid { var } if var == VAR_DATA_DIR));
    }

    #[test]
    fn missing_file_referenced_by_file_variant_is_rejected() {
        let env = FakeEnv::default().with(
            &format!("{VAR_LOG}_FILE"),
            "/nonexistent/path/does-not-exist",
        );
        let err = Config::load(&env).expect_err("missing file must fail");
        assert!(matches!(err, ConfigError::FileRead { var } if var == VAR_LOG));
    }

    #[test]
    fn error_messages_never_contain_the_offending_value() {
        let env = FakeEnv::default().with(VAR_LOG, "super-secret-looking-value");
        let err = Config::load(&env).expect_err("invalid level must fail");
        let message = err.to_string();
        assert!(!message.contains("super-secret-looking-value"));
    }

    /// Pinned as one exact string rather than a set of `contains`
    /// checks: `Config` formats itself by hand so that a new field is a
    /// deliberate decision, and this test is the thing that makes
    /// skipping that decision noisy. If it fails because a field was
    /// added, add it here too - after checking it is safe to print.
    #[test]
    fn debug_output_contains_only_the_known_safe_fields() {
        let config = Config::load(&FakeEnv::default()).unwrap();
        assert_eq!(
            format!("{config:?}"),
            concat!(
                "Config { ",
                "bind_addr: 127.0.0.1:8080, ",
                "data_dir: \"./data\", ",
                "log_level: \"info\", ",
                "public_url: \"http://127.0.0.1:8080\", ",
                "trusted_proxies: TrustedProxies([]), ",
                "session_idle_timeout: 604800s, ",
                "session_absolute_timeout: 2592000s, ",
                "argon2: HashingParams { m_cost_kib: 19456, t_cost: 2, p_cost: 1 }, ",
                "argon2_max_concurrent: 2, ",
                "argon2_wait_timeout: 5s, ",
                "rate_limit_login_ip: RateLimitRule { max: 10, window: 300s }, ",
                "rate_limit_login_username: RateLimitRule { max: 5, window: 300s }, ",
                "rate_limit_setup_ip: RateLimitRule { max: 5, window: 3600s }, ",
                "rate_limit_max_entries: 10000",
                " }",
            )
        );
    }

    /// Whatever else changes, a dump of the configuration must never
    /// carry anything that looks like a credential.
    #[test]
    fn debug_output_carries_no_secret_material() {
        let env = FakeEnv::default()
            .with(VAR_BIND_ADDR, "0.0.0.0:8080")
            .with(VAR_PUBLIC_URL, "https://example.org")
            .with(VAR_TRUSTED_PROXIES, "192.0.2.0/24");
        let debug = format!("{:?}", Config::load(&env).unwrap());
        for marker in ["password", "token", "secret", "cookie", "csrf"] {
            assert!(
                !debug.to_ascii_lowercase().contains(marker),
                "Debug output mentions {marker:?}: {debug}"
            );
        }
    }
}
