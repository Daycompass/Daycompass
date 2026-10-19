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

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

const VAR_BIND_ADDR: &str = "SCREENWARD_BIND_ADDR";
const VAR_DATA_DIR: &str = "SCREENWARD_DATA_DIR";
const VAR_LOG: &str = "SCREENWARD_LOG";

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_DATA_DIR: &str = "./data";
const DEFAULT_LOG_LEVEL: &str = "info";

const VALID_LOG_LEVELS: &[&str] = &["error", "warn", "info", "debug", "trace"];

/// Backend configuration. Construct with [`Config::from_env`].
pub struct Config {
    pub bind_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub log_level: String,
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

impl Config {
    /// Loads configuration from the real process environment. Fails on the
    /// first invalid or ambiguous variable; never includes any value in
    /// the returned error.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::load(&ProcessEnv)
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

        Ok(Config {
            bind_addr,
            data_dir,
            log_level,
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

    #[test]
    fn debug_output_contains_only_the_known_safe_fields() {
        let config = Config::load(&FakeEnv::default()).unwrap();
        let debug = format!("{config:?}");
        assert_eq!(
            debug,
            format!(
                "Config {{ bind_addr: {:?}, data_dir: {:?}, log_level: {:?} }}",
                config.bind_addr, config.data_dir, config.log_level
            )
        );
    }
}
