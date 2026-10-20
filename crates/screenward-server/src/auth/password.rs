//! The password policy and Argon2id hashing.
//!
//! Hashing a password deliberately costs about 19 MiB of memory and a
//! few milliseconds of CPU, which is the whole point of Argon2 - and
//! also a denial-of-service lever if an attacker can start arbitrarily
//! many hashes at once. Two things bound that: a semaphore caps how many
//! hashes run concurrently, and waiting for a permit has a timeout, so a
//! flood is shed rather than queued until the process runs out of
//! memory. The work itself runs on [`tokio::task::spawn_blocking`], off
//! the async runtime's worker threads.
//!
//! Nothing in this module formats, logs, or serializes a password. The
//! plaintext only ever appears behind [`SecretString::expose`] and in the
//! byte buffer handed to Argon2, which is zeroized as soon as hashing
//! returns.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    ARGON2ID_IDENT,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroize;

use super::secret::SecretString;

/// Shortest accepted password, in characters. Length is the only rule:
/// composition requirements (a digit, a symbol, mixed case) push people
/// towards predictable substitutions and are not applied here.
pub const MIN_CHARS: usize = 12;

/// Longest accepted password, in characters. An upper bound exists so a
/// single request cannot ask Argon2 to chew through a huge input.
pub const MAX_CHARS: usize = 128;

/// OWASP's minimum Argon2id memory cost, in KiB.
pub const MIN_M_COST_KIB: u32 = 19_456;

/// OWASP's minimum Argon2id iteration count.
pub const MIN_T_COST: u32 = 2;

/// OWASP's minimum Argon2id parallelism.
pub const MIN_P_COST: u32 = 1;

/// Why a password was rejected. These messages describe the rule, which
/// is public, and never echo the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordPolicyError {
    #[error("the password must not be empty or only whitespace")]
    Blank,

    #[error("the password must be between {MIN_CHARS} and {MAX_CHARS} characters long")]
    Length,
}

/// A password that satisfies the policy. Still secret: this type only
/// certifies the length rules were checked, it does not make the value
/// any less sensitive.
pub struct Password(SecretString);

impl Password {
    /// Checks `candidate` against the policy.
    ///
    /// No Unicode normalization is applied. The bytes are hashed exactly
    /// as received, so a password typed with a differently composed
    /// accent will not verify. Normalizing would mean another dependency
    /// and a migration for every stored hash, so it is left out
    /// knowingly rather than by oversight.
    pub fn parse(candidate: SecretString) -> Result<Self, PasswordPolicyError> {
        if candidate.is_blank() {
            return Err(PasswordPolicyError::Blank);
        }

        let length = candidate.char_count();
        if !(MIN_CHARS..=MAX_CHARS).contains(&length) {
            return Err(PasswordPolicyError::Length);
        }

        Ok(Self(candidate))
    }

    /// Checks only blankness and the upper bound, not the minimum
    /// length.
    ///
    /// Login uses this rather than [`Password::parse`]. The minimum is a
    /// rule for *choosing* a password, not for presenting one: raising
    /// it later must stop new weak passwords, not lock out every
    /// existing account whose password is now below the new floor.
    ///
    /// The upper bound still applies, because it bounds the work a
    /// single request can ask for. Rejecting on it leaks nothing about
    /// accounts - the outcome depends only on the caller's own input.
    pub fn parse_for_verification(candidate: SecretString) -> Result<Self, PasswordPolicyError> {
        if candidate.is_blank() {
            return Err(PasswordPolicyError::Blank);
        }
        if candidate.char_count() > MAX_CHARS {
            return Err(PasswordPolicyError::Length);
        }
        Ok(Self(candidate))
    }

    fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegates to SecretString, which redacts itself.
        f.debug_tuple("Password").field(&self.0).finish()
    }
}

/// Argon2id cost parameters, guaranteed to be at least the OWASP
/// minimum. Construction goes through [`HashingParams::new`], so a
/// weaker set cannot exist as a value of this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashingParams {
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
}

/// The configured parameters were below the floor, or Argon2 rejected
/// them. Names the parameter, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParamsError {
    #[error("the Argon2 memory cost must be at least {MIN_M_COST_KIB} KiB")]
    MemoryTooLow,

    #[error("the Argon2 iteration count must be at least {MIN_T_COST}")]
    IterationsTooLow,

    #[error("the Argon2 parallelism must be at least {MIN_P_COST}")]
    ParallelismTooLow,

    #[error("Argon2 rejected the combination of parameters")]
    Rejected,
}

impl HashingParams {
    /// Validates a configured set of parameters.
    pub fn new(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<Self, ParamsError> {
        if m_cost_kib < MIN_M_COST_KIB {
            return Err(ParamsError::MemoryTooLow);
        }
        if t_cost < MIN_T_COST {
            return Err(ParamsError::IterationsTooLow);
        }
        if p_cost < MIN_P_COST {
            return Err(ParamsError::ParallelismTooLow);
        }

        let candidate = Self {
            m_cost_kib,
            t_cost,
            p_cost,
        };
        // Argon2 has its own internal constraints (for instance m_cost
        // relative to p_cost); reject here rather than at the first
        // login attempt.
        candidate.to_argon2()?;
        Ok(candidate)
    }

    /// The floor itself, which is also the default.
    pub const fn owasp_minimum() -> Self {
        Self {
            m_cost_kib: MIN_M_COST_KIB,
            t_cost: MIN_T_COST,
            p_cost: MIN_P_COST,
        }
    }

    pub fn m_cost_kib(self) -> u32 {
        self.m_cost_kib
    }

    pub fn t_cost(self) -> u32 {
        self.t_cost
    }

    pub fn p_cost(self) -> u32 {
        self.p_cost
    }

    fn to_argon2(self) -> Result<Params, ParamsError> {
        Params::new(self.m_cost_kib, self.t_cost, self.p_cost, None)
            .map_err(|_| ParamsError::Rejected)
    }
}

/// The outcome of checking a password against a stored hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The password matched. `needs_rehash` is true when the stored hash
    /// was produced with a weaker configuration than the current one, so
    /// the caller should replace it now that it holds the plaintext.
    Match { needs_rehash: bool },
    /// The password did not match.
    Mismatch,
}

/// Something went wrong while hashing - as opposed to the password
/// simply being wrong, which is [`Verification::Mismatch`].
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("the server is too busy to process a password right now")]
    Busy,

    #[error("the stored password hash is malformed")]
    MalformedStoredHash,

    #[error("hashing a password failed")]
    Backend,

    #[error("the password hashing task did not finish")]
    TaskFailed,
}

/// Hashes and verifies passwords under a concurrency cap.
///
/// Cheap to clone: clones share the same semaphore, which is what makes
/// the cap global rather than per-clone.
#[derive(Clone)]
pub struct Hasher {
    params: HashingParams,
    permits: Arc<Semaphore>,
    wait_timeout: Duration,
}

impl Hasher {
    /// `max_concurrent` is how many hashes may run at once; it is
    /// clamped to at least 1, since zero would wedge every login.
    /// `wait_timeout` bounds how long a request waits for a permit.
    pub fn new(params: HashingParams, max_concurrent: usize, wait_timeout: Duration) -> Self {
        Self {
            params,
            permits: Arc::new(Semaphore::new(max_concurrent.max(1))),
            wait_timeout,
        }
    }

    pub fn params(&self) -> HashingParams {
        self.params
    }

    /// How long a caller may wait for a permit. Handlers use this as the
    /// `Retry-After` value when they have to shed a request.
    pub fn wait_timeout(&self) -> Duration {
        self.wait_timeout
    }

    /// Hashes `password` into a PHC string, with a fresh random salt.
    pub async fn hash(&self, password: &Password) -> Result<String, HashError> {
        let params = self.params;
        self.run_blocking(password, move |secret| {
            let argon2 = build_argon2(params)?;
            argon2
                .hash_password(secret)
                .map(|hash| hash.to_string())
                .map_err(|_| HashError::Backend)
        })
        .await
    }

    /// Checks `password` against `stored_phc` and reports whether that
    /// stored hash is now below the configured parameters.
    ///
    /// Verification uses the parameters recorded *in the stored hash*,
    /// not the configured ones - that is what lets an old, weaker hash
    /// still verify so it can be upgraded.
    pub async fn verify(
        &self,
        password: &Password,
        stored_phc: &str,
    ) -> Result<Verification, HashError> {
        let params = self.params;
        let stored = stored_phc.to_owned();

        self.run_blocking(password, move |secret| {
            let parsed = PasswordHash::new(&stored).map_err(|_| HashError::MalformedStoredHash)?;
            // A PHC string parses even with no salt and no output - for
            // instance a truncated column. verify_password answers
            // PasswordInvalid for those, which would report database
            // corruption as a wrong password forever, with nothing
            // logged. Check explicitly instead of relying on that
            // fall-through.
            if parsed.salt.is_none() || parsed.hash.is_none() {
                return Err(HashError::MalformedStoredHash);
            }
            // Any configured instance works here: verify_password reads
            // the algorithm, version and parameters out of `parsed`.
            let argon2 = build_argon2(params)?;
            match argon2.verify_password(secret, &parsed) {
                Ok(()) => Ok(Verification::Match {
                    needs_rehash: is_below(&parsed, params),
                }),
                Err(argon2::password_hash::Error::PasswordInvalid) => Ok(Verification::Mismatch),
                Err(_) => Err(HashError::MalformedStoredHash),
            }
        })
        .await
    }

    /// Hashes a throwaway random password with the current parameters.
    ///
    /// Login verifies against this when the username is unknown, so an
    /// unknown account costs the same work as a known one. The plaintext
    /// is discarded here and never leaves this function, so nothing can
    /// ever verify successfully against the result.
    pub async fn decoy_hash(&self) -> Result<String, HashError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| HashError::Backend)?;
        let mut encoded = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();

        let password =
            Password::parse(SecretString::new(encoded.clone())).map_err(|_| HashError::Backend)?;
        encoded.zeroize();

        self.hash(&password).await
    }

    async fn acquire(&self) -> Result<OwnedSemaphorePermit, HashError> {
        match tokio::time::timeout(self.wait_timeout, self.permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            // Waited too long, or the semaphore was closed during
            // shutdown. Either way the caller is shed, not queued.
            Ok(Err(_)) | Err(_) => Err(HashError::Busy),
        }
    }

    /// Takes a permit, copies the plaintext into an owned buffer, runs
    /// `work` on a blocking thread, and zeroizes the buffer afterwards.
    async fn run_blocking<T, F>(&self, password: &Password, work: F) -> Result<T, HashError>
    where
        T: Send + 'static,
        F: FnOnce(&[u8]) -> Result<T, HashError> + Send + 'static,
    {
        let permit = self.acquire().await?;
        // spawn_blocking needs an owned, 'static buffer, so the
        // plaintext is copied once. The copy is wiped below before the
        // thread returns.
        let mut secret = password.expose().as_bytes().to_vec();

        let joined = tokio::task::spawn_blocking(move || {
            let result = work(&secret);
            secret.zeroize();
            result
        })
        .await;

        drop(permit);
        joined.map_err(|_| HashError::TaskFailed)?
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No secrets here, but spelled out so a future field has to be
        // considered rather than printed by default.
        f.debug_struct("Hasher")
            .field("params", &self.params)
            .field("available_permits", &self.permits.available_permits())
            .field("wait_timeout", &self.wait_timeout)
            .finish()
    }
}

fn build_argon2(params: HashingParams) -> Result<Argon2<'static>, HashError> {
    let params = params.to_argon2().map_err(|_| HashError::Backend)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// True if `stored` was produced with anything weaker than `current`.
///
/// "Weaker" covers a different algorithm or version as well as lower
/// cost parameters: an Argon2i or v0x10 hash is upgraded even when its
/// numbers look fine. An unparseable parameter string also counts, since
/// a hash whose cost cannot be determined cannot be trusted to meet the
/// floor.
fn is_below(stored: &PasswordHash, current: HashingParams) -> bool {
    if stored.algorithm != ARGON2ID_IDENT {
        return true;
    }
    if stored.version != Some(u32::from(Version::V0x13)) {
        return true;
    }
    match Params::try_from(stored) {
        Ok(params) => {
            params.m_cost() < current.m_cost_kib
                || params.t_cost() < current.t_cost
                || params.p_cost() < current.p_cost
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every password in these tests is generated at runtime, so no
    /// credential-shaped literal exists in the source.
    fn random_password() -> SecretString {
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        SecretString::new(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn password_of_length(chars: usize) -> SecretString {
        SecretString::new(std::iter::repeat_n('x', chars).collect())
    }

    /// Weakest parameters Argon2 itself will accept, for the rehash
    /// test. Built through `Params` directly, bypassing the floor that
    /// `HashingParams` enforces, because the point is to simulate a hash
    /// written by an older, laxer version of this server.
    fn legacy_weak_hash(password: &Password) -> String {
        let params = Params::new(Params::MIN_M_COST, 1, 1, None).expect("minimum params are valid");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon2
            .hash_password(password.expose().as_bytes())
            .expect("hashing must succeed")
            .to_string()
    }

    fn test_hasher() -> Hasher {
        Hasher::new(HashingParams::owasp_minimum(), 2, Duration::from_secs(10))
    }

    #[test]
    fn the_default_parameters_are_the_owasp_floor() {
        let params = HashingParams::owasp_minimum();
        assert_eq!(params.m_cost_kib(), 19_456);
        assert_eq!(params.t_cost(), 2);
        assert_eq!(params.p_cost(), 1);
        // The floor must itself be constructible through the validating
        // constructor.
        assert_eq!(
            HashingParams::new(19_456, 2, 1).expect("the floor must be valid"),
            params
        );
    }

    #[test]
    fn parameters_below_the_floor_are_rejected() {
        assert_eq!(
            HashingParams::new(MIN_M_COST_KIB - 1, MIN_T_COST, MIN_P_COST),
            Err(ParamsError::MemoryTooLow)
        );
        assert_eq!(
            HashingParams::new(MIN_M_COST_KIB, MIN_T_COST - 1, MIN_P_COST),
            Err(ParamsError::IterationsTooLow)
        );
        assert_eq!(
            HashingParams::new(MIN_M_COST_KIB, MIN_T_COST, MIN_P_COST - 1),
            Err(ParamsError::ParallelismTooLow)
        );
        assert_eq!(HashingParams::new(0, 0, 0), Err(ParamsError::MemoryTooLow));
    }

    #[test]
    fn stronger_parameters_are_accepted() {
        let params = HashingParams::new(MIN_M_COST_KIB * 2, MIN_T_COST + 1, MIN_P_COST + 1)
            .expect("stronger than the floor must be valid");
        assert_eq!(params.m_cost_kib(), MIN_M_COST_KIB * 2);
    }

    #[test]
    fn the_password_policy_enforces_only_length_and_blankness() {
        assert_eq!(
            Password::parse(SecretString::new(String::new())).unwrap_err(),
            PasswordPolicyError::Blank
        );
        assert_eq!(
            Password::parse(SecretString::new("   \t\n  ".to_owned())).unwrap_err(),
            PasswordPolicyError::Blank
        );
        assert_eq!(
            Password::parse(password_of_length(MIN_CHARS - 1)).unwrap_err(),
            PasswordPolicyError::Length
        );
        assert_eq!(
            Password::parse(password_of_length(MAX_CHARS + 1)).unwrap_err(),
            PasswordPolicyError::Length
        );

        assert!(Password::parse(password_of_length(MIN_CHARS)).is_ok());
        assert!(Password::parse(password_of_length(MAX_CHARS)).is_ok());
        // No composition rules: all digits, or all one repeated
        // character, is accepted at the right length.
        assert!(Password::parse(SecretString::new("012345678901".to_owned())).is_ok());
    }

    /// Tightening the minimum must not lock existing accounts out, so
    /// verification accepts a password the current policy would refuse
    /// to set.
    #[test]
    fn verification_does_not_enforce_the_minimum_length() {
        let short = password_of_length(MIN_CHARS - 4);
        assert_eq!(
            Password::parse(password_of_length(MIN_CHARS - 4)).unwrap_err(),
            PasswordPolicyError::Length,
            "setting it must still be refused"
        );
        assert!(
            Password::parse_for_verification(short).is_ok(),
            "presenting it must still be allowed"
        );

        // The upper bound and blankness still apply.
        assert_eq!(
            Password::parse_for_verification(password_of_length(MAX_CHARS + 1)).unwrap_err(),
            PasswordPolicyError::Length
        );
        assert_eq!(
            Password::parse_for_verification(SecretString::new("  ".to_owned())).unwrap_err(),
            PasswordPolicyError::Blank
        );
    }

    #[test]
    fn length_is_counted_in_characters_not_bytes() {
        // MIN_CHARS multi-byte characters: too short by bytes would be
        // wrong, and too long would be wrong too.
        let value: String = std::iter::repeat_n('\u{1f600}', MIN_CHARS).collect();
        assert!(value.len() > MIN_CHARS, "the test input must be multi-byte");
        assert!(Password::parse(SecretString::new(value)).is_ok());

        let too_long: String = std::iter::repeat_n('\u{1f600}', MAX_CHARS + 1).collect();
        assert_eq!(
            Password::parse(SecretString::new(too_long)).unwrap_err(),
            PasswordPolicyError::Length
        );
    }

    #[test]
    fn debug_output_leaks_neither_the_password_nor_the_hasher_state() {
        let secret = random_password();
        let plaintext = secret.expose().to_owned();
        let password = Password::parse(secret).expect("a random 32-character password is valid");

        let debug = format!("{password:?}");
        assert!(!debug.contains(&plaintext), "Debug must not leak");
        assert!(debug.contains("[redacted]"));

        // The hasher's own Debug is safe, and shows no secret material.
        let hasher_debug = format!("{:?}", test_hasher());
        assert!(hasher_debug.contains("Hasher"));
        assert!(!hasher_debug.contains(&plaintext));
    }

    #[tokio::test]
    async fn a_hash_is_a_phc_string_with_the_configured_parameters() {
        let password = Password::parse(random_password()).unwrap();
        let phc = test_hasher().hash(&password).await.expect("hashing works");

        assert!(phc.starts_with("$argon2id$v=19$"));
        let parsed = PasswordHash::new(&phc).expect("our own output must parse");
        assert_eq!(parsed.algorithm, ARGON2ID_IDENT);
        assert_eq!(parsed.version, Some(19));
        let params = Params::try_from(&parsed).expect("parameters must parse");
        assert_eq!(params.m_cost(), MIN_M_COST_KIB);
        assert_eq!(params.t_cost(), MIN_T_COST);
        assert_eq!(params.p_cost(), MIN_P_COST);
    }

    #[tokio::test]
    async fn the_plaintext_does_not_appear_in_the_hash() {
        let secret = random_password();
        let plaintext = secret.expose().to_owned();
        let password = Password::parse(secret).unwrap();
        let phc = test_hasher().hash(&password).await.unwrap();
        assert!(!phc.contains(&plaintext));
    }

    #[tokio::test]
    async fn the_same_password_hashes_differently_every_time() {
        let hasher = test_hasher();
        let password = Password::parse(random_password()).unwrap();
        let first = hasher.hash(&password).await.unwrap();
        let second = hasher.hash(&password).await.unwrap();
        assert_ne!(first, second, "each hash must use a fresh random salt");

        // Both must still verify.
        for phc in [first, second] {
            assert_eq!(
                hasher.verify(&password, &phc).await.unwrap(),
                Verification::Match {
                    needs_rehash: false
                }
            );
        }
    }

    #[tokio::test]
    async fn the_wrong_password_does_not_verify() {
        let hasher = test_hasher();
        let password = Password::parse(random_password()).unwrap();
        let other = Password::parse(random_password()).unwrap();
        let phc = hasher.hash(&password).await.unwrap();

        assert_eq!(
            hasher.verify(&other, &phc).await.unwrap(),
            Verification::Mismatch
        );
    }

    #[tokio::test]
    async fn a_hash_with_weaker_parameters_verifies_but_asks_for_a_rehash() {
        let hasher = test_hasher();
        let password = Password::parse(random_password()).unwrap();
        let weak = legacy_weak_hash(&password);

        // It must still verify - otherwise an upgrade could never happen,
        // because the user could not log in to trigger it.
        assert_eq!(
            hasher.verify(&password, &weak).await.unwrap(),
            Verification::Match { needs_rehash: true }
        );

        // And the wrong password against a weak hash is still a
        // mismatch, not an accidental upgrade path.
        let other = Password::parse(random_password()).unwrap();
        assert_eq!(
            hasher.verify(&other, &weak).await.unwrap(),
            Verification::Mismatch
        );

        // Rehashing produces something that no longer asks for it.
        let rehashed = hasher.hash(&password).await.unwrap();
        assert_eq!(
            hasher.verify(&password, &rehashed).await.unwrap(),
            Verification::Match {
                needs_rehash: false
            }
        );
    }

    #[tokio::test]
    async fn a_hash_from_a_stronger_configuration_is_not_downgraded() {
        // A server that was reconfigured downwards must not rewrite
        // existing, stronger hashes into weaker ones.
        let strong = Hasher::new(
            HashingParams::new(MIN_M_COST_KIB * 2, MIN_T_COST + 1, MIN_P_COST).unwrap(),
            1,
            Duration::from_secs(10),
        );
        let password = Password::parse(random_password()).unwrap();
        let phc = strong.hash(&password).await.unwrap();

        let weaker_config = test_hasher();
        assert_eq!(
            weaker_config.verify(&password, &phc).await.unwrap(),
            Verification::Match {
                needs_rehash: false
            }
        );
    }

    #[tokio::test]
    async fn an_argon2i_hash_is_upgraded_even_at_adequate_cost() {
        // Right cost, wrong variant: Argon2i rather than Argon2id.
        let password = Password::parse(random_password()).unwrap();
        let params = HashingParams::owasp_minimum().to_argon2().unwrap();
        let argon2i = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);
        let phc = argon2i
            .hash_password(password.expose().as_bytes())
            .unwrap()
            .to_string();

        assert_eq!(
            test_hasher().verify(&password, &phc).await.unwrap(),
            Verification::Match { needs_rehash: true }
        );
    }

    #[tokio::test]
    async fn a_malformed_stored_hash_is_an_error_not_a_match() {
        let hasher = test_hasher();
        let password = Password::parse(random_password()).unwrap();

        for stored in ["", "not-a-phc-string", "$argon2id$", "$argon2id$v=19$m=1"] {
            let result = hasher.verify(&password, stored).await;
            assert!(
                matches!(result, Err(HashError::MalformedStoredHash)),
                "{stored:?} must be rejected as malformed, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn nothing_verifies_against_a_decoy_hash() {
        let hasher = test_hasher();
        let decoy = hasher.decoy_hash().await.expect("the decoy must be built");

        // It is a well-formed hash at the current parameters, so using it
        // for an unknown username costs the same as a real one.
        let parsed = PasswordHash::new(&decoy).expect("the decoy must parse");
        assert_eq!(parsed.algorithm, ARGON2ID_IDENT);
        let params = Params::try_from(&parsed).unwrap();
        assert_eq!(params.m_cost(), MIN_M_COST_KIB);

        // Its plaintext was discarded, so no password matches it.
        for _ in 0..3 {
            let attempt = Password::parse(random_password()).unwrap();
            assert_eq!(
                hasher.verify(&attempt, &decoy).await.unwrap(),
                Verification::Mismatch
            );
        }

        // Two decoys differ, so one cannot be fingerprinted across
        // restarts.
        assert_ne!(decoy, hasher.decoy_hash().await.unwrap());
    }

    #[tokio::test]
    async fn waiting_too_long_for_a_permit_is_shed_as_busy() {
        // One permit, held for the whole test, and a wait timeout short
        // enough that the second caller gives up quickly.
        let hasher = Hasher::new(HashingParams::owasp_minimum(), 1, Duration::from_millis(50));
        let held = hasher
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("the only permit must be available");

        let password = Password::parse(random_password()).unwrap();
        let result = hasher.hash(&password).await;
        assert!(
            matches!(result, Err(HashError::Busy)),
            "a shed request must report Busy, got {result:?}"
        );

        // Once the permit is back, hashing works again - the limiter
        // sheds load, it does not latch.
        drop(held);
        assert!(hasher.hash(&password).await.is_ok());
    }

    #[tokio::test]
    async fn the_concurrency_cap_is_shared_across_clones() {
        let hasher = Hasher::new(HashingParams::owasp_minimum(), 1, Duration::from_millis(50));
        let clone = hasher.clone();
        let held = hasher
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("permit available");

        let password = Password::parse(random_password()).unwrap();
        assert!(matches!(clone.hash(&password).await, Err(HashError::Busy)));
        drop(held);
    }

    #[tokio::test]
    async fn concurrent_hashes_all_complete_under_the_cap() {
        let hasher = test_hasher();
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let hasher = hasher.clone();
            tasks.push(tokio::spawn(async move {
                let password = Password::parse(random_password()).unwrap();
                let phc = hasher.hash(&password).await.expect("hashing works");
                hasher.verify(&password, &phc).await.expect("verify works")
            }));
        }
        for task in tasks {
            assert_eq!(
                task.await.expect("no task may panic"),
                Verification::Match {
                    needs_rehash: false
                }
            );
        }
    }
}
