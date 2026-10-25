//! Shared harness for the HTTP integration tests.
//!
//! Every test drives the real router, with the real middleware stack,
//! against an in-memory SQLite database. Nothing is stubbed out: the
//! Argon2 parameters are the production floor, so these tests are not
//! fast, and the cost is accepted because weakening them would mean
//! testing a configuration nobody runs.
//!
//! No credential here is a literal. Passwords and tokens are generated
//! at runtime, so the test sources contain nothing credential-shaped.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tower::ServiceExt;

use daycompass_server::config::Config;
use daycompass_server::db::{connect, migrate, DbTarget};
use daycompass_server::state::AppState;

/// The peer address a request appears to come from unless a test says
/// otherwise. From the documentation range, per `CLAUDE.md`.
pub const DEFAULT_PEER: &str = "192.0.2.10:54321";

/// Matches the default configuration's public URL, which is what the
/// `Origin` check compares against.
pub const GOOD_ORIGIN: &str = "http://127.0.0.1:8080";

/// An origin that is not this instance.
pub const BAD_ORIGIN: &str = "https://attacker.example";

/// Rate limits high enough that a test which is not about rate limiting
/// never trips one.
pub const GENEROUS_LIMITS: &[(&str, &str)] = &[
    ("DAYCOMPASS_RATE_LIMIT_LOGIN_IP", "1000/300"),
    ("DAYCOMPASS_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
    ("DAYCOMPASS_RATE_LIMIT_SETUP_IP", "1000/3600"),
    ("DAYCOMPASS_RATE_LIMIT_PW_CHANGE", "1000/900"),
    ("DAYCOMPASS_RATE_LIMIT_PAIR_IP", "1000/300"),
    ("DAYCOMPASS_RATE_LIMIT_PAIR_GLOBAL", "100000/60"),
    ("DAYCOMPASS_RATE_LIMIT_INGEST_DEVICE", "1000/60"),
    // Generous, but not so generous that a test about this bucket
    // cannot reach it. `tests/device_auth_limit.rs` sets its own
    // tight values rather than relying on this one.
    ("DAYCOMPASS_RATE_LIMIT_DEVICE_AUTH_FAIL", "1000/60"),
    ("DAYCOMPASS_RATE_LIMIT_EXPORT", "1000/3600"),
];

/// A running app plus the pool behind it.
pub struct TestApp {
    router: Router,
    pub pool: SqlitePool,
    /// Set for a file-backed app; removed on drop.
    data_dir: Option<std::path::PathBuf>,
}

impl TestApp {
    /// An app with generous rate limits, so a test that is not about
    /// rate limiting never trips one.
    pub async fn new() -> Self {
        Self::with_vars(GENEROUS_LIMITS).await
    }

    /// An app configured by explicit environment variables, without
    /// touching the real process environment.
    pub async fn with_vars(vars: &[(&str, &str)]) -> Self {
        let pool = connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect");
        migrate(&pool).await.expect("migrations must apply");
        Self::over(pool, None, vars).await
    }

    /// An app over a file-backed database in a fresh temporary
    /// directory.
    ///
    /// Needed wherever two requests have to be in flight at once: the
    /// in-memory pool is capped at a single connection, so concurrent
    /// requests would queue on the pool and never contend for SQLite's
    /// write lock - which is the thing a race test is about.
    pub async fn with_file_db() -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir = std::env::temp_dir().join(format!(
            "daycompass-http-test-{}-{unique}",
            std::process::id()
        ));
        let pool = connect(&DbTarget::File {
            data_dir: data_dir.clone(),
        })
        .await
        .expect("file pool must connect");
        migrate(&pool).await.expect("migrations must apply");

        Self::over(pool, Some(data_dir), GENEROUS_LIMITS).await
    }

    async fn over(
        pool: SqlitePool,
        data_dir: Option<std::path::PathBuf>,
        vars: &[(&str, &str)],
    ) -> Self {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let config = Config::for_test(&map).expect("the test configuration must be valid");

        let state = AppState::new(pool.clone(), &config)
            .await
            .expect("building the state must succeed");

        Self {
            router: daycompass_server::build_app(state),
            pool,
            data_dir,
        }
    }

    /// The router itself, for the test that serves it over a real
    /// socket rather than calling it with `oneshot`.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Sends one request and returns status, headers and parsed body.
    pub async fn send(&self, request: TestRequest) -> TestResponse {
        let response = self
            .router
            .clone()
            .oneshot(request.build())
            .await
            .expect("the router must answer");

        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("reading the body must not fail");
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };

        TestResponse {
            status,
            headers,
            body,
        }
    }

    /// Issues a setup token the way startup does, and returns it.
    pub async fn issue_setup_token(&self) -> String {
        use daycompass_server::auth::setup;
        use daycompass_server::auth::time::UnixTime;

        setup::issue_token_if_unprovisioned(&self.pool, UnixTime::now())
            .await
            .expect("issuing must succeed")
            .expect("an unprovisioned instance must issue a token")
            .expose()
            .to_owned()
    }

    /// A syntactically valid setup token for an instance that already
    /// has an admin, where `issue_setup_token` would correctly refuse to
    /// mint one.
    pub async fn issue_setup_token_after_provisioning(&self) -> String {
        use daycompass_server::auth::token::{Token, TokenKind};

        Token::generate(TokenKind::Setup)
            .expect("the OS CSPRNG must be available")
            .expose()
            .to_owned()
    }

    /// Completes setup over HTTP and returns the admin's credentials.
    pub async fn provision_admin(&self) -> Credentials {
        let token = self.issue_setup_token().await;
        let credentials = Credentials::generate("alice");

        let response = self
            .send(TestRequest::post("/api/v1/setup").json(json!({
                "setup_token": token,
                "username": credentials.username,
                "password": credentials.password,
            })))
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "setup must succeed: {:?}",
            response.body
        );
        credentials
    }

    /// Logs in and returns the cookie value and CSRF token.
    pub async fn log_in(&self, credentials: &Credentials) -> Session {
        let response = self
            .send(
                TestRequest::post("/api/v1/auth/login")
                    .origin(GOOD_ORIGIN)
                    .json(json!({
                        "username": credentials.username,
                        "password": credentials.password,
                    })),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "login must succeed: {:?}",
            response.body
        );

        Session {
            cookie: response.session_cookie().expect("a session cookie"),
            csrf_token: response.body["csrf_token"]
                .as_str()
                .expect("a CSRF token in the body")
                .to_owned(),
        }
    }

    /// Creates a pending account over HTTP as `admin`, and returns its
    /// id together with the raw invite: the token and its expiry.
    ///
    /// For tests that want the invite itself - expired, reused,
    /// malformed - rather than an account ready to log in with. Most
    /// tests want [`TestApp::create_account`] instead.
    pub async fn create_pending_account(
        &self,
        admin: &Session,
        username: &str,
        role: &str,
    ) -> (String, String, i64) {
        let response = self
            .send(
                TestRequest::post("/api/v1/users")
                    .origin(GOOD_ORIGIN)
                    .authenticated(admin)
                    .json(json!({
                        "username": username,
                        "role": role,
                    })),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "creating {username} must succeed: {:?}",
            response.body
        );
        let id = response.body["user"]["id"]
            .as_str()
            .expect("the created account's id")
            .to_owned();
        let token = response.body["invite"]["token"]
            .as_str()
            .expect("an invite token in the body")
            .to_owned();
        let expires_at = response.body["invite"]["expires_at"]
            .as_i64()
            .expect("an invite expiry in the body");
        (id, token, expires_at)
    }

    /// Creates an account over HTTP as `admin`, redeems its invite, and
    /// returns its id with the credentials it can now log in with.
    pub async fn create_account(
        &self,
        admin: &Session,
        username: &str,
        role: &str,
    ) -> (String, Credentials) {
        let (id, token, _expires_at) = self.create_pending_account(admin, username, role).await;
        let credentials = Credentials::generate(username);

        let response = self
            .send(
                TestRequest::post("/api/v1/invites/redeem")
                    .origin(GOOD_ORIGIN)
                    .json(json!({
                        "invite_token": token,
                        "new_password": credentials.password,
                    })),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::NO_CONTENT,
            "redeeming the invite for {username} must succeed: {:?}",
            response.body
        );

        (id, credentials)
    }

    /// Provisions the first admin and logs it in, which is the starting
    /// point of nearly every account-management test.
    pub async fn provisioned_admin(&self) -> (Credentials, Session) {
        let credentials = self.provision_admin().await;
        let session = self.log_in(&credentials).await;
        (credentials, session)
    }

    /// Adds a second admin and logs it in.
    pub async fn second_admin(&self, admin: &Session, username: &str) -> (String, Session) {
        let (id, credentials) = self.create_account(admin, username, "admin").await;
        let session = self.log_in(&credentials).await;
        (id, session)
    }

    /// Mints a pairing code for `session`'s account, over HTTP.
    pub async fn issue_pairing_code(&self, session: &Session) -> String {
        let response = self
            .send(
                TestRequest::post("/api/v1/pairing-codes")
                    .origin(GOOD_ORIGIN)
                    .authenticated(session),
            )
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "minting a pairing code must succeed: {:?}",
            response.body
        );
        response.body["pairing_code"]
            .as_str()
            .expect("a pairing code in the body")
            .to_owned()
    }

    /// Pairs a device for `session`'s account and returns it.
    ///
    /// Goes through the real two-step flow - mint, then redeem - so
    /// every test that needs a device is also exercising pairing.
    pub async fn pair_device(&self, session: &Session, name: &str, platform: &str) -> Device {
        let code = self.issue_pairing_code(session).await;
        self.redeem_pairing_code(&code, name, platform).await
    }

    /// Redeems a code that is already in hand, asserting it worked.
    pub async fn redeem_pairing_code(&self, code: &str, name: &str, platform: &str) -> Device {
        let response = self
            .send(TestRequest::post("/api/v1/pair").json(json!({
                "pairing_code": code,
                "device_name": name,
                "platform": platform,
            })))
            .await;
        assert_eq!(
            response.status,
            StatusCode::CREATED,
            "pairing must succeed: {:?}",
            response.body
        );

        Device {
            token: response.body["device_token"]
                .as_str()
                .expect("a device token in the body")
                .to_owned(),
            id: response.body["device"]["id"]
                .as_str()
                .expect("the device's id")
                .to_owned(),
        }
    }

    /// Mints a code, returning `None` if the account is at its cap.
    ///
    /// The fallible counterpart to [`TestApp::issue_pairing_code`],
    /// for the test that fills the cap deliberately.
    pub async fn issue_pairing_code_raw(&self, session: &Session) -> Option<String> {
        let response = self
            .send(
                TestRequest::post("/api/v1/pairing-codes")
                    .origin(GOOD_ORIGIN)
                    .authenticated(session),
            )
            .await;
        response.body["pairing_code"].as_str().map(str::to_owned)
    }

    /// Ages every outstanding pairing code out.
    ///
    /// Reaches into the database rather than sleeping: the expiry is
    /// ten minutes, and the thing under test is the `expires_at`
    /// comparison, not the clock.
    pub async fn expire_all_pairing_codes(&self) {
        sqlx::query("UPDATE pairing_codes SET expires_at = 1")
            .execute(&self.pool)
            .await
            .expect("expiring the codes must succeed");
    }

    pub async fn count_pairing_codes(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM pairing_codes")
            .fetch_one(&self.pool)
            .await
            .expect("counting must succeed")
    }

    pub async fn count_devices(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM devices")
            .fetch_one(&self.pool)
            .await
            .expect("counting must succeed")
    }

    pub async fn count_events(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(&self.pool)
            .await
            .expect("counting must succeed")
    }

    /// Dumps every value in every table as text, for the no-plaintext
    /// scan.
    pub async fn dump_all_values(&self) -> Vec<String> {
        use sqlx::{AssertSqlSafe, Column, Row};

        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_all(&self.pool)
        .await
        .expect("listing tables must succeed");

        let mut values = Vec::new();
        for table in tables {
            // Deliberately dynamic, and the only place in the codebase
            // that is: the table name comes from sqlite_master, not from
            // user input, and the point of the test is to look at every
            // table including ones added later.
            let rows = sqlx::query(AssertSqlSafe(format!("SELECT * FROM \"{table}\"")))
                .fetch_all(&self.pool)
                .await
                .unwrap_or_else(|err| panic!("reading {table} must succeed: {err}"));

            for row in rows {
                for index in 0..row.len() {
                    let column = row.column(index).name().to_owned();
                    // Read as whatever it is; a BLOB of hash bytes is
                    // read as lossy text so a plaintext needle would
                    // still be found inside it.
                    let text = row
                        .try_get::<String, _>(index)
                        .or_else(|_| {
                            row.try_get::<Vec<u8>, _>(index)
                                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                        })
                        .or_else(|_| row.try_get::<i64, _>(index).map(|n| n.to_string()))
                        .unwrap_or_default();
                    values.push(format!("{table}.{column}={text}"));
                }
            }
        }
        values
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if let Some(dir) = &self.data_dir {
            std::fs::remove_dir_all(dir).ok();
        }
    }
}

/// A username and password, generated at runtime.
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl Credentials {
    pub fn generate(username: &str) -> Self {
        Self {
            username: username.to_owned(),
            password: random_secret(),
        }
    }
}

/// What a successful login hands back.
pub struct Session {
    /// The `name=value` pair to send in a `Cookie` header.
    pub cookie: String,
    pub csrf_token: String,
}

/// What a successful pairing hands back.
pub struct Device {
    /// The bearer token, shown exactly once.
    pub token: String,
    pub id: String,
}

/// 32 bytes of randomness as base64url: well above the 12-character
/// minimum, and never a literal in the sources.
pub fn random_secret() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Builder for a request, including the peer address the extractor
/// needs.
pub struct TestRequest {
    method: Method,
    uri: String,
    peer: Option<String>,
    /// Every `Origin` header to send, in order. A list rather than one
    /// value so a test can send two, which the server must refuse.
    origins: Vec<String>,
    cookie: Option<String>,
    csrf: Option<String>,
    /// Every `Authorization` header to send, in order. A list so a
    /// test can send two, which the server must refuse.
    authorization: Vec<String>,
    forwarded: Vec<String>,
    body: Option<String>,
    /// Sent instead of a JSON body, for the oversized-body tests.
    raw_body: Option<Vec<u8>>,
    /// Suppresses the `Content-Type` header a body would otherwise
    /// imply, for the wrong-content-type test.
    omit_content_type: bool,
}

impl TestRequest {
    pub fn get(uri: &str) -> Self {
        Self::new(Method::GET, uri)
    }

    pub fn post(uri: &str) -> Self {
        Self::new(Method::POST, uri)
    }

    pub fn patch(uri: &str) -> Self {
        Self::new(Method::PATCH, uri)
    }

    pub fn delete(uri: &str) -> Self {
        Self::new(Method::DELETE, uri)
    }

    pub fn new(method: Method, uri: &str) -> Self {
        Self {
            method,
            uri: uri.to_owned(),
            peer: Some(DEFAULT_PEER.to_owned()),
            origins: Vec::new(),
            cookie: None,
            csrf: None,
            authorization: Vec::new(),
            forwarded: Vec::new(),
            body: None,
            raw_body: None,
            omit_content_type: false,
        }
    }

    pub fn peer(mut self, peer: &str) -> Self {
        self.peer = Some(peer.to_owned());
        self
    }

    /// Adds an `Origin` header. Calling it twice sends two, which is
    /// what the duplicate-header rejection is tested with.
    pub fn origin(mut self, origin: &str) -> Self {
        self.origins.push(origin.to_owned());
        self
    }

    pub fn cookie(mut self, cookie: &str) -> Self {
        self.cookie = Some(cookie.to_owned());
        self
    }

    pub fn csrf(mut self, token: &str) -> Self {
        self.csrf = Some(token.to_owned());
        self
    }

    pub fn forwarded_for(mut self, value: &str) -> Self {
        self.forwarded.push(value.to_owned());
        self
    }

    pub fn json(mut self, body: Value) -> Self {
        self.body = Some(body.to_string());
        self
    }

    /// Authenticates as `session`, sending both the cookie and the CSRF
    /// token.
    pub fn authenticated(self, session: &Session) -> Self {
        self.cookie(&session.cookie).csrf(&session.csrf_token)
    }

    /// Adds an `Authorization` header verbatim. Calling it twice sends
    /// two, which the server must refuse.
    pub fn authorization(mut self, value: &str) -> Self {
        self.authorization.push(value.to_owned());
        self
    }

    /// Authenticates as `device`, with the canonical scheme spelling.
    pub fn authenticated_as_device(self, device: &Device) -> Self {
        self.authorization(&format!("Bearer {}", device.token))
    }

    /// A bearer token with the scheme spelled however the test likes,
    /// for the case-insensitivity checks.
    pub fn bearer_with_scheme(self, scheme: &str, token: &str) -> Self {
        self.authorization(&format!("{scheme} {token}"))
    }

    /// Drops the peer address the connect-info extractor needs.
    ///
    /// Normally `into_make_service_with_connect_info` supplies it and
    /// the harness fakes it; this is for the tests that check what
    /// happens when it is missing, which must be a refusal rather
    /// than an uncounted request.
    pub fn without_peer(mut self) -> Self {
        self.peer = None;
        self
    }

    /// Sends `bytes` as the body, with a JSON content type, bypassing
    /// the JSON builder. For the body-size limit tests.
    pub fn raw_json(mut self, bytes: Vec<u8>) -> Self {
        self.raw_body = Some(bytes);
        self
    }

    /// Sends the body without a `Content-Type` header.
    pub fn without_content_type(mut self) -> Self {
        self.omit_content_type = true;
        self
    }

    fn build(self) -> Request<Body> {
        let mut builder = Request::builder().method(self.method).uri(&self.uri);

        let has_body = self.body.is_some() || self.raw_body.is_some();
        if has_body && !self.omit_content_type {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        for origin in &self.origins {
            builder = builder.header(header::ORIGIN, origin);
        }
        if let Some(cookie) = &self.cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if let Some(csrf) = &self.csrf {
            builder = builder.header("x-csrf-token", csrf);
        }
        for value in &self.authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        for value in &self.forwarded {
            builder = builder.header("x-forwarded-for", value);
        }

        let body = match (self.raw_body, self.body) {
            (Some(bytes), _) => Body::from(bytes),
            (None, Some(json)) => Body::from(json),
            (None, None) => Body::empty(),
        };
        let mut request = builder.body(body).expect("the request must be valid");

        // Normally set by `into_make_service_with_connect_info`; the
        // ClientAddr extractor fails closed without it.
        if let Some(peer) = self.peer {
            let peer: SocketAddr = peer.parse().expect("a valid peer address");
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        request
    }
}

/// A response, already read.
pub struct TestResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl TestResponse {
    /// The raw `Set-Cookie` value, if there is one.
    pub fn set_cookie(&self) -> Option<&str> {
        self.headers
            .get(header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
    }

    /// Just the `name=value` pair from `Set-Cookie`, ready to send back.
    pub fn session_cookie(&self) -> Option<String> {
        self.set_cookie()
            .and_then(|value| value.split(';').next())
            .map(str::to_owned)
    }

    pub fn retry_after(&self) -> Option<u64> {
        self.headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
    }

    /// The `error.code` field of the uniform error body.
    pub fn error_code(&self) -> Option<&str> {
        self.body["error"]["code"].as_str()
    }

    /// The set of JSON keys at the top level, for comparing the *shape*
    /// of two responses rather than their contents.
    pub fn shape(&self) -> Vec<String> {
        fn walk(prefix: &str, value: &Value, out: &mut Vec<String>) {
            match value {
                Value::Object(map) => {
                    for (key, nested) in map {
                        let path = if prefix.is_empty() {
                            key.clone()
                        } else {
                            format!("{prefix}.{key}")
                        };
                        walk(&path, nested, out);
                    }
                }
                _ => out.push(prefix.to_owned()),
            }
        }
        let mut out = Vec::new();
        walk("", &self.body, &mut out);
        out.sort();
        out
    }
}
