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

use screenward_server::config::Config;
use screenward_server::db::{connect, migrate, DbTarget};
use screenward_server::state::AppState;

/// The peer address a request appears to come from unless a test says
/// otherwise. From the documentation range, per `CLAUDE.md`.
pub const DEFAULT_PEER: &str = "192.0.2.10:54321";

/// Matches the default configuration's public URL, which is what the
/// `Origin` check compares against.
pub const GOOD_ORIGIN: &str = "http://127.0.0.1:8080";

/// An origin that is not this instance.
pub const BAD_ORIGIN: &str = "https://attacker.example";

/// A running app plus the pool behind it.
pub struct TestApp {
    router: Router,
    pub pool: SqlitePool,
}

impl TestApp {
    /// An app with generous rate limits, so a test that is not about
    /// rate limiting never trips one.
    pub async fn new() -> Self {
        Self::with_vars(&[
            ("SCREENWARD_RATE_LIMIT_LOGIN_IP", "1000/300"),
            ("SCREENWARD_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
            ("SCREENWARD_RATE_LIMIT_SETUP_IP", "1000/3600"),
        ])
        .await
    }

    /// An app configured by explicit environment variables, without
    /// touching the real process environment.
    pub async fn with_vars(vars: &[(&str, &str)]) -> Self {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        let config = Config::for_test(&map).expect("the test configuration must be valid");

        let pool = connect(&DbTarget::Memory)
            .await
            .expect("in-memory pool must connect");
        migrate(&pool).await.expect("migrations must apply");

        let state = AppState::new(pool.clone(), &config)
            .await
            .expect("building the state must succeed");

        Self {
            router: screenward_server::build_app(state),
            pool,
        }
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
        use screenward_server::auth::setup;
        use screenward_server::auth::time::UnixTime;

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
        use screenward_server::auth::token::{Token, TokenKind};

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
    peer: String,
    origin: Option<String>,
    cookie: Option<String>,
    csrf: Option<String>,
    forwarded: Vec<String>,
    body: Option<String>,
}

impl TestRequest {
    pub fn get(uri: &str) -> Self {
        Self::new(Method::GET, uri)
    }

    pub fn post(uri: &str) -> Self {
        Self::new(Method::POST, uri)
    }

    pub fn new(method: Method, uri: &str) -> Self {
        Self {
            method,
            uri: uri.to_owned(),
            peer: DEFAULT_PEER.to_owned(),
            origin: None,
            cookie: None,
            csrf: None,
            forwarded: Vec::new(),
            body: None,
        }
    }

    pub fn peer(mut self, peer: &str) -> Self {
        self.peer = peer.to_owned();
        self
    }

    pub fn origin(mut self, origin: &str) -> Self {
        self.origin = Some(origin.to_owned());
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

    fn build(self) -> Request<Body> {
        let mut builder = Request::builder().method(self.method).uri(&self.uri);

        if self.body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        if let Some(origin) = &self.origin {
            builder = builder.header(header::ORIGIN, origin);
        }
        if let Some(cookie) = &self.cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if let Some(csrf) = &self.csrf {
            builder = builder.header("x-csrf-token", csrf);
        }
        for value in &self.forwarded {
            builder = builder.header("x-forwarded-for", value);
        }

        let body = match self.body {
            Some(json) => Body::from(json),
            None => Body::empty(),
        };
        let mut request = builder.body(body).expect("the request must be valid");

        // Normally set by `into_make_service_with_connect_info`; the
        // ClientAddr extractor fails closed without it.
        let peer: SocketAddr = self.peer.parse().expect("a valid peer address");
        request.extensions_mut().insert(ConnectInfo(peer));
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
