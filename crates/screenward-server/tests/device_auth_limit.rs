//! The limiter on *failed* device authentication.
//!
//! This is the only limiter consulted before anything is
//! authenticated, so it is the only thing bounding what an anonymous
//! caller can make the two device routes do. Without it a well-formed
//! but unknown bearer token costs one indexed lookup per request,
//! forever.
//!
//! The four properties worth pinning:
//!
//!   * failures are counted, and the budget runs out;
//!   * a *successful* request never spends from it, which is what
//!     makes the limit affordable behind a school NAT;
//!   * the refusal happens before any database access, which a green
//!     test against a working database would not prove - so one test
//!     closes the pool first;
//!   * a database error is not the caller's fault and is not charged.
//!
//! The window reset is covered where it can be driven directly, in
//! the `ratelimit` unit tests: nothing here can advance the clock,
//! because the layer reads `UnixTime::now()` itself.

mod common;

use std::net::SocketAddr;

use axum::http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use common::{Device, TestApp, TestRequest};

/// A syntactically valid device token that names no device.
///
/// Well formed on purpose: a malformed one is refused in memory, so
/// only this shape reaches - and must be stopped before - the
/// database.
fn unknown_token() -> String {
    use screenward_server::auth::token::{Token, TokenKind};
    Token::generate(TokenKind::Device)
        .expect("the OS CSPRNG must be available")
        .expose()
        .to_owned()
}

fn failing_request() -> TestRequest {
    TestRequest::get("/api/v1/device/me").authorization(&format!("Bearer {}", unknown_token()))
}

/// An app whose failure budget is `max` per `window_secs`, with every
/// other limit out of the way.
async fn app_with_fail_limit(rule: &str) -> TestApp {
    TestApp::with_vars(&[
        ("SCREENWARD_RATE_LIMIT_DEVICE_AUTH_FAIL", rule),
        ("SCREENWARD_RATE_LIMIT_PAIR_IP", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_PAIR_GLOBAL", "100000/60"),
        ("SCREENWARD_RATE_LIMIT_INGEST_DEVICE", "100000/60"),
        ("SCREENWARD_RATE_LIMIT_SETUP_IP", "1000/3600"),
        ("SCREENWARD_RATE_LIMIT_LOGIN_IP", "1000/300"),
        ("SCREENWARD_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
    ])
    .await
}

// --- the budget -------------------------------------------------------

#[tokio::test]
async fn failures_are_counted_and_then_refused() {
    let app = app_with_fail_limit("3/60").await;
    app.provisioned_admin().await;

    for attempt in 1..=3 {
        let response = app.send(failing_request()).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} must still be answered"
        );
        assert_eq!(response.error_code(), Some("unauthenticated"));
    }

    let limited = app.send(failing_request()).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error_code(), Some("rate_limited"));
    assert!(
        limited.retry_after().is_some_and(|after| after >= 1),
        "a 429 must say when to come back, like every other limiter here"
    );
}

/// The trade-off, stated as a test so it is a decision rather than a
/// surprise: the budget is per address, so once it is spent a *valid*
/// token from that address is refused too.
#[tokio::test]
async fn an_exhausted_budget_also_refuses_a_valid_token_from_that_peer() {
    let app = app_with_fail_limit("2/60").await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    // Works before.
    let before = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(before.status, StatusCode::OK);

    for _ in 0..2 {
        assert_eq!(
            app.send(failing_request()).await.status,
            StatusCode::UNAUTHORIZED
        );
    }

    let valid = app
        .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
        .await;
    assert_eq!(
        valid.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the budget is per address, so a good token shares the consequences"
    );

    // But only for that address. A device syncing from somewhere else
    // is unaffected, which is what keeps one broken client from
    // taking down an instance rather than a network.
    let elsewhere = app
        .send(
            TestRequest::get("/api/v1/device/me")
                .authenticated_as_device(&device)
                .peer("198.51.100.7:2222"),
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::OK);
}

/// A working device must never spend from the failure budget, however
/// much it talks to the server. This is the property that makes the
/// limit affordable behind a NAT.
#[tokio::test]
async fn two_hundred_successful_requests_do_not_spend_the_failure_budget() {
    let app = app_with_fail_limit("3/60").await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    for n in 0..200 {
        let response = app
            .send(TestRequest::get("/api/v1/device/me").authenticated_as_device(&device))
            .await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "successful request {n} must not be limited"
        );
    }

    // The full failure budget is still there.
    for attempt in 1..=3 {
        assert_eq!(
            app.send(failing_request()).await.status,
            StatusCode::UNAUTHORIZED,
            "failure {attempt} of 3 must still be allowed"
        );
    }
    assert_eq!(
        app.send(failing_request()).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// Every kind of authentication failure charges, not just an unknown
/// token - including a request that carries the session cookie, which
/// is a client with a bug spending its own address's budget.
#[tokio::test]
async fn every_kind_of_auth_failure_charges_the_budget() {
    /// Builds one flavour of failing request from a paired device and
    /// a session cookie, so the cases below stay a flat table.
    type BuildFailure = fn(&Device, &str) -> TestRequest;

    let cases: [(&str, BuildFailure); 4] = [
        ("no credential", |_device, _cookie| {
            TestRequest::get("/api/v1/device/me")
        }),
        ("a malformed token", |_device, _cookie| {
            TestRequest::get("/api/v1/device/me").authorization("Bearer not-a-token")
        }),
        ("an unknown token", |_device, _cookie| failing_request()),
        (
            "a session cookie alongside a valid token",
            |device, cookie| {
                TestRequest::get("/api/v1/device/me")
                    .authenticated_as_device(device)
                    .cookie(cookie)
            },
        ),
    ];

    for (label, build) in cases {
        let app = app_with_fail_limit("1/60").await;
        let (_credentials, session) = app.provisioned_admin().await;
        let device = app.pair_device(&session, "laptop", "linux").await;

        let first = app.send(build(&device, &session.cookie)).await;
        assert_eq!(
            first.status,
            StatusCode::UNAUTHORIZED,
            "{label} must be refused"
        );

        // The one unit of budget is gone, so the next failure is a
        // 429 rather than another 401.
        let second = app.send(failing_request()).await;
        assert_eq!(
            second.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{label} must have charged the budget"
        );
    }
}

// --- the refusal costs no database access -----------------------------

/// The claim is that the peek happens before any query. A green test
/// against a working database does not show that, so this one takes
/// the database away first: if the check sat after the lookup, the
/// answer would be a 500 instead of a 429.
#[tokio::test]
async fn an_exhausted_budget_is_refused_with_the_database_closed() {
    let app = app_with_fail_limit("2/60").await;
    app.provisioned_admin().await;

    for _ in 0..2 {
        assert_eq!(
            app.send(failing_request()).await.status,
            StatusCode::UNAUTHORIZED
        );
    }

    // No database from here on.
    app.pool.close().await;
    assert!(app.pool.is_closed());

    let limited = app.send(failing_request()).await;
    assert_eq!(
        limited.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the refusal must not need the database: {:?}",
        limited.body
    );
    assert_eq!(limited.error_code(), Some("rate_limited"));
}

/// A database error is this server failing, not the caller
/// misbehaving, so it must not spend the caller's budget - otherwise
/// a database wobble locks out the clients that happened to be
/// syncing through it.
#[tokio::test]
async fn a_database_error_does_not_charge_the_budget() {
    let app = app_with_fail_limit("2/60").await;
    app.provisioned_admin().await;

    // One real failure: budget now 1 of 2.
    assert_eq!(
        app.send(failing_request()).await.status,
        StatusCode::UNAUTHORIZED
    );

    app.pool.close().await;

    // A well-formed token gets past the in-memory checks and reaches
    // the lookup, which now fails.
    let errored = app.send(failing_request()).await;
    assert_eq!(
        errored.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{:?}",
        errored.body
    );

    // If that had charged, the budget would be 2 of 2 and this would
    // be a 429. It is another 500, so it did not.
    let again = app.send(failing_request()).await;
    assert_eq!(
        again.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a database error must not have spent the budget"
    );
}

// --- the peer must be resolvable --------------------------------------

/// Without a peer address there is no key to count against. Letting
/// the request through uncounted is exactly the hole this limiter
/// closes, so it is refused instead - and refused before the lookup.
#[tokio::test]
async fn a_request_with_no_peer_address_is_refused() {
    let app = app_with_fail_limit("1000/60").await;
    let (_credentials, session) = app.provisioned_admin().await;
    let device = app.pair_device(&session, "laptop", "linux").await;

    // Even a perfectly valid token does not get through.
    let response = app
        .send(
            TestRequest::get("/api/v1/device/me")
                .authenticated_as_device(&device)
                .without_peer(),
        )
        .await;
    assert_eq!(
        response.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "no peer address means no limiter key, so the request must stop: {:?}",
        response.body
    );

    // And with the database gone it is still refused, which shows the
    // peer resolution happens before the lookup rather than after.
    app.pool.close().await;
    let without_db = app
        .send(
            TestRequest::get("/api/v1/device/me")
                .authenticated_as_device(&device)
                .without_peer(),
        )
        .await;
    assert_eq!(without_db.status, StatusCode::INTERNAL_SERVER_ERROR);
}

// --- over a real socket -----------------------------------------------

/// A server on an ephemeral port, shut down on drop.
struct Server {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

impl Server {
    async fn start(app: axum::Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding an ephemeral port must succeed");
        let addr = listener
            .local_addr()
            .expect("the listener must report its address");

        let (shutdown, signal) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            screenward_server::serve(listener, app, async move {
                let _ = signal.await;
            })
            .await
        });

        Self {
            addr,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .expect("the server task must not panic")
                .expect("the server must shut down cleanly");
        }
    }

    /// One GET on its own connection, written by hand.
    async fn get_with_bearer(&self, path: &str, token: &str) -> u16 {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .expect("connecting must succeed");

        let head = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             Authorization: Bearer {token}\r\n\r\n",
            self.addr
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("writing must succeed");
        stream.flush().await.expect("flushing must succeed");

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .expect("reading must succeed");

        String::from_utf8_lossy(&raw)
            .lines()
            .next()
            .expect("a status line")
            .split_whitespace()
            .nth(1)
            .expect("a status code")
            .parse()
            .expect("a numeric status")
    }
}

/// The limiter counts against the address the *connection* came from.
///
/// Every other test here injects the peer address itself, so none of
/// them would notice if the key came from somewhere a client can
/// choose. Same reasoning as `serve_over_tcp.rs`.
#[tokio::test]
async fn the_failure_limit_counts_the_real_peer_address() {
    let app = app_with_fail_limit("3/60").await;
    app.provisioned_admin().await;
    let server = Server::start(app.router()).await;

    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(
            server
                .get_with_bearer("/api/v1/device/me", &unknown_token())
                .await,
        );
    }

    assert_eq!(
        &statuses[..3],
        &[401, 401, 401],
        "the first three must be answered, saw {statuses:?}"
    );
    assert_eq!(
        &statuses[3..],
        &[429, 429],
        "the limit must bite over a real connection, saw {statuses:?}"
    );

    server.stop().await;
}

/// Both device routes share the bucket, so exhausting it on one
/// refuses the other.
#[tokio::test]
async fn the_budget_is_shared_across_both_device_routes() {
    let app = app_with_fail_limit("2/60").await;
    app.provisioned_admin().await;

    assert_eq!(
        app.send(failing_request()).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.send(
            TestRequest::post("/api/v1/events")
                .authorization(&format!("Bearer {}", unknown_token()))
                .json(serde_json::json!({ "events": [] }))
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );

    // Two failures spent across the two routes; the third is refused
    // on either of them.
    assert_eq!(
        app.send(failing_request()).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        app.send(
            TestRequest::post("/api/v1/events")
                .authorization(&format!("Bearer {}", unknown_token()))
                .json(serde_json::json!({ "events": [] }))
        )
        .await
        .status,
        StatusCode::TOO_MANY_REQUESTS
    );
}
