//! The two pairing properties that cannot be checked with `oneshot`
//! against an in-memory database.
//!
//! Both need a file-backed database. The in-memory pool is capped at a
//! single connection, so concurrent requests would queue on the pool
//! instead of contending for SQLite's write lock - which is precisely
//! the thing a race test is about.
//!
//! The rate-limit test additionally needs a real socket: every other
//! test injects the peer address itself, so none of them would notice
//! if the per-address bucket were counting something that does not
//! come from the connection. This is the same reasoning as
//! `serve_over_tcp.rs`, and it is why that file exists at all.

mod common;

use std::net::SocketAddr;

use axum::http::StatusCode;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use common::{TestApp, TestRequest};

/// Two clients redeem the same code at the same moment.
///
/// Exactly one device must result. The transaction takes
/// `BEGIN IMMEDIATE`, so the two are serialized and the loser finds
/// `used_at` already set.
#[tokio::test]
async fn concurrent_redemption_of_one_code_yields_exactly_one_device() {
    // Repeated, because a race that only sometimes interleaves would
    // otherwise pass by luck.
    for attempt in 1..=5 {
        let app = TestApp::with_file_db().await;
        let (_credentials, session) = app.provisioned_admin().await;
        let code = app.issue_pairing_code(&session).await;

        let request = |name: &str| {
            TestRequest::post("/api/v1/pair").json(json!({
                "pairing_code": code,
                "device_name": name,
                "platform": "linux",
            }))
        };

        let (first, second) =
            tokio::join!(app.send(request("first")), app.send(request("second")),);

        let statuses = [first.status, second.status];
        let created = statuses
            .iter()
            .filter(|status| **status == StatusCode::CREATED)
            .count();
        let refused = statuses
            .iter()
            .filter(|status| **status == StatusCode::UNAUTHORIZED)
            .count();

        assert_eq!(
            created, 1,
            "attempt {attempt}: exactly one must win, saw {statuses:?}"
        );
        assert_eq!(
            refused, 1,
            "attempt {attempt}: the loser must be refused, saw {statuses:?}"
        );
        assert_eq!(
            app.count_devices().await,
            1,
            "attempt {attempt}: one code must never create two devices"
        );

        // The loser gets the ordinary refusal, with nothing in it
        // that says it lost a race rather than presenting a bad code.
        let loser = if first.status == StatusCode::CREATED {
            second
        } else {
            first
        };
        assert_eq!(loser.error_code(), Some("invalid_pairing_code"));
    }
}

/// Two devices being paired from two different codes at once must
/// both succeed - the serialization above must not be a lock on
/// pairing in general.
#[tokio::test]
async fn two_different_codes_pair_concurrently() {
    let app = TestApp::with_file_db().await;
    let (_credentials, session) = app.provisioned_admin().await;
    let first_code = app.issue_pairing_code(&session).await;
    let second_code = app.issue_pairing_code(&session).await;

    let request = |code: &str, name: &str| {
        TestRequest::post("/api/v1/pair").json(json!({
            "pairing_code": code,
            "device_name": name,
            "platform": "linux",
        }))
    };

    let (first, second) = tokio::join!(
        app.send(request(&first_code, "first")),
        app.send(request(&second_code, "second")),
    );

    assert_eq!(first.status, StatusCode::CREATED, "{:?}", first.body);
    assert_eq!(second.status, StatusCode::CREATED, "{:?}", second.body);
    assert_eq!(app.count_devices().await, 2);
}

/// Concurrent minting must respect the cap: eight requests in flight
/// at once may not produce more than five codes.
///
/// Spelled out with `tokio::join!` rather than a loop over a vector of
/// futures. A loop that awaits each future in turn is sequential, and
/// a sequential test here would pass whether or not the count and the
/// insert are in one transaction - which is the only thing it is
/// supposed to be checking.
#[tokio::test]
async fn concurrent_minting_cannot_exceed_the_code_cap() {
    let app = TestApp::with_file_db().await;
    let (_credentials, session) = app.provisioned_admin().await;

    let mint = || {
        app.send(
            TestRequest::post("/api/v1/pairing-codes")
                .origin(common::GOOD_ORIGIN)
                .authenticated(&session),
        )
    };

    let (a, b, c, d, e, f, g, h) = tokio::join!(
        mint(),
        mint(),
        mint(),
        mint(),
        mint(),
        mint(),
        mint(),
        mint(),
    );

    let responses = [a, b, c, d, e, f, g, h];
    let created = responses
        .iter()
        .filter(|response| response.status == StatusCode::CREATED)
        .count();
    let refused = responses
        .iter()
        .filter(|response| response.status == StatusCode::CONFLICT)
        .count();

    assert_eq!(created, 5, "the cap must hold under concurrency");
    assert_eq!(refused, 3, "the rest must be refused, not dropped");
    assert_eq!(app.count_pairing_codes().await, 5);
}

// --- the rate limit, over a real socket -------------------------------

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
            screenwarden_server::serve(listener, app, async move {
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

    /// One POST on its own connection, written by hand. `Connection:
    /// close` makes the response readable to EOF, which is all the
    /// parsing this needs.
    async fn post_json(&self, path: &str, body: &str) -> u16 {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .expect("connecting must succeed");

        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            self.addr,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .await
            .expect("writing the head must succeed");
        stream
            .write_all(body.as_bytes())
            .await
            .expect("writing the body must succeed");
        stream.flush().await.expect("flushing must succeed");

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .expect("reading must succeed");

        let text = String::from_utf8_lossy(&raw);
        let status_line = text.lines().next().expect("a status line");
        status_line
            .split_whitespace()
            .nth(1)
            .expect("a status code")
            .parse()
            .expect("a numeric status")
    }
}

/// Failed pairing attempts must hit the per-address limit, counted
/// against the address the *connection* came from.
///
/// Driven over a real socket for the reason in the module comment:
/// with no connect info the address resolver fails closed, and every
/// `oneshot` test in the suite injects a peer address itself, so none
/// of them would catch it.
#[tokio::test]
async fn failed_pairing_attempts_are_limited_per_address_over_a_real_socket() {
    let app = TestApp::with_vars(&[
        ("SCREENWARDEN_RATE_LIMIT_PAIR_IP", "3/300"),
        ("SCREENWARDEN_RATE_LIMIT_PAIR_GLOBAL", "100000/60"),
        ("SCREENWARDEN_RATE_LIMIT_SETUP_IP", "1000/3600"),
    ])
    .await;
    let server = Server::start(app.router()).await;

    let body = json!({
        "pairing_code": "0123456789",
        "device_name": "laptop",
        "platform": "linux",
    })
    .to_string();

    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(server.post_json("/api/v1/pair", &body).await);
    }

    // The first three are processed and refused on the code; the rest
    // never reach the handler.
    assert_eq!(
        &statuses[..3],
        &[401, 401, 401],
        "the first attempts must be answered, saw {statuses:?}"
    );
    assert_eq!(
        &statuses[3..],
        &[429, 429],
        "the limit must bite, saw {statuses:?}"
    );

    server.stop().await;
}

/// The global ceiling is a separate bucket, and must refuse even a
/// caller who is well inside the per-address limit.
#[tokio::test]
async fn the_global_ceiling_refuses_independently_of_the_address() {
    let app = TestApp::with_vars(&[
        // Wide, so it cannot be what refuses.
        ("SCREENWARDEN_RATE_LIMIT_PAIR_IP", "1000/300"),
        ("SCREENWARDEN_RATE_LIMIT_PAIR_GLOBAL", "3/60"),
    ])
    .await;

    let request = || {
        TestRequest::post("/api/v1/pair")
            .json(json!({
                "pairing_code": "0123456789",
                "device_name": "laptop",
                "platform": "linux",
            }))
            .peer("192.0.2.10:1111")
    };

    for attempt in 1..=3 {
        let response = app.send(request()).await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "attempt {attempt} must be processed"
        );
    }

    let limited = app.send(request()).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error_code(), Some("rate_limited"));

    // A different address shares the ceiling, which is what makes it
    // a ceiling rather than a per-caller limit.
    let elsewhere = app.send(request().peer("198.51.100.7:2222")).await;
    assert_eq!(
        elsewhere.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the ceiling must apply across addresses"
    );
}

/// Every IPv6 address in one `/64` shares a bucket, or a client with a
/// routed prefix would have effectively no limit at all.
#[tokio::test]
async fn one_ipv6_prefix_shares_a_single_pairing_bucket() {
    let app = TestApp::with_vars(&[
        ("SCREENWARDEN_RATE_LIMIT_PAIR_IP", "2/300"),
        ("SCREENWARDEN_RATE_LIMIT_PAIR_GLOBAL", "100000/60"),
    ])
    .await;

    let attempt = |peer: &str| {
        app.send(
            TestRequest::post("/api/v1/pair")
                .json(json!({
                    "pairing_code": "0123456789",
                    "device_name": "laptop",
                    "platform": "linux",
                }))
                .peer(peer),
        )
    };

    assert_eq!(
        attempt("[2001:db8::1]:1111").await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        attempt("[2001:db8::2]:1111").await.status,
        StatusCode::UNAUTHORIZED
    );

    // A third address in the same /64 must not get a fresh budget.
    assert_eq!(
        attempt("[2001:db8::dead:beef]:1111").await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "a /64 must be one bucket"
    );

    // A different /64 is a different client.
    assert_eq!(
        attempt("[2001:db8:0:1::1]:1111").await.status,
        StatusCode::UNAUTHORIZED,
        "another prefix must have its own budget"
    );
}
