//! Serves the real app on a real TCP socket and drives it with real
//! HTTP over the wire.
//!
//! Every other test calls the router with `oneshot` and injects the
//! peer address itself, which means none of them can notice if the
//! server is assembled without connect info. This one goes through
//! `screenwarden_server::serve`, the same function `main` calls, so the
//! peer address has to come from the actual TCP connection.
//!
//! That matters because the failure is silent in the wrong direction:
//! with no connect info the `ClientAddr` extractor fails closed, so
//! login and setup answer 500 for every request while the rest of the
//! suite stays green. This file is the only thing that catches it.
//!
//! The client here speaks HTTP/1.1 by hand rather than pulling in an
//! HTTP client crate. `Connection: close` makes the response readable
//! to EOF, which is all the parsing this needs.

mod common;

use std::net::SocketAddr;

use axum::Router;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use common::{Credentials, TestApp};

/// A server listening on an ephemeral port, shut down on drop.
struct Server {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

impl Server {
    /// Binds 127.0.0.1:0 and serves `app` through the same function the
    /// binary uses.
    async fn start(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding an ephemeral port must succeed");
        let addr = listener
            .local_addr()
            .expect("the listener must report its address");

        let (shutdown, signal) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            screenwarden_server::serve(listener, app, async move {
                // A dropped sender also ends the server, so a panicking
                // test cannot leave the task running.
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

    async fn get(&self, path: &str) -> RawResponse {
        self.request("GET", path, None).await
    }

    async fn post_json(&self, path: &str, body: &str) -> RawResponse {
        self.request("POST", path, Some(body)).await
    }

    /// One request on its own connection, written byte by byte.
    async fn request(&self, method: &str, path: &str, body: Option<&str>) -> RawResponse {
        let mut stream = TcpStream::connect(self.addr)
            .await
            .expect("connecting to the server must succeed");

        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.addr
        );
        if let Some(body) = body {
            head.push_str("Content-Type: application/json\r\n");
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");

        stream
            .write_all(head.as_bytes())
            .await
            .expect("writing the request head must succeed");
        if let Some(body) = body {
            stream
                .write_all(body.as_bytes())
                .await
                .expect("writing the body must succeed");
        }
        stream.flush().await.expect("flushing must succeed");

        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .expect("reading the response must succeed");
        RawResponse::parse(&raw)
    }
}

struct RawResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl RawResponse {
    fn parse(raw: &[u8]) -> Self {
        let text = String::from_utf8_lossy(raw).into_owned();
        let (head, body) = text
            .split_once("\r\n\r\n")
            .unwrap_or_else(|| panic!("not a complete HTTP response: {text:?}"));

        let mut lines = head.split("\r\n");
        let status_line = lines.next().expect("a status line");
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status code in {status_line:?}"));

        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();

        Self {
            status,
            headers,
            body: body.to_owned(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

fn login_body(credentials: &Credentials, password: &str) -> String {
    json!({ "username": credentials.username, "password": password }).to_string()
}

/// A server with a login limit low enough to reach in a few requests.
async fn fixture() -> (TestApp, Credentials, Server) {
    let app = TestApp::with_vars(&[
        ("SCREENWARDEN_RATE_LIMIT_LOGIN_IP", "2/300"),
        ("SCREENWARDEN_RATE_LIMIT_LOGIN_USERNAME", "1000/300"),
        ("SCREENWARDEN_RATE_LIMIT_SETUP_IP", "1000/3600"),
    ])
    .await;
    let credentials = app.provision_admin().await;
    let server = Server::start(app.router()).await;
    (app, credentials, server)
}

/// The point of the file: the limit must be enforced against the
/// address the kernel reports, with nothing injecting it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_login_rate_limit_counts_the_real_peer_address() {
    let (_app, credentials, server) = fixture().await;
    let wrong_password = common::random_secret();

    for attempt in 1..=2 {
        let response = server
            .post_json(
                "/api/v1/auth/login",
                &login_body(&credentials, &wrong_password),
            )
            .await;
        assert_ne!(
            response.status, 500,
            "attempt {attempt} returned 500: the peer address is not reaching the handler, \
             which means `serve` is not attaching connect info"
        );
        assert_eq!(
            response.status, 401,
            "attempt {attempt} must be processed and refused on the credentials"
        );
    }

    // Same peer, third attempt: the bucket keyed on 127.0.0.1 is spent.
    let limited = server
        .post_json(
            "/api/v1/auth/login",
            &login_body(&credentials, &wrong_password),
        )
        .await;
    assert_eq!(
        limited.status, 429,
        "the limit must trigger on the real peer address, got {} with body {:?}",
        limited.status, limited.body
    );
    assert_eq!(limited.json()["error"]["code"], "rate_limited");

    let retry_after: u64 = limited
        .header("retry-after")
        .expect("a 429 over the wire must carry Retry-After")
        .parse()
        .expect("Retry-After must be a number of seconds");
    assert!(
        retry_after > 0 && retry_after <= 300,
        "Retry-After must fall inside the window, got {retry_after}"
    );

    server.stop().await;
}

/// A correct password must still work end to end, cookie and all, so
/// the test above is not passing because everything is broken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_login_over_tcp_sets_the_session_cookie() {
    let (_app, credentials, server) = fixture().await;

    let response = server
        .post_json(
            "/api/v1/auth/login",
            &login_body(&credentials, &credentials.password),
        )
        .await;

    assert_eq!(
        response.status, 200,
        "login over a real socket must succeed, got {:?}",
        response.body
    );

    let cookie = response
        .header("set-cookie")
        .expect("a Set-Cookie header on the wire");
    assert!(cookie.starts_with("__Host-sws=sws_"));
    assert!(cookie.contains("; HttpOnly"));
    assert!(cookie.contains("; Secure"));
    assert!(cookie.contains("; SameSite=Strict"));
    assert_eq!(response.json()["user"]["role"], "admin");

    server.stop().await;
}

/// Setup also needs a client address, so it must not answer 500 either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_over_tcp_reaches_its_handler() {
    let app = TestApp::new().await;
    let token = app.issue_setup_token().await;
    let server = Server::start(app.router()).await;

    let response = server
        .post_json(
            "/api/v1/setup",
            &json!({
                "setup_token": token,
                "username": "alice",
                "password": common::random_secret(),
            })
            .to_string(),
        )
        .await;

    assert_ne!(
        response.status, 500,
        "setup returned 500: the peer address is not reaching the handler"
    );
    assert_eq!(response.status, 201, "body was {:?}", response.body);

    server.stop().await;
}

/// A route that needs no client address, as a control: if this passed
/// while the others returned 500, the fault is the connect info and not
/// the socket plumbing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_over_tcp_answers_without_a_client_address() {
    let app = TestApp::new().await;
    let server = Server::start(app.router()).await;

    let response = server.get("/healthz").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["status"], "ok");
    // The middleware stack really is in play over the wire.
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert!(response.header("x-request-id").is_some());

    server.stop().await;
}
