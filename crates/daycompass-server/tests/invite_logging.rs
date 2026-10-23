//! A dedicated process - this file is its own test binary, like every
//! file under `tests/` - that installs a tracing subscriber capturing
//! every line into memory, then proves that an invite token, through
//! creation, an admin reset, and redemption, never reaches it: neither
//! the full token nor its 43-character random body with the prefix
//! stripped off.
//!
//! One test only, deliberately: installing a process-global tracing
//! subscriber is a one-time thing, and a second test in this file
//! would either conflict with it or capture a mix of two tests' output.

mod common;

use std::sync::{Arc, Mutex};

use serde_json::json;
use tracing_subscriber::EnvFilter;

use common::{TestApp, TestRequest, GOOD_ORIGIN};

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the lock must not be poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn no_invite_token_or_its_body_ever_reaches_the_log() {
    let captured = CapturedLog::default();
    let writer = captured.clone();
    // The widest filter there is: if a token could leak at any level,
    // this is the configuration that would show it.
    tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .with_env_filter(EnvFilter::new("trace"))
        .try_init()
        .expect("installing the subscriber must succeed");

    let app = TestApp::new().await;
    let (_credentials, admin) = app.provisioned_admin().await;

    let (user_id, created_token, _expires_at) =
        app.create_pending_account(&admin, "bob", "user").await;

    let reset = app
        .send(
            TestRequest::post(&format!("/api/v1/users/{user_id}/password-reset"))
                .origin(GOOD_ORIGIN)
                .authenticated(&admin),
        )
        .await;
    let reset_token = reset.body["invite"]["token"]
        .as_str()
        .expect("an invite token")
        .to_owned();

    let redeemed = app
        .send(
            TestRequest::post("/api/v1/invites/redeem")
                .origin(GOOD_ORIGIN)
                .json(json!({
                    "invite_token": reset_token,
                    "new_password": common::random_secret(),
                })),
        )
        .await;
    assert_eq!(
        redeemed.status,
        axum::http::StatusCode::NO_CONTENT,
        "{:?}",
        redeemed.body
    );

    let bytes = captured.0.lock().expect("the lock must not be poisoned");
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.is_empty(), "the capture must have recorded something");

    for (label, token) in [
        ("the created invite", &created_token),
        ("the reset invite", &reset_token),
    ] {
        assert!(
            !text.contains(token.as_str()),
            "{label} token appears in the log: {text}"
        );
        // `dci_` is 4 characters; everything after it is the 43-
        // character random body, which must not appear either, even
        // stripped of its prefix.
        let body = &token[4..];
        assert!(
            !text.contains(body),
            "{label} token's body appears in the log, stripped of its prefix: {text}"
        );
    }
}
