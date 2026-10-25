//! `GET`/`POST /setup` and `GET`/`POST /invite` - the two pages that
//! come before a first login: creating the first admin with the setup
//! token, and activating an account by redeeming its invite.
//!
//! Both are the JSON routes' work (`attempt_setup`, `invite::redeem`)
//! behind a form, with the same rate-limit buckets. Two things differ
//! from their API counterparts on purpose:
//!
//! * They are `OriginRule::Required`, like every dashboard write,
//!   rather than `Origin`-exempt as `POST /api/v1/setup` is. A browser
//!   always sends `Origin`, so the exemption has no caller here.
//! * The secret is typed or pasted into the form, never carried in the
//!   URL - no `/invite?token=...` link. A URL ends up in history,
//!   bookmarks and screenshots; a form body does not.
//!
//! `GET /setup` answers 404 once an admin exists, exactly like
//! `POST /api/v1/setup`, so a provisioned instance shows nothing that
//! says it ever had a setup step.

use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use super::{redirect_after_post, render};
use crate::auth::invite;
use crate::auth::secret::SecretString;
use crate::auth::time::UnixTime;
use crate::error::{ApiError, ErrorKind};
use crate::routes::{invites, setup};
use crate::state::AppState;

#[derive(Template)]
#[template(path = "setup.html")]
struct SetupPage;

#[derive(Template)]
#[template(path = "invite.html")]
struct InvitePage;

pub async fn setup_page(State(state): State<AppState>) -> Response {
    match setup::setup_is_complete(&state).await {
        Ok(false) => render(&SetupPage),
        Ok(true) => ApiError::of(ErrorKind::NotFound).into_response(),
        Err(error) => error.into_response(),
    }
}

/// The setup form. Same field names as the JSON body.
#[derive(Deserialize)]
pub struct SetupForm {
    setup_token: SecretString,
    username: String,
    password: SecretString,
}

/// Creates the first admin and sends the browser to the login page.
/// Logging in is a separate step, as on the API: setup mints no session.
pub async fn submit_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<SetupForm>,
) -> Response {
    match setup::attempt_setup(&state, &form.setup_token, &form.username, form.password).await {
        Ok(_) => redirect_after_post(&headers, "/login"),
        Err(error) => error.into_response(),
    }
}

pub async fn invite_page() -> Response {
    render(&InvitePage)
}

/// The invite form. Same field names as the JSON body.
#[derive(Deserialize)]
pub struct InviteForm {
    invite_token: SecretString,
    new_password: SecretString,
}

/// Activates the account and sends the browser to the login page. No
/// session is minted here either.
pub async fn submit_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<InviteForm>,
) -> Response {
    let result = invite::redeem(
        &state.pool,
        &state.hasher,
        &form.invite_token,
        form.new_password,
        UnixTime::now(),
    )
    .await;
    match result {
        Ok(()) => redirect_after_post(&headers, "/login"),
        Err(err) => invites::to_api_error(err, &state).into_response(),
    }
}
