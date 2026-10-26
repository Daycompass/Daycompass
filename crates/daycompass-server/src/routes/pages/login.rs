//! `GET /login`, `POST /login` and `POST /logout` - the dashboard's
//! session pages.
//!
//! The work is the JSON routes' own: [`auth::attempt_login`] and
//! [`auth::end_session`] are shared with `POST /api/v1/auth/login` and
//! `POST /api/v1/auth/logout`, and so are the rate-limit buckets, the
//! cookie and the `Origin` rule. Only the response differs - a redirect
//! where the API answers with JSON.
//!
//! [`auth::attempt_login`]: crate::routes::auth::attempt_login
//! [`auth::end_session`]: crate::routes::auth::end_session

use askama::Template;
use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use super::{redirect_after_post, render};
use crate::auth::secret::SecretString;
use crate::routes::{auth, SessionContext};
use crate::state::AppState;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage;

pub async fn page() -> Response {
    render(&LoginPage)
}

/// The login form's fields. Same names as the JSON body.
#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: SecretString,
}

/// Logs in from the form. On success the session cookie is set and the
/// browser is sent to the overview; on failure the error is whatever
/// the JSON route would have answered, rendered by the page layer.
pub async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    match auth::attempt_login(&state, &form.username, form.password).await {
        Ok(outcome) => (
            [(
                header::SET_COOKIE,
                state.cookie_mode.set(outcome.session.token.expose()),
            )],
            redirect_after_post(&headers, "/"),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

/// Ends the session and sends the browser back to the login page.
pub async fn log_out(
    State(state): State<AppState>,
    headers: HeaderMap,
    session_context: SessionContext,
) -> Response {
    if let Err(error) = auth::end_session(&state, &session_context).await {
        return error.into_response();
    }

    (
        [(header::SET_COOKIE, state.cookie_mode.clear())],
        redirect_after_post(&headers, "/login"),
    )
        .into_response()
}
