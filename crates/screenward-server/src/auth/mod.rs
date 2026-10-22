//! Authentication and accounts: passwords, opaque tokens, login
//! sessions, the one-time flow that creates the very first admin, and
//! account management.
//!
//! This is the service layer. HTTP concerns (status codes, headers,
//! cookies on the wire) belong in [`crate::routes`]; the types here know
//! nothing about axum, so the JSON API and the later dashboard can share
//! them without duplicating any logic.
//!
//! # Where each decision is written down
//!
//! `CLAUDE.md` points here rather than restating any of it, so this list
//! is the index. Read the module before changing the code in it.
//!
//! | Topic | Module |
//! | --- | --- |
//! | Token format, why only hashes are stored, constant-time comparison | [`token`] |
//! | Device tokens: bearer only, cookies refused, revocation uncached | [`device`] |
//! | The `__Host-sws` cookie and its attributes, by hand and why | [`cookie`] |
//! | CSRF tokens: derived not stored, what that buys and costs | [`csrf`] |
//! | The `Origin` rule, including why an absent header is allowed | [`origin`] |
//! | The password policy and the Argon2 semaphore | [`password`] |
//! | Login: no account enumeration, the decoy hash, rehash on login | [`login`] |
//! | The order of work in a login, end to end | [`login`] |
//! | Sessions: the two timeouts, resolution, the sweep | [`session`] |
//! | First-start setup: the token, the 404, the ordering of checks | [`setup`] |
//! | Username normalization and charset | [`username`] |
//! | Account management, the last-admin rule, password changes | [`users`] |
//! | Every SQL statement, and which ones take the write lock | [`store`] |
//! | The authentication extractor and the one CSRF check | [`extract`] |
//!
//! Two things live outside this module because they are HTTP-level:
//!
//! * **Which** protection applies to which route, and the layers that
//!   apply it, come from the route inventory in [`crate::routes`] and
//!   its enforcement in `crate::routes::access`.
//! * **Which address** a request is attributed to, which is what every
//!   per-client rate limit depends on, is [`crate::clientip`].

pub mod cookie;
pub mod csrf;
pub mod device;
pub mod extract;
pub mod login;
pub mod origin;
pub mod password;
pub mod role;
pub mod secret;
pub mod session;
pub mod setup;
pub mod store;
pub mod time;
pub mod token;
pub mod username;
pub mod users;
