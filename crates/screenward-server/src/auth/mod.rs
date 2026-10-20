//! Authentication: accounts, passwords, opaque tokens, login sessions,
//! and the one-time flow that creates the very first admin.
//!
//! This is the service layer. HTTP concerns (status codes, headers,
//! cookies on the wire) belong in [`crate::routes`]; the types here know
//! nothing about axum, so the JSON API and the later dashboard can share
//! them without duplicating any logic.

pub mod password;
pub mod secret;
pub mod token;
pub mod username;
