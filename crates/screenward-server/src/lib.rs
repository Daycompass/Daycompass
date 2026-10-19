//! Screenward backend library.
//!
//! Exposes the pieces `main.rs` wires together, and lets integration
//! tests under `tests/` exercise them without going through a spawned
//! process.
#![forbid(unsafe_code)]

pub mod config;
pub mod db;
