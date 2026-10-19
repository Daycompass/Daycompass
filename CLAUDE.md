# CLAUDE.md

Screenward is a self-hosted, open-source (AGPL-3.0) screentime backend for
students. This file applies to the whole repository.

## Hard rules

1. Never write, invent, or request real secrets, tokens, passwords,
   email addresses, personal names, hostnames, or IPs. Use only
   placeholders: `example.com`, `example.org`, IPs from `192.0.2.0/24`,
   and the names "alice" / "bob".
2. Never ask the user for credentials. If a design would need them,
   change the design instead.
3. Never read or write `.env` files. The only exception is
   `.env.example`, which lists variable *names* only, with no values.
4. No hardcoded credentials, including in test code.
5. When unsure, ask rather than guess.

## Stack conventions

- Rust stable, Cargo workspace, edition 2021 or newer.
- Toolchain is pinned in `rust-toolchain.toml`; CI uses the same version.
- Every crate has `#![forbid(unsafe_code)]`.
- `Cargo.lock` is committed. All `cargo` invocations in CI (and when
  checking locally) use `--locked`.
- Planned for later milestones, **not yet present**: axum, tokio, sqlx
  (SQLite), argon2, utoipa. Do not add these dependencies, a database,
  authentication, or API endpoints unless a specific task asks for them.
- No `authors` field and no real names/emails anywhere in `Cargo.toml`
  files. Where a rights holder must be named, use "Screenward
  contributors".

## Secret hygiene

- Pre-commit hook: `.githooks/pre-commit` runs gitleaks against staged
  changes and fails closed (rejects the commit) if gitleaks is missing.
  Enable it once per clone with `git config core.hooksPath .githooks`.
- `.gitleaks.toml` additions are reactive only: add an allowlist entry
  per path/pattern *after* a real false positive, with a comment
  explaining why. Never add speculative allowlist entries.
