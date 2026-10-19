# Contributing to Screenward

Thanks for your interest in contributing. This project is early-stage;
please open an issue before large changes so effort isn't wasted on
something already in flight.

## Secret rule (read this before your first commit)

- **Never commit real secrets, tokens, passwords, credentials, personal
  names, email addresses, hostnames, or IP addresses.** This applies to
  code, tests, fixtures, comments, commit messages, and CI config.
- Use only placeholders: `example.com`, `example.org`, IP addresses from
  `192.0.2.0/24`, and the names "alice" / "bob" for example people.
- `.env` files are never committed (see `.gitignore`). Only
  `.env.example` is tracked, and it must contain variable *names* only,
  with empty values - never fill in real ones there either.
- Test code must not contain hardcoded credentials, even fake-looking
  ones that resemble real formats. Use obviously-synthetic placeholders.

## Local setup

1. Install the Rust toolchain pinned in `rust-toolchain.toml` (rustup
   will install it automatically the first time you run `cargo` or
   `rustup show` in this directory).
2. Install [gitleaks](https://github.com/gitleaks/gitleaks) and make
   sure it is on your `PATH`.
3. Enable the repository's pre-commit hook once per clone:

   ```sh
   git config core.hooksPath .githooks
   ```

   The hook runs gitleaks against your staged changes before every
   commit. It fails closed: if gitleaks isn't installed, the commit is
   rejected rather than silently skipping the scan.

## Before opening a pull request

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --locked`
- `cargo deny check` (install with `cargo install cargo-deny --locked`)

All of these also run in CI; running them locally first saves a review
round-trip.

## Reporting a security issue

Do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md) for the reporting process.
