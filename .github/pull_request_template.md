## Summary

<!-- What does this change do, and why? -->

## Checklist

- [ ] No secrets, tokens, credentials, or real personal data (names,
      emails, hostnames, IPs) anywhere in this diff - only placeholders
      (`example.com`, `example.org`, `192.0.2.0/24`, "alice"/"bob").
- [ ] `cargo fmt --check`, `cargo clippy -- -D warnings`, and
      `cargo test --locked` pass locally.
- [ ] `cargo deny check` passes (if dependencies changed).
- [ ] No `.env` file is included; `.env.example` only lists variable
      names, never values.
