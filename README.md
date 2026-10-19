# Screenward

Screenward is an open-source, self-hosted screentime backend for students,
built so schools and individuals can run their own instance instead of
relying on a third-party service.

This repository holds the backend only: the JSON API today and a web
dashboard served by the same binary later. The clients (Android,
Windows, macOS, Linux, later iOS) live in separate repositories and
sync to this server.

## Status: early development

The backend currently has configuration, SQLite storage with migrations,
and a hardened HTTP skeleton (`/healthz`). There are no users, no
authentication, and no domain endpoints yet. Expect breaking changes at
any time.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), in particular the rules on
secrets and test data before opening a pull request.
