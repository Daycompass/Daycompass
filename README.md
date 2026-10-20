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
a hardened HTTP skeleton (`/healthz`), and authentication: the
first-admin setup flow, login, logout, sessions with CSRF protection,
and rate limiting. There is no user management API, no devices, no
pairing and no event ingest yet. Expect breaking changes at any time.

## First start

On the very first start the database has no accounts, so there is no way
to log in yet. The server notices this, generates a single-use **setup
token**, and prints it to standard output:

```text
Screenward first-time setup: no admin account exists yet.
Create one within 60 minutes by sending this token, a username and a
password to POST http://127.0.0.1:8080/api/v1/setup
Setup token: swb_...
This token is single use. It appears in this process's output, so treat
these logs as sensitive until setup is complete.
```

Redeem it to create the first admin:

```sh
curl -X POST http://127.0.0.1:8080/api/v1/setup \
  -H 'Content-Type: application/json' \
  -d '{"setup_token":"<the token>","username":"<name>","password":"<password>"}'
```

Usernames are 3 to 32 characters from `a-z`, `0-9`, `_`, `.` and `-`,
and are stored lowercase. Passwords are 12 to 128 characters with no
composition rules.

A few properties worth knowing:

- **The token is printed once, to stdout, not through the log system.**
  A log level cannot hide it and JSON log output cannot bury it.
- **Every restart without an admin invalidates the previous token** and
  prints a new one, so only the most recent line works.
- **It expires after one hour** and can be redeemed only once.
- **Once an admin exists, `POST /api/v1/setup` answers 404** for any
  input - the same response as a route that does not exist. The setup
  path is then dead code for the lifetime of the installation.

### The setup token ends up in the container logs

This is expected and accepted. Printing to stdout is what makes the
token reachable with `docker logs` or `kubectl logs`, which is the only
channel a fresh container reliably has. The exposure is bounded: the
token is valid for one hour, is usable exactly once, and grants nothing
but the creation of the first admin on an instance that has no accounts
at all. After setup it cannot be redeemed again even if someone reads it
later.

If that trade-off is not acceptable for your deployment, complete setup
promptly and rotate the log, or run the first start with log collection
disabled.

## Authentication

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/setup` | Redeem the setup token, create the first admin. 404 once one exists. |
| `POST /api/v1/auth/login` | Sets the `__Host-sws` session cookie, returns a CSRF token. |
| `POST /api/v1/auth/logout` | Deletes the session server side and clears the cookie. |
| `GET /api/v1/auth/me` | The current account, and the session's CSRF token. |

Every state-changing request authenticated by the session cookie must
send the CSRF token in an `X-CSRF-Token` header. The token is derived
from the session, so a page reload or a second tab can recover it from
`GET /api/v1/auth/me` rather than having to store it.

The session cookie is `Secure` and uses the `__Host-` prefix, which
browsers only accept over HTTPS. **Run the server behind TLS**; over
plain HTTP a browser will refuse to store the cookie at all. Command
line clients are unaffected.

If the server is reachable at anything other than a loopback address,
`SCREENWARD_PUBLIC_URL` is required: it is what incoming `Origin`
headers are checked against, and the server refuses to start without it.

### Behind a reverse proxy

`X-Forwarded-For` is ignored unless the connecting peer is listed in
`SCREENWARD_TRUSTED_PROXIES` (a comma-separated list of CIDRs, empty by
default). Set it to the addresses of your own proxies, or per-client
rate limiting will count every request against the proxy instead.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), in particular the rules on
secrets and test data before opening a pull request.
