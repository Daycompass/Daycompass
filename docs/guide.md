# Operating guide and API overview

How to run a Daycompass server and what its API does, with the reasoning
behind the parts that are not obvious. The short introduction is the
[README](../README.md); the exact request and response formats are in
[wire-format.md](wire-format.md).

## First start

On the very first start the database has no accounts, so there is no way
to log in yet. The server notices this, generates a single-use **setup
token**, and prints it to standard output:

```text
Daycompass first-time setup: no admin account exists yet.
Create one within 60 minutes by sending this token, a username and a
password to POST http://127.0.0.1:8080/api/v1/setup
Setup token: dcb_...
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

## Running in a container

The repository's `Dockerfile` builds a small image (a distroless base,
no shell, running as a non-root user). Both base images are pinned by
digest.

```sh
podman build -t daycompass .        # or: docker build -t daycompass .

podman volume create daycompass-data
podman run -d --name daycompass \
  -p 127.0.0.1:8080:8080 \
  -v daycompass-data:/data \
  -e DAYCOMPASS_PUBLIC_URL=https://daycompass.example.com \
  daycompass
```

Then read the setup token from `podman logs daycompass` (see
"First start" above).

- **`DAYCOMPASS_PUBLIC_URL` is required.** The image binds to
  `0.0.0.0:8080` so the port can be published, and for any bind beyond
  loopback the server refuses to start without knowing its public
  origin. Set it to the URL people actually open.
- **Keep `/data` on a volume.** It holds the SQLite database. A named
  volume, as above, gets the right owner automatically. A bind mount
  must be owned by uid `65532`, the image's user, or the server
  refuses to start: `chown 65532:65532 /srv/daycompass` before the first
  run.
- **Configuration is environment variables only**, as everywhere else.
  Every `DAYCOMPASS_*` variable can be passed with `-e`, or read from a
  mounted file through its `_FILE` variant. Nothing is baked into the
  image beyond the bind address and data directory above.
- **Behind a reverse proxy**, publish the port to loopback only (as
  above) and set `DAYCOMPASS_TRUSTED_PROXIES` - see "Behind a reverse
  proxy" below.
- **There is no `HEALTHCHECK`**: the image has no shell or `curl` to run
  one with. Probe `GET /healthz` from your orchestrator instead.
- The server handles `SIGTERM` itself, so `podman stop` / `docker stop`
  shut it down cleanly.

## Authentication

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/setup` | Redeem the setup token, create the first admin. 404 once one exists. |
| `POST /api/v1/auth/login` | Sets the `__Host-dcs` session cookie, returns a CSRF token. |
| `POST /api/v1/auth/logout` | Deletes the session server side and clears the cookie. |
| `GET /api/v1/auth/me` | The current account, and the session's CSRF token. |
| `POST /api/v1/auth/password` | Change your own password. |

Every state-changing request authenticated by the session cookie must
send the CSRF token in an `X-CSRF-Token` header. The token is derived
from the session, so a page reload or a second tab can recover it from
`GET /api/v1/auth/me` rather than having to store it.

The session cookie is `Secure` and uses the `__Host-` prefix, which
browsers only accept over HTTPS. **Run the server behind TLS**; over
plain HTTP a browser will refuse to store the cookie at all. Command
line clients are unaffected.

#### Plain HTTP on a home network

If the server is only reachable on a trusted LAN (for example a
Raspberry Pi at `http://192.0.2.10:8080`) and you cannot or do not want
to set up TLS, set `DAYCOMPASS_INSECURE_COOKIES=true` together with an
`http://` `DAYCOMPASS_PUBLIC_URL`. The session cookie is then named
`dcs` and loses `Secure` and the `__Host-` prefix, so browsers keep it
over HTTP. It stays `HttpOnly` and `SameSite=Strict`.

This is a real downgrade: anyone who can read the network traffic can
take over a session, and a sibling host can shadow the cookie. The
server refuses to start with this set and an `https://` public URL, and
only the exact values `true` and `false` are accepted. Do not use it on
anything reachable from the internet.

If the server is reachable at anything other than a loopback address,
`DAYCOMPASS_PUBLIC_URL` is required: it is what incoming `Origin`
headers are checked against, and the server refuses to start without it.

### Behind a reverse proxy

`X-Forwarded-For` is ignored unless the connecting peer is listed in
`DAYCOMPASS_TRUSTED_PROXIES` (a comma-separated list of CIDRs, empty by
default). Set it to the addresses of your own proxies, or per-client
rate limiting will count every request against the proxy instead.

## Accounts

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/users` | Create a pending account: `username`, `role`. Answers with the account and an invite. Admin only. |
| `GET /api/v1/users` | List accounts: `id`, `username`, `role`, `status`, `created_at`. Admin only. |
| `PATCH /api/v1/users/{id}` | Change an account's `role`. Admin only. |
| `DELETE /api/v1/users/{id}` | Delete an account and its sessions. Admin only. |
| `POST /api/v1/users/{id}/password-reset` | Reset an account to pending, issuing a fresh invite. Admin only. |

A password hash never leaves the server: the account endpoints select no
such column in the first place.

Usernames follow the same rules everywhere - trimmed, lowercased, 3 to
32 characters of `a-z`, `0-9`, `_`, `.` and `-` - so `Alice` and `alice`
are the same account, and creating the second one answers 409.

Request bodies reject unknown fields. A stray or misspelled field is an
error rather than something silently ignored.

### Invite-based onboarding

An admin never chooses, sees, or stores another account's password.
Creating an account or resetting one's password both answer with an
`invite: { token, expires_at }` instead - a one-time token, shown
exactly once, that the admin hands over however accounts are normally
communicated at that instance. The person redeems it themselves:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/invites/redeem` | Redeem an invite token and set the account's first password. Public. |
| `GET /api/v1/account/log` | Your own account's log of invites redeemed and password resets. Session. |

`POST /api/v1/invites/redeem` takes `invite_token` and `new_password`
(the full password policy applies, since this is a password being
chosen) and answers `204 No Content` with no cookie - the account logs
in normally afterwards through `POST /api/v1/auth/login`. An unknown,
expired, already-used or malformed token all answer the same
`invalid_invite_token`, same as a pending account's login fails
exactly like a wrong password: neither tells an unauthenticated caller
anything about which accounts exist or what state they are in.

Invites expire after `DAYCOMPASS_INVITE_TTL_SECS` (72 hours by
default - see `design-decisions.md` for why).

### What an admin can and cannot do

An admin manages accounts. An admin **cannot** read another account's
usage events or stats - not now that an owner can read their own back,
and not once stats exist either.

An admin *can* reset any account's password - and after doing so,
could in principle redeem the new invite and log in as that account.
That power is not hidden: every reset writes an entry to the account's
own log (`GET /api/v1/account/log`), naming the acting admin and when
it happened, and only the account holder can read their own log. See
`design-decisions.md` for why that power exists and why it is
made visible rather than removed.

Beyond a reset, there is still no endpoint for an admin to directly set
someone else's password. `POST /api/v1/auth/password` takes no account
parameter at all, so it can only ever change the caller's own.

### The last admin

The last remaining **active** admin can be neither deleted, demoted,
nor reset; all three answer 409 `last_admin_protected`. The check and
the write happen in one `BEGIN IMMEDIATE` transaction, so two admins
removing each other at the same moment cannot leave the instance with
none.

A *pending* admin - one that has not yet redeemed its invite - never
counts towards this: it cannot log in, so it is not an administrator
anyone can currently rely on, and may be demoted or deleted freely even
while it is the only other admin on the instance.

Short of that, an admin may demote or delete **themselves**. A role is
read from the database on every request and is never cached in a
session, so such an admin loses administrative access on their very next
request - no new login, and no waiting for a session to expire. The same
is why demoting another admin takes effect immediately, and why deleting
an account ends its sessions at once: the sessions are deleted with the
row, so every cookie it handed out stops working.

### Changing your own password

`POST /api/v1/auth/password` takes `current_password` and
`new_password`. The current password must be correct (403
`invalid_current_password` otherwise - the session stays valid, so a
client must not treat this as being logged out), and the new one must
satisfy the password policy.

On success, **every other session of that account is ended** and the one
that made the request survives, so changing a password is a reliable way
to sign other devices out without signing yourself out. The response
says how many sessions that was.

Two changes in flight at once leave exactly one in effect: the write
applies only if the stored hash is still the one that was verified, and
the other request is answered 409 `password_change_conflict`.

The endpoint is rate limited **per session**, in front of the Argon2
semaphore, because each attempt costs one verification plus one hash -
the most expensive thing an authenticated caller can ask for. Every
attempt counts, including successful ones. See
`DAYCOMPASS_RATE_LIMIT_PW_CHANGE` in `.env.example`.

Per session rather than per account on purpose: someone who has stolen
a session cannot exhaust the budget the owner needs to lock them out.
Logging in again yields a fresh session with its own budget, and
changing the password there ends every other session including the
stolen one. The cost of that choice is that the limit bounds Argon2 work
per session rather than per account; opening more sessions means more
budget, which the login limits bound in turn.

## Devices and events

A device is a client - a phone, a laptop - paired to one account. It
authenticates with its own bearer token and reports what applications
were in use for how long.

The full request and response format is in
[wire-format.md](wire-format.md), which is the reference for
client repositories. This section is the shape of it and the reasoning
behind the parts that are not obvious.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/pairing-codes` | Mint a code for your own account. Session. |
| `POST /api/v1/pair` | Redeem a code, receive a device token. Public. |
| `POST /api/v1/events` | Report events. Device. |
| `GET /api/v1/device/me` | Identity and the server's clock. Device. |
| `GET /api/v1/events` | Your own events, within a time window. Session. |
| `GET /api/v1/devices` | Your own devices. Session. |
| `PATCH /api/v1/devices/{id}` | Rename your own device. Session. |
| `POST /api/v1/devices/{id}/revoke` | Revoke your own device. Session. |
| `GET /api/v1/admin/devices` | Every device, metadata only. Admin. |
| `POST /api/v1/admin/devices/{id}/revoke` | Revoke any device. Admin. |

### Pairing

A logged-in person mints a ten-character code, reads it to the new
device, and the device redeems it for a token. The code is single use,
expires after ten minutes, and only its hash is stored. At most five
live codes and twenty live devices per account; both are configurable.

The code is short because somebody types it on a phone, which is a real
trade-off and the reason the ten-minute expiry is not negotiable: a
leaked hash is only worth cracking while the code is still redeemable.
Ambiguous characters are left out of the alphabet, so `I`, `L`, `O` and
`U` are never generated and the first three are folded onto the digits
they are mistaken for.

An unknown, expired, used and malformed code all produce the same
answer. Hitting the device cap is reported differently, which is safe
because it takes a valid code to get there - and that case leaves the
code **unspent**, so revoking an old device and retrying the same code
works.

### Two kinds of caller

The dashboard authenticates with a cookie; a device authenticates with
`Authorization: Bearer`. They are not interchangeable, and the server
refuses requests that are confused about which they are: a device route
rejects any request carrying the session cookie, and a session route
rejects any bearer credential.

`POST /api/v1/pair`, `POST /api/v1/events` and `GET /api/v1/device/me`
are exempt from the `Origin` check, because native clients send no
`Origin` header. That is only safe because none of them has ambient
cookie authority in either direction - they do not authenticate by
cookie and they do not hand one out. The exemption is a named property
of each route's entry in the route inventory rather than a per-route
flag, and the inventory refuses to let it be attached to anything else.
Login, in particular, cannot have it.

### Reporting events

A batch of up to 500 events, in a body of up to 512 KiB. Each event
carries a client-generated id, and deduplication is per event on
`(device, id)` - so **resending is always safe**, and a client never has
to track what it has already delivered.

The response is `200` with one result per event: accepted, duplicate, or
rejected with a machine-readable reason. Only a malformed request fails
as a whole. A client that could not get rid of one bad event would
otherwise retry the same batch forever.

Events carry no category. Categories are assigned at query time from
rules, so recategorising does not rewrite history.

Events record an application id, an optional label, and an optional
**bare hostname** for browser activity. There is no column for a window
title or a URL, and the hostname field rejects anything carrying a
scheme, port, path or query - a screen time tool does not need a
browsing history, so it does not store one.

Overlapping events are kept as reported. One device reporting a
foreground application and a browser domain at once is normal, as is
two devices covering the same span; deciding what an overlap means is a
query-time question.

### Reading your own events back

`GET /api/v1/events?start_ts=...&end_ts=...` returns the caller's own
events across every device they own, inside that half-open window.
Both parameters are required and bounded - a window wider than the
server allows, or with the end not strictly after the start, is
refused rather than silently clamped. A response wider than the
server's row cap says so in a `truncated` flag instead of a cursor: a
client that hits it narrows its own window and asks again, the same
way an oversized batch is split on the way in.

Events still carry no category. Categories come from your own rules at
query time, and `GET /api/v1/stats` sums a day's totals per category;
both are documented in [wire-format.md](wire-format.md).

### Revoking

Revoking keeps the device row and every event it reported - it is not a
delete. The token stops working on the device's very next request,
because the row is re-read every time and nothing is cached. Revoking
twice is not an error.

A revoked device is indistinguishable from an unknown one in the
response, so neither can be used to probe the other.

### What an admin can and cannot see here

An admin can list every device on the instance and revoke any of them,
and sees metadata only: id, owner, name, platform, and the three
timestamps.

An admin has **no way to read anyone's events** - not even their own
account's, through this endpoint. There is no admin variant of
`GET /api/v1/events` and no id parameter on it that could point it at
another account; it always answers for the session that called it,
whoever that is. That is checked rather than remembered: a test fails
if a route touching events appears in the inventory outside the one
write and the one owner-scoped read, if any file outside the events
store queries the table without scoping by the caller's own user id,
or if either device view grows a field.

## Design decisions

[design-decisions.md](design-decisions.md) records the
reasoning behind a few choices that are not obvious from the code
alone - starting with why an admin can reset a password but never
choose one, and why that is made visible rather than removed.

## License

AGPL-3.0-only. See [LICENSE](../LICENSE).

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md), in particular the rules on
secrets and test data before opening a pull request.
