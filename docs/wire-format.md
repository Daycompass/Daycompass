# Wire format: accounts, invites, pairing, device auth, and events

Reference for client implementations: every route this server answers
— setup, login and session management, account and device
administration, pairing a device, authenticating as one, reporting
events, reading an account's own events back, managing the category
rules those events are matched against, and reading the resulting
screen time summed per day and category.

Everything here is normative for the server as it stands. The
authoritative definitions live in the code (`src/routes/`,
`src/events/validate.rs`); this file exists so client repositories have
something to read without following Rust.

Every route in `src/routes/mod.rs`'s `INVENTORY` has a section below,
each preceded by an HTML-comment anchor naming its method and path.
`tests/wire_format_documented.rs` enforces the correspondence in both
directions: a route added to `INVENTORY` with no matching section here
fails the test, and so does a section whose anchor names a route that
no longer exists.

## Conventions

- All timestamps are **integer Unix seconds, UTC**.
- All request and response bodies are `application/json`.
- Request bodies reject unknown fields, with two exceptions:
  `POST /api/v1/auth/login` and `POST /api/v1/setup` ignore a field
  they do not recognize instead of failing the request on it. **Do not
  rely on either behaviour** — send exactly the fields documented for
  the endpoint. Both endpoints' own sections repeat this.
- Errors share one shape:

  ```json
  { "error": { "code": "invalid_pairing_code", "message": "the pairing code is not valid" } }
  ```

  Branch on `code`, which is stable. `message` is for humans and may be
  reworded. Neither ever echoes back what you sent.

### Errors any endpoint can return

These come from infrastructure that wraps every route, not from an
endpoint's own logic, and share the error shape above like any other
failure:

| Status | Code | When |
| --- | --- | --- |
| 400 | `bad_request` | Malformed JSON, or a request shape the server could not parse at all. |
| 401 | `unauthenticated` | No valid session or device credential. |
| 403 | `forbidden` | Authenticated, but not allowed to do this. |
| 403 | `csrf_token_missing` / `csrf_token_invalid` | A route that requires `X-CSRF-Token` on writes did not get one, or got one that does not match the session. |
| 403 | `origin_mismatch` | A present `Origin` header names something other than this instance, on a route that checks it. |
| 408 | `request_timeout` | The request took longer than 10 seconds end to end. |
| 413 | `payload_too_large` | Body over the global 64 KiB request limit. Some endpoints set a smaller limit of their own — see that endpoint's section. |
| 415 | `unsupported_media_type` | `Content-Type` is missing or not `application/json`. |
| 500 | `internal_server_error` | Something broke on the server. Never carries detail. |

## Authentication

Two kinds of caller, which are never interchangeable.

| | Session (dashboard) | Device (native client) |
| --- | --- | --- |
| Credential | `__Host-dcs` cookie | `Authorization: Bearer dcd_…` |
| CSRF | `X-CSRF-Token` required on writes | not applicable |
| `Origin` | checked on writes | not checked |

A device route **rejects** any request carrying the `__Host-dcs`
cookie, even one that also presents a valid token. A session route
rejects any request carrying a `Bearer` credential. Do not send both.

The `Bearer` scheme name is matched case-insensitively.

---

## Health

<!-- route: GET /healthz -->
### `GET /healthz`

No authentication, no CSRF, no rate limit. A liveness probe: it
reports only whether the database is reachable right now, nothing
about why not.

**`200 OK`:**

```json
{ "status": "ok" }
```

**`503 service_unavailable`** — the handler itself answers with an
empty body, but `normalize_error_responses`
(`src/middleware.rs`) rewrites every non-2xx response that is not
already in the server's uniform shape into it before it reaches the
wire, this one included:

```json
{ "error": { "code": "service_unavailable", "message": "service unavailable" } }
```

The underlying database error is logged server-side and never appears
in the response — a client learns only "ok" or "not ok", nothing more
specific.

---

## Setup

<!-- route: POST /api/v1/setup -->
### `POST /api/v1/setup`

Creates the instance's first admin account. Authenticated by the setup
token printed to stdout at server startup — an unguessable capability
in the body, not a session — so there is no CSRF check and no `Origin`
check: neither protects a cookie that does not exist here. Unknown
fields are ignored (see [Conventions](#conventions)).

```json
{ "setup_token": "…", "username": "alice", "password": "a long enough passphrase" }
```

`username` and `password` follow the same rules as account creation —
see [`POST /api/v1/users`](#post-apiv1users) below.

**`201 Created`:**

```json
{ "user": { "id": "0199…", "username": "alice", "role": "admin" } }
```

Note what this is missing, unlike every other account view: no
`status`, no `created_at` — see
["The `status` field on a user object"](#the-status-field-on-a-user-object)
below. It describes an account that is already usable, the same as
`/api/v1/auth/login` and `/api/v1/auth/me`. The response sets **no
cookie**; log in afterward through `POST /api/v1/auth/login`.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 404 | `not_found` | An admin already exists. Byte-identical to the response an unknown route gives, so a provisioned instance is indistinguishable from one that never had this endpoint. |
| 401 | `invalid_setup_token` | Unknown or wrong token. |
| 400 | `invalid_username` | Fails the length or charset rule. |
| 400 | `invalid_password` | Blank, or outside 12–128 characters. |
| 503 | `server_busy` | Password hashing capacity is exhausted; shed, not refused. Carries `Retry-After`, honour it the same as a `429`. |
| 429 | `rate_limited` | Per client address, 5 per hour by default, operator-configurable. Counts every attempt, successful or not. |

---

## Sessions

<!-- route: POST /api/v1/auth/login -->
### `POST /api/v1/auth/login`

**No authentication**, but `Origin` **is** checked — a successful login
mints a session cookie, so this is exactly the route login CSRF would
target. Unknown fields are ignored (see [Conventions](#conventions)).

```json
{ "username": "alice", "password": "…" }
```

**`200 OK`:**

```json
{
  "user": { "id": "0199…", "username": "alice", "role": "user" },
  "csrf_token": "…"
}
```

Sets `Set-Cookie: __Host-dcs=…; Path=/; HttpOnly; Secure; SameSite=Strict`
— no `Max-Age`: the server decides when a session ends, not the
client's clock. Keep `csrf_token` in memory and send it back as
`X-CSRF-Token` on every write this session makes.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | `invalid_credentials` | Wrong password, unknown account, or a **pending** account that has not redeemed its invite — all three answer identically; see [the `status` field](#the-status-field-on-a-user-object). |
| 503 | `server_busy` | Password hashing capacity is exhausted. Carries `Retry-After`. |
| 429 | `rate_limited` | Two buckets, either can produce this: per client address (10 per 5 minutes by default) and per username across every address (5 per 5 minutes by default). Both are operator-configurable and may differ from these defaults on any given instance. The response does not say which. Both count every attempt. |

<!-- route: POST /api/v1/auth/logout -->
### `POST /api/v1/auth/logout`

Session auth, CSRF required, no body.

**`204 No Content`**, with the cookie cleared (`Max-Age=0`). The
session row is deleted server-side — that is what actually ends the
session — and the cookie clear is cosmetic on top of it.

<!-- route: GET /api/v1/auth/me -->
### `GET /api/v1/auth/me`

Session auth. The documented way to get the CSRF token back after a
page reload or in a new tab: the value is derived from the session
cookie, so any tab holding it can ask.

**`200 OK`:** same shape as login's success response, minus the
`Set-Cookie` header — `{"user": {...}, "csrf_token": "…"}`. No
`status` field on `user`; see
[the `status` field](#the-status-field-on-a-user-object).

**Failures:** `401 unauthenticated` — no valid session.

<!-- route: POST /api/v1/auth/password -->
### `POST /api/v1/auth/password`

Session auth, CSRF required. Changes the caller's **own** password —
there is no account parameter, so no request can aim this at somebody
else.

```json
{ "current_password": "…", "new_password": "a long enough passphrase" }
```

This body rejects unknown fields (no exception here).

**`200 OK`:**

```json
{ "other_sessions_ended": 2 }
```

The session that made this request survives and keeps working;
`other_sessions_ended` counts only the rest.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 403 | `invalid_current_password` | **403, not 401** — the calling session stays valid. A password-change form must not react to this by logging the user out. |
| 400 | `invalid_password` | The new password is blank, or outside 12–128 characters. |
| 409 | `password_change_conflict` | Another request changed the password first; retry with the new current password. |
| 401 | `unauthenticated` | The account was deleted between the session being resolved and the change being applied. |
| 503 | `server_busy` | Password hashing capacity is exhausted. Carries `Retry-After`. |
| 429 | `rate_limited` | Per **session**, not per account — 5 per 15 minutes by default, operator-configurable — so a stolen session cannot spend the budget the rightful owner needs to lock it out. |

---

## Accounts and invites

An admin never chooses, sees, or stores a new account's password.
Instead an admin creates a **pending** account and hands the person a
one-time invite token; the person redeems it and chooses their own
password. The same flow is how an admin resets a forgotten password:
it does not set a new one, it issues a fresh invite in place of the
old one. Nothing stops an admin from redeeming that invite themselves
and logging in as the account instead of handing it over; the
account's own log, below, records the reset and which admin performed
it, but not who went on to redeem the invite, and recording does not
prevent the takeover.

### The `status` field on a user object

Appears on every account-management response below — `POST`/`GET
/api/v1/users`, `PATCH /api/v1/users/{id}`, and the `user` object
inside the two invite responses that follow. It is **absent** from
`/api/v1/auth/me`, `/api/v1/auth/login`, and `/api/v1/setup`, which
only ever describe an account that is already usable.

| Value | Meaning |
| --- | --- |
| `"active"` | Has a password and can log in. |
| `"pending"` | Created by an admin, or reset by one, and has not yet redeemed its invite. Cannot log in — a login attempt against a pending account answers identically to an unknown one (`401` `invalid_credentials`). |

<!-- route: POST /api/v1/users -->
### `POST /api/v1/users`

Admin session auth, CSRF required. Creates a pending account and its
invite.

```json
{ "username": "alice", "role": "user" }
```

`username`: 3–32 characters after trimming, from `a-z`, `0-9`, `_`,
`.`, `-`. Normalized to lowercase ASCII before storage and before the
uniqueness check, so `Alice` and `alice` are the same account.

`role`: exactly `"admin"` or `"user"`, lowercase — not case-folded the
way `platform` is on `/api/v1/pair`.

**`201 Created`:**

```json
{
  "user": {
    "id": "0199…",
    "username": "alice",
    "role": "user",
    "status": "pending",
    "created_at": 1800000000
  },
  "invite": {
    "token": "dci_…",
    "expires_at": 1800259200
  }
}
```

`invite.token` is shown **exactly once**; the server stores only its
hash. It is redeemable for 72 hours by default (`expires_at` is the
authoritative expiry — do not hardcode the 72 hours client-side).

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_username` | Fails the length or charset rule above. |
| 400 | `invalid_role` | Not `admin` or `user`. |
| 409 | `username_taken` | Another account already normalizes to this username. |

<!-- route: GET /api/v1/users -->
### `GET /api/v1/users`

Admin session auth, no CSRF (a `GET`). Lists every account on the
instance.

**`200 OK`:**

```json
{
  "users": [
    { "id": "0199…", "username": "alice", "role": "user", "status": "active", "created_at": 1800000000 }
  ]
}
```

Ordered `created_at, id` ascending — stable across requests, including
between two accounts created in the same second.

**Failures:** `403 forbidden` for a non-admin session; `401
unauthenticated` for no session.

<!-- route: PATCH /api/v1/users/{id} -->
### `PATCH /api/v1/users/{id}`

Admin session auth, CSRF required. Changes an account's role — nothing
else. There is no way to rename an account or touch its password here;
that is `POST /api/v1/users/{id}/password-reset`, below.

```json
{ "role": "admin" }
```

`role`: exactly `"admin"` or `"user"`, lowercase — same rule as
creation.

**`200 OK`:**

```json
{ "user": { "id": "0199…", "username": "alice", "role": "admin", "status": "active", "created_at": 1800000000 } }
```

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_role` | Not `admin` or `user`. |
| 404 | `not_found` | No account with this id. |
| 409 | `last_admin_protected` | This account is the instance's only active admin, and the change would demote it. |

<!-- route: DELETE /api/v1/users/{id} -->
### `DELETE /api/v1/users/{id}`

Admin session auth, CSRF required. The **only** destructive account
operation — do not confuse it with a password reset, which keeps the
account and only replaces its credential.

No request body.

**`204 No Content`**, no body. Deleting cascades: every session,
device (and every event that device reported), pairing code, invite
and account-log entry belonging to this account is deleted with it
(`ON DELETE CASCADE`, migrations `0002_auth.sql` through
`0004_invites_account_log.sql`).

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 404 | `not_found` | No account with this id. |
| 409 | `last_admin_protected` | This is the instance's only active admin. |

<!-- route: POST /api/v1/users/{id}/password-reset -->
### `POST /api/v1/users/{id}/password-reset`

Admin session auth, CSRF required. Resets an existing account to
pending in place of whatever password it had: every session the
account held is ended, every device it had paired is revoked, and any
pairing code it had minted but not yet redeemed is revoked too — it
will no longer pair a device. A fresh invite is issued in the same
step.

No request body.

**`200 OK`:**

```json
{
  "invite": {
    "token": "dci_…",
    "expires_at": 1800259200
  },
  "sessions_ended": 1,
  "devices_revoked": 1
}
```

`sessions_ended` and `devices_revoked` count what **this** reset just
ended — not a running total for the account.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 404 | `not_found` | No account with this id. |
| 409 | `last_admin_protected` | This is the instance's only active admin. |

<!-- route: POST /api/v1/invites/redeem -->
### `POST /api/v1/invites/redeem`

**No authentication.** Unlike `/api/v1/setup` and `/api/v1/pair`, the
`Origin` header **is** checked here — redeeming changes the password
of an account that already exists, which is closer in spirit to
logging in than to creating something new. No CSRF, since there is no
cookie for a token to be checked against.

A request with no `Origin` header at all - a native client, curl, a
script - is allowed, exactly as it is for login. A request that does
carry one must match the instance's public origin, or it is refused
with `origin_mismatch` below. A browser always sends `Origin` on a
cross-site `POST`, so this is the case the check exists to catch.

```json
{
  "invite_token": "dci_…",
  "new_password": "a long enough passphrase"
}
```

`new_password`: 12–128 characters, not blank. The password policy is
checked **before** the token, so a too-short password against an
unknown or expired token still answers `invalid_password`, not
`invalid_invite_token`.

**`204 No Content`** — sets no cookie. Log in normally afterward
through `POST /api/v1/auth/login`.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_password` | Blank, or outside 12–128 characters. |
| 401 | `invalid_invite_token` | Unknown, expired, already used, or malformed. Deliberately indistinguishable — redeeming is unauthenticated, so the response must not say whether a token ever existed. |
| 403 | `origin_mismatch` | A present `Origin` header names something other than this instance. |
| 503 | `server_busy` | Password hashing capacity is exhausted; shed, not refused. Carries `Retry-After`, honour it the same as a 429. |
| 429 | `rate_limited` | Per-address or instance-wide limit; see below. Carries `Retry-After`. |

**Rate limits**, both counting **every** attempt, successful or not,
same as pairing:

| Limit | Default | Scope |
| --- | --- | --- |
| Per client address | 100 per 5 minutes | One address — sized with headroom for many people redeeming from behind one shared address (a school's NAT), not as a guessing defence. The token is unguessable regardless of this number. |
| Instance-wide | 600 per minute | A ceiling on total work across every caller, not a per-person budget. |

Both are operator-configurable and may differ from these defaults on
any given instance.

<!-- route: GET /api/v1/account/log -->
### `GET /api/v1/account/log`

Session auth, no CSRF (a `GET`). Returns the **caller's own** history
of invite redemptions and password resets — there is no id parameter
and no admin variant, so an account can never read anyone else's.

**`200 OK`:**

```json
{
  "entries": [
    { "kind": "invite_redeemed", "actor_id": null, "at": 1800001000 },
    { "kind": "password_reset_by_admin", "actor_id": "0199…", "at": 1800000000 }
  ]
}
```

`kind` is one of `invite_redeemed`, `password_reset_by_admin`, or
`password_changed`.

`actor_id` is the acting admin's id, present only for
`password_reset_by_admin` — the other two kinds are the account acting
on itself, so it is `null`.

The `password_reset_by_admin` entry is written at the moment of the
reset, independent of who redeems the resulting invite — but this
endpoint is session auth, so the entry is only ever readable by
whoever can log in as the account. If the rightful holder redeems the
invite, they will see it on their next visit here. If an admin
redeems it first instead and logs in as the account, the holder never
gets the password needed to log in at all, and so never sees it
either. An `invite_redeemed` entry never says who redeemed it.

Newest first, capped at the 200 most recent entries.

---

## Pairing

<!-- route: POST /api/v1/pairing-codes -->
### `POST /api/v1/pairing-codes`

Session auth, CSRF required. Mints a code for the calling account.

```json
{
  "pairing_code": "4K7M9-QRT2V",
  "expires_at": 1800000600,
  "server_time": 1800000000
}
```

- The code is shown **once**. The server stores only a hash.
- Valid for 10 minutes, single use.
- At most 5 live codes per account; a sixth returns `409`
  `pairing_code_limit_reached`.

<!-- route: POST /api/v1/pair -->
### `POST /api/v1/pair`

**No authentication.** No `Origin` check, no CSRF. This is the one
endpoint a brand-new client calls.

```json
{
  "pairing_code": "4K7M9-QRT2V",
  "device_name": "Alice's Laptop",
  "platform": "linux"
}
```

`pairing_code` is normalized before lookup, so all of these are the
same code: dashes and whitespace are stripped, letters are uppercased,
and `I`/`L` fold to `1` while `O` folds to `0`. Those four characters
are never generated, so folding them is lossless. **Send what the
person typed**; do not normalize client-side.

`device_name`: 1–64 characters after trimming, non-blank. No control
characters, and no bidirectional overrides (U+202A–U+202E,
U+2066–U+2069). Counted in characters, not bytes.

`platform`: one of `android`, `windows`, `macos`, `linux`, `ios`.
Case-insensitive.

**`201 Created`:**

```json
{
  "device_token": "dcd_…",
  "device": {
    "id": "0199…",
    "name": "Alice's Laptop",
    "platform": "linux",
    "created_at": 1800000000,
    "last_seen_at": 1800000000,
    "revoked_at": null
  },
  "server_time": 1800000000
}
```

`device_token` is returned **exactly once** and cannot be recovered.
Store it securely; if it is lost, the device must be paired again.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | `invalid_pairing_code` | Unknown, expired, already used, or malformed. Deliberately indistinguishable. |
| 409 | `device_limit_reached` | Valid code, but the owner is at their device cap. **The code is not consumed** — revoke a device and retry the same code. |
| 400 | `invalid_device_name` | Fails the name policy. |
| 400 | `invalid_platform` | Not one of the five. |
| 429 | `rate_limited` | Per-address or instance-wide limit. Honour `Retry-After`. |

Rate limits count **every** attempt, not only failures.

---

## Device endpoints

<!-- route: GET /api/v1/device/me -->
### `GET /api/v1/device/me`

Device auth. Confirms identity and reports the server's clock.

```json
{
  "id": "0199…",
  "name": "Alice's Laptop",
  "platform": "linux",
  "server_time": 1800000000
}
```

Call this on startup and compare `server_time` with your own clock.
Ingest refuses events dated more than 300 seconds into the future, so a
skewed client will otherwise see rejections it cannot explain.

**This is a startup and clock-skew check, not a heartbeat. Do not poll
it on a sync interval.**

**Limits:**

| Limit | Status | Code |
| --- | --- | --- |
| Failed device authentication, per address | 429 | `rate_limited` |
| Requests from this device | 429 | `rate_limited` |

Both device routes share one per-device bucket: calling `device/me`
spends the same budget as sending events, there are not two numbers to
keep in step. Both are also covered by the per-address limit on
*failed* authentication - see
["Handling errors on device routes"](#handling-errors-on-device-routes)
below for what to do with either 429.

<!-- route: POST /api/v1/events -->
### `POST /api/v1/events`

Device auth. Reports observed activity.

```json
{
  "events": [
    {
      "event_id": "0123456789abcdef0123456789abcdef",
      "start_ts": 1799996400,
      "duration_secs": 300,
      "app_id": "org.mozilla.firefox",
      "label": "Firefox",
      "domain": "example.com"
    }
  ]
}
```

**Limits on the request as a whole** — these fail the whole call:

| Limit | Status | Code |
| --- | --- | --- |
| Body over 512 KiB | 413 | `payload_too_large` |
| More than 500 events | 413 | `batch_too_large` |
| Malformed JSON | 400 | `bad_request` |
| Missing/wrong `Content-Type` | 415 | `unsupported_media_type` |
| Unknown field on an event | 400 | `bad_request` |

**Per-event fields:**

| Field | Required | Rule |
| --- | --- | --- |
| `event_id` | yes | Client-generated. **Send 32 lowercase hex characters.** A canonical dashed UUID is also accepted; it is normalized to the bare form before storage, so the two spellings of one id are the same id and will not produce two rows. Hex case is folded. |
| `start_ts` | yes | At most 300 s in the future; not older than the server's configured window (90 days by default). |
| `duration_secs` | yes | 1–86400. `start_ts + duration_secs` may also be at most 300 s in the future. |
| `app_id` | yes | 1–256 characters, non-blank. Stored **exactly** as sent — never trimmed or rewritten. |
| `label` | no | Up to 128 characters. A human-readable name. |
| `domain` | no | Up to 253 characters, a **bare hostname**. Lowercased on storage. |

### `event_id`: send the canonical form

The server stores 32 lowercase hex characters. If you send a dashed
UUID the dashes are stripped and the value is lowercased before it is
written, so what comes back out of the database is not byte-identical
to what you sent.

That normalization exists so idempotency survives a client changing
how it formats ids between versions — the bare and dashed spellings of
one id collide rather than producing two rows. Send the bare lowercase
form and the question does not arise.

### `domain`: a hostname, never a URL

`domain` must be a hostname and nothing else. No scheme, port, path,
query, fragment or userinfo — all are rejected. ASCII only; punycode
an internationalised name yourself. A single trailing dot is accepted
and dropped. This field exists for browser tracking and is deliberately
incapable of holding a URL.

### Every string field

No string may contain a control character or a bidirectional override.

**There is no `category` field and never will be on an event.**
Categories are assigned at query time from rules.

**`200 OK`** — always, if the request itself was well formed:

```json
{
  "accepted": 2,
  "duplicate": 1,
  "rejected": 1,
  "results": [
    { "index": 0, "status": "accepted" },
    { "index": 1, "status": "duplicate" },
    { "index": 2, "status": "accepted" },
    { "index": 3, "status": "rejected", "reason": "duration_out_of_range" }
  ],
  "server_time": 1800000000
}
```

`results` is **positional**: `index` is the offset in the `events`
array you sent. Your own `event_id` is not echoed back. `reason` is
present only when `status` is `rejected`.

One bad event never fails a batch. This is so a client that cannot get
rid of a malformed event does not retry the same batch forever.

**Rejection reasons:**

| Code | Meaning |
| --- | --- |
| `event_id_malformed` | Not 32 hex characters or a canonical UUID. |
| `duration_out_of_range` | Outside 1–86400. |
| `start_ts_in_future` | Starts more than 300 s ahead. |
| `end_ts_in_future` | `start_ts + duration_secs` is more than 300 s ahead. |
| `start_ts_too_old` | Older than the configured window. |
| `app_id_length` | Outside 1–256 characters. |
| `app_id_blank` | Empty or only whitespace. |
| `label_length` | Over 128 characters. |
| `domain_length` | Over 253 characters. |
| `domain_malformed` | Not shaped like a hostname. |
| `forbidden_character` | A control character or bidi override in any field. |

### Idempotency, and how to sync

Deduplication is per event, on `(device, event_id)`. Generate a stable
`event_id` per observed event and **resending is always safe**:

- A resent batch writes nothing and reports every event as `duplicate`.
- A batch that partly overlaps an earlier one writes exactly the new
  part.

So a client does not need to track what it has already delivered. The
recommended loop is: buffer locally, send a batch, and only drop events
once the response accounts for them (as `accepted` **or** `duplicate`).
On a `429` or a network failure, back off and resend the same batch.

Overlapping events are expected and are stored as reported — one device
reporting a foreground app and a browser domain at once, or two devices
covering the same span. The server does not merge or resolve overlaps;
that is a query-time concern.

---

## Handling errors on device routes

Two statuses need deliberate client behaviour. Getting these wrong is
how a client turns a transient problem into a sustained one.

### `429 Too Many Requests` — buffer locally and back off

Every 429 carries a `Retry-After` header, in whole seconds. **Honour
it.** Do not retry before it elapses, and do not treat the refused
batch as lost.

Keep the events in your local buffer and send them again after the
delay. Ingest is idempotent per event, so resending costs nothing: the
events that did land come back as `duplicate`, and nothing is written
twice. A client that drops a batch on a 429 loses screen time that the
server was willing to accept a moment later.

Two different limits can produce a 429 here:

- **Per device**, on how often you may call the device routes. This is
  the one a healthy, busy client can reach. Back off and continue.
- **Per IP address**, on *failed* authentication — see below. If you
  are getting this one, something is already wrong.

The response does not say which. Treat both the same way: wait, then
resend the same batch.

### `401 Unauthorized` — stop, do not retry in a loop

The token is not valid. Either it never was, or the device has been
revoked by its owner or an administrator. The response deliberately
does not distinguish those.

**Do not retry on a timer.** Failed device authentication is rate
limited per IP address, so a client that loops on a 401 will exhaust
that budget and start getting 429s — and because the budget is shared
by everyone behind the same address, it will do that to every other
Daycompass device on the network too. On a school or household NAT
that means one misconfigured client taking out its neighbours.

The correct response to a 401 is to stop making device requests, keep
whatever is buffered, and surface a "this device needs to be paired
again" state to the person using it. Pairing again issues a new token.

If you retry at all, retry once, well after a long delay — not on a
sync interval.

---

## Device management (session auth)

These are dashboard endpoints, listed here only so a client knows what
a person can do to it. Revoking is **not** deleting: the device row
and every event it reported are kept. A revoked device's token stops
working on its very next request, with nothing cached in between —
expect `401 unauthenticated` and stop retrying. A revoked device
cannot be un-revoked; pair again. A revoked device is
indistinguishable from an unknown one in any of these responses — do
not try to tell them apart.

<!-- route: GET /api/v1/devices -->
### `GET /api/v1/devices`

Session auth, no CSRF (a `GET`). The caller's own devices — revoked
ones included, with `revoked_at` set for those.

**`200 OK`:**

```json
{
  "devices": [
    {
      "id": "0199…",
      "name": "Alice's Laptop",
      "platform": "linux",
      "created_at": 1800000000,
      "last_seen_at": 1800003600,
      "revoked_at": null
    },
    {
      "id": "0199…",
      "name": "Old Phone",
      "platform": "android",
      "created_at": 1700000000,
      "last_seen_at": 1700003600,
      "revoked_at": 1700090000
    }
  ]
}
```

Ordered `created_at, id` ascending.

**Failures:** `401 unauthenticated` for no session.

<!-- route: PATCH /api/v1/devices/{id} -->
### `PATCH /api/v1/devices/{id}`

Session auth, CSRF required. Renames one of the caller's own devices.

```json
{ "name": "Alice's Laptop" }
```

Same name policy as `device_name` on
[`POST /api/v1/pair`](#post-apiv1pair) — repeated here would just be
two places that could drift apart.

**`200 OK`:** the updated device, same shape as one entry of
`GET /api/v1/devices` above.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_device_name` | Fails the length or charset rule — one code for both causes. |
| 404 | `not_found` | No such device, **or** it exists but belongs to someone else — deliberately the same answer, so a caller cannot probe which device ids exist on other accounts. |

<!-- route: POST /api/v1/devices/{id}/revoke -->
### `POST /api/v1/devices/{id}/revoke`

Session auth, CSRF required. Revokes one of the caller's own devices.
No request body.

**`200 OK`:** the device, with `revoked_at` set.

**Idempotent.** A second call against an already-revoked device
answers the same `200` with the same `revoked_at` it already had —
there is no "already done" error, and the second call does not move
the timestamp forward.

**Failures:** `404 not_found` — same "no such device, or not yours"
meaning as above.

## Reading your own events (session auth)

<!-- route: GET /api/v1/events -->
### `GET /api/v1/events`

Session auth, no CSRF (a `GET`). The caller's own events, across every
device they own — revoked devices included, since revoking is not
deleting and their past events are kept. There is no admin variant and
no id parameter that could point this at another account; see
["Admin endpoints"](#admin-endpoints) below for what an admin may and
may not see.

**Query parameters, both required:**

| Parameter | Meaning |
| --- | --- |
| `start_ts` | Inclusive start of the window, Unix seconds. |
| `end_ts` | Exclusive end of the window, Unix seconds. |

The window is `[start_ts, end_ts)`: an event starting exactly at
`end_ts` is outside it. Querying consecutive windows back to back —
this call's `end_ts` as the next call's `start_ts` — therefore never
double-counts or skips the event sitting on the boundary.

```
GET /api/v1/events?start_ts=1799990000&end_ts=1800000000
```

**`200 OK`:**

```json
{
  "events": [
    {
      "device_id": "0199…",
      "event_id": "0123456789abcdef0123456789abcdef",
      "start_ts": 1799996400,
      "duration_secs": 300,
      "app_id": "org.mozilla.firefox",
      "label": "Firefox",
      "domain": "example.com",
      "category": "Browsing"
    }
  ],
  "truncated": false
}
```

Ordered `start_ts, device_id, event_id` ascending. `label`, `domain`
and `category` are all omitted when the event has none — same
optionality as `label`/`domain` have on the way in. `category` is
never stored on the row: it is resolved from the caller's own
[category rules](#category-rules-session-auth) at the moment this
route answers, so creating, editing or deleting a rule changes what
the *next* call to this route reports, never anything already
returned.

**`truncated`:** `true` when more events matched the window than this
response carries. There is no cursor to resume with — narrow
`start_ts`/`end_ts` and ask again, the same way a client that oversends
to `POST /api/v1/events` splits its batch rather than being handed a
page token.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `bad_request` | `start_ts` or `end_ts` missing, not a number, or an unknown query parameter was sent. |
| 400 | `invalid_event_range` | `end_ts` is not strictly after `start_ts`, **or** the span between them is wider than this server allows in one request. |
| 401 | `unauthenticated` | No session. A device's bearer token does not substitute for one — this route does not accept it. |

## Category rules (session auth)

An account's own rules for turning an event's `app_id` or `domain`
into the `category` field on `GET /api/v1/events` above. Session-
scoped only, same reasoning as that route: there is no admin variant
and no id parameter that could point a rule at another account.

A rule matches on exactly one of two fields, named by `kind`:

- `app_id` — exact, case-sensitive, the same identifier semantics as
  an event's own `app_id`.
- `domain` — case-insensitive, and matches the pattern's subdomains
  too: a rule on `google.com` also matches `mail.google.com`, but not
  `notgoogle.com`.

When an event matches both an `app_id` rule and one or more `domain`
rules, the `app_id` rule wins. Among domain rules, the longest (most
specific) matching pattern wins. An event matching no rule has no
`category` at all, not a sentinel value.

<!-- route: POST /api/v1/category-rules -->
### `POST /api/v1/category-rules`

Session auth, CSRF required. Creates a rule for the caller's own
account.

```json
{ "kind": "domain", "pattern": "google.com", "category": "Search" }
```

`pattern` is validated and normalized per `kind`: an `app_id` pattern
follows the same rules as an event's `app_id` (never modified); a
`domain` pattern follows the same rules as an event's `domain`
(lowercased, one trailing dot stripped, checked as a bare hostname —
no scheme, path, port or query). `category` is a display string, 1–64
characters after trimming, with the same control/text-direction
charset rule as a device name.

**`201 Created`:**

```json
{
  "rule": {
    "id": "0199…",
    "kind": "domain",
    "pattern": "google.com",
    "category": "Search",
    "created_at": 1800000000
  }
}
```

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_category_rule_kind` | `kind` was something other than `app_id` or `domain`. |
| 400 | `invalid_category_pattern` | `pattern` is blank, too long for its kind, not shaped like a hostname (`domain` only), or carries a control or text-direction character. |
| 400 | `invalid_category_label` | `category` is blank once trimmed, too long, or carries a control or text-direction character. |
| 409 | `category_rule_duplicate` | This account already has a rule of this `kind` for this `pattern` — `(kind, pattern)` is the whole key, whatever `category` either one names. |
| 409 | `category_rule_limit_reached` | This account already holds the maximum number of category rules. |
| 401 | `unauthenticated` | No session. |

<!-- route: GET /api/v1/category-rules -->
### `GET /api/v1/category-rules`

Session auth, no CSRF (a `GET`). The caller's own rules.

**`200 OK`:**

```json
{
  "rules": [
    {
      "id": "0199…",
      "kind": "app_id",
      "pattern": "org.mozilla.firefox",
      "category": "Browsing",
      "created_at": 1800000000
    }
  ]
}
```

Ordered `created_at, id` ascending.

**Failures:** `401 unauthenticated` for no session.

<!-- route: DELETE /api/v1/category-rules/{id} -->
### `DELETE /api/v1/category-rules/{id}`

Session auth, CSRF required. Deletes one of the caller's own rules.
No request body.

**`204 No Content`** on success.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 404 | `not_found` | No such rule, **or** it exists but belongs to someone else — deliberately the same answer, so a caller cannot probe which rule ids exist on other accounts. |
| 401 | `unauthenticated` | No session. |

## Stats (session auth)

<!-- route: GET /api/v1/stats -->
### `GET /api/v1/stats`

Session auth, no CSRF (a `GET`). The caller's own screen time, across
every device it owns, summed per UTC calendar day and
[category](#category-rules-session-auth). There is no admin variant
and no id parameter — same reasoning as `GET /api/v1/events`.

**Query parameters, both required:**

| Parameter | Meaning |
| --- | --- |
| `start_ts` | Inclusive start of the window, Unix seconds. |
| `end_ts` | Exclusive end of the window, Unix seconds. |

The window is `[start_ts, end_ts)`, same convention as
[`GET /api/v1/events`](#get-apiv1events), but wider: up to 366 days in
one request rather than 31. The response here is bounded by the
number of (day, category) combinations in the window, not by raw
event count, so it can afford to cover a full year.

```
GET /api/v1/stats?start_ts=1799990000&end_ts=1800000000
```

**`200 OK`:**

```json
{
  "days": [
    {
      "day_start_ts": 1799942400,
      "category": "Study",
      "total_duration_secs": 5400
    },
    {
      "day_start_ts": 1799942400,
      "total_duration_secs": 300
    }
  ]
}
```

Each entry is one (day, category) total. `category` is omitted when
it is the total for events that matched no rule — not a sentinel
string. **Sparse:** a day or category with nothing in it has no entry
at all, there is no zero-filled row. Ordered `day_start_ts` ascending,
then `category` ascending with the no-category entry last within its
day.

An event's whole duration counts toward the UTC calendar day its own
`start_ts` falls in, even one that runs past midnight — it is not
split across the boundary. Overlapping events — two devices covering
the same span, or one device reporting an app and a domain for the
same span — are summed exactly as reported, the same as
`GET /api/v1/events` hands them back unmerged; this endpoint does not
resolve that either.

**Failures:**

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `bad_request` | `start_ts` or `end_ts` missing, not a number, or an unknown query parameter was sent. |
| 400 | `invalid_stats_range` | `end_ts` is not strictly after `start_ts`, **or** the span between them is wider than this server allows in one request. |
| 401 | `unauthenticated` | No session. A device's bearer token does not substitute for one — this route does not accept it. |

## Admin endpoints

An admin sees device **metadata only** — id, owner, name, platform, and
the three timestamps. An admin has no way to read any user's events or
aggregated stats, by design and enforced by `tests/no_event_reads.rs`.

<!-- route: GET /api/v1/admin/devices -->
### `GET /api/v1/admin/devices`

Admin session auth, no CSRF (a `GET`). Every device on the instance,
any owner, revoked ones included.

**`200 OK`:**

```json
{
  "devices": [
    {
      "id": "0199…",
      "owner_id": "0199…",
      "owner_username": "alice",
      "name": "Alice's Laptop",
      "platform": "linux",
      "created_at": 1800000000,
      "last_seen_at": 1800003600,
      "revoked_at": null
    }
  ]
}
```

Ordered `d.created_at, d.id` ascending.

**Failures:** `403 forbidden` for a non-admin session; `401
unauthenticated` for no session.

<!-- route: POST /api/v1/admin/devices/{id}/revoke -->
### `POST /api/v1/admin/devices/{id}/revoke`

Admin session auth, CSRF required. Revokes any device on the instance,
regardless of owner. No request body.

**Responds with the owner's `DeviceView`, not `AdminDeviceView`** — the
same shape as `GET /api/v1/devices`' entries, with **no** `owner_id` or
`owner_username` in it. Easy to assume otherwise; it is not a superset
of the list response.

**`200 OK`:** the device, with `revoked_at` set. Same idempotency as
the owner-scoped revoke above: a second call answers the same `200`
with the same `revoked_at`.

**Failures:** `404 not_found`.
