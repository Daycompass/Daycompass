# Wire format: pairing, device auth, and event ingest

Reference for client implementations. This describes the M2 endpoints
only — pairing a device, authenticating as one, and reporting events.
There is deliberately **no way to read events back** in M2.

Everything here is normative for the server as it stands. The
authoritative definitions live in the code (`src/routes/`,
`src/events/validate.rs`); this file exists so client repositories have
something to read without following Rust.

## Conventions

- All timestamps are **integer Unix seconds, UTC**.
- All request and response bodies are `application/json`.
- Request bodies reject unknown fields. A stray or misspelled field
  fails the whole request — it is never silently ignored.
- Errors share one shape:

  ```json
  { "error": { "code": "invalid_pairing_code", "message": "the pairing code is not valid" } }
  ```

  Branch on `code`, which is stable. `message` is for humans and may be
  reworded. Neither ever echoes back what you sent.

## Authentication

Two kinds of caller, which are never interchangeable.

| | Session (dashboard) | Device (native client) |
| --- | --- | --- |
| Credential | `__Host-sws` cookie | `Authorization: Bearer swd_…` |
| CSRF | `X-CSRF-Token` required on writes | not applicable |
| `Origin` | checked on writes | not checked |

A device route **rejects** any request carrying the `__Host-sws`
cookie, even one that also presents a valid token. A session route
rejects any request carrying a `Bearer` credential. Do not send both.

The `Bearer` scheme name is matched case-insensitively.

---

## Pairing

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

### `POST /api/v1/pair`

**No authentication.** No `Origin` check, no CSRF. This is the one
endpoint a brand-new client calls.

```json
{
  "pairing_code": "4K7M9-QRT2V",
  "device_name": "Mika's Laptop",
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
  "device_token": "swd_…",
  "device": {
    "id": "0199…",
    "name": "Mika's Laptop",
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

### `GET /api/v1/device/me`

Device auth. Confirms identity and reports the server's clock.

```json
{
  "id": "0199…",
  "name": "Mika's Laptop",
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
Screenwarden device on the network too. On a school or household NAT
that means one misconfigured client taking out its neighbours.

The correct response to a 401 is to stop making device requests, keep
whatever is buffered, and surface a "this device needs to be paired
again" state to the person using it. Pairing again issues a new token.

If you retry at all, retry once, well after a long delay — not on a
sync interval.

---

## Device management (session auth)

These are dashboard endpoints, listed here only so a client knows what
a person can do to it.

| Endpoint | Effect |
| --- | --- |
| `GET /api/v1/devices` | The caller's own devices, revoked ones included. |
| `PATCH /api/v1/devices/{id}` | Rename. Body: `{"name": "…"}`. |
| `POST /api/v1/devices/{id}/revoke` | Revoke. Idempotent. |

Revoking is **not** deleting: the device row and every event it reported
are kept. A revoked device's token stops working on its very next
request, with nothing cached in between — expect `401 unauthenticated`
and stop retrying. A revoked device cannot be un-revoked; pair again.

A revoked device is indistinguishable from an unknown one in the
response. Do not try to tell them apart.

## Admin endpoints

`GET /api/v1/admin/devices` and
`POST /api/v1/admin/devices/{id}/revoke`.

An admin sees device **metadata only** — id, owner, name, platform, and
the three timestamps. An admin has no way to read any user's events, by
design and enforced by tests.
