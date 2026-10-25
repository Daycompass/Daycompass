# Design decisions

Not a reference for client implementations — that is `wire-format.md`.
This is the record of *why* a few things in this backend work the way
they do, for the decisions that are not obvious from reading the code
alone and that a future change should not casually undo.

## Why an admin no longer chooses a new account's password

Before M1d, `POST /api/v1/users` took a `password` field: an admin
creating an account picked its first password. That is the wrong shape
for software whose users include minors. An admin must be able to
*give* someone access without ever *having* it.

M1d replaces that with an invite token. An admin creates a pending
account and hands over the token once, in person or however the
instance's accounts are normally communicated. The person redeems it
and chooses their own password. The admin never sees the password,
because the admin never has a password to see — the account has none
until redemption.

## An admin can still reset a password — and that is not a contradiction

`POST /api/v1/users/{id}/password-reset` lets an admin reset any
account to pending, handing out a fresh invite in place of whatever
password it had. After the account redeems that invite, the admin
knows nothing about the new password either — but between the reset
and the redemption, an admin who is willing to intercept the invite
*could* redeem it themselves and then be logged in as that account.

That power cannot be removed without making a forgotten password
permanently unrecoverable, which is worse: an account with no admin
override and a forgotten password is an account nobody can ever get
back into. So the power stays, and the trade-off is made honest instead
of hidden: a reset is never silent. It writes a `password_reset_by_admin`
entry to the account's own log (`auth::account_log`, read back through
`GET /api/v1/account/log`), naming the acting admin's id and when it
happened. Only the account holder can read their own log — there is no
admin variant of that endpoint and no id parameter that could point it
at someone else's. If an admin resets an account and quietly logs in as
it, the account holder finds out the next time they look at their own
log, even though nothing stopped the admin from doing it.

This is the same shape of trade-off as "an admin can read the
database file directly": there is no technical control that can
prevent an operator with that level of access from impersonating an
account, short of removing their ability to administer at all. What
software *can* do is make the action visible after the fact rather
than pretending it cannot happen.

## A reset revokes every session and every device token

Resetting a password ends every session the account had and revokes
every device it had paired, in the same transaction as the reset
itself (`auth::store::reset_to_pending`). There is no window in which
the account is reachable by anything other than the invite just
issued.

The cost of this is real: a parent resetting a child's forgotten
password silently signs out every device the child was using, and each
one has to be paired again by hand afterwards. The response reports
how many sessions ended and how many devices were revoked, specifically
so the admin performing the reset is not surprised by it.

Events already reported by a revoked device are kept — revocation is
not deletion, here as everywhere else devices are revoked in this
backend.

## Why the invite TTL is 72 hours

The setup token that creates the very first admin lives for one hour,
which is far too short for an invite. A setup token is redeemed by the
same person who just read it off their own terminal; an invite is
handed over to someone else, often on a slip of paper, and commonly
redeemed at home that evening or the next day rather than on the spot.

A week would be a long life for a credential a minor is carrying
around on paper. 72 hours covers a weekend — handed out on a Friday,
still good on Monday — and nothing more. It is a default
(`DAYCOMPASS_INVITE_TTL_SECS`), not a fixed constant, so an instance
with different needs can change it.

## Why invite redemption keeps the `Origin` check

Every other route that authenticates by an unguessable secret in its
body rather than a cookie — setup, pairing — is exempt from the
`Origin` check, because the request carries no ambient cookie
authority in either direction. `POST /api/v1/invites/redeem` is the
same shape in that respect: it is `Access::BodySecret`, and it hands
back no cookie either.

It keeps the check anyway. Setup and pairing create something new —
the first admin, a device — where there is no existing state for a
cross-origin page to interfere with. Redeeming an invite changes the
password of an **account that already exists**, which is closer in
spirit to the login endpoint than to setup or pairing: both are the
moment ambient authority could be planted against a real account, even
though a redemption itself never sets a cookie. `RouteSpec::validate`
permits a `BodySecret` route to stay `Origin`-checked; only the
*exemption* is whitelisted, and this route deliberately does not claim
it.

## Why reading events back is a bounded window with a flag, not a cursor

`GET /api/v1/events` (`events::query::list_own`) requires both
`start_ts` and `end_ts`, caps how wide their span may be
(`MAX_RANGE_SECS`), and caps how many rows one response carries
(`MAX_ROWS`) independently of that span — a window across many devices
can still hold more rows than is reasonable to return at once. A
response that hit the row cap says so with `truncated: true` rather
than handing back a cursor to resume with.

Retention is off unless an operator configures it (M4), so an
account's history has no upper bound in rows or in age by default. Without *some* cap, one request could
ask the database to do an unbounded amount of work on a single SQLite
connection shared by the whole instance, which is a cost to everyone
else's requests, not just the caller's own. A cursor would let a client
walk an arbitrarily large result a page at a time, which is more
machinery than this first read needs: a client that sees `truncated:
true` narrows its own window and asks again, exactly as a client that
oversends to `POST /api/v1/events` splits its batch rather than being
handed a page token. Real pagination can be added later if a real use
ever needs it; until then, the extra state a cursor implies (what it
encodes, how long it stays valid, what happens if the underlying data
changes between pages) is complexity this endpoint does not have to
carry.

## Why the event read has no admin variant, and never gets one on this route

`GET /api/v1/events` takes no id parameter and resolves its caller from
the session alone (`crate::auth::extract::SessionContext`), the same
shape as `GET /api/v1/account/log`. An admin calling it sees their own
events, if they have any — never another account's, however many
accounts or devices that admin manages.

This is not an oversight waiting for an "admin view" to be added later.
"An admin manages accounts and devices but can never read another
user's events or stats" is a fixed design decision (see `CLAUDE.md`),
and the one case where an admin *can* end up seeing an account's data —
resetting its password and redeeming the invite themselves — is a
documented, logged trade-off (see "An admin can still reset a password"
above), not a second way to reach this endpoint. Any future admin-
facing view of usage would need its own explicit decision and its own
review, not a parameter bolted onto this route.

## Why the export streams keyset pages, and has no admin variant

`GET /api/v1/export` (`crate::export`) hands an account everything it
has, every event included, with no window and no row cap — unlike
`GET /api/v1/events` above, whose bounded window exists precisely so
one request cannot ask for unbounded work. The export cannot take that
way out: a download that a client has to stitch together from many
windowed requests is not an export, and unless an operator configures
retention (off by default) the history it has to cover is unbounded.

So the bound moves from *what* is read to *how*. The account, devices,
rules and log are small and read up front. Events follow in keyset
pages of 1,000 (`events::store::select_own_page_after`), and the next
page is read only when the client has taken the previous one, so:

- memory stays at roughly one page, however large the history — the
  whole document is never built, which `axum::Json` would have done;
- each page is a short query, and no pool connection is held while a
  slow client downloads — the same cost-to-everyone-else argument as
  above, answered by paging rather than by refusing;
- keyset rather than `OFFSET`, so the last page costs the same as the
  first.

The price is that the status line goes out before the events are read.
A database failure halfway through cannot become a 500 any more; it is
logged and the connection is cut, and the document's final field,
`"complete": true`, is never written. A client checks for it — that is
the whole error channel, and it is documented as such. The pages are
separate queries rather than one transaction, so the export is not a
snapshot either; events ingested while it runs may or may not appear,
but keyset order guarantees that none that existed beforehand is
repeated or lost. A snapshot would mean one read transaction held open
for the length of a download, which is the very cost paging avoids.

A per-session rate limit (3 per hour by default) bounds how often one
caller can ask for this most expensive of reads.

There is no admin variant for the same reason as the event read above:
the route takes no id, rejects every query parameter, and resolves its
account from the session alone. `tests/no_event_reads.rs` was
deliberately extended to allow it as the third owner read, not
widened. Events are exported without a category — categories are
assigned at query time, not stored — and the rules are exported
alongside so the file alone is enough to derive them again.

## Why retention is env-only, off by default, and never shorter than the ingest window

`DAYCOMPASS_RETENTION_DAYS` (`crate::events::retention`) deletes
events whose own `start_ts` is older than that many days, in the
existing hourly cleanup sweep. Four choices in it:

- **Env-only, not an admin setting.** Every other operational limit is
  env-only (`CLAUDE.md`), and a retention an admin could shorten
  through the API would be a way to destroy every account's history
  from a dashboard — a much bigger lever than anything else the admin
  role holds. An operator who can set environment variables can
  already do anything to the database.
- **Off by default.** Deleting a person's data is something an operator
  opts into, not a default they discover afterwards. The export
  (above) exists so an account can save its history whether or not
  retention is on.
- **Never shorter than `DAYCOMPASS_EVENT_MAX_AGE_SECS`.** A device may
  upload events up to that age; a shorter retention would accept an
  event and delete it at the next sweep. That combination is refused at
  startup rather than quietly honoured, the same way a session idle
  timeout longer than its absolute lifetime is.
- **Events only, by `start_ts`.** Retention is about how long a record
  of what somebody did is kept, so a backfilled event is as old as the
  moment it describes, not as the upload. Accounts, devices, category
  rules and the account log are not usage data and go only when the
  account does.

The delete is the one statement over `events` that is not scoped to an
account, because it is on nobody's behalf. That is why
`tests/no_event_reads.rs` allows exactly one such statement, selecting
by `start_ts` alone, and pins that it is reachable only from the
background sweep, never from a request. It runs in batches of 5,000 so
one sweep never holds SQLite's write lock long enough for ingest or a
login to notice, and migration `0006` adds an index on `start_ts` so a
sweep with nothing to delete costs an index probe, not a table scan.


## How the dashboard (M5) fits the existing protections

The dashboard is server-rendered HTML (askama) with htmx for writes.
It adds no new kind of protection and no second copy of an existing
one; every page route is an ordinary entry in `routes::INVENTORY`, and
the inventory walk in `tests/route_inventory.rs` covers it like any API
route.

- **A `surface` column, not a second router.** `Surface::Page` changes
  how a refusal is *shown* - an HTML page, an htmx fragment, or a 303 to
  `/login` for a plain page load without a session - and nothing about
  whether it happens. The status code survives the re-rendering. The
  surface follows the path (API under `/api/` plus `/healthz`, pages
  everywhere else) and `RouteSpec::validate` refuses an entry where it
  does not.
- **CSRF is the same header.** The layout puts the session's CSRF token
  into `hx-headers` on `<body>`, so every htmx request carries the same
  `X-CSRF-Token` the API checks, through the same `verify_csrf`. A
  hidden form field would have worked without JavaScript, but it would
  have meant a second CSRF path, and one that reads the request body in
  the access layer - which today runs, deliberately, before any body is
  read. The cost: writes on the dashboard need JavaScript. Reading
  does not, and the login form (no session, so no token) works as a
  plain form post, `Origin`-checked exactly like the API login.
- **One login budget.** `POST /login` and `POST /api/v1/auth/login`
  share one function (`routes::auth::attempt_login`) and the same two
  rate-limit buckets. A second set of buckets would have doubled what a
  password-guessing attack gets by alternating between the routes;
  `tests/dashboard.rs` pins that a refusal on one is a refusal on the
  other.
- **The dashboard's writes require an `Origin`.** The API allows a
  request with no `Origin` because native clients send none
  (`auth::origin`). `POST /login` and `POST /logout` have no such
  caller - only browsers, which always send the header on a POST - so
  they use `OriginRule::Required`, which refuses an absent header too.
  Login CSRF then no longer rests on every browser sending `Origin`.
  Only page routes may claim this rule; `RouteSpec::validate` refuses
  it on an API route, where it would lock out every native client.
- **A strict CSP on every response.** `default-src 'none'`, then
  `'self'` for scripts, styles, fonts, images and requests; no inline
  script or style anywhere, no framing, no `<base>`, forms post only
  here. htmx is configured to match (no `eval`, no inline indicator
  `<style>`) and with its history cache off, because a history snapshot
  is the page's HTML - CSRF token included - copied into
  `localStorage`. Bars on the overview are `<progress>` elements for
  the same reason: a sized `<div>` would need an inline style.
- **Pages are never cached; assets are revalidated.** Pages carry the
  CSRF token and the account's own numbers, so they stay `no-store`
  like the API. The global `Cache-Control` layer now sets `no-store`
  only where a handler set nothing, and the one handler that does set
  something is the asset route: `no-cache` with an `ETag`, so a browser
  keeps its copy and asks with `If-None-Match`. Asset URLs carry no
  version, which is why revalidation rather than a long `max-age`.
- **Assets are a table, not a directory.** Stylesheet, fonts, htmx and
  favicon are compiled in with `include_bytes!` and looked up by exact
  name, so no request ever touches the filesystem. htmx is vendored as
  `assets/vendor/htmx-2.0.11.min.js` (0BSD), checked against the npm
  registry's SHA-512 when it was added. Fredoka and Nunito are under the
  OFL, whose text is served next to them.
- **Not in the wire format.** Dashboard routes answer browsers, not
  clients, so they are neither in `docs/wire-format.md` nor in the
  OpenAPI spec; both tests filter on `Surface::Api`.
- **Days are UTC.** The overview shows what `GET /api/v1/stats`
  computes, and that is UTC calendar days. The page says so. A
  per-account time zone is a separate decision.
