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

Retention does not exist yet — that is M4 — so an account's history has
no upper bound in rows or in age. Without *some* cap, one request could
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
