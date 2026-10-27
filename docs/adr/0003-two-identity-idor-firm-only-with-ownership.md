# ADR 0003 — A two-identity IDOR cross-read is firm only with ownership evidence

- **Status:** Accepted
- **Date:** 2026-10-27
- **Context artefacts:** PR #363 review (`checks_idor.go:202`, `:224`), commits `dc1610ea`, `324fa6f0`

## Context

The two-identity check replays identity A's request under identity B's credentials. B being
served A's object, while the credential-stripped control is refused, proves only that the object
needs a login. A shared, login-only record (a product, an organisation, a team page) answers every
signed-in account the same way, and was being reported as high/firm broken object-level
authorization. Separately, the replay counted as "B's" even when A's own session cookie or a
credential header B had no value for rode through unchanged.

## Decision

1. **Coverage.** A replay is B's only when every cookie name in B's set was substituted and no
   credential header (`idorCredentialHeader`) is left carrying A's value. Otherwise the request is
   uncovered and nothing is reported.
2. **Ownership.** The cross-read is reported **firm** only when an owner field in A's object names
   the session's own user id (from A's JWT): `owner`, `sub`, `uid`, a person's id (`user_id`,
   `ownerId`, `customer_no`), or a bare `id`/`pk`/`uuid` under a person-named parent (`user.id`).
   The object's own primary key (`$.id`, `order.id`) and another object's id (`product_id`) are
   not ownership. Without such evidence the finding is **tentative**, and its text says the
   record may be one every signed-in account is meant to read.
3. A tentative cross-read does not stop the one-account probe; the stronger finding wins.
4. The same owner rule (`idorOwnerKey`) serves the cross-read and the one-account binding.

## Consequences

- Cookie-session targets, where no user id is readable, get tentative cross-reads. That is
  honest: a firm verdict there was never supported by evidence.
