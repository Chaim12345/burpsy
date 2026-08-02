<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-02 | Updated: 2026-08-02 -->

# session (`burpsy-session`)

## Purpose

Recorded-login re-authentication: scoped per target, bounded, collapsed, and honest about giving up.
Phase 5's goal is one sentence — a recorded login survives session loss automatically, on the
operator's own terms for what "valid" means, without looping forever — and each clause is a module.

## Session handling is a rule *list*, not one always-on macro

A real engagement has more than one login: an admin account and a user account, a staging host whose
form differs from production, an API subdomain that authenticates with a bearer token instead of a
cookie. "Which login applies here" is a property of the target, so `ReloginCoordinator` holds an
ordered list of `SessionRule`s, each with its own name, its own optional `Scope`, its own macro, its
own `ValidityRule` and its own retry bound. The first enabled rule whose scope covers a request
handles it; a request no rule covers is reported as `RecoveryOutcome::NoRuleApplies` rather than
quietly logged into with somebody else's credentials. A per-rule scope is a *selector*, never an
authorisation.

## A macro can carry values forward, not just cookies

`CookieJar` carries `Set-Cookie` state between steps. The other half of a real login flow is a value
the application expects echoed back — a CSRF token in a hidden field, a `state` parameter, a bearer
token in a JSON body. `Extraction` names one such value out of a step's response (regex capture
group, dotted JSON path, or whole header), and a later step writes `{{name}}` wherever it needs it.
That substitution is deliberately not a template language.

## Why sending is a trait, not a call into `burpsy_sender`

`MacroSender` exists for a reason with a name: HARD-03. A login macro is a request-originating
surface exactly like the crawler, plugins, or MCP. This crate is not where that authorisation wiring
happens — it defines the re-login *policy* against a trait, and the wiring in `cli`/`web` implements
that trait once, over an `AuthorisedSender`, so the one place a constructed request is allowed to
reach a socket stays the one place. Every test here runs against a fake `MacroSender` and never had
a path to a real socket.

## What "valid" means is not this crate's call

`ValidityRule` is the operator's stated rule, not a heuristic here. A 200 with a login form, a 302
to `/login`, and a 200 `{"error":"unauthenticated"}` are all failed sessions that no fixed
status-code check catches uniformly. `ValidityRule::evaluate` is the only thing that reads a response
and produces an answer — `Valid`, `Invalid`, or `Indeterminate`, which is never treated as `Valid`.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | The re-login policy contract; `MacroSender` trait |
| `src/coordinator.rs` | `ReloginCoordinator` — bounding, collapsing concurrent drops, `update_macro` repair |
| `src/rule.rs` | `SessionRule`; why per-rule scope is a selector, not authorisation |
| `src/step.rs` | Macro steps and the no-real-socket argument |
| `src/validity.rs` | `ValidityRule` — the operator's stated definition of a valid session |
| `src/cookie.rs` | `CookieJar` — per-host cookie carry-over |
| `src/extract.rs` | `Extraction` — `{{name}}` substitution, deliberately not a template language |
| `src/target.rs` | Target/scope application |

## Testing Requirements

```bash
cargo test -p burpsy-session    # 78 tests, all inline, against a fake MacroSender
cargo test --workspace
```

Tests must never reach a socket — by construction.

## Dependencies

### Internal

- `burpsy-core` — `Scope` (as a per-rule selector) and message/response types.

### External

- `bytes` — message bytes
- `parking_lot` — the coordinator's condvar/mutex collapse of concurrent session drops
- `regex` — pinned per-crate the way `tools`/`scanner` pin it, for step response matching
- `serde_json` — read-only, for `ExtractHow::JsonPath`; this crate derives no serde traits on its
  public types, the wire format stays `burpsy-web`'s business

No transport crates — sending is the trait's business, and `MacroSender`'s real implementation lives
in `cli`/`web`.

<!-- MANUAL: -->
