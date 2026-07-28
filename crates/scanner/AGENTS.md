<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# scanner (`burpsy-scanner`)

## Purpose

Passive BCheck scanning, an active audit engine, and Burp's shipped issue catalog transcribed.

Scanning happens **off the proxy's hot path**: the proxy hands over `(exchange_id, response_id)` and
returns to serving traffic immediately. Burp's own audit engine bounds work by *discarding* it
(`Zq5.LIMIT_EXCEEDED`), which is a symptom of coupling scan cost to request handling — a proxy that
gets slower as its check set grows is a proxy people turn off.

The bounding here is **admission-side**: work is refused before a request is built, and *counted*, so
the saving is visible rather than looking like checks that quietly stopped firing.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | `PassiveScanner`, the `audit` / `audit_within` / `audit_session` entry points, `AuditOutcome`, and the test doubles (`SlowSender`, `RecordingSender`, `FailingSender`) |
| `src/audit.rs` | The audit engine: seven dispatch scopes, the item state machine, admission-side bounding |
| `src/catalog.rs` | Burp's issue catalog — the 183 definitions behind `burp.Zcot` |
| `src/catalog_data.rs` | The transcribed catalog data. **Generated — do not edit by hand** (5.7k lines) |
| `tools/gen_catalog.py` | The generator that produces `catalog_data.rs` |

## For AI Agents

### `catalog_data.rs` is generated

5,775 lines of nested struct and raw-string literals. Edit `tools/gen_catalog.py` and regenerate;
hand-editing will be lost and will also produce an enormous, unreviewable diff. (A repo-wide
`cargo fmt` once rewrote 3,354 lines of this file with zero semantic change, which is what that kind of
literal does to a formatter.)

### Audit budgets are session-wide, not per exchange

`audit_session` shares one budget, ledger and set of circuit breakers across a batch. This is where the
bounding pays for itself: a `given host` check has one answer per host, so auditing 500 exchanges on
one host dispatches it once and attributes the other 499 as `AlreadyCovered`. Every skipped item still
comes back with its whole check set attributed to a reason — that attribution is the feature, not
bookkeeping.

`audit` (single, operator-triggered) is deliberately one-shot with a fresh ledger, so re-auditing the
same exchange really re-audits it. An operator who clicks audit again means it. Do not collapse scope
across single audits to "save work".

### The scope check no longer lives here

There used to be a crate-private `Metered` wrapper holding a `Scope` and checking it before delegating
to an injected `Sender`. That pattern was correct and has been promoted to
`burpsy_sender::AuthorisedSender`. The audit entry points still take `&dyn Sender`; callers are expected
to hand in an `AuthorisedSender`, and the CLI does. If you find yourself re-adding a scope check inside
this crate, that is the anti-pattern the chokepoint exists to remove — see `../sender/AGENTS.md`.

### Active scanning is never automatic

It is operator-triggered via `POST /api/audit/{id}`, because it sends traffic to the target. Making it
a side effect of browsing through the proxy would be a serious behaviour change, not an optimisation.

### Testing Requirements

```bash
cargo test -p burpsy-scanner     # 55 tests
```

Use the in-crate test doubles rather than a real socket. `RecordingSender` is how you prove a request
*was* built and dispatched; `FailingSender` and `SlowSender` cover the breaker and timeout paths.

### Common Patterns

- Two coverage paths are kept deliberately separate (passive and active) and reported separately.
- Every refusal carries a `Disposition` naming why. A count without a reason is not acceptable output
  here.

## Dependencies

### Internal

- `burpsy-core` — the store, `Scope`, findings
- `burpsy-bcheck` — the check parser/evaluator and the `Sender` trait

### External

- `parking_lot`, `serde`; `bytes` as a dev-dependency

Note: this crate has **no `tokio` dependency at all**, which is why there was nothing to narrow when the
egress work went through the workspace. Keep it that way.

<!-- MANUAL: -->
