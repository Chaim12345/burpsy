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
| `src/native.rs` | Where the two native (non-BCheck) checks hook into `PassiveScanner`, and their combined coverage |
| `src/js_vulns.rs` | SCAN-01: known-vulnerable JavaScript libraries, matched by real version-range arithmetic |
| `src/jwt_weak.rs` | SCAN-02: JWTs signed with a weak HMAC secret, proved by recomputing the signature |
| `data/retirejs_repository.json` | The retire.js corpus as shipped by Burp, `include_str!`-ed by `js_vulns.rs`. **Vendored — refresh from upstream, do not hand-edit** |

## For AI Agents

### `catalog_data.rs` is generated

5,775 lines of nested struct and raw-string literals. Edit `tools/gen_catalog.py` and regenerate;
hand-editing will be lost and will also produce an enormous, unreviewable diff. (A repo-wide
`cargo fmt` once rewrote 3,354 lines of this file with zero semantic change, which is what that kind of
literal does to a formatter.)

### The native checks are not BChecks and must not be put in `passive`

SCAN-01 needs version arithmetic over a 683-entry dataset and SCAN-02 needs HMAC computation over a
wordlist. Neither is expressible in the BCheck DSL, so neither can be parsed into a `Check` and
neither belongs in `PassiveScanner::passive`. They live in `native::NativeChecks`, are dispatched
from the same place in `scan_message`, and record through the same `record()` — the registration path
is shared, only the evaluation differs.

They are **off by default**. `PassiveScanner::with_native(NativeChecks::vendored())` turns them on.
A check that appeared silently would make every existing coverage figure in this crate wrong by one.

Both deliberately use Burp's exact catalogued issue names ("Vulnerable JavaScript dependency", "JWT
weak HMAC secret") so `enrich` attaches Burp's own remediation. That is why they must stay out of the
check vectors the `none_of_the_two_hundred_and_sixty_four_check_names_is_a_catalogued_issue` test
walks.

### Their honest-coverage states are the feature

`CoverageReport::native` carries them, so anything already serialising coverage gets them. Three
states exist specifically because their absence would read as a clean result:

- **SCAN-01 unavailable** — no dataset loaded, so nothing was examined. Not "no vulnerable libraries".
- **SCAN-01 undetermined** — a library was identified at a version that cannot be compared
  (`jquery-latest.min.js`), or its component has ranges this engine cannot evaluate. Reported as an
  `Info`/`Tentative` finding of its own, never silently dropped and never guessed in either direction.
- **SCAN-02 truncated** — the per-response HMAC budget stopped a token part-way through the wordlist.
  That token is `tokens_abandoned`, never `tokens_exhausted`. A truncated brute force reported as
  clean is the easiest defect to introduce here.

SCAN-02 additionally counts non-HMAC tokens (`RS*`, `ES*`, `none`) as out of scope *per algorithm*
rather than omitting them, and every negative result is stated relative to a named wordlist with its
exact entry count.

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

- Three coverage paths are kept deliberately separate (passive BChecks, the active audit, and the two
  native checks) and reported separately.
- Every refusal carries a `Disposition` naming why. A count without a reason is not acceptable output
  here.

## Dependencies

### Internal

- `burpsy-core` — the store, `Scope`, findings
- `burpsy-bcheck` — the check parser/evaluator and the `Sender` trait

### External

- `parking_lot`, `serde`, `serde_json`; `regex` (SCAN-01's extractor patterns, pinned per-crate the
  way `bcheck` pins it); `hmac` + `sha2` (SCAN-02's signature verification); `bytes` as a
  dev-dependency

Note: this crate has **no `tokio` dependency at all**, which is why there was nothing to narrow when the
egress work went through the workspace. Keep it that way.

<!-- MANUAL: -->
