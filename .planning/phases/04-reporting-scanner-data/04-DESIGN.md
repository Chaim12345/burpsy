# Phase 4 — Reporting & Scanner Data: design

**Requirements**: REPORT-01, REPORT-02, REPORT-03, REPORT-04, SCAN-01, SCAN-02, SCAN-03
**Design around**: success criterion 3 — *a zero-finding report still enumerates what did not run and
why, including the 26 Collaborator-gated checks, so a clean report cannot be mistaken for full
coverage.*

Claims are marked `[VERIFIED: how]` or `[ASSUMED]`. Nothing about an external format or an external
consumer is asserted from memory; where it matters and could not be checked, this says what needs to be
true and flags it. Out of scope: HTTP/2 (Phase 2, in parallel), crawling (Phase 6), DOM (Phases 11–12).

---

## 1. Where report generation lives

**Decision: a new crate, `crates/report` (`burpsy-report`), depending on `core` and `scanner`, depended
on by `cli` alone.**

```
core ──► bcheck ──► {scanner, sender} ──► proxy ──► web ──► cli
                        │                                    ▲
                        └──►  report  ──────────────────────►─┘
```

Tenth workspace crate, so it needs an entry in the root `Cargo.toml` `members` list — cargo does not
discover it otherwise — and its own `AGENTS.md`, since the hierarchy is one per crate [VERIFIED:
`crates/AGENTS.md` "Adding a crate"; root `AGENTS.md:40-49`].

**Not `core`.** The coverage model must name `Disposition`, `ItemState` and `LoadReport` by type, and
those live in `scanner` [VERIFIED: `crates/scanner/src/audit.rs:159-178`, `:235-255`;
`crates/scanner/src/lib.rs:62-74`]. Putting reporting in `core` means either dragging the audit engine's
vocabulary into the crate that must depend on nothing [VERIFIED: `crates/core/AGENTS.md` "must stay that
way"], or re-declaring it there — a parallel mechanism, which is what REPORT-04 must not be built on.

**Not `scanner`.** `proxy` depends on `scanner` [VERIFIED: `crates/proxy/src/lib.rs:75`], so a SARIF
writer and an HTML page in `scanner` become transitive baggage on the hot path. `scanner` also has no
`serde_json` and, deliberately, no `tokio` [VERIFIED: `crates/scanner/Cargo.toml`;
`crates/scanner/AGENTS.md` "Keep it that way"]. A crate boundary here is a statement about what a
component may not reach [VERIFIED: `crates/AGENTS.md` Purpose]: `scanner` is detection, and presentation
has a different failure mode — a bug produces a misleading document, not a missed vulnerability.

**The split.** Facts stay where they are produced; composition and rendering move out.

| Stays in `scanner` | Moves to `report` |
|---|---|
| `PassiveOutcome` / passive disposition counters (§2) | `CoverageReport` composition, zero-finding verdict |
| Retained identities for the not-loaded buckets | JSON / HTML / SARIF writers |
| `ConfigLoadReport` (it decides `AuditConfig`) | Rendering the unmapped-settings list |
| SCAN-01 / SCAN-02 checks and their budget accounting | — |

**`web` gains no dependency on this.** `crates/web` must not depend on `burpsy-scanner`; it takes an
`AuditHook` closure so the binary owns the wiring [VERIFIED: `crates/web/src/lib.rs:37-48`;
`crates/cli/src/main.rs:244-263`]. `report → scanner`, so `web → report` would smuggle that edge in.
The download endpoint therefore reuses the pattern rather than working around it:

```rust
pub type ExportHook = Arc<dyn Fn(ExportFormat) -> Result<Export, String> + Send + Sync>;
pub struct Export { pub mime: &'static str, pub filename: String, pub bytes: Vec<u8> }
pub enum ExportFormat { Html, Json, Sarif }   // plain data, owned by `web`
```

New route area `crates/web/src/routes/report.rs`, declared in `mod.rs` and merged in `all()` — and
specifically *not* an edit to `web/src/lib.rs`'s route table, which is the collision that layout removes
[VERIFIED: `crates/web/src/routes/mod.rs:17-23`; `crates/web/src/routes/AGENTS.md`].

The alternative worth naming and rejecting: make `report` depend only on `core` and inject coverage facts
as generic data, letting `web` depend on it directly. That buys one endpoint's convenience and costs the
type-level link to `Disposition` — reasons would become stringly-typed and could drift from the engine's
actual dispositions without a compile error.

---

## 2. The coverage model for REPORT-04

This is the phase. Everything else renders it.

### What exists, and precisely what it lacks

`LoadReport` has `files`, `passive`, `active`, `needs_insertion_point`, `collaborator`, `errors`, and
`summary()` [VERIFIED: `crates/scanner/src/lib.rs:62-95`]. A corpus test pins `collaborator == 26` and
asserts the four buckets sum to `files == 264` [VERIFIED: `:1666-1689`]. `AuditOutcome` carries nine
disposition counters with the identity `considered() == active.len()` whenever the item was dispatched,
enforced by `debug_assert_eq!` [VERIFIED: `:515-519`, `:704-717`]. That is the substrate; build on it.

**The gap is a tense mismatch.** `LoadReport` describes what was **loaded**. REPORT-04 asks what was
**checked**. A check can sit in the `active` bucket — parsed, runnable — and never once have been
dispatched at a given target. Five concrete holes:

1. **Passive scanning records no dispositions.** `scan` returns a bare `usize` of findings [VERIFIED:
   `:203`] and `scan_message` swallows evaluator errors — `let Ok(found) = run_passive(check, &ctx) else
   { continue; }` [VERIFIED: `:233-235`]. A passive check that errors on every response (a Java-only
   regex is the named case) is invisible: counted as *runnable* in `LoadReport.passive`, contributing
   nothing, with no counter anywhere. The 105 is a load-time claim no run-time evidence backs.
2. **The scanned population is not recorded.** `scan` returns `0` early for an empty check set, a missing
   exchange, an out-of-scope host, and a missing response [VERIFIED: `:203-217`] — all four
   indistinguishable from "scanned, found nothing".
3. **Nothing knows whether an audit ever ran.** Active audit is operator-triggered per exchange
   [VERIFIED: `crates/scanner/AGENTS.md`; `crates/cli/src/main.rs:241-243`]. A `FindingStore` with zero
   findings looks identical whether 127 active checks ran clean or nobody clicked audit. **This is
   success criterion 3's core failure.**
4. **The not-loaded buckets keep counts, not identities.** `build()` increments `collaborator` /
   `needs_insertion_point` and drops the check [VERIFIED: `:149-164`]. The report can say "26" but not
   *which* 26 — and a number is not a statement of what was not checked.
5. **`AlreadyCovered` is classified inconsistently.** `Disposition::AlreadyCovered.stopped_looking()` is
   `true` [VERIFIED: `crates/scanner/src/audit.rs:188-193`] while `ItemState::completed_audit`
   deliberately counts scope collapse as audited, because doing otherwise "would make the saving look
   like a coverage regression" [VERIFIED: `:263-275`]. Both are right in their own frame; a report must
   pick one and say why.

### The structure

One type in `burpsy-report`, three populations, one explicit unknowns list.

```rust
pub struct CoverageReport {
    pub generated_unix_ms: u64,
    pub scope: ScopeStatement,     // a coverage claim is meaningless without its scope
    pub corpus: CorpusCoverage,    // BCheck corpus: LoadReport + retained identities
    pub native: NativeCoverage,    // SCAN-01/02 — a sibling population, not a wider LoadReport
    pub passive: PassiveCoverage,  // what the passive path actually did, per check
    pub active: ActiveCoverage,    // audit-engine dispositions, aggregated across items
    pub unknowns: Vec<Unknown>,    // present so they are not rendered as zero
}
```

The load-bearing primitive is a per-check verdict whose **default is not "ran"**:

```rust
pub enum CheckStatus {
    Ran { dispatches: usize },              // the only status under which "no finding" is evidence
    CoveredElsewhere { unit: String },      // AlreadyCovered, resolved within this report
    NotChecked(NotCheckedReason),           // reason mandatory and typed
    Unknown { because: &'static str },
}

pub enum NotCheckedReason {
    NotLoaded(LoadBucket),                        // Collaborator / insertion point / parse error
    NotDispatched(burpsy_scanner::Disposition),   // the existing enum, not a copy
    NeverRun(NeverRunReason),                     // new: loaded, runnable, never reached
}

pub enum NeverRunReason {
    NoAuditRequested,             // hole 3
    NoRespondingExchange,         // hole 2
    HostOutOfScope,
    PassiveRuntimeError(String),  // hole 1, with the evaluator's message
    BudgetSpent(BudgetKind),      // SCAN-02's HMAC budget, §7
    DisabledByConfig(String),     // SCAN-03 turned it off; names the config
}
```

**Construction starts with every check at `NotChecked(NeverRun(NoAuditRequested))` and promotes as
evidence arrives.** A check no instrumentation mentions therefore reports as unchecked, not clean.
Inverting that default is the whole design: a builder that starts from "ran" and demotes on failure
behaves identically on the happy path and wrongly on every path that matters.

### The invariant that makes it checkable rather than asserted

Mirroring the two identities already in the tree — `LoadReport`'s four-bucket sum [VERIFIED: `:1682-1686`]
and `considered() == active.len()` [VERIFIED: `:515-519`] — each population carries its own tested sum:

```
for each population P:   |Ran| + |CoveredElsewhere| + |NotChecked| + |Unknown| == P.total
corpus: passive.total + active.total + |collaborator| + |needs_insertion_point| + |unparsable| == files
```

Same discipline one level up, and the reason to build on `LoadReport` rather than beside it: `LoadReport`
stays a report about **files** and keeps its 264/105/127/6/26 test untouched. Do not widen it to hold
native checks (§6).

### Resolving `AlreadyCovered`

`CoveredElsewhere` is a distinct status because the honest answer depends on report boundaries. Within
one `SessionOutcome` the refusal is genuinely covered: the ledger holds one exact bit per `(dispatch
unit, check)` — not probabilistic, because "a silently skipped check in a security scanner is a false
negative nobody can see" [VERIFIED: `crates/scanner/src/audit.rs:457-492`] — so the covering dispatch
provably happened in the same run. The report resolves which unit admitted it and counts it as coverage.
When the covering dispatch is *not* in this report — outcomes partly discarded, or a report built from a
single-exchange `audit()` with a fresh ledger [VERIFIED: `:287-305`] — resolution fails and the status
becomes `Unknown { because: "refused as already covered, but the run that covered it is not in this
report" }`. Never silently `Ran`.

### What is genuinely unknowable, and must be `Unknown` rather than zero

Structural, not gaps to close later. Stated every time:

- **Whether the loaded corpus is the current published corpus.** `LoadReport.files` counts `.bcheck`
  files under the directory it was given [VERIFIED: `:117-138`]; the tool cannot know what PortSwigger
  publishes today. The report says "264 files loaded from `<dir>`", and any percentage-of-published claim
  cites the pinned expected total as a stated assumption. The crate header's 264 and 87.9% [VERIFIED:
  `:14-23`] must read as *corpus-as-loaded*, not *corpus-as-published*.
- **Whether the traffic in the store represents the application.** Site coverage is not computable from a
  proxy's history. Report requests, hosts and paths seen — never "the application was covered".
- **What a check would have found on a response never captured.** Same reason.
- **Whether a `SendFailed` target is clean.** No: the check never saw its own probe [VERIFIED:
  `crates/scanner/src/audit.rs:200-202`]. Not-checked, never clean.
- **Whether SCAN-01's vulnerability data is current** (§6).

### The zero-finding verdict

Derived, not stored, so it cannot disagree with the counters it summarises:

```rust
pub enum ZeroFindingVerdict {
    CheckedAndClean { checks: usize, responses_scanned: usize },
    PartiallyChecked { checked: usize, not_checked: usize, unknown: usize },
    NothingChecked,   // a report in this state must not contain the word "clean"
}
```

For the shipped corpus without Collaborator, `CheckedAndClean` is **unreachable** — 26 checks are always
`NotChecked(NotLoaded(Collaborator))` [VERIFIED: pinned at `:1681`]. That is correct, and the report says
it in those words rather than showing 92% and letting the reader round up. All three writers render this
verdict; HTML puts it above the findings table.

---

## 3. SARIF conformance (REPORT-03)

**Version: SARIF 2.1.0** — the OASIS-standardised version and the only one GitHub Code Scanning accepts
[ASSUMED: from GitHub's published documentation; not verified here]. Emit `"version": "2.1.0"` and a
`$schema` pointing at the 2.1.0 schema.

Populated: `runs[].tool.driver.{name,version,informationUri,rules[]}`; `results[].ruleId`, `.level`,
`.message.text` (from `Finding::detail`, or the check name when absent),
`.locations[].physicalLocation.artifactLocation.uri` (the target URL of the first occurrence),
`.partialFingerprints["burpsyDedupKey/v1"]` (a hash of `Finding::dedup_key()`, which already exists for
exactly this purpose [VERIFIED: `crates/core/src/findings.rs:100-107`]), `.occurrenceCount` from
`times_seen`, `.properties.confidence`; `runs[].automationDetails.id`; and
`runs[].invocations[0].toolExecutionNotifications[]` for the coverage statement. `region` is **omitted**
— no line numbers exist and fabricating line 1 would be an invented location.

### Severity and confidence, and what is lost

`Severity` is `Info | Low | Medium | High` [VERIFIED: `crates/core/src/findings.rs:22-28`]; SARIF `level`
is `none | note | warning | error`.

| burpsy | `level` | `properties["security-severity"]` |
|---|---|---|
| `High` | `error` | `"7.0"` |
| `Medium` | `warning` | `"5.0"` |
| `Low` | `note` | `"3.0"` |
| `Info` | `note` | `"0.0"` |

**Lost:** `Low` and `Info` collapse onto `note`, and GitHub's bands put `3.0` and `0.0` together
[ASSUMED: critical ≥9.0, high 7.0–8.9, medium 4.0–6.9, low <4.0; from documentation, unverified here].
Consequence: **Info findings are excluded from SARIF by default**, with the excluded count in the
coverage notification and an opt-in `--sarif-include-info`. An informational finding rendered as a
low-severity security alert is a misrepresentation; dropping it silently is worse; dropping it with a
count is right.

`Confidence` has no SARIF equivalent. `reportingDescriptor.properties.precision` is a *rule* property and
burpsy's confidence is per-finding, so it does not fit; `result.rank` is priority, not confidence, and
using it as one would be a misuse. Decision: carry confidence verbatim in `result.properties.confidence`
and set `rank` from a stated severity×confidence formula documented as *priority*. **Lost:** no
mainstream consumer, GitHub included, surfaces `properties.confidence` — a `Tentative` and a `Certain`
finding look identical in the GitHub UI. The coverage notification says so in one sentence, because a
consumer who does not know it will treat every alert as firm.

### Rule ids and the `rules[]` array

`burpsy/bcheck/<slug(check_name)>`, `burpsy/native/js-vulnerable-dependency`,
`burpsy/native/jwt-weak-hmac-secret`, plus `properties.burpIssueTypeIndex` when the issue name is an
exact catalog match. Rule ids must be stable or GitHub closes old alerts and opens new ones; a check name
is the only stable identifier a BCheck has, so **an upstream BCheck rename re-opens its alerts** —
unavoidable, and stated rather than discovered.

Rule metadata comes from Burp's catalog on an exact name match: `fullDescription` from
`description_text()`, `help.text` from `remediation_text()`, `properties.tags` as `["security",
"external/cwe/cwe-89", …]` from `cwe_ids()` [VERIFIED: `crates/scanner/src/catalog.rs:99-121`]. For the
published corpus that is **never** — no BCheck name matches any of the 183 catalogued issues, measured
and pinned [VERIFIED: `crates/scanner/src/lib.rs:1751-1772`]. Corpus rules therefore ship with a name and
no help text, and that absence stays visible; inventing prose to fill it is the failure the catalog
module exists to prevent [VERIFIED: `crates/scanner/src/catalog.rs:11-17`].

**`rules[]` lists only checks that ran or produced results.** Declaring all 264 with zero results would
present the tool's capability as a clean bill of health for each — the exact ambiguity REPORT-04 removes.
The not-run set goes in notifications, where it cannot be read as a clean rule.

### Carrying REPORT-04 into SARIF

SARIF has no standard "this rule did not run" marker.

| Option | Pros | Cons |
|---|---|---|
| A. `toolExecutionNotifications` + `runs[].properties.coverage` | Standard, round-trippable, cannot be mistaken for a finding | Not in GitHub's alert list; a gate reading only alerts sees nothing |
| B. `invocations[0].executionSuccessful = false` | Strong, visible | The tool did not fail; GitHub's handling of a failed invocation is unverified and may reject the run |
| C. A `note` result against `burpsy/coverage-incomplete` | Visible in the alert list | Manufactures a finding about the scan; pollutes alerts |

**Default A; opt-in `--sarif-coverage-alert` adds C.** B is rejected: `executionSuccessful` describes
whether the tool ran, and reporting a successful bounded scan as a failed invocation is a different lie
from the one being avoided. C is not the default because a fabricated result is the one thing this
project's reporting must never do; it exists because some CI gates read only alerts, and an operator who
selects it knows what they are selecting.

### The real conformance risk: locations

burpsy findings are about HTTP endpoints; GitHub annotates **source files** relative to the repo root. A
finding at `https://host/path` has no repository file, and SARIF needs an artifact URI for a result to be
displayable. **What needs to be true:** GitHub must ingest results whose `artifactLocation.uri` is an
absolute `https:` URL absent from the repository, and surface them as alerts rather than dropping them.
DAST tools publish SARIF this way [ASSUMED], but GitHub's current behaviour could not be verified from
this environment and there is a known class of behaviour where unresolvable paths are filtered from the
PR view. **Highest-risk unknown in the phase; verify before S4, not after.** Fallback if it fails:
`--sarif-path-prefix` mapping a URL onto an operator-named repository path, default off, with the mapping
stated in the report.

### How "GitHub ingests it unmodified" gets verified

A claim about an external consumer is not self-assessable.

**Offline, in `verify.sh`:** vendor the SARIF 2.1.0 schema into `crates/report/tests/data/` recording its
source URL and fetch date (the `gen_catalog.py` provenance precedent [VERIFIED:
`crates/scanner/tools/gen_catalog.py:1-20`]); validate against it with
`crates/report/tools/validate_sarif.py`, **skipped with a printed message when `jsonschema` is absent**,
never silently passing — there is no SARIF or JSON-schema crate in the workspace [VERIFIED: all
manifests] and adding one for a test-only need is a poor trade; plus a Rust test asserting the required
property set directly, so conformance does not hinge on an optional Python module. Both a zero-finding
and a populated run must validate.

**Not offline, and must be said plainly:** actual ingestion needs a real repository, a token with
`security_events` scope, `POST /repos/{o}/{r}/code-scanning/sarifs`, and polling for processing status.
That cannot run in this repo's CI. **It is a documented manual gate**, recorded in the phase's validation
notes with date, burpsy version and API response, verified once per release. Anything stronger would be a
claim about someone else's service that the gate cannot back.

To state in the export's own coverage section [ASSUMED, from documentation]: GitHub's limits of 5,000
results per run, 25 MB gzipped upload, 20 runs per file. Exceeding 5,000 truncates **with the truncated
count in the notification**, never silently.
