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

`CoveredElsewhere` is a distinct status because the honest answer depends on report boundaries. Within one
`SessionOutcome` the refusal is genuinely covered: the ledger holds one exact bit per `(dispatch unit,
check)`, not probabilistic, because "a silently skipped check in a security scanner is a false negative
nobody can see" [VERIFIED: `crates/scanner/src/audit.rs:457-492`] — so the covering dispatch provably
happened in the same run, and the report resolves which unit admitted it. When that dispatch is *not* in
this report (outcomes partly discarded, or a report built from a single-exchange `audit()` with a fresh
ledger [VERIFIED: `:287-305`]) resolution fails and the status becomes `Unknown`, never silently `Ran`.

### What is genuinely unknowable, and must be `Unknown` rather than zero

Structural, not gaps to close later. Stated every time:

- **Whether the loaded corpus is the current published corpus.** `LoadReport.files` counts `.bcheck`
  files under the directory given [VERIFIED: `:117-138`]; the tool cannot know what PortSwigger publishes
  today. The report says "264 files loaded from `<dir>`"; any percentage-of-published claim cites the
  pinned total as a stated assumption. The crate header's 264 and 87.9% [VERIFIED: `:14-23`] must read as
  *corpus-as-loaded*, not *corpus-as-published*.
- **Whether the traffic in the store represents the application**, or what a check would have found on a
  response never captured. Site coverage is not computable from a proxy's history: report requests, hosts
  and paths seen, never "the application was covered".
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

Ids: `burpsy/bcheck/<slug(check_name)>`, `burpsy/native/js-vulnerable-dependency`,
`burpsy/native/jwt-weak-hmac-secret`, plus `properties.burpIssueTypeIndex` on an exact catalog match. Ids
must be stable or GitHub closes old alerts and opens new ones; a check name is the only stable identifier a
BCheck has, so **an upstream BCheck rename re-opens its alerts** — unavoidable, and stated rather than
discovered. Metadata comes from Burp's catalog on an exact name match (`fullDescription` from
`description_text()`, `help.text` from `remediation_text()`, `properties.tags` as
`["security", "external/cwe/cwe-89", …]` from `cwe_ids()` [VERIFIED:
`crates/scanner/src/catalog.rs:99-121`]) — which for the published corpus is **never**, since no BCheck
name matches any of the 183 catalogued issues [VERIFIED: `crates/scanner/src/lib.rs:1751-1772`]. Corpus
rules therefore ship with a name and no help text, and that absence stays visible; inventing prose to fill
it is the failure the catalog module exists to prevent [VERIFIED: `crates/scanner/src/catalog.rs:11-17`].

**`rules[]` lists only checks that ran or produced results.** Declaring all 264 with zero results would
present capability as a clean bill of health for each — the exact ambiguity REPORT-04 removes. The not-run
set goes in notifications, where it cannot be read as a clean rule.

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

**Offline, in `verify.sh`:** vendor the SARIF 2.1.0 schema into `crates/report/tests/data/` with its
source URL and fetch date (the `gen_catalog.py` provenance precedent [VERIFIED:
`crates/scanner/tools/gen_catalog.py:1-20`]); validate against it with `tools/validate_sarif.py`,
**skipped with a printed message when `jsonschema` is absent**, never silently passing — no SARIF or
JSON-schema crate exists in the workspace [VERIFIED: all manifests] and adding one for a test-only need is
a poor trade. Plus a Rust test asserting the required property set directly, so conformance does not hinge
on an optional Python module. Both a zero-finding and a populated run must validate.

**Not offline, and must be said plainly:** actual ingestion needs a real repository, a token with
`security_events` scope, `POST /repos/{o}/{r}/code-scanning/sarifs`, and polling for processing status.
That cannot run in this repo's CI. **It is a documented manual gate**, recorded in the phase's validation
notes with date, burpsy version and API response, verified once per release. Anything stronger would be a
claim about someone else's service that the gate cannot back.

Also stated in the export's coverage section [ASSUMED, from documentation]: GitHub's limits of 5,000
results per run, 25 MB gzipped upload, 20 runs per file. Exceeding 5,000 truncates **with the truncated
count in the notification**, never silently.

---

## 4. HTML output (REPORT-01)

**Decision: one self-contained file, hand-rolled, with zero JavaScript.**

No templating dependency. The project already hand-rolls its single-page UI as a raw string literal
[VERIFIED: `crates/web/src/lib.rs:756-760`, `const UI: &str = r#"<!doctype html>…`] and hand-rolls
HTML-to-text over a closed tag set rather than pretending to be a parser [VERIFIED:
`crates/scanner/src/catalog.rs:204-238`]. A template engine's auto-escaping is exactly the control you
must not take on trust for this data, and taking a dependency to get a guarantee you must then audit
anyway is the worse trade.

### Escaping is a security control here, not formatting

`Finding::detail` is interpolated from response content by the check that reported it, and
`Occurrence.path` is a request target [VERIFIED: `crates/core/src/findings.rs:62-85`]. Rendering either
unescaped is a stored-XSS vector in the operator's own browser, typically from a `file://` origin — the
most privileged context they have. Two controls, structural first:

1. **No finding-derived byte reaches a dangerous context.** All finding data is emitted as element text
   content: never in an attribute value, `<script>`, `<style>`, URL position, or comment. Enforced by
   shape — one `push_text(&mut out, s)` helper is the only function permitted to emit finding-derived
   bytes and it always escapes; attribute values are built solely from tool-controlled constants and
   integers.
2. **`escape_text` escapes five characters: `& < > " '`.** The existing UI's `esc` escapes only three
   [VERIFIED: `crates/web/src/lib.rs:847`, `.replace(/[&<>]/g, …)`], which is safe *only* because it
   never lands in an attribute there. A report writer that inherits the three-character version and then
   puts a finding string in a `title=` attribute has an XSS. Five costs nothing and decouples the escape
   set from the emission site.

Defence in depth, not the primary control: `<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; style-src 'unsafe-inline'">` — free, and it fails closed if control 1 is ever
violated. Zero JavaScript is what makes control 2 sufficient *by construction*: with no script context
there is no context the five-character escape can be escaped from. **Lost:** client-side sort, filter and
search — recovered where it matters, since `FindingStore::all()` already returns findings
most-severe-first, then by confidence, then frequency [VERIFIED: `crates/core/src/findings.rs:204-213`],
with `<details>` for per-finding collapse and `#id` anchors for a severity jump list. An operator needing
real filtering uses the JSON export.

### A large finding set

Three bounds, each with stated numbers rather than a silent trim. Findings are deduplicated in storage, so
the count is bounded by distinct `(check, issue name, host)` rather than by traffic volume, and
occurrences are already capped at `MAX_OCCURRENCES = 50` while `times_seen` keeps the true count
[VERIFIED: `crates/core/src/findings.rs:87-93` and the test at `:331-347`] — HTML renders both ("50 of
1,204 occurrences shown"). `detail` is truncated at `--report-detail-bytes` (default 4,096) with the
marker "… 4,096 of 91,203 bytes shown". Above a finding-count threshold the detail blocks render
collapsed; the bytes are still in the file.

Layout order, deliberately: coverage verdict → severity counts (`severity_counts()` returns
`[high, medium, low, info]` [VERIFIED: `:228-240`]) → what was not checked and why → findings. A reader
who stops after the first screen must have seen the coverage statement.

---

## 5. JSON output (REPORT-02)

**Decision: a separate versioned export shape — not `Finding`'s internal `serde` representation.**

`Finding` derives `Serialize` and is already returned raw by the web API [VERIFIED:
`crates/core/src/findings.rs:69`; `crates/web/src/lib.rs:219` `"findings": g.all()`]. Reusing it for a
file export works on day one and is a trap after:

- **`Occurrence.response` is a `MsgId`** [VERIFIED: `crates/core/src/findings.rs:61-66`] — an index into
  *this process's* store, meaningless externally and different between captures. An export must resolve it
  or omit it, not publish an integer that looks like an identifier.
- **The `#[serde(default)]` convention in `core` exists for reading old captures**, not for a published
  contract [VERIFIED: `crates/core/AGENTS.md`]. Different compatibility problems, opposite directions.
- An accidentally-stable internal shape means every field rename in `Finding` breaks somebody's
  downstream script, discovered by them rather than by us.

```rust
pub struct Document {
    pub schema_version: u32,      // 1 — bumped deliberately, never implicitly
    pub generated_at: String,     // RFC 3339
    pub tool: Tool,
    pub scope: ScopeStatement,
    pub coverage: CoverageReport, // §2 in full, not a summary
    pub findings: Vec<ExportFinding>,
}
```

`ExportFinding: From<&Finding>` names every field explicitly and resolves occurrences to
`{ exchange_id, method, url, status }`. **The cost, stated:** the field list is now duplicated, so a new
`Finding` field can silently fail to reach the export. Mitigation is the same trick as the corpus sum
test — a test asserting the **exact set of top-level JSON keys**, plus a module-doc exclusion list naming
every `Finding` field deliberately not exported and why. A rename then fails a test whose message says
what it means, which is the house style [VERIFIED: root `AGENTS.md`].

This is also the reference serialisation of `CoverageReport`: HTML and SARIF are renderings, this is the
data, so it is the format REPORT-04 is tested against.

---

## 6. SCAN-01 — vulnerable JavaScript libraries by version

**Data source.** The de-facto corpus is Retire.js's `jsrepository.json` [ASSUMED: not fetched or
inspected in this environment]. **Two things must be checked and recorded before implementation, not
assumed: its licence terms for vendoring, and its actual schema.** If the licence is unsuitable, the
fallback is OSV/GHSA keyed by npm package name — a worse fit, because an npm package name is not the
identity of a delivered script.

**Currency is reported, not implied.** Follow the generator precedent rather than hand-writing tables
[VERIFIED: `crates/scanner/AGENTS.md`; `crates/scanner/tools/gen_catalog.py:1-20`]:
`tools/gen_js_vulns.py` reads a pinned local snapshot and emits `src/js_vulns_data.rs`, whose header
records source URL, commit/ETag and fetch date, and which exits non-zero rather than emit anything if the
source stops matching its assumptions. The table carries `DATA_AS_OF`, every finding's detail includes it,
and coverage states it. "Kept current" means a documented regeneration step per release with a visible
date — **not** a runtime fetch, which is rejected outright: that would be egress from `scanner`, and the
only authorised path from a constructed request to a socket is `sender`, enforced by
`sender/tests/no_alternate_egress.rs` [VERIFIED: `crates/AGENTS.md`].

**Identification**, mapped onto the existing `Confidence` ladder, which is what that enum is for:

| Signal | Confidence |
|---|---|
| URI/filename pattern only (`/jquery-1.4.2.min.js`) | `Tentative` |
| In-content version marker (a Retire.js `filecontent`/`func` extractor) | `Firm` |
| Content hash match against a Retire.js `hashes` entry | `Certain` |

**False-positive posture: report only what the signal supports.** A URI-only match on a minified bundle
stays `Tentative` and is labelled so, never promoted to look decisive. `FindingStore::insert` keeps the
strongest confidence across merges [VERIFIED: `crates/core/src/findings.rs:172-178`], so one hash-confirmed
sighting correctly upgrades a finding first seen by filename. **False negatives are counted:** a
concatenated bundle with jQuery inlined usually matches nothing, so coverage carries `js_assets_seen` and
`js_assets_identified` — "0 vulnerable libraries" must be distinguishable from "we could not identify any
of the 41 scripts we saw".

**Version comparison — the subtle part. Assumed scheme: dotted numeric components with an optional
non-numeric tail.** Not semver: real versions include `1.4.2`, `2.0`, `3.0.0-rc1`, `1.11.0b1`,
`2.2.4-lite`, and a strict semver parser rejects most.

```rust
struct Version { parts: Vec<u64>, tail: String }   // "3.0.0-rc1" -> ([3,0,0], "rc1")
```

Compare `parts` element-wise with the shorter zero-padded, so `2.0 == 2.0.0`; a non-empty `tail` sorts
*before* the same numeric version with an empty tail, so `3.0.0-rc1 < 3.0.0`. Retire.js predicates are
`atOrAbove`/`above`/`below`/`atOrBelow` [ASSUMED — confirm against the real schema].

**A version string that does not parse is not compared, not assumed vulnerable, and not dropped.** It
becomes an `Info`/`Tentative` finding of its own class — "JavaScript library version not comparable" —
naming the library, the raw string and the range that could not be evaluated, and increments
`js_versions_unparsable`. The house rule is refuse-by-default on unparseable input [VERIFIED: root
`AGENTS.md`]; here "refuse" means refuse to conclude in **both** directions and say so. Guessing
"probably vulnerable" invents a finding; guessing "probably fine" hides one.

**Placement, and a constraint the existing tests impose.** A passive check but not a BCheck — it needs a
data table and version arithmetic the DSL cannot express. **It must not be appended to
`PassiveScanner::passive`**: that `Vec<Check>` holds parsed BChecks [VERIFIED:
`crates/scanner/src/lib.rs:99`] and a test walks `s.passive.iter().chain(&s.active)` asserting no loaded
check shares a catalogued issue name [VERIFIED: `:1751-1772`]. Findings here are deliberately named
"Vulnerable JavaScript dependency", an exact catalog match [VERIFIED:
`crates/scanner/src/catalog_data.rs:3591`; `type_index` 5243008 = `0x500080`, `typical_severity:
Severity::Low`], so `enrich()` attaches Burp's real remediation with no invented prose [VERIFIED:
`:570-578`]. Native checks live in their own collection.

---

## 7. SCAN-02 — JWT weak-secret detection

**Algorithms: HS256, HS384, HS512 only.** Those are the algorithms whose signing key is a shared secret,
so a wordlist attack is the relevant attack at all; `RS*`/`ES*`/`PS*` are asymmetric. `alg: none`,
`jku`/`x5u` injection and unverified signatures are *different* issues with their own catalogued
definitions [VERIFIED: `crates/scanner/src/catalog_data.rs:2829`, `:2793`, `:2931`, `:2969`] and are
explicitly out of scope — which means **reported as out of scope in the coverage section**, not absent.

Findings are named **"JWT weak HMAC secret"**, the exact catalogued issue with `typical_severity:
Severity::High` [VERIFIED: `:2901`], so enrichment attaches Burp's own remediation. Same non-appending
constraint as §6.

**Where tokens come from.** Passively, from what the store already holds: response bodies, `Set-Cookie`
values, request `Authorization` headers. No outbound traffic. Match
`eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`, base64url-decode the header, require an
`alg` of `HS256`/`HS384`/`HS512`. Anything that does not decode is refused, not guessed at; tokens above a
byte cap are refused before any hashing, and counted.

**Where the wordlist comes from.** Operator-supplied file (`--jwt-wordlist`) plus a small vendored
default. Do not bundle a password dump: megabytes of unclear provenance for a check whose real hit rate
comes from a few dozen library defaults. The default is generated by `tools/gen_jwt_wordlist.py` from a
pinned source, header recording source, date and entry count. **The wordlist's identity and size appear in
every report** — "no weak secrets found against a 48-entry wordlist" and "…against 10 million entries"
are different claims, and stating only the conclusion is dishonest. `CoverageReport` carries
`jwt_wordlist: { name, entries, source }`.

**The cost bound, and counting the give-up.** This is brute force, budgeted the way the audit engine
budgets everything — but along a **new dimension**: `AuditConfig::max_requests` bounds outbound probes
[VERIFIED: `crates/scanner/src/audit.rs:316`] and this check sends nothing, so that budget does not touch
it.

- **Bound: `distinct_tokens × wordlist_entries` HMAC computations**, capped by `max_hmac_attempts:
  Option<u64>` (default 200,000) and by the run's wall-clock budget. 200,000 short-input HMACs should cost
  well under a second [ASSUMED — unmeasured; set the default from a measurement taken during
  implementation, not from this estimate].
- **Deduplicate by signing input**, so a token seen on 200 pages is cracked once. The same insight as
  `FindingStore`'s insertion-time dedup and the ledger's `AlreadyCovered` [VERIFIED:
  `crates/core/src/findings.rs` module docs; `crates/scanner/src/audit.rs:457-463`] — reuse that
  vocabulary rather than invent a third word.
- **It is counted when it gives up.** Not a new `Disposition`: that enum is about `(dispatch unit, check)`
  admission in the *active* engine and must not be stretched. The passive outcome carries `HmacBudget {
  tokens_seen, tokens_exhausted, tokens_abandoned, words_tried }`, and coverage renders abandoned tokens as
  `NotChecked(NeverRun(BudgetSpent(Hmac)))` — *"3 of 11 JWTs were not tested against the full wordlist"*.
  A truncated brute force reported as clean is precisely the defect this project rejects, and the easiest
  one in this phase to introduce by accident.

A token exhausted against the whole wordlist with no match is `Ran` — real evidence, bounded by the
wordlist, and the report names which wordlist.

---

## 8. SCAN-03 — Burp's built-in scan configurations, unchanged

**What the format actually is**, verified by extracting `resources/BuiltInConfigs/*` from
`/root/burp-re/in/burpsuite.jar` [VERIFIED: `unzip` of the shipped jar, 2026-07-28]:

- **29 files**, each a JSON object with a `description` block (`featured`, `uuid`, optionally `default`,
  `display_order`, `icon`, `text`) plus `scanner` and/or `crawler` sub-objects.
- **84 distinct leaf key paths**, in eleven groups: `scanner/` `error_handling`, `audit_optimization`,
  `issues_reported`, `insertion_point_types`, `frequently_occurring_insertion_points`,
  `ignored_insertion_points`, `misc_insertion_point_options`, `modifying_parameter_locations`,
  `javascript_analysis`, `audit_project_option_overrides`, and `crawler/*`.
- "Unchanged" means the file is consumed byte-for-byte as shipped and never edited. Two load paths: by
  name from a generated table, and from an arbitrary path, so an operator can point at a config exported
  from their own Burp.

Today `BUILT_IN_CONFIGS` transcribes **6 of 29** and omits the rest [VERIFIED:
`crates/scanner/src/audit.rs:364-455`; the `len() == 6` test at `:865-869`], arguing the others would be
"knobs that do nothing". REPORT-04's discipline overturns that: **all 29 must be present, with the 23
non-mapping ones reported as unmapped.** Omission and honest non-mapping are not the same statement.

**A correction the extraction surfaced.** `BUILT_IN_CONFIGS`'s doc comment says *"None of them sets
`pause_task_failed_audit_item_percentage`"*. **Two do** — `Crawl and Audit - CICD Optimized` and `Never
stop audit due to application errors`, both `0` [VERIFIED: extracted JSON]. Behaviourally harmless, since
`0` disables the breaker and the default is already `0` [VERIFIED: `:338-347`], but the comment is false
and `BuiltInConfig` has no field for the key, so it cannot be overlaid even where set. Fix in this slice.

**Fully mapped** (verified per file): `scanner/error_handling/`
`consecutive_audit_check_failures_to_skip_insertion_point`,
`consecutive_insertion_point_failures_to_fail_audit_item`, `pause_task_failed_audit_item_count`,
`pause_task_failed_audit_item_percentage`, and `audit_optimization/maximum_crawl_and_audit_time` (minutes;
`15` in CICD Optimized and Lightweight) [VERIFIED: extracted values match `BUILT_IN_CONFIGS` for all six
configs that set them].

**Newly mappable, and worth the code:** `issues_reported/scan_type_passive` and
`scan_type_{light,medium,intrusive}_active`. `Audit checks - passive.json` sets `scan_type_passive: true`
with all three active types `false` [VERIFIED: extracted] — exactly burpsy's split: run the 105, skip the
127. Mapping: any active type `true` enables the active set, all `false` disables it, `scan_type_passive`
gates the passive set.

**Partly mapped, and it must say so:** burpsy has no light/medium/intrusive taxonomy for BChecks, so
`Audit checks - light active` cannot be honoured precisely. Behaviour: the whole active set runs, and the
report records `ActiveIntensityNotDistinguished`. Silently running intrusive checks under a config named
"light active" is worse than admitting the distinction does not exist here.

**Semantically resolvable but operationally inert — the interesting case.** `issues_reported/
selected_issues[]` carries hex `type_index` strings such as `"0x00100210"` [VERIFIED: extracted], and
those resolve against the catalog's `type_index`, which burpsy holds for all 183 [VERIFIED:
`crates/scanner/src/catalog.rs:128-134`; `0x00100200` is "SQL injection", pinned at `:319-323`]. But no
published BCheck shares a name with any catalogued issue [VERIFIED: `crates/scanner/src/lib.rs:1751-1772`],
so `scan_only_selected_issues: true` selects nothing burpsy can run. **The loader resolves the ids anyway
and lists the resolved issue names**, because "we understood your selection and it selects nothing we can
run" is a completely different statement from "we ignored it". Two configs make this concrete: `Audit
checks - critical issues only` selects 13 issue types, and `Audit checks - BChecks only` selects exactly
`0x09000000` — which the catalog names "BCheck generated issue" [VERIFIED:
`crates/scanner/src/catalog_data.rs:5758`; id pinned at `crates/scanner/src/catalog.rs:369-371`]. That
config's intent burpsy satisfies **completely**, and saying so is the most useful sentence this loader can
produce.

**Not mapped:** `scan_speed` ∈ {`fast`,`normal`,`thorough`} and `scan_accuracy` ∈
{`minimise_false_negatives`,`minimise_false_positives`} [VERIFIED: extracted values]; all
insertion-point groups (none exist yet — the same gap as the 6 `needs_insertion_point` checks);
`javascript_analysis` (Phases 11–12); `modifying_parameter_locations`; the project-option timeout
overrides; all 23 `crawler/*` leaves (Phase 6). Each reported with a reason and, where one exists, the
phase that would provide it.

**Reporting the unmapped settings — three buckets, not two:**

```rust
pub struct ConfigLoadReport {
    pub name: String,
    pub uuid: Option<String>,
    pub mapped: Vec<AppliedSetting>,       // key path, source value, what it was applied to
    pub unmapped: Vec<UnmappedSetting>,    // a key we know, with nothing to apply it to, plus the reason
    pub unrecognised: Vec<(String, serde_json::Value)>, // not among the 84 — a newer Burp, or hand-edited
}
```

Conflating `unmapped` and `unrecognised` would let a key from a future Burp release silently become
"unmapped, as designed" — the loader would look honest while having learned nothing. **The strongest test
in this section:** for every one of the 29 shipped files, `mapped + unmapped + unrecognised` accounts for
every leaf key, and `unrecognised` is empty. Same shape as the `LoadReport` sum, and it catches both a
dropped key and a drifted transcription. The table is generated by `tools/gen_builtin_configs.py` from a
jar extraction, recording the Burp version — the existing table already cites 2026.7.1 [VERIFIED:
`crates/scanner/src/audit.rs:405-406`].

---

## 9. Slice plan

Seven slices in dependency order. Each is one executor pass; each states what it does **not** deliver so
the next agent assumes nothing.

**S1 — Passive coverage instrumentation (`scanner`).** Add `PassiveOutcome` with a per-check disposition
histogram; change `scan`/`scan_message` to return it instead of a bare `usize`; count the four early
returns and the swallowed `run_passive` error [`crates/scanner/src/lib.rs:203-242`]. Retain check
identities for the `collaborator`, `needs_insertion_point` and unparsable buckets on `LoadReport` (add
fields; do not touch the four counters). One production call site: `crates/proxy/src/lib.rs:903`
[VERIFIED: only caller].
*Acceptance:* a scan of N in-scope responses yields counters summing to `passive.len() * N`; a check whose
regex fails at runtime appears as `PassiveRuntimeError` with its message; an out-of-scope exchange is
distinguishable from a clean scan; the corpus test still pins 264/105/127/6/26.
*Does not yet deliver:* no report file, no new crate, no coverage composition.

**S2 — `crates/report`, the coverage model, and JSON (REPORT-02, REPORT-04).** New crate in the workspace
`members` with its `AGENTS.md`. `CoverageReport`, `CheckStatus`, `NotCheckedReason`, `ZeroFindingVerdict`,
the population sum invariants, the versioned JSON `Document`, and the in-process `RunLedger` that retains
`SessionOutcome`s (risk 7). CLI: `burpsy report --json`.
*Acceptance:* a run with zero findings and no audit produces JSON whose verdict is `NothingChecked` and
which names all 26 Collaborator-gated checks individually with their reason; sum invariants are tests; a
pinned top-level-key test on `ExportFinding`; a test asserting `CheckedAndClean` is unreachable for the
shipped corpus.
*Does not yet deliver:* HTML, SARIF, the web endpoint, any new check.

**S3 — HTML (REPORT-01).** Zero-JavaScript self-contained page: single `push_text` chokepoint,
five-character escape, CSP meta, `<details>` collapse, detail-byte cap with stated counts, coverage verdict
above the findings table. CLI: `burpsy report --html`.
*Acceptance:* a finding whose `detail` is `"><script>alert(1)</script>` renders as visible literal text; a
test asserts the document contains no `<script` element and that no finding-derived byte appears within an
attribute region; the truncation marker states both numbers.
*Does not yet deliver:* SARIF, the web endpoint.

**S4 — SARIF (REPORT-03).** 2.1.0 writer, catalog rule metadata, the severity/`security-severity` mapping,
Info excluded by default with a stated count, `partialFingerprints` from `dedup_key()`, coverage as
notifications + `runs[].properties`, optional `--sarif-coverage-alert`. Vendored schema plus
`tools/validate_sarif.py` (skipped loudly without `jsonschema`) and a Rust required-property test. CLI:
`burpsy report --sarif`.
*Acceptance:* zero-finding and populated runs both validate against the vendored schema and pass the
property test; the manual upload procedure is documented and its one-off result recorded with date and
version.
*Does not yet deliver:* automated proof of GitHub ingestion in CI — out of reach, see §3.

**S5 — Web export endpoint.** `ExportHook` on `AppState`, new `crates/web/src/routes/report.rs`, CLI builds
the closure.
*Acceptance:* `GET /api/report?format=html|json|sarif` returns the same bytes as the CLI for the same
state; a test asserts `crates/web/Cargo.toml` gained no scanner or report dependency.
*Does not yet deliver:* any scanner change.

**S6 — SCAN-03: all 29 configs, with unmapped reporting.** `tools/gen_builtin_configs.py` → generated
table for all 29; loader for an arbitrary path; `ConfigLoadReport` with its three buckets; the
`scan_type_*` mapping; `selected_issues` resolution against the catalog; the
`pause_task_failed_audit_item_percentage` correction. CLI: `--scan-config NAME|PATH`, printing the unmapped
list.
*Acceptance:* all 29 files load with `mapped + unmapped + unrecognised` covering every leaf and
`unrecognised` empty; `Audit checks - passive` disables the active set; `Audit checks - BChecks only`
reports its intent as fully satisfied; resolved issue titles are named for a `selected_issues` config.
*Does not yet deliver:* SCAN-01, SCAN-02.

**S7 — SCAN-01 and SCAN-02, the two native checks.** Two commits in one pass; S7a ships independently.
*S7a (SCAN-01):* `tools/gen_js_vulns.py` → `js_vulns_data.rs` with `DATA_AS_OF`; version parser and range
comparison; three-signal identification with confidence tiers; `js_assets_seen` /
`js_assets_identified` / `js_versions_unparsable` in coverage; findings named "Vulnerable JavaScript
dependency". *S7b (SCAN-02):* HS256/384/512 extraction, dedup by signing input, vendored wordlist with
stated size, `max_hmac_attempts` with a counted give-up; findings named "JWT weak HMAC secret".
*Acceptance:* a jQuery 1.4.2 response yields a finding carrying the catalog's real remediation; `1.11.0b1`
and a garbage version each produce a counted non-conclusion and never a vulnerable verdict; a token signed
with a wordlist entry is `Certain`; a token signed with a random secret is exhausted-and-clean naming the
wordlist; a run that hits the HMAC budget reports the abandoned token count and never reports those tokens
as clean.
*Does not yet deliver:* `alg=none`, `jku`/`x5u`, unverified-signature checks — separate catalogued issues,
out of scope.

Neither native check may be appended to `PassiveScanner::passive` (§6).

---

## 10. Risks and open questions

1. **GitHub ingestion of URL-based locations — highest risk.** REPORT-03 depends on GitHub accepting
   `artifactLocation.uri` values absent from the repository and surfacing them as alerts. Not verifiable
   here. If it fails, S4's acceptance holds but the requirement does not, and the fallback is a worse
   product. **Verify before S4, not after.**
2. **Retire.js licence and schema — both `[ASSUMED]`.** Confirm vendoring is permitted and the real
   predicate/extractor shapes before writing the generator. The OSV fallback has a genuine identity
   problem (npm name ≠ delivered script) and would change SCAN-01's confidence story.
3. **The HMAC budget default is unmeasured.** 200,000 is an estimate; measure in S7b and set it from the
   measurement. A budget number nobody measured is the kind of figure this project otherwise refuses to
   print.
4. **`AlreadyCovered` across report boundaries.** Resolved within a report, `Unknown` otherwise (§2) —
   correct but conservative: an operator who audits over several sessions and exports once sees `Unknown`
   where coverage genuinely happened. The alternative, a persisted cross-run ledger, is a new durability
   concern and is deliberately out of this phase. Flagged rather than silently chosen.
5. **`scan`'s signature change (S1) is a public API break.** One production caller [VERIFIED:
   `crates/proxy/src/lib.rs:903`], but the scanner tests use the return value widely. Returning a struct
   whose findings count preserves the old meaning keeps call sites readable.
6. **Adding a tenth crate touches shared files** — the workspace `members` list, the root `AGENTS.md`
   graph, and `crates/AGENTS.md`'s "nine workspace crates". All three say nine today [VERIFIED]. S2 must
   update them; a reviewer should treat a stale "nine" as a defect.
7. **`SessionOutcome` is not persisted.** The audit hook returns JSON to the web layer and discards it
   [VERIFIED: `crates/cli/src/main.rs:255-262`], so a report generated later has no record of any audit.
   **This is the practical blocker on success criterion 3's positive half** — the report can always say "no
   audit evidence", but for it to ever say "these ran", something must retain the outcomes. Hence the
   `RunLedger` in S2. Called out because it is easy to discover only at the end of that slice.
8. **Whether `--sarif-coverage-alert` should exist at all.** It emits a result about the scan rather than
   about the target, which is a fabricated finding by one reading. Kept opt-in and documented, but a
   reviewer may reasonably want it dropped; I did not want to decide it silently.
9. **Whether the HTML report should ever carry raw response bytes.** Findings hold ids, not bodies
   [VERIFIED: `crates/core/src/findings.rs:60-66`], and `detail` is check-authored. This design assumes the
   report never resolves and embeds response bodies. If evidence excerpts are wanted later, the structural
   rule in §4 is the thing that must not be relaxed to get them.
