# Scanner Coverage

Status of the 183-issue Burp Suite catalog (`internal/scanner/catalog_data.go`) against the
burpsy scanner. **Every catalog row is now runnable; nothing is declined** — but
*runnable* is registration, not proof. The runtime-demonstration layer below
(section "Runtime demonstration") is the honest half of this story and the
figure to quote.

## Totals

| Bucket | Count |
|---|---:|
| Catalog issues (total) | 183 |
| **Runnable checks** | **183** |
| Declined (explicit, `DeclinedCatalogDescriptors`) | 0 |

### Rows per descriptor family

| Family | Rows |
|---|---:|
| original native (`NativeCheckRegistry` body) | 5 |
| HeaderChecks (`checks_headers.go`) | 6 |
| CacheChecks (`checks_cache.go`) | 2 |
| ReflectionProbe (`checks_reflection2.go`) | 6 |
| HostDiscovery (`checks_discovery.go`) | 5 |
| ResponseDependence (`checks_reflection3.go`) | 5 |
| PassivePosture (`checks_passive_posture.go`) | 15 |
| PassiveAnalysis (`checks_passive_analysis.go`) | 28 |
| Injection (`checks_injection.go`) | 12 |
| DOM (`checks_dom.go`) | 48 |
| DOMExtra (`checks_dom_extra.go`) | 3 |
| Stored (`checks_stored.go`) | 10 |
| Remaining (`checks_remaining.go`) | 22 |
| Final (`checks_final.go`) | 16 |

Sum check: 5 + 6 + 2 + 6 + 5 + 5 + 15 + 28 + 12 + 48 + 3 + 10 + 22 + 16 = 183. Every catalog
`TypeIndex` is accounted for exactly once; no `TypeIndex` is claimed by more than one family
(`ValidateRegistry` rejects a duplicate, and `TestDeclinedCatalogDescriptors` fails if the
per-family partition stops summing to 183).

## Outside the catalog: burpsy's own rows

Classes burpsy detects that Burp's catalogue has no row for. They are not catalogue rows: the 183
above stay Burp's, and each burpsy row is reported by a check riding an existing Burp descriptor
behind its own switch (`scanner.BurpsyNativeRows`, `internal/scanner/burpsy_rows.go`). Each has a
burpsy-authored advisory in `internal/advisory/native/` (index range `0xb5000000`-`0xb5ffffff`),
which is what carries its CWE onto the finding.

| TypeIndex | Row | CWE | Rides | Switch |
|---|---|---|---|---|
| `b5000100` | Insecure direct object reference | 639 | Broken access control | `check_idor` |
| `b5000200` | Authentication attempts not rate limited | 307 | Broken access control | `check_login_rate_limit` (+ `login_rate_limit_attempts`, default 20, 5-100) |
| `b5000300` | Username enumeration | 204 | Broken access control | `check_username_enumeration` |
| `b5001000` | Host header injection | 20 | Link manipulation (reflected) | `check_host_header` |
| `b5001800` | GraphQL query batching enabled | 799 | GraphQL endpoint found | `check_graphql_hardening` |
| `b5001810` | GraphQL query depth not limited | 770 | GraphQL endpoint found | `check_graphql_hardening` |
| `b5001820` | GraphQL debug information disclosed | 209 | GraphQL endpoint found | `check_graphql_hardening` |
| `b5001400` | Insecure deserialization | 502 | React Server Components remote code execution (React2Shell) | `check_insecure_deserialization` |

The two authentication rows (`checks_auth_logic.go`) are off by default because they send failed
logins. Missing rate limiting is reported *tentative*: the burst uses an invented identity so no
real account can be locked, which also means a lockout that engages only for existing accounts is
not observable. Riding "Broken access control" puts them in that row's light tier and per-URL scope.

Host header injection (`checks_host_header.go`) is off by default because it sends requests naming
hosts the target does not serve (random labels under `.invalid`, each with a cache-buster). It is
reported only when the canary became the host of a URL in the response (Location, Refresh, Link,
or a body URL starting at an attribute/string boundary), was absent from the baseline, and a second
canary through the same vehicle moved with it. Routing-based SSRF through the Host header is filed
under Burp's own "External service interaction (DNS/HTTP)" rows, which now also plant the
collaborator as the request's Host and absolute-form target.
The three GraphQL rows (`checks_graphql_hardening.go`) are off by default and probe only a URL whose
answer to `query{<fresh alias>:__typename}` carries that alias back: batching is ten array-batched
operations and one hundred aliases, each answered under its own alias; depth is one query ten object
fields deep along a self-referential path of the introspected schema, never fanning out (needs
introspection; undecided without it); debug is two or more stack frames in the errors of a malformed
query, or Apollo's tracing extension.
Insecure deserialization (`checks_deserialization.go`) is proved by benign accepted/rejected value
pairs (a nonexistent class versus a corrupted Java stream or PHP string, a pushed int versus an
undefined pickle opcode, a resolvable JDK collection versus a nonexistent `@class`/`@type`, and for a
cookie an empty versus an unterminated JSON object), each pair repeated with fresh names. No gadget is
sent. Unsigned JSON state is reported low/tentative; the other formats high/firm.

## Outside the catalog: DOM Invader's detections

The 183-row catalog above is the **scanner's** issue set — the rows Burp's own audit engine can
report. Two DOM Invader detections sit outside it, and burpsy's disposition of each is stated
here rather than left silent, because "not in the catalog" and "nobody thought about it" read
the same from outside:

- **DOM clobbering** (Burp: `tools/dom-invader/dom-clobbering.html` — "DOM Invader can
  automatically test for DOM clobbering vulnerabilities on your behalf"). Burp ships this in
  the DOM Invader **browser extension**, not the scanner: zero `clobber` strings anywhere in the
  recovered binary, no issue-descriptions page, no catalog row — so burpsy's catalog genuinely
  has no row to decline. A clobbering detection at burpsy's browser tier would require
  instrumenting *named property reads* (`window.someId` resolving to an injected element) in
  domexec: the harness observes sources flowing into a fixed sink list, and a clobbered read is
  neither — it is identifier resolution the ES engine (goja) cannot model because named access
  is a DOM behaviour, not an ES one. That instrumentation is a domexec subsystem, out of scope
  until a bead asks for it by name. Until then: **not detected, stated** — the runtime coverage
  numbers on this page must not be read as covering it.

- **Prototype-pollution gadget discovery**: `checks_dom_extra.go` reports the SOURCE (a
  URL-controlled property written onto `Object.prototype`) and deliberately defers gadget
  discovery to a browser tier, the same scope cut Burp's own check makes before deferring to
  DOM Invader.

## Runtime demonstration

Registration answers "is a detector wired to this catalog row?". It cannot answer "when
this scanner is pointed at something that really is vulnerable, does it say so?" — a non-nil
function pointer cannot be told apart from a stub. That question is answered by
`internal/scanner/runtime_coverage_test.go`, which starts the deliberately vulnerable app in
`internal/vulnapp`, seeds real exchanges over real HTTP, runs the real `AuditWithin`, and
asserts every declared vulnerability is reported while its **safe counterpart** stays silent.

| Bucket | Count |
|---|---:|
| Catalog rows with an end-to-end runtime demonstration | **160 / 183** |
| Rows registered but not runtime-demonstrated | 23 / 183 |

- The 160 is both *measured* and pinned by `wantDemonstrated = 160` in `runtime_coverage_test.go`
  — removing a manifest entry fails the suite rather than quietly lowering the published number. It
  counts **distinct rows**, not endpoints (163 vulnerable endpoints in the manifest; some rows have
  two).
- Provenance (2026-08-27): reproduced with
  `go test ./internal/scanner/ -run TestTheScannerDetects -count=1 -v -timeout 30m`, which printed
  verbatim:

  > `runtime detection: 160 distinct catalog rows demonstrated across 163 endpoints, 0 missed`

- **Correction of a stale figure:** this table previously read **145 / 183** with 38 not
  demonstrated. The number was transcribed from the 145-era snapshot recorded in
  [HANDOFF-2026-08-18.md](./HANDOFF-2026-08-18.md) and never re-derived against the live object after the
  pin moved, so it understated real coverage for two days. The direction of that error is worth
  naming because every other wrong figure on this branch inflated; an understated claim still
  erodes trust once noticed, which is why it is corrected here rather than silently overwritten.
  Registry context from the same day, measured by walking `NativeCheckRegistry()`: **183 total /
  183 runnable / 0 declined / no duplicate names**; the 23 undemonstrated names group into
  stored-DOM platform walls (WebSQL removed from Chromium, `[object File]` canaries, navigation-only
  sinks), OOB/collaborator dependence, request smuggling's non-conformant-listener requirement,
  generated-issue placeholders, and native checks without a planted vulnerable endpoint — the
  per-row list lives in the handoff's registered-only section.
- Coverage grows by planting another vulnerability in `internal/vulnapp`, not by editing a
  constant: the assertions come from the manifest declaration.
- The exact 38 registered-only rows, grouped by why they lack a demonstration (stored-DOM
  pairing, OOB/collaborator channel, smuggling listener, generated-issue rows, native
  checks without a manifest endpoint), are listed in
  [HANDOFF-2026-08-18.md](./HANDOFF-2026-08-18.md).

`CacheChecks` holds 2, not 4: `HTTP request smuggling` and `Client-side desync` moved to
`checks_final.go` when the pipelining driver over `internal/sender/pipeline.go` was built.
`DOMAndStoredXSSDescriptors` and `DeclinedCatalogDescriptors` both return empty slices now —
they are kept as registration points so a future decline has somewhere honest to go.

## Native / implemented checks

These are registered as runnable `CheckDescriptor`s (Implementation = `ImplementationNative`).
Each is gated behind a per-family `ScanConfig` switch, all off by default.

### Original native registry (5)

The rows `NativeCheckRegistry`'s own body still declares. `SQL injection`,
`Cross-site scripting (reflected)` and `File path traversal` left this list for
`checks_core_injection.go` when they were ported onto enumerated insertion points, and
`XML external entity injection` / `Out-of-band resource load (HTTP)` moved to
`checks_remaining.go`.

| Catalog name | TypeIndex |
|---|---:|
| `JWT weak HMAC secret` | 2099459 |
| `Vulnerable JavaScript dependency` | 5243008 |

(Two rows here plus the three in `checks_core_injection.go` are the five the totals table counts as
"original native": the split is by which file declares the descriptor, and
`coreInjectionDescriptors()` is aggregated into the registry body.)

### HeaderChecks family (6)

| Catalog name | TypeIndex |
|---|---:|
| `Content security policy: allows clickjacking` | 2098439 |
| `Content security policy: not enforced` | 2098441 |
| `Cross-origin resource sharing: arbitrary origin trusted` | 2098689 |
| `Cross-origin resource sharing: unencrypted origin trusted` | 2098690 |
| `Cross-origin resource sharing: all subdomains trusted` | 2098691 |
| `Duplicate cookies set` | 4196864 |

### CacheChecks family (2)

| Catalog name | TypeIndex |
|---|---:|
| `Web cache poisoning` | 2097536 |
| `Web cache deception` | 2098768 |

`HTTP request smuggling` and `Client-side desync` were listed here while this family declined them
for want of a pipelining primitive. They are registered in `checks_final.go`; since 0vzb.1 their
runners live in `checks_smuggling.go`: request smuggling is detected by timing alone (CL.TE, TE.CL,
H2.TE, H2.CL against a consistently framed control, switch `check_request_smuggling`) and is
demonstrated on vulnapp's two-tier listeners (`/desync/*`); Client-side desync declines at run time,
because its only confirmation can poison a shared back-end connection (see `gaps.md`).

### Main-claimed family (0)

`DOMAndStoredXSSDescriptors()` returns nothing. Its nine rows — the DOM-based and stored XSS /
JavaScript-injection variants plus `SQL injection (second order)` and
`Client-side template injection` — moved to `checks_dom.go`, `checks_dom_extra.go` (with `checks_csti.go`) and
`checks_stored.go` once `internal/domexec` and the stored ledger existed. The function is kept as a
registration point; see `checks_declined_dom.go`.

### ReflectionProbe family (6)

All six are the catalog issues `java_check_inventory.json`'s live-scan JDI trace confirmed firing
(Zr02, Zuag, Zb_5, Zwi, Zsn3, Zexx) that were not yet native. See `checks_reflection2.go`'s file
header for exactly which parts of each are ported from recovered Java evidence
(`out/strings/map_root.tsv` literals, `Zw9s.Ze`'s encoding logic) versus a documented,
non-Burp-specific standard payload where the Java literal is ZKM ciphertext residue with no
recoverable value.

| Catalog name | TypeIndex |
|---|---:|
| `Input returned in response (reflected)` | 4197376 |
| `Open redirection (reflected)` | 5243136 |
| `Link manipulation (reflected)` | 5246979 |
| `HTTP response header injection` | 2097664 |
| `Unidentified code injection` | 1052672 |
| `SSI injection` | 1052928 |

### HostDiscovery family (5)

All five are host-wide checks in `checks_discovery.go`: three from real recovered Java probe
lists (`out/strings/map_root.tsv`) and two (HTTP PUT/TRACE) from RFC-defined method confirmation
behavior, ported once `sendTestRequestBody` made arbitrary-method probing available for probes
with a method other than the captured exchange's own.

| Catalog name | TypeIndex |
|---|---:|
| `OpenAPI definition found (active scan check)` | 6293760 |
| `Robots.txt file` | 6292992 |
| `GraphQL endpoint discovered` | 2098449 |
| `HTTP PUT method is enabled` | 1050880 |
| `HTTP TRACE method is enabled` | 5245440 |

### ResponseDependence family (5)

All five are per-URL checks in `checks_reflection3.go`, ported from real recovered Java probe
strings (`out/strings/map_root.tsv`): four distinct backup-file classes combined into one check,
a mobile User-Agent string, Referer literal fragments, and the ASP.NET debugging/tracing wire
protocol markers.

| Catalog name | TypeIndex |
|---|---:|
| `Backup file` | 6291672 |
| `User agent-dependent response` | 4194592 |
| `Referer-dependent response` | 4194560 |
| `ASP.NET debugging enabled` | 1050624 |
| `ASP.NET tracing enabled` | 1049216 |

## BCheck-implemented (0)

The 264-file BCheck corpus at `/root/.cache/BChecks` was scanned for any `metadata.name` whose value
matches a catalog issue `Name`, using both an exact case-insensitive comparison and a normalized
comparison (case and punctuation stripped, whitespace collapsed). **No BCheck matched any catalog
issue name.** Every BCheck in the corpus targets a CVE, a specific technology, or a token/secret
class that is not one of the 183 catalog issue names, so the `bcheck_implemented` set is empty.
BChecks are a separate evaluator architecture (the plan defers wiring them into the native registry)
and are surfaced through `ScanConfig.CheckCorpus` rather than as catalog-declined rows.

## Declined (0)

Nothing is declined. `DeclinedCatalogDescriptors()` returns an empty slice, and the mechanism is
kept for the next row that genuinely cannot be answered — see `check_registry_declined.go`'s header.

This section used to carry a 141-row table of decline reasons. It was left in place after the totals
above were rewritten, so for a while this document asserted both "nothing is declined" and
"`OS command injection` — burpsy has no native evaluator for this injection class" while
`checks_injection.go` implemented exactly that. A document that states a fact and its negation is
the same defect as a scanner that reports a partial result as a complete one, so the stale half is
gone rather than annotated. The retired reasons are recoverable from git history if the wording is
ever wanted again.

## Unclassified

None. All 183 catalog issues fall into exactly one bucket above; the partition is exhaustive and
sums to 183, asserted by `TestDeclinedCatalogDescriptors`.

## Per-issue selection in an imported scan configuration (saq3.1, 2hze, gmdk)

A Burp scan configuration loaded with `-scan-config /path/to/file.json` (`scanner.ApplyBurpConfigFile`)
selects issues the way Burp 2026.7.1 (build 51467) does — `internal/scanner/issue_selection.go` carries
the citations:

| Burp key | What burpsy does |
|---|---|
| `select_individual_issues` / `scan_only_selected_issues` | Either one puts the run in per-issue mode, where the `scan_type_*` keys are **not consulted** (`Zmzw.java:80-87`). |
| `selected_issues` without `scan_only_selected_issues` | **Per-issue overrides**, not a whitelist (`Zwnn.java:13-25`): an unlisted type still runs, `enabled: false` removes the type. |
| `selected_issues` with `scan_only_selected_issues` | A whitelist of the enabled entries; an empty list restricts nothing. |
| `selected_issues[].detection_methods[]` set false | Keyed per issue type (`Zwx_.java:43-61`). A check whose declared method is disabled is not dispatched; a probe of a disabled method is withheld at the harness and counted in the item's `methods_declined` with the requests withheld. |
| `selected_issues[].detection_methods[]` set true that burpsy does not implement | Named in `declined_detection_methods` with the reason and repeated on every item whose check of that type runs. **Burp Infiltrator** always lands here. |
| `skip_server_side_injection_for_parameters` | Parameter names (API) are not probed by Burp's server-side-injection set: SQL injection, second-order SQL injection and XPath always (`Zppj.java:166`); the rest — reflected and stored XSS included — only while `skip_ineffective_checks` is on (`Zfhb.java:81-82`). See `server_side_injection.go`. |

The live sweep's passive pass (`RunPassiveChecks`, run over every admitted exchange before the sweep's
audit session) reads the same run configuration through the same `enabledChecksUnder` selection: a
deselected passive type, a disabled method, or `scan_type_passive` false stops it there too
(saq3.3.2, `TestTheSweepPassivePassDoesNotRaiseAnIssueTypeTheRunConfigurationDeselected`). Before
that fix the sweep's active half honoured the selection and its passive half, one loop earlier, did
not. The capture pass (`Capture.ScanExchange`, run for every proxied, crawled, Repeater and API-scan
exchange) reads it too (saq3.3.3). The shared `PassiveScanner` carries the engagement's run configuration
from the `ActiveScanner`, so capture honours the following:
- `scan_type_passive` false skips the passive BChecks;
- `use_static_analysis` false skips the static DOM pass, and `max_static_time_per_item` bounds it;
- a deselected type, or a disabled "Passive checks" or "Javascript static analysis" method, drops the
  finding (`Test_capture_honours_the_run_configuration`).

A finding outside the catalogue cannot be filtered by type, as on the audit side. That covers a corpus
BCheck's own issue, and the four no-corpus built-in header and cookie rows, whose names are not
catalogue names.

What each check detects by, in Burp's method vocabulary, is `burpsyDetectionMethods`. What that shows
is real coverage, not a configuration artefact (saq3.2.1): SQL injection's one check sends three probe
banks through three method gates — error signatures ("Error messages"), the boolean differential
("Boolean conditions") and the timing bank ("Time delays", whose PostgreSQL and SQL Server forms are
additionally gated by "PostgreSQL specific" / "SQL Server specific") — so blind SQLi is detectable,
and a disabled method withholds exactly its own probes and names the decline. Still not implemented
for SQL injection: "Burp Collaborator", and the MySQL/Oracle timing banks whose payload text sits
inside ZKM string decoders this tree does not run; both are declined by name. No other native check
sends a time-delay probe.

Every shipped configuration that sets `issues_reported` is pinned to behaviour matching its name by
`TestEveryShippedSelectionConfigurationBehavesAsItsNameSays`, over the 29 files vendored byte-for-byte
in `internal/scanner/testdata/burp-configs`.

## Per-run project-option overrides (o2p3)

Read from Burp 2026.7.1 (build 51467); `internal/scanner/run_overrides.go` carries the citations.

| Burp key | What burpsy does |
|---|---|
| `audit_optimization/follow_redirections` | A boolean (`Zhd_.java:41`), not the four-way project redirect mode (`Zxt4.java`). True makes the **reflected-XSS check** follow a probe's redirect — within the engagement scope, or to the same host and port when no scope is configured (the documented in-scope / out-of-scope rule) — with every hop authorised on its own bytes, paced by the run's resource pool and counted against its request budget, and look for the breakout on the landing page. **Every other check reads the 30x itself**: open redirection and header injection depend on it, and Burp's own per-check "where necessary" predicate was not located. False or unset follows nothing. |
| `audit_project_option_overrides/connect_timeout`, `normal_timeout` | Whole seconds (`Zbuj.java:19-22`); `-1` is "not overridden" and is honoured as such; `0` never times out. The run gets its **own derived sender** (`sender.DeriveWithTimeouts`) behind the same scope gate: connect bounds the dial and handshake, normal bounds the wait for the response, and a shorter per-probe budget still wins. The engagement sender Repeater, Intruder and every other run share is never changed. Probes sent after the run returns (the deferred stored and out-of-band phases) use the engagement's timeouts. |

Proved through `AuditSession` against vulnapp by
`TestFollowRedirectionsDecidesWhetherTheReflectedXSSProbeFollowsAVulnappRedirect` (a 302 whose landing
page reflects input: not requested and no finding when false, requested and found when true, under both
scope rules) and `TestNormalTimeoutBoundsTheRunsProbesAndLeavesTheEngagementSenderAlone` (a 1.5 s
endpoint is a counted send failure under `normal_timeout` 1 and runs under no override; the engagement
sender is the same object with the same settings afterwards and still waits the answer out).

## JavaScript analysis keys (9mti)

Read from Burp 2026.7.1 (build 51467) at `Zxc3.java:27-31`; `internal/scanner/js_analysis.go` carries
the citations. In burpsy, **static** is the audit's lexical source-to-sink pass over an item's own
response (`AnalyzeDOMDocument`) and **dynamic** is everything that drives the headless browser: the DOM
check families and the confirmation of static candidates.

| Burp key | What burpsy does |
|---|---|
| `use_static_analysis` | False stops the static pass and the confirmation it seeds; the browser-driven DOM checks still run. |
| `use_dynamic_analysis` | False takes every browser-driven DOM check out of the run's check set and skips confirmation, so **the run starts no browser**; the static candidates are then reported as tentative findings that say dynamic analysis was off. The crawl's rendered-location pass declines with the reason. |
| `max_static_time_per_item` | Seconds (Burp's panel labels it so, `Zrde.java:204,230`); 0 is no limit, as the documentation says of zero or blank. When it runs out the pass keeps what it found, marks the analysis incomplete, and the item's `javascript_analysis_skips` names the static pass and the limit. |
| `max_dynamic_time_per_item` | Seconds; 0 is no limit. One clock per item, started by its first browser use and shared by its DOM checks and the confirmation tier. A DOM check it stops, or never lets start, is counted **Skipped** — not clean, and not a send failure that trips the breaker — and named in `javascript_analysis_skips`. |
| `max_time_per_item` | Burp's pre-split spelling, which Burp reads into the static limit (`Zxc3.java:30`). No shipped file carries it, so it has no row: a file naming it is told the key did nothing. |

The selection a run carries applies to what this tail reports: a deselected type, or "Javascript static
analysis" disabled for a type, removes its static candidates; "Javascript dynamic analysis" disabled for
a type reports its candidates static-only. `scan_type_javascript_analysis` false now stops the tail
too — before, it removed the DOM checks and left the confirmation tier starting the browser.

Proved through `AuditSession` against vulnapp: `TestAStaticOnlyRunStartsNoBrowserAndReportsTheStaticCandidate`
(zero `Browser()` calls, a tentative DOM-based finding, and a control run that does call it),
`TestMaxStaticTimePerItemStopsThePassAndCountsTheSkip`, and
`TestMaxDynamicTimePerItemIsACountedSkipNotACleanResultOrABreakerTrip` (real Chrome against a page that
answers after 1.5 s under a 1 s limit; skipped, and says so, where Chrome is absent).
