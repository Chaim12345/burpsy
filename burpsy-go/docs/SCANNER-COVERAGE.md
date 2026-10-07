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
for want of a pipelining primitive. They moved to `checks_final.go` when `SendPipelined` gained a
driver.

### Main-claimed family (0)

`DOMAndStoredXSSDescriptors()` returns nothing. Its nine rows — the DOM-based and stored XSS /
JavaScript-injection variants plus `SQL injection (second order)` and
`Client-side template injection` — moved to `checks_dom.go`, `checks_dom_extra.go` and
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
