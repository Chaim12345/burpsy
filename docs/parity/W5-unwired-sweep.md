<!-- ROUTE-NAME CORRECTION (added 2026-08-26, W7b) -->

> **This file refers to `/api/proxy/matchreplace`. That route does not exist and never did.**
> The real endpoints are `/api/tools/rules` and `/api/tools/rules/test` (`web/server.go:789-790`).
> The phantom path appears in **zero** non-markdown files in this repo — it existed only in our
> prose, and spread by copying between documents. Control: `/api/proxy/*` is a genuine prefix
> (`passthrough`, `options` at `server.go:740-741`), so a search would have found the route had
> it existed. Left in place below rather than rewritten, so the error stays visible; see
> §3.1 of the master report. Per ADR rule 14, this note exists because a cited evidence file
> must not contradict the report that cites it.

---

# W5 — STATE 2/3 sweep across all 37 internal packages

Baseline: burpsy `a619c9a` (the W5 brief's baseline). Every file:line in this document was read
from an immutable export of that commit:

```
git archive a619c9a | tar -x -C /tmp/w5base
```

**Why the export, not the working tree.** At the time this sweep ran, `git status --short` in
`/root/burpsy-react-ui` was dirty (9 modified files under `burpsy-go/`, 2 untracked) from concurrent
agents, and `HEAD` moved from `a619c9a` to `9194df6` mid-sweep. Working-tree observations are
inadmissible under the taxonomy's rule 1, so nothing here was measured from the checkout. Reproduce
by re-running the export above; the SHA pins it.

---

## Denominator (recounted, not inherited)

**37 internal Go packages.** Counted by me, two independent ways that agree:

```
find internal -name '*.go' | xargs -n1 dirname | sort -u | wc -l      -> 37
go list ./... | grep /internal/ | wc -l                               -> 37
```

The number is 36 top-level directories under `internal/` **plus** one nested package,
`internal/upstream/upstreamtest`. A sweep that globs `internal/*/` only sees 36 and silently drops
the nested one. The brief's "~35" and "37" both appear; 37 is correct for *packages*, 36 for
*top-level directories*. Both counts are stated so neither can be misquoted.

Secondary denominators, also recounted here:

| Quantity | Value | How counted |
|---|---|---|
| Routes registered in `setupRoutes` | **82** | go/ast walk of `mux.HandleFunc` string-literal first args, `internal/web/server.go` |
| Routes excluding the `/` UI catch-all | **81** | as above, minus `/` |
| UI source files (non-test) | **75** | `*.ts`/`*.tsx` under `internal/web/ui/src`, excluding `.test.`/`.spec.` |
| UI source files (all) | **79** | same, including tests |
| Declared infra primitives | **24** | `File:` entries in `internal/scanner/infra_coverage.go` |

---

## Method

The brief's 5-step method (a: grep non-test importers, b: read the handler, c: grep `setupRoutes`,
d: grep `route_manifest_test.go`, e: grep `ui/src` for a fetch path). Steps (a) and (c) were
executed with go/ast tools rather than grep, because grep is wrong here in two specific ways that
would have produced false STATE 2 claims:

1. **`go list` separates `.Imports` from `.TestImports`/`.XTestImports` natively.** A grep for
   `"internal/foo"` cannot tell a non-test importer from a test one without also parsing which file
   it landed in. The import graph in this document is `go list -f '{{.ImportPath}}|{{join .Imports}}'`,
   which is the compiler's own answer.

2. **Packages reached through a struct field are invisible to a package-name grep.** My first
   route→package pass reported `internal/organizer` as reached by **zero** routes. That was a false
   negative: the handler calls `s.organizer.List()` (`internal/web/api_toolkit.go:1253`), where
   `organizer` is a `*organizer.Store` **field** on `Server` (`internal/web/server.go:62`), not a
   package qualifier. I rebuilt the tool to resolve all 26 package-typed `Server` fields to their
   packages before walking. This corrected `organizer` 0→2 routes, `persist` 0→14, `intercept` 4→7,
   `proxy` 1→2, `scanner` 9→17. **Anyone repeating this sweep with grep will report those five
   packages as unwired, and will be wrong.**

A further correction that changed conclusions: an exported symbol with no *external* reference is
not dead if the package's own reached entry point calls it internally. The final table therefore
classifies every exported symbol into `EXTREF` / `INTRA` / `TEST-ONLY` / `NO-PROD`, and only
`NO-PROD` counts toward a STATE 2 claim. This is what saved `internal/sequencer` from a
false STATE 2 — see the sequencer row.

---

## Headline counts

| | Count | Which |
|---|---|---|
| **STATE 2, whole package** | **1** | `internal/jsexec` |
| **STATE 2, sub-capability** | **3 new + 1 inherited** | tlsprobe cipher analysis; `advisory.Catalogue.ByName`; http2 `Malformation` vocabulary *(residue, see caveat)*; `tools/comparer.go` *(inherited)* |
| **STATE 3** | **1 new + 1 inherited** | `/api/intercept/drop-all` *(new)*; `/api/discovery` *(inherited, independently re-confirmed)* |
| **STATE 5** | **0 found by me** | none; see the matchreplace row for a peer agent's STATE 5 at a different SHA |
| Packages reached by ≥1 route | 29 / 37 | |
| Packages with no route (by design) | 8 / 37 | alpn, domexec, httputil, jsexec, tlsprobe, upstreamtest, vulnapp, web |
| Routes with zero production-UI reference | 4 / 81 | 2 documented legacy aliases + the 2 STATE 3 rows |

**Coherence check.** Every per-package UI shortfall in the table below is fully explained by those
same 4 unreferenced routes. No package has an unexplained gap. That is a property of the data, not
an assumption — it is why I trust the table.

---

## Findings, ranked by user-visible damage

### 1. `internal/jsexec` — STATE 2 (whole package)

**burpsy side:** `internal/jsexec/jsexec.go`, 14 exported symbols, 316 lines. A goja-backed
JavaScript sandbox: `TestPrototypePollution` (`:153`), `PollutionPayloads` (`:124`),
`EvaluateSnippet` (`:235`), `ObservationsForSink` (`:294`), with sink constants for `eval`,
`Function`, `setTimeout(string)` and `JSON.parse` (`:208`–`:211`).

**Proof — zero importers of any kind:**

```
$ grep -rn 'internal/jsexec' --include=*.go . | grep -v '^./internal/jsexec/'
internal/scanner/infra_coverage.go:274:         File: "internal/jsexec/jsexec.go",
```

The single hit is a **string literal in a coverage table**, not an import. Confirmed against the
compiler's own graph: `go list` reports 0 non-test importers *and* 0 test importers — the only
package in the repo with neither. (Its **own** tests do exercise it —
`internal/jsexec/jsexec_test.go` calls `PollutionPayloads`, `TestPrototypePollution` and
`EvaluateSnippet`. That is what makes this STATE 2 rather than STATE 1: the implementation is real
and demonstrably works; nothing in production reaches it.)

**Positive control** (same grep shape, a package known to be imported):

```
$ grep -rn 'internal/sequencer' --include=*.go . | grep -v '^./internal/sequencer/'
internal/web/api_tools.go:22:   "github.com/burpsy-go/burpsy/internal/sequencer"
internal/web/api_sequencer_capture.go:16: ...
cmd/burpsy/cli_tools.go:17: ...
cmd/burpsy/cli.go:21: ...
```

Cross-checked at symbol level: of jsexec's 14 exported symbols, **0 have an external reference**;
10 are referenced only within jsexec itself and 4 are referenced nowhere at all. The package is
entirely self-referential.

**Is this a dishonest claim? No — and this matters.** `internal/scanner/infra_coverage.go:1-17`
states in its own header that a row appearing there means *"we now have the machinery"* and
explicitly **not** *"we now detect this"*, and that conflating the two "is exactly the dishonest
counting this project forbids." jsexec is a **self-declared** built-but-unwired primitive. It is
STATE 2 by the taxonomy's definition, and it is honestly labelled as such by the codebase.
Classify it as STATE 2; do **not** report it as a false parity claim.

**Not determined:** whether wiring `TestPrototypePollution` into the DOM check path is blocked by
anything beyond scheduling. `infra_coverage.go:269-274` says the prototype-pollution row's decline
reason cites a browser blocker that `domexec` already retires, which suggests it is not blocked —
but I did not verify that end to end.

---

### 2. `/api/intercept/drop-all` — STATE 3 (new)

**Burp side:** Burp's Proxy intercept toolbar offers a bulk drop for held messages.

**burpsy side:** registered at `internal/web/server.go:758`; in the manifest at
`internal/web/route_manifest_test.go:281` ("drop every held message in one round trip; answers the
count actually dropped"); handler `handleInterceptDropAll` at `internal/web/api_intercept.go:130-145`
is real — it calls `s.intercept.DropAll(reason)` (`internal/intercept/intercept.go:574`) and returns
the count.

**Proof — routed, in manifest, zero UI reference.** The positive control here is unusually strong,
because its own three siblings match on the identical grep shape in the identical directory:

```
$ grep -rno '/api/intercept[a-z/-]*' internal/web/ui/src | sed 's/.*:\(\/api.*\)/\1/' | sort -u
/api/intercept
/api/intercept/
/api/intercept/enable
/api/intercept/rules/
```

`/api/intercept/drop-all` is absent while all three siblings are present. Backend complete, UI path
never built.

**Denominator:** 1 of 81 registered non-catch-all routes; 1 of the 7 routes reaching
`internal/intercept`.

---

### 3. `advisory.Catalogue.ByName` — STATE 2, and it corrects a "verified" shared-context claim

The `verified_advisories` context entry states: *"183/183 bundled, 181/183 index-reachable, 2
shadowed-by-design and reachable BY NAME."* The bundling and index counts are right. **The
"reachable by name" half does not hold at the product surface.**

**Proof.** `(*Catalogue).ByName` (`internal/advisory/advisory.go:216`) has **zero non-test
callers**. Its only references are `internal/advisory/advisory_load_test.go:13,29` and
`internal/advisory/index_collision_test.go:92,98` — the latter being
`TestShadowedDefinitionsRemainReachableByName`, a test that proves the *Go API* can reach them.

**Positive control / disambiguation.** A naive `grep ByName` returns ~50 hits and looks alive. Almost
all are `scanner.ByName` (`internal/scanner/catalog.go:167`) and `scanner.BuiltInConfigByName`
(`internal/scanner/audit.go:744`) — **different functions in a different package**, both genuinely
live (e.g. `internal/scanner/enrich.go:11`, `internal/web/api_scanner_configs.go:124`). The
method-vs-function distinction is what makes this one easy to get wrong.

**The live path resolves by index only.** `handleAdvisoryDetail` parses the URL segment as hex and
calls `s.advisories.ByIndex(...)` (`internal/web/api_advisories.go:198-210`). There is no name
branch. The UI agrees: `internal/web/ui/src/lib/data.advisory.ts:51` requests
`` `/api/advisories/${typeIndex ?? ""}` ``.

**Honest restatement:** 183 bundled, 181 addressable by index, and the 2 shadowed definitions are
reachable **only through a Go API that nothing but a test calls** — not through any HTTP route or UI
path. The UI is aware of the index collision and handles the *list* correctly
(`internal/web/ui/src/pages/advisories.tsx:91-96` keys selection on a composite row key precisely
because "type_index alone cannot address a row"), but the *detail* fetch it then issues still goes
by index, so for a shared index the reader gets the winner's definition.

**Not determined:** whether either shadowed advisory is one a user would realistically open. I did
not identify the two definitions by name in this pass.

---

### 4. `tlsprobe` cipher and protocol analysis — STATE 2 (sub-capability)

**Burp side:** Burp reports TLS cipher-suite weaknesses and deprecated protocol versions as issues
distinct from certificate defects.

**burpsy side:** `internal/tlsprobe/tlsprobe.go` computes exactly that.
`Host.WeakCiphers()` (`:99`) flattens weak and insecure suites across every enumerated version;
`Host.DeprecatedProtocols()` (`:113`) lists negotiated versions below TLS 1.2. Both have
**zero non-test callers anywhere in the module** — the taxonomy's STATE 2 criterion exactly. Their
own package tests do exercise them (`internal/tlsprobe/tlsprobe_test.go:37` asserts `WeakCiphers()`
returns 3 entries; `:50` asserts `DeprecatedProtocols()` returns `[tls10]`), which strengthens the
finding rather than weakening it: the analysis is implemented, tested and known-good, and no
production code path reads it.

**The data is fetched and discarded.** The only non-test consumer of tlsprobe is
`checkTLSCertificate` (`internal/scanner/checks_remaining.go:279-303`). It calls
`tlsprobe.Probe(...)`, checks `res.Outcome`, then reads **only** certificate defects:

```go
for name, present := range map[string]bool{
        "expired": host.Expired, "self-signed": host.SelfSigned,
        "hostname mismatch": host.Mismatched, "untrusted issuer": host.Untrusted,
        "revoked": host.Revoked,
} {
```

`host.CipherEnum` — the field both dead methods read — is populated by the probe and never consulted.

**Positive control:** the same grep shape finds the live entry points, `tlsprobe.Probe` and
`tlsprobe.OutcomeCompleted`, at `internal/scanner/checks_remaining.go:279-280`. So tlsprobe is
reached; it is the *analysis half* that is not.

**Why this one is not self-declared.** Unlike jsexec, `infra_coverage.go:26-31` discusses tlsprobe's
limits only in terms of what it *does not perform* ("response-header and subresource analysis"). It
does not say that the cipher analysis it *does* perform is unread. This gap is undocumented.

**Denominator:** 3 of tlsprobe's 19 exported symbols are NO-PROD; 5 have external
references; 11 are internal-only.

---

### 5. `/api/discovery` — STATE 3 (inherited, independently re-confirmed)

Inherited from `GAP_ANALYSIS_ENGINE_CAPABILITIES.md` (commit `a518385`). Re-derived here by a method
that did not consult that document: my all-routes UI sweep flagged it independently as 1 of only 4
routes with zero production-UI reference. Registered `internal/web/server.go:772`, manifest
`internal/web/route_manifest_test.go:207`, handler reaches `core`, `crawler`, `dash`, `extscan`,
`query`. Confirmed.

---

### 6. `tools/comparer.go` — STATE 2 (inherited)

Inherited from `a518385`. Independently corroborated at symbol level: `DiffResult.IsIdentical`
(`internal/tools/comparer.go:88`) and `DiffResult.Changes` (`:94`) are both NO-PROD in my
cross-reference. Not re-litigated.

---

### 7. `internal/http2` `Malformation` vocabulary — STATE 2 residue, **not** a capability gap

Reported because it *looks* like a headline finding and is not — recording the negative so the next
sweep does not re-raise it.

The deliberate-malformation constructor API in `internal/http2/malformed.go` — `SetType` (`:153`),
`SetFlags` (`:158`), `AddFlags` (`:163`), `ClearFlags` (`:168`), `SetStreamID` (`:173`),
`FrameSpec.Malformed` (`:220`) — has **zero non-test callers** (positive control: `http2.Authorise`
matches at `internal/sender/h2program.go:152` and `internal/web/api_protocol.go:94`).

**But the capability is wired, by a different route.** `/api/http2/program` accepts `type`, `flags`,
`stream`, `payload_base64` and `declared_len` as **raw values** (`internal/web/api_protocol.go:87-96`),
so a client can already express every malformation those constructors name — `ClearFlags(x)` is just
writing the flags octet you want. And `http2.Audit` **is** called, at
`internal/sender/h2program.go:153`. So the `Malformation` type is redundant convenience vocabulary,
not an unreachable capability. **STATE 4 for the capability; the vocabulary layer is dead code.**

**Side finding — stale comment.** `internal/http2/malformed.go:45-47` asserts "nothing in
internal/sender or internal/proxy calls Audit or Encode". `internal/sender/h2program.go:153` calls
`Audit`. The comment was true when written and is false at `a619c9a`.

---

### 8. `sequencer` — the near-miss that was NOT STATE 2 (method note)

`internal/sequencer` shows 36 of 54 exported symbols with no external reference, including
`ShannonEntropy`, `ChiSquare`, `SerialCorrelation`, `MonteCarloPi`, `DetectPatterns` and an entire
FIPS 140-2 suite. On the brief's grep-only method this reads as a large STATE 2. **It is not.**

There are two analysis stacks in the package. `AnalyseAs` (`internal/sequencer/report.go:167`) is the
live one — the handler calls it at `internal/web/api_tools.go:925` — and it calls `AnalyseChars`,
`BitsOf`, `BitStatsOf` and `AnalyseFipsBits` **internally**. The UI renders the FIPS output
(`internal/web/ui/src/pages/sequencer.tsx:72-88`). Those symbols are reached; they are just reached
without crossing a package boundary.

The *older* stack — `Analyse` (`sequencer.go:240`) → `ShannonEntropy`/`ChiSquare`/
`SerialCorrelation`/`MonteCarloPi`/`DetectPatterns` — has exactly one non-test caller:
`cmd/burpsy/cli_tools.go:361`. So it is **CLI-only**, which is STATE 4 by the letter of the taxonomy
(it has a non-test caller), but it is a real **capability asymmetry**: the CLI sequencer reports
chi-square, serial correlation, Monte-Carlo pi and duplicate-token detection; the web UI does not.

Genuinely NO-PROD in sequencer: only 3 symbols — `Encoding.MarshalJSON` (`fips.go:95`),
`AnalyseFips` (`fips.go:535`, the token-taking wrapper; the bit-taking `AnalyseFipsBits` is live) and
`AnalyseReport` (`report.go:158`).

**Worth flagging as follow-up work, not as a defect:** the duplicate-token detection
(`DetectPatterns`) missing from the web UI is a Burp Sequencer feature. Recommend a TODO rather than
a fix — it is an addition, not a repair.

---

### 9. `intruder` and `tools` legacy families — dead code, **inverse** of the comparer shape

The comparer pattern is dangerous because **the dead code is the stronger one and the live path is
weaker**, so the feature appears to work while silently under-delivering. Two families here look
like it and are the other way round — the dead code is the *weaker* one. Recorded so they are not
misfiled:

- **`intruder`:** the legacy `AttackType` family — `AttackSniper`/`AttackBatteringRam`/
  `AttackPitchfork`/`AttackClusterBomb` (`internal/intruder/intruder.go:19-22`), plus
  `NewPayloadGenerator`+`GenerateNumbers`/`GenerateFromFile`/`GenerateCustom` (`:350-387`) and
  `Intruder.GetProgress`/`GetResults`/`ClearResults` (`:310-327`) — is dead. It is superseded by
  `AttackKind` (`plan.go:30-43`), which the web uses. All four attack kinds are reachable:
  `ParseAttackKind` (`plan.go`) accepts `sniper`, `battering_ram`, `pitchfork`, `cluster_bomb`, and
  the UI offers all four (`internal/web/ui/src/lib/types.tools.ts:6-9`). **No capability lost.**
- **`tools`:** `Decoder.DecodeJWT` (`tools.go:111`) and `EncodeJWT` (`:132`) are dead — a naive
  3-way split with `strings.Split`. The live path is `JWTDecode` (`codec.go:571`), the stronger
  implementation, reached as the `jwt` layer of `/api/tools/decode` (`codec.go:159-160`). Also dead:
  `Decoder.Reverse` (`:188`), `Grep` (`:279`, a substring line matcher, not even regex) and
  `ExtractRegex` (`:304`). Burp's Intruder grep-match/grep-extract is served by the separate, live
  `intruder.Grep` (`internal/intruder/engine.go:76`). **No capability lost.**

---

### 10. UI-side reimplementation of the Go codec — CLEAN, documented

Checked because it is the comparer shape at the frontend boundary.
`internal/web/ui/src/lib/transforms.ts` implements `urlEncodeKeyChars`, `urlDecode`,
`htmlEncodeKeyChars`, `htmlDecode`, `base64Encode`, `base64Decode` in TypeScript, duplicating layers
of `internal/tools/codec.go`.

**Verdict: not a shadow.** Its header (`transforms.ts:1-7`) gives the rationale — editor hotkeys must
change bytes instantly and "a network round-trip per keystroke would make the editor feel broken" —
and its only importer is `ui/editor.tsx:17`. The Decoder tool itself **does** call the Go engine:
`lib/data.workbench.ts:132` posts to `/api/tools/decode` and `:138` to `/api/tools/encode`. So the Go
codec is the live path for the feature, and `transforms.ts` is a deliberate, scoped, documented
duplicate for hotkeys only.

**Residual risk, stated not overclaimed:** the two can drift (`urlEncodeKeyChars` deliberately encodes
a narrower character set than a full URL layer), and nothing tests them against each other. That is a
drift hazard, not a current defect.

---

## Per-package state table — all 37 rows

`EXP` = exported symbols. `EXT` = have a non-test reference from another package. `INTRA` = referenced
only within their own package (non-test). `T-ONLY` = referenced only from
*another* package's tests. `NO-PROD` = **no non-test reference anywhere in the module** — the
symbol's own package tests may still exercise it. `NO-PROD` is the taxonomy's STATE 2 criterion
("zero non-test callers"), not a claim that nothing at all touches the symbol. `RT` = routes transitively reaching the package (field-aware). `UI` = how many of those
routes are referenced from a non-test UI source file.

| # | Package | EXP | EXT | INTRA | T-ONLY | NO-PROD | RT | UI | State | Basis |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | advisory | 21 | 17 | 1 | 0 | 3 | 4 | 4 | **4** *(sub: 2)* | routed+UI; `ByName` test-only → finding 3 |
| 2 | alpn | 9 | 9 | 0 | 0 | 0 | 0 | 0 | **4** | no route by design; dataplane lib for proxy/sender/scanner; 0 no-prod |
| 3 | bcheck | 88 | 37 | 42 | 0 | 9 | 4 | 4 | **4** | routed+UI |
| 4 | blindxss | 14 | 11 | 2 | 0 | 1 | 1 | 1 | **4** | inherited already-STATE-4; re-confirmed |
| 5 | core | 230 | 164 | 56 | 2 | 8 | 57 | 53 | **4** | routed+UI; 4-route shortfall = the 4 known unreferenced routes |
| 6 | crawler | 106 | 34 | 70 | 0 | 2 | 3 | 2 | **4** | shortfall is `/api/discovery` (finding 5) |
| 7 | dash | 98 | 65 | 17 | 2 | 14 | 11 | 10 | **4** | shortfall is `/api/discovery` |
| 8 | domexec | 44 | 43 | 1 | 0 | 0 | 0 | 0 | **4** | no route; reached via scanner (routed) + `cmd/burpsy`; 0 no-prod |
| 9 | extension | 65 | 19 | 46 | 0 | 0 | 6 | 6 | **4** | routed+UI; 0 no-prod |
| 10 | extscan | 36 | 21 | 14 | 0 | 1 | 4 | 3 | **4** | inherited already-STATE-4; shortfall is `/api/discovery` |
| 11 | http2 | 145 | 42 | 82 | 4 | 17 | 1 | 1 | **4** *(residue)* | routed+UI; `Malformation` vocabulary dead → finding 7 |
| 12 | httputil | 6 | 4 | 2 | 0 | 0 | 0 | 0 | **4** | no route; lib for proxy/sender; 0 no-prod |
| 13 | intercept | 48 | 29 | 18 | 0 | 1 | 7 | 6 | **4** *(sub: 3)* | shortfall is `/api/intercept/drop-all` → finding 2 |
| 14 | intruder | 150 | 63 | 67 | 1 | 19 | 5 | 5 | **4** | routed+UI; legacy family dead → finding 9 |
| 15 | **jsexec** | 14 | **0** | 10 | 0 | 4 | 0 | 0 | **2** | **zero importers of any kind → finding 1** |
| 16 | matchreplace | 25 | 25 | 0 | 0 | 0 | 2 | 2 | **4** *(at this SHA)* | routed+UI; 0 no-prod. See caveat below |
| 17 | netauth | 36 | 30 | 6 | 0 | 0 | 2 | 2 | **4** | routed+UI; 0 no-prod |
| 18 | oob | 9 | 9 | 0 | 0 | 0 | 5 | 5 | **4** | inherited already-STATE-4; re-confirmed, 0 no-prod |
| 19 | organizer | 9 | 8 | 0 | 0 | 1 | 2 | 2 | **4** | routed+UI **via `Server` field** — the grep false negative |
| 20 | persist | 38 | 30 | 8 | 0 | 0 | 14 | 14 | **4** | routed+UI via field; 0 no-prod |
| 21 | pool | 38 | 28 | 10 | 0 | 0 | 9 | 9 | **4** | routed+UI; 0 no-prod |
| 22 | proxy | 58 | 36 | 19 | 0 | 3 | 2 | 2 | **4** | routed+UI |
| 23 | query | 11 | 9 | 2 | 0 | 0 | 15 | 14 | **4** | shortfall is `/api/discovery`; 0 no-prod |
| 24 | report | 7 | 7 | 0 | 0 | 0 | 1 | 1 | **4** | routed+UI; 0 no-prod |
| 25 | scanner | 774 | 213 | 473 | 0 | 88 | 17 | 17 | **4** | routed+UI. 88 dead of 774 — large but it is a check catalog; not swept per-check |
| 26 | schedule | 31 | 20 | 9 | 0 | 2 | 4 | 4 | **4** | routed+UI |
| 27 | sender | 117 | 59 | 49 | 0 | 9 | 11 | 11 | **4** | routed+UI |
| 28 | sequencer | 54 | 18 | 33 | 0 | 3 | 2 | 2 | **4** | routed+UI; CLI/web asymmetry → finding 8 |
| 29 | session | 84 | 57 | 26 | 0 | 1 | 7 | 7 | **4** | routed+UI |
| 30 | sitemap | 11 | 8 | 1 | 0 | 2 | 1 | 1 | **4** | routed+UI |
| 31 | tlsprobe | 19 | 5 | 11 | 0 | 3 | 0 | 0 | **4** *(sub: 2)* | no route; reached via scanner check. Analysis half dead → finding 4 |
| 32 | toollog | 25 | 20 | 4 | 1 | 1 | 9 | 9 | **4** | routed+UI |
| 33 | tools | 66 | 26 | 30 | 3 | 7 | 3 | 3 | **4** *(sub: 2)* | routed+UI; `comparer.go` STATE 2 inherited → finding 6 |
| 34 | upstream | 41 | 32 | 9 | 0 | 0 | 1 | 1 | **4** | routed+UI; 0 no-prod |
| 35 | upstream/upstreamtest | 9 | 3 | 1 | 3 | 2 | 0 | 0 | **n/a** | test harness by design; importers are proxy/sender/upstream **tests** only |
| 36 | vulnapp | 3 | 2 | 1 | 0 | 0 | 0 | 0 | **4** | no route by design; deliberate target app for `cmd/demo-target`, `cmd/crawl-scan-demo` |
| 37 | web | 70 | 43 | 23 | 0 | 4 | 0 | 0 | **4** | the host package itself; 82 routes originate here |

### Inherited rows, with source

| Package / capability | Inherited state | Source | This pass |
|---|---|---|---|
| `tools/comparer.go` word/byte Myers diff | STATE 2 | `GAP_ANALYSIS_ENGINE_CAPABILITIES.md` @ `a518385` | Corroborated at symbol level (finding 6) |
| `/api/discovery` ffuf sweep | STATE 3 | same | Independently re-derived (finding 5) |
| `internal/oob` | STATE 4 | same | Re-confirmed: 9/9 exported have external refs, 0 no-prod |
| `internal/blindxss` | STATE 4 | same | Re-confirmed: routed + UI (`lib/data.collab.ts`) |
| `internal/extscan` (as a package) | STATE 4 | same | Re-confirmed: 4 routes, 3 UI-reached |

### Caveat on row 16 (matchreplace)

At `a619c9a` matchreplace is STATE 4 by every test in this sweep: 25/25 exported symbols have
external references, zero dead, 2 routes, both UI-reached. A peer agent has separately reported a
**STATE 5** in `/api/proxy/matchreplace` at HEAD `ede8f1f` (`request_param_name` /
`request_param_value` accepted by the parser but unhandled in `applyOne`, falling through to a
body-wide rewrite), with behavioural proof. `ede8f1f` is an **ancestor** of my baseline, so that
defect is very likely present at `a619c9a` too. I did **not** re-run their proof and I am not
claiming their finding as mine — state 5 outranks state 4, so **treat row 16 as provisional and
defer to `finding_matchreplace_param_targets`.**

---

## What I did not determine

- **Per-check sweep of `internal/scanner`.** 88 of 774 exported symbols are NO-PROD. At
  ~11% that is in line with a large catalog of check definitions, but I did not classify them
  individually. A dead *check* would be a STATE 2 worth finding, and this sweep would not have
  distinguished one from a dead helper. **Recommend this as the next unit of work** — it is the
  single largest unexamined surface left.
- **No STATE 5 claims.** The taxonomy requires execution, not reading, and I ran no scratch
  executions this pass. Everything above is a reachability claim, which reading *can* establish.
  Absence of STATE 5 findings here means I did not look for them, not that none exist.
- **`internal/core` and `internal/bcheck` dead symbols** (8 and 9 respectively) were not
  individually triaged.
- **`section-marker`** — see below.

## Method caveats (things that could make this table wrong)

1. **Method-name matching is by name, not by receiver type.** For methods I fall back to a bare
   selector match across packages, so a method named `List` on one type is credited if *any* package
   calls `.List()` on anything. This biases toward **over**-reporting reachability, i.e. toward
   missing STATE 2, never toward inventing one. Every STATE 2 claim above is a package-level
   function or a distinctively-named method (`WeakCiphers`, `DeprecatedProtocols`, `ByName`), and each
   was hand-verified with a grep plus positive control rather than trusted from the tool.
2. **Reflection is invisible to the AST walk, and it inflates the NO-PROD column.**
   `MarshalJSON`/`UnmarshalJSON`/`MarshalText`/`String` are invoked by `encoding/json` and `fmt`
   through interfaces, so my tool sees no caller and files them NO-PROD. **13 of the 157 NO-PROD
   entries (8.3%) are these**, and they are false positives. I counted them rather than estimating:

   ```
   $ grep 'NO-PROD' /tmp/w5_dead.txt | tr ';' '\n' \
       | grep -c 'MarshalJSON\|UnmarshalJSON\|method:.* String (\|MarshalText\|UnmarshalText'
   13
   $ grep 'NO-PROD' /tmp/w5_dead.txt | tr ';' '\n' | grep -c '('
   157
   ```

   None of the STATE 2 findings above rests on such a symbol. `go:generate`, build tags and struct
   tags are likewise invisible.

3. **Symbols used only by their own package's tests are counted NO-PROD, by design.** I found this
   by auditing my own output: `scanner.AnalyzeDOMScript` (`internal/scanner/dom.go:713`) shows
   NO-PROD despite 33 calls in `internal/scanner/dom_test.go`. That is **correct** under the
   taxonomy — STATE 2 is defined as "zero *non-test* callers" — but it means NO-PROD must never be
   read as "nothing references this". Every STATE 2 finding above was re-verified against this
   distinction by hand: jsexec, `tlsprobe.WeakCiphers`, `tlsprobe.DeprecatedProtocols` and
   `advisory.Catalogue.ByName` are all exercised by their own tests and reached by no production
   caller, which is the finding, not a contradiction of it.
4. **UI reachability is a substring match on the route path** in non-test `.ts`/`.tsx`. A route
   assembled at runtime from fragments would be missed. Rated low risk: all three positive controls
   (`/api/history`, `/api/sitemap`, `/api/sequencer/analyse`) matched in the expected data layer, and
   77 of 81 routes matched — a systematic miss would show a far worse hit rate.
5. **Per taxonomy rule 5, nothing here is gated.** CI at HEAD runs gofmt, build, vet, `go test` only
   (`.github/workflows/go.yml:84-103`). I ran no TypeScript typecheck and no e2e suite, and I make no
   WORKING claim resting on either. My claims are reachability claims derived from source at a pinned
   SHA, which is the evidence class the taxonomy admits for states 0–4.
