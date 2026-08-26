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

# W4 — What does burpsy's green build actually prove?

Analyst W4. Measurement contract: `/root/burpsy-parity/TAXONOMY.md`.
Feeds §6 of `/root/burpsy-parity/BURP_PARITY_GAP_ANALYSIS.md`.

---

## BASELINE

```
$ git rev-parse HEAD
638c48005c9b4998ead63de2822bb176aa591147

$ git status --short --branch
## orchestry/tsk_KBUxW7m/auto-cto-burp-parity-gap-analysis-measur
   (no modified files — working tree clean)

$ git log -1 --format='%H %cI %s'
638c48005c9b4998ead63de2822bb176aa591147 2026-08-26T20:04:37+03:00 \
  logger: two-axis tool filters, and the matchreplace refusal they surfaced
```

**Baseline drift, and it matters.** TAXONOMY names `a619c9a`; the master report was
authored at `9194df6`. This wave measures `638c480`, which is **four commits later** and
contains `9194df6` → `8700e2e` (a revert) → `638c480` (a re-fix). Every file:line below is
at `638c480` unless explicitly labelled otherwise. Where a master-report finding has
changed state between `9194df6` and `638c480` I say so rather than restating the old text.

**Shared-checkout drift DURING this wave — disclosed, and checked.** HEAD moved under me
mid-analysis, from `638c480` to `804e47c`, because another analyst committed to the same
worktree. I re-checked rather than assuming:

```
$ git log --oneline 638c480..HEAD
804e47c parity: the config surface is fully mapped — 41 of 85 panels wired, 0 stubs
6e83ced parity: fold in the UI sweep, the package census, and a correction to our own claim

$ git diff --stat 638c480..HEAD -- burpsy-go/ .github/
(empty)
$ git diff 638c480..HEAD -- burpsy-go/ .github/ | wc -l
0
```

**Both new commits touch documentation only.** Not one byte of `burpsy-go/` or `.github/`
changed. Every measurement, coverage number and `file:line` in this report is therefore
valid at `804e47c` as well as at `638c480`, and the working tree was clean at both. Stating
this rather than silently re-anchoring, because §6.4 already records "a measurement taken
against the working tree and reported as committed state" as one of the seven.

### CI facts — verified cheaply, as instructed (all CONFIRMED)

```
$ ls .github/workflows/
go.yml  release.yml                                  # exactly 2, as §6.3 states

$ grep -n 'gofmt\|go build\|go vet\|go test' .github/workflows/go.yml
84:      - name: gofmt
93:      - name: go build      94:        run: go build ./...
96:      - name: go vet        97:        run: go vet ./...
102:      - name: go test     103:        run: go test ./... -count=1 -timeout 1700s
```

Negative grep **with the positive control the taxonomy requires** — the same command,
same corpus, finds the Go steps it should:

```
$ grep -rn 'bun run check\|tsc --noEmit\|playwright\|behaviour.spec\|bun test' .github/
(no output; exit 1)
```

§6.3 holds at `638c480`: **the four gates are gofmt / build / vet / test, and nothing
frontend is gated.** I did not re-derive the 118-assertion figure; it is §6.3's and I take
it as given per my brief.

---

## HEADLINE — the answer to "what does the green build prove?"

Four sentences, then the evidence.

1. **The gated Go suite is real and it is large.** `go test ./...` at `638c480` runs **2 213
   `Test*` functions across 243 test files in 46 packages**, all green, in ~8 minutes.
   **69.0 % per-package**, and **77.7 % of the whole tree** (78.3 % excluding demo and
   fixture packages) once measured with `-coverpkg=./...`. It is not a rubber stamp.
2. **But it is measured with three specific blind spots**, each of which is *NOT GATED*
   rather than *NOT WORKING*: **no `-race`**, **no `-coverpkg`-style whole-tree coverage
   target**, and **the entire CLI at 15.8 %**.
3. **On the vocabulary/handler defect class the master report treats as endemic, §6.5 is
   now out of date.** The exemplar defect is **fixed at `638c480`**, and the antidote
   pattern has in fact been propagated — I verified **12 structurally exhaustive tests** by reading them, across
   7 packages (§3.5). A full AST sweep of every enum and every string-literal `switch` in the tree
   found **no second live instance** of "parser accepts N, consumer handles M<N, silently
   defaults."
4. **What the sweep did find instead is a smaller, sharper class**: three
   *un-tested* boolean coercions and one *hand-maintained* exhaustiveness list where the
   antidote's own guarantee does not hold.

---

## 1. Coverage of the Go suite that actually gates

### Command

```
$ cd burpsy-go && go test ./... -coverprofile=/tmp/w4cover.out -covermode=atomic
EXIT=0        # whole suite green at 638c480, ~8 min wall (internal/scanner alone 453 s)

$ go tool cover -func=/tmp/w4cover.out | tail -1
total:  (statements)  69.0%
```

**Methodological caveat, stated up front because it changes how the table reads.** With
`-coverprofile` and *no* `-coverpkg`, Go measures each package **only against its own
tests**. A package exercised heavily by a *neighbour's* tests still reads 0 %. So the table
below is "how well is this package tested *by itself*", which is the right question for
"what does a change to this package get checked against", but it is **not** "how much of
this code runs during CI". A cross-package run is in §1.4.

### 1.1 Per-package, sorted worst-first (46 packages, all `ok`)

| Package | Coverage | User-facing capability? |
|---|---|---|
| `cmd/blindxss-demo` | **0.0 %** (no test files) | no — demo |
| `cmd/crawl-scan-demo` | **0.0 %** (no test files) | no — demo |
| `cmd/demo-target` | **0.0 %** (no test files) | no — test fixture |
| `cmd/desktop` | **0.0 %** (no test files) | **YES — the desktop entrypoint** |
| `cmd/live-test` | **0.0 %** (no test files) | no — harness |
| `cmd/xsschallenge` | **0.0 %** (no test files) | no — fixture |
| `internal/httputil` | **0.0 %** (no test files) | **YES — imported by 6 files** |
| `internal/upstream/upstreamtest` | 0.0 % (no test files) | no — test helper |
| `internal/vulnapp` | 0.0 % (no test files) | no — deliberate vulnerable app |
| **`cmd/burpsy`** | **15.8 %** | **YES — the entire CLI** |
| `internal/alpn` | 35.4 % | yes (TLS ALPN negotiation) |
| `internal/domexec` | 50.9 % | yes (DOM execution / headless) |
| `internal/tlsprobe` | 51.4 % | yes |
| `internal/sitemap` | 60.0 % | **YES — the site-map tool** |
| `internal/toollog` | 63.1 % | **YES — the Logger tool** |
| `internal/tools` | 64.3 % | **YES — Decoder / Encoder tool** |
| `internal/advisory` | 66.2 % | yes (issue advisories) |
| `internal/sequencer` | 66.4 % | **YES — the Sequencer tool** |
| `internal/persist` | 70.5 % | yes |
| `internal/matchreplace` | 70.7 % | yes |
| `internal/upstream` | 73.2 % | yes |
| `internal/organizer` | 73.3 % | yes |
| `internal/pool` | 74.5 % | yes |
| `pkg/graphqlmap` | 74.6 % | yes |
| `internal/proxy` | 75.0 % | yes |
| `internal/schedule` | 75.2 % | yes |
| `internal/oob` | 76.4 % | yes |
| `internal/bcheck` | 77.2 % | yes |
| `internal/intercept` | 77.2 % | yes |
| `internal/extscan` | 77.5 % | yes |
| `internal/sender` | 78.2 % | yes |
| `internal/core` | 79.0 % | yes |
| `internal/jsexec` | 80.0 % | yes |
| `internal/session` | 80.0 % | yes |
| `internal/dash` | 81.3 % | yes |
| `cmd/conform` | 81.4 % | no — tooling |
| `internal/intruder` | 82.6 % | yes |
| `internal/blindxss` | 82.8 % | yes |
| `internal/scanner` | 83.1 % | yes |
| `internal/crawler` | 83.9 % | yes |
| `internal/netauth` | 86.3 % | yes |
| `internal/extension` | 88.9 % | yes |
| `internal/http2` | 89.5 % | yes |
| `internal/query` | 90.3 % | yes |
| `internal/report` | 95.7 % | yes |
| **`internal/web`** | **72.3 %** | **YES — every HTTP API the UI calls** |

### 1.2 The near-zero packages that implement user-facing capability

Three, and only three, matter:

**`cmd/burpsy` — 15.8 %. This is the finding.** The CLI is a first-class surface (it is how
the Go port is driven headlessly) and its coverage profile has 104 measured functions, of
which the entire capture/history family is at zero:

```
$ go tool cover -func=/tmp/w4cover.out | grep cmd/burpsy | sort -k2 -t'%' | head
cmd/burpsy/cli_capture.go:101  cmdHistory     0.0%
cmd/burpsy/cli_capture.go:155  exchangeView   0.0%
cmd/burpsy/cli_capture.go:182  cmdMessage     0.0%
cmd/burpsy/cli_capture.go:207  cmdExchange    0.0%
cmd/burpsy/cli_capture.go:231  cmdStats       0.0%
```

This is the surface with the **densest concentration of accepted-input vocabularies in the
whole tree** — my switch sweep (§3.1) put **18 of 59** string-literal `switch`-with-`default`
sites in `cmd/burpsy/cli_*.go` alone, more than any other directory. A subcommand
vocabulary at 15.8 % coverage is the highest-leverage untested surface in the repo.

**`internal/httputil` — 0.0 % here, but see §1.4: the real figure is 82.0 %.**
`burpsy-go/internal/httputil/httputil.go` is 214 lines of shared HTTP helpers with **no test
file of its own** (6 importers; positive control — the same `grep -rln` idiom finds 4
importers for `internal/tools`, so the corpus and pattern are right). The cross-package run
shows **82.0 % of its 100 statements execute during CI**, driven entirely by neighbours'
tests. So this is a **maintainability** gap — a change to it fails in someone else's package
with someone else's error message — **not** a coverage gap. Recording it as "0 % untested"
would have been a fifth false denominator.

```
$ go list -f '{{.ImportPath}} {{len .TestGoFiles}} {{len .XTestGoFiles}}' ./... | awk '$2==0 && $3==0'
  → 9 packages, of which the only production ones are internal/httputil and cmd/desktop
```

**`cmd/desktop` — 0.0 %, no test files, and 0 % cross-package too.** The cross-package run
sizes it at **66 statements, none executed**. A thin entrypoint, entirely unexercised. Small
enough that it is a note rather than a finding.

The rest of the 0 % list (`blindxss-demo`, `crawl-scan-demo`, `demo-target`, `live-test`,
`xsschallenge`, `upstreamtest`, `vulnapp`) are demos, fixtures and test helpers — correctly
untested, and **not** findings. Counting them as gaps would be a fifth false denominator.

### 1.3 The `-race` hole — a distinct, cheap, and load-bearing gap

```
$ grep -rn 'race' .github/workflows/
(no output; exit 1)
```
Positive control: the same directory yields `go test ./... -count=1 -timeout 1700s`
(`.github/workflows/go.yml:103`) — so the corpus is right and the absence is real.

**CI never runs `go test -race`.** This is not a coverage number, it is a whole class of
assertion that is written down and never evaluated — see §4.1, where two concurrency tests
exist whose *only* documented failure mode is under `-race`.

### 1.4 Cross-package coverage — what CI actually executes

The per-package table above understates several packages badly, because it credits a
package only for its **own** tests. Re-run with `-coverpkg=./...` so every test binary
measures the whole tree, then merged (a statement counts as covered if **any** binary
reached it):

```
$ go test ./... -coverprofile=/tmp/w4coverpkg.out -coverpkg=./...
EXIT=0
$ go tool cover -func=/tmp/w4coverpkg.out | tail -1
total:  (statements)  77.7%
```

**77.7 % of 31 176 statements execute during the gated suite; 78.3 % of 28 727 once the six
demo/fixture/tooling packages are removed.**

The packages whose story changes:

| Package | own-tests | whole-tree | reading |
|---|---|---|---|
| `internal/httputil` | 0.0 % | **82.0 %** | exercised entirely by neighbours — a *maintainability* gap, not a coverage one |
| `internal/sitemap` | 60.0 % | **92.0 %** | fine |
| `internal/tlsprobe` | 51.4 % | **75.7 %** | fine (and its `tlsx` skip is CI-documented) |
| `internal/domexec` | 50.9 % | **74.9 %** | fine |
| `internal/alpn` | 35.4 % | **68.8 %** | fine |
| `internal/tools` | 64.3 % | **72.3 %** | fine |
| **`cmd/burpsy`** | 15.8 % | **15.8 %** | **unchanged — nothing else drives the CLI either** |
| `cmd/desktop` | 0.0 % | **0.0 %** (66 stmts) | unchanged |
| `internal/sequencer` | 66.4 % | **70.5 %** | lowest non-CLI production package |
| `internal/web` | 72.3 % | **72.3 %** | unchanged — it is the top of the stack |

**The single conclusion that survives both measurements: `cmd/burpsy` at 15.8 %.** Every
other apparent hole closes once you measure the whole tree. The CLI's does not, because
nothing else in the repo drives it.


---

## 2. Do the tests test behaviour, or shape?

### 2.1 The right denominator, and why the obvious one is wrong

The naive metric — "how many assertions only look at `rec.Code`" — gives a flattering and
meaningless answer (**2 of 42** by a first pass). It is meaningless because for a
*pure-transform* endpoint like `POST /api/tools/encode`, the response **is** the effect;
a response-only assertion there is a full behaviour test.

The distinction only bites on **config-mutating endpoints**, where the API's job is to
change what some *other* subsystem does later. burpsy conveniently classifies its own
routes for exactly this: `internal/web/route_manifest_test.go:53-83` defines a `riskClass`
per route, and `riskLocal` ("mutates burpsy's own state — annotations, rules, settings —
without sending traffic") plus `riskScope` are precisely the set in question.

```
$ python3 <parse `var manifest` at internal/web/route_manifest_test.go:119>
entries: 82
riskRead 37 | riskLocal 14 | riskAttack 10 | riskCredential 7 | riskScope 6
riskEgress 3 | riskAsset 2 | riskExecute 2 | riskDestructive 1
```

**82 routes**, of which **20 are config-mutating** (`riskLocal` 14 + `riskScope` 6).

### 2.2 The measurement

For each config-mutating route, I counted the `internal/web` test functions that name that
path, and how many of those reach **past the response** — i.e. reference an unexported
`Server` engine handle (the 35 non-plumbing fields of `type Server struct`, enumerated from
`internal/web/server.go`), stand up an `httptest.NewServer` target, dial, or call `.Apply(`.

| Config-mutating route | tests naming it | with an effect signal |
|---|---|---|
| `/api/tools/rules` (match & replace) | 7 | **5** |
| `/api/scope` | 15 | **6** |
| `/api/exchange/` | 7 | **3** |
| `/api/tools/organizer` | 2 | **2** |
| `/api/scanner/config` | 5 | **2** |
| `/api/pools` | 15 | **1** |
| `/api/blindxss/payload` | 4 | **0** |
| `/api/config/import` | 3 | **0** |
| `/api/extensions/unload` | 2 | **0** |
| `/api/intercept/` | 1 | **0** |
| `/api/intercept/drop-all` | **0** | 0 |
| `/api/intercept/enable` | **0** | 0 |
| `/api/intercept/rules/` | 1 | **0** |
| `/api/network/proxy` | 7 | **0** |
| `/api/network/settings` | 3 | **0** |
| `/api/pools/` | 5 | **0** |
| `/api/proxy/options` | 3 | **0** |
| `/api/proxy/passthrough` | 4 | **0** |
| `/api/tasks/` | 1 | **0** |
| `/api/tools/organizer/` | **0** | 0 |

**85 tests name a config-mutating route; 19 of them (22 %) reach past the response.**
**14 of the 20 routes (70 %) have no `internal/web` test that observes an effect at all,
and 3 of the 20 have no `internal/web` test that names them at all.**

Whole-package figure, same method: of **194** `internal/web` tests that drive the API,
**75 reach past the response and 119 (61 %) assert only against the API's own reply.**

### 2.3 NOT GATED vs NOT WORKING — the caveat that must not be dropped

A zero in the right-hand column above is **not** proof the effect is untested. For at least
one route I checked by hand it is tested **one package down**. Worked example:

- `internal/web/proxy_options_api_test.go:55` `TestProxyOptionsPutFlipsAKeyAndReportsConfirmedState`
  PUTs `{"remove_all_javascript": true}`, asserts `200`, and asserts the response echoes
  `true`. **That is a textbook shape test.** It would pass unchanged if the proxy ignored
  the flag entirely.
- But `internal/proxy/options_test.go:52`
  `Test_each_response_rule_rewrites_the_markup_it_names` runs `ApplyResponse` over real
  markup per rule and asserts the rewritten bytes, and
  `internal/proxy/options_test.go:353` `Test_response_rules_rewrite_real_traffic_and_history_agrees`
  does it through real traffic.

So the honest claim is narrower and still sharp:

> **The `internal/web` layer is predominantly tested for shape.** The effect testing that
> exists lives in the engine packages. That is a defensible architecture — *provided*
> something binds the API vocabulary to the engine's applier set. §3 is about the places
> where nothing does.

### 2.4 The counter-example that shows the good pattern

`internal/web/matchreplace_proxy_share_test.go:24`
`TestWebLayerAndProxyObserveOneSharedMatchReplaceRuleset` is what a behaviour test of a
config endpoint looks like: it PUTs the rules the page sends to `/api/tools/rules`, then
asserts on the `*matchreplace.RuleSet` **the proxy config was built from**, and finally
calls `shared.Apply(DirRequest, ...)` and asserts the header was rewritten. Its own comment
names the failure it exists to catch — "the page renders a list the proxy no longer
honours." That is the template the other 14 routes lack.

---

## 3. The vocabulary/handler gap, systematically

### 3.0 FIRST, A CORRECTION TO THE MASTER REPORT — the exemplar defect is FIXED at `638c480`

My brief, and §3/§6.5 of the master report, describe `/api/proxy/matchreplace` accepting
`request_param_name` / `request_param_value`, returning 200, and falling through
`applyOne`'s `default:` to a body-wide rewrite. **That is true at `9194df6` and false at
`638c480`.** Both halves were fixed, in the last commit on this branch.

```
$ git log --oneline -- burpsy-go/internal/matchreplace/
638c480 logger: two-axis tool filters, and the matchreplace refusal they surfaced   <-- HEAD
8700e2e Revert "fix(matchreplace): an unimplemented target must change nothing…"
9194df6 fix(matchreplace): an unimplemented target must change nothing…            <-- report SHA
```

**Engine side** — `burpsy-go/internal/matchreplace/matchreplace.go:242-272` (`applyOne`). `applyOne`'s
`default:` now `return nil`, with a 20-line comment recording *both* the original defect
and why the reverted attempt (`return raw`) was also wrong: `raw` is non-nil, so it reads
as "the rule fired", which would "mark the message changed, count a modification that never
happened, and run `fixContentLength` over an untouched body — trading a wrong rewrite for a
wrong count."

**API side** — `burpsy-go/internal/web/api_toolkit.go:613-637` (`targetToCategory`). `targetToCategory` now has
five accepting cases, and its `default:` consults
`matchReplaceUnappliedTargets` (`api_toolkit.go:576-579`) to **400 by name**:
`rule_type %q is declared by the engine as %s but has no applier yet … refused until it is
implemented`.

**Residual state.** Per TAXONOMY rule 7 this is now a documented **CAPABILITY GAP** (5 of 7
Burp `rule_type` values implemented), not a defect. Confirmed no UI exposure:

```
$ grep -rn "request_param_name|request_param_value" --include=*.ts --include=*.tsx --include=*.go .
  → 7 hits, all in burpsy-go/internal/web/api_toolkit.go and its tests. Zero in the UI.
```

**And the antidote WAS propagated** — §6.5's "did not propagate" is out of date:
`burpsy-go/internal/web/matchreplace_target_test.go:139`
`TestEveryEngineTargetHasANameAndOnlyAppliableOnesRoundTrip` walks every `Target`, requires
each to have a wire name, and requires the unappliable ones to be **refused** by
`targetToCategory`; `internal/matchreplace/unapplied_target_test.go` proves the no-op
behaviourally, including a test that the five *implemented* targets still fire so the fix
cannot have disabled them.

### 3.1 The systematic sweep — method

Two AST passes over `burpsy-go` at `638c480`, excluding `_test.go` and `bench/`:

**Pass A — every `switch` on a string vocabulary with a `default`.**
316 `switch` statements with ≥2 cases; **59** switch on string literals *and* carry a
`default` (`/tmp/w4vocab.txt`). Directory distribution — and this is itself a finding:

| Directory | string-vocab switches w/ default |
|---|---|
| `cmd/burpsy/cli_*.go` | **18** (the CLI, at 15.8 % coverage) |
| `internal/web/api_*.go` | 10 |
| `internal/bcheck` | 5 |
| `internal/intruder` | 6 |
| `internal/scanner` | 3 |
| everything else (14 dirs) | 17 |

**Pass B — every Go const-enum, and every `switch` that dispatches on its members**, with
per-switch coverage and missing-member list. 61 partial switches reported; after removing
cross-package type-name collisions (`Kind`, `Severity`, `Outcome`, `Direction`, `uint8`) and
switches that are legitimately partial by design (`String()` methods, per-arm helpers),
**every remaining one was read by hand.**

### 3.2 Result: NO second live instance of the exemplar defect

I could not find another place where an API or UI parser accepts a vocabulary value that
the consumer silently mis-handles. The parser/consumer discipline in this tree is high, and
the negative deserves to be recorded with its evidence:

| Vocabulary | Parser | Consumer | Verdict |
|---|---|---|---|
| Intercept match fields (7 wire names) | `internal/intercept/intercept.go:71-89` `ParseField` — errors on unknown | `internal/intercept/intercept.go:190-212` `FieldValue` — **all 7 cases present** | MATCHED |
| Codec layers (8, with 18 aliases) | `internal/tools/codec.go:59-77` `ParseLayer` — returns `false`, no guess | `codec.go:121-166` `Decode` / `:173-208` `Encode` — 8 cases each, `default:` = `"unknown layer"` error | MATCHED |
| Upstream proxy schemes | `internal/upstream/upstream.go:112-128` — `default:` 400s naming the scheme | `internal/upstream/upstream.go:268-287` `DialContext` — `default:` at `:281-285` **errors** with "the proxy was ignored is the one failure this package exists to make impossible" | MATCHED |
| Intruder payload-processing rules (9) | `internal/intruder/process.go:174-215` `NewChain` — `default:` returns `unknown rule %q` | `internal/intruder/process.go:253-296` `Apply` — 9 cases, closed enum | MATCHED |
| Sequencer token location (`cookie`/`header`/`body_regex`) | `internal/web/api_sequencer_capture.go:87-110` `compile` — `default:` names the three accepted kinds | same file | MATCHED |
| Session `ExtractHow` union (`regex` / `json_path` / `"whole"`) | `internal/web/api_session.go:97-139` — refuses both-arms and unknown strings | `internal/session/session.go:397-429` `runJSONPath` — `default:` returns `ExtractInert` **with a reason** | MATCHED |
| BCheck `given … insertion point` (`any`\|`query`\|`header`\|`body`\|`cookie`) | `internal/bcheck/parser.go:478-517` `frequency` — errors on any other word | `internal/bcheck/insertion.go:594-601` `dslAddressable` — exactly the same 4 | MATCHED (documented 4-of-16 restriction) |
| History query DSL fields × operators | `internal/query/query.go:463-473` `fieldAllows` — an explicit **matrix**, `default: false` | `query.go:701-735` `matchCmp`, `:739-759` `strOp`, `:761-781` `statusOp` | MATCHED — and see §3.4 |

**A second in-tree antidote, not previously credited.** `internal/query/query.go:147-148`
makes exhaustiveness a *compile* error rather than a test:

```go
fieldCount = iota   // "adding a field above without extending that array is a compile
                    //  error rather than a silent out-of-range panic"
```

### 3.3 What the sweep DID find — four live instances, ranked

#### 3.3.1 `proxy.OptionKeys` — an option can be listed, set, 200'd, and do nothing — STATE 4 (no defect today; unguarded)

**Shape.** `internal/proxy/options.go:42-63` declares 6 `OptionKey` constants;
`options.go:66-75` lists them in `OptionKeys`; `options.go:98-104` lists the 5
response-direction ones in `responseRules`. The applier is **not a switch** —
`options.go:367-381` is a run of `if enabled[K] { … }`, so a key present in `OptionKeys` and
`responseRules` but absent from that run is a **silent no-op**: listed by the API, settable,
confirmed `true` in the PUT response, and it does nothing.

**Would a test catch it? NO.**
`internal/proxy/options_test.go:52` `Test_each_response_rule_rewrites_the_markup_it_names`
is a genuine per-rule effect test — but over a **hand-written table of 5 cases**, with no
assertion that the table's length equals `len(responseRules)`.

Negative grep, with the positive control the taxonomy requires:
```
$ grep -rn 'responseRules|len(OptionKeys)|len(proxy.OptionKeys)' --include=*_test.go .
internal/web/proxy_options_api_test.go:47  len(view.Keys) != len(proxy.OptionKeys)
internal/web/proxy_options_api_test.go:50  len(view.Options) != len(proxy.OptionKeys)
internal/proxy/options_test.go:314         len(snap) != len(OptionKeys)
```
Three tests bind the **listing** to `OptionKeys`. **Zero** bind the **applier**. `responseRules`
appears in no test at all. The listing cannot drift; the applier can.
This is the `builtInConfigKeys` problem exactly, in a package that never got the fix.

#### 3.3.2 `category` — two 2-value vocabularies, unvalidated, defaulting in *opposite* directions — STATE 4 (unguarded)

```
internal/web/api_toolkit.go:692   if spec.Category == "regex" { cat = CategoryRegex }   // else LITERAL
internal/web/api_toolkit.go:782   if spec.Category == "regex" { cat = CategoryRegex }   // else LITERAL
internal/web/api_intercept.go:167 if sp.Category == "literal" { cat = CategoryLiteral } // else REGEX
```

Neither validates. `"Regex"`, `"REGEX"`, `"rege"`, `""` or a field the client forgot to send
all fall to the else-branch, **200 OK**, and the rule runs with the *other* interpretation.
The two surfaces disagree about which way to fall: a match/replace rule degrades to
**literal**, an intercept rule degrades to **regex**. For intercept that is the more
dangerous direction — a literal pattern containing `.` or `*` reinterpreted as a regex holds
traffic the operator did not select.

Contrast `rule_type` **five lines above** at `api_toolkit.go:690`, which goes through
`targetToCategory` and 400s by name. The same handler validates one field and coerces the
other.

**Would a test catch it? NO.**
```
$ grep -rn 'category' internal/web/*_test.go | grep -iE 'bad|unknown|invalid|typo'
(no output)
```
Positive control: the same corpus and idiom finds the `rule_type` refusal tests —
`internal/web/matchreplace_target_test.go:178` iterates `{"request_param_name",
"request_param_value"}` and asserts each is refused.

#### 3.3.3 BCheck metadata keys — tolerant by design, silent by consequence — CAPABILITY GAP, not a defect

`internal/bcheck/parser.go:388-411` switches on the metadata key and ends:
```go
default:
    // Unknown metadata fields are tolerated (v2-beta extensions).
```
A `.bcheck` file is operator-supplied input. `severty: high` is accepted, ignored, and the
check runs with no severity. **Graded as a documented deliberate divergence per TAXONOMY
rule 7**, and no test can catch it *by construction* — but it is the same failure shape and
belongs in the list. Note the contrast with the *same file* at `parser.go:668-689`, where
the `report issue` field switch ends `default: return nil, p.errf("unknown report issue
field %q", …)`. One parser in one file refuses; the other tolerates.

#### 3.3.4 The propagated antidote's own list is hand-maintained — a latent regression

`internal/web/matchreplace_target_test.go:139-146` opens:
```go
// This test walks every declared Target rather than an enumerated list of names, so
// adding a Target to the engine without teaching both directions about it fails here.
func TestEveryEngineTargetHasANameAndOnlyAppliableOnesRoundTrip(t *testing.T) {
    all := []matchreplace.Target{ …seven literals… }
```
The comment claims it "walks every declared Target". **It does not** — it walks a
hand-written slice of 7. Add an eighth `Target` to `matchreplace.go:18-26` and this test
still passes.

Compare the original antidote, which does what this comment claims:
`internal/scanner/audit_test.go:513-542` uses `reflect.TypeOf(BuiltInConfig{})`, counts
`OptUint32` fields, and `t.Fatalf`s when the count differs from `len(builtInConfigKeys)`.
**Reflection makes the guarantee; a literal list only documents an intention.**

`matchreplace.Target` is an `iota` enum, so `reflect` cannot enumerate it — but the
`fieldCount = iota` trick already used at `internal/query/query.go:147` would, at compile
time, and is the fix.

### 3.4 One more shape worth flagging: "unreachable" defaults that return a plausible wrong answer

`internal/query/query.go:739-759` `strOp` and `:761-781` `statusOp` end with `return false`
under the comment "Unreachable: `fieldAllows` admits no other operator". That is true today.
But **`fieldAllows` is a hand-written matrix** (`query.go:463-473`) and nothing binds it to
`strOp`/`statusOp`. Widen `fieldAllows` to admit one more operator for a string field and
every such query silently evaluates to **false** — a history filter that quietly shows
nothing, which is the worst possible failure for a search box.

Same shape, safely handled, at `internal/upstream/upstream.go:281-285`: the "unreachable"
default **returns an error** instead of a value. That is the pattern to copy.

### 3.5 Census: the exhaustive-vocabulary tests that DO exist

Definition used: a test that derives its member set **at run time from the production
source of truth** — `reflect`, a `go/ast` parse of the production file, or ranging over an
exported registry variable — rather than from a hand-typed list. Twelve verified by reading:

| Test | Source of truth | Mechanism |
|---|---|---|
| `internal/scanner/audit_test.go:513` | `BuiltInConfig` struct | `reflect.TypeOf` |
| `internal/web/route_manifest_test.go:592` | `setupRoutes` source | `go/ast` |
| `internal/web/route_manifest_test.go:631` | `setupRoutes` source | `go/ast` |
| `internal/web/route_manifest_test.go:698` | `var manifest` | range + live 405 probe |
| `internal/web/route_manifest_test.go:758` | `var manifest` | range |
| `internal/extension/protocol_test.go:136` | package source | `go/ast` |
| `internal/extension/protocol_test.go:168` | `MethodSpecs` | range |
| `internal/tools/codec_test.go:355` | `AllLayers()` | range + round-trip |
| `internal/http2/authorise_test.go:359` | `RefusalKindAll` | range |
| `internal/pool/pool_test.go:273` | `Support()` | range |
| `internal/proxy/options_test.go:314` | `OptionKeys` | range — **listing only** |
| `internal/web/proxy_options_api_test.go:47` | `proxy.OptionKeys` | `len()` — **listing only** |

**Hand-typed-list tests that read as exhaustive but are not** (they document an intention,
they do not enforce it): `internal/web/matchreplace_target_test.go:139` (7 `Target`
literals), `internal/web/toolkit_codec_honesty_test.go:153` (7 encoding-name literals),
`internal/query/fields_test.go:12` (12 query literals),
`cmd/burpsy/cli_capability_test.go:19` (5 handle accessors),
`internal/proxy/options_test.go:52` (5 rule cases — §3.3.1).

**The pattern is real and spreading; the mechanism is not yet standard.** That is a
different, and much cheaper, problem than §6.5 currently describes.

---

## 4. Assertion-free and vacuous tests

### 4.1 The two tests whose only real failure mode is `-race`, in a CI with no `-race`

This is the sharpest item in this section, and it is **NOT GATED**, not NOT WORKING.

**`internal/scanner/scanner_test.go:131`
`TestRuntimeConfigEditIsAtomicAgainstTheDispatchCount`** — contains **zero assertions**.
Its own comment states the contract:

> "…so this fails under `-race` if any reader reaches straight into `s.config` while
> `PUT /api/scanner/config` writes."

It spins 2 000 concurrent `UpdateScanConfig` / `ConfigSnapshot` pairs and then returns.
Under `go test -race` it is a real test. Under `go test` — which is what
`.github/workflows/go.yml:103` runs — the mutex-guarded data races raise nothing, the
function returns, and it **passes unconditionally**. In CI it is a no-op that costs 4 000
iterations of wall time and buys nothing.

**`internal/sitemap/concurrent_test.go:19`
`TestReadingTheTreeWhileTrafficArrivesIsSafe`** — also zero assertions, and its comment is
more careful:

> "Under `-race` it fails on the unsynchronised access; without `-race` it fails by killing
> the test binary outright. Both are the bug."

That second mode is genuine — `fatal error: concurrent map iteration and map write` is
unrecoverable — but it is **probabilistic**, not deterministic. It is a flake-shaped
detector, and §6.4 of the master report already records "a racy test committed green" as one
of the seven working-while-broken items.

```
$ grep -rn 'race' .github/workflows/     → no output (exit 1)
$ grep -n 'go test' .github/workflows/go.yml
103:        run: go test ./... -count=1 -timeout 1700s      # positive control
```

**Adding `-race` to one CI line converts both from decorative to real.** (Runtime cost is
the honest objection: the suite already takes ~8 minutes and `internal/scanner` alone is
453 s; `-race` typically multiplies by 2-10×, against a 1700 s timeout. A `-race` job
scoped to the concurrency-sensitive packages would be the cheap version.)

### 4.2 Assertion-free tests overall: the number is small and mostly benign

Denominator recounted with an AST pass over all 243 `_test.go` files (`/tmp/w4ast2`), which
counts a test as asserting if its body — including closures — calls any of
`t.Error/Errorf/Fatal/Fatalf/Skip/Skipf/SkipNow/Fail/FailNow`:

```
TOTAL_TESTFUNCS=2213  NO_DIRECT_ASSERT=76
```

**76 / 2 213 (3.4 %)** contain no direct assertion. A second pass removed those that
delegate to an asserting helper (`assertMatch`, `wantNoViolations`, `refusalOf`, `hasKV`,
`domFlowFor`, …), leaving **13**:

| | |
|---|---|
| 2 × `TestMain` | correct — `TestMain` is not a test |
| 4 × `internal/http2/authorise_test.go:124,155,173,237` | delegate to `refusalOf(t, …)` — the helper regex missed it. **Fine.** |
| 1 × `internal/intruder/points_test.go:45` | delegates to `hasKV(t, …)` which `t.Errorf`s at `:42`. **Fine.** |
| 4 × `internal/scanner/dom_test.go:110,861,874,882` | delegate to `domFlowFor(t, …)`. **Fine.** |
| **2 × `scanner_test.go:131`, `sitemap/concurrent_test.go:19`** | **§4.1 — genuinely assertion-free** |

**So: 2 genuinely assertion-free tests out of 2 213.** The "vacuous test" problem this
project might have feared **does not exist**; the concentrated version of it is §4.1.

### 4.3 `t.Skip`: 15 calls in 13 files, and all but two name why

```
$ grep -rEn '\b[tb]\.Skip(Now)?f?\(' --include=*_test.go . | wc -l   → 15
$ grep -rEln '\b[tb]\.Skip(Now)?f?\(' --include=*_test.go . | wc -l  → 13
```
(The naive `grep -c 't\.Skip'` returns 39; **24 of those are `.Skipped`/`Skips`/`SkipReason`
struct fields, not skip calls.** Recounted, per rule 2.)

Every one is environment-conditional and self-describing, and the project has evidently
already thought about this failure mode — several use the exact phrasing "this test is
**NOT exercised in this run**":

| Skip | Condition | Verdict |
|---|---|---|
| `internal/extscan/live_test.go:44` | ffuf/nuclei absent | **Good** — and CI *installs* both (`go.yml:71,76`), so it does run there |
| `internal/web/api_discovery_test.go:53` | same | Good |
| `internal/scanner/runtime_coverage_test.go:834,981` | no Chrome on PATH | Good — CI provisions Chrome (`go.yml:47`) |
| `internal/scanner/capability_handles_live_test.go:37` | `BURPSY_ALLOW_NO_CHROME=1` | Good — opt-out is explicit |
| `internal/domexec/browser_test.go:62`, `internal/blindxss/listener_test.go:72,143` | no browser | Good |
| `internal/tlsprobe/tlsprobe_live_test.go:15` | `tlsx` not on PATH | **Good, and explicitly reasoned in CI itself.** `.github/workflows/go.yml:59-62` states "tlsx and interactsh-client are NOT installed here, so the rows that shell out to them stay undemonstrated … That is the honest outcome rather than a hidden one." A permanent skip, declared as such. Consistent with `internal/tlsprobe` at 51.4 %. |
| `internal/core/segment_store_test.go:41` | platform cannot mmap | Good |
| `cmd/conform/main_test.go:200` | platform cannot make dangling symlink | Good |
| `internal/extension/plugin_helper_test.go:48`, `internal/web/extensions_api_test.go:232` | not a helper subprocess | Good — standard re-exec idiom |
| **`internal/advisory/index_collision_test.go:82`** | "no index collisions in this data set" | **Self-nulling.** The test skips when the condition it exists to check is absent. Correct, but it means a shipped-data change that *introduced* a collision would be checked by a test that had been silently green for months. |
| **`internal/web/route_manifest_test.go:668`** | source key count ≠ manifest count | **Self-nulling, and this one matters** — see §4.4 |

### 4.4 The one self-nulling skip that guards a real invariant

`internal/web/route_manifest_test.go:668`:
```go
t.Skipf("found %d '/'-prefixed keys in source against %d manifest entries; ordering not checked", …)
```
The manifest's own header comment (`route_manifest_test.go:117-118`) says "Keep it sorted by
pattern; **the test enforces that**, because a map this size that is not sorted is a merge
conflict generator." The test enforces it **only when the source key count matches the
manifest count** — i.e. exactly when nothing has drifted. The moment a route is added or
removed (the moment ordering is most likely to be broken), the ordering check turns itself
off. The *other* manifest tests still fail loudly on drift, so nothing is unguarded; but the
sorting claim in the comment is stronger than the test behind it.

### 4.5 What I did NOT find

- **No `t.Skip` that is unconditional.** All 15 are behind a condition.
- **No `-short` gating.** `testing.Short()` appears zero times outside the skip census.
- **No focused/exclusive test idiom** (Go has none, and no home-grown equivalent exists).
- **No `t.Log`-instead-of-`t.Error`** as a primary failure path, with one *deliberate*
  exception that is correctly reasoned: `internal/matchreplace/unapplied_target_test.go:60`
  `t.Log`s when the two param targets begin to differ, because that would mean an applier
  landed and the expectation needs a deliberate update — recorded rather than asserted-away.

---

## 5. What the green build proves, and what it does not

Stated as two lists, because conflating them is the reporting error TAXONOMY rule 4 exists
to prevent.

### It DOES prove

1. **46 Go packages compile, vet clean, gofmt clean, and 2 213 test functions pass** at
   `638c480`, in ~8 minutes, at 69.0 % per-package statement coverage.
2. **Live-dependency rows actually ran.** CI provisions headless Chrome and *fails the job*
   if it is absent (`go.yml:41-56`), and installs `ffuf` and `nuclei` with a nuclei
   template corpus (`go.yml:66-79`). The scanner package's 453 s runtime is real work.
3. **The HTTP route surface did not drift.** `route_manifest_test.go` parses `setupRoutes`
   with `go/ast` and fails in *both* directions — a registered route missing from the
   manifest, and a manifest entry with no registration — plus a live 405 probe per route.
4. **Twelve vocabularies cannot silently lose a member** (§3.5).
5. **The specific exemplar defect is dead**, with three tests standing over its grave
   (§3.0).

### It does NOT prove

1. **Nothing about the frontend.** §6.3, re-verified: zero of `tsc --noEmit`, `bun test`,
   Playwright, or token-drift is invoked from `.github/**`. **NOT GATED.**
2. **Nothing about data races.** No `-race` anywhere in CI. Two committed concurrency tests
   are inert as a result (§4.1). **NOT GATED.**
3. **Almost nothing about the CLI.** `cmd/burpsy` at **15.8 %**, holding **18 of the 59**
   string-vocabulary `switch`-with-`default` sites in the tree — the densest concentration
   of the exact construct that produced the exemplar defect, at the lowest coverage of any
   production package. **This is the single largest gated-but-unmeasured surface.**
4. **That a config accepted by the API takes effect.** For **14 of 20** config-mutating
   routes no `internal/web` test observes an effect; 3 have no test naming them at all
   (§2.2). For at least one (`/api/proxy/options`) the effect *is* covered a package down —
   so this is "the binding is untested", **NOT** "the feature is broken".
5. **That a proxy option added tomorrow would do anything.** Three tests bind the option
   *listing* to `OptionKeys`; **zero** bind the *applier* (§3.3.1).
6. **That `category` means what the client said.** Two unvalidated 2-value coercions,
   defaulting in opposite directions, with no test (§3.3.2).

### The one-line version

> The green build proves the **Go engines** behave. It proves almost nothing about the
> **seams** — API-vocabulary→engine-applier, config-endpoint→subsystem-effect, Go→frontend —
> and every one of the seven working-while-broken items in §6.4 lived in a seam.

---

## 6. The cheapest fixes, ordered by (risk closed ÷ effort)

Not a plan — an ordering, with the evidence each rests on.

| # | Fix | Effort | Closes |
|---|---|---|---|
| 1 | Gate `bun run check` in `go.yml` | **one line of YAML** | 118 frontend assertions + 2 typechecks + 2 token-drift checks currently outside the wall (§6.3 of master) |
| 2 | Bind `responseRules` to its applier: assert `len(cases) == len(responseRules)` in `internal/proxy/options_test.go:52` | **two lines** | §3.3.1 — a proxy option that lists, sets, 200s and does nothing |
| 3 | Validate `category` through a parse function that 400s, in all three call sites | **~15 lines** | §3.3.2 — two coercions defaulting in opposite directions, untested |
| 4 | Add a `targetCount = iota` sentinel to `matchreplace.Target` and assert it in `matchreplace_target_test.go:139` | **two lines** | §3.3.4 — the antidote's own list is hand-maintained; the `query.go:147` idiom already exists in-tree |
| 5 | A `-race` CI job scoped to `internal/{core,scanner,sitemap,proxy,web}` | **~10 lines of YAML** | §4.1 — two committed concurrency tests are currently inert |
| 6 | CLI tests for the 18 `cmd/burpsy` subcommand vocabularies | **days** | §1.2 — 15.8 % coverage on the densest concentration of the exemplar construct |
| 7 | An effect test per config-mutating route, on the `matchreplace_proxy_share_test.go:24` template | **days** | §2.2 — 14 of 20 routes |

Items 2-4 are each smaller than the comment explaining them. Item 1 was already identified
by the master report and remains the highest-value single line in the repository.

---

## 7. One correction the master report should absorb

§6.5 currently reads: *"this team already solved the accepted-but-unhandled problem,
correctly, and did not propagate the solution … The match/replace vocabulary two packages
away has an API list, a separate engine switch, and no test binding them — and carries a
live traffic-corrupting bug as a direct result."*

**At `638c480` / `804e47c` that is no longer true.** The bug is fixed on both sides
(§3.0), three tests now bind the vocabulary to the applier, and **twelve** structurally
exhaustive tests exist across seven packages (§3.5). The accurate replacement claim is
narrower and more useful:

> The pattern **has** propagated. What has not propagated is the *mechanism*: five of the
> newer "exhaustive" tests enforce their vocabulary with a **hand-typed literal list**,
> which documents an intention rather than enforcing it. `reflect` (`audit_test.go:513`),
> `go/ast` (`route_manifest_test.go:592`) and the `fieldCount = iota` sentinel
> (`query.go:147`) are all already in-tree and all three make the guarantee real. Picking
> one and writing it down as a convention is the remaining work, and it is hours.

*(Note for the CTO: `/root/burpsy-parity/` now mirrors into `burpsy-go/docs/parity/` as of
`804e47c`. This file is not there yet.)*

---

## NOT DETERMINED

1. ~~Whole-tree cross-package coverage.~~ **RESOLVED during the run — see §1.4.**
   77.7 % overall, 78.3 % production-only.
2. ~~`cmd/desktop` at 0 %.~~ **RESOLVED — 66 statements, 0 executed.** Too small to be a
   finding; I still did not read it, so "thin entrypoint" is an inference from size.
3. ~~Whether `internal/httputil` is exercised transitively.~~ **RESOLVED — 82.0 %.**
4. **Whether the 119 response-only `internal/web` tests each have an engine-level effect
   test one package down.** I verified this by hand for `/api/proxy/options` only. Doing it
   for all 20 config routes is roughly a day of reading and is the obvious follow-up.
5. **Whether the frontend's 118 ungated assertions currently pass.** Out of scope for me
   and, per rule 4, orthogonal to whether they are gated.
6. **Burp's own BCheck insertion-point vocabulary.** burpsy's `given … insertion point`
   accepts 5 words against 16 `IpKind`s. Whether *Burp* accepts more than 5 is a question
   for `/root/burp-re` and I did not check it. If it does, that is a **capability gap** row
   for §2 of the master report, not a defect.
7. **Whether any of §3.3's four findings is reachable from the UI today.** I confirmed only
   the negative for the matchreplace param targets (zero UI references). For `category` the
   UI is typed TypeScript — but TypeScript types are **not gated** (§6.3), so the
   type-level guarantee rests on an ungated `tsc`.

---

## DENOMINATORS I RECOUNTED

Every count below was produced by me at `638c480`, with the command shown. Corpus is
`burpsy-go/` unless stated.

| Count | Value | Command | What it counts |
|---|---|---|---|
| Whole-tree statement coverage | **24 212 / 31 176 = 77.7 %** | `go test ./... -coverpkg=./...` then `go tool cover -func \| tail -1` | a statement counts once, covered if any test binary reached it |
| …production-only | **22 491 / 28 727 = 78.3 %** | same profile, excluding 6 demo/fixture/tooling packages | |
| Per-package statement coverage | **69.0 %** | `go test ./... -coverprofile` (no `-coverpkg`) | credits each package only for its **own** tests — understates 6 packages badly (§1.4) |
| Go packages | **46** | `go list ./... \| wc -l` | all packages incl. `cmd/`, `bench/`, `pkg/` |
| Packages with **zero** test files | **9** | `go list -f '{{.ImportPath}} {{len .TestGoFiles}} {{len .XTestGoFiles}}' ./... \| awk '$2==0 && $3==0'` | of which only `internal/httputil` and `cmd/desktop` are production |
| Non-test `.go` files | **253** | `find . -name '*.go' ! -name '*_test.go' \| wc -l` | |
| Test files | **243** | `find . -name '*_test.go' \| wc -l` | |
| Test-file lines | **64 634** | `find . -name '*_test.go' \| xargs wc -l \| tail -1` | |
| `Test*` functions | **2 213** | AST pass, `/tmp/w4ast2` — `FuncDecl`, no receiver, name `Test[A-Z]` | matches `grep -rEc '^func Test[A-Z_]'` |
| Tests with **no direct** assertion | **76** (3.4 %) | same AST pass, checking for `t.Error/Errorf/Fatal/Fatalf/Skip/Skipf/SkipNow/Fail/FailNow` incl. closures | denominator 2 213 |
| Tests **genuinely** assertion-free | **2** | 76 minus 63 helper-delegating (regex triage) minus 2 `TestMain`, then **all 13 survivors read by hand** | see §4.2 |
| `t.Skip` **calls** | **15** in **13 files** | `grep -rEn '\b[tb]\.Skip(Now)?f?\(' --include=*_test.go .` | naive `grep -c 't\.Skip'` gives **39**; 24 of those are `.Skipped`/`Skips`/`SkipReason` struct fields |
| `testing.Short()` uses | **0** | `grep -rn 'testing\.Short' --include=*_test.go . \| wc -l` | |
| `-race` in CI | **0** | `grep -rn 'race' .github/workflows/` — positive control `go test ./... -count=1 -timeout 1700s` at `go.yml:103` | |
| `switch` stmts with ≥2 cases | **316** | AST pass, `/tmp/w4ast` | excl. `_test.go` |
| …of those, string-literal vocab **with a `default`** | **59** | same, `/tmp/w4vocab.txt`, `bench/` excluded | 18 `cmd/burpsy`, 10 `internal/web/api_*`, 6 `internal/intruder`, 5 `internal/bcheck`, 3 `internal/scanner`, 17 across 14 other dirs |
| Partial enum switches flagged | **61** | AST pass 2, `/tmp/w4ast/enum.go` | after removing cross-package type-name collisions and by-design partials, **every survivor read by hand** |
| Routes in `var manifest` | **82** | python parse of `internal/web/route_manifest_test.go:119` | `riskRead` 37, `riskLocal` 14, `riskAttack` 10, `riskCredential` 7, `riskScope` 6, `riskEgress` 3, `riskAsset` 2, `riskExecute` 2, `riskDestructive` 1 = 82 ✓ |
| **Config-mutating** routes | **20** | `riskLocal` (14) + `riskScope` (6) | the §2 denominator |
| …with an `internal/web` effect test | **6 of 20** | see §2.2 table | 14 have none; 3 have no test naming them at all |
| Tests naming a config-mutating route | **85** | python scan of 311 parsed `internal/web` test funcs | 19 (22 %) carry an effect signal |
| `internal/web` API-driving tests | **194** | same scan | **75** effect-signalled, **119 (61 %)** response-only |
| Unexported `Server` struct fields | **48** (35 non-plumbing used as effect signals) | python parse of `type Server struct` in `internal/web/server.go` | `mux`, `logger`, `*Once`, bind addrs etc. excluded |
| `proxy.OptionKeys` | **6** (5 in `responseRules`) | `internal/proxy/options.go:66-75`, `:98-104` | |
| …applier `if` arms in `ApplyResponse` | **5** | `internal/proxy/options.go:372-386` | + `ApplyRequest` for the 6th |
| …tests binding **listing** to `OptionKeys` | **3** | `grep -rn 'responseRules\|len(OptionKeys)\|len(proxy.OptionKeys)' --include=*_test.go .` | |
| …tests binding **applier** to `responseRules` | **0** | same grep; positive control returns the 3 listing tests | §3.3.1 |
| `matchreplace.Target` members | **7** | `internal/matchreplace/matchreplace.go:18-26` | 5 with an `applyOne` case, 2 refused by name |
| Structurally exhaustive tests verified | **12** across 7 packages | read by hand, §3.5 | 5 further "exhaustive-looking" tests use hand-typed literal lists |
| UI files containing `<option` | **14** | `grep -rln '<option' --include=*.tsx src/` under `internal/web/ui` | |
| UI refs to the refused matchreplace targets | **0** | `grep -rn 'request_param_name\|request_param_value' --include=*.ts --include=*.tsx .` — 7 hits, all Go | positive control: the same grep finds all 7 Go sites |
