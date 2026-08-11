# Crawler Upgrade — Executable Slices

> Companion to `CRAWLER_UPGRADE_PLAN.md` (imported from master `657c6c5`). The plan
> names the six bursts of work; this document breaks each into grab-able slices with
> acceptance criteria tied to the code as it is now. Grounded 2026-08-06.
>
> Order follows the plan's phased delivery order: A (session wiring), D (concurrency),
> B-static, E (subresources), C (navigation graph), B-headless. Each slice ends with a
> `go test ./internal/crawler/...` run; none changes default crawl behaviour unless the
> slice's requirement says it must.
>
> Naming follows the repo's slice/test convention: a slice is one honest behavioural
> change plus the tests that pin it.

## Current code map (anchors)

| Anchor | Location |
|--------|----------|
| `Config` (`Headers` map, `SubmitForms`, no session field) | `crawler.go:211` |
| `Crawler` struct (frontier/queued sets, not goroutine-safe) | `crawler.go:402` |
| `New` — invalid-config refusal, `MaxInFlight: 1` limiter | `crawler.go:469,562` |
| `Run` — sequential `for { front[0]; visit }` loop | `crawler.go:655-682` |
| `visit` — send→capture→scan→fingerprint→admit pipeline | `crawler.go:702-912` |
| `Limits` + `CrawlStop` (11 stops) + `LimitReport` | `limits.go` |
| `SkipReason` set (33) + `SkipReport` | `skip.go` (`SkipDestructiveLogout Skip = iota` at :44) |
| `discover.go` walk — meta-refresh / srcset / script URLs omitted | `discover.go:32-33,350` |
| `session.Coordinator` — `EnsureLoggedIn`, `HandleRecovery`, `SessionRule.MatchHost` | `session/recovery.go:320,333`, `session.go:604` |
| `session.Coordinator` — `runs` (one login per rule), `observed` (macro promotion) | `session.go:616-662` |
| Per-host rate limiter (`limiterFor`) | `crawler.go:1369` |

---

## Phase 1 — Gap A: Authenticated crawl / session wiring

### A1 — `SessionCoordinator` config seam
Optional interface `SessionCoordinator` + `Config.SessionCoordinator` field; `nil`
keeps today's static-`Headers` behaviour byte-for-byte (plan step 1's "no breaking
change" is pinned here). Interface must be satisfied by `*session.Coordinator` without
an adapter: `EnsureLoggedIn(rule, runner)`, `HandleRecovery(...)`, a way to find the
first enabled rule whose `MatchHost(host)` resolves for `item.url`, and a way to get
the refreshed cookie jar onto a rebuilt request.

Pass: `New(cfg)` accepts nil and non-nil; nil produces `Report` fields identical to
today; a fake coordinator records the calls it received.

### A2 — Session expiry detection in `visit`
New `session_gate.go`: given captured `(status, contentType, body)` after `visit`'s
capture path, emit `gateResult{loggedOut bool, reason string}`. Detection rules:
(1) non-200 on a template previously seen at 200, or (2) body matching
`Config.LoginPagePattern` (new regex field; validated in `New`; empty = rule 1 only).

Slice proves: a 200→401 drop on a revisited template fires; a first-visit 401 does
not; both outcomes are *counted*, never silent. Pure function, table-tested, no I/O.

### A3 — Re-login budget + stop reason
In `limits.go`: `Limits.MaxRelogins int` (defaulted in `DefaultLimits`), new `CrawlStop`
member `StopReloginBudget`, added to `CrawlStopAll` legend and `Caveat()`, and a
generation counter on `Crawler` (binds sequential waves, not just concurrent — the
plan's stated extra). `LimitReport` gains `Relogins`. Unit tests: budget hit stops the
crawl *with frontier non-empty*; report's `Truncated()` flips true.

### A4 — Wire re-login into `visit`, one retry
When the gate fires on a request that already carried `Config.Headers`, call
`EnsureLoggedIn`, rebuild the request from the refreshed jar (re-validated
`Content-Length` through the existing `buildRequest`), send exactly once more through
`as.Send` (re-scoped, route unchanged). Failure paths: relogin's own refusal records
`SkipSendRefused`; budget exhausted records a new `SkipReloginFailed` and
`Report.ReloginFailed++`.

### A5 — Report fields `ReloginCount`, `ReloginFailed`
`Report` gains both JSON fields; `Summary()` mentions them when non-zero. Partition
invariant restated in a test: `Fetched+Refused+Failed+NotCaptured` still sums to
attempted exactly.

_Files:_ `crawler.go`, `session_gate.go` (new), `limits.go`, `skip.go`,
`crawler_test.go`.
Gate: `cd burpsy-go && go test ./internal/crawler/...`

---

## Phase 2 — Gap D: Concurrency

### D1 — Serialise shared state
Protect `frontier`, `queued`, `locations`, `templates`, `robotsSeeded`, `senders`,
`credentialOrigins`, `headersWithheld` behind a single `Crawler.mu sync.Mutex`. Rule,
enforced by test: no map is read or written outside the lock. Dispatch order is
preserved while the lock is held — `item := c.frontier[0]; c.frontier = c.frontier[1:]`
still happens atomically — so existing fixture order stays stable.

### D2 — `Config.MaxConcurrency` (default 1)
Field added, default 1 = backwards compatible by construction. `Run()` spawns up to
`MaxConcurrency` goroutines, each pulling from the frontier under the lock; the
aggregate `c.limiter` becomes `MaxInFlight: cfg.MaxConcurrency` while the per-host
`limiterFor` AutoThrottle stays untouched. Surfaces in `LimitReport`. Tests:
`MaxConcurrency: 1` reproduces today's exact sequential ordering; `MaxConcurrency: 4`
yields the same location set *and* the same skip partition on a fixed fixture (any
dispatch order).

### D3 — Deterministic accounting under concurrency
Concurrency regression test: a fixture crawl with `MaxConcurrency: 4` and `MaxRequests`
bounds asserting `Fetched+Refused+Failed+NotCaptured` still sums exactly and that
`queued` grows monotonically as in the single-thread crawl. The plan's note — the two
rate limiters already own multi-host fairness; concurrency changes dispatch only —
is verified here by test, not assertion.

_Files:_ `crawler.go`, `limits.go`.
Gate: `go test ./internal/crawler/...`

---

## Phase 3 — Gap B (static): meta-refresh / srcset / inline-JS

### B1 — `<meta http-equiv=refresh>` in `discover.go` walking
Parse `meta[http-equiv=refresh]` `content`: the `url=…` value after the numeric delay.
Emit a `discoveredLink{tag: "meta-refresh"}`. New tests: delay + url; bare refresh
(no url) = refresh-of-self → skipped and counted `SkipMalformedURL`; relative URL
resolution. ~15 lines of change.

### B2 — `srcset` candidates
Split on `,`, strip descriptors (`2x`, `800w`), resolve relative, emit per-candidate
links. Tests: multiple candidates with mixed descriptors, `data:` entry refused by the
existing scheme gate, absolute and relative URLs. ~20 lines of change.

### B3 — Inline JS string-path pass, `Config.ExtractInlineJSLinks bool`
Over `<script>` text nodes: extract quoted string literals that resolve to a path
(leading `/`-headed, `./`, `../`, or schema-relative `//host`). OFF by default, per
plan step 3: a default run emits nothing new and `New` still validates the flag name.
Test: flag on yields expected new links; flag off yields today's discovery set byte-identical.

### B4 — Static B regression gate
One test that `ExtractInlineJSLinks=false` (zero value) leaves today's discovery set
byte-identical on a fixed fixture — the guard that static work doesn't drift a default
crawl.

_Files:_ `discover.go`, `config.go`, `discover_test.go`.
Gate: `go test ./internal/crawler/...`

---

## Phase 4 — Gap E: Subresource fetching

### E1 — Config seam: `Config.FetchSubresources bool` (false)
Default false keeps the bundle-hash argument the default (plan step 1). With the flag
on,
`walk` collects `img[src]`, `script[src]`, `link[href]`, `source[src]` into a separate
`subresources []subresourceLink` returned on `pageStructure` — never promoted to
`page.links`, and never entering the location fingerprint whether fetched or not
(plan step 4's deploy-hash point is orthogonal).

### E2 — `admitSubresource()`
Identical pipeline to `admit()` — resolve → scheme → userinfo → destructive → scope →
query → depth/dup/frontier — plus:
- recording `SkipSubresourceDisabled` (new `SkipReason`) when the flag is off, so the
  count is visible on a default run (plan step 3's census);
- a test that two pages differing only in a bundle-URL hash are the same location.

---

## Phase 5 — Gap C: Navigation graph

### C1 — `NavigationGraph` type, new `internal/crawler/graph.go`
Nodes keyed by content fingerprint; edges the requests that produced them (`method`,
`body`, `foundAt→this`). Add-only: nodes never mutate after record; edges immutable.
Simple accessor `Path(from fingerprint → to template) []Edge` returning a replayable
request path. This is the most architecturally novel slice; its identity semantics
(fingerprint node identity, cross-page links) each get unit tests.

### C2 — Record in `visit` + `Config.UseNavigationGraph bool` (off)
After the existing fingerprint/duplicate handling, when the flag is on, record the
edge `(foundAt fingerprint → this)` when the response was previously seen. Off by
default → no change to default fixture output. `Report.GraphReplays` gains a
`GraphReplayFailed` pair.

### C3 — Replay a path before a queued template miss
When a queued URL's template has not yet been fingeprinted and the graph has a known
edge path from the seed fingerprint, replay each step first, each step a fresh
`AuthorisedSender`. New stop reason `StopReplayBudget` in `limits.go` (bounds the
replay work); replayed requests bill against the request budget. Failed replay →
new `SkipReplayFailed` ledger record. `TestDefaultCrawlEquality` pins that the
default-frontier-of-flag-off crawl has identical coverage fields to today.

Files: `graph.go` (new), `crawler.go`, `limits.go`, `skip.go`. Expect 2–3 review
rounds; this is the phase asked for a navigation graph for the biggest reason.

---

## Phase 6 — Gap B (headless browser)

### H1 — Dependency decision (no code in the slice)
Evaluate `chromedp` against CRAWL-02 chokepoint compliance: every `Fetch.enable`
response must egress through `AuthorisedSender` — the browser's own sockets never
write a request that has not been scope-checked. Record the decision in `docs/` and
cross-ref the ROADMAP Phase 12. If `chromedp` is chosen, pin it in `go.mod` only in
this slice; otherwise route CDP over the existing `sender` transport with no third
-party dep.

### H2 — `Config.HeadlessBrowser bool` + `browserVisit()`
Flag + `browserVisit()` in `crawler.go`: drives the headless session, discovers links
by DOM query, hands each to the same `admit` pipeline — location identity stays
content-fingerprint, not URL. Scope-escape test: a browser that follows an
out-of-scope redirect to an external host is refused at the chokepoint before any
dial.

### H3 — SPA fixture e2e
Target a minimal SPA fixture; assert the crawl reaches routes built at runtime (more than
the shell) and that every exchange is captured through the shared seam
(`Source: core.SourceCrawl`). Without a real browser in CI this slice is **skipped-not-flaky**
— recorded in `LIVE_TEST_REPORT.md` per honest-reporting convention, never claimed as
passed.

Files: `go.mod`, `crawler.go`, `discover.go`, web crawler router, ROADMAP Phase 12 ref.

Gate: `go test ./internal/crawler/...` (headless slice behind the headless build tag).

---

## Cross-cut honesty invariants every slice must hold

1. `Report` counts partition exactly — a new count/{StopReason}/{SkipReason} is added
   and never double-counted inside `visit`.
2. Every new config flag's zero value = old behaviour, and a test runs the old fixture
   with the default and asserts byte-identical output.
3. Every `SkipReason` change is recorded in the ledger and rendered by the skip table;
   nothing silent.
4. Nothing opens a raw `net`/`http.Client` outside `sender.AuthorisedSender` — the
   CRAWL-02/HARD-03 chokepoint holds across every slice including the headless one.
5. Destructive checks and `session_gate` gates are table-driven with a cause logged.

> Every slice's report is not a claim: run `go test ./internal/crawler/...` after the
> last diff and record pass/skip in the commit body per the repo's honest-counting
> convention.