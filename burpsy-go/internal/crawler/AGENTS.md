# crawler

<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

## Purpose

Discovers an application's structure from a seed URL, feeding everything it fetches through the
**same** capture-and-scan path that proxied traffic takes. This is new work, not a port: the Rust
`crates/` tree has no crawler crate at all, so there is no parity oracle for it — the package's own
doc comment says so, and `gaps.md` is where any Rust↔Go difference would be recorded if one existed.

It covers roadmap Phase 6's CRAWL-01..04, CRAWL-07 and DSL-03. The organising value is the same as
the rest of burpsy: **honest counting**. Every count in a `Report` is a partition of something, so a
reader can always answer "what happened to the URLs that were not fetched" — `Fetched + Refused +
Failed + NotCaptured` is every request attempted, and `Skips` accounts for every URL discovered and
not attempted.

## Key Files

| File | Description |
|------|-------------|
| `crawler.go` | The engine: `Config`, `Crawler`, `New`, the breadth-first `Run` loop, `Fetch`/`Report`, the frontier queue, per-authority sender/limiter selection, request building. Carries the long package doc that states every named limit. Also carries **seeds-only mode** (`Config.SeedsOnly` + `Config.SeedRequests`) — see below. |
| `discover.go` | HTML parsing (`golang.org/x/net/html`): extracts links and forms, computes the page skeleton and location fingerprint, fills form-field defaults a browser would send. Subresources (`img`/`script`/`link`/`video`) are deliberately neither queued nor fingerprinted. |
| `fingerprint.go` | The two identities: the pre-fetch request fingerprint (`requestFingerprint`, normalises query) and the URL template (`urlTemplate`, collapses id-shaped segments via `looksLikeID`/`isUUID`/`isHex`), plus the post-fetch content fingerprint. |
| `limits.go` | `Limits`/`DefaultLimits`, the `CrawlStop` enum (12 stops, `CrawlStopAll`) with `String`/`Explanation`, and `LimitReport` (`Truncated`, `Unfetched`, `Caveat`). |
| `skip.go` | The `Skip` enum (29 reasons, `SkipAll`, in declaration order) with `Category`/`String`/`Explanation`, `SkipRecord`/`SkipReport`, and the bounded `skipLedger` that samples refusal detail. |
| `destructive.go` | CRAWL-04 refusal: a signal table matched by token *runs* against link target and text (`classifyDestructive`, `tokenise`, `containsRun`), yielding a `DestructiveVerdict`. |
| `session_gate.go` | Optional re-login seam: `SessionCoordinator`, expired-session detection (status-flip or login-page pattern), `recoverSession`, and request rebuilding with a fresh cookie. |
| `crawler_test.go` | The bulk of the tests — discovery, the shared-seam authorisation chokepoint, scope/redirect/credential refusals, limits, query scoping, robots handling, session recovery. |
| `seeds_only_test.go` | The seeds-only mode: that it sends exactly the requests it was given (method, body, headers), that it follows nothing and probes no robots.txt, that its report says which mode ran, and that its input is validated as strictly as a seed URL. |
| `destructive_test.go`, `fingerprint_test.go`, `fingerprint_budget_test.go` | Focused tests for the signal table, the two fingerprints, and the fingerprint-budget cutoff. |

## Two modes: discovery, and seeds-only

`Config.SeedsOnly` fetches exactly what `Config.Seeds` / `Config.SeedRequests` name and follows
nothing: no robots.txt probe, no redirect traversal, no link or form extraction, and no location
fingerprint. `Config.SeedRequests` is the reason the mode exists — an API-only scan's attack surface is
a definition's operations, and `DELETE /items/1` and `GET /items/1` are two endpoints of one path, so
the frontier item carries a method, a body and its own headers rather than being a URL.

This is a second scan kind rather than a tighter bound, and the distinction is load-bearing: every
mechanism that adds a request the operator did not name is a *feature* of a crawl and would be a defect
here. The run reports which mode it was in (`Report.SeedsOnly`), because a crawl that found no links and
a scan that never looked produce identical counts and are different runs. `SeedRequests` without
`SeedsOnly` is refused in `New` rather than ignored — a crawl has nowhere to put a method or a body,
and silently sending a GET at a path meant for a POST is the failure the field would otherwise cause.

## For AI Agents

- **There is exactly one way out of this package, and it is the scope chokepoint.** `Crawler` holds
  no `net.Dialer`, no `http.Client` and no bare `*sender.Sender` — every send is wrapped in a
  `sender.AuthorisedSender` bound to the target origin (`senderFor`), which re-checks the exact
  request bytes before the dial. Do not add a transport that reaches around it; that turns the crawler
  into an SSRF engine with a scope list attached.
- **Do not route crawl traffic through burpsy's own proxy listener to "get scope for free".** The
  proxy gates *capture*, not *forwarding* (its out-of-scope path is `forwardOnly`, "forward without
  storing") — a crawl through it would be off-scope *and* invisible. The package doc explains this at
  length; it is a settled decision.
- **Capture and scan go through `scanner.Capture`, the same seam the proxy's passive scan uses.** A
  second copy is forbidden precisely because it drifts, and the first thing to drift is the
  honest-reporting behaviour. `Config.Capture.Store` is required; a nil Scanner/Findings captures
  without scanning (that is `scanner.Capture`'s own behaviour, not this package's to override).
- **robots.txt is read for discovery, never obeyed.** Do not "fix this later" by adding `Disallow`
  enforcement — it is a deliberate two-part decision. Robots-derived paths enter as *discovered
  links, not seeds*, so they still pass the destructive check, scope gate and query; seeds skip the
  destructive check because they are the operator's instruction.
- **A redirect is not followed.** A 3xx `Location` re-enters the frontier as an ordinary discovered
  link and is re-authorised on its own bytes, so a cross-host redirect cannot escape scope.
- **Userinfo in a URL is refused** (`SkipCredentialsInURL`), and the **scheme is checked first** —
  http/https only.
- **The two enums are total at compile time.** `Skip.slot()` and `CrawlStop` map via a `switch`, not
  a search, and `SkipAll`/`CrawlStopAll` are fixed-size arrays ([29] and [12]) — adding a variant
  means updating the array length, the switch, `String`, and `Explanation` together, or the build
  breaks. That is intentional.
- **Named limits are stated, not hidden:** one request at a time (sequential loop, not a knob), no
  JavaScript execution (SPAs report one location honestly), subresources not fetched or
  fingerprinted, and the frontier-queue design means multi-step/wizard state is unreachable — which
  only bites once `SubmitForms` is on. `SubmitForms` defaults off because submitting forms writes to
  the application.
- **The fingerprint budget refuses admission rather than evicting** (`StopFingerprintBudget` /
  `SkipFingerprintBudget`): eviction would launder unvisited pages through `StopFrontierCapacity` and
  make `Unfetched` smaller than the truth. Keep it a visible decline.
- **`RobotsPolicy` and `FormSubmission` are carried in every `Report`**, not implied by absence, so a
  report cannot be misread as "no forms found" when it means "forms not submitted".

## Testing Requirements

```bash
go test ./internal/crawler/...
```

Tests are named as full sentences that state a claim (e.g.
`TestTheCrawlerAuthorisesEveryRequestThroughTheSharedChokepoint`,
`TestRobotsTxtIsReadForDiscoveryAndNotObeyed`). The chokepoint test uses a `refuseEverythingScope`
to prove no request bypasses `AuthoriseRaw`; session-recovery tests drive a `fakeCoordinator`.
The full-tree gate (`go build ./... && go vet ./... && gofmt -l . && go test ./...`) still applies.

## Dependencies

Internal: `core` (exchange ids, scope types), `sender` (the `AuthorisedSender` egress and
`ScopeChecker`), `scanner` (the `Capture` seam), `intruder` (its `RateLimiter`, reused rather than
reimplemented — one per authority plus a crawl-wide cap), `query` (the DSL-03 scope and retention
queries), `session` (the re-login coordinator's `SessionRule`/`LoginOutcome`/`MacroStepRunner`).

External: `golang.org/x/net/html` (parsing — chosen over katana/colly, see the package doc for why),
`go.uber.org/zap` (optional logger).
