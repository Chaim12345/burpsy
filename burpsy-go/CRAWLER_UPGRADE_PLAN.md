# Crawler Upgrade Plan — Burp Parity

> Generated 2026-08-06. Based on direct source reads of `internal/crawler/crawler.go`,
> `internal/crawler/discover.go`, and `gaps.md`.
>
> All 13 original Rust-parity gaps (HTTP/2, scanner, audit engine, etc.) are
> **COMPLETE** as of 2026-08-04. The audit engine's last unwired scope —
> `given insertion point` / `send payload` (M3) — landed 2026-08-09 with
> `Finding.Param` attribution end to end; see `gaps.md` §3. The remaining open
> work is entirely within the crawler itself, which the code comments document
> with unusual candour.

---

## The Four Real Gaps (From the Code)

The `crawler.go` package doc names four gaps explicitly and `gaps.md` adds a fifth
as a Phase 6 named shortfall. None are vague — each has a precise technical boundary.

---

### Gap A — Authenticated Crawling *(Highest Value)*

**What exists:** `Config.Headers` lets an operator paste a session cookie. It works
until the cookie expires. After that the crawl quietly starts mapping the login page
with no detection and no recovery.

**What Burp does:** Session Coordinator integration — when a probe response indicates
the session is gone, the crawler calls `EnsureLoggedIn`/`HandleRecovery`, re-runs the
login macro, and continues without operator intervention.

**What's already in the codebase:** `session.Coordinator` with `EnsureLoggedIn` and
`HandleRecovery` is **fully built and tested** (Gap 12, closed 2026-08-04). It is
simply **not wired to the crawler**. `gaps.md` names two additional pieces needed
beyond the wiring: a re-login generation counter (so sequential waves of expiry are
bounded, not just concurrent ones), and a per-crawl re-login cap with its own
`StopReason`.

**Implementation steps:**

1. Add `SessionCoordinator` (an interface wrapping `session.Coordinator`) to
   `Config` — optional, `nil` = current static-headers behaviour, no breaking change.
2. In `visit()`, after a captured response, detect session expiry: non-200 on a
   previously-200 template, or a body fingerprint matching a configurable
   login-page pattern.
3. Call `coordinator.EnsureLoggedIn()`, rebuild the request with the refreshed
   jar, retry once.
4. Add `StopReloginBudget` to `limits.go`, a `MaxRelogins` field to `Limits`, and
   a generation counter to `Crawler`.
5. Add `Report.ReloginCount` and `Report.ReloginFailed` so session health is
   visible in the report rather than invisible in the skip ledger.

**Files touched:** `crawler.go` (Config, Crawler, visit, Run), `limits.go`
(Limits, StopReason), new `session_gate.go` for the detection logic.

---

### Gap B — JavaScript / SPA Support *(Largest Coverage Gap)*

**What exists:** `discover.go` parses static HTML with `golang.org/x/net/html`.
A single-page application returns one location — its shell — and the crawl is
honest but nearly empty. The package doc defers full JS support to Phase 12
(dynamic confirmation / headless browser).

**What Burp does:** Phase 12 brings in a real browser. Short of that, Burp still
picks up `<meta http-equiv=refresh>` targets, `srcset` candidates, and inline
hardcoded paths.

**What's currently missing (named in `discover.go`):**
- `<meta http-equiv=refresh>` targets
- `srcset` candidate lists
- URLs built by script
- URLs in CSS
- `data-*` conventions

**Implementation steps (in order of effort):**

1. **`<meta http-equiv=refresh>`** — add to `walk` in `discover.go`, parse the
   `content` attribute for `url=…` after the delay. ~15 lines.
2. **`srcset` candidates** — split on `,`, strip descriptors (`2x`, `800w`),
   emit each as a `discoveredLink{tag: "srcset"}`. ~20 lines.
3. **Inline JS regex pass** — over `<script>` text node content, extract quoted
   string literals that look like paths (`"` or `'` around something starting
   with `/`). Gate behind `Config.ExtractInlineJSLinks bool`.
4. **True headless (Phase 12 scope)** — add `Config.HeadlessBrowser bool` and a
   `browserVisit()` path in `crawler.go` that drives `chromedp`, routing all
   network calls through `AuthorisedSender` via the CDP `Fetch.enable` intercept.
   This is the only step requiring a new external dependency.

**Files touched:** `discover.go` (steps 1–3), `crawler.go` (step 4),
`Config` struct for new flags.

---

### Gap C — Navigation Graph / State Machine

**What exists:** A frontier queue — each URL is fetched in isolation. Any location
reachable only through a sequence of state-changing requests is missed. The code
comment is precise: this gap only *matters* when `SubmitForms` is on, because
multi-step wizards and POST-only paths are by definition behind form submissions.
A default crawl cannot hit these cases.

**What Burp does:** Models the application as a directed graph and re-navigates
from a known node to reach locations that require a specific prior state.

**Implementation steps:**

1. Build a `NavigationGraph` type in a new `internal/crawler/graph.go` — nodes
   are content fingerprints, edges are the requests that produced them, with
   each edge carrying its method and body.
2. In `visit()`, after fingerprinting a response, record the edge
   `(foundAt fingerprint) → (this fingerprint)` keyed by the request that
   produced it.
3. For a queued URL whose template has not yet been fingerprinted, look up
   whether the graph has a known path of edges from a seed fingerprint to a
   node that links to it; if so, replay that path first, each step
   re-authorised through `AuthorisedSender`.
4. Gate behind `Config.UseNavigationGraph bool` — off by default. A frontier
   crawler is not compromised by this being absent on a default run.
5. Add `Report.GraphReplays int` and `Report.GraphReplayFailed int`.

**Files touched:** new `graph.go`, `crawler.go` (visit, enqueue), `limits.go`
(new stop reason for replay budget).

---

### Gap D — Concurrency

**What exists:** Deliberately sequential (`MaxInFlight: 1` by construction, not
by config). The package doc says "slow in exact proportion to its size." The
reason is exact accounting — the current pipeline is not goroutine-safe:
`frontier`, `queued`, `locations`, `templates` are all unsynchronised
maps/slices.

**What Burp does:** Parallel crawl workers.

**Implementation steps:**

1. Protect `frontier`, `queued`, `locations`, `templates`, `robotsSeeded`,
   `senders`, `hostLimiters` behind a single `sync.Mutex` (or promote
   `queued`/`locations` to `sync.Map` if contention measurements justify it).
2. Change `c.limiter` to `MaxInFlight: cfg.MaxConcurrency`.
3. Change `Run()`'s loop to spawn up to `MaxConcurrency` goroutines, each
   pulling from the frontier under the lock.
4. Add `Config.MaxConcurrency int` (default 1 — backwards compatible) and
   surface it in `LimitReport`.

**Note:** The two rate limiters (`c.limiter` aggregate + per-host `limiterFor`)
already handle the multi-host fairness problem; concurrency changes only the
dispatch loop, not the rate model.

**Files touched:** `crawler.go` (Crawler struct, Run, visit), `limits.go`
(Limits, Config).

---

### Gap E — Subresource Fetching

**What exists:** `img`, `script`, `link`, `video` are never queued and their
`src` values are stripped from the location fingerprint. The `discover.go`
comment explains why: a rebuilt bundle hash in a filename would make every
page a new location on every deploy.

**What Burp does:** Fetches subresources (scripts, stylesheets, images).

**Implementation steps:**

1. Add `Config.FetchSubresources bool` (off by default — the naming argument
   is sound and should remain the default).
2. In `discover.go`'s `walk`, when `FetchSubresources` is enabled, collect
   `img[src]`, `script[src]`, `link[href]`, `source[src]` into a separate
   `subresources []discoveredLink` list returned on `pageStructure`.
3. Add `admitSubresource()` in `crawler.go` — identical pipeline to `admit()`
   but records `SkipSubresourceDisabled` when the flag is off, so the count is
   visible regardless.
4. Subresource URLs must **not** enter the location fingerprint regardless of
   whether they are fetched (the deploy-hash problem is orthogonal to fetching).

**Files touched:** `discover.go` (walk, pageStructure), `crawler.go`
(admitSubresource, visit), `skip.go` (new SkipReason), `Config` struct.

---

## Phased Delivery Order

| Phase | Gap | Rationale |
|-------|-----|-----------|
| **1** | A — Session wiring | The coordinator is already built and tested. Pure integration, highest capability-to-effort ratio. |
| **2** | D — Concurrency | Mechanical but foundational — all later phases benefit from parallel traversal. |
| **3** | B (static) | `<meta refresh>`, `srcset`, inline JS regex — each a few lines in `discover.go`, no new dependencies. |
| **4** | E — Subresources | Low complexity, config-gated, uses the existing admit pipeline. |
| **5** | C — Navigation graph | Most architecturally novel. Depends on Phase 2 (concurrent runner) to make path replays affordable. |
| **6** | B (headless) | Requires external dependency decision (`chromedp`), CRAWL-02 compliance for browser intercept, and Phase 12 in the roadmap. |

---

## Decision that closes most of the practical gap vs Burp

**On real engagements:** Gap A (session wiring). An unauthenticated crawl of an
authenticated application maps the login page, not the application.

**On modern SPAs:** Gap B’s headless phase. No amount of static HTML parsing
recovers routes built at runtime — the shell is one location whatever the
fingerprinter does.

**On large applications:** Gap D (concurrency). The sequential loop is correct
and safe; it is just slow, and a large app will hit `MaxDuration` before it
hits an empty frontier.
