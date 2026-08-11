# Scanner Upgrade Research — Reaching Burp Scanner Level

> Generated 2026-08-11. Research note, not a plan — findings with evidence, in the
> same verification style as `docs/`: `[VERIFIED: ...]` for claims checked against a
> primary source this session, `[ASSUMED: ...]` for reasoned recommendations.
> Burp-side facts are checked against PortSwigger's own documentation (last
> updated 2026-08-03 per the pages themselves); burpsy-side facts are checked
> against the Go port source (`burpsy-go/`) and `gaps.md`. Where the Go port and
> the Rust reference diverge, the Go port is the live implementation and the one
> assessed here.

## TL;DR

burpsy already runs the published BCheck corpus (264 files, 100% parse) through a
real passive + active audit engine with honest coverage accounting. The distance
to "Burp Scanner level" is **not** the corpus — it is the *surrounding machinery*
Burp uses to make its checks reach more code:

1. **OAST (out-of-band testing)** — ✅ implemented (see §P0-1): a self-hosted
   Collaborator-style interaction server; the 26 corpus checks that need one
   are no longer skipped at load but dispatch when the operator attaches it.
2. **Browser-powered crawling** — absent; static-HTML-only frontier crawl misses
   JS/SPA apps entirely (named Gap B in `CRAWLER_UPGRADE_PLAN.md`).
3. **Insertion-point breadth** — 4 of Burp's 8 types are DSL-namable and
   dispatched (query/header/cookie/body); XML and multipart bodies are now
   modelled containers (2026-08-11), and `param-name` / `path-folder` /
   `path-filename` / `body-whole` are enumerable via the public API but not
   reachable from BCheck grammar (`any` never expands to them); payload
   relocation exists as `Relocations()` but is not wired into dispatch;
   nested encoding and base64 detection are still missing. Non-UTF-8 and
   plain-text bodies stay declined (recorded as skipped, never silently empty).
4. **JS analysis depth** — static lexical one-var taint vs Burp's AST taint +
   headless-browser dynamic confirmation.
5. **Audit prioritization + session maintenance during audit** — no
   attack-surface/interest scoring, no crawl-path replay with checkpoint/rollback.
6. **Native check catalog** — thin: 5 real built-in checks (SQLi, XSS, path
   traversal, retire.js, JWT-weak) + 2 deliberate stubs (SSRF, XXE).

Each is quantified below with the evidence, what it unlocks, and an implementation
sketch. The order is deliberate: the first two items unlock measurable corpus
coverage (checks that today are *counted, not run*), which is exactly the
honest-counting currency this project trades in.

---

## 1. The reference: Burp Scanner

[VERIFIED: PortSwigger documentation, `https://portswigger.net/burp/documentation/scanner`
and subpages, all "Last updated: August 3, 2026".]

### 1.1 Scan structure

- Two phases — **Crawling** (catalog content + navigational paths: follow links,
  submit forms, log in) and **Auditing** (send requests, examine results). They
  can run **in parallel** (audit starts as soon as the first item is crawled).
- Auditing is three phases:
  - **Passive** — observes normal traffic, no modified requests; consolidates
    frequently-occurring issues (e.g. clickjacking across every page) to one
    report instance with all occurrences kept as evidence.
  - **Active** — sends modified requests, in three intensity tiers:
    **light** (few requests; misconfigurations like permissive CORS), **medium**
    (requests that may look malicious; e.g. OS command injection), **intrusive**
    (attempts to confirm exploitation; e.g. SQLi). Tiers are individually
    enable/disable-able.
  - **JavaScript analysis** — hybrid **static** (AST parse, taint flow
    source→sink→path) + **dynamic** (headless browser loads the response,
    injects payloads at DOM sinks, simulates `onclick`, observes whether injected
    data reaches a dangerous sink). Static-only findings get lower confidence
    than dynamically-confirmed ones.

### 1.2 Crawling

- **Browser-powered by default**: an embedded Chromium navigates in both crawl
  and audit phases; handles JS-generated UI, async/event-handler requests,
  clickable elements (`onclick`, `addEventListener`).
- **Content-based location identity**: locations are identified by *contents*,
  not URL — survives ephemeral URLs (CSRF tokens, cache-busters), and
  stateful same-URL-different-content apps.
- **Directed graph** of locations + edges; the crawler never "jumps" to a
  pending link — it navigates contextually or reverts to the start location.
  Tracks **state changes** caused by its own actions (path `ABCD` reaches a
  populated cart that path `AD` cannot); records **non-deterministic edges**
  when repeated visits disagree.
- **Volatile content**: identifies template-vs-variable parts of responses;
  re-identifies the same location across visits despite differences.
- **Bounded**: breadth-first, fingerprints of visited links, configurable
  cutoffs (for "infinite" apps like calendars).
- **Session handling during crawl**: requests are built dynamically from the
  previous response — CSRF tokens in URLs or forms are handled automatically,
  no macros required.
- **Authenticated scanning**: unauthenticated phase first (finds login +
  self-registration forms), optional self-registration, optional
  invalid-username probes, then authenticated crawl per credential set;
  **recorded login sequences** for SSO/complex logins (one method per scan).
- **SPA support**: fragment-routing detection (fragments containing `/ \ ? = &`),
  "click all clickable elements" option, crawl strategies from *Fastest*
  (static sites) to *Most complete* (SPAs).

### 1.3 Auditing

- **Insertion points** — 8 types: URL parameter values; body parameter values
  (form fields, multipart attributes including uploaded file names, XML values
  and attributes, JSON values); cookie values; **parameter names** (added
  arbitrary parameter — always URL, plus body for POSTs); HTTP headers
  (Referer, User-Agent, any `x-*`); **entire body** (XML/JSON); **URL path
  filename**; **URL path folders**.
- **Encoding**: per-type encoding of payloads (URL-encoding, JSON escaping, XML
  escaping); **nested insertion points** (multi-layer encoding, e.g. base64
  wrapping JSON — Burp detects and mirrors the layers); base64 detection.
- **Payload relocation rules**: URL↔body, URL↔cookie, body↔cookie (6 moves) —
  retests a parameter from a different location to bypass per-parameter
  validation/WAFs.
- **Frequent insertion points**: ones that occur in many requests without
  generating issues are identified and given a *lightweight* audit; a full
  audit resumes if the lightweight pass shows server-side processing.
- **Insertion point limits**: a cap per base request, with the skipped count
  reported in the audit item.
- **Prioritization**: each audit item gets a priority score =
  **80% attack-surface exposure** (how many unique insertion points it adds vs
  the queue) + **20% interest level** (action type — POST/PUT/PATCH/DELETE
  higher; content type — HTML/JSON/XML higher; authentication requirement —
  higher). Recalculated as the crawl discovers new items.
- **Automatic session handling during audit**: for crawl-derived items, Burp
  finds the shortest path from the crawl start, re-walks it to refresh session
  tokens, tests path simplifications (often the final request alone suffices),
  handles single-use CSRF tokens by re-issuing the preceding request, and —
  during the audit — **monitors session validity with checkpoints**: on session
  loss it rolls back to the last checkpoint and resumes.
- **Error handling**: granular failure tracking that escalates — repeated
  failures mark: individual checks → individual insertion points → the whole
  request → the whole scan (pause/abort); **follow-up retry passes** re-issue
  requests that timed out after the audit completes.
- **Skip-unlikely-effective**: omits checks irrelevant to a parameter's base
  value (e.g. no path traversal on a value that cannot contain a filename).

### 1.4 Scan configuration surface

- Preset modes: **Lightweight** (≤15 min), **Fast**, **Balanced**, **Deep**.
- Audit behavior: audit speed (fast/normal/thorough), audit accuracy (retry
  counts for blind-technique confirmation — false-negative vs false-positive
  bias), maximum total scan time, network timeouts, repeated-timeout thresholds
  (the escalation in §1.3), issue noise reduction.
- Check selection by **scan type** (passive / light active / medium active /
  intrusive active / JavaScript analysis) or by individual issue.

### 1.5 OAST — Burp Collaborator

[VERIFIED: portswigger.net/burp/application-security-testing/oast and
/burp/vulnerability-scanner; corroborated by the Collaborator docs and the
"Out-of-Band Application Security Testing" blog.]

Burp's blind-checks infrastructure: the scanner injects payloads that trigger an
out-of-band interaction (DNS/HTTP hit to a Collaborator domain) and watches for
the interaction. Detects **blind SQLi, blind XSS, blind OS command injection,
blind SSRF**, etc. — vulnerabilities that never echo anything back in the
response. Collaborator is a network service; OAST is the technique.

### 1.6 BChecks

[VERIFIED: /burp/documentation/scanner/bchecks.]

BChecks are custom checks that Burp runs **in addition to its built-in routine**.
The PortSwigger BChecks GitHub repo is the published, community-maintained check
set. This is the one surface where burpsy is *deliberately* aligned with Burp —
running the same published corpus — which is the project's stated purpose.

---

## 2. burpsy today (Go port, verified from source)

[VERIFIED: `burpsy-go/internal/*` source and `gaps.md`, read 2026-08-11. The Go
port reached parity with the Rust reference on all 13 tracked gaps (gaps.md
header); the Rust reference itself has no crawler, no OAST, no DOM checks, and
no insertion-point dispatch on master (RustScannerMap inventory, e.g.
`ROADMAP.md` Phase 4/5/6 TODOs) — so the Go port is *ahead* of Rust in crawl and
DOM, and the gaps below are gaps of the whole project, not port drift.]

### 2.1 What exists

| Area | State | Evidence |
|---|---|---|
| Passive scan | BCheck corpus per exchange, opt-in `--bchecks DIR`; per-check coverage tracked; findings enriched from the 183-entry catalog | `scanner/passive.go`, `scanner/enrich.go`, `scanner/coverage.go`, `GET /api/scanner/coverage` |
| Issue catalog | 183 transcribed Burp issue definitions, 169 with remediation | `scanner/catalog_data.go:23-25` |
| Active audit engine | 7 dispatch scopes, 9 dispositions, budgets + circuit breakers, ledger; BCheck active checks (`given host/path/request/insertion point`) ride the same machinery; every probe egresses through `AuthorisedSender` | `scanner/audit.go`, `scanner/audit_engine.go`, `scanner/bcheck_runner.go` |
| BCheck active evaluator | M2 `send request`, M3 `given insertion point` / `send payload` with per-point `latest` isolation and `Finding.Param` attribution end-to-end (landed 2026-08-09) | `bcheck/active.go`, `bcheck/insertion.go`, `gaps.md:396-414` |
| Tool runner | Allowlist-gated `run tool` exec, 5-min timeout, 1 MiB output cap, no shell | `scanner/toolrunner.go` |
| Insertion points | query / header / cookie / body (`any`); JSON, form, XML (text+attr+CDATA) and multipart (values+filenames) splice; `param-name`/`path-folder`/`path-filename`/`body-whole` enumerable non-DSL families; `Relocations()` for URL↔body↔cookie; **non-UTF-8 and plain-text bodies declined** | `bcheck/insertion.go` |
| DOM | Static lexical taint analysis, one-var-deep: sources→sinks→sanitizers, budgeted (DOM-01/02/03) | `scanner/dom.go`, `scanner/dom_data.go` |
| Native checks | SQLi, XSS, path traversal (hand-rolled payload/error lists); retire.js (76 components / 683 vulns, real version arithmetic); JWT weak-HMAC (51-word wordlist); **SSRF and XXE are deliberate stubs → `DispositionUnsupported`** | `scanner/scanner.go`, `scanner/js_vulns.go`, `scanner/jwt_weak.go`, `scanner/scanner_checks.go` |
| Crawler | Static-HTML frontier crawler: content-based location fingerprinting, volatile-param URL normalisation, id-shaped segment quota for infinite apps, destructive-action refusal (29-category skip ledger), robots read-not-obeyed; **no JS execution, no subresource fetching, no state-machine re-navigation** | `crawler/crawler.go`, `crawler/fingerprint.go`, `crawler/destructive.go`, `crawler/skip.go` |
| Crawler session gate | Expiry detection (template flip + login-page pattern), bounded relogin through the session coordinator (Gap A) | `crawler/session_gate.go`, `crawler/limits.go` |
| Session handling | Rule-based: validity rules, extraction (regex + JSONPath), cookie jar; single-flight relogin | `session/session.go`, `session/recovery.go` |
| Crawl↔audit parallelism | Live active-audit sweep over newly-completed in-scope exchanges (shared ledger) | `web/liveaudit.go` |
| Reports | JSON, SARIF 2.1.0, self-contained HTML | `scanner/scanner_reports.go`, `report/report.go` |
| Scan configs | 6 of Burp's 29 built-in configs, omitted reasons named | `web/api_scanner_configs.go` |

### 2.2 Corpus position (the honest numbers)

- 264 corpus files, 100% parse (`go run ./cmd/conform`).
- `given` families: response 104, host 98, request 40, path 11, insertion
  point 9 (gaps.md §"How the corpus was counted").
- **26 of 264 checks need a Collaborator interaction server** (`gaps.md:414`).
  They used to be skipped at load; they are now counted as collaborator checks
  and dispatch whenever the operator attaches a server (`-collab-base`) — see
  P0-1, implemented 2026-08-11 with a live-oracle recount below.

---

## 3. Gap matrix

Legend: ✅ aligned · 🟡 partial (named sub-gap) · ❌ absent.

| # | Capability | Burp | burpsy | Delta / what it unlocks |
|---|---|---|---|---|
| 1 | **OAST / Collaborator** | ✅ built-in blind-checks infra | ✅ self-hosted DNS/HTTP/SMTP interaction server behind a `bcheck.Collaborator` seam (2026-08-11) | **26 corpus checks go from skipped to runnable** — verified: dispatch delta with server = LoadReport.Collaborator = 26 |
| 2 | **Browser-powered crawl** (JS rendering, event handlers, clickable elements) | ✅ default Chromium in crawl+audit | ❌ static HTML only (`crawler/discover.go`) | JS/SPA coverage; named Gap B in `CRAWLER_UPGRADE_PLAN.md` |
| 3 | **Crawl: subresource fetching** (img/script/link/…) | ✅ (browser) | ❌ neither fetched nor fingerprinted | attack surface beyond HTML |
| 4 | **Crawl: state-machine re-navigation / contextual graph** | ✅ directed graph, no jumps, state-change detection | 🟡 breadth-first frontier with content fingerprints | stateful-app coverage |
| 5 | **Crawl: volatile content identification** | ✅ template-vs-variable | 🟡 content-hash dedup only | stable identity for volatile pages |
| 6 | **Crawl: automatic session handling** (dynamic CSRF tokens in URLs/forms) | ✅ no macros needed | 🟡 rule-based extraction + session gate | less configuration, more coverage |
| 7 | **Crawl: authenticated scanning** (login-form auto-ID, self-registration, invalid-username probes, recorded sequences) | ✅ | ❌ credentials/headers + relogin gate only | privileged-content coverage |
| 8 | **Audit intensity tiers** (light/medium/intrusive) | ✅ selectable | ❌ uniform; 6-of-29 built-in configs | policy control, safer live scans |
| 9 | **JS analysis: static AST taint** | ✅ AST parse | 🟡 lexical one-var-deep taint | fewer false negatives, real data flow |
| 10 | **JS analysis: dynamic confirmation** | ✅ headless browser | ❌ | static findings confirmed; FP reduction |
| 11 | **Insertion points: breadth** | ✅ 8 types | 🟡 4 DSL kinds dispatched; XML+multipart modelled; 4 more families enumerable | the 9 insertion-point corpus checks + M3 dispatch reach more code |
| 12 | **Insertion points: parameter names / entire body / URL path filename / URL path folders** | ✅ | 🟡 enumerable via `Enumerate`, not reachable from BCheck grammar | server-side-log injection, path-based routing bugs |
| 13 | **Insertion points: encoding + nesting + base64 detection** | ✅ | 🟡 per-type splice + XML/path escaping; no nesting/base64 | multi-layer-encoded data (base64→JSON) |
| 14 | **Insertion points: payload relocation** (URL↔body↔cookie) | ✅ 6 rules | 🟡 `Relocations()` exposed, not wired into dispatch | WAF/per-parameter-validation bypass |
| 15 | **Insertion points: frequent-IP lightweight audit** | ✅ | 🟡 budgets exist, no lightweight heuristic | redundant-work reduction |
| 16 | **Audit prioritization** (80/20 exposure/interest) | ✅ dynamic queue | ❌ | right items first in long scans |
| 17 | **Session maintenance during audit** (path replay, checkpoint/rollback) | ✅ | ❌ | audited requests stay in-session (single-use tokens) |
| 18 | **Error escalation + retry passes** | ✅ granular → pause/abort + follow-up retries | 🟡 circuit breakers/budgets | resilience to flaky apps/WAFs |
| 19 | **Native check catalog depth** | ✅ ~100+ built-in active checks | 🟡 5 real + 2 stubs | the categories BChecks express poorly or the corpus is thin on |
| 20 | **Scan config surface** (presets, speed/accuracy, total-time cap, skip-unlikely-effective) | ✅ | 🟡 6/29 configs, no speed/accuracy knobs | scan policy |
| 21 | **Issue noise reduction** (consolidate frequent passive issues) | ✅ | ❌ | report readability |
| 22 | **Reports** | HTML/XML | JSON/SARIF/HTML | XML report format |
| 23 | **Crawl↔audit parallelism** | ✅ | ✅ live sweep over new exchanges | — (already aligned) |
| 24 | **BCheck corpus execution** | ✅ | ✅ 264 files, 100% parse, honest skips | — (already aligned — the project's core) |

---

## 4. Upgrade roadmap (prioritized)

Priorities are set by the project's own currency — *checks that are counted but
not run*. Every item below that converts a counted-but-skipped check into a run
check comes first.

### P0-1 — OAST interaction service (✅ implemented 2026-08-11)

**Evidence:** `gaps.md:414` — "checks that need a Collaborator interaction
server (26 of the loaded corpus) still count as skipped at load time." The
parser already recognizes `<type> interactions` conditions (`bcheck/parser.go`
:964-971) and `NeedsCollaborator` classification exists (`bcheck/bcheck.go`) —
the refusal was a *runtime* gap, not a parse gap.

**What landed — an in-process recorder, no new deployment surface:**
- `internal/collaborator/collaborator.go` — a stdlib-only interaction server:
  `Config{Base, HTTP, DNS, SMTP}`, one 12-hex token per issued address
  (`<token>.<base>`), wildcard DNS A-records (HTTP listener's IP, NOERROR only
  under the base, NXDOMAIN otherwise, TTL 60), an HTTP recorder that logs the
  request then answers 200, and a minimal SMTP responder (EHLO/MAIL/RCPT/DATA,
  full session transcript, 10s deadline). An empty listener address disables
  that protocol; traffic never matching an issued token is kept as noise and
  never attributed — an interaction is only ever reported if the server
  actually observed it.
- `bcheck.Collaborator` seam beside `ToolRunner` (`bcheck/active.go`):
  `NewAddress() string` + `Interactions(addrs) (dns, http, smtp bool)`. The
  evaluator resolves `generate_collaborator_address()` (appends to the check's
  issued set) and evaluates boolean `dns|http|smtp|any interactions` by polling
  the server directly — in-process, no poll API, honest by construction.
- `InteractionSettleTimeout = 300ms` (package var, 50ms poll) lets async
  triggers land (a proxy forwarding an injected header after answering);
  synchronous fetches (blind SSRF, fastjson DNS during send) hit on the first
  poll with no added latency.
- Counted-but-excluded policy, unchanged for an absent seam: `LoadReport
  .Collaborator` counts the checks at load, `scanner.corpusActiveChecks` admits
  them only when `WithCollaborator` is set — exactly the tool-runner gate.

**Two latent bugs this exposed and fixed:**
- `exprHasInteractions` (the `NeedsCollaborator` classifier) tested for a
  different parse shape than the parser produces (`is "interactions"` vs
  operator `interactions`). It answered false for *every* real collaborator
  check, so those 26 loaded as ordinary active checks and were dispatched —
  sending empty-address probes rather than being refused. The load report now
  buckets them correctly.
- `ActiveChecks()` dropped collaborator checks at load (counted but not kept),
  which made the seam gate unreachable: a scan with `-collab-base` silently ran
  without them. They are now counted *and* kept, exactly like the tool set.

**Live-oracle recount** (blind-ssrf + fastjson family + forwardedRequests, run
against the published corpus at `/tmp/BChecks`, 264 files / 100% parse):

```
LoadReport summary: 264 files: 105 passive, 127 active, 26 collaborator,
6 need insertion point, 0 need tools, 0 parse errors
active checks: nil seam=137, with server=163 (delta = the collaborator set)
```

- The dispatch delta with a server attached (26) equals LoadReport.Collaborator
  (26) exactly — every collaborator check is admitted when the seam is present
  and excluded when it is not.
- Corpus e2e tests (`internal/bcheck/collaborator_test.go`) verify the verdicts
  against a live oracle: HTTP fetch of an issued address reports an `http
  interactions` hit, a raw UDP DNS query reports a `dns` hit, SMTP via embedded
  token in RCPT, attribution isolation between two addresses, and refusal
  preserved when the seam is nil.
- CLI surface: `-collab-base <domain>` enables the server (issued addresses
  `<token>.<base>`); `-collab-http/-collab-dns/-collab-smtp` default to
  `127.0.0.1:18888/15353/12525`, `""` disables a protocol; an unbindable
  listener refuses startup rather than half-wiring an oracle. Real deployment
  binds :80/:53 behind a wildcard record for the base.
- Nothing is faked: `smtp interactions` never fires without an SMTP listener;
  DNS wildcard answers resolve to the HTTP recorder so a resolving target's
  fetch is observed twice, like Burp.

### P0-2 — Insertion-point breadth (grows M3 dispatch coverage)

**Evidence:** `bcheck/insertion.go` — XML, multipart, and non-UTF-8 bodies are
`Declined`; parameter names, entire-body, URL path filename/folders absent.

**Design sketch [ASSUMED]:**
1. XML body splicing (value + attribute) — Burp escapes payloads for XML
   contexts; a small XML tokenizer suffices (no full DOM needed for splicing).
2. Multipart parameter values and uploaded-file *names*.
3. Parameter-name insertion points (added `x-<payload>` param).
4. URL path filename and folder tokens.
5. Payload relocation rules (URL→body, URL→cookie, …) behind a config flag —
   they multiply request count, so default off, consistent with the project's
   budget philosophy.
6. Nested/base64 encoding detection (base64-decode the parameter, resplice,
   re-encode) — `base64_decode` already exists as a BCheck builtin, so the
   primitive is present.

**Deliverable metric:** corpus checks that were `Declined` at dispatch due to
body type now run; conformance re-count with the new `IpKind`s.

### P1-1 — Browser-powered crawl (Gap B; the largest coverage gap)

**Evidence:** `crawler/discover.go` (a/area[href], iframe/frame[src], forms
queued; img/script/link/source/embed/video/audio neither fetched nor
fingerprinted); `crawler/crawler.go` named limits (no JS, no subresources,
one-at-a-time, no state-machine re-navigation); `CRAWLER_UPGRADE_PLAN.md` Gap B.

**Design sketch [ASSUMED]:**
- Headless Chromium driven from Go (`rod` is the natural fit — pure Go,
  no Node dependency), behind a `Browser` seam so the existing frontier engine
  and the browser engine share the same capture/session/scope gates.
- Browser engine responsibilities: render page, wait for network idle,
  enumerate the rendered DOM (links, forms, clickable elements), record
  async/XHR/fetch requests as discovered URLs, support fragment-routing
  detection and "click all clickable" as crawl-strategy options.
- The existing content-fingerprint and template-quota machinery applies
  unchanged to browser-discovered locations.
- Progressive: static engine stays the default for pure-HTML targets; browser
  engine engages when JS is detected (or via config).

### P1-2 — JS analysis depth (AST taint + dynamic confirmation)

**Evidence:** `scanner/dom.go` — lexical, one-var-deep taint.

**Design sketch [ASSUMED]:**
- Static: replace the lexical pass with a real JS AST taint analysis (a Go JS
  parser such as `goja`'s parser, or `github.com/tdewolff/parse` for a lighter
  pass) — multi-assignment data flow, sanitizer tracking. Keep the existing
  source/sink tables (`dom_data.go`).
- Dynamic: reuse the P1-1 browser engine to load the response, inject payloads
  at DOM sinks, and observe sink reachability — Burp's own hybrid (static
  alone = lower confidence; dynamic confirmation = higher). The confidence
  distinction should be carried into `Finding`.

### P2 — Scan-level machinery

- **Audit prioritization** (80/20 exposure/interest): the ledger already
  counts dispositions per item; add an exposure score from insertion-point
  uniqueness and reorder the plan queue. [ASSUMED: highest value once
  insertion points are broad — P0-2 is a prerequisite.]
- **Session maintenance during audit**: requires the crawl graph (P1-1);
  replay shortest path, refresh tokens, checkpoint/rollback on session loss.
- **Error escalation + retry passes**: map Burp's granular failure thresholds
  onto the existing breaker/budget machinery; add the follow-up retry pass.
- **Native check depth**: implement the SSRF/XXE stubs (server-side request
  forgery needs the OAST service for the blind half — another reason OAST is
  P0); expand SQLi/XSS/path-traversal payload+error-pattern sets; grow the
  JWT wordlist (51 vs Burp's 103,975 — the corpus count is honest, the
  wordlist need not be).
- **Config surface**: audit speed/accuracy knobs, total-time cap, issue
  consolidation for frequent passive findings.
- **XML report format** if consumers need it (JSON/SARIF/HTML exist).

---

## 5. What "Burp Scanner level" honestly means here

This project's value is honest counting, so the claim needs the same discipline:

- **Reachable and countable:** run the published BCheck corpus at Burp-level
  fidelity — 264/264 parsed, 264/264 runnable given the operator attaches the
  interaction server and tool runner (26 collaborate via `-collab-base`; the
  remaining dispatches depend on scan config), with per-check coverage. OAST
  (P0-1) is done: the largest countable skip now dispatches.
- **Not honestly claimable without the native catalog:** "detects everything
  Burp does". Burp's built-in active checks are a proprietary ~100+ check
  catalog; burpsy's native set is 5 real checks + 2 stubs. The BCheck corpus
  is PortSwigger's *published extension* set — running it is real coverage but
  is not the built-in catalog, and the doc/code should keep saying so.
- **The claim to make:** "runs the entire published BCheck corpus (the same
  checks Burp users import), plus N native checks, with every skipped or
  unverifiable result reported — no partial result dressed as complete."

Suggested success thresholds per item (all corpus-driven, all measurable):

| Item | Success threshold |
|---|---|
| OAST | ✅ 26/26 collaborator checks dispatch with a server attached (delta verified == LoadReport.Collaborator) and verdict against a live oracle in e2e tests |
| Insertion points | XML/multipart/param-name/path-part corpus checks stop being `Declined` |
| Browser crawl | a JS/SPA fixture yields the same locations a human browser sees |
| JS analysis | DOM-01/02/03 findings carry static vs dynamic confidence |
| Prioritization | audit queue order matches attack-surface exposure on a fixture |

---

## Appendix — Sources

Burp (PortSwigger documentation, all "Last updated: August 3, 2026"):
- `/burp/documentation/scanner` — scan structure, phase overview
- `/burp/documentation/scanner/auditing` — 3 audit phases, prioritization, insertion points, encoding, relocation, session handling, error handling
- `/burp/documentation/scanner/crawling` — browser crawl, content identity, graph, state, volatile content, authenticated scanning
- `/burp/documentation/scanner/scan-configurations/audit-settings` — 8 insertion point types, check tiers, audit speed/accuracy, timeout escalation
- `/burp/documentation/scanner/scan-configurations/preset-scan-modes` — Lightweight/Fast/Balanced/Deep
- `/burp/documentation/scanner/scanning-spas`, `/scanner/browser-powered-scanning`, `/scanner/bchecks`
- OAST: `/burp/application-security-testing/oast`, `/burp/vulnerability-scanner`, `/burp/documentation/collaborator` (via web search, 5 corroborating sources)

burpsy (read 2026-08-11): `burpsy-go/internal/scanner/*`, `internal/bcheck/{active,insertion,parser,bcheck}.go`, `internal/crawler/*`, `internal/session/*`, `internal/web/api_scanner_*`, `burpsy-go/gaps.md`, plus Rust reference inventory (`crates/scanner`, `crates/bcheck`, `ROADMAP.md`, `.planning/STATE.md`) for the parity baseline.
