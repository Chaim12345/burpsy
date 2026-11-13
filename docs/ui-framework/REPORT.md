# UI framework review & vertical slice — REPORT

Worktree: `/root/burpsy-wt-ui-framework` (branch `ui-framework`). Date: 2026-10-29.
Live data: own burpsy instance on 127.0.0.1:18180/18190, `-db /tmp/ui-fw/bench.db` (read-only `.backup` copy of `/root/bench-juice-pi/burpsy/bench.db`: 783 exchanges, 1829 messages, 394 findings, 13.4 MB stored). The running burpsy on 8080/8090 was never touched; no traffic was sent through the proxy.

## 1. Current UI — measured, not guessed

Console: `burpsy-go/internal/web/ui`, Bun-built React 19 SPA embedded via `//go:embed` in `internal/web/ui.go`, served at `/` by `s.mux.HandleFunc("/", s.handleUI)`.

| Metric | Old SPA (measured live) | New /ui2/ (measured live) |
|---|---|---|
| JS bundle | `app.js` = **2,757,261 B (2693 KB)** transfer | htmx.min.js **50,917 B** + sse.min.js **3,523 B** (54 KB raw, ~18 KB gzip) |
| CSS | style.css 79 KB | inline in layout.html (~4 KB) |
| Total transfer on first load | **~3.0 MB** (app.js + style.css + ~20 shell API calls) | **~89 KB** (2 scripts + 1 HTML page) |
| DOMContentLoaded | ~180–290 ms | **269 ms** |
| History rows fetched | `/api/history?limit=500` = **226 KB** JSON, all parsed into React state | server renders **100 rows/page = 35 KB** HTML; next pages via infinite scroll (`hx-trigger="revealed"`) |
| Issues list | `/api/issues` full = **1,135 KB**; `?summary=1` = **215 KB** | **14.6 KB** HTML, grouped by issue+host, severity counts in the meta line |
| History filter `?search=login` | client-side over 500-row page | server-side: **9.2 KB**, "16 of 783 rows" in 0.75 ms |
| Detail (one exchange) | JSON row + `/api/message/{id}` per half, rendered client-side | **1.4 KB** HTML with both panes, 1.2 ms |
| DOM nodes (history view) | 1,835 | **941** (100 rows) |
| JS heap | 48 MB (React runtime) | 48 MB baseline browser heap, no framework runtime |

Old UI's fetch shape: `useHistory(q, limit=500)` in `src/lib/data.ts:409` pulls 500 index rows per query; issues badge is `?count=1` (1 KB) but the tree page pulls the summary (215 KB) or full (1.1 MB); everything polls `/api/intercept` + `/api/scanner/live` on a loop plus SSE `/api/events`.

### Missing / badly shown in the old UI (from code + live pass)

- Issue evidence excerpt lives only in the full `/api/issues` body (1.1 MB for 394 findings); the summary the tree actually loads omits it, so evidence is one row-click and one full fetch away — the new UI puts evidence in the detail pane reached from the grouped list.
- Request/response pairing: history rows carry message ids only; the viewer fetches `/api/message/{id}` per half. Fine, but on a **restored project** (this tree's restore path leaves `Exchange.Request` nil — verified: all 783 bench rows serve `request: null` though the DB `request_msg` column is populated and message bytes exist), the old viewer shows an empty request pane with no explanation. /ui2/ shows an explicit "No request bytes recorded" note instead of a blank `<pre>`.
- No server-side paging: the history page is capped at 500 rows client-side; deeper rows need the datasets API by hand.
- 100k+ row captures: React holds every row of the current page in state plus the virtualizer; /ui2/ never holds more than one page server-side (O(total) scan of index rows, O(page) render).

## 2. Framework research — server does the work, client minimal

Candidates measured (GitHub API 2026-10-29, CDN byte counts, release cadence):

| Framework | Stars | Last push | Releases | Client bytes (min/gzip) | Fit for single-binary Go embed |
|---|---|---|---|---|---|
| **htmx 2.0.4 (+sse ext)** | ~84k (htmx-org) | active | v2.0.4 current | **50.9 KB / 16.4 KB** (+3.5 KB sse) | vendored file, `//go:embed`, zero Go deps |
| Datastar 1.0.4 | 5,203 | 2026-09-21 | v1.0.4 | ~11–21 KB claimed | npm-only dist; needs build or CDN pin |
| templ (a-h) | 10,593 | 2026-10-28 | v0.3.1100 (weekly) | 0 (compile-time) | **new Go dependency** + codegen step |
| go-app | 8,975 | 2026-10-22 | — | **whole WASM binary (~2 MB+)** | contradicts "client minimal" |
| godom (siongui) | 179 | **2022-10-12** | **none, no tags** | WASM via GopherJS (~MBs) | stale 4 years; rejected |
| Vugu | 5,014 | 2026-09-23 | sparse | WASM | same WASM problem |
| Hotwire/Turbo | 7,399 | 2026-09-29 | v8.0.23 | ~100 KB+ | heavier than htmx, same model |
| Preact/Solid/Lit/Svelte | 38k–88k | active | — | 3–45 KB each | still a client framework; needs build; virtualised lists only solve the list, not the payload |

Scored comparison (1–5; weights: single-binary fit 30%, client weight 25%, streaming/live 20%, 100k-row lists 15%, maturity 10%):

| | htmx+sse | Datastar | templ+htmx | go-app/Vugu/godom | Preact/Solid |
|---|---|---|---|---|---|
| Single-binary Go embed | 5 | 4 | 3 | 1 | 3 |
| Client weight | 4 | 5 | 4 | 1 | 3 |
| Streaming (SSE) | 5 (ext) | 5 | 5 | 2 | 4 |
| Big lists | 4 (server paging) | 4 | 5 | 2 | 4 (virtualizer) |
| Maturity | 5 | 4 | 5 | 2 | 5 |
| **Weighted** | **4.55** | 4.35 | 4.10 | 1.55 | 3.45 |

**Decision: stdlib `html/template` + vendored htmx 2.0.4 + its SSE extension, served under `/ui2/`.** The obvious answer (godom, WASM, "write UI in Go") loses on every axis that matters here: stale since 2022, ships a multi-MB WASM blob per page load, and puts a second runtime in the browser. templ would add a codegen dependency for markup that is already trivially expressible as five small templates — the server-rendering half is stdlib either way. htmx keeps the client to 54 KB raw and the server owns all rendering, paging, filtering, and grouping, which is exactly the "fast under load" property: cost is O(rows scanned) on the server and O(page) in the browser, never O(total) in the DOM.

## 3. What was built (vertical slice)

New files:
- `burpsy-go/internal/web/ui2.go` — handlers: `/ui2/` (shell), `/ui2/history` (server-paged, `q` DSL + `search` + `offset`/`limit`, fragment when `HX-Request`), `/ui2/history/{id}` (request/response panes), `/ui2/issues` (grouped by issue+host, severity counts), `/ui2/issues/{id}` (evidence, occurrences, advisory detail), `/ui2/htmx.min.js`, `/ui2/sse.min.js`.
- `burpsy-go/internal/web/ui2/` — 5 `html/template` templates + vendored htmx 2.0.4 (sha256 e209dda5…) and sse ext (6ca6a3c3…).
- `burpsy-go/internal/web/ui2_test.go` — 8 Go tests: shell render, HX fragment, server-side search+paging (incl. sentinel presence/absence), detail 200/400/404, **HTML-escaping of attacker bytes** (`<script>` in a path), issues grouping + severity classes, issue detail, asset serving + old-UI catch-all intact, 405s on wrong verbs.

Wiring (all additive, old UI untouched):
- `server.go` `setupRoutes`: 7 `s.route("/ui2/…", …)` literal patterns before the `/` catch-all.
- `route_manifest.go`: 7 entries, `riskAsset`, sorted.
- `internal/mcp/groups.go` `notExposed`: 7 entries with reasons (browser-navigated assets, JSON API is the agent surface).
- `ui_route_reachability_test.go` `uiRouteExempt`: 7 entries with reasons.
- `json_nil_slice_test.go` `nonJSONAsset`: 7 entries (`<!doctype html` / `text/javascript` markers).
- Regenerated derived files: `gated-routes.ts`, `route-risk.ts`, `gated-routes.contract.json` (via `BURPSY_UPDATE_GATE_CONTRACT=1`), `api-schema.d.ts` (via `bun run gen:api-types` with the pinned `tools/api-types` toolchain).

Live-update: the layout opens `/api/events` through the htmx SSE extension; a 3-line inline script re-issues the current view's request when a `history`/`issues` frame arrives (coalesced server-side at 150 ms, so a saturated crawl cannot flood the tab).

## 4. Verification run

- `go build ./...`, `go vet ./...`, `gofmt -l .` — clean.
- `go test ./internal/web/ -run TestUI2` — **8/8 pass**.
- Manifest/gate/MCP/openapi suites: `Test_every_registered_route_is_in_the_manifest`, `Test_every_route_pattern_is_a_literal`, `Test_the_manifest_is_sorted_by_pattern`, `Test_every_route_rejects_a_verb_it_does_not_implement`, `TestEveryOperatorFacingRouteIsReferencedFromTheConsole`, `TestNoRouteExemptionIsStale`, `TestOpenAPICoversEveryManifestRoute`, `TestEveryMutatingRouteVerbDeclaresItsInput`, `TestGatedRouteContractFixtureIsCurrent`, MCP `TestEveryRouteVerbIsReachableFromExactlyOneGroupedTool` / `TestNoGroupedToolSpansTwoRiskClasses` — all pass.
- Full `go test ./internal/web/` — only failure is `Test_no_get_route_serves_a_null_on_empty_state` on `/api/issues/` (400 "Invalid issue ID"), **confirmed pre-existing on clean HEAD** (stashed my changes, same failure).
- Live smoke against the bench DB: `/ui2/history` 200 (35 KB, 4.5 ms), `?search=login` 200 (9.2 KB), `/ui2/history/780` 200, `/ui2/issues` 200 (14.6 KB, 394 findings, severity counts rendered), `/ui2/issues/1` 200, assets 200, old `/` and `/app.js` unchanged. Browser pass via agent-browser: DCL 269 ms, 100 rows rendered, 941 DOM nodes, click-through to detail pane works, screenshots in `/tmp/ui-fw/shot-ui2-*.png`.

## 5. Summary — what was built, numbers, what's next

**Built:** a server-rendered `/ui2/` console (stdlib templates + vendored htmx+SSE) with end-to-end History (server-paged, DSL filter, substring search, infinite scroll, request/response detail) and Issues (grouped, severity-counted, evidence in detail), live-refresh via the existing `/api/events` SSE hub, served alongside the untouched React SPA.

**Numbers vs old UI (same bench data):** 3.0 MB → 89 KB first load; 226 KB history JSON → 35 KB HTML page (100 rows, server-paged); 1.1 MB issues JSON → 14.6 KB grouped HTML; detail 2 JSON calls → 1.4 KB HTML.

**Not verified / known gaps:**
- On this tree, restored projects serve `request: null` for every exchange (the `ex.Request = core.MsgPtr(...)` line present in commit e2cda670 is absent from HEAD's `LoadExchanges`; the DB column is populated). /ui2/ renders an explicit note instead of a blank pane; fixing the restore wiring is a separate pre-existing bug, not part of this slice.
- `internal/mcp` screenshot test fails for a missing `ui/node_modules` in this environment — pre-existing, unrelated.
- The old UI's `bun run check` was not run (no `node_modules` in this worktree); the regenerated TS files were produced by the repo's own generators and the Go-side contract tests pass.
- Only History and Issues were sliced; Intercept/Scanner/Scope/Target pages are the next pages in the migration plan (each is one template + one handler + one manifest entry, per this slice's pattern).

## 6. Load test — 2k events/sec (added after the first slice)

In-process harness (`internal/web/ui2_load_test.go`, 5 tests, all passing): 20k seeded
exchanges (each firing a `changeHistory` notify through the store observer), while a goroutine
floods `live.notify(changeHistory)` at 2000/sec, while 1200 requests hit 6 ui2 paths:

| Measurement | p50 | p90 | p99 | max |
|---|---|---|---|---|
| `/ui2/history` (+filter/search/offset/issues variants) under flood, 20k rows | 5.6 ms | 15.1 ms | 31.8 ms | 53.0 ms |
| Detail pane (`/ui2/history/{id}`, reads message bytes) under flood | 16.7 µs | — | 73.7 µs | 225 µs |
| Filter typing (growing `search=` prefixes, 60 requests) | 9.7 ms | — | 24.9 ms | 26.6 ms |
| Old SPA catch-all `/` under flood | 1.9 µs | — | 31.7 µs | — |

SSE coalescing under flood: 2000 notifies/sec → **6.7 frames/sec** (the hub's 150 ms window
ceiling), carrying every one of ~2950 notifies exactly once (Swap-claim in `flush`). The
browser's re-fetch loop is therefore capped at ~7 refreshes/sec no matter how hard the
capture path fires — the property that keeps the tab responsive during a saturated crawl.

Live browser pass under a background load generator (~470–520 req/s hammering
`/api/history`, `/api/issues`, `/api/dashboard`, `/api/stats`, `/api/events/stats`,
`/api/scope` — read-only, no proxy traffic): `/ui2/history` answered 200 in 6.9 ms;
first load DCL 238 ms with 3 resources (htmx 50 KB, sse 4 KB, app.js 2 KB); heap 13 MB;
942 DOM nodes. Infinite scroll drove 100 → 200 → 300 → 400 → 401 rows with exactly one
live sentinel at all times (older sentinels removed after each swap), each page fetch ~19 ms.
Filter `path~rest` narrowed 783 → 103 rows; `path~rest` + `search=login` → 16 rows; URL
carries the state (`?q=…&search=…`), so filtered views are bookmarkable. Row click updates
the detail pane and marks the row selected; issue occurrence rows deep-link into history
detail. DSL syntax note: `path:` is not valid — the operator uses `path~x` / `path=x`
(the API's own error text names the valid operators; /ui2/ shows it inline).

## 7. UX audit — /ui2/ vs old SPA

Driven with agent-browser against the bench DB (screenshots in `/tmp/ui-fw/shot-ui2-*.png`):

| Aspect | Old SPA | /ui2/ | Verdict |
|---|---|---|---|
| First paint | 2.7 MB JS parse before anything | 56 KB JS + server-rendered HTML, DCL ~240 ms | **ui2 wins** |
| History under 783 rows | 500-row JSON page + virtualizer, 1,835 DOM nodes | 100 rows/page server-paged, 942 DOM nodes, infinite scroll works | **ui2 wins** |
| Filter/search | client-side over the loaded page; URL state via hash | server-side `q` DSL + `search`, state in the query string (shareable URL) | **ui2 wins** |
| Detail pane | 2 JSON fetches, blank request pane on restored projects | 1 HTML fragment; explicit "No request bytes recorded" note | **ui2 wins** (honesty) |
| Issues | 1.1 MB full JSON for evidence; tree from 215 KB summary | 14 KB grouped list, evidence in per-issue detail, occurrences deep-link to history | **ui2 wins** |
| Live updates | SSE + 350 ms debounce + React re-render of the whole list | SSE → htmx fragment swap of just `#rows` (≤7/s coalesced) | **ui2 wins** (smaller DOM churn) |
| Empty state | — | "0 of 783 rows · search zzzznomatch · page 0–0" + "No rows match." row | ok |
| a11y basics | Radix landmarks, WCAG-tagged live pass | `header`/`nav`/`main` landmarks, `role=region` panes, `aria-live=polite` detail, `aria-label` on both filter inputs, `scope=col` on all `th`, `lang=en`, no images-without-alt, no empty links | ok (basic pass done; full axe run not done — no node_modules here) |
| Console errors | — | none observed during the whole driven session | ok |
| Keyboard | old SPA has hotkeys (Ctrl+R etc.) | **/ui2/ has none yet** — gap, listed below | old UI wins |
| Multi-select rows, send-to tools, context menus | present in old SPA | **absent in /ui2/** — gap | old UI wins |
| Dark mode | theme toggle | `prefers-color-scheme` only, no manual toggle | old UI wins |
| Intercept / Scanner / Scope / Target / Repeater pages | full | **not in the slice** | old UI wins |

**Honest gaps of the slice:** no keyboard shortcuts, no row multi-select/actions, no manual
theme toggle, only History + Issues exist. These are the next migration pages, not defects
of the chosen approach — each is one template + one handler + one manifest entry.

## 8. Bugs found while testing (fixed in this branch)

1. **Infinite scroll stalled after page 1**: the sentinel's `hx-swap="outerHTML"` on `#rows`
   replaced the whole block, and every appended page re-added a sentinel with the same id, so
   only the first ever fired. Fixed: append mode (`offset` present + `HX-Request`) emits
   rows-only via `history_rows_append.html` with `hx-swap="beforeend"` on `#rows-body`, and
   `app.js` removes all but the newest `.sentinel-row` after each swap. Pinned by
   `TestUI2HistoryAppendFragmentIsRowsOnly`.
2. **`html/template` choked on inline JS**: the layout's `<script>` block ended in a JS
   regex/brace context the template parser reads as non-text. Fixed by moving all client JS
   to a static `/ui2/app.js` (also a new asset route + manifest entry).
3. **a11y**: added landmark roles, `aria-label`s, `scope=col`, `aria-live` on the detail pane.

## 9. Full migration (second commit, b124f82d) — all 18 tool pages in /ui2/

Every old-UI tool now has a server-rendered page under /ui2/, sharing one nav partial and the
same SSE live-refresh: Dashboard, Site map, Scope, Intercept (+ enable/disable/forward-all/
drop-all actions), HTTP History, Issues, WebSockets, Proxy settings (listeners, options,
match&replace, passthrough), Repeater (editor + send through /api/repeater/send), Decoder
(decode/encode/hash), Comparer, Logger (server-paged, infinite scroll), Organizer, Session,
Extensions, Scanner (configs, BCheck corpus, coverage, live-audit, queue), Issue definitions,
Settings overview. Each page reuses the existing JSON handler's own view builder server-side,
so ui2 and the JSON API cannot drift. 24 Go tests cover every page (shell+fragment, markers,
nav completeness, decoder md5, comparer diff, intercept actions, 405s).

**UAT (agent-browser against the bench DB, all live):** all 18 pages answer 200 with the shell
(4.6–41 KB each, 2–51 ms); nav has 19 links; dashboard shows "783 exchanges · 1829 messages ·
13453497 bytes · suite running"; sitemap renders 190 nodes; history infinite-scroll 100→201
rows with one live sentinel, `status=403` filter narrows 783→24, row click fills the detail
pane and marks the row selected; decoder run returns md5("hello") correctly; comparer renders
a diff. 17 screenshots + a 17 s walkthrough video + overview grid were emailed to
awayt3005@proton.me via proton-cli (message in Sent, 2026-10-30).

**Remaining honest gaps (old SPA still wins these):** keyboard shortcuts, row multi-select /
send-to-tool actions, manual theme toggle, Intruder attack launch UI, Collaborator/Sequencer/
content-discovery/DOM-auditor/authz interactive flows, and per-row edit forms (intercept edit,
organizer notes, scope rule editor). Each is one template + one form handler + one manifest
entry following the established pattern; the read-only surfaces are all migrated.

**Pushed:** branch `ui-framework` at `b124f82d` on origin (two commits on top of 0827f083).
Final gates: gofmt/vet/build clean, all TestUI2* (24) and MCP route tests pass; the only
web-package failure remains the pre-existing `/api/issues/` nil-slice one confirmed on HEAD.
