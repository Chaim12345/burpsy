# Web UI Burp-Parity — WORKING MEMORY (live tracker)
> Created 2026-08-19. This file is the durable record for the page-by-page UI parity work.
> UPDATE IT after every file read/write/verification. Do not re-derive facts already stored here.
> MASTER LEDGER: see `2026-08-19-webui-full-plan.md` for the full task plan (P0–P5) with acceptance checks.
## Goal
Bring `burpsy-go/internal/web/ui` (React SPA) to full Burp Suite look-and-feel parity —
menus, data, actions, UX — page by page, then desktop shell later.
## VERIFIED API SURFACE (do not re-read these — trust this)
### ui/table.tsx — VirtualTable<T> props
```
data, columns (Column<T>=ColumnDef<T,any>), getRowId:(row)=>string, ariaLabel:string (REQUIRED),
selectedId?:string|null, onSelect?:(row)=>void, onActivate?, menuGroups?:(row)=>MenuGroup[],  // NOTE: prop is "menuGroups", NOT "contextMenu"
rowClassName?:(row)=>string|undefined, loading?, empty?:ReactNode, density?, height?, initialSort?,
enableColumnVisibility?, columnVisibility?, onColumnVisibilityChange?
```
### ui/layout.tsx — SplitPane props
```
master:ReactNode, detail:ReactNode, orientation?: "vertical"|"horizontal",  // NOTE: NOT first/second/direction
storageId:string (REQUIRED), defaultMasterSize?:"58", minMasterSize?:"20", className?
```
Also exports: PageHeader (title, description, actions), RefreshButton.
### ui/menu.tsx
```
MenuAction { id, label, icon?, shortcut?, danger?, disabled?, onSelect:()=>void }
MenuGroup  { id, actions: MenuAction[] }
ContextMenu({groups, children})  — right-click wrapper
DropdownMenu({groups, trigger, align?})  — click-to-open
```
### ui/primitives.tsx
Button({variant:"primary"|"outline"|"quiet"|"danger", size, ...}), IconButton({label, size}), Input, Select (plain <select className="input select">),
Badge({tone?}), Field({label, hint, children}), Toolbar, Empty({title, detail, action}), ErrorNotice({title, detail}),
Metric({label, value, detail?, accent?, tone?}) → renders .card.metric, Kbd, Spinner, Tooltip({content, children}),
Switch({checked, onCheckedChange, label}), Checkbox({checked, onCheckedChange, label}),
Tabs/TabsList/TabsTrigger/TabsContent (Radix), Modal({open, onOpenChange, title, description?, children, wide?})
Tone = "neutral"|"good"|"warn"|"bad"|"info"|"accent"
### ui/editor.tsx — HttpEditor props
```
value, onChange?, readOnly?, label?, actions?, height?, filename?, placeholder?, className?, views? (default true)
Views: pretty/raw/hex/render. Only RAW is editable ("exact bytes").
```
### lib/data.ts hooks
useHistory(q, limit=500) → Exchange[]; useMessage(id); useDebounced(value, ms);
useStats/useScope/useIntercept(poll)/useToolLog(filter,search,limit);
useAnnotateExchange() → mutate({id, notes?, highlight?});
useInterceptControls() → {setEnabled, forward({id, raw}), drop(id)};
useInvalidate(); keys = {...history:(q,limit)=>["history",q,limit]...}
### lib/api.ts
api<T>(path, init?), json(method, body), query(params), formatBytes, formatDuration, relativeTime,
statusTone, copyToClipboard, downloadText(filename, text, type="text/plain"), authorityFromRaw
### lib/actions.ts — useExchangeActions()
returns {sendToRepeater, sendToIntruder, sendToComparer(ex, "a"|"b"), addToOrganizer, copyUrl, copyCurl, filterByHost, menu(ex, extra?)}
menu() = 3 groups: send (Repeater R / Intruder I / Comparer A / Comparer B), copy (URL / curl / id), organise (Organizer / filter by host)
### lib/data.attack.ts
useInterceptDetailed(pollMs=1500) → InterceptStateDetail {enabled, wired, hint?, pending, held:HeldMessageDetail[], holds_every_request?, holds_every_response?}
useInterceptRules(dir), useSaveInterceptRules(dir), useForwardHeld(), attackKeys.interceptRules(dir)
### lib/types.ts
Exchange {id, request, response, host, port, method, path, status, response_len, started_ms, duration_ms, tls, protocol, mime?, source?, notes?, related?, highlight}
HIGHLIGHTS = ["none","red","orange","yellow","green","cyan","blue","pink","magenta","gray"]; HIGHLIGHT_TONE map
### lib/types.attack.ts
HeldMessageDetail {id, direction, host, port, tls, method, path, status, held_ms, len, raw}
InterceptStateDetail (see above); InterceptRuleSpec {enabled, field, kind, match, comment}; InterceptDirection = "requests"|"responses"
### Go backend (internal/web/server.go routes — verified)
/api/intercept (GET status), /api/intercept/enable (POST), /api/intercept/rules/ (GET/PUT),
/api/intercept/ (subtree: per-held id ops — forward/drop at /api/intercept/{id}/forward, /api/intercept/{id}/drop)
/api/history, /api/message/{id}, /api/exchange/{id} (PATCH notes/highlight), /api/scope, /api/tools/organizer (POST),
/api/tools/log, /api/ws/*, /api/crawl, /api/audit/, /api/stats, /api/issues
### internal/query DSL fields (query.go)
host, status, method, path, mime, body — operators = != >= > <= < ~ (substring) ; AND/OR/NOT/parens
### history.tsx CURRENT STATE (622 lines, verified intact)
Has: STATUS_BUCKETS filter, METHODS select, term DSL box (debounced 260ms), limit select, scopeOnly toggle,
hideNoResponse toggle, HighlightPicker, note input (annotate), Inspector toggle, QueryHelp modal,
VirtualTable w/ menuGroups (actions.menu + extra groups), rowClassName highlight classes,
detail pane (HttpEditor request/response + Inspector + badges + Repeater/Intruder/Compare buttons),
hotkeys (arrows j/k nav?), escapeQueryString/scopeToQueryFragment helpers for scope-only filtering
## PAGE STATUS
| Page | File | Status | Notes |
|---|---|---|---|
| Proxy/Intercept | pages/intercept.tsx | ✅ FULL PARITY | Drop All (backend one round trip, honest count), queue direction filter, context menu (Forward/Drop/Copy URL/Copy cURL with shortcuts), Original vs Edited tabs, status bar. Commits a5deab4/cbc043d/e5938a2 |
| History | pages/history.tsx | ✅ FULL PARITY | DSL search, status/method/MIME filters, row limit, scope toggle, MIME/Type column, CSV export, status bar with honest counts, highlight picker, notes. Commits 599e489/9ec0b76 |
| Repeater | pages/repeater.tsx | ✅ BUILT (313 lines) | Multi-tab (persisted in store), per-tab response history with paging, Inspector toggle, Send via /api/repeater/send, To-Intruder handoff, mod+Enter hotkey |
| Scanner | pages/scanner.tsx | ✅ BUILT (802 lines) | Issue table with severity dots + filters, live active-audit toggle, passive coverage view, config selector, advisory/request/response tabs, report download |
| Intruder | pages/intruder.tsx | ✅ BUILT (790 lines) | Positions/Payloads/Resource pool/Settings/Results tabs, sniper/battering_ram/pitchfork/cluster_bomb modes, payload sets, results table |
| Target/SiteMap | pages/sitemap.tsx (555) + scope.tsx | ✅ BUILT | Host→path→segment tree with expand/collapse + search, VirtualTable with actions.menu; scope editor shared with settings |
| Dashboard | pages/dashboard.tsx | ✅ BUILT (255 lines) | Metrics (coverage summary), task table (crawl/audit/attack), activity feed, all from useDashboard |
| Decoder | pages/decoder.tsx | ✅ BUILT (391 lines) | Chained decode/encode/hash steps, auto-decode, live /api/tools endpoints |
| Comparer | pages/comparer.tsx | ✅ BUILT (327 lines) | A/B message diff with nav + download |
| Sequencer | pages/sequencer.tsx | ✅ BUILT (584 lines) | Paste-live token source tabs, /api/sequencer/analyse, encodings |
| Settings | pages/settings.tsx | ✅ BUILT (501 lines) | Protocols, appearance/theme, CA download, diagnostics, scope editor (shared with Scope page) |
| Logger | pages/logger.tsx | ✅ BUILT (365 lines) | Tool-log table, filter/search, column visibility, menuGroups, VirtualTable |
| Organizer | pages/organizer.tsx | ✅ BUILT (333 lines) | Saved exchanges list + notes via useOrganizer, SimpleTable |
| Match/Replace | pages/matchreplace.tsx | ✅ BUILT (457 lines) | Rule list + editor, test against pasted request, /api/tools/rules wiring |
| WS History | pages/wshistory.tsx | ✅ BUILT (284 lines) | Connection list + frame detail, ContextMenu, VirtualTable with menuGroups |
| Session | pages/session.tsx | ✅ BUILT (1064 lines) | Rules (match/action), cookies table, login macro runner |
## BACKEND GAPS IDENTIFIED (add when frontend needs them)
- [ ] POST /api/intercept/drop-all — batch drop (currently frontend loops N drop calls; works but N round-trips)
- [ ] GET /api/history?format=csv (or client-side export — prefer client-side downloadText from loaded rows)
- [ ] IP address column in history — Exchange has no ip field → need core.Exchange + api_types.go change if we add it
- [ ] Delete-from-history — TrafficStore is append-only by design → document as deliberate gap instead of implementing
## VERIFICATION COMMANDS
cd burpsy-go/internal/web/ui && bun run check   # tsc --noEmit + token checks
cd burpsy-go/internal/web/ui && bun run build   # bundle to dist/ (style.css + dist/app.js)
cd burpsy-go && go build ./... && go vet ./... && gofmt -l .   # Go gate (only if Go changed)
cd burpsy-go && go test ./internal/web/...                    # web tests
## PROGRESS LOG
- 2026-08-19a: Survey complete (src tree 17 pages, 11 ui components, package.json deps verified: radix context-menu, dropdown-menu, dialog, switch, tabs, tooltip; tanstack query/table/virtual; react-hotkeys-hook; sonner; lucide; codemirror; zustand persist)
- 2026-08-19b: intercept.tsx enhanced version written (21.3KB) — KNOWN BUGS listed above, must fix before typecheck
- 2026-08-19f: history.tsx Burp-parity: MIME type filter dropdown (8 options incl. Binary = non-text-ish), client-side filter composed with status/method in the rows useMemo (dep array +mime), CSV export button in PageHeader actions exporting ID/Timestamp/Method/Host/Port/Path/Status/Length/MIME/Duration via downloadText (no backend needed), Download icon + downloadText imports. bun check + bun build GREEN. Diff: +60/-2 across 1 file.
- 2026-08-19g: history.tsx status bar added (MIME column was already present): shows visible rows over loaded total, summed response bytes, pending count, selected exchange. bun check + bun build GREEN.

- 2026-08-20a: Full audit — all 17 page components verified built (255–1064 lines each), every page wired in nav.ts, whole app typechecks (bun run check exit 0), whole Go tree builds/vets/formats clean, go test ./... passes across every package including internal/scanner (401s).
- 2026-08-20b: Desktop bridge (P4) committed as adbf8ec: cmd/desktop/main.go (Wails v2, hybrid reverse-proxy AssetServer onto in-process web.Server, native menu bar, bound SaveFileDialog/OpenFileDialog/Notify), internal/web/ui/src/lib/runtime.ts (getRuntimeMode/isDesktop + dialog/notify wrappers), docs/DESKTOP.md (operator guide + honest known-gaps list). go.mod picks up wails/v2 v2.15.0.
- 2026-08-20d: Burp-parity verification pass ("verify we have all same pages menus and settings as burp"). Result: 17 routes verified (nav.ts = e2e harness ROUTES, enforced by routes.spec.ts); every Burp tool present (Dashboard, Target→Site map/Issues/Scope, Proxy→Intercept/HTTP history/WebSockets/Match & Replace, Intruder, Repeater, Sequencer, Decoder, Comparer, Logger, Organizer, Session, Settings); Settings page covers Scope/Protocols/Appearance/Certificate/Diagnostics. Verification FOUND ONE REAL DEFECT: desktop shell emitted burpsy:navigate/burpsy:menu Wails events with NO frontend subscriber — every native menu item dead while DESKTOP.md claimed the shell listens. Fixed: runtime.ts onDesktopEvent (EventsOn/EventsOff wrapper), app.tsx desktop menu bridge effect, api.ts historyToCSV shared helper (one CSV shape for both doors), history.tsx refactored onto it, cmd/desktop Tools menu expanded 4→9 items (all hotkey-bound tools in nav order), DESKTOP.md corrected with a historical note. Gates: bun run check 0, go build/vet/gofmt clean.
- 2026-08-20c: Plan ledger (2026-08-19-webui-full-plan.md) P1/P2 rows corrected from stale NOT STARTED to verified ✅ with evidence. P3-3/P3-4 remain deliberate gaps (documented).

## FINAL HONEST PARITY REPORT (2026-08-20)

### What is done
- **17/17 pages** built, wired in src/nav.ts, typechecking, rendering. Two (Intercept, History) have explicit Burp-parity enhancements committed in this branch; the other 15 were built in an earlier span and verified at audit time.
- **Desktop bridge (P4)**: Wails v2 shell, hybrid mode (one server, two doors — desktop window and remote browser render byte-identical UI), native menu bar, file dialogs, notification events. Binary builds with plain go build (no wails-cli asset pipeline required).
- **Backend gaps (P3)**: /api/intercept/drop-all implemented (one round trip, honest count); CSV export handled client-side via downloadText; IP column and delete-from-history documented as deliberate gaps (Exchange has no ip field; TrafficStore is append-only by design).
- **Gate**: go build ./... clean, go vet ./... clean, gofmt -l . clean, go test ./... all ok, bun run check clean, bun run build produces 1.40MB bundle.

### What is honestly not done (documented, not hidden)
- **-db not wired in desktop shell** — flag accepted, persistence not opened; every desktop session starts empty. Documented in docs/DESKTOP.md Known gaps.
- **No system tray icon** — only native menu bar. Needs wails build asset pipeline to bundle an icon.
- **No native OS notification** — Notify emits a frontend event rendered as sonner toast. Wails v2 classic runtime has no cross-platform Linux notification without per-OS wiring.
- **-tools, -bchecks, -intercept-tls, scope flags, -scan-config** not exposed in desktop shell. Operator configures these through the same web UI panels once the window opens.
- **No single headline parity percentage** — consistent with the project's honest-counting value. Per-page feature lists above are the evidence; no aggregated number is published until someone re-verifies against a running Burp instance.

### Commits in this branch (ui-react-comparison)
- a5deab4 web(intercept): add Drop All — one round trip, honest count
- cbc043d web(intercept): Burp-parity enhancements — direction filter, context menu, message view tabs
- e5938a2 web(intercept): status bar (intercept ON/OFF, queue count, filter indicator)
- 599e489 web(history): MIME type filter + CSV export
- 9ec0b76 web(history): status bar with honest capture counts
- d8dbc17 docs(plans): full WebUI Burp-parity plan and task ledger
- fde7e86 docs(plans): point working memory at master task ledger
- 13b9b71 docs(plans): correct page status to verified reality; mark P1/P2 complete
- adbf8ec desktop: Wails v2 shell, hybrid reverse-proxy, native menus and dialogs
## PROGRESS LOG (2026-08-21 session — finishing the dsh session's five gaps)

Recovered context from dsh session 6a3d3ca7 into docs/plans/2026-08-20-dsh-session-context.md,
then closed every gap it had committed to:

- 6669247 web(settings): /api/stats gains proxy_bind/web_bind/tls_interception; Settings gains
  Proxy listener/Web console/TLS metrics + Scanner configs section; organizer swatches; e2e tests
  re-pinned to the Darcula+compact defaults 7d0c7d5 shipped (its 151/151 claim was false).
- 288889b web(scope): standalone Scope page — Burp-style rule table (Kind|Host|Port|Path), add
  with optional port/path arms, exact-tuple remove. Backend already supported all of it.
- 6481352 web(shell): menu bar burpsy/File/Repeater/Tools/View/Help — Tools lists every tool with
  alt+N; View gains Reset panel layout (clears burpsy.split.*). menubar.spec.ts pins it (574786c).
- 5f468d3 web(wshistory): Frame | Handshake tabs — Handshake renders the upgrade request/response
  via useMessage(exchange.request/.response). No backend change needed.
- 926ba57 web(settings): Hotkeys section from shared lib/shortcuts.ts registry.
- 2b435d2 web(actions): row context menus gain "Add <host> to scope" and "Audit exchange #N".
- bbf8a0b web(logger): method + status-class filters (client-side over loaded rows).

All verified against a running server with agent-browser (real keypresses, real right-clicks, real
WS traffic seeded through the proxy via raw RFC6455). Deliberate gaps after this session:
scan-config creation wizard (would expose engine knobs that do not exist), settings/rules
import-export (needs new endpoints), scope protocol arm (core change), Extensions/plugins (no
plugin API by design), system tray (Wails asset pipeline).

## PROGRESS LOG (2026-08-21 session, later — configuration portability)

- dd0781f web(config): GET /api/config/export and POST /api/config/import carry scope + intercept
  rules + session handling rules as one atomic bundle. Import converts every section before
  touching state — an invalid rule anywhere refuses the whole bundle with 400 and nothing applied
  (pinned by api_config_test.go: export round-trips all three surfaces, clean-server apply,
  refusal atomicity). File menu gains Export configuration (blob download) and Import
  configuration… (hidden input, result modal with per-surface counts, blanket query invalidation).
  Import is riskScope in the route manifest: the bundle rewrites what the engagement may touch.
  Verified live via agent-browser: valid bundle replaced scope wholesale (qa-roundtrip.test tuple
  pair), invalid bundle left it untouched.
- Scope protocol arm assessed and scoped in ui-gaps.md (six layers: core match, caller-side scheme
  plumbing in sender/proxy/crawler, scope_rules_v3 migration per the v2 precedent, wire fields,
  UI select+column, parity-ledger entry). Deferred as one coherent change rather than half-migrated.

Final gate at close: go build/vet/gofmt clean; go test ./... = 31/31 packages ok; e2e-ui.sh run
recorded in docs/plans/2026-08-21-final-gate.md.

## PROGRESS LOG (2026-08-24 session — the DOM engine reaches the shipped binary)

Review of the lightpanda/obscura work found the capability was tested but unreachable from
production: cmd/burpsy wired no browser provider AND ScanConfig.CheckDOM defaulted false — two
gates, `plain=3` active checks dispatched by the real binary while the suite demonstrated 160/160.
Closed by 776cca2:

- `-dom` flag: "" (off), "chrome"/browser-path (LookPath-resolved at the command line), or
  ws://…/wss://… CDP endpoint. Attaching flips CheckDOM per the WithCorpusChecks precedent;
  WithConfig can turn it back off.
- /api/stats dom_engine/dom_checks + Settings → Browser engine section (Burp's User-options-Misc
  slot, beside Hotkeys). Read-only on purpose: enabledChecks reads config unlocked and the lazy
  provider caches one browser for process lifetime — live switching would be a data race wearing a
  settings dialog. Recorded here so nobody re-litigates without addressing both hazards.
- Measured through the real binary vs vulnapp: chrome launches headless chromium (RSS ~161MB×2),
  DOM XSS Tentative→Firm, 7→11 findings; lightpanda ws:// byte-identical results at RSS 33MB.
  lightpanda sinks: 18/20 parallel, 20/20 serialised — its CDP server drops parallel dials
  ("could not dial: EOF"), a server-side concurrency limit, not a sink defect. obscura not
  installed on this machine (validated upstream, v0.2.1).
- Engine guidance until connection serialisation exists: chrome is the honest default; lightpanda
  is the memory win behind a serialisation gate; obscura remains the validated fast option.

Still open from the audit that surfaced all this: the shipping binary's default dispatch set is
THREE checks (CheckSqli/Xss/PathTraversal) — CheckSSRF true but unexercised in the A/B, XXE false,
CheckCorpus false unless a corpus loads, and no CLI surface for any of it. Burp's default audit
covers far more. This is the next increment: decide the shipped defaults deliberately, with the
-scan-config list as the model, rather than leaving NewActiveScanner's struct literal as policy.

## 2026-08-25 — runtime scan config + dashboard/settings control surfaces (commits 8b7dc63, 10bfa10)

- **ScanConfig is runtime state**: `ActiveScanner.mu` + `ConfigSnapshot()`/`UpdateScanConfig(fn)`;
  `GET/PUT /api/scanner/config` (whitelisted keys, ms durations, unknown key → 400); persisted via
  `persist.Save/LoadScanConfig` (nil-for-absent — main previously clobbered defaults with a zero
  config on first launch, showing concurrency 0). Precedence: persisted edits beat launch flags.
- **Passive-by-default**: `CheckHeaders`, `CheckPassivePosture` (15), `CheckPassiveAnalysis` (28),
  `CheckHostDiscovery` (3) now default true in `NewActiveScanner`.
- **Settings → Audit checks card**: all 21 family switches grouped active/passive/corpus+DOM,
  concurrency/timeout steppers, unsaved badge, batch Save. Verified live: toggle OOB → Save →
  server `check_out_of_band: true`.
- **Dashboard control surfaces**: New scan modal (Burp scan-type cards; unbuilt ones honestly
  disabled "not built yet"), New live task modal, per-task progress bars (indeterminate pulse when
  fraction unknown), cancel route `POST /api/tasks/{id}/cancel` (registry.Cancel finally reachable),
  severity strip renders whenever issues are loaded (0 findings genuinely means 0 high).
- **Standing live-audit row**: while enabled, a LIVE AUDIT row stays visible between sweep batches
  (registry only records per-batch rows); driven by /api/scanner/live, stop button disables sweep.
  Verified: enable → row; stop → row gone + toast + server enabled:false; crawl → batch row with
  26 findings from 4 exchanges, honest bounded summaries.
- **Design-system lesson**: `Field` mints branded `LabelledId` via children render-prop — passing a
  plain string `id` to Input/Switch is a type error by design; `--radius-sm` emits unitless "2" so
  raw px + `token-exempt` comment is the established pattern.
- **Library research (librarian, 2026-08-25)**: adopt nothing now. Two real candidates tied to
  future features: recharts (dashboard activity/severity charts) and golang.org/x/time/rate
  (intruder/scan throttling). Everything else (RHF, dnd-kit, validator, errgroup, SSE lib) either
  duplicates working hand-rolled code or has no consumer today — no dep without a user.

## 2026-08-25 (later) — the agent worktrees are merged: proxy options, audit queue, collaborator, discover, issue definitions

Five parallel agent worktrees (from a credit-exhausted opencode ultraworker session) were
reviewed, merged one at a time into `ui-react-comparison`, and gated. Landed:

- **U12 proxy options** (`132f924`/`c23198e`/`8c9ea01`): `proxy.Options.Set/Snapshot/Counters/
  KnownOption`, `GET/PUT /api/proxy/options` (flat map PUT, validate-all-before-apply, 400 names
  the refused key), and the Proxy-settings leaf — six switches + outcome counters, route in
  routes.ts AND nav.ts (routes.spec.ts asserts the palette matches routes.ts exactly).
  Test contract: `newTestServerWithProxyOptions` builds `NewServer(...).WithProxyOptions(...)`.
- **U6 audit queue** (`514d838`/`1688d22`): `/api/scanner/audit-items` + SCANNER-tab queue card —
  what the audit did per item and why anything was skipped.
- **U1 match/replace live** (`bd6908`/`0bcdb83`): match/replace reaches live traffic via the
  shared `matchReplaceRules` pointer.
- **U7 issue definitions** (`495b17b`/`e25623f`): Issue definitions catalogue page (Burp's
  browseable catalogue, not just findings).
- **U8 discover** (`5ebb83c`): Discover tab + in-app operator reference pane (the console
  explains itself).
- **U4 collaborator** (`d9d93aeb`-era `361deb0`/`9094fab`): collaborator tab in nav, cache keys,
  bundle; `data.collab.ts` hooks; fufuf/nuclei discovery from the server.
- **`dd93aeb`**: main.go wires the five capability handles (stored-input ledger, provenance
  ledger, session coordinator, CheckJSLibs, CheckJWTWeak) — the shipped binary stops refusing
  work its engine can do.

**Merge-method lessons** (reusable): (1) the gate catches what eyeballing misses — missing route
registrations, imports from modules that don't export the symbol (`api`/`json` live in ./api not
./data), missing cache-key registry entries, pages without PageHeader (the route sweep requires
an `<h1>` per route); (2) predictable collisions between sibling agents: both declare
`mintedPayload` with different shapes, manifest splice order matters (collaborator sorts before
config); (3) merge one worktree at a time, gate between each — the batch-then-fix alternative
cost opencode its session.

**Remaining from the agent batch**: any worktree under `/root/burpsy/.claude/worktrees/` not in
this log is unreviewed; the collaborator tab needs a configured live listener before its panel
means anything; UAT 0/1300 unchanged.
