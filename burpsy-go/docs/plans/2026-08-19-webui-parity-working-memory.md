# Web UI Burp-Parity — WORKING MEMORY (live tracker)
> Created 2026-08-19. This file is the durable record for the page-by-page UI parity work.
> UPDATE IT after every file read/write/verification. Do not re-derive facts already stored here.
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
| Proxy/Intercept | pages/intercept.tsx | 🟡 REWRITE IN PROGRESS | Enhanced version WRITTEN but has 3 bugs to fix: uses contextMenu= (must be menuGroups=), SplitPane props wrong (direction/first/second → orientation/master/detail/storageId), missing ariaLabel. Drop-all = N client-side drop calls (no backend endpoint yet) |
| History | pages/history.tsx | ✅ ENHANCED | MIME type filter dropdown (HTML/JSON/XML/JavaScript/CSS/Images/Binary), CSV export button (client-side from loaded rows via downloadText utility). Existing features preserved: DSL search, status/method filters, scope toggle, row limit, highlight picker, notes. TODO: MIME column in table, status bar counts |
| Repeater | pages/repeater.tsx | ⏳ NOT STARTED | |
| Scanner | pages/scanner.tsx | ⏳ NOT STARTED | |
| Intruder | pages/intruder.tsx | ⏳ NOT STARTED | |
| Target/SiteMap | pages/sitemap.tsx + scope.tsx | ⏳ NOT STARTED | |
| Dashboard | pages/dashboard.tsx | ⏳ NOT STARTED | |
| Decoder | pages/decoder.tsx | ⏳ NOT STARTED | |
| Comparer | pages/comparer.tsx | ⏳ NOT STARTED | |
| Sequencer | pages/sequencer.tsx | ⏳ NOT STARTED | |
| Settings | pages/settings.tsx | ⏳ NOT STARTED | |
| Logger | pages/logger.tsx | ⏳ NOT STARTED | |
| Organizer | pages/organizer.tsx | ⏳ NOT STARTED | |
| Match/Replace | pages/matchreplace.tsx | ⏳ NOT STARTED | |
| WS History | pages/wshistory.tsx | ⏳ NOT STARTED | |
| Session | pages/session.tsx | ⏳ NOT STARTED | |
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
- NEXT: history.tsx MIME column + status bar counts → Repeater page → Scanner/Intruder pages
