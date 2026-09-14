# UI-parity re-verification — Target (Site map, Issues, Issue definitions, Audit queue), Scope, Proxy (Intercept, HTTP history, WebSockets history, Match & Replace, Proxy settings)

Read-only sweep against the live console at http://127.0.0.1:18281/, 2026-09-14.
Baseline: `burpsy-go/docs/ui-parity-audit-complete.md` (2026-08-27).
Burp reference: `/root/burp-re/out/strings/map_root.tsv` and the bundled docs under
`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/`.

Route note: the audit's page names are not the hashes. Real ids from `internal/web/ui/src/nav.ts`:
`sitemap, scope, scanner` (= Issues), `advisories` (= Issue definitions), `auditqueue, intercept,
history, wshistory, matchreplace, proxysettings`. An unknown hash leaves the previous page mounted,
so every query below carries `location.hash` + the rendered `h1`.

---

## 1. Target -> Site map

| Audit claim | Status | Evidence |
|---|---|---|
| Crawl paths view — missing (HIGH) | **CLOSED** | `#sitemap` h1 `Site map`; `[...main.querySelectorAll("button")].map(e=>e.innerText)` -> `["URL view","Crawl paths","Engagement tools",...]`. Clicking `Crawl paths` re-renders main to `... Crawl paths \| Engagement tools \| 9 NODES \| 7 EXCHANGES \| ... \| No crawl has run \| Crawl paths show how the crawler reached each page ...` |
| Passive scan branch — missing (MEDIUM) | **CLOSED** | Toolbar button `Passive scan branch` present (`disabled=1` with no node selected). Also a context-menu item: right-click the `zebra` tree row -> `Add 127.0.0.1 to scope \| Passively scan this branch \| Actively scan this branch (crawl) \| Delete branch \| Delete this item only \| Copy URLs in this branch` |
| Passive scan selected — missing (MEDIUM) | **CLOSED** | Same menu; host-node right-click gives `Passively scan this host`. Selection-scoped, exactly as Burp does it. |
| Site map filter: "Advanced dialog vs Simple text" (MEDIUM) | **CLOSED** | Not a single text box: `input{Filter site map}` + `button{Type filter}` + `button{Status filter}` + 4 checkboxes (`In scope only`, `Requested only`, `Parameterized only`, `Hide not-found`) |
| Read-only indicator — missing (LOW) | **CLOSED** | `pages/sitemap.tsx:799,806` `readOnly`; `:820` `readOnlyNote="This request has already been sent, so it is read-only here. Send it to Repeater to change it and try again."` |
| URL view is the only view (LOW) | **CLOSED** | Three views: `URL view`, `Crawl paths`, `Engagement tools` (the last holds `Find comments \| Find scripts \| Find references to… \| Search \| 0 MATCHES`) |
| Items added / Responses queued / Responses processed counters (LOW) | **STILL-OPEN** | Header shows only `8 NODES` / `6 EXCHANGES`. `grep -n -iE 'items added\|queued\|processed' pages/sitemap.tsx` -> no matches. Burp strings: `burp.Zreo 5770 "Site map items added:"`, `5771 "Responses queued:"`, `5769 "Responses processed:"` |
| Warning bar — missing (LOW) | **UNVERIFIED** | I could not pin down which Burp control this names. The nearest site-map string is `burp.Zx 7450 "Site map crawl paths view is empty"`, which burpsy has an equivalent of ("No crawl has run"). Not claimed either way rather than guessed. |

## 2. Target -> Issues (`#scanner`)

| Audit claim | Status | Evidence |
|---|---|---|
| Tree structure Host->Path->Finding vs "Flat list" (HIGH) | **CLOSED** | `#scanner` h1 `Issues`. `main.innerText` -> `25 FINDING(S) \| 127.0.0.1 \| 25 \| /zebra \| 10 \| HTTP PUT method is enabled \| Certain \| ... \| /alpha?q=1 \| 3 \| ...`. Tree disclosure buttons: `aria-label` = `Collapse 127.0.0.1`, `Collapse /zebra`, `Collapse /alpha?q=1`, `Collapse /beta`, `Collapse /mango/deep/path`, `Collapse /quokka?size=8` |
| Issue details "Minimal" (MEDIUM) | **CLOSED (source-cited)** | The browser host dropped before I could select a finding, so this row is source, not observation. `pages/scanner.tsx:13` imports `AdvisoryReader` from `../ui/advisory`; `:591` `const advisory = selected ? (…)`. That is the same renderer I *did* watch produce Description / Recommended remediation / Classifications / References live on `#advisories` (`ui/advisory.tsx:55-71`). The pane adds `TriageCommentEditor` (`:93`) and a `Copy issue detail` action (`:423-429`) that the definitions page has no equivalent of |
| Audit settings "Button only" (MEDIUM) | **CLOSED** | `Scanner controls` button on the page, and `nav.ts` now carries a dedicated `scannerlaunch` leaf labelled `Scanner` / "Launch an audit and choose what it runs" — the audit's P0 #1 ("Scanner tab — no scan configuration UI") no longer holds |
| Severity counts / Confidence filter | **CLOSED (was already ✓)** | `1 HIGH \| 14 LOW \| 10 INFORMATIONAL`; `Show only` Critical/High/Medium/Low/Informational; `Confidence` Certain/Firm/Tentative; `Hide false positives`. Export as `HTML \| JSON \| SARIF` (not in the audit at all) |

## 3. Target -> Issue definitions (`#advisories`)

| Audit claim | Status | Evidence |
|---|---|---|
| Documentation link — missing (LOW) | **CLOSED** | Select `SQL injection`, then `[...main.querySelectorAll("a[href]")]` -> `Web Security Academy: SQL injection -> https://portswigger.net/web-security/sql-injection`, `Using Burp to Test for Injection Flaws -> https://support.portswigger.net/...`, `Web Security Academy: SQL Injection Cheat Sheet`, plus `CWE-89`, `CWE-94`, `CWE-116`, `CAPEC-66` |
| Count / severity counts / search | **CLOSED (was already ✓)** | 183 definition buttons; `select{Typical severity filter}` -> `All severities/High (57)/Medium (22)/Low (36)…`; `input{Search issue definitions}` |

## 4. Target -> Audit queue (`#auditqueue`)

| Audit claim | Status | Evidence |
|---|---|---|
| Total items counter — missing (LOW) | **CLOSED** | Header metrics: `PENDING 0 \| AUDITING 0 \| COMPLETED 1 \| BOUNDED 0 (hit a budget or breaker) \| FAILED 0 \| OUT OF SCOPE 0`, and `1 row(s) · Burp status parity: 6/15 modelled (not modelled: Light-auditing, Light-audited, NOT_LIGHT_AUDITED, Skipped, …)` |
| State badges "Minimal" (MEDIUM) | **CLOSED** | Colour-coded, not just text: `pages/auditqueue.tsx:29-36` `function stateTone(state): "good" \| "bad" \| "warn" \| "info"` maps complete/audited→good, fail/abandon→bad, bound/pause/cancel/skip→warn, pending/audit→info; applied at `:115` `<Badge tone={stateTone(item.state)}>`. Live row renders `AUDITED AUDITED`. The page also states its own coverage (6/15 Burp statuses modelled) rather than implying parity |
| Insertion points "Toggle only" (MEDIUM) | **CLOSED (gated on data)** | Live shows `button "Points (0)"`, `disabled=1`, `title="No insertion points were recorded for this item"` — the one seeded item recorded none. `pages/auditqueue.tsx:145-147` labels it `Hide`/`Points (N)` once `insertion_points.length > 0`, and `:165-180` expands a full-width `<tr colSpan={6}>` listing `{point.kind}/{point.name}: {point.status} — {point.detail}` per point. A detail view, not a toggle; unexercised because the fixture has no points |

## 5. Scope (`#scope`)

| Audit claim | Status | Evidence |
|---|---|---|
| Advanced scope control — missing (MEDIUM) | **CLOSED** | `Advanced scope control` is a literal section heading in `main.innerText`: `... \| Advanced scope control \| RULE KIND \| Include \| Exclude \| ... \| HOST MATCH \| Wildcard \| Regular expression \| IP range \| ... \| PATH MATCH \| Prefix \| Regular expression ...`. Burp string `burp.Zrda 8632 ", use advanced scope control for regex capability."` — the capability the toggle unlocks in Burp is regex host/path matching, which burpsy exposes unconditionally |
| URL scope / Custom scope / Use suite scope (LOW) | **NOT-APPLICABLE** (all three) | The three labels are one control group in Burp, and it is not on Target > Scope. `burp.Zrgn` holds `21001 "Use suite scope [defined above]"` *and* `21005 "Use custom scope"`; `burp.Zgw7` holds `-20979 "Use suite scope [defined in Target tab]"`, `-20961 "Use custom scope"` *and* `-20971 "URL scope"`; `burp.Zhwl` pairs `1322 "Custom scope"` with `1328 "URL scope"`. These are the per-tool scope selector on Scanner/Intruder config panels — filed against the wrong page. |
| Save to library — missing (LOW) | **STILL-OPEN** | `grep -n -iE 'library' pages/scope.tsx` -> no matches. Burp: `burp.Zhw_ -13442 "Save to library"` sits in the same class as `burp.Zhw_ -13456 "Use advanced scope control"`, i.e. the scope panel |
| Add/Edit/Remove, include/exclude, protocol, port/path | **CLOSED (was already ✓)** | `Add rule`, `Edit rule`, `Remove rule`, `Paste URL`, `Clear scope`, sortable headers ENABLED/KIND/HOST/PORT/PROTOCOL/PATH. Plus `Drop all out-of-scope requests` (not in the audit) |

## 6. Proxy -> Intercept (`#intercept`)

The live queue is empty (`PENDING 0`, `Queue is clear`), so the per-message toolbar is not mounted.
Each row below therefore cites source with the gating condition named, not an empty page.

| Audit claim | Status | Evidence |
|---|---|---|
| Forward button "context menu only" (HIGH) | **CLOSED** | `pages/intercept.tsx:1186-1190` renders `<Button onClick={forward}><Send size={14}/>Forward</Button>` in a `<Toolbar>`; `:815` action id `forward`; `:1195` comment "Burp's queue toolbar pairs Forward with 'Forward all'"; `:1285` `Drop all ${held.length}`. Gated on a selected held message |
| Drop button "context menu only" (HIGH) | **CLOSED** | `pages/intercept.tsx:828-829` action id `drop`, label `Drop`; bulk `Drop all` at `:1285` |
| Action menu "Minimal" (HIGH) | **CLOSED** | `pages/intercept.tsx:768-859`: `Send to Repeater`, `Send to Comparer (A)`, `Send to Comparer (B)`, `Send to Decoder`, `Forward`, `Drop`, `Do intercept the response to this request`, `Copy as curl` (`:888`) |
| Comment button — missing (MEDIUM) | **CLOSED** | `pages/intercept.tsx:1124` `aria-label={`Annotation comment for held #${selected.id}`}` |
| Highlight button — missing (MEDIUM) | **CLOSED** | `pages/intercept.tsx:1131-1136` `aria-label={`Highlight colour for held #${selected.id}`}` with `<option value="">No highlight</option>` |
| Edit target — missing (MEDIUM) | **CLOSED** | `pages/intercept.tsx:1056-1064`, cites Burp's own control: `BurpClass9694.java proxyInterceptEditTargetButton`; label `Edit target — currently ${describeTarget(...)}` |
| In-scope only — missing (MEDIUM) | **CLOSED** | `pages/intercept.tsx:1161-1183` `label="Only intercept in-scope messages"`, `disabled={!data?.scope_attached}` with the reason in a tooltip |
| Open browser — missing (LOW) | **NOT-APPLICABLE** | Burp's string sits in the Intercept tab class beside the interception toggle itself: `burp.Zrxt 14836 "Open browser"`, `14835 proxyInterceptTargetLabel`, `14838 "Toggle message interception"`, `14839 "Intercept off"`, `14845 "Intercept on"`; the other hit is `burp.Zw5t 3956` with `3957 toolEmptyStatePanel`. It launches Burp's embedded Chromium. burpsy's console is already running in the operator's browser, so there is no embedded browser to launch |
| Enable/disable, queue table | **CLOSED (was already ✓)** | Toggle `{Intercept is on}`; header `WIRED \| Intercept is off \| PENDING 0 \| MODE Passing \| TRANSPORT Connected \| QUEUE DEPTH 0`; columns `✓ # DIR METHOD HOST PATH STATUS HELD LEN`; direction select `All messages / Requests only / Responses only / WebSocket → server only / WebSocket → client only`; second tab `Interception rules` -> four rule lists (`Hold requests…`, `Hold responses…`, `Hold client frames…`, `Hold server frames…`), each `ON \| FIELD \| MATCH \| KIND \| ACTION \| COMMENT \| ORDER` with `Add rule` / `Save` |

## 7. Proxy -> HTTP history (`#history`)

| Audit claim | Status | Evidence |
|---|---|---|
| Per-column filters — missing (MEDIUM) | **CLOSED (partial)** | `Column filters` toggle reveals `main [aria-label="Per-column filters"]` -> `HOST \| PATH \| RESPONSE BODY`, inputs placeheld `api.example`, `/admin`, `searches response bytes`. The panel states its own limit: "extension, params, length, time and comment cannot be expressed in the query grammar and so have no filter here" |
| MIME type filter "single select" (MEDIUM) | **CLOSED** | `Type` is a multi-select bucket menu: `HTML \| JSON \| XML \| JavaScript \| CSS \| Images \| Binary \| Reset type` (`STATUS_BUCKETS`/`MIME_TYPES` at `pages/history.tsx:1234-1249`) |
| Status filter "single select" (LOW) | **CLOSED** | `Status` menu: `2xx success \| 3xx redirect \| 4xx client \| 5xx server \| No response \| Reset status` |
| Show highlighted — missing (LOW) | **CLOSED** | `More filters` -> `SHOW ONLY \| Parameterized requests \| Commented items \| Highlighted items` (`pages/history.tsx:1470-1471`) |
| Show commented — missing (LOW) | **CLOSED** | Same popover, `Commented items` |
| Auto-scroll — missing (LOW) | **CLOSED** | `button "Auto-scroll" {Keep the bottom of the table in view as new rows arrive}` |
| In-scope only (from the cross-cutting list) | **CLOSED** | `button "In scope only"`, plus `Hide items without responses`, `Filter {Suspend every filter below without clearing it}` |
| History context menus — none (MEDIUM, P2 #18) | **CLOSED** | `document.querySelectorAll("[role=menu],[role=menuitem]").length` = **0** before, **29** after dispatching `contextmenu` on `main tbody tr`. Items: `Send to Repeater \| Send to Intruder \| Send to Sequencer \| Send to Comparer (A) \| Send to Comparer (B) \| Send to Decoder \| EDIT A COPY IN REPEATER \| Change request method (GET/POST) \| Change body encoding \| Toggle chunked transfer framing \| Copy URL \| Copy as curl \| Copy exchange id (#6) \| Copy request to file \| Copy links \| Save request and response \| Highlight \| Add comment \| Add to Organizer \| Filter history by 127.0.0.1 \| Open URL in browser \| Show response in browser \| Add 127.0.0.1 to scope \| Audit exchange #6 \| Actively scan this branch (crawl) \| Actively scan this host (crawl) \| ENGAGEMENT TOOLS \| Record an issue \| Generate CSRF PoC \| Copy response bytes` |
| Bambda mode — missing (HIGH) | **STILL-OPEN (re-ranked LOW)** | `grep -rn -i bambda` over `internal/web/ui/src` -> only `lib/reference.ts:360-362`, which records it as a decision: "importBambda takes Java source. The filter substrate here is the closed typed grammar above, deliberately not a scripting engine." Burp side: `burp.Zg5m -1433 filterBambdaModeRadioButton`. burpsy's substitute is a documented DSL (`Filter syntax` dialog: fields `host, status, method, path, mime, body, length, duration, extension, params, highlight, comment, header["…"]`, operators `= != ~ >= in`, `and/or/not`) |
| Column visibility (not in the audit) | **burpsy wins** | `button{Show or hide columns}` -> `# \| Method \| Host \| Path \| Status \| Type \| Ext \| Query \| TLS \| Comment \| Cookies \| IP \| Listener port \| Title \| Edited \| Length \| Time \| Age \| Reset columns` — 18 columns, matching Burp's own set |

## 8. Proxy -> WebSockets history (`#wshistory`)

**Zero connections in the fixture, so nothing below the toolbar was exercised live.** The detail
pane never mounted; rows marked CLOSED here are source- and empty-state-cited, in the same way as
Intercept in §6, and are flagged as such per row.

| Audit claim | Status | Evidence |
|---|---|---|
| Connection detail "Minimal", can't inspect frames (HIGH) | **CLOSED** | Empty-state copy: `Pick a connection on the left to see its frames and the HTTP handshake that opened it.` `pages/wshistory.tsx:477-532`: `<TabsTrigger value="handshake">Handshake</TabsTrigger>` with request/response editors (`ws-handshake-${exchange}-request.txt`). Frame filters `Both directions/Sent/Received`, `Any opcode/text/binary/ping/pong/close`, `input{Filter frames}` — server-side on `/api/ws/history` |
| Bambda filter — missing (MEDIUM) | **STILL-OPEN (LOW)** | Same single `reference.ts` hit; no script-mode control. Burp doc `tools/proxy/websockets-history/index.html`: "Script mode - Apply a Java-based script to define your custom filter." |
| Filter settings dialog — missing (MEDIUM) | **STILL-OPEN (LOW)** | Page buttons are only `Refresh` + the six sort headers; the three filters are inline, with no saved/named filter panel. Burp doc, same file: "Click the Filter settings bar, then choose … Settings mode / Script mode"; strings `burp.Zrmn 24488 "Filter settings"` |
| Refresh / table | **CLOSED (was already ✓)** | `CONNECTIONS 0 observed \| FRAMES 0 total \| SENT 0 client → server \| RECEIVED 0 server → client` |

## 9. Proxy -> Match & Replace (`#matchreplace`)

| Audit claim | Status | Evidence |
|---|---|---|
| Edit rule — missing (HIGH) | **CLOSED** | Rules are inline-editable: `pages/matchreplace.tsx:330-372` `aria-label={`Rule ${i+1} target`}`, `… match kind`, `… match`, `… replacement` (`placeholder="empty = delete the match"`), `… comment` |
| Remove rule — missing (HIGH) | **CLOSED** | `:411` `<IconButton label={`Delete rule ${i+1}`}>` -> confirm dialog `:483` `title="Delete this rule?"` -> `:494` `replaceRules(rules.filter((_, i) => i !== confirmDelete))` |
| Move up/down — missing (MEDIUM) | **CLOSED** | `:381-392` `label={`Move rule ${i+1} up`}` / `down` calling `move(index, -1)` / `move(index, 1)`; `move` at `:130` |
| In-scope only — missing (MEDIUM) | **CLOSED** | Live: `ONLY APPLY TO IN-SCOPE ITEMS` toggle, `{Only apply these rules to in-scope items}`, with the note "Burp has this one switch and no per-rule scope" |
| HTTP/WS separation — missing (MEDIUM) | **CLOSED** | `:26-27` rule targets `websocket_to_server` / `websocket_to_client` alongside request/response; `:54-55` map both to a `websocket` class, and `:193-201` summarise per class so a WS rule is not reported as affecting requests |
| Auto-modified / original message preview (LOW) | **CLOSED** | `Draft test` section: `SAMPLE INPUT` and `TRANSFORMED OUTPUT` editors side by side, `RAW`/`HEX`, charset selects, `Test direction` = `Request rules` / `Response rules`, "Compiled and applied server-side as a throwaway rule set — the saved rules and live traffic are untouched" |

## 10. Proxy -> Proxy settings (`#proxysettings`)

Section headings: `Response modification`, `TLS passthrough`, `Outcome counters`, `Transport adjustments`, `Proxy listener`.

| Audit claim | Status | Evidence |
|---|---|---|
| TLS passthrough — missing (HIGH) | **CLOSED** | `H2:TLS passthrough` — "Hosts the proxy relays without intercepting. Edits apply immediately and survive a restart." with `label{HOST PATTERN}`, `input{e.g. internal.bank.test or *.cdn.example}`, `Add rule`, empty state `No passthrough rules`. Backend `server.go:915 /api/proxy/passthrough`. Burp side: `burp.Zrd5 12805 "tls pass-through"` |
| Resource pools — missing (HIGH) | **NOT-APPLICABLE** | Burp's own doc `settings/tools/proxy.html` enumerates the page: "Proxy listeners. Request and response interception rules. WebSocket interception rules. Response modification rules. HTTP and WebSocket match and replace rules. TLS pass through. Default Proxy history message display. Proxy history logging. Default Proxy interception state. Miscellaneous." — no resource pools. Burp's resource pools are project options (`burp.Zrfc -23399 "project_options.resource_pools"`, `configPanelResourcePools`). burpsy has the backend anyway (`server.go:929-930 /api/pools`, `/api/pools/`) |
| Miscellaneous settings — missing (LOW) | **CLOSED** | `Transport adjustments`: `Strip Sec-WebSocket-Extensions from handshakes`, `Don't log out-of-scope traffic` (= Burp's "Proxy history logging"), `Strip Proxy-* headers from requests`, `Set "Connection: close" on requests and responses`; `Proxy listener`: `Support invisible proxying` (Burp `burp.Zg5l 10377` "Invisible proxy support allows non-proxy-aware clients to connect directly to the listener.") |
| Web interface disable — missing (LOW) | **STILL-OPEN** | No such control in the page's 39 enumerated controls. Burp: `burp.Zrv7 10906 "Disable web interface at http://burpsuite"` |
| Response modification / outcome counters | **CLOSED (was already ✓)** | 9 switches (`Unhide hidden form fields` … `Strip Accept-Encoding from requests`) and `CONSIDERED / MODIFIED / UNCHANGED / SKIPPED: COMPRESSED / SKIPPED: NOT HTML / SKIPPED: UNFRAMED` |

## 11. Cross-cutting claim the audit got wrong

| Audit claim | Status | Evidence |
|---|---|---|
| "Context menus (Burp has ~12, burpsy has 0)" | **CLOSED for these pages** | HTTP history row: 0 -> 29 menu nodes, 30 labelled items (§7). Site map host node: `Add 127.0.0.1 to scope \| Passively scan this host \| Actively scan this host (crawl) \| Delete host \| Copy URLs in this host`. Site map path node: 6 items incl. `Delete this item only`. Shared via `lib/actions.ts` `useExchangeActions`, imported by `history.tsx`, `sitemap.tsx`, `wshistory.tsx`, `scanner.tsx`, `auditqueue.tsx`, `repeater.tsx` |

---

# STILL-OPEN, ranked

### HIGH — 1. Proxy settings has one listener, not a listener list (missed by the audit)

Burp's Proxy settings doc names **Proxy listeners** as the first section of the page, and Burp
manages a *list*: `burp.Zg5l 10412 "Add a new proxy listener"`, `10385 "Edit proxy listener"`,
`10393 "These settings control how Burp binds the proxy listener."`, plus per-listener Request
handling (`Redirect to host`, `Redirect to port`, `Force use of TLS`), Certificate options (self-signed
/ CA-signed per-host / fixed hostname / custom `.p12`) and TLS Protocols. burpsy shows a single
bound address: `main.innerText` under `H2:Proxy listener` is `BOUND TO \| 127.0.0.1:18280 \|
RE-BIND LISTENER \| Re-bind \| host:port — for example 127.0.0.1:8080 … \| Support invisible proxying`
— two controls, one of them a rebind of the same socket.

The backend is the binding constraint, not the UI: `internal/web/api_proxylistener.go:39-75`
`handleProxyListener` serves only `GET` (`proxyListenerView{Bind: s.proxyServer.ListenerAddr()}`) and
`PUT {"bind":"host:port"}` -> `s.proxyServer.Rebind(addr)`. There is no listener collection, no
redirect target, no force-TLS and no per-listener certificate selection anywhere in the type.

Smallest honest sketch: this is a backend-first item. Step 1 is `internal/proxy` growing a listener
set (`Add`/`Remove` alongside the existing `Rebind`) and `api_proxylistener.go` becoming
`GET/POST /api/proxy/listeners` + `PUT/DELETE /api/proxy/listeners/{id}`, carrying `bind`,
`redirect_host`, `redirect_port`, `force_tls`, `invisible`. Step 2 is a table in
`pages/proxysettings.tsx` under the existing `Proxy listener` heading, reusing the `TLS passthrough`
section's add-row + list shape that is already on the page. Certificate/TLS-protocol configuration is
a separate, larger item and should be filed apart.

**Why this is first:** it is the only STILL-OPEN item where a core Burp flow is absent rather than a
control. Redirecting a listener to a host and forcing TLS is how sslstrip-style tests and
non-proxy-aware clients get set up at all; without it the page cannot do what Burp's Proxy settings
page is primarily for. Everything else below is a control or a column on a flow that already works.

### MEDIUM — 2. WebSockets history frame table is missing most of Burp's columns (missed by the audit)

Burp's WebSockets history (doc `tools/proxy/websockets-history/index.html`) lists `# / URL /
Direction / Edited / Length / Notes / TLS / Time / Listener port / WebSocket ID`, as one flat table
across connections. burpsy's is `[...main.querySelectorAll("th")].map(e=>e.innerText)` ->
`["#","DIR","OPCODE","LENGTH","AGE"]`, and only after a connection is selected. Positive control:
the same query on `#history` returns 18 headers plus a `Show or hide columns` menu, so the table
substrate supports this — WS simply does not use it.

Backend is half there: `api_ws.go:27-37` `wsRowView` already carries `exchange`, `at_ms` and `note`,
so `Time` and `Notes` are UI-only, and `URL` is one join away via the connection's exchange. `Edited`,
`TLS` and `Listener port` are not on the type and would need adding. Sketch: give `pages/wshistory.tsx`
the same `useStoredColumnVisibility` treatment `history.tsx` uses (`history-columns`), add the
three derivable columns first, and file the three that need `wsRowView` fields separately.

### MEDIUM — 3. Scope has no rule library

`grep -n -iE 'library' pages/scope.tsx` -> no matches; the page's only persistence is the live rule
list. Burp keeps `Save to library` in the scope panel class (`burp.Zhw_ -13442`, same class as
`-13456 "Use advanced scope control"`), so a rule set can be named and re-loaded across projects.
Positive control: the same grep for `'Paste URL'` does hit, and that button is live in the toolbar.
Sketch: the rules already round-trip as JSON through the scope API, so this is a named-blob store —
a `scope_libraries` table or a file under the session dir, `GET/POST /api/scope/library`, and a
`Save to library` / `Load…` pair next to `Clear scope` in `pages/scope.tsx`.

### LOW — 4. No Bambda / script-mode filter on HTTP history or WebSockets history

Burp: `burp.Zg5m -1433 filterBambdaModeRadioButton`, and the WS doc's "Script mode - Apply a
Java-based script to define your custom filter". burpsy: the only `bambda` hit in the whole UI tree
is `lib/reference.ts:360-362`, which records this as a deliberate choice — "The filter substrate here
is the closed typed grammar above, deliberately not a scripting engine." The audit ranked this HIGH
(P1 #6); given a documented DSL with 13 fields and a grammar dialog already shipping, HIGH overstates
it. Re-ranked LOW, and it is arguably a WONTFIX rather than a gap. Note `matchReplaceBambdaUpsellPanel`
(`burp.Zg5m -1416`) — in Burp this surface is itself a Pro upsell panel.

### LOW — 5. WebSockets history has no filter-settings panel

The three filters (direction, opcode, payload substring) are inline and unnamed; Burp has a
`Filter settings` bar (`burp.Zrmn 24488`) with saveable criteria. Sketch: `pages/wshistory.tsx`
already funnels all three into the `/api/ws/history` query key, so a `More filters` popover
mirroring `history.tsx:1226-1233` would be a UI-only change.

### LOW — 6. Site map has no crawl-progress counters

Header shows `8 NODES / 6 EXCHANGES`; Burp shows `burp.Zreo 5770 "Site map items added:"`,
`5771 "Responses queued:"`, `5769 "Responses processed:"`. `grep -n -iE 'items added|queued|processed'
pages/sitemap.tsx` -> no matches; positive control: `grep -n 'subtree_exchanges'` hits at `:268`, so
the header does render counters, just not these. Only meaningful once a crawl is running.

### LOW — 7. Proxy settings has no "Disable web interface" switch

Burp: `burp.Zrv7 10906 "Disable web interface at http://burpsuite"`. Absent from the 39 controls
enumerated on `#proxysettings`. Positive control: the same enumeration does find
`Support invisible proxying` and `Re-bind`, both on the same `Proxy listener` card.

### LOW — 8. "Add to site map" is absent from the history context menu

`/Add to site map/i.test(document.body.innerText)` -> `false` with the 6-item site-map menu open
(positive control: `document.querySelectorAll("[role=menuitem]").length` -> `6` at that moment).
Burp has it as a *destination* action from other tools — `burp.Zsgx 29790` sits with
"try re-running the attack and setting the option to save requests or full payloads" (Intruder
results) and `burp.Zr83 -18024` with "Are you sure you want to add this item to the site map?".
So it belongs on history/Intruder/Repeater rows, not on the Site map page — which is why the audit's
Site map section was right to omit it and its Intruder section should have carried it.

---

## Audit rows resolved

57 audit claims checked across these ten pages (55 table rows — the Scope row bundles three):
**45 CLOSED**, **5 NOT-APPLICABLE**, **1 UNVERIFIED**, **6 STILL-OPEN** — and 4 of the 6 are LOW, one of which (Bambda) is a documented design decision
rather than an oversight.

Against the audit's own §5 numbering: one P0 item is on my pages — **#3 Intercept Forward/Drop/Action
toolbar** — and it has shipped. Six P1 items are on my pages: **#7** (history per-column filters),
**#8** (WebSocket connection detail), **#10** (TLS passthrough) and **#12** (Match & Replace
edit/remove) have shipped; **#11** (Proxy settings resource pools) was never a Burp feature of that
page; **#6** (history Bambda mode) is the one P1 still open here, and is re-ranked LOW above.

Three gaps the audit missed are reported above — items 1, 2 and 8 — and the first two outrank
everything the audit still has open on these pages.
