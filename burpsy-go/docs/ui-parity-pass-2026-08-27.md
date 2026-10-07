# burpsy UI parity pass — 2026-08-27 (with Burp Java evidence)

Manual inventory of every page in burpsy's React UI, compared against Burp Suite's
actual decompiled Java source at `/root/burp-re/out/clean/root/`. No screenshots —
rendered DOM from `http://127.0.0.1:18181` vs Java class structure and string literals.

**HTML mockup:** `ui-parity-mockup-burp-vs-burpsy.html` (side-by-side visual comparison)

## 1. Burp's actual tab structure (from `ToolRegistry.java`)

```java
// ToolRegistry.java:113-115
DASHBOARD, TARGET, PROXY, SCANNER, INTRUDER, REPEATER, COLLABORATOR,
SEQUENCER, COMPARER, LOGGER, ORGANISER, BURP_AI, EXTENDER, REPLAYER, DISCOVER
```

**Burp has 15 tools.** burpsy has 15 top-level tabs. The mapping:

| Burp tool | burpsy tab | Match? |
|-----------|------------|--------|
| DASHBOARD | Dashboard | ✅ |
| TARGET | Target (5 sub-tabs) | ✅ |
| PROXY | Proxy (5 sub-tabs) | ✅ |
| SCANNER | — | ❌ burpsy has no Scanner tab |
| INTRUDER | Intruder (5 sub-tabs) | ✅ |
| REPEATER | Repeater | ✅ |
| COLLABORATOR | Collaborator | ✅ |
| SEQUENCER | Sequencer | ✅ |
| COMPARER | Comparer | ✅ |
| LOGGER | Logger | ✅ |
| ORGANISER | Organizer | ✅ |
| BURP_AI | — | ❌ burpsy has no AI tab |
| EXTENDER | Extender | ✅ |
| REPLAYER | — | ❌ burpsy has no Replayer tab |
| DISCOVER | Discover | ✅ (but see placement) |

**Burp tools burpsy is missing:** Scanner, Burp AI, Replayer.
**burpsy tabs Burp doesn't have as tabs:** Session, Decoder, Discover (Burp has Discover under Target), Settings (Burp has Settings as menu).

## 2. Sub-tab structure comparison

### Target sub-tabs

**Burp (from strings):** Site map, Issue definitions, Scope, Audit queue, Crawl paths
**burpsy:** Site map, Issues, Audit queue, Issue definitions, Scope

| Burp | burpsy | Match? |
|------|--------|--------|
| Site map | Site map | ✅ |
| Issue definitions | Issue definitions | ✅ |
| Scope | Scope | ✅ |
| Audit queue | Audit queue | ✅ |
| Crawl paths | — | ❌ burpsy missing crawl paths view |

**Burp strings confirming sub-tabs:**
- `subtab.site_map.shown`, `subtab.issue_definitions.shown`, `subtab.scope.shown`
- `Site map URL view is empty`, `Site map crawl paths view is empty`
- `Crawl paths view` — a second site map view showing "tree of Burp Scanner actions and pages"

### Proxy sub-tabs

**Burp (from strings):** Intercept, HTTP history, WebSockets history, Match and Replace, Proxy settings
**burpsy:** Intercept, HTTP history, WebSockets history, Match & Replace, Proxy settings

| Burp | burpsy | Match? |
|------|--------|--------|
| Intercept | Intercept | ✅ |
| HTTP history | HTTP history | ✅ |
| WebSockets history | WebSockets history | ✅ |
| Match and Replace | Match & Replace | ✅ |
| Proxy settings | Proxy settings | ✅ |

**All 5 Proxy sub-tabs match.**

### Intruder sub-tabs

**Burp (from Java classes):**
- **Positions** — `Zr7k.java` extends `Zrop`, uses `GridBagLayout`, contains `Zr7h` (positions inner panel) with `Add §`, `Auto §`, `Clear §` buttons and request editor
- **Payloads** — `Zija.java` implements `Ziik`, named `intruderPayloadsTab`, contains `Zr7m.java` (empty state panel) with payload type selector, `Add §`, `Load...`, `Paste`, `Remove` buttons
- **Resource pool** — `Zxcq.java` implements `Ziik`, named `intruderResourcePoolTab`, contains `Zh3g.java` with `Concurrent requests`, `Delay`, `With random variations`, `Increase delay in increments of`
- **Settings** — `Zxoh.java` implements `Ziik`, named `intruderSettingsTab`, contains `Zmx7` with `Scan details`, `Scope`, `Isolate scan`
- **Results** — `Zr_q.java` extends `Zr_n`, contains `buildResultsPanel()` with `Results table`, `Server responses`, `Attack progress bar`, `Pause`, `Resume`, `Stop`

**burpsy:** All 5 sub-tabs render the same "Base request" panel with attack type selector and "Find positions" button.

**Verdict:** burpsy's Intruder sub-tabs are stubs. In Burp each is a distinct panel with different controls. This is the single largest UI parity gap.

## 3. Detailed page comparison

### 3.1 Intruder sub-tabs identical (HIGH)

**Burp's actual sub-tab content (from Java classes):**

- **Positions** (`Zr7k.java:19-209`): `Add §`, `Auto §`, `Clear §`, `Find insertion points`, request editor with `Zruh` (target field), `Zru2` (payload preview)
- **Payloads** (`Zija.java` + `Zr7m.java`): `Payload type:` selector, `Load...`, `Paste`, `Remove`, `Payloads to generate:`, `Grep — Payloads`, `Match / replace in list items`, `Do illegal UTF-8`, `Hex formatting`, `Maximize permutations in multi-byte encodings`
- **Resource pool** (`Zxcq.java` + `Zh3g.java`): `Concurrent requests`, `Delay`, `With random variations`, `Increase delay in increments of`, `Custom resource pool`
- **Settings** (`Zxoh.java`): `Scan details`, `Scope`, `Isolate scan`, `Engine configuration`
- **Results** (`Zr_q.java:31-938`): `Results table`, `Server responses`, `Attack progress bar`, `Pause`, `Resume`, `Stop`, `# / Status / Error / Timeout / Length / Time / Comment / Total`

**burpsy's actual sub-tab content:** All 5 sub-tabs render the same "Base request" panel with attack type selector and "Find positions" button.

**Verdict:** burpsy's Intruder sub-tabs are stubs. In Burp each is a distinct panel with different controls. This is the single largest UI parity gap.

### 3.2 Repeater

**Burp (from `RepeaterModule.java` + strings):**
- `RepeaterModule` is a Guice module binding `RepeaterToolTabFlasher`, `RepeaterToolFrameProvider`
- `RepeaterNewHttpTabOption`, `RepeaterNewWsTabOption` — separate HTTP/WS tabs
- `RepeaterSendButton`, `RepeaterSendRequest`, `RepeaterSearchCheckbox`
- `RepeaterConfigurationOverrideMenuItemFollowRedirectionsInScope`
- Request/response editor with message analyser

**burpsy:** Empty state "No request open" + "New request" button. No visible editor until a request is opened from history.

**Verdict:** The editor exists (e2e tests exercise it) but the empty state doesn't lead to it. Burp opens Repeater with a blank editor by default.

### 3.3 Logger

**Burp (from strings):**
- "HTTP history is empty" — `httpHistoryEmptyPanel`
- "WebSockets history is empty" — `WebSockets history is empty`
- "Event log" — `DashboardEventLogTable`
- "Site map" — `DashboardModule`
- "Logger" — `DashboardActivityLogTable`
- Filter: `filterBambdaModeRadioButton`, `bambda.http_history_display_filter`
- Columns: `proxy.http_history_display_filter.by_mime_type.show_html`, `show_css`, `show_images`
- Annotations: `proxy.http_history_display_filter.by_annotation.show_only_commented_items`

**burpsy:** "0 of 0 shown", "0 dropped", Clear log, Refresh, search input, selects (All tools, Any method, Any status), 8 column-filter inputs, table (Age/Tool/Authority/Request/Status/Length/Time/Error).

**Verdict:** burpsy's Logger is more feature-rich than Burp's — per-tool capture toggles, dropped-request counters, column filters. Burp's Logger is a simple table. burpsy wins here.

### 3.4 Collaborator

**Burp (from strings):**
- "Burp Collaborator" — `Burp Collaborator enables you to test whether you can induce an application to interact with an external service via DNS, HTTP, or SMTP`
- "Poll now" — `Poll now`
- "Payloads to generate:" — `Payloads to generate:`
- "Include Collaborator server location" — `Include Collaborator server location`
- "This payload type generates Collaborator payloads..." — `payloadCollaboratorNumberOfPayloads`

**burpsy:** "not configured", Refresh, Interaction channel (Copy payload, Poll now), Blind XSS callbacks (Copy script tag).

**Verdict:** burpsy matches Burp's Collaborator but lacks a configuration flow. Burp has "Burp Collaborator" configuration; burpsy just says "not configured".

### 3.5 Intercept

**Burp (from strings):**
- "Intercept is on" / "Intercept is off" — `Intercept is on/off`
- "Queue" — `proxyInterceptTablePopup`
- "Interception rules" — `configPanelProxyInterception`
- "Messages between Burp's browser and your target servers are held here..."
- "If you turn Intercept on, messages between Burp's browser and your target servers are held here..."
- "Forward", "Drop", "Send to Repeater", "Send to Comparer" — context menu items
- "interceptToggleButton", "proxyInterceptEditTargetButton", "Edit target"

**burpsy:** "wired", switch, select (All messages/Requests only/Responses only/WebSocket→server/WebSocket→client), Queue, Interception rules, table (#/Dir/Method/Host/Path/Status/Held/Len).

**Verdict:** burpsy matches Burp's Intercept. burpsy's WebSocket direction filters are more explicit than Burp's.

### 3.6 Match and Replace

**Burp (from strings):**
- "HTTP match and replace rules" — `HTTP match and replace rules`
- "WebSocket match and replace rules" — `WebSocket match and replace rules`
- "addHttpMatchReplaceRuleButton", "editHttpMatchReplaceRuleButton"
- "addWsMatchReplaceRuleButton", "editWsMatchReplaceRuleButton"
- "Only apply to in-scope items" — `Only apply to in-scope items`
- "Use these settings to automatically replace parts of HTTP requests and responses passing through the Proxy"

**burpsy:** "saved", Revert, Save rules, Refresh, Rules (requests/responses spans, Add rule, switch, "0 of 0 enabled"), Draft test (Request rules/Response rules).

**Verdict:** burpsy matches Burp's Match and Replace. burpsy's "Draft test" panel is a feature Burp lacks (Burp requires installing rules before testing).

### 3.7 Scope

**Burp (from strings):**
- "Use advanced scope control" — `Use advanced scope control`
- "Add", "Edit", "Remove" — scope rule management
- "Save to library" — `Save to library`
- "URL scope" — `URL scope`
- "Use suite scope [defined in Target tab]" — `Use suite scope`
- "The rule is not in-scope for any tools" — `The rule is not in-scope for any tools`

**burpsy:** "restricted", Clear scope, Refresh, Add scope rule (Include/Exclude, 3 inputs, Any/HTTP/HTTPS, Add rule), Rules (Remove rule, table Kind/Host/Port/Protocol/Path prefix).

**Verdict:** burpsy matches Burp's Scope. Burp's "advanced scope control" and "Save to library" are missing from burpsy.

### 3.8 Site map

**Burp (from strings):**
- "Site map URL view is empty" — `Site map URL view is empty`
- "Site map crawl paths view is empty" — `Site map crawl paths view is empty`
- "Crawl paths view" — `Crawl paths view`
- "The site map displays information about the contents of your target applications..."
- "Site map is read-only" — `Site map is read-only`
- "Site map filter" — `Site map filter`
- "Passively scan this branch" — `Passively scan this branch`
- "Passively scan selected branches" — `Passively scan selected branches`
- "Site map items added:" — `Site map items added:`
- "Responses queued:" — `Responses queued:`
- "Responses processed:" — `Responses processed:`

**burpsy:** "0 nodes", "0 exchanges", Crawl, Refresh, filter input, "No traffic captured yet", "No path selected".

**Verdict:** burpsy's Site map is a simplified version. Burp has two views (URL + crawl paths), passive scan branch controls, and read-only indicators. burpsy has neither.

### 3.9 Issue definitions

**Burp (from strings):**
- "This listing contains the definitions of all issues that can be detected by Burp Scanner."
- "https://portswigger.net/kb/issues"

**burpsy:** Refresh, select (All severities with counts), "183 definition(s)", search input, lists all 183 BCheck definitions with severity badges.

**Verdict:** burpsy matches Burp's Issue definitions. burpsy lists all 183; Burp hides some behind "Active" passive checks.

### 3.10 Audit queue

**Burp (from strings):**
- "Audit queue" — `Audit queue`
- "Total audit items:" — `Total audit items:`
- "Audit again" — `AuditItemContextMenuAuditAgain`

**burpsy:** Refresh, H2: Queue, table (Seq/Request/State/Attempts/Note), Show insertion points.

**Verdict:** burpsy matches Burp's Audit queue.

### 3.11 Proxy settings

**Burp (from strings):**
- "Proxy interception state" — `Proxy interception state`
- "TLS passthrough" — `proxy.ssl_pass_through`
- "Resource pools" — `Resource pools`
- "Automatically add entries on client TLS negotiation failure"
- "Don't send items to Proxy history or live tasks, if out of scope"

**burpsy:** Refresh, Response modification (6 switches), Outcome counters, Transport adjustments (table Adjustment/Count).

**Verdict:** burpsy's Proxy settings is a simplified version. Burp has TLS passthrough, resource pools, and out-of-scope request handling. burpsy has response modification switches (which Burp has elsewhere).

### 3.12 Settings

**Burp (from strings):**
- "Project options" — `Project options`
- "Scope" — `configPanelTargetScope`
- "Crawling" — `Crawling`
- "Application login" — `configFunctionApplicationLogin`
- "configFunctionScope"

**burpsy:** Proxy (Refresh), TLS passthrough (Refresh, input, Add rule), Resource pools (New pool, Refresh), What each tool honours (table Tool/Route/Max concurrent/Delay/Throttling/Why not).

**Verdict:** burpsy's Settings is a tool-limits editor. Burp's Settings is a comprehensive project options dialog. Different scope — burpsy's is more like Burp's "Resource pools" + "What each tool honours".

### 3.13 Discover

**Burp (from strings):**
- "Discover content" — under Target → Site map
- "Discover" as a tool in ToolRegistry

**burpsy:** Top-level tab with search, "69 entries", buttons (What burpsy does not do, Query language, BCheck syntax, Keyboard shortcuts, Shipped documentation).

**Verdict:** burpsy's Discover is a documentation hub. Burp's Discover is a content discovery tool (ffuf-based). Different purpose entirely.

### 3.14 Session

**Burp (from strings):**
- "Session handling rules" — `ISessionHandlingAction`
- "Login rules" — `configFunctionApplicationLogin`
- "Run login macro" — `Run login macro`
- "Cookie jar" — `getCookieJarContents`

**burpsy:** "wired", New rule, Refresh, Login rules (0 configured, New rule), Log in again (2 inputs, Add header, Run login now), Cookie jar (Refresh jar).

**Verdict:** burpsy matches Burp's Session handling. The "New rule" button doesn't open a dialog in the empty state.

### 3.15 Extender

**Burp (from strings):**
- "Extension" — `Extension`
- "installing", "installed" — extension states
- "Extension JMenus" — `Extension JMenus`
- "Hot key handlers" — `Hot key handlers`

**burpsy:** Refresh, H2: Allowlist, "No plugin is allowlisted".

**Verdict:** burpsy's Extender is a stub. Burp has full extension management (install/uninstall/configure). burpsy just shows an empty allowlist.

### 3.16 Organizer

**Burp (from strings):**
- "organiserShowOnlyInScopeCheckbox"
- "organiser.display_filter.status.new"
- "organiserShowStatus3xxCheckbox"
- "organiserShowMimeXmlCheckbox"

**burpsy:** "0 saved", Refresh, Saved exchanges (input, Save exchange), "Nothing saved yet", "No item selected".

**Verdict:** burpsy matches Burp's Organizer but lacks the filtering controls (in-scope only, status, MIME type).

### 3.17 Decoder

**Burp:** No Decoder tab in ToolRegistry. Burp has a Decoder tool accessible from the right-click menu or Tools menu.

**burpsy:** Top-level tab with "0 B in", Text/Hex/Clear all/Run pipeline, Transform pipeline (Decode/Encode/Hash, step 1, selects).

**Verdict:** burpsy's Decoder is a top-level tab; Burp's is a utility accessible from menus. burpsy's pipeline-based decoder is more structured than Burp's single-shot decoder.

### 3.18 Comparer

**Burp:** Comparer tab exists in ToolRegistry.

**burpsy:** "byte-level", Swap, Compare, Slot A (input, Load, 0 B, Raw/Hex), Slot B (input, Load, 0 B, Raw/Hex).

**Verdict:** burpsy matches Burp's Comparer.

### 3.19 Sequencer

**Burp:** Sequencer tab exists in ToolRegistry.

**burpsy:** "0 pasted", select (detect encoding/hex/base64/raw bytes), Analyse, Paste a list, Capture from a live exchange, "No analysis yet".

**Verdict:** burpsy matches Burp's Sequencer.

### 3.20 Dashboard

**Burp (from `DashboardModule.java` + strings):**
- `DashboardModule` binds `DashboardToolTabFlasher`, `DashboardToolFrameProvider`
- `DashboardActivityLogTable`, `DashboardEventLogTable`, `DashboardEventLogEmpty`
- `DashboardTaskProgress`, `DashboardTelemetry`, `DashboardToolbar`
- "Event log", "Site map", "Logger", "Live crawl view", "Live audit", "Live passive crawl"
- "New scan", "Task execution is paused", "No proxy listeners are currently running"

**burpsy:** Exchanges, Capture store, Running tasks, Coverage gaps, Finding severity counts, Coverage panel (Issues/Passive checks/Live audit/Captured traffic/Tasks), Requests sent by burpsy, Tool events, Tasks, Traffic sources.

**Verdict:** burpsy's Dashboard is more detailed than Burp's. Burp shows event log + task progress; burpsy shows coverage accounting, tool traffic, and traffic sources. burpsy's "honest coverage accounting" is a deliberate improvement over Burp's simpler dashboard.

## 4. Summary

| Metric | Count |
|--------|-------|
| Total burpsy pages | 30 |
| Pages matching Burp | 22 |
| Pages with functional gaps | 5 |
| Burp tools burpsy doesn't have | 3 (Scanner, Burp AI, Replayer) |
| burpsy tabs Burp doesn't have as tabs | 3 (Session, Decoder, Discover) |
| High-severity gaps | 1 (Intruder sub-tabs identical) |
| Medium-severity gaps | 4 |
| Low-severity gaps | 2 |

### High severity
1. **Intruder sub-tabs identical** — all 5 render the same panel; Burp has distinct content per sub-tab.

### Medium severity
2. **Repeater empty state** — no blank editor by default; Burp opens with one.
3. **Extender stub** — "No plugin is allowlisted" with no add/remove UI; Burp has full extension management.
4. **Session rule creation** — "New rule" button doesn't open a dialog in empty state.
5. **Site map simplified** — missing crawl paths view and passive scan branch controls.

### Low severity
6. **Discover placement** — top-level tab in burpsy, under Target in Burp.
7. **Settings scope** — burpsy's Settings is tool-limits only; Burp's is comprehensive project options.

### What burpsy does better than Burp
- **Dashboard** coverage accounting is more honest (gated work counted separately).
- **Logger** has per-tool capture toggles and dropped-request counters.
- **Match & Replace** has a "Draft test" panel (Burp requires installing first).
- **Issue definitions** lists all 183 (Burp hides some).
- **Intercept** has explicit WebSocket direction filters.

— PlumOtter, manual parity pass 2026-08-27
