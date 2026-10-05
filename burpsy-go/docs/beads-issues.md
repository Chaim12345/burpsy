# Beads Issues — burpsy UI parity gaps

## Dashboard gaps

### Issue: Dashboard task progress bar missing
Dashboard has no animated progress bar for running tasks. Burp shows a progress bar with task completion percentage.

**Gap:** Dashboard shows "0 tasks" text instead of progress bar
**Evidence:** `DashboardTaskProgress.java` in Burp has progress animation methods (Z_, ZA, Zz, Zv, Zk, Zh)
**Acceptance Criteria:**
- [ ] Show progress bar when tasks are running
- [ ] Animate progress as tasks complete
- [ ] Show estimated time remaining
- [ ] Match Burp's visual style

---

### Issue: Dashboard event log missing context menu
Burp's event log has a popup menu (Copy column, Hide column, Sort Ascending/Descending/Cancel).

**Gap:** Static event list with no context menu
**Evidence:** `DashboardActivityLogTable.java` popupMenuWillBecomeVisible
**Acceptance Criteria:**
- [ ] Add right-click context menu to event log
- [ ] Copy column, Hide column options
- [ ] Sort ascending/descending/cancel
- [ ] Auto-scroll to match option

---

### Issue: Dashboard activity log missing context menu
Burp's activity log has a popup menu for interaction.

**Gap:** Static activity list with no context menu
**Evidence:** `DashboardActivityLogTable.java` popupMenu handlers
**Acceptance Criteria:**
- [ ] Add right-click context menu to activity log
- [ ] Copy, Hide, Sort options

---

### Issue: Dashboard missing pause/resume controls
Burp shows "Task execution is paused" with pause/resume buttons.

**Gap:** No pause/resume controls on Dashboard
**Evidence:** "Task execution is paused" string in Burp
**Acceptance Criteria:**
- [ ] Show paused state when tasks are paused
- [ ] Add pause/resume buttons
- [ ] Show pause reason

---

### Issue: Dashboard missing listener status warning
Burp shows "No proxy listeners are currently running" warning.

**Gap:** No listener status warning on Dashboard
**Evidence:** "No proxy listeners are currently running" string in Burp
**Acceptance Criteria:**
- [ ] Show warning when no proxy listeners running
- [ ] Link to listener configuration

---

## Intruder gaps

### Issue: Intruder sub-tabs all render identically
All 5 Intruder sub-tabs (Positions, Payloads, Resource pool, Settings, Results) render the same "Base request" panel.

**Gap:** No distinct content per sub-tab
**Evidence:** `Zr7k.java`, `Zija.java`, `Zxcq.java`, `Zxoh.java`, `Zr_q.java` are distinct panels
**Acceptance Criteria:**
- [ ] Positions: request editor with Add §/Auto §/Clear § buttons
- [ ] Payloads: payload type selector with conditional fields
- [ ] Resource pool: concurrent requests/delay/variations controls
- [ ] Settings: scan details/scope/isolate scan
- [ ] Results: results table with progress bar/pause/resume/stop

---

### Issue: Intruder missing payload type selector
Burp has 12+ payload types (Simple list, Runtime file, Character substitution, etc.) with conditional fields.

**Gap:** Only attack type selector, no payload type
**Evidence:** Payload type strings in Burp (Simple list, Runtime file, etc.)
**Acceptance Criteria:**
- [ ] Add payload type selector with all 12+ types
- [ ] Show conditional fields per type (Numbers: from/to/step, File: server path, etc.)
- [ ] Wire to backend Resolve functions

---

### Issue: Intruder missing resource pool controls
Burp has Concurrent requests, Delay, With random variations, Increase delay in increments of.

**Gap:** No resource pool controls in Intruder
**Evidence:** `Zxcq.java` + `Zh3g.java` resource pool panel
**Acceptance Criteria:**
- [ ] Concurrent requests input
- [ ] Delay input
- [ ] Random variations checkbox
- [ ] Increment delay input
- [ ] Custom resource pool selector

---

### Issue: Intruder missing scan settings
Burp has Scan details, Scope, Isolate scan, Engine configuration, Attack configuration.

**Gap:** No scan settings in Intruder
**Evidence:** `Zxoh.java` settings panel
**Acceptance Criteria:**
- [ ] Scan details section
- [ ] Scope configuration
- [ ] Isolate scan checkbox
- [ ] Engine/attack config options

---

### Issue: Intruder missing results table
Burp has Results table with #/Status/Error/Timeout/Length/Time/Comment/Total columns, progress bar, pause/resume/stop.

**Gap:** No results display in Intruder
**Evidence:** `Zr_q.java` buildResultsPanel with 19 string literals
**Acceptance Criteria:**
- [ ] Results table with all columns
- [ ] Attack progress bar
- [ ] Pause/Resume/Stop buttons
- [ ] Save results option

---

## Repeater gaps

### Issue: Repeater empty state doesn't lead to editor
Burp opens Repeater with a blank request editor by default. burpsy shows "No request open" with only a "New request" button.

**Gap:** No blank editor by default
**Evidence:** `RepeaterModule.java` + `RepeaterNewHttpTabOption.java`
**Acceptance Criteria:**
- [ ] Open with blank editor by default
- [ ] Send/Cancel buttons visible
- [ ] Protocol selector (HTTP/HTTPS)
- [ ] Request/response view

---

### Issue: Repeater missing Send/Cancel buttons
Burp has prominent Send and Cancel buttons.

**Gap:** No Send/Cancel buttons in empty state
**Evidence:** `RepeaterSendButton.java`, `repeaterCancelButton` string
**Acceptance Criteria:**
- [ ] Send button visible
- [ ] Cancel button visible
- [ ] Keyboard shortcut for Send

---

### Issue: Repeater missing tab panel
Burp has multiple tabs with close/reopen/duplicate functionality.

**Gap:** Single tab, no tab management
**Evidence:** `repeaterTabPanel` string
**Acceptance Criteria:**
- [ ] Multiple tabs support
- [ ] Close/reopen/duplicate tabs
- [ ] Tab groups with colors

---

## Extender gaps

### Issue: Extender missing extension management UI
Burp has Add/Edit/Remove extension buttons with extension list and details.

**Gap:** Stub UI ("No plugin is allowlisted")
**Evidence:** `Ze4x.java` + 6 API endpoints in server.go
**Acceptance Criteria:**
- [ ] Add extension button
- [ ] Edit extension button
- [ ] Remove extension button
- [ ] Extension list with details
- [ ] Output/Errors tabs

---

### Issue: Extender missing extension details/output/errors
Burp shows extension details with Output and Errors tabs.

**Gap:** No extension details panel
**Evidence:** `Zbwe.java` getPluginMenuItems
**Acceptance Criteria:**
- [ ] Extension details panel
- [ ] Output tab for stdout
- [ ] Errors tab for stderr
- [ ] Console output with auto-scroll

---

## Session gaps

### Issue: Session "New rule" button doesn't open dialog
Burp has full session rule creation form. burpsy's "New rule" button does nothing in empty state.

**Gap:** New rule button non-functional
**Evidence:** `ISessionHandlingAction` + `configFunctionApplicationLogin`
**Acceptance Criteria:**
- [ ] Click "New rule" opens rule creation dialog
- [ ] Dialog has: name, scope, match condition, action
- [ ] Save creates rule via POST /api/session/rules

---

### Issue: Session missing rule edit/remove
Burp has Edit and Remove buttons for each rule.

**Gap:** No rule management
**Evidence:** Edit/Remove buttons in Burp
**Acceptance Criteria:**
- [ ] Edit button per rule
- [ ] Remove button per rule
- [ ] Update via PUT /api/session/rules/{id}
- [ ] Delete via DELETE /api/session/rules/{id}

---

## Intercept gaps

### Issue: Intercept missing Forward/Drop/Action toolbar
Burp has Forward, Drop, Action menu, Comment, Highlight buttons.

**Gap:** No toolbar buttons
**Evidence:** `Zulj.java` context menu + `proxyInterceptTablePopup` strings
**Acceptance Criteria:**
- [ ] Forward button
- [ ] Drop button
- [ ] Action menu (Send to Repeater/Comparer/Intruder/Spider)
- [ ] Comment button
- [ ] Highlight button

---

### Issue: Intercept missing in-scope only filter
Burp has "Only intercept in-scope messages" checkbox.

**Gap:** No in-scope filter on Intercept page
**Evidence:** "Only intercept in-scope messages" string in Burp
**Acceptance Criteria:**
- [ ] In-scope only toggle
- [ ] Filters held messages to in-scope only

---

## HTTP history gaps

### Issue: HTTP history missing Bambda mode
Burp has Bambda mode for advanced filtering.

**Gap:** No Bambda mode
**Evidence:** "filterBambdaModeRadioButton" string in Burp
**Acceptance Criteria:**
- [ ] Bambda mode toggle
- [ ] Bambda editor
- [ ] Save/load bambda filters

---

### Issue: HTTP history missing per-column filters
Burp has per-column filter inputs in table headers.

**Gap:** No column filters
**Evidence:** Column-specific filter strings in Burp
**Acceptance Criteria:**
- [ ] Filter input per column
- [ ] Apply filters to query

---

## Match & Replace gaps

### Issue: Match & Replace missing edit/remove/move
Burp has Edit, Remove, Move up, Move down buttons for each rule.

**Gap:** No rule management in empty state
**Evidence:** `Zrd4.java` editHttpMatchReplaceRuleButton, delete rule, Move up/down strings
**Acceptance Criteria:**
- [ ] Edit button per rule
- [ ] Remove button per rule
- [ ] Move up/down buttons
- [ ] In-scope only checkbox per rule

---

### Issue: Match & Replace missing HTTP/WS separation
Burp has separate HTTP and WebSocket rule sets.

**Gap:** Single rule set
**Evidence:** "HTTP match and replace rules" + "WebSocket match and replace rules" strings
**Acceptance Criteria:**
- [ ] Separate HTTP and WS rule tabs
- [ ] Independent rule sets

---

## Site map gaps

### Issue: Site map missing crawl paths view
Burp has two views: URL view and Crawl paths view.

**Gap:** Only URL tree view
**Evidence:** "Crawl paths view" string + `Zx.java` in Burp
**Acceptance Criteria:**
- [ ] Toggle between URL view and Crawl paths view
- [ ] Crawl paths shows scanner actions as tree

---

### Issue: Site map missing passive scan controls
Burp has "Passively scan this branch" and "Passively scan selected branches" options.

**Gap:** No passive scan controls
**Evidence:** "Passively scan this branch" strings in Burp
**Acceptance Criteria:**
- [ ] Passive scan branch option
- [ ] Passive scan selected branches option

---

## Organizer gaps

### Issue: Organizer missing in-scope/status/MIME filters
Burp has in-scope checkbox, status filter, and MIME type filter.

**Gap:** No filters
**Evidence:** "organiserShowOnlyInScopeCheckbox" + status/MIME filter strings
**Acceptance Criteria:**
- [ ] In-scope only checkbox
- [ ] Status filter (2xx/3xx/4xx/5xx)
- [ ] MIME type filter

---

## Proxy settings gaps

### Issue: Proxy settings missing TLS passthrough
Burp has TLS passthrough host-pattern configuration.

**Gap:** TLS passthrough not in Proxy settings page
**Evidence:** "proxy.ssl_pass_through" string + `configPanelProxyTlsPassThrough` strings
**Acceptance Criteria:**
- [ ] TLS passthrough section in Proxy settings
- [ ] Add/remove passthrough rules

---

### Issue: Proxy settings missing resource pools
Burp has Resource pools management in Proxy settings.

**Gap:** Resource pools not in Proxy settings page
**Evidence:** "Resource pools" + `configPanelResourcePoolsEditBtn` strings
**Acceptance Criteria:**
- [ ] Resource pools section in Proxy settings
- [ ] New/Edit/Delete pool buttons

---

## Scanner gaps

### Issue: No Scanner tab exists
Burp has a dedicated Scanner tab with scan configuration, live audit, crawl/audit controls.

**Gap:** No Scanner tab in burpsy
**Evidence:** `DashboardModule.java` references Scanner
**Acceptance Criteria:**
- [ ] Scanner tab with scan configuration
- [ ] Live audit controls
- [ ] Crawl and audit launch buttons
- [ ] Coverage display

---

### Issue: Scanner engine not wired at binary level
`DispatchScopeStoredPerInsertionPoint` is reachable but needs `WithStoredLedger()` at scanner construction.

**Gap:** Stored ledger not wired
**Evidence:** `internal/scanner/audit.go` + `cmd/burpsy/main.go`
**Acceptance Criteria:**
- [ ] Wire stored ledger at scanner construction
- [ ] Enable stored/second-order checks
- [ ] Demonstrate DOM-based checks

---

## WebSocket gaps

### Issue: WebSocket UI missing connection detail
Burp has per-connection frame history with detail view.

**Gap:** Minimal WebSocket history UI
**Evidence:** `Burp Proxy WebSockets History` + frame-level view
**Acceptance Criteria:**
- [ ] Per-connection frame list
- [ ] Frame detail view with payload
- [ ] Text/Hex view toggle

---

### Issue: WebSocket interception not fully exposed
`intercept.DirectionWebSocketToServer` and `DirectionWebSocketToClient` exist in engine but UI doesn't fully expose hold/forward/drop.

**Gap:** WS intercept UI incomplete
**Evidence:** `internal/proxy/ws.go` + `wsHoldable()` function
**Acceptance Criteria:**
- [ ] Hold WS messages
- [ ] Forward/edit WS messages
- [ ] Drop WS messages
- [ ] WS match/replace rules

---

## Content discovery gaps

### Issue: Discover tab is docs only
Burp's "Discover content" is a content discovery tool (ffuf-based). burpsy's Discover is a documentation hub.

**Gap:** No content discovery functionality
**Evidence:** `/api/discovery` endpoint exists in server.go
**Acceptance Criteria:**
- [ ] Launch ffuf-based content discovery
- [ ] Show discovery results
- [ ] Wordlist management

---

## Cross-cutting gaps

### Issue: Context menus missing everywhere
Burp has context menus on tables, trees, lists throughout. burpsy has none.

**Gap:** No context menus in burpsy UI
**Evidence:** `Ze_s.java` table header context menu + `Zb3y.java` scan check context menu
**Acceptance Criteria:**
- [ ] Add right-click context menus to all tables
- [ ] Copy column, Hide column, Sort options
- [ ] Copy, Paste, Delete options for lists

---

### Issue: React key warning in list rendering
`console.error: Each child in a list should have a unique "key" prop` — fails 4 e2e tests.

**Gap:** Missing React keys in list rendering
**Evidence:** e2e-ui failures in behaviour.spec.ts (tests 70, 79, 80, 81)
**Acceptance Criteria:**
- [ ] Add unique keys to all list items
- [ ] Pass all console-error assertions
