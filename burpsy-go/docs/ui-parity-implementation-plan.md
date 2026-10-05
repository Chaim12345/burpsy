# burpsy UI parity — implementation plan

## Goal

Fill all 56 gaps identified in the parity audit to achieve ~90% feature parity with Burp Suite.

## Strategy

1. **P0 first** — functional blocks that make tools unusable
2. **P1 second** — major UX gaps that make tools painful
3. **P3 last** — cosmetic gaps (can be done incrementally)
4. **P2 in parallel** — medium gaps can be filled by any available agent

---

## Phase 1: P0 — Functional blocks (4 issues, ~2 weeks)

### 1.1 Scanner tab

**Gap:** No Scanner page exists. `scanner.tsx` is the Issues page.

**Files to create:**
- `burpsy-go/internal/web/ui/src/pages/scanner.tsx` — new Scanner page
- `burpsy-go/internal/web/ui/src/lib/data.scanner.ts` — scanner data hooks

**Components needed:**
- Scan configuration panel (audit families, performance knobs)
- Live audit controls (enable/disable, scope filter)
- Crawl/audit launch buttons
- Coverage display (issues, passive checks, live audit, captured traffic, tasks)
- Scan queue with progress

**API endpoints to wire:**
- `GET /api/scanner/config` — current config
- `PUT /api/scanner/config` — save config
- `GET /api/scanner/live` — live audit state
- `POST /api/scanner/live` — toggle live audit
- `GET /api/scanner/coverage` — coverage summary
- `GET /api/scanner/configs` — built-in scan configurations
- `GET /api/scanner/audit-items` — audit queue
- `POST /api/scanner/audit-items/{id}/again` — re-audit

**Burp reference:** `DashboardModule.java`, `LiveAuditLauncherUI.java`, `scanConfigurationEditor*` strings

---

### 1.2 Intruder sub-tab content

**Gap:** All 5 sub-tabs render the same "Base request" panel.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/intruder.tsx` — add sub-tab content

**Sub-tab content:**

**Positions:**
- Request editor (HTTP message editor)
- Add § / Auto § / Clear § buttons
- Position list with checkboxes
- Target field
- Find insertion points button

**Payloads:**
- Payload type selector (Simple list, Runtime file, Character substitution, Case substitution, Numbers, Dates, Brute force, Null payloads, Character frobber, Bit flipper, Custom iterator, File, Collaborator)
- Conditional fields per type (Numbers: from/to/step, File: server path, Brute force: charset/min/max, Dates: from/to/step/format, Custom iterator: positions+separator, Null: count)
- Load/Paste/Remove buttons
- Payload count display
- Processing rules (RuleRow exists, needs to be wired)
- Grep payloads section
- Match/replace in list items
- Illegal UTF-8, Hex formatting, Max permutations checkboxes

**Resource pool:**
- Concurrent requests input
- Delay input
- Random variations checkbox
- Increment delay input
- Custom resource pool selector
- Edit/Delete pool buttons

**Settings:**
- Scan details section
- Scope configuration
- Isolate scan checkbox
- Engine configuration
- Attack configuration
- Duplicate attacks

**Results:**
- Results table (#/Status/Error/Timeout/Length/Time/Comment/Total)
- Attack progress bar
- Pause/Resume/Stop buttons
- Save results option
- Split pane with server responses

**Burp reference:** `Zr7k.java`, `Zija.java`, `Zxcq.java`, `Zxoh.java`, `Zr_q.java`

---

### 1.3 Intercept Forward/Drop/Action toolbar

**Gap:** No toolbar buttons for intercept actions.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/intercept.tsx` — add toolbar

**Components needed:**
- Forward button (calls `POST /api/intercept/{id}/forward`)
- Drop button (calls `POST /api/intercept/{id}/drop`)
- Action menu (Send to Repeater, Comparer, Intruder, Spider, Do intercept, Drop, Comment, Highlight)
- Comment button
- Highlight button
- Edit target button
- Open browser button

**Burp reference:** `Zulj.java` context menu + `proxyInterceptTablePopup` strings

---

### 1.4 Extender Add/Edit/Remove

**Gap:** No extension management UI.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/extensions.tsx` — add management buttons

**Components needed:**
- Add extension button (opens file picker → `POST /api/extensions/load`)
- Edit extension button (opens edit dialog)
- Remove extension button (calls `POST /api/extensions/unload`)
- Extension list with details (exists, needs management actions)

**API endpoints to wire:**
- `POST /api/extensions/load` — load extension
- `POST /api/extensions/unload` — unload extension
- `GET /api/extensions` — list extensions (exists)
- `GET /api/extensions/console` — console output (exists)
- `GET /api/extensions/apis` — API contracts (exists)
- `POST /api/extensions/invoke` — invoke registration (exists)

**Burp reference:** `Ze4x.java` + extension state strings

---

## Phase 2: P1 — Major UX gaps (8 issues, ~2 weeks)

### 2.1 Repeater empty state

**Gap:** Empty state doesn't lead to editor.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/repeater.tsx` — modify empty state

**Changes:**
- Open with blank editor by default (remove "No request open" empty state)
- Show Send/Cancel buttons immediately
- Show protocol selector (HTTP/HTTPS)
- Show request/response view

---

### 2.2 History Bambda mode

**Gap:** No Bambda mode for advanced filtering.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/history.tsx` — add Bambda mode

**Components needed:**
- Bambda mode toggle (radio button)
- Bambda editor (code editor)
- Save/load bambda filters
- Apply bambda to filter

---

### 2.3 History per-column filters

**Gap:** No per-column filter inputs.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/history.tsx` — add column filters

**Components needed:**
- Filter input per column in table header
- Apply filters to query
- Clear column filter

---

### 2.4 WebSocket connection detail

**Gap:** Can't inspect WS frames.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/wshistory.tsx` — add detail view

**Components needed:**
- Per-connection frame list
- Frame detail view with payload
- Text/Hex view toggle
- Frame metadata (direction, opcode, length, age)

**API endpoints to wire:**
- `GET /api/ws/connections` — connection list (exists)
- `GET /api/ws/history` — frame history (exists)
- `GET /api/ws/message/{id}` — frame payload (exists)

---

### 2.5 Discover content discovery

**Gap:** Discover tab is docs only, no ffuf integration.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/discover.tsx` — add content discovery

**Components needed:**
- Content discovery section
- Launch ffuf-based path sweep
- Show discovery results
- Wordlist management

**API endpoints to wire:**
- `GET /api/discovery` — discovery state
- `POST /api/discovery` — start discovery

---

### 2.6 Proxy settings TLS passthrough

**Gap:** TLS passthrough not in Proxy settings page.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/proxysettings.tsx` — add TLS passthrough

**Components needed:**
- TLS passthrough section
- Host pattern input
- Add rule button
- Rules table
- Remove rule button

**API endpoints to wire:**
- `GET /api/proxy/passthrough` — current rules
- `POST /api/proxy/passthrough` — add rule
- `DELETE /api/proxy/passthrough` — remove rule

---

### 2.7 Proxy settings resource pools

**Gap:** Resource pools not in Proxy settings page.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/proxysettings.tsx` — add resource pools

**Components needed:**
- Resource pools section
- New pool button
- Pool table
- Edit/Delete pool buttons

**API endpoints to wire:**
- `GET /api/pools` — pool list (exists)
- `POST /api/pools` — create pool (exists)
- `PUT /api/pools/{name}` — update pool (exists)
- `DELETE /api/pools/{name}` — delete pool (exists)

---

### 2.8 Match & Replace edit/remove

**Gap:** Can't edit/remove rules in empty state.

**Files to modify:**
- `burpsy-go/internal/web/ui/src/pages/matchreplace.tsx` — add rule management

**Components needed:**
- Edit button per rule
- Remove button per rule
- Move up/down buttons
- In-scope only checkbox per rule
- Auto-modified preview
- Original message preview

---

## Phase 3: P2 — Medium gaps (14 issues, ~1 week)

### 3.1 Dashboard task progress bar

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/dashboard.tsx`

**Changes:**
- Add animated progress bar component
- Show ETA
- Animate as tasks complete

---

### 3.2 Dashboard event log popup

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/dashboard.tsx`

**Changes:**
- Add right-click context menu to event log
- Copy column, Hide column, Sort options

---

### 3.3 Dashboard activity log popup

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/dashboard.tsx`

**Changes:**
- Add right-click context menu to activity log
- Copy, Hide, Sort options

---

### 3.4 Site map crawl paths view

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/sitemap.tsx`

**Changes:**
- Toggle between URL view and Crawl paths view
- Crawl paths shows scanner actions as tree

---

### 3.5 Site map passive scan controls

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/sitemap.tsx`

**Changes:**
- Passive scan branch option
- Passive scan selected branches option

---

### 3.6 HTTP history context menus

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/history.tsx`

**Changes:**
- Right-click menu on history rows
- Send to Repeater, Comparer, Intruder, Spider
- Do intercept, Drop, Comment, Highlight

---

### 3.7 Intercept Comment/Highlight

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/intercept.tsx`

**Changes:**
- Comment button
- Highlight button

---

### 3.8 Intercept Edit target

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/intercept.tsx`

**Changes:**
- Edit target button
- Target modification dialog

---

### 3.9 Intruder payload type selector

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/intruder.tsx`

**Changes:**
- Payload type selector dropdown
- Conditional fields per type

---

### 3.10 Intruder resource pool

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/intruder.tsx`

**Changes:**
- Concurrent requests input
- Delay input
- Random variations checkbox
- Increment delay input

---

### 3.11 Intruder scan settings

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/intruder.tsx`

**Changes:**
- Scan details section
- Scope configuration
- Isolate scan checkbox

---

### 3.12 Intruder results table

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/intruder.tsx`

**Changes:**
- Results table with all columns
- Attack progress bar
- Pause/Resume/Stop buttons

---

### 3.13 Repeater Cancel button

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/repeater.tsx`

**Changes:**
- Cancel button visible during send

---

### 3.14 Sequencer token analysis

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/sequencer.tsx`

**Changes:**
- Token analysis section (Spectral, Transitions, FIPS poker)
- Token handling section (base64 decode, pad short tokens)

---

## Phase 4: P3 — Low gaps (30 issues, ~1 week)

### 3.15 Dashboard pause/resume

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/dashboard.tsx`

---

### 3.16 Dashboard listener status

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/dashboard.tsx`

---

### 3.17 Site map read-only indicator

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/sitemap.tsx`

---

### 3.18 Site map items/queued/processed

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/sitemap.tsx`

---

### 3.19 Scope advanced scope control

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/scope.tsx`

---

### 3.20 Scope save to library

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/scope.tsx`

---

### 3.21 History show highlighted

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/history.tsx`

---

### 3.22 History show commented

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/history.tsx`

---

### 3.23 History auto-scroll

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/history.tsx`

---

### 3.24 WebSockets Bambda filter

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/wshistory.tsx`

---

### 3.25 WebSockets filter settings

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/wshistory.tsx`

---

### 3.26 Match & Replace auto-modified preview

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/matchreplace.tsx`

---

### 3.27 Match & Replace original message preview

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/matchreplace.tsx`

---

### 3.28 Proxy settings miscellaneous

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/proxysettings.tsx`

---

### 3.29 Proxy settings web interface

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/proxysettings.tsx`

---

### 3.30 Collaborator payload count

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/collaborator.tsx`

---

### 3.31 Collaborator server location

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/collaborator.tsx`

---

### 3.32 Comparer word-level

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/comparer.tsx`

---

### 3.33 Extender JMenu items

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/extensions.tsx`

---

### 3.34 Extender hot key handlers

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/extensions.tsx`

---

### 3.35 Extender bapp update

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/extensions.tsx`

---

### 3.36 Extender suppress popup

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/extensions.tsx`

---

### 3.37 Extender Ruby/Python/Java config

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/extensions.tsx`

---

### 3.38 Repeater status label

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/repeater.tsx`

---

### 3.39 Repeater follow redirects

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/repeater.tsx`

---

### 3.40 Repeater explore (AI)

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/repeater.tsx`

---

### 3.41 Repeater search

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/repeater.tsx`

---

### 3.42 Repeater WS tab option

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/repeater.tsx`

---

### 3.43 Repeater streaming config

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/repeater.tsx`

---

### 3.44 Repeater validation warnings

**Files to modify:** `burpsy-go/internal/web/ui/src/pages/repeater.tsx`

---

## Phase 5: Cross-cutting improvements

### 5.1 Context menus everywhere

**Files to create:**
- `burpsy-go/internal/web/ui/src/ui/contextmenu.tsx` — reusable context menu component

**Files to modify:**
- All table pages (history, logger, intercept, etc.)

---

### 5.2 Keyboard shortcuts

**Files to modify:**
- `burpsy-go/internal/web/ui/src/app.tsx` — add global shortcuts

**Shortcuts to add:**
- Ctrl+F: Find
- Ctrl+Enter: Send request (Repeater/Intruder)
- Ctrl+1-9: Navigate tabs
- Ctrl+Shift+C: Copy
+ more

---

### 5.3 Dialogs/windows

**Files to create:**
- `burpsy-go/internal/web/ui/src/ui/dialog.tsx` — reusable dialog component

**Dialogs to add:**
- Scan configuration editor
- Documentation/help dialog
- Message editor dialog
- Floating tool window

---

## Estimated effort

| Phase | Issues | Effort | Priority |
|-------|--------|--------|----------|
| Phase 1 | 4 | 2 weeks | P0 |
| Phase 2 | 8 | 2 weeks | P1 |
| Phase 3 | 14 | 1 week | P2 |
| Phase 4 | 30 | 1 week | P3 |
| Phase 5 | 3 | 1 week | Cross-cutting |
| **Total** | **59** | **7 weeks** | |

## Recommended agent assignments

- **Agent 1 (UI specialist):** Phase 1.1 (Scanner tab) + Phase 1.2 (Intruder sub-tabs)
- **Agent 2 (UI specialist):** Phase 1.3 (Intercept toolbar) + Phase 1.4 (Extender management)
- **Agent 3 (UI specialist):** Phase 2.1-2.4 (Repeater, History, WebSocket)
- **Agent 4 (UI specialist):** Phase 2.5-2.8 (Discover, Proxy settings, Match & Replace)
- **All agents:** Phase 3 (P2 gaps) — parallel by page
- **All agents:** Phase 4 (P3 gaps) — parallel by page
- **Agent 1:** Phase 5 (cross-cutting)

## Success criteria

- [ ] Scanner tab functional with scan config, live audit, crawl/audit launch
- [ ] Intruder sub-tabs have distinct content matching Burp
- [ ] Intercept has Forward/Drop/Action toolbar
- [ ] Extender has Add/Edit/Remove buttons
- [ ] Repeater opens with blank editor by default
- [ ] History has Bambda mode and per-column filters
- [ ] WebSocket has frame-level detail view
- [ ] Discover has content discovery (ffuf)
- [ ] All context menus implemented
- [ ] Keyboard shortcuts documented and working

---

— PlumOtter, implementation plan 2026-08-27
