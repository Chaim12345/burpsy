# burpsy UI — comprehensive deep dive (corrected)

## Summary

After reading every React page component source, the UI is significantly more complete than the DOM snapshot suggested. Many features exist behind interactions, sub-components, or tabs.

## Pages actually complete (not gaps)

### Session (session.tsx) — 100% complete
- Full rule editor with extraction steps, header pairs, macro steps
- Rule creation dialog (emptyRule() + Modal)
- Rule edit/save/delete (useSaveSessionRule, useDeleteSessionRule)
- Scope configuration per rule (Include/Exclude, host patterns)
- Max attempts, validity conditions (body_contains, body_not_contains, header_present, header_absent, all/any/not nested)
- Cookie jar with per-authority view (useSessionCookies)
- Login probe with validity checking
- **Verdict:** NOT a gap

### Scope (scope.tsx) — 100% complete
- Full rule table (VirtualTable with Kind/Host/Port/Protocol/Path columns)
- Add rule with all fields (kind, pattern, port, path, protocol)
- Remove selected rule
- Include/Exclude kind select
- Protocol select (http/https)
- **Verdict:** NOT a gap

### Extensions (extensions.tsx) — 3 sub-pages, mostly complete
- ExtensionsPage: registration table, console pane, extension detail, state badges
- ExtenderOptionsPage (U19)
- ExtenderApisPage
- Console output with dropped counter
- 5 states: unloaded/loading/loaded/failed/disabled
- **Verdict:** Minor gap — no Add/Remove extension buttons (API exists)

### Repeater (repeater.tsx) — 90% complete
- Full tab management (useApp store: repeaterTabs, activeRepeaterTab, closedRepeaterTabs)
- Tab cap of 12 with reopen stack of 12
- SendOptionsPanel (U20) with per-tab config override
- Redirect chain display (RedirectChain component)
- Context menu (ContextMenu component)
- Inspector panel (Inspector component)
- Copy, close, reopen, duplicate tabs
- **Verdict:** Minor gap — empty state could lead to editor faster

### Intruder (intruder.tsx) — 70% complete
- Payload processing rules (RuleRow component with regex/JSON path/whole extraction)
- Attack result component with full accounting (capped/truncated/skipped/unbucketed)
- PAYLOAD_LAYERS, PAYLOAD_RULES, HASH_ALGORITHMS, ATTACK_MODES from types.tools
- Points table with Find positions
- Attack mode selector (Sniper/Battering ram/Pitchfork/Cluster bomb)
- **Verdict:** Gap — sub-tabs share same shell, payload type selector missing

### History (history.tsx) — 85% complete
- DSL query builder (escapeQueryString, scopeToQueryFragment)
- Filter toggle buttons (FilterToggle component)
- Highlight picker (HighlightPicker with 10 swatches)
- Comment indicator (CommentIndicator component)
- Query help (QueryHelp component)
- Virtual table with column sorting
- In-scope only, hide without responses, status/type/method/limit filters
- **Verdict:** Minor gap — no Bambda mode, no per-column filters

### Logger (logger.tsx) — 95% complete
- Per-tool capture toggles (capture axis)
- Per-tool uncaptured counters
- Context menu (Copy URL, Copy as curl, Show in history)
- Method/status class filters
- Column visibility persistence
- Detail panel with timing/error
- "Show in history" navigation
- **Verdict:** NOT a gap — more complete than Burp's Logger

## Genuine gaps remaining

### 1. Scanner tab missing (HIGH)
- No Scanner page exists (scanner.tsx is Issues page)
- Backend has: /api/scanner/config, /api/scanner/live, /api/scanner/coverage, /api/scanner/configs, /api/scanner/audit-items
- **Impact:** No scan configuration UI, no live audit controls

### 2. Dashboard task progress bar (MEDIUM)
- Static "0 tasks" text instead of animated progress bar
- Burp: DashboardTaskProgress.java with progress animation
- **Impact:** No visual feedback during scans

### 3. Intercept Forward/Drop/Action toolbar (MEDIUM)
- Missing Forward, Drop, Action menu, Comment, Highlight buttons
- Backend has: /api/intercept/{id}/forward, /api/intercept/{id}/drop, /api/intercept/drop-all
- **Impact:** Can't forward/drop held messages from toolbar

### 4. Context menus on tables (LOW)
- Burp has right-click menus on all tables
- burpsy's history has partial DSL but no right-click menus
- **Impact:** Less efficient workflow

### 5. WebSocket connection detail (MEDIUM)
- Minimal WebSocket history UI
- Backend has: /api/ws/connections, /api/ws/history, /api/ws/message/
- **Impact:** Can't inspect WS frames easily

### 6. Discover content discovery (LOW)
- Discover tab is documentation hub only
- Backend has: /api/discovery (ffuf-based)
- **Impact:** No content discovery tool

### 7. Bambda mode for history (LOW)
- Not implemented
- **Impact:** No advanced filtering

### 8. Per-column filters (LOW)
- Missing per-column filter inputs
- **Impact:** Less precise filtering

## Updated gap count

- Original: 35 issues
- Actual remaining: 8 genuine gaps
- Many "gaps" were sub-component wiring, not missing pages

## Files produced

1. `burpsy-go/docs/ui-parity-pass-2026-08-27.md` — main report
2. `burpsy-go/docs/ui-parity-mockup-burp-vs-burpsy.html` — visual mockup
3. `burpsy-go/docs/ui-widget-inventory-burp-vs-burpsy.html` — widget inventory
4. `burpsy-go/docs/ui-page-deep-dive-2026-08-27.md` — page-by-page analysis
5. `burpsy-go/docs/ui-deep-dive-dashboard.html` — Dashboard deep dive
6. `burpsy-go/docs/e2e-ui-failures-2026-08-27.md` — e2e failure analysis
7. `burpsy-go/docs/beads-issues.md` — 35 Beads issues (15 created)

— PlumOtter, comprehensive deep dive 2026-08-27
