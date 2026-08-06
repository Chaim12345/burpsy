# Target tools — interaction map

## SiteMap (`pages/sitemap.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|-------------|
| Filter input field | input | "Filter site map" | Always | Filters site map tree nodes by segment/path; updates `filter` state on change; debounced to 250ms |
| Clear filter button | icon-button | "Clear filter" | `filter` is non-empty | Clears the filter input, resetting filter to "" |
| Tree toggle button (each node) | icon-button | "Expand {node.segment}" or "Collapse {node.segment}" | Only when `hasChildren` is true | Toggles expansion state of tree node via `toggle(row)` |
| Tree row (each node) | tree-row | N/A | Always | Clickable row; selects node via `select(row.key)` on click; keyboard-navigable with arrow keys, Enter |
| VirtualTable rows (exchanges) | table-row | N/A | `selected` node exists and `nodeExchanges.length > 0` | Selects/activates exchange; `onSelect` sets `selectedExchange` to `row.id`; `onActivate` sends to Repeater |
| Send to Repeater button | button | N/A (none) | `activeExchange` exists | Calls `actions.sendToRepeater(activeExchange)` on click |
| Send to Intruder button | button | N/A (none) | `activeExchange` exists | Calls `actions.sendToIntruder(activeExchange)` on click |
| Send to Comparer button | button | N/A (none) | `activeExchange` exists | Calls `actions.sendToComparer(activeExchange, "a")` on click |
| Show/Hide Inspector button | icon-button | "Show Inspector" or "Hide Inspector" (dynamic) | `activeExchange` exists | Toggles `inspector` state; when true, shows Inspector component alongside Request/Response editors; `aria-pressed={inspector}` |
| Filter history button | button | N/A (none) | `selected` node exists | Calls `filterHistory(selected)` which constructs a query filter and navigates to history page via `setRoute("history")` and `setHistoryQuery(query)` |
| Page refresh button | icon-button | "Refresh" | Always | Calls `refetch()` to reload sitemap data; shows loading state via `loading={isFetching}` |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|-------------|
| `useSitemapDetailed()` | Fetches `/api/sitemap/detailed` | Always | `data` → tree data, `error` → error display, `isFetching` → loading state, `refetch()` → refresh button |
| `useHistory("", 1000)` | Fetches HTTP history cache key "" with limit 1000 | Always | `history` → filters exchanges by node selection; lookup for `activeExchange` |
| `useExchangeActions()` | Returns action object with `sendToRepeater`, `sendToIntruder`, `sendToComparer`, `menu()` | Always | Button click handlers and table context menu |
| `useMessage(activeExchange?.request)` | Fetches full request message text for active exchange | `activeExchange` exists | `request.data?.text` displayed in HttpEditor; `request.isFetching` shows "Loading request bytes…" |
| `useMessage(activeExchange?.response ?? null)` | Fetches full response message text for active exchange | `activeExchange` exists | `response.data?.text` displayed in HttpEditor; `response.isFetching` shows "Loading response bytes…" |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `filter` | `""` | Input `onChange` event; clear button click | Tree filter function; debounced to `debouncedFilter` |
| `expanded` | `{}` | `toggle(row)` function; forced open when filter matches | `flatten()` tree rendering; determines node visibility |
| `selectedId` | `null` | `select(key)` function; cleared when new node selected | `index.get(selectedId)` to find selected node; row highlight styling |
| `cursorId` | `null` | Keyboard navigation (arrow keys) via `moveCursor()`; `select()` also calls `setCursorId()` | `cursorIndex` lookup; outline styling on tree row |
| `selectedExchange` | `null` | Table row selection via `onSelect`; cleared when node changes | Looks up `activeExchange` from `nodeExchanges` array; Editor/Inspector display |
| `inspector` | `false` | Inspector button click toggles it | Toggles CSS class `editor-grid-inspected` vs `editor-grid`; renders Inspector component conditionally |

### Cross-page effects

| Trigger | Destination | Store/Router action |
|---------|-------------|-------------------|
| User clicks "Filter history" button | Navigate to HTTP History tab with filter query | `setHistoryQuery(query)` where query is constructed from selected node path; `setRoute("history")` |

### Action flows

**FLOW SITEMAP-1: Node selection and navigation**
1. User clicks tree row → `onSelect()` called
2. `select(key)` sets `selectedId = key`, `cursorId = key`, `selectedExchange = null`
3. Component re-renders; selected row highlights, cursor outline appears
4. `selected` computed value finds IndexedNode from index
5. `nodeExchanges` computed value filters history for exchanges under node
6. Detail pane updates to show selected node's metadata and exchanges table
7. **Failure:** If node key not in index, `selected` = null → "No path selected" empty state displays

**FLOW SITEMAP-2: Tree navigation with keyboard**
1. User presses arrow key (Up/Down/Left/Right) with tree focused
2. `onKeyDown` → `moveCursor(delta)` updates `cursorId` or `toggle(row)` expands/collapses
3. Tree row outline moves to new position
4. If user presses Enter, calls `select(cursorId)` → same as FLOW SITEMAP-1

**FLOW SITEMAP-3: Exchange selection in table**
1. User clicks row in VirtualTable (beneath selected node)
2. `onSelect` callback sets `selectedExchange = row.id`
3. `activeExchange` computed value finds exchange in `nodeExchanges`
4. `useMessage` hooks fetch request and response text
5. Detail pane (right side) shows request/response editors; status badge, duration badge, action buttons
6. **Failure:** If exchange not found, `activeExchange` = null → "No request selected" empty state

**FLOW SITEMAP-4: Send exchange to Repeater**
1. User clicks "Repeater" button (enabled when `activeExchange` exists)
2. `onClick` calls `actions.sendToRepeater(activeExchange)`
3. Action sends exchange to Repeater tool (cross-page effect)

**FLOW SITEMAP-5: Send exchange to Intruder**
1. User clicks "Intruder" button (enabled when `activeExchange` exists)
2. `onClick` calls `actions.sendToIntruder(activeExchange)`
3. Action sends exchange to Intruder tool (cross-page effect)

**FLOW SITEMAP-6: Send exchange to Comparer**
1. User clicks "Compare" button (enabled when `activeExchange` exists)
2. `onClick` calls `actions.sendToComparer(activeExchange, "a")`
3. Action sends exchange to Comparer slot "a" (cross-page effect)

**FLOW SITEMAP-7: Toggle Inspector**
1. User clicks Inspector icon button (enabled when `activeExchange` exists)
2. `onClick` toggles `inspector` state
3. If true: editor grid changes to 3-column layout, Inspector component renders with request raw bytes
4. If false: grid returns to 2-column, Inspector hidden

**FLOW SITEMAP-8: Filter history navigation**
1. User clicks "Filter history" button (enabled when `selected` node exists)
2. `onClick` calls `filterHistory(selected)`
3. Constructs query string from node path; escapes quotes and backslashes
4. Calls `setHistoryQuery(query)` and `setRoute("history")`
5. Router navigates to history page with this query active; history table displays filtered exchanges

**FLOW SITEMAP-9: Refresh sitemap**
1. User clicks refresh button
2. `onClick` calls `refetch()`
3. Page re-fetches `/api/sitemap/detailed` (SWR cache)
4. `data` updated; tree re-renders with new nodes
5. LoadingPanel shown while `isFetching && !data`

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| `isFetching && !data` | `Empty` component | Title: "Loading site map…"; Detail: "Folding captured traffic into a tree." |
| `rows.length === 0 && term` (no matches after filter) | `Empty` component | Title: "No path matches this filter"; Detail: "Relax the filter, or clear it to see the whole map." |
| `rows.length === 0 && !term` (no traffic captured) | `Empty` component | Title: "No traffic captured yet"; Detail: "Point a client at the proxy to start building the map." |
| `!selected` (no node selected in tree) | `Empty` component | Title: "No path selected"; Detail: "Choose a host or path in the tree to see the requests captured under it." |
| `!activeExchange` (no exchange selected in table) | `Empty` component | Title: "No request selected"; Detail: "Choose a row above to read its exact request and response bytes." |
| `nodeExchanges.length === 0` (selected node has no exchanges) | `Empty` component | Title: "No requests under this node"; Detail: "The capture holding these exchanges may have rolled over." (if `selected.node.requested` true) OR "Nothing requested this folder itself — open a child node to see its traffic." (if requested false) |
| `error` exists | `ErrorNotice` component | Error message from API; "Retry" button calls `refetch()` |

---

## Scanner (`pages/scanner.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|-------------|
| Filter input (findings) | input | "Filter findings" | Always | Filters findings by check name, issue name, host, or detail; updates `term` state; debounced 260ms |
| Severity filter select | select | "Severity filter" | Always | Changes `severity` state; "all" or one of SEVERITIES; filters findings list |
| Confidence filter select | select | "Confidence filter" | Always | Changes `confidence` state; "all" or one of CONFIDENCES; filters findings list |
| "Audit settings" button | button | N/A (none) | Always | Opens modal via `setSettingsOpen(true)` |
| Report download buttons (HTML/JSON/SARIF) | link-button | N/A (none) | Always | Links to `/api/report/{format}` with `download` attribute; 3 separate buttons |
| Page refresh button | icon-button | "Refresh" (inferred) | Always | Calls `refetch()` to reload issues; shows loading state via `loading={isFetching}` |
| Host tree-row toggle button | icon-button | "Collapse {host.host}" or "Expand {host.host}" (dynamic) | Always | Toggles host collapse state via `setCollapsed` |
| Host tree-row (clickable) | tree-row | N/A | Always | Clicking toggles host collapse; `aria-level={1}`, `aria-expanded={hostOpen}` |
| Path tree-row toggle button | icon-button | "Collapse {path.path}" or "Expand {path.path}" (dynamic) | Host is open | Toggles path collapse state via `setCollapsed` |
| Path tree-row (clickable) | tree-row | N/A | Host is open | Clicking toggles path collapse; `aria-level={2}`, `aria-expanded={pathOpen}` |
| Finding leaf tree-row (selectable) | tree-row | N/A | Path is open | Clicking selects finding via `setSelectedKey(leaf.key)`; `aria-level={3}`, `aria-selected={leaf.key === selectedKey}` |
| "In history" button | button | N/A (none) | `selected` finding exists AND has `occurrence` | Calls `focusExchange(selected.occurrence?.exchange_id)` and `setRoute("history")` |
| Severity badge (in advisory) | badge | N/A (none) | `selected` finding exists | Display only; `tone={severityTone(selected.finding.severity)}` |
| Confidence badge (in advisory) | badge | N/A (none) | `selected` finding exists | Display only; `tone={confidenceTone(selected.finding.confidence)}` |
| Occurrence buttons (in advisory) | button | N/A (none) | `selected.finding.occurrences.length > 1` | Each button is labeled `#{occurrence.exchange_id} {occurrence.path}`; calls `focusExchange(occurrence.exchange_id)` and `setRoute("history")` |
| Advisory tab trigger | tab | N/A (none) | Always (when finding selected) | Switches tabs to "Advisory" content |
| Request tab trigger | tab | N/A (none) | Always (when finding selected) | Switches tabs to "Request" content |
| Response tab trigger | tab | N/A (none) | Always (when finding selected) | Switches tabs to "Response" content |
| Live audit switch (in modal) | switch | "Live active audit" | Modal is open | Toggles live audit via `setLive.mutate({ enabled: !data.enabled })`; `disabled` if `!data?.wired` |
| Coverage card (in modal) | card | N/A | Modal is open | Display-only section showing passive BCheck coverage; no interactive elements except within collapse state (if present) |
| Scan config select (in modal) | select | "Scan configuration" | Modal is open | Sets `configName` state; options populated from `configsQuery.data?.configs` |
| Exchange ID input (in modal) | input | "Exchange ID" | Modal is open | Sets `exchangeId` state; `type="number"`; placeholder "Exchange ID" |
| "Audit" button (in modal) | button | "Audit" or "Auditing…" (dynamic) | Modal is open; `disabled` if `!exchangeId || runAudit.isPending` | Calls `runOnExchange()` which runs audit via `runAudit.mutate()` |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|-------------|
| `useIssuesDetailed()` | Fetches findings list | Always | `issues` → findings data; `error` → error display; `isFetching` → loading state; `refetch()` → refresh button |
| `useScannerConfigs()` | Fetches available scanner configs | Always (modal lazy-loads) | `configsQuery.data?.configs` populates scan config select in audit modal |
| `useRunAudit()` | Mutation for running targeted audit | Always (modal uses) | `runAudit.mutate()` called by "Audit" button; `isPending` disables button and changes label |
| `useHistory("", 1000)` | Fetches HTTP history cache key "" with limit 1000 | Always | `history` → lookup for exchanges linked to findings |
| `useMessage(exchange?.request)` | Fetches full request message text | `exchange` exists | `request.data?.text` displayed in Request tab; `request.isFetching` shows "Loading request bytes…" |
| `useMessage(exchange?.response ?? null)` | Fetches full response message text | `exchange` exists | `response.data?.text` displayed in Response tab; `response.isFetching` shows "Loading response bytes…" |
| `useScannerLive()` | Fetches live audit status | Modal is open | `data` → live audit configuration display; `error` → error notice |
| `useSetScannerLive()` | Mutation to enable/disable live audit | Modal is open | `setLive.mutate()` called by live audit switch; toast feedback on success/error |
| `useScannerCoverage()` | Fetches passive BCheck coverage | Modal is open | `data` → coverage card display; `error` → error notice; `isFetching` → loading panel |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `severity` | `"all"` | Severity filter select `onChange` → `setSeverity(event.target.value)` | `rows` computed filter; badge display for counts |
| `confidence` | `"all"` | Confidence filter select `onChange` → `setConfidence(event.target.value)` | `rows` computed filter |
| `term` | `""` | Filter input `onChange` → `setTerm(event.target.value)`; debounced to `debouncedTerm` | `rows` computed filter |
| `selectedKey` | `null` | Finding leaf click → `setSelectedKey(leaf.key)` | `selected` computed lookup; finding detail display; tab content |
| `collapsed` | `{}` | Host/path toggle click → `setCollapsed(c => ({ ...c, [key]: !collapsed[key] }))` | Tree row `aria-expanded` and conditional rendering of children |
| `exchangeId` | `""` | Audit modal input `onChange` → `setExchangeId(event.target.value)` | "Audit" button `disabled={!exchangeId}` check; passed to `runAudit.mutate({ exchangeId: Number(exchangeId) })` |
| `configName` | `""` | Audit modal select `onChange` → `setConfigName(event.target.value)` | Passed to `runAudit.mutate({ config: configName \|\| undefined })`; displayed in audit result |
| `auditResult` | `null` | `runAudit.mutate()` `onSuccess` → `setAuditResult(result)` | Audit result card display; shows breakdown, outcome, dispositions as JsonView |
| `settingsOpen` | `false` | "Audit settings" button → `setSettingsOpen(true)`; Modal close → `setSettingsOpen(false)` | Modal `open={settingsOpen}` prop |

### Cross-page effects

| Trigger | Destination | Store/Router action |
|---------|-------------|-------------------|
| User clicks "In history" button on finding | Navigate to HTTP History tab with exchange focused | `focusExchange(selected.occurrence?.exchange_id)` then `setRoute("history")` |
| User clicks occurrence button in advisory | Navigate to HTTP History tab with that exchange focused | `focusExchange(occurrence.exchange_id)` then `setRoute("history")` for each occurrence |

### Action flows

**FLOW SCANNER-1: Find and select a finding**
1. User types in filter input → `setTerm(value)`
2. Debounce timer fires → `rows` computed value filters findings by severity, confidence, and text match
3. `groups` computed value rebuilds tree from filtered `rows`
4. Tree re-renders with matching findings highlighted
5. **Failure:** No matches → "No finding matches this filter" empty state

**FLOW SCANNER-2: Expand/collapse host in tree**
1. User clicks host toggle button
2. `setCollapsed(c => ({ ...c, [hostKey]: !hostOpen }))`
3. `hostOpen` boolean flips; conditionally renders `host.paths` if true
4. Path-level tree items appear/disappear with animation (CSS)

**FLOW SCANNER-3: Expand/collapse path in tree**
1. User clicks path toggle button (inside open host)
2. `setCollapsed(c => ({ ...c, [pathKey]: !pathOpen }))`
3. `pathOpen` boolean flips; conditionally renders path.leaves if true
4. Finding leaf items appear/disappear with animation

**FLOW SCANNER-4: Select and view finding detail**
1. User clicks finding leaf item
2. `setSelectedKey(leaf.key)`
3. `selected` computed value looks up leaf across all groups
4. `exchange` computed looks up linked exchange from history (if occurrence exists)
5. Advisory tab shows finding detail: check name, host, path, times seen, occurrences, detail prose, remediation prose
6. Request/Response tabs fetch and display message bytes via `useMessage` hooks
7. "In history" button becomes enabled if occurrence exists
8. **Failure case 1:** No occurrence → Request/Response tabs show "No request/response recorded" + "This finding was not tied to a captured exchange."
9. **Failure case 2:** Exchange outside last 1000 loaded → "Exchange not in the loaded history" + "Finding points at exchange #X, which is outside the last 1000 captured."

**FLOW SCANNER-5: Navigate to exchange from finding**
1. User clicks "In history" button or one of the occurrence buttons
2. Button `onClick` calls `focusExchange(exchangeId)` then `setRoute("history")`
3. Router navigates to history page; exchange is highlighted/focused in history table

**FLOW SCANNER-6: Open audit settings modal**
1. User clicks "Audit settings" button
2. `setSettingsOpen(true)`
3. Modal opens, revealing:
   - LiveAuditCard: live audit switch, swept/findings counts, status badges (gaps, covered, ledger resets)
   - CoverageCard: passive BCheck coverage table (check name, ran count, findings count, errored count, state)
   - Targeted audit section: config select, exchange ID input, "Audit" button
   - Audit result card (populated after running targeted audit)

**FLOW SCANNER-7: Toggle live active audit**
1. User clicks live audit switch (enabled if `data?.wired` true)
2. `switch` `onCheckedChange` → `toggle()` function
3. Calls `setLive.mutate({ enabled: !data.enabled })`
4. Server enables/disables live audit
5. On success: toast "completed"; `data` updates showing swept exchanges and findings count
6. On error: toast shows error message
7. **Failure:** If `!data?.wired`, toast shows "Live active audit is not wired up on this server"

**FLOW SCANNER-8: Run targeted audit**
1. User enters exchange ID in audit modal input
2. User selects scan configuration (optional, defaults to server default)
3. User clicks "Audit" button
4. `runOnExchange()` validates exchange ID is numeric
5. Calls `runAudit.mutate({ exchangeId: id, config: configName || undefined })`
6. Button shows "Auditing…" and becomes disabled
7. Server runs audit checks against exchange
8. On success: `setAuditResult(result)`; toast "Audit ran against #X" (or "Audit refused: [error]" if result.error set)
9. Audit result card renders showing:
   - Exchange ID and summary
   - Config name badge
   - Active checks count, unimplemented checks count, time budget, max requests
   - JsonView of breakdown, outcome, dispositions (if present)
10. On error: toast shows error; `auditResult` set to null

**FLOW SCANNER-9: Download audit report**
1. User clicks one of the report buttons (HTML, JSON, SARIF)
2. LinkButton `href={`/api/report/{format}`}` with `download` attribute
3. Browser downloads report file from server

**FLOW SCANNER-10: Refresh findings**
1. User clicks refresh button
2. `refetch()` called
3. Page re-fetches `/api/issues/detailed`
4. `data` updated; `groups` recomputes with new findings
5. LoadingPanel shown while `isFetching && !issues`

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| `isFetching && !issues` | `LoadingPanel` component | (No label shown; generic spinner) |
| `groups.length === 0 && (term || severity !== "all" || confidence !== "all")` | `Empty` component | Title: "No finding matches this filter"; Detail: `issues?.hint ?? "Captured and audited traffic has not produced findings."` |
| `groups.length === 0 && !filters active` | `Empty` component | Title: "No findings yet"; Detail: `issues?.hint ?? "Captured and audited traffic has not produced findings."` |
| `!selected` (no finding selected) | `Empty` component | Title: "Select a finding"; Detail: "Choose an issue in the tree to read its advisory and the exact request and response it was found in." |
| `selected.occurrence === null && (request or response tab)` | `Empty` component | Title: "No request recorded" or "No response recorded"; Detail: "This finding was not tied to a captured exchange." |
| `exchange === null && (request or response tab)` | `Empty` component | Title: "Exchange not in the loaded history"; Detail: "Finding points at exchange #X, which is outside the last 1000 captured." |
| `error` exists (top level) | `ErrorNotice` component | Error message from API; "Retry" button calls `refetch()` |
| `issues && !issues.enabled` | `div` with class "notice notice-warn" | Text: `issues.hint ?? "passive scanning is not enabled"` |
| `!data?.wired` in LiveAuditCard | `div` with class "notice notice-warn" | Text: `data.hint ?? "not available"` |
| `!data.enabled` in CoverageCard | `div` with class "notice notice-warn" | Text: `data.hint ?? "passive BCheck scanning is not enabled"` |

---

## Scope (`pages/scope.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|-------------|
| Scope rule kind select | select | "Scope rule kind" | Always | Sets `kind` state ("include" or "exclude"); rendered by ScopeSection |
| Host pattern input | input | "Scope host pattern" | Always | Sets `pattern` state; placeholder "api.example.com"; Enter key submits; rendered by ScopeSection |
| "Add rule" button | button | N/A (none) | `pattern.trim()` is non-empty AND `!update.isPending` | Calls `run({ action: kind, pattern: pattern.trim() }, ...)` and clears `pattern` input; rendered by ScopeSection |
| "Clear scope" button | button | N/A (none) | `data` exists AND `!data.empty` | Opens confirmation modal via `setConfirmClear(true)`; rendered by ScopeSection |
| Refresh button | icon-button | "Refresh" (inferred) | Always | Calls `refetch()` to reload scope rules; `loading={isFetching}`; rendered by ScopeSection |
| Remove rule button (per row in table) | icon-button | "Remove {Include\|Exclude} rule for {host\|any host}" (dynamic) | Row exists AND `rule.host !== null` AND `!update.isPending` | Calls `run({ action: "remove", kind: ..., pattern: rule.host }, ...)`; rendered by ScopeSection |
| Confirmation modal "Cancel" button | button | N/A (none) | Modal is open | Closes modal via `setConfirmClear(false)` |
| Confirmation modal "Clear scope" button | button | N/A (none) | Modal is open | Calls `run({ action: "clear" }, "Scope cleared")` then closes modal via `setConfirmClear(false)` |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|-------------|
| `useScopeView()` | Fetches `/api/scope` view (scope rules list) | Always | `data` → rules table; `error` → error display; `isFetching` → loading state; `refetch()` → refresh button |
| `useUpdateScope()` | Mutation for adding/removing/clearing scope rules | Always | `update.mutate()` called by "Add rule", remove, and "Clear scope" actions; `isPending` disables buttons |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `kind` | `"include"` | Scope rule kind select `onChange` → `setKind(event.target.value === "exclude" ? "exclude" : "include")` | Passed to `run({ action: kind, ... })` |
| `pattern` | `""` | Host pattern input `onChange` → `setPattern(event.target.value)`; input cleared after submit | Passed to `run({ action: ..., pattern: pattern.trim() })` |
| `confirmClear` | `false` | "Clear scope" button → `setConfirmClear(true)`; modal actions → `setConfirmClear(false)` | Modal `open={confirmClear}` prop |

### Cross-page effects

None — all state changes are local to this page. Scope changes persist to the server but do not navigate to other pages or modify the Zustand store.

### Action flows

**FLOW SCOPE-1: Add scope rule**
1. User selects rule kind (Include/Exclude) from dropdown
2. User enters host pattern in input (e.g., "api.example.com" or "*.example.com")
3. User either presses Enter key or clicks "Add rule" button
4. `run({ action: kind, pattern: pattern.trim() }, ...)` called
5. `update.mutate()` sends request to server
6. Button shows loading state (disabled, label may change based on `isPending`)
7. On success: toast "included api.example.com" or "excluded api.example.com"; `pattern` cleared; rules table re-fetches and updates
8. On error: toast shows error message
9. **Failure:** If pattern is empty or whitespace only → button disabled, no action occurs

**FLOW SCOPE-2: Remove scope rule**
1. User clicks trash icon button on rule row
2. Button is disabled if `rule.host === null` (wildcard rule cannot be removed)
3. `run({ action: "remove", kind: ..., pattern: rule.host }, ...)` called
4. Server removes this single rule
5. On success: toast "Removed {host}"; rules table re-fetches
6. On error: toast shows error message

**FLOW SCOPE-3: Clear all scope rules**
1. User clicks "Clear scope" button (disabled if no rules or `data.empty`)
2. Confirmation modal opens
3. User clicks "Clear scope" button in modal
4. `run({ action: "clear" }, "Scope cleared")` called
5. Server removes all rules
6. On success: toast "Scope cleared"; modal closes; rules table becomes empty
7. On error: toast shows error message; modal closes
8. User can click "Cancel" to dismiss modal without action

**FLOW SCOPE-4: Refresh scope rules**
1. User clicks refresh button
2. `refetch()` called
3. Page re-fetches `/api/scope` view
4. Rules table updates with latest data

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| `isLoading` | `LoadingPanel` component | Label: "Loading scope" |
| `data?.rules.length === 0` | `Empty` component | Title: "No scope rules"; Detail: "Every host is in scope. Add an include rule to bound what the proxy, scanner and crawler will touch." |
| `error` exists | `ErrorNotice` component | Error message from API; "Retry" button calls `refetch()` |
| `data?.allow_all === true` | Badge | Tone: "warn"; Text: "everything in scope" (shown in section heading actions) |
| `data?.allow_all === false` | Badge | Tone: "good"; Text: "restricted" (shown in section heading actions) |
| Always (notice) | `div` with class "notice" | Text: "A scope rule matches on a host pattern only — this build's scope API has no port, protocol or path arm, so those are not offered here. An empty scope means everything is in scope." |
| Confirmation modal | Modal with title and description | Title: "Clear every scope rule?"; Description: "With no rules left, every host is in scope again." |
