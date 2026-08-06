# Proxy tools — interaction map

## Intercept (`pages/intercept.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|-----------------|--------------|------------|
| Hold requests matching rules | checkbox | `label="Hold ${noun}s matching these rules"` | always | Toggles whether request interception is active; marks dirty when changed |
| Field count hint | text | describeRules() output | always | Shows status: "off — no requests/responses is held", "on with no conditions — every X is held", "on, but every condition is unchecked — no X is held", or "on with N condition(s)" |
| Add rule button | button | "Add rule" | always | Appends a new rule with defaults (host for requests, status_code for responses) to the rules list |
| Save rules button | button | "Save" (or "Saving…") | dirty=true, !save.isPending | POSTs rules to server; disables during mutation |
| Rule enabled checkbox (per row) | checkbox | "On" (line 180) | always | Toggles rule.enabled; marks dirty |
| Field select (per row) | select | `aria-label="Field for rule ${index + 1}"` | always | Selects from FIELDS array (host, path, extension, method, url, status_code, content_type); marks dirty |
| Match pattern input (per row) | input | `aria-label="Match pattern for rule ${index + 1}"` | always | Text field for rule.string_match pattern; marks dirty |
| Match kind select (per row) | select | `aria-label="Match kind for rule ${index + 1}"` | always | Selects regex or literal; marks dirty |
| Comment input (per row) | input | `aria-label="Comment for rule ${index + 1}"` | always | Text field for rule.comment; marks dirty |
| Delete rule button (per row) | icon-button | `label="Remove rule ${index + 1}"` | always | Filters out rule at index; marks dirty |
| Intercept on/off switch | switch | "Intercept is on" | data?.wired=true | Calls controls.setEnabled.mutate(!data.enabled); shows "wired" or "not wired" status |
| Status badge | badge | Shows "wired" or "not wired" | always | Read-only indicator of wiring status |
| Queue tab | tab | "Queue" | always | Switches to queue view (default); displays held messages table |
| Interception rules tab | tab | "Interception rules" | always | Switches to rules editor view with request and response rule editors side-by-side |
| Held messages table | table | `ariaLabel="Held messages"` | always | VirtualTable; selectable rows by id; columns: #, Dir, Method, Host, Path, Status, Held, Len; onSelect sets selectedId |
| Message detail view header | detail | HELD #{selected.id} | selected!==null | Shows message ID, direction, method, host:port, path |
| Clear selection icon-button | icon-button | "Clear selection" | selected!==null | Resets selectedId to null |
| HttpEditor (held bytes) | editor | "Held bytes" | selected!==null | Displays and edits raw message bytes; onChange sets raw state |
| Fix Content-Length checkbox | checkbox | "Fix Content-Length when forwarding" | selected!==null | Toggles fixContentLength flag |
| Forward button | button | "Forward" | selected!==null, !forwardHeld.isPending | Calls forwardHeld.mutate({id, raw, fixContentLength}); clears selection on success |
| Drop button | button | "Drop" | selected!==null, !controls.drop.isPending | Calls controls.drop.mutate(selected.id); clears selection on success |

### Keyboard shortcuts

| Keys | Scope | Condition | Action |
|------|-------|-----------|--------|
| Ctrl+F / Cmd+F | intercept page | selected message exists | Prevents browser Find; calls forward() |
| Alt+T | intercept page | always | Prevents default; calls toggle() |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| useInterceptDetailed() | GET /api/intercept | page mounted | Provides data, error, isFetching, refetch for held message queue and status |
| useInterceptRules(direction) | GET /api/intercept/rules/{direction} | RuleEditor mounted | Provides data (active, rules, wired), error, isFetching, refetch for one direction's rules |
| useSaveInterceptRules(direction) | POST /api/intercept/rules/{direction} | RuleEditor component exists | Mutation to save active flag and rules list |
| useForwardHeld() | POST /api/intercept/forward | forward() called | Mutation to send edited message and fix_content_length flag |
| useInterceptControls() | POST /api/intercept/enable, POST /api/intercept/drop | InterceptPage mounted | Provides setEnabled and drop mutations for toggle() and drop() handlers |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| selectedId | null | setSelectedId (onClick in table, after forward/drop, effect when data changes) | selected memo, useEffect for raw, forward/drop handlers, VirtualTable onSelect prop |
| raw | "" from selected?.raw | setRaw (useEffect on selectedId change, onChange in HttpEditor) | Forward button onClick, forwardHeld.mutate payload |
| fixContentLength | true | setFixContentLength (Checkbox onCheckedChange) | Forward button onClick, forwardHeld.mutate payload |
| active (RuleEditor) | false (then synced from data) | setActive (effect on data change, Checkbox onCheckedChange in toolbar) | onSave mutation payload, describeRules function |
| rules (RuleEditor) | [] (then synced from data) | setRules (effect on data change, update() calls via map handlers) | onSave mutation payload, rule table render, describeRules function |
| dirty (RuleEditor) | false | setDirty (effect on data change sets to false, update() sets to true) | Save button disabled state, toast message on success |

### Cross-page effects

None. InterceptPage does not call setRoute, setHistoryQuery, focusExchange, setIntruderSeed, setComparerSlot, or openRepeaterTab. It does not write to zustand store.

### Action flows

**FLOW INTERCEPT-1: Toggle interception on/off**
1. User clicks switch "Intercept is on"
2. toggle() called, checks data?.wired; if false, shows error toast
3. controls.setEnabled.mutate(!data.enabled) fired
4. Server updates intercept state
5. useInterceptDetailed refetch updates data.enabled
6. Switch reflects new state; metrics update; toast shows "Intercept is [on|off]"
7. Failure: toast.error with error message

**FLOW INTERCEPT-2: Add and save interception rule**
1. User clicks "Add rule" button in either requests or responses RuleEditor
2. New rule appended to rules list with direction-appropriate defaults
3. setDirty(true); user edits field, pattern, kind, comment
4. User clicks "Save" button
5. save.mutate({active, rules}) fired
6. Server compiles and persists rules
7. On success: setDirty(false), toast.success("Request/Response rules saved")
8. useInterceptRules refetch updates data
9. useEffect re-syncs active and rules from data (only while !dirty)
10. Failure: toast.error with message

**FLOW INTERCEPT-3: Edit and forward held message**
1. User clicks row in held messages table
2. setSelectedId(row.id); useEffect sets raw from selected?.raw
3. HttpEditor displays message bytes; user edits raw state
4. User clicks "Forward" or presses Ctrl+F
5. forward() called; checks selected exists
6. forwardHeld.mutate({id, raw, fixContentLength}) fired
7. Server validates, optionally fixes Content-Length, forwards to upstream
8. On success: setSelectedId(null), toast.success("Held message #X forwarded")
9. useInterceptDetailed refetch removes message from held list
10. Table clears selection; editor shows empty state
11. Failure: toast.error

**FLOW INTERCEPT-4: Drop held message**
1. User clicks "Drop" button on selected message
2. drop() called; checks selected exists
3. controls.drop.mutate(selected.id) fired
4. Server removes from queue
5. On success: setSelectedId(null), toast.success("Held message #X dropped")
6. useInterceptDetailed refetch
7. Table and detail view clear
8. Failure: toast.error

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| error in useInterceptDetailed | ErrorNotice component | (varies by error object) |
| data?.wired = false | warning banner | "Request/Response interception rules are not wired up." or "interception is not wired up" (from data.hint) |
| !data && isFetching | Loading card in RuleEditor | "Loading…" |
| held.length === 0 | Empty in VirtualTable | title: "Queue is clear", detail: "Requests will stop here when a rule matches." (if enabled) or "Enable interception to hold matching traffic." (if disabled) |
| rules.length === 0 in rule table | Single row with colspan | "no rules — every request/response is held while this list is on" (cell-dim class) |
| selected === null | Empty detail pane | title: "Nothing selected", detail: "Select a held message to view and edit its exact bytes before forwarding or dropping it." |

---

## History (`pages/history.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|-----------------|--------------|------------|
| Filter input | input | `aria-label="Filter history"` | always | Text field for query DSL; onChange updates term, triggers debounced useHistory refetch |
| Clear filter button | icon-button | "Clear filter" | term !== "" | Clears filter input |
| Filter syntax tooltip trigger | button | `aria-label="Filter syntax"`, type="button" | always | Opens QueryHelp modal |
| Status filter select | select | `aria-label="Status filter"` | always | Selects from STATUS_BUCKETS (all, 2, 3, 4, 5, none); onChange updates status filter |
| Method filter select | select | `aria-label="Method filter"` | always | Selects GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, or "all"; onChange updates method filter |
| Row limit select | select | `aria-label="Row limit"` | always | Selects 200, 500, 1000, or 5000; onChange updates limit |
| Refresh button | icon-button | (in RefreshButton component) | always | Calls refetch() on useHistory query |
| Exchanges table | table | `ariaLabel="Captured HTTP exchanges"` | always | VirtualTable; selectable by id; columns: #, Method, Host, Path, Status, Type, Length, Time, Age; onSelect sets selectedId; onActivate calls sendToRepeater |
| Repeater button | button | "Repeater" | selected !== null | Calls actions.sendToRepeater(selected) |
| Intruder button | button | "Intruder" | selected !== null | Calls actions.sendToIntruder(selected) |
| Compare button | button | "Compare" | selected !== null | Calls actions.sendToComparer(selected, "a") |
| Inspector toggle | icon-button | `label={inspector ? "Hide Inspector" : "Show Inspector"}`, `aria-pressed={inspector}` | selected !== null | Toggles inspector boolean |
| Clear selection button | icon-button | "Clear selection" | selected !== null | Calls setSelectedId(null) |
| Request editor | editor | "Request" | selected !== null | HttpEditor (readOnly); shows request.data?.text, "Loading request bytes…", or "No request bytes captured." |
| Response editor | editor | "Response" | selected !== null | HttpEditor (readOnly); shows response.data?.text, "Loading response bytes…", or "No response bytes captured." (if no response, "No response was captured for this exchange.") |
| Inspector panel | panel | "Inspector · request" | selected !== null && inspector=true | Shows parsed structure of request |
| QueryHelp modal | dialog | "Filter syntax" | helpOpen=true | Displays filter expression examples and field reference |

### Keyboard shortcuts

| Keys | Scope | Condition | Action |
|------|-------|-----------|--------|
| Ctrl+R / Cmd+R | history page | selected exchange exists | Prevents browser reload; calls actions.sendToRepeater(selected) |
| Ctrl+I / Cmd+I | history page | selected exchange exists | Prevents default; calls actions.sendToIntruder(selected) |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| useHistory(debouncedTerm, limit) | GET /api/history?q={debouncedTerm}&limit={limit} | page mounted, debouncedTerm or limit changes | Provides data (array of Exchange), error, isFetching, refetch |
| useMessage(selected?.request) | GET /api/messages/{id} | selected !== null | Provides request.data?.text, request.isFetching for HttpEditor label |
| useMessage(selected?.response) | GET /api/messages/{id} | selected !== null && selected.response !== null | Provides response.data?.text, response.isFetching for HttpEditor label |
| useExchangeActions() | (menu context, sendToRepeater/Intruder/Comparer actions) | page mounted | Provides actions.menu(), actions.sendToRepeater(), actions.sendToIntruder(), actions.sendToComparer(), actions.onActivate |
| useDebounced(term, 260) | client-side | page mounted | Provides debouncedTerm to useHistory query |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| term | historyQuery (from zustand) | setTerm (onChange on filter input), effect on historyQuery change | useHistory call, filter input value, "Clear filter" button visible condition |
| status | "all" | setStatus (onChange on status select) | rows memo filter, status select value |
| method | "all" | setMethod (onChange on method select) | rows memo filter, method select value |
| selectedId | null | setSelectedId (table onSelect, effect on historyFocus, manually cleared) | selected memo, table selectedId prop, detail view rendering |
| helpOpen | false | setHelpOpen (modal onOpenChange) | QueryHelp open prop |
| limit | 500 | setLimit (onChange on limit select) | useHistory call, limit select value |
| inspector | true | setInspector (toggle button onClick) | Inspector panel render condition, button aria-pressed and label |

### Cross-page effects

| Trigger | Destination | Code | Effect |
|---------|-------------|------|--------|
| Another page sets historyQuery | local term state | effect lines 70-74 | setTerm(historyQuery), setHistoryQuery("") clears store |
| Another page sets historyFocus | local selectedId state | effect lines 77-81 | setSelectedId(historyFocus), focusExchange(null) clears store |
| actions.sendToRepeater called | zustand store (via useExchangeActions) | line 104 | Sets route and exchange state to show repeater page |
| actions.sendToIntruder called | zustand store (via useExchangeActions) | line 114 | Sets route and prepares intruder state |
| actions.sendToComparer called | zustand store (via useExchangeActions) | line 203 | Sets route and comparer slot state |

### Action flows

**FLOW HISTORY-1: Filter exchanges by query expression**
1. User types in filter input
2. onChange updates term state
3. setTerm triggers debouncedTerm update after 260ms
4. debouncedTerm change triggers useHistory refetch with new query
5. Rows memo refilters by method and status on top of query results
6. Table updates with matching exchanges
7. selectedId persists if row still matches; else selection clears (memo dependency)

**FLOW HISTORY-2: Select exchange and view details**
1. User clicks row in exchanges table
2. onSelect sets selectedId
3. useMessage(selected?.request) and useMessage(selected?.response) refetch if needed
4. HttpEditor components show request and response bytes (or "Loading…")
5. Inspector shows parsed request structure
6. Detail header shows method, URL, status, badges, action buttons

**FLOW HISTORY-3: Send selected exchange to Repeater**
1. User clicks "Repeater" button or presses Ctrl+R
2. actions.sendToRepeater(selected) called
3. Zustand store updates (setRoute, internal repeater state)
4. UI navigates to repeater page with exchange loaded
5. Note: implemented in useExchangeActions (not visible in this file)

**FLOW HISTORY-4: Send selected exchange to Intruder**
1. User clicks "Intruder" button or presses Ctrl+I
2. actions.sendToIntruder(selected) called
3. Zustand store updates (setRoute, intruder seed state)
4. UI navigates to intruder page
5. Note: implemented in useExchangeActions

**FLOW HISTORY-5: Send selected exchange to Comparer**
1. User clicks "Compare" button
2. actions.sendToComparer(selected, "a") called (slot "a")
3. Zustand store updates (setRoute, comparer state for slot a)
4. UI navigates to comparer page
5. Note: implemented in useExchangeActions

**FLOW HISTORY-6: Focus exchange from another page**
1. Another page calls focusExchange(exchange_id)
2. useApp state updates historyFocus
3. HistoryPage effect (lines 77-81) detects change
4. setSelectedId(historyFocus), focusExchange(null)
5. Table scrolls/highlights row; detail view shows exchange
6. Note: historyFocus is one-time use; cleared after reading

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| error from useHistory | ErrorNotice component | (varies by error) |
| isFetching && !data | VirtualTable loading prop | (sets visual loading state) |
| rows.length === 0 && term !== "" | Empty | title: "No exchange matches this filter", detail: "Relax the filter, or clear it to see the whole capture." |
| rows.length === 0 && term === "" | Empty | title: "No traffic captured yet", detail: "Point a client at the proxy and install the CA certificate to start capturing HTTPS." |
| selected === null | Empty detail pane | title: "No exchange selected", detail: "Choose a row to read its exact request and response bytes. Arrow keys move through the table; right-click a row for send-to actions." |
| request.isFetching && !request.data | HttpEditor label "Request" | value: "Loading request bytes…" |
| !request.data && !request.isFetching | HttpEditor label "Request" | value: "No request bytes captured." |
| response === null | HttpEditor label "Response" | value: "No response was captured for this exchange." |
| response.isFetching && !response.data | HttpEditor label "Response" | value: "Loading response bytes…" |
| !response.data && !response.isFetching | HttpEditor label "Response" | value: "No response bytes captured." |

---

## WebSocket Traffic (`pages/wshistory.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|-----------------|--------------|------------|
| Connection row | button | (implicit from conn text) | always | list-row button; onClick calls onSelect() to set selectedExchange; shows host:port path, message counts, relative time |
| Context menu on connection row | context-menu | (from menuFor function) | always | Right-click menu with actions based on exchangeDetail state: sendToRepeater, sendToIntruder, sendToComparer, or id-only copy/show options |
| WebSocket frames table | table | `ariaLabel="WebSocket frames"` | selectedExchange !== null | VirtualTable; selectable rows by id; columns: #, Dir, Opcode, Length (with truncation badge), Age |
| Frame detail header | detail | #{selectedFrame.id} | selectedFrame !== null | Shows eyebrow "#", opcode, length badge, clear button |
| Clear frame selection | icon-button | "Clear selection" | selectedFrame !== null | Calls setSelectedFrameId(null) |
| Payload view (text/hex editor) | editor | "Text payload" or "Hex payload" | selectedFrame !== null && !message.close | HttpEditor (readOnly); shows message.text or message.hex |
| Payload view (close frame) | detail-list | (close code and reason) | selectedFrame !== null && message.close=true | DetailList showing close.code badge and close.reason |
| Truncation warning | notice | (warning tone) | selectedFrame !== null && message.truncated=true | "N byte(s) were dropped from this frame; showing only what was kept." |
| Refresh button | icon-button | (in RefreshButton) | always | Calls connections.refetch() |

### Keyboard shortcuts

None visible in this file.

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| useWsConnections() | GET /api/ws/connections | page mounted | Provides data (array of WsConnection), error, isFetching, refetch |
| useWsHistory(selectedExchange) | GET /api/ws/frames?exchange={selectedExchange} | selectedExchange !== null | Provides data.rows (array of WsRow), error, isFetching, refetch |
| useWsMessageDetailed(selectedFrameId) | GET /api/ws/message/{selectedFrameId} | selectedFrameId !== null | Provides data (WsMessageDetail), isFetching |
| useExchange(selectedExchange) | GET /api/exchange/{selectedExchange} | selectedExchange !== null | Provides data (full Exchange), used for menu construction when available |
| useExchangeActions() | (menu context) | page mounted | Provides actions.menu() for context menu generation |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| selectedExchange | null | setSelectedExchange (connection row onClick, sets to conn.exchange) | useWsHistory call, selectedConn memo, menuFor function, connection row "active" class |
| selectedFrameId | null | setSelectedFrameId (table onSelect, effect when selectedExchange changes, manual clear) | useWsMessageDetailed call, selectedFrame memo, frame detail view rendering |

### Cross-page effects

| Trigger | Destination | Code | Effect |
|---------|-------------|------|--------|
| focusExchange called in menuFor | zustand setRoute | line 184 | Sets route to "history"; also calls focusExchange(conn.exchange) to highlight exchange in history page |
| actions.menu called | context menu items | line 168 | Generates full menu if exchangeDetail.data available (sendToRepeater, sendToIntruder, sendToComparer), else minimal id-only menu |

### Action flows

**FLOW WSHISTORY-1: Select WebSocket connection**
1. User clicks a connection row
2. onClick calls onSelect() → setSelectedExchange(conn.exchange)
3. setSelectedFrameId(null) (clears any frame selection)
4. useWsHistory(selectedExchange) refetch fires
5. Frame table populates with rows from that connection
6. Connection row highlights with "active" class

**FLOW WSHISTORY-2: View frame payload**
1. User clicks frame in table
2. onSelect sets selectedFrameId
3. useWsMessageDetailed(selectedFrameId) refetch fires
4. PayloadView component receives frame.data
5. If message.close: shows DetailList with close code and reason
6. Else if message.truncated: shows warning + editor with truncated bytes
7. Else: shows editor with full text or hex payload
8. Detail header shows frame ID, opcode, length

**FLOW WSHISTORY-3: Show connection in HTTP history**
1. User right-clicks connection row
2. "Show this exchange in HTTP history" menu item clicked (line 180-186)
3. focusExchange(conn.exchange) called
4. setRoute("history") called
5. UI navigates to history page
6. History page effect detects historyFocus set, highlights that exchange

**FLOW WSHISTORY-4: Send WebSocket connection to Repeater/Intruder/Comparer**
1. User right-clicks connection where exchangeDetail.data available (after selection + load)
2. Full menu generated by actions.menu(exchangeDetail.data)
3. User selects sendToRepeater/Intruder/Comparer menu item
4. Zustand store updated via useExchangeActions
5. UI navigates to target page

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| conns.length === 0 | Empty in connectionsList | title: "No upgrades observed", detail: "WebSocket connections appear here once a client upgrades through the proxy." |
| selectedExchange === null && history.isFetching | VirtualTable loading prop set | (visual loading state) |
| selectedExchange === null | Empty in frame table | title: "No WebSocket traffic captured yet", detail: "Point a client at the proxy and upgrade a connection to start capturing frames." |
| selectedExchange !== null && rows.length === 0 | Empty in frame table | title: "No frames on this connection", detail: "Select another connection, or clear the selection to see every frame." |
| frame.isFetching && !frame.data | Empty in detail panel | title: "Loading payload…", detail: "Fetching the frame's bytes." |
| selectedFrameId === null | Empty in detail panel | title: "No frame selected", detail: "Pick a row from the frame table to inspect its payload." |
| connections.error | ErrorNotice | (varies by error) |
| history.error | ErrorNotice | (varies by error) |

---

## Match / Replace (`pages/matchreplace.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|-----------------|--------------|------------|
| Revert button | button | "Revert" | dirty=true | Calls onRevert(); setDraft(JSON.parse(baseline)); toast.success("Reverted to the saved rule set") |
| Save rules button | button | "Save rules" (or "Saving…") | dirty=true && !save.isPending | Calls onSave(); POSTs rules and update_content_length to server |
| Refresh button | icon-button | (RefreshButton) | always | Calls refetch() on useMatchReplace query |
| Add rule button | button | "Add rule" | always | Calls addRule(); appends new rule with defaults (direction-appropriate target, empty strings, literal) |
| Update Content-Length switch | switch | `id="mr-ucl"`, "Update Content-Length after a body rewrite" | always | Toggles draft.update_content_length |
| Enabled count badge | badge | "N of M enabled" | always | Read-only; shows count of enabled rules |
| Saved affects badges | badge x2 | "saved · requests yes/no", "saved · responses yes/no" | always | Read-only; shows which directions the saved rule set touches |
| Draft affects badge | badge | "draft · requests yes/no / responses yes/no" | dirty=true | Conditional; shows what the unsaved draft touches |
| Rule enabled checkbox (per row) | checkbox | (input type="checkbox", sr-only "Rule N enabled") | always | Toggles rule.enabled; calls patch(index, {enabled}) |
| Rule target select (per row) | select | `aria-label="Rule ${index + 1} target"` | always | Selects from TARGETS (request_first_line, request_header, request_body, response_header, response_body); calls patch |
| Rule match kind select (per row) | select | `aria-label="Rule ${index + 1} match kind"` | always | Selects literal or regex; calls patch |
| Rule match input (per row) | input | `aria-label="Rule ${index + 1} match"` | always | Text field for string_match; placeholder "empty = add this header"; calls patch |
| Rule replace input (per row) | input | `aria-label="Rule ${index + 1} replacement"` | always | Text field for string_replace; placeholder "empty = delete the match"; calls patch |
| Rule comment input (per row) | input | `aria-label="Rule ${index + 1} comment"` | always | Text field for comment; placeholder "why this rule exists"; calls patch |
| Move rule up button (per row) | icon-button | `label="Move rule ${index + 1} up"` | index > 0 | Calls move(index, -1); reorders rules list |
| Move rule down button (per row) | icon-button | `label="Move rule ${index + 1} down"` | index < rules.length - 1 | Calls move(index, 1); reorders rules list |
| Duplicate rule button (per row) | icon-button | `label="Duplicate rule ${index + 1}"` | always | Inserts copy of rule at index+1 |
| Delete rule button (per row) | icon-button | `label="Delete rule ${index + 1}"` | always | Calls setConfirmDelete(index); opens confirmation modal |
| Test direction select | select | `aria-label="Test direction"` | always | Selects request or response; onChange updates direction, clears output |
| Test draft button | button | "Test draft" (or "Testing…") | sample !== "" && !test.isPending | Calls runTest(); POSTs draft.rules, direction, sample to server |
| Sample input editor | editor | "Sample input" | always | HttpEditor (editable); onChange updates sample, clears output; placeholder SAMPLE_PLACEHOLDER |
| Output editor | editor | "Transformed output" | always | HttpEditor (readOnly); shows output.text or default message; updated by test result |
| Test changed badge | badge | "changed" or "no change" | output !== null | Conditional; shows whether test modified the input |
| Delete confirmation modal | dialog | "Delete this rule?" | confirmDelete !== null | Shows "Keep it" and "Delete rule" buttons |
| Keep it button | button | "Keep it" | confirmDelete !== null | Calls setConfirmDelete(null); closes modal |
| Delete rule modal button | button | "Delete rule" | confirmDelete !== null | Filters rule at confirmDelete index, clears confirmDelete |
| Wired rules warning | notice | (warning tone) | rules.some(r => r.scope || r.query !== undefined) | "A rule carries a scope or query condition. This build's rule endpoint does not persist either, so saving from here drops it." |

### Keyboard shortcuts

None visible in this file.

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| useMatchReplace() | GET /api/matchreplace | page mounted | Provides data (config.rules, config.update_content_length, affects_requests, affects_responses), error, isFetching, refetch |
| useSaveMatchReplace() | POST /api/matchreplace | onSave() called | Mutation to save rules and update_content_length |
| useTestMatchReplace() | POST /api/matchreplace/test | runTest() called | Mutation to test draft rules against sample input |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| draft | null | setDraft (effect syncs from data, onRevert, manual edits via patch/replaceRules/move) | rules memo, dirty check, onSave payload, test payload, patch/replaceRules/move functions, affects memo |
| baseline | "" | setBaseline (effect from data, onSave success) | dirty comparison (JSON.stringify(draft) !== baseline), onRevert source |
| confirmDelete | null | setConfirmDelete (delete button onClick, modal onOpenChange) | Modal open condition, delete confirmation button |
| direction | "request" | setDirection (test select onChange, runTest onSuccess) | runTest payload, test direction select value |
| sample | "" | setSample (sample editor onChange, runTest onSuccess clears it? no, stays) | runTest payload, test button disabled condition, sample editor value |
| output | null | setOutput (runTest onSuccess sets {text, changed}, runTest onError/sample change clears) | output editor value, test changed badge |

### Cross-page effects

None visible. MatchReplacePage does not call setRoute, setHistoryQuery, focusExchange, setIntruderSeed, setComparerSlot, or openRepeaterTab. It does not write to zustand store.

### Action flows

**FLOW MATCHREPLACE-1: Edit and save rules**
1. User edits rule fields (enabled, target, match, replace, comment) via inline inputs/selects
2. Each onChange calls patch(index, changes) → setDraft
3. setDraft updates draft state; no immediate server effect
4. dirty = true (JSON.stringify(draft) !== baseline)
5. Affected badges update to show what draft touches
6. User clicks "Save rules" button
7. onSave() fires: save.mutate({rules: draft.rules, update_content_length})
8. Server validates, compiles, persists rules
9. On success: setBaseline(JSON.stringify(draft)), setDraft resets, dirty = false, toast.success("Saved N rule(s)")
10. useMatchReplace refetch syncs data
11. On error: toast.error with message

**FLOW MATCHREPLACE-2: Add rule**
1. User clicks "Add rule" button
2. addRule() appends rule to draft.rules with defaults based on current direction
3. Defaults: target = "request_header" or "response_header", enabled = true, empty strings, category = "literal", comment = ""
4. Table re-renders with new row; move/duplicate/delete buttons appear
5. dirty = true
6. User edits new rule fields

**FLOW MATCHREPLACE-3: Reorder rule**
1. User clicks "Move rule up" or "Move rule down" button
2. move(index, delta) called
3. Splices rule out at index, inserts at index+delta
4. replaceRules(next) updates draft
5. dirty = true
6. Table re-renders with new order; buttons disabled appropriately (first row no up, last row no down)

**FLOW MATCHREPLACE-4: Duplicate rule**
1. User clicks "Duplicate rule" button on row
2. Inserts copy (spread) of rule at index+1
3. replaceRules(next) updates draft
4. dirty = true
5. Table re-renders with duplicate visible

**FLOW MATCHREPLACE-5: Delete rule**
1. User clicks "Delete rule" button
2. setConfirmDelete(index) opens modal
3. Modal shows "Keep it" and "Delete rule" buttons
4. User clicks "Delete rule"
5. replaceRules(rules.filter((_, i) => i !== confirmDelete))
6. setConfirmDelete(null) closes modal
7. dirty = true
8. Table re-renders without deleted row

**FLOW MATCHREPLACE-6: Test draft rules**
1. User enters sample input (request or response bytes) in sample editor
2. User selects direction (request or response) from select
3. User clicks "Test draft" button
4. runTest() fires: test.mutate({input: sample, direction, draft_rules: draft.rules})
5. Server receives draft rules; compiles as one-time rule set; applies to sample input
6. On success: setOutput({text: result.output.text, changed: result.changed})
7. Output editor shows result; badge shows "changed" or "no change"
8. Saved rules and live traffic unchanged (throwaway execution)
9. On error: setOutput(null), toast.error with message

**FLOW MATCHREPLACE-7: Revert unsaved changes**
1. User clicks "Revert" button (only enabled when dirty=true)
2. onRevert() fires: setDraft(JSON.parse(baseline))
3. draft reverts to last saved state
4. dirty = false
5. Table and badges update
6. toast.success("Reverted to the saved rule set")

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| error from useMatchReplace | page with ErrorNotice | (varies by error) |
| !draft (initial load) | LoadingPanel | label: "Loading rule set" |
| rules.length === 0 | Empty | title: "No rules", detail: "Add a rule to rewrite a header, a request line, or a body on the way through the proxy.", action button "Add rule" |
| test.isPending | test button label | "Testing…" |
| save.isPending | save button label | "Saving…" |
| !sample | test button disabled | (disabled state) |
| output === null (before test) | output editor value | "Run the test to see what the draft rules would produce." |
