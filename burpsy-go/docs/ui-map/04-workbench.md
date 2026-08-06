# Workbench tools — interaction map

## Decoder (`pages/decoder.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|------------|
| Text view button | button | "Text" | Always | Switches output view to text mode, sets `view` to "text" |
| Hex view button | button | "Hex" | Always | Switches output view to hex mode, sets `view` to "hex" |
| Run pipeline button | button | "Run pipeline" / "Running…" | `input !== ""` AND `steps.length > 0` AND NOT `pipeline.isPending` | Executes the transformation pipeline via `pipeline.mutate()` |
| Decode step button | button | "Decode" | Always | Adds a new decode step via `addStep("decode")` |
| Encode step button | button | "Encode" | Always | Adds a new encode step via `addStep("encode")` |
| Hash step button | button | "Hash" | Always | Adds a new hash step via `addStep("hash")` |
| Step operation select | select | `Step ${index + 1} operation` | Always; mapped for each step in `steps.map()` | Changes `step.kind` to selected value; resets `step.value` to default for that kind |
| Step value/encoding select | select | `Step ${index + 1} ${step.kind === "hash" ? "algorithm" : "encoding"}` | Always; mapped for each step | Changes `step.value` to selected encoding/algorithm |
| Guess checkbox | checkbox | "guess base64 / hex alphabets" | When `step.kind === "decode"` AND `step.value === "auto"` | Toggles `step.guess` boolean |
| Move step up icon-button | icon-button | `Move step ${index + 1} earlier` | `index !== 0` | Calls `moveStep(index, -1)` |
| Move step down icon-button | icon-button | `Move step ${index + 1} later` | `index !== total - 1` | Calls `moveStep(index, 1)` |
| Remove step icon-button | icon-button | `Remove step ${index + 1}` | Always | Calls `removeStep(step.id)` |
| Copy result icon-button | icon-button | `Copy step ${index + 1} output` | Within each `ResultCard`, mapped for each result | Copies `result.output` to clipboard via `copyToClipboard()` |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| `useTransformPipeline()` | POST `/api/decoder/transform-pipeline` | Always | Stores pipeline results in `pipeline.data`, error in `pipeline.error`, pending state |
| Input bytes calculation | `useMemo()` on `input` | Always | Displays byte count in header badge |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `input` | `""` | `setInput()` from HttpEditor `onChange` | HttpEditor value, pipeline execution payload, byte count memo |
| `steps` | `[newTransformStep("decode", "auto")]` | `setSteps()` via `addStep()`, `patchStep()`, `moveStep()`, `removeStep()` | Render loop mapping steps, pipeline execution payload, validation checks |
| `view` | `"text"` | `setView("text")` or `setView("hex")` | ResultCard display mode, button styling |

### Cross-page effects

None identified. No calls to `setRoute`, `setHistoryQuery`, `focusExchange`, `setIntruderSeed`, `setComparerSlot`, or `openRepeaterTab`. No zustand writes to cross-page state.

### Action flows

**FLOW DECODER-1: Execute transformation pipeline**
1. User clicks "Run pipeline" button
2. `execute()` called → `pipeline.mutate({ input, steps }, { onSuccess, onError })`
3. Network call POSTs to transform handler
4. On success: Toast displays `"${result.results.length} step(s) ran"` or error message with failed step index; `pipeline.data` updated with results
5. On error: Toast displays `"Pipeline could not run: ${cause.message}"`
6. ResultCard components render with each step's output

**FLOW DECODER-2: Add and modify a step**
1. User clicks "Decode" / "Encode" / "Hash" button
2. `addStep(kind)` appends new `TransformStep` to `steps` array
3. User changes operation via step select → `patchStep()` updates `step.kind` and resets `step.value`
4. User changes encoding via second select → `patchStep()` updates `step.value`
5. If decode with auto: user toggles "guess" checkbox → `patchStep()` sets `step.guess`
6. Steps re-render with new values; no network call until user clicks "Run pipeline"

**FLOW DECODER-3: Reorder steps**
1. User clicks move-up / move-down icon on step
2. `moveStep(index, delta)` swaps step at `index` with step at `index + delta`
3. `steps` array updated; StepRow components re-render in new order

**FLOW DECODER-4: Copy result output**
1. User clicks copy icon on a ResultCard
2. `copyToClipboard(result.output)` invoked
3. Toast shows `"Step ${index + 1} output copied"`

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| No steps added | `<Empty title="No steps" detail="Add a decode, encode or hash step to build a chain." />` | "No steps" / "Add a decode, encode or hash step to build a chain." |
| Pipeline never executed | `<Empty title="Nothing run yet" detail="Paste an input, arrange the steps, then run the pipeline to see each layer come off in turn." />` | "Nothing run yet" / "Paste an input, arrange the steps, then run the pipeline to see each layer come off in turn." |
| First step failed (no output) | `<Empty title="No output" detail="The first step failed, so nothing was produced." />` | "No output" / "The first step failed, so nothing was produced." |
| Hash in chain not at end | `<div className="notice notice-warn">A hash is one-way: step {hashIndex + 1} onwards operates on the hex digest, not on the original bytes.</div>` | "A hash is one-way: step {hashIndex + 1} onwards operates on the hex digest, not on the original bytes." |
| Step failed mid-pipeline | `<div className="notice notice-warn">Step {run.failedAt + 1} failed and the chain stopped there: {run.message ?? "no detail was returned"}. The steps below are the ones that did run.</div>` | "Step {failedAt + 1} failed and the chain stopped there: {message}. The steps below are the ones that did run." |
| Smart decode found nothing | `<div className="notice notice-warn">Nothing was detected: no layer decoded cleanly, so this step passed the input through unchanged.</div>` | "Nothing was detected: no layer decoded cleanly, so this step passed the input through unchanged." |
| Partial decompression | `<div className="notice notice-warn">This stream only partly decompressed, so the output below is a prefix of the plaintext, not all of it. A search that finds nothing here has not ruled the string out.</div>` | "This stream only partly decompressed, so the output below is a prefix of the plaintext, not all of it. A search that finds nothing here has not ruled the string out." |
| Non-UTF-8 output in hex view | `<div className="notice notice-warn">The server sends a lossy text rendering, not raw bytes, so this dump is of the replacement characters that reached the browser — {bytes.length} B here against {result.len} B decoded.</div>` | "The server sends a lossy text rendering, not raw bytes, so this dump is of the replacement characters that reached the browser — {bytes.length} B here against {result.len} B decoded." |
| Output empty after successful step | `(empty output)` (rendered in prose div) | "(empty output)" |
| Hex dump at max cap | `… {bytes.length - shown.length} more bytes not dumped; switch back to text for the whole output` (appended to hex dump) | "… {count} more bytes not dumped; switch back to text for the whole output" |

---

## Comparer (`pages/comparer.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|------------|
| Swap button | button | "Swap" | `a !== ""` OR `b !== ""` | Swaps contents of slots A and B via `swap()` |
| Compare button | button | "Compare" / "Comparing…" | NOT (`a === ""` AND `b === ""`) AND NOT `compare.isPending` | Executes comparison via `compare.mutate()` |
| Load slot A input | input | `Stored message id for slot A` | Always | Text input for message ID; user types numeric ID |
| Load slot B input | input | `Stored message id for slot B` | Always | Text input for message ID; user types numeric ID |
| Load slot A button | button | "Load" | NOT `loadMessage.isPending` | Calls `loadSlot("a")` → loads message by ID into slot A |
| Load slot B button | button | "Load" | NOT `loadMessage.isPending` | Calls `loadSlot("b")` → loads message by ID into slot B |
| Previous hunk button | button | "Previous" | `hunks > 0` | Calls `jump(-1)` → moves to previous diff hunk |
| Next hunk button | button | "Next" | `hunks > 0` | Calls `jump(1)` → moves to next diff hunk |
| HttpEditor A | textarea | `Side A` | Always | User pastes text into side A via `setA()` |
| HttpEditor B | textarea | `Side B` | Always | User pastes text into side B via `setB()` |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| `useCompare()` | POST `/api/compare` | Always | Stores comparison result in `compare.data`, error, pending state |
| `useLoadMessage()` | GET `/api/messages/{id}` | When "Load" button clicked | Fetches message text by ID, writes to slot A or B |
| `slots.a` and `slots.b` | `useApp(state => state.comparerSlots)` | On mount and when slots update | Consumed via `useEffect` hooks to pre-fill sides A/B |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `a` | `""` | `setA()` from HttpEditor OR `useEffect` consuming `slots.a` | Compare payload, display, byte calculation, segment building |
| `b` | `""` | `setB()` from HttpEditor OR `useEffect` consuming `slots.b` | Compare payload, display, byte calculation, segment building |
| `msgA` | `""` | `setMsgA()` from Load input | Load input field value |
| `msgB` | `""` | `setMsgB()` from Load input | Load input field value |
| `currentHunk` | `-1` | `setCurrentHunk()` via `jump()` or reset in `run()`/`swap()` | Pane rendering (highlights current hunk), hunk display text |
| `paneRef` | `useRef<HTMLDivElement>` | Ref attachment to diff panes container | Scroll to selected hunk via `querySelector` |

### Cross-page effects

| Effect | Trigger | Destination |
|--------|---------|-------------|
| `setComparerSlot("a", "")` | `useEffect` when `slots.a` changes | Zustand store; clears slot A after consuming it |
| `setComparerSlot("b", "")` | `useEffect` when `slots.b` changes | Zustand store; clears slot B after consuming it |

### Action flows

**FLOW COMPARER-1: Load message into slot**
1. User enters numeric message ID in "Stored message id for slot A/B" input
2. User clicks "Load" button
3. `loadSlot(slot)` parses ID, validates it's a positive integer
4. `loadMessage.mutate(id, { onSuccess, onError })`
5. On success: `setA()` or `setB()` updates corresponding side; toast shows `"Message ${id} loaded into slot ${slot.toUpperCase()}"`
6. On error: toast shows `"Could not load message ${id}: ${cause.message}"`

**FLOW COMPARER-2: Compare two sides**
1. User clicks "Compare" button
2. `run()` called → `compare.mutate({ a, b }, { onSuccess, onError })`
3. `setCurrentHunk(-1)` resets focus
4. Network call POSTs to comparison handler
5. On success: Toast shows either `"The two inputs are byte-for-byte identical"` OR `"${diffCount} difference(s) found"`
6. On error: toast shows `"Comparison failed: ${cause.message}"`
7. `compare.data` populated; Pane components render with segments

**FLOW COMPARER-3: Swap sides**
1. User clicks "Swap" button
2. `swap()` called → swaps `a` ↔ `b`, resets `currentHunk` to `-1`, clears result via `compare.reset()`
3. Panes re-render with swapped content

**FLOW COMPARER-4: Navigate hunks**
1. User clicks "Previous" or "Next" button
2. `jump(delta)` calculates next hunk index: `(currentHunk + delta + hunks) % hunks`
3. `setCurrentHunk(next)` updates state
4. CSS class `.diff-hunk-current` highlights matching segment
5. `paneRef.current?.querySelector([data-hunk="${next}"])?.scrollIntoView(...)` auto-scrolls to hunk

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| No comparison run yet | `<Empty title="Nothing compared yet" detail="Paste both sides, load them by stored message id, or use "Send to Comparer" from HTTP history, then compare." />` | "Nothing compared yet" / "Paste both sides, load them by stored message id, or use "Send to Comparer" from HTTP history, then compare." |
| Sides are identical | `<Empty title="No differences" detail="Every byte matches, so there is no diff to draw." />` | "No differences" / "Every byte matches, so there is no diff to draw." |
| Comparison truncated or ops omitted | `<div className="notice notice-warn">{truncation warnings}</div>` | "The server truncated the comparison. " / "${ops_omitted} run(s) were omitted server-side. " / "${omitted} run(s) past the first 2000 are not drawn here." |
| No hunk focused | Toolbar text: `"no hunk focused"` | "no hunk focused" |
| Hunk focused | Toolbar text: `"hunk ${currentHunk + 1} of ${hunks}"` | "hunk {N} of {total}" |

---

## Organizer (`pages/organizer.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|------------|
| Exchange id input | input | `Exchange id to save` | Always | Numeric input for exchange ID to add to organizer |
| Save exchange button | button | "Save exchange" | `exchangeId.trim() !== ""` AND NOT `mutations.add.isPending` | Calls `add()` → posts exchange ID to organizer |
| Exchange input (onKeyDown) | — | — | When user presses Enter in exchange id input | Triggers `add()` |
| Table row (clickable) | table-row | — | Always (all rows in items.map) | Selects item when clicked via `select(item)` |
| Open in history icon-button | icon-button | `Open exchange #${item.exchange} in HTTP history` | Always | Calls `openInHistory(item.exchange)` → `focusExchange()` + `setRoute("history")` |
| Remove item icon-button | icon-button | `Remove item ${item.id}` | Always | Sets `confirmDelete` state to trigger modal |
| Title input | input | — | When item selected and draft exists | User edits `draft.title` |
| Highlight select | select | `Highlight colour` | When item selected and draft exists | User changes `draft.highlight` to one of `HIGHLIGHTS` array |
| Investigation note textarea | textarea | — | When item selected and draft exists | User edits `draft.note` |
| Revert button | button | "Revert" | `dirty === true` | Reverts `draft` to baseline via `JSON.parse(baseline)` |
| Save button | button | "Save" / "Saving…" | `dirty === true` AND NOT `mutations.save.isPending` | Calls `save()` → POSTs updated item |
| Remove button (from detail section) | button | "Remove" (variant="danger") | Always | Sets `confirmDelete` to `selected.id` |
| Show in history button (from detail) | button | "Show in history" | Always | Calls `openInHistory(selected.exchange)` |
| Delete confirmation button | button | "Remove item" (variant="danger") | NOT `mutations.remove.isPending` | Calls `remove(confirmDelete)` → deletes item |
| Keep it button | button | "Keep it" | Always | Closes modal by setting `confirmDelete = null` |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| `useOrganizer()` | GET `/api/organizer` | On mount | Fetches `data.items`, displays loading/error, refetch trigger |
| `useOrganizerMutations()` | POST/PATCH/DELETE endpoints | Always | `mutations.add`, `mutations.save`, `mutations.remove` for network ops |
| `useApp()` | Zustand store | Always | `focusExchange()`, `setRoute()` for cross-page navigation |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `selectedId` | `null` | `setSelectedId()` when row clicked or after add/remove | Select item from items array, enable/disable UI |
| `draft` | `null` | `setDraft()` when item selected; set in `useEffect` | Edit fields, dirty check, revert operation |
| `baseline` | `""` | `setBaseline()` with stringified draft snapshot | Dirty comparison, revert source |
| `confirmDelete` | `null` | `setConfirmDelete(id)` on remove click | Controls modal open state, delete confirmation |
| `exchangeId` | `""` | `setExchangeId()` from input onChange; cleared on success | Input value, add validation, button disable state |

### Cross-page effects

| Effect | Trigger | Destination |
|--------|---------|-------------|
| `focusExchange(exchange)` | Click "Open in history" | Zustand store; scrolls HTTP history to this exchange |
| `setRoute("history")` | Click "Open in history" | Zustand store; navigates to history page |

### Action flows

**FLOW ORGANIZER-1: Add exchange to organizer**
1. User enters exchange ID in input field
2. User clicks "Save exchange" button OR presses Enter
3. `add()` parses ID, validates it's a positive integer
4. `mutations.add.mutate(exchange, { onSuccess, onError })`
5. On success: `exchangeId` cleared, item selected via `select(item)`, toast shows `"Saved exchange #${exchange}"`
6. On error: toast shows `"Could not save that exchange"`

**FLOW ORGANIZER-2: Edit and save note**
1. User clicks table row → `select(item)` populates `draft` and `baseline`
2. User edits title, highlight, or note fields → `draft` updated
3. `dirty` computed as `JSON.stringify(draft) !== baseline`
4. User clicks "Save" button
5. `save()` constructs payload with updated values, calls `mutations.save.mutate(payload, { onSuccess, onError })`
6. On success: `baseline` updated to match new draft state, toast shows `"Note saved"`
7. On error: toast shows `"Save failed"`

**FLOW ORGANIZER-3: Revert unsaved changes**
1. User edits draft (making `dirty === true`)
2. User clicks "Revert" button
3. `draft` reset to parsed baseline via `JSON.parse(baseline)`, toast shows `"Reverted to the saved note"`

**FLOW ORGANIZER-4: Delete item**
1. User clicks "Remove" button on table row or detail section
2. `confirmDelete` set to item ID → modal opens
3. User clicks "Remove item" in modal
4. `remove(confirmDelete)` calls `mutations.remove.mutate(id, { onSuccess, onError })`
5. On success: If deleted item was selected, clear selection; toast shows `"Removed from the organizer"`
6. `confirmDelete` reset to null; modal closes
7. On error: toast shows `"Delete failed"`

**FLOW ORGANIZER-5: Navigate to exchange in HTTP history**
1. User clicks "Open exchange #${exchange} in history" icon
2. `openInHistory(exchange)` called
3. `focusExchange(exchange)` → stores exchange id in zustand
4. `setRoute("history")` → navigates to history page

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| Loading saved exchanges | `<LoadingPanel label="Loading saved exchanges" />` | "Loading saved exchanges" |
| No items saved yet | `<Empty title="Nothing saved yet" detail="Save an exchange from HTTP history, or add one by id above, to start an investigation note." />` | "Nothing saved yet" / "Save an exchange from HTTP history, or add one by id above, to start an investigation note." |
| No item selected | `<Empty title="No item selected" detail="Choose a saved exchange to read or edit its note." />` | "No item selected" / "Choose a saved exchange to read or edit its note." |
| Item selected with unsaved changes | `<Badge tone="warn">unsaved changes</Badge>` | "unsaved changes" |
| Item selected with saved state | `<Badge tone="good">saved</Badge>` | "saved" |
| Highlight not set (display in table) | `<span className="cell-dim">—</span>` | "—" |
| No highlight selected in edit | "none" (option value in HIGHLIGHTS) | "none" |
| Note not set (display in table) | `<span className="cell-dim">no note</span>` | "no note" |
| Title not set in table | `<span className="cell-dim">untitled</span>` | "untitled" |

---

## Logger (`pages/logger.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|------------|
| Search input | input | `Search the tool log` | Always | Filters log by text via `setTerm()` (debounced) |
| Clear search icon-button | icon-button | `Clear search` | `term !== ""` | Clears search term via `setTerm("")` |
| Tool filter select | select | `Tool filter` | Always | Filters log by tool name via `setTool()` |
| Table row (clickable) | table-row | — | Always (all rows in data.map) | Selects row when clicked via `setSelectedId(row.id)` |
| Table context menu | context-menu-item | "Copy URL (as logged)" | Right-click on any row | Copies row URL via `copyToClipboard(rowUrl(row))` |
| Table context menu | context-menu-item | "Copy as curl (request line only)" | Right-click on any row | Copies curl command via `copyToClipboard(rowCurl(row))` |
| Table context menu | context-menu-item | `Show ${row.host} in HTTP history` | Right-click on any row | Calls `showInHistory("host = ${row.host}")` |
| Table context menu | context-menu-item | `Show ${row.host} ${row.path} in HTTP history` | Right-click on any row | Calls `showInHistory("host = ${row.host} AND path ~ ${row.path}")` |
| Clear log button | button | "Clear log" | `rows.length > 0` | Sets `confirmClear = true` → modal opens |
| Clear log confirmation button | button | `Clear ${total.toLocaleString()} entries` / "Clearing…" | NOT `clearLog.isPending` | Calls `clearLog.mutate()` |
| Keep log button | button | "Keep the log" | Always | Closes modal by setting `confirmClear = false` |
| Clear selection icon-button | icon-button | `Clear selection` | Always (in detail panel) | Clears selection via `setSelectedId(null)` |
| Show in history button (detail) | button | `Show in history` | Always (in detail panel) | Calls `showInHistory("host = ${selected.host}")` |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| `useToolLogView(tool, debouncedTerm)` | GET `/api/toollog?tool=&term=` | Always | Fetches filtered log entries, error state, refetch trigger |
| `useClearToolLog()` | DELETE `/api/toollog` | Always | Network mutation for clearing entire log |
| `useDebounced(term, 260)` | Local debounce hook | Always | Delays search query to 260ms to avoid excessive API calls |
| `useApp()` | Zustand store | Always | `setHistoryQuery()`, `setRoute()` for navigation |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `tool` | `""` | `setTool()` from select onChange | Tool filter query, display in select |
| `term` | `""` | `setTerm()` from search input onChange | Search filter query (debounced), clear button disable |
| `selectedId` | `null` | `setSelectedId()` when row clicked or clear selection clicked | Row highlight, detail panel display |
| `confirmClear` | `false` | `setConfirmClear(true)` on clear button, `setConfirmClear(false)` on modal close/cancel | Controls modal open state |

### Cross-page effects

| Effect | Trigger | Destination |
|--------|---------|-------------|
| `setHistoryQuery(expression)` | Click "Show in history" on context menu or detail panel | Zustand store; filters HTTP history by expression |
| `setRoute("history")` | Click "Show in history" | Zustand store; navigates to history page |

### Action flows

**FLOW LOGGER-1: Search and filter log**
1. User types in search input → `setTerm()` updates state
2. `term` is debounced to `debouncedTerm` (260ms delay)
3. `useToolLogView(tool, debouncedTerm)` refetches with new filters
4. Table rows update via `rows = data?.entries ?? []`
5. Empty state updates if no rows match

**FLOW LOGGER-2: Select and view log entry detail**
1. User clicks table row
2. `setSelectedId(row.id)` updates state
3. `selected` memoized from `rows.find()` re-evaluates
4. Detail panel renders with selected row's full information
5. Buttons for "Show in history" and "Copy URL" become available

**FLOW LOGGER-3: Copy from context menu**
1. User right-clicks table row
2. Context menu appears with 4 actions
3. User clicks "Copy URL (as logged)" → `copyToClipboard(rowUrl(row))`; toast shows `"URL copied"`
4. OR "Copy as curl (request line only)" → `copyToClipboard(rowCurl(row))`; toast shows `"curl command copied — the log stores no headers or body"`

**FLOW LOGGER-4: Show in HTTP history**
1. User clicks "Show in history" from context menu or detail panel
2. `showInHistory(expression)` called with query expression
3. `setHistoryQuery(expression)` stores filter in zustand
4. `setRoute("history")` navigates to history page
5. HTTP history page loads and applies the filter expression

**FLOW LOGGER-5: Clear entire log**
1. User clicks "Clear log" button (only enabled when `rows.length > 0`)
2. `confirmClear` set to `true` → modal opens
3. Modal displays "Clear the tool log?" and description
4. User clicks "Clear {count} entries" button
5. `clearLog.mutate(undefined, { onSuccess, onError })`
6. On success: `selectedId` cleared, modal closed, toast shows `"Tool log cleared"`
7. On error: toast shows `"Could not clear the log: ${cause.message}"`

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| Table loading | Table shows `loading={isFetching && !data}` state | — |
| No matches with active search/filter | `<Empty title="No logged request matches" detail="Relax the search or switch back to all tools." />` | "No logged request matches" / "Relax the search or switch back to all tools." |
| Nothing logged yet | `<Empty title="Nothing logged yet" detail="Repeater, Intruder, Scanner and the crawler record every request they send here, apart from proxy history." />` | "Nothing logged yet" / "Repeater, Intruder, Scanner and the crawler record every request they send here, apart from proxy history." |
| No row selected | `<Empty title="No row selected" detail="Choose a logged request to read its timing and error text in full. Right-click a row to copy its URL or jump to the same host in HTTP history." />` | "No row selected" / "Choose a logged request to read its timing and error text in full. Right-click a row to copy its URL or jump to the same host in HTTP history." |
| Error on refetch | `<ErrorNotice error={error} onRetry={() => void refetch()} />` | — |

---

## Dashboard (`pages/dashboard.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|------------|
| Open HTTP history button | button | "Open HTTP history" (in traffic sources section) | Always | Calls `setRoute("history")` → navigates to history page |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| `useDashboard()` | GET `/api/dashboard` | On mount | Fetches dashboard data: exchanges, messages, tasks, activity, events, coverage summaries, traffic sources |
| `useApp()` | Zustand store | Always | `setRoute()` for navigation |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `sources` | `useMemo(() => Object.entries(data?.sources ?? {}).sort(...))` | Computed from `data?.sources` | Traffic sources metric grid |
| `incomplete` | `useMemo(() => (data?.summaries ?? []).filter(s => !s.breakdown.complete).length)` | Computed from `data?.summaries` | Coverage gaps metric, warning notice |

### Cross-page effects

| Effect | Trigger | Destination |
|--------|---------|-------------|
| `setRoute("history")` | Click "Open HTTP history" button in traffic sources section | Zustand store; navigates to history page |

### Action flows

**FLOW DASHBOARD-1: View dashboard overview**
1. User navigates to Dashboard page
2. `useDashboard()` fetches data on mount
3. Page displays 4 top metrics: Exchanges, Capture store, Running tasks, Coverage gaps
4. Coverage card rendered for each summary in `data.summaries`
5. Activity table shows last 10 tool requests
6. Events list shows last 12 events
7. Tasks table shows all tasks
8. Traffic sources metric grid shows exchanges by source (sorted by count descending)

**FLOW DASHBOARD-2: Navigate to HTTP history from traffic sources**
1. User clicks "Open HTTP history" button in traffic sources section
2. `setRoute("history")` called
3. UI navigates to history page

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| Coverage summary error | `<ErrorNotice error={error} onRetry={() => void refetch()} />` | — |
| No coverage reported | `<Empty title="No coverage reported" detail="Run a crawl or an audit to produce coverage accounting." />` | "No coverage reported" / "Run a crawl or an audit to produce coverage accounting." |
| No tasks | `<Empty title="No tasks" detail="Crawls, audits and attacks appear here with their progress and bounded results." />` | "No tasks" / "Crawls, audits and attacks appear here with their progress and bounded results." |
| No tool traffic | `<Empty title="No tool traffic" detail="Requests that burpsy itself sends — Repeater, Intruder, Scanner — are logged here." />` | "No tool traffic" / "Requests that burpsy itself sends — Repeater, Intruder, Scanner — are logged here." |
| No events | `<Empty title="No events" detail="Start an audit, a crawl or an attack to populate this feed." />` | "No events" / "Start an audit, a crawl or an attack to populate this feed." |
| No traffic yet (empty sources) | `<Empty title="No traffic yet" detail="Configure a client to use the proxy, then install the CA certificate to capture HTTPS." />` | "No traffic yet" / "Configure a client to use the proxy, then install the CA certificate to capture HTTPS." |
| Nothing captured yet | `<div className="notice">... Nothing captured yet. Point a browser or client at the proxy listener, install the CA certificate from the sidebar, then reload this page. Use Intercept to hold traffic, or Repeater to craft a request by hand.</div>` | "Nothing captured yet. Point a browser or client at the proxy listener, install the CA certificate from the sidebar, then reload this page. Use Intercept to hold traffic, or Repeater to craft a request by hand." |
| Coverage gaps exist | `<div className="notice notice-warn">... {incomplete} coverage {plural} report(s) work without a verdict. Treat the finding counts above as a lower bound, not a clean result.</div>` | "{incomplete} coverage {summaries report / summaries report} work without a verdict. Treat the finding counts above as a lower bound, not a clean result." |

---

## Settings (`pages/settings.tsx`)

### Interactive elements

**ScopeSection**

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|------------|
| Rule kind select | select | `Scope rule kind` | Always | Selects "include" or "exclude" rule type via `setKind()` |
| Host pattern input | input | `Scope host pattern` | Always | Text input for host pattern; user can press Enter to add rule |
| Add rule button | button | "Add rule" | `pattern.trim() !== ""` AND NOT `update.isPending` | Calls `run({ action: kind, pattern })` → POSTs scope rule |
| Pattern input (onKeyDown) | — | — | When user presses Enter in pattern input | Triggers `run()` if pattern is not empty |
| Remove scope rule icon-button | icon-button | `Remove ${rule.kind} rule for ${rule.host ?? "any host"}` | `rule.host !== null` AND NOT `update.isPending` | Calls `run({ action: "remove", ... })` to delete rule |
| Clear scope button | button | "Clear scope" | `data !== null` AND NOT `data.empty` | Sets `confirmClear = true` → modal opens |
| Clear scope confirmation button | button | "Clear scope" | Always (in modal) | Calls `run({ action: "clear" }, message)` |
| Cancel scope clear button | button | "Cancel" | Always (in modal) | Closes modal by setting `confirmClear = false` |

**ProtocolSection**

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|------------|
| Probe host input | input | `Probe host` | Always | Text input for host to probe |
| Probe port input | input | `Probe port` | Always | Numeric input for port; defaults to "443" |
| Probe TLS switch | switch | "Use TLS for the probe" (htmlFor="protocol-probe-tls") | Always | Toggle TLS on/off via `setTls()` |
| Probe negotiation button | button | "Probe negotiation" / "Probing…" | NOT `probe.isPending` | Calls `runProbe()` → POSTs probe request |

**AppearanceSection**

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|------------|
| Theme select | select | `Theme` | Always | Selects theme from THEMES; calls `setTheme()` |
| Table density select | select | `Table density` | Always | Selects density from DENSITIES; calls `setDensity()` |

**CertificateSection**

| Element | Type | Link | Enabled when | What it does |
|---------|------|------|--------------|------------|
| Download CA cert link | link | href="/ca.crt" download="burpsy-ca.crt" | `data?.available === true` | Downloads CA certificate file |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| `useScopeView()` | GET `/api/scope` | On mount | Fetches scope rules, displays loading/error, refetch trigger |
| `useUpdateScope()` | POST `/api/scope` | Always | Network mutation for add/remove/clear scope rules |
| `useProtocols()` | GET `/api/protocols` | On mount | Fetches protocol statistics and authority list |
| `useSendFrameProgram()` | POST `/api/protocols/probe` | Always | Network mutation for sending probe frame |
| `useCaCert()` | GET `/api/ca-cert` | On mount | Fetches CA cert availability, refetch trigger |
| `useStats()` | GET `/api/diagnostics/stats` | On mount | Fetches store statistics |
| `useEventHubStats()` | GET `/api/diagnostics/events` | On mount | Fetches event hub statistics |
| `useApp()` | Zustand store | Always | `theme`, `setTheme()`, `density`, `setDensity()` |

### Local state

**ScopeSection**

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `kind` | `"include"` | `setKind()` from select onChange | Scope rule type selection, add rule payload |
| `pattern` | `""` | `setPattern()` from input onChange | Host pattern input value, add rule payload, button disable |
| `confirmClear` | `false` | `setConfirmClear(true)` on clear button, `setConfirmClear(false)` on modal close | Controls clear confirmation modal open state |

**ProtocolSection**

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `host` | `""` | `setHost()` from input onChange | Probe host input value, probe payload |
| `port` | `"443"` | `setPort()` from input onChange | Probe port input value, probe payload |
| `tls` | `true` | `setTls()` from switch onCheckedChange | Probe TLS toggle state, probe payload |
| `result` | `null` | `setResult(response)` on probe success, `setResult(null)` on error | Probe result display section |

**AppearanceSection**

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| `theme` | From zustand store | `setTheme()` from select onChange | Theme select value, application theme application |
| `density` | From zustand store | `setDensity()` from select onChange | Density select value, table rendering |

### Cross-page effects

None identified. No calls to `setRoute`, `setHistoryQuery`, `focusExchange`, `setIntruderSeed`, `setComparerSlot`, or `openRepeaterTab`.

### Action flows

**FLOW SETTINGS-1: Add scope rule**
1. User selects rule kind (include/exclude) via dropdown
2. User enters host pattern (e.g., "api.example.com")
3. User clicks "Add rule" OR presses Enter in pattern input
4. `run({ action: kind, pattern })` called
5. `update.mutate(body, { onSuccess, onError })`
6. On success: `pattern` cleared, toast shows `"${kind}d ${pattern}"`
7. On error: toast shows `"Scope change failed"`
8. Scope rules table updates via refetch

**FLOW SETTINGS-2: Remove scope rule**
1. User clicks remove icon on a rule in the table
2. `run({ action: "remove", kind, pattern })` called
3. Network mutation POSTs delete
4. On success: Toast shows `"Removed ${pattern}"`
5. Rule removed from table

**FLOW SETTINGS-3: Clear all scope rules**
1. User clicks "Clear scope" button
2. `confirmClear` set to `true` → modal opens with message "Clear every scope rule?" / "With no rules left, every host is in scope again."
3. User clicks "Clear scope" in modal
4. `run({ action: "clear" }, "Scope cleared")` called
5. On success: All rules cleared from table; toast shows `"Scope cleared"`
6. Modal closes

**FLOW SETTINGS-4: Probe protocol negotiation**
1. User enters host, port, and TLS preference
2. User clicks "Probe negotiation" button
3. `runProbe()` validates inputs (non-empty host, positive integer port)
4. `probe.mutate({ host, port, tls, preface: true, read_for_ms: 750, frames: [] }, { onSuccess, onError })`
5. On success: `setResult(response)` stores response; toast shows success or error from response
6. On error: `setResult(null)`; toast shows `"Probe failed"`
7. Result section renders with negotiation details, frames table, violations/refusals lists

**FLOW SETTINGS-5: Change appearance**
1. User selects theme from dropdown
2. `setTheme(value)` called → updates zustand store
3. Application theme changes immediately
4. OR User selects table density from dropdown
5. `setDensity(value)` called → updates zustand store
6. Table rendering updates (layout changes applied)

**FLOW SETTINGS-6: Download CA certificate**
1. User clicks "Download burpsy-ca.crt" link
2. Browser downloads file from `/ca.crt` endpoint
3. File saved as "burpsy-ca.crt"

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| Loading scope | `<LoadingPanel label="Loading scope" />` | "Loading scope" |
| Scope error | `<ErrorNotice error={error} onRetry={() => void refetch()} />` | — |
| No scope rules | `<Empty title="No scope rules" detail="Every host is in scope. Add an include rule to bound what the proxy, scanner and crawler will touch." />` | "No scope rules" / "Every host is in scope. Add an include rule to bound what the proxy, scanner and crawler will touch." |
| Scope warning (notice) | `<div className="notice">... A scope rule matches on a host pattern only — this build's scope API has no port, protocol or path arm, so those are not offered here. An empty scope means everything is in scope.</div>` | "A scope rule matches on a host pattern only — this build's scope API has no port, protocol or path arm, so those are not offered here. An empty scope means everything is in scope." |
| Loading protocol report | `<LoadingPanel label="Loading protocol report" />` | "Loading protocol report" |
| Protocol error | `<ErrorNotice error={error} onRetry={() => void refetch()} />` | — |
| Protocols not enabled | `<div className="notice notice-warn"><span>{data.hint ?? "No sender is wired, so nothing has been sent from this process."}</span></div>` | "{hint text}" or "No sender is wired, so nothing has been sent from this process." |
| No authority probed | `<Empty title="No authority has been probed" detail="Send a request from Repeater, or probe one below." />` | "No authority has been probed" / "Send a request from Repeater, or probe one below." |
| No downgrades recorded | `<p className="field-hint">No downgrades recorded: nothing fell back from HTTP/2 for a stated reason.</p>` | "No downgrades recorded: nothing fell back from HTTP/2 for a stated reason." |
| No frames in probe reply | `<p className="field-hint">The peer sent no complete frame back.</p>` | "The peer sent no complete frame back." |
| Protocol probe refusals | `<div className="notice notice-warn"><span>Scope refused this probe: {reasons}</span></div>` | "Scope refused this probe: {list}" |
| Protocol probe violations | `<div className="notice notice-warn"><span>Protocol violations observed: {violations}</span></div>` | "Protocol violations observed: {list}" |
| CA cert not available | `<div className="notice notice-warn"><span>{data.detail}</span></div>` | "{detail text}" |
| CA cert available | `<Toolbar>...Download link...badge "certificate available"</Toolbar>` | "certificate available" |
| No pending event deliveries | `<p className="field-hint">Nothing is waiting to be delivered to a subscriber.</p>` | "Nothing is waiting to be delivered to a subscriber." |
