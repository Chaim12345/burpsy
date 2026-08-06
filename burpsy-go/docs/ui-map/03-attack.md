# Burpsy React UI Interaction Surface Inventory

## Intruder (`pages/intruder.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|-------------|
| Stored message id input | input | (no explicit label) | always | Supplies msgId; clears points/selected when changed |
| Target authority input | input | (no explicit label) | always | Sets target URL for attack |
| Attack type select | select | (no explicit label) | always | Chooses mode: sniper, battering_ram, pitchfork, cluster_bomb |
| Include every candidate position switch | switch | "Include every candidate position" | always | Sets allPoints; clears points/selected when toggled |
| Find positions button | button | (no explicit label) | msgId > 0 && !discover.isPending | Calls discover.mutate(); discovers injection points |
| Position checkboxes | checkbox | `"Use position ${point.label}"` | always | Toggles inclusion in selected array; adds to positions list |
| Payloads textarea (per set) | textarea | (no explicit label in Field) | always | Edits payloadTexts[index]; one per selected position |
| Rule operation select (RuleRow) | select | `"Rule ${index + 1} operation"` | always | Chooses rule type; resets rule to empty when changed |
| Rule text input | input | `"Rule ${index + 1} text"` | rule uses "text" field | Enters text for add_prefix, add_suffix, etc. |
| Rule pattern input | input | `"Rule ${index + 1} pattern"` | rule uses "pattern" field | Enters regex for match/replace |
| Rule replacement input | input | `"Rule ${index + 1} replacement"` | rule uses "replace" field | Enters replacement text (with $1 backrefs) |
| Rule layer/codec select | select | `"Rule ${index + 1} codec"` | rule uses "layer" field | Chooses encoding layer: URL, HTML, Base64, etc. |
| Rule algorithm select | select | `"Rule ${index + 1} algorithm"` | rule uses "algorithm" field | Chooses hash: MD5, SHA1, SHA256, etc. |
| Rule "every match" checkbox | checkbox | (implicit in label) | rule uses "all" field | Toggles rule.all for match-all behavior |
| Remove rule icon button | icon-button | `"Remove rule ${index + 1}"` | always | Splices rule from rules array |
| Add rule button | button | (no explicit label) | always | Appends new rule with add_prefix |
| Max requests input | input | (no explicit label) | always | Sets maxRequests limit |
| Max concurrent requests input | input | (no explicit label) | always | Sets maxInFlight limit |
| Requests per second input | input | (no explicit label) | always | Sets rps; blank = unlimited |
| Grep match input | input | (no explicit label) | always | Sets grepMatch string |
| Grep extract input | input | (no explicit label) | always | Sets grepExtract string |
| Launch attack button | button | (no explicit label) | canRun (msg, target, positions, payloads) && !run.isPending | Calls run.mutate(); executes attack |
| Positions tab | tab | "Positions" | always | Switches to tab="positions" |
| Payloads tab | tab | "Payloads" | always | Switches to tab="payloads" |
| Resource pool tab | tab | "Resource pool" | always | Switches to tab="pool" |
| Settings tab | tab | "Settings" | always | Switches to tab="settings" |
| Results tab | tab | `"Results${result ? ` (${formatCount(result.report.sent)})` : ""}"` | always | Switches to tab="results" |

### Sub-tabs

| Sub-tab | Renders when | Contents summary |
|---------|--------------|------------------|
| Positions | tab === "positions" | Base request selection, message id input, target, attack mode, point discovery, and base request viewer showing HTTP editor |
| Payloads | tab === "payloads" | Payload set textareas (count matches mode/positions), payload processing rules editor with add/remove/reorder, rule types and parameters |
| Resource pool | tab === "pool" | Max requests, max concurrent, requests-per-second throttle limits |
| Settings | tab === "settings" | Grep match and grep extract string inputs for response pattern matching/extraction |
| Results | tab === "results" | AttackResult component showing metrics, caveats, result buckets, errors, payload set accounting, and per-attempt detail table; or legacy JSON result; or empty state if no attack run yet |

### Keyboard shortcuts

| Keys | Scope | Condition | Action |
|------|-------|-----------|--------|
| (none defined) | - | - | - |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| useIntruderPoints() | /api/intruder/discover | msgId.trim() !== "" && Number(msgId) > 0 | discover button; onDiscover calls mutate() |
| useIntruderRun() | /api/intruder/run | canRun && !run.isPending | Launch attack button; onRun calls mutate() |
| useMessage(msgId) | /api/message/{msgId} | msgId exists | Displays base message in HttpEditor with readOnly=true |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| msgId | "" | Input field, useEffect (from seed) | discover canRun, baseMessage query, attack payload |
| target | "" | Input field, useEffect (from seed) | attack payload, error message copy |
| label | "" | useEffect (from seed) | PageHeader description |
| mode | "sniper" | Select field | setsNeeded calc, attack payload, ATTACK_MODES lookup |
| allPoints | false | Switch | discover payload, attack payload |
| points | [] | discover.onSuccess, useEffect (from seed) | point checkboxes display, isEmpty check |
| selected | [] | checkbox change, useEffect (from seed) | estimate calc, canRun check, attack payload |
| payloadTexts | [DEFAULT_PAYLOADS] | Textarea, useEffect (setsNeeded) | setSizes calc, attack payload |
| rules | [] | RuleRow onChange, Add rule click, Remove rule | attack payload if rules.length > 0 |
| grepMatch | "" | Input field | attack payload if trim() |
| grepExtract | "" | Input field | attack payload if trim() |
| maxRequests | 1000 | Input field | overBudget calc, attack payload, estimate comparison |
| maxInFlight | 8 | Input field | attack payload |
| rps | "" | Input field | attack payload if trim() |
| result | null | run.onSuccess (if report shape) | Results tab display, estimate badge copy |
| legacyResult | null | run.onSuccess (if non-report shape) | Results tab legacy JSON display |
| tab | "positions" | TabsTrigger onValueChange, run.onSuccess -> setTab("results") | Tabs value and content render |

### Cross-page effects

| Effect | Trigger | Destination |
|--------|---------|-------------|
| setIntruderSeed(null) | useEffect cleanup after seed is consumed | zustand store clears intruderSeed |
| seed read from store | useEffect watches seed | fills msgId, target, label; clears points/selected/result |

### Action flows

**FLOW INTRUDER-1: Discover insertion points**
1. User enters message ID and target URL
2. User clicks "Find positions" button (canDiscover = msgId.trim() !== "" && Number(msgId) > 0)
3. discover.mutate({ msg_id: Number(msgId), all: allPoints })
4. Backend returns PointView[] or error
5. onSuccess: setPoints(found), toast.success or toast.error if empty
6. onError: toast.error with error message
7. Visible result: Point list rendered with checkboxes; each shows label, kind, offset, current value

**FLOW INTRUDER-2: Configure and run attack**
1. User selects one or more points (checkboxes mark selected array)
2. Payload sets auto-scale: useEffect keeps payloadTexts.length === setsNeeded
3. User fills payload textareas (one set per selected position, or one shared set)
4. User optionally adds payload processing rules (click Add rule, select rule type, fill parameters)
5. User optionally sets resource limits: maxRequests, maxInFlight, rps
6. User optionally sets grep match/extract
7. estimate shows: estimateRequests(mode, selected.length, setSizes) vs maxRequests; badge tone="warn" if overBudget
8. User clicks "Launch attack" (enabled when canRun = canDiscover && target.trim() !== "" && selected.length > 0 && setSizes.every(size > 0))
9. run.mutate(body) with mode, points, payload_sets (as payloadList), max_requests, max_in_flight, rules, grep_match, grep_extract, rps
10. Backend executes attack; returns RunView (if named mode) or legacy array
11. onSuccess: setResult(view), setTab("results"), toast.success with sent count and elapsed
12. onError: toast.error
13. Visible result: Results tab opens automatically; shows AttackResult component with metric grid, caveats notice, result buckets, errors, payload set accounting, attempts detail

**FLOW INTRUDER-3: Edit payload rules (failure case)**
1. User clicks "Add rule" or opens existing rule row
2. User selects rule operation from PAYLOAD_RULES
3. Rule changes type; empty rule spawned (emptyRule factory)
4. User fills rule-specific fields (text, pattern, replace, layer, algorithm, all)
5. If user provides invalid regex: no client validation; error deferred to server in attack run
6. If attack runs and rules fail: run.error toasted; Results tab shows error from backend

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| msgId is empty or ≤ 0 | Empty component | "No base request" / "Enter a stored message id, or right-click a row in HTTP history and choose "Send to Intruder"." |
| canDiscover but points.length === 0 | Empty component | "No positions loaded" / "Find positions before launching an attack." |
| discover.isPending | Button shows text | "Scanning…" |
| discover.error | ErrorNotice | (error.message) with onRetry |
| run.isPending | Button shows text | "Attacking…" |
| run.error in Results tab | ErrorNotice | (error.message) with onRetry |
| !result && !legacyResult && !run.isPending && !run.error | Empty component (Results tab) | "No attack run yet" / "Pick a base request, choose positions and payloads, then launch. The report shows what was sent and what was bounded away." |
| result.report.buckets.length === 0 | Empty in SimpleTable | "No buckets" / "The attack produced no grouped responses." |
| result.report.errors.length === 0 | SimpleTable not rendered | (skipped) |
| result.report.attempts.length === 0 | SimpleTable not rendered | (skipped) |
| sets.length === 0 | Empty in SimpleTable | "No set accounting" / "The server reported no per-set breakdown." |
| estimate.count > maxRequests | notice-warn | "This configuration implies {count} requests but the cap is {maxRequests}. The server will stop at the cap and mark the report truncated. Raise the cap or narrow the payload sets." |
| overBudget badge | Badge tone="warn" | (shows count and "request(s)") |
| caveats (truncated, non-exact combinations, buckets truncated, unbucketed, limited detail, auto-throttle) | notice-warn with ul | Bulleted list of applied bounds |

---

## Repeater (`pages/repeater.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|-------------|
| Target input | input | (no explicit label) | always | Edits active.target; extracts scheme (http/https) for schemeOf() |
| Tab name input | input | (no explicit label) | always | Edits active.name |
| Tab row (custom role=tab) | tab | "Repeater requests" (in tablist aria-label) | always | Selects tab by clicking; keyboard support for Enter/Space |
| Tab close button | button | `"Close ${tab.name}"` | always | Closes tab; removes from results |
| New request icon button | icon-button | "New request" | always | Creates new tab with openRepeaterTab |
| To Intruder button | button | (no explicit label) | !handingOff | Initiates handoff; sends request if needed, fetches exchange, calls setIntruderSeed |
| Inspector toggle icon button | icon-button | inspector ? "Hide Inspector" : "Show Inspector" | always | Toggles inspector visibility; aria-pressed={inspector} |
| Send button | button | (no explicit label) | !send.isPending | Calls submit(active); sends request |
| Request editor | editor | "Request" | always | HttpEditor with onChange that calls updateRepeaterTab |
| Response editor | editor | "Response" | always | HttpEditor readOnly; shows result?.response or loading message |
| Inspector (request view) | inspector | "Inspector · request" | inspector === true | Shows request parsing/details |

### Sub-tabs

| Sub-tab | Renders when | Contents summary |
|---------|--------------|------------------|
| Tab list (custom) | always (if active tab exists) | Horizontal tab row with close buttons; "Repeater requests" aria-label; custom onClick and onKeyDown handlers |
| Editor grid | active tab exists | Three-column layout (request, response, inspector) or two-column (request, response) depending on inspector toggle |

### Keyboard shortcuts

| Keys | Scope | Condition | Action |
|------|-------|-----------|--------|
| mod+enter (Cmd+Enter or Ctrl+Enter) | httpeditor, contenteditable, formtags | active tab exists && !send.isPending | Calls submit(active) to send request |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| useRepeaterSend() | /api/repeater/send | send button click | submit() function calls mutate(); also called in handOffToIntruder async |
| useApp store | repeaterTabs, activeRepeaterTab, setters | always | Reads tabs, activeId; calls openRepeaterTab, updateRepeaterTab, closeRepeaterTab, setActiveRepeaterTab |
| useApp store | setIntruderSeed | handOffToIntruder flow | Sets seed for Intruder page |
| useApp store | setRoute | handOffToIntruder flow | Routes to "intruder" |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| results | {} | send.onSuccess, setResults in handOffToIntruder | result variable assignment, close tab cleanup |
| handingOff | false | handOffToIntruder try/finally | To Intruder button disabled, button text |
| inspector | true | Inspector toggle icon button | Inspector component render, className on editor grid |

### Cross-page effects

| Effect | Trigger | Destination |
|--------|---------|-------------|
| setIntruderSeed({ msgId: exchange.request, target: tab.target, label: tab.name }) | handOffToIntruder success | zustand store intruderSeed |
| setRoute("intruder") | handOffToIntruder success | zustand store route navigation |
| updateRepeaterTab(active.id, { target, protocol }) | Target input onChange | zustand store updates persisted tab |
| updateRepeaterTab(active.id, { request }) | Request editor onChange | zustand store updates persisted tab |
| setActiveRepeaterTab(id) | Tab click or keyboard Enter/Space | zustand store activeRepeaterTab |

### Action flows

**FLOW REPEATER-1: Open and navigate tabs**
1. User is on Repeater page; tabs array populated from store (persisted)
2. User clicks a tab row (role=tab)
3. onClick calls setActiveRepeaterTab(tab.id)
4. active useMemo updates; activeId changes
5. Visible result: Tab row className updated to data-state="active"; new request/response shown

**FLOW REPEATER-2: Create new request tab**
1. User clicks "New request" button
2. newTab() calls openRepeaterTab({ name: `Request ${tabs.length + 1}`, target: DEFAULT_TARGET, protocol: "https", request: templateRequest() })
3. zustand store adds tab to repeaterTabs
4. Visible result: New tab appears in tab list; becomes active; blank request editor shown

**FLOW REPEATER-3: Send request**
1. User edits request in Request editor (HttpEditor)
2. onChange calls updateRepeaterTab(active.id, { request: value })
3. Request persisted in store
4. User clicks "Send" button or presses Ctrl+Enter/Cmd+Enter
5. submit(active) called
6. send.mutate({ target, request, protocol: schemeOf(target), from_exchange })
7. Backend executes request; returns RepeaterResult { status, duration_ms, exchange_id, response }
8. onSuccess: setResults(current => ({ ...current, [tab.id]: result })), toast.success with status and duration
9. onError: toast.error
10. Visible result: Response editor shows response bytes; status/duration badges updated in header; exchange_id badge shown if captured

**FLOW REPEATER-4: Hand off to Intruder (failure case)**
1. User clicks "To Intruder"
2. handOffToIntruder(active) starts
3. If no prior result for this tab: send request first via api call
4. If send succeeds: setResults, exchangeId = sent.exchange_id
5. If exchangeId falsy: toast.error "This request was not captured…"
6. If exchangeId exists: fetch /api/exchange/{exchangeId}
7. If fetch succeeds: setIntruderSeed, setRoute("intruder"), toast.success
8. If fetch fails or send fails: toast.error with message
9. Finally: setHandingOff(false)
10. Visible result: Toast success + route change to Intruder, or toast error

**FLOW REPEATER-5: Close tab**
1. User clicks X button in tab row
2. onClick.stopPropagation called; closeRepeaterTab(tab.id) called
3. setResults removes tab.id key
4. zustand store removes tab from repeaterTabs
5. useEffect updates activeId if closed tab was active
6. Visible result: Tab removed from list; if was active, another tab becomes active

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| !active (no tabs) | Empty component in Page | "No request open" / "Start a blank request, or right-click any row in HTTP history and choose "Send to Repeater"." |
| send.isPending | Response editor shows | "Waiting for the response…" |
| send.error | ErrorNotice with onRetry | (error.message) |
| !result && !send.isPending | Response editor shows | "Send the request to see the response bytes." |
| Inspector toggle off | Inspector not rendered | (editor grid becomes 2-column) |

---

## Sequencer (`pages/sequencer.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|-------------|
| Token source (Paste/Capture) | tabs | "Token source" | always | Switches between paste and live capture tabs |
| Encoding select | select | "Read token bits as" | always | Chooses encoding: auto-detect, raw, hex, base32, base64, etc. |
| Analyse button | button | (no explicit label) | !pending && (source === "paste" ? pastedCount > 0 : captured.length > 0) | Calls runPaste or runCaptured; analyzes tokens |
| Tokens textarea (Paste tab) | textarea | "Tokens, one per line" | always | HttpEditor (views=false) with onChange that updates tokens |
| Capture id input (Capture tab) | input | "Capture id to attach to" | always | Edits captureId; inputMode="numeric" |
| Attach button (Capture tab) | button | (no explicit label) | captureId.trim() !== "" | Sets attached = captureId; calls toast.success |
| Re-attach button (Capture tab) | button | (no explicit label) | attached exists | Re-attaches to existing capture |
| Stop capture button (Capture tab) | button | (no explicit label) | captured.length > 0 && !stopCapture.isPending | Calls stopCapture.mutate(); stops live polling |
| Show all positions button (Positions component) | button | (no explicit label) | characters.positions.length > POSITIONS_SHOWN | Toggles showAll; aria-pressed={showAll} |

### Sub-tabs

| Sub-tab | Renders when | Contents summary |
|---------|--------------|------------------|
| Paste a list | source === "paste" | HttpEditor with tokens textarea; pastedCount badge in header |
| Capture from a live exchange | source === "live" | Warning notice (capture loop not implemented in Go port); capture id input, attach button, stop capture button, polling/idle badge, accumulated count badge; empty state if no tokens yet |

### Keyboard shortcuts

| Keys | Scope | Condition | Action |
|------|-------|-----------|--------|
| (none defined) | - | - | - |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| useSequencerAnalyse() | /api/sequencer/analyse | Analyse button click (paste tab) | runPaste mutate(); sets report on success |
| useSequencerAnalyseTokens() | /api/sequencer/analyse-tokens | Analyse button click (capture tab) | runCaptured mutate(); sets report on success |
| useSequencerCapture(attached) | /api/sequencer/capture/{attached} | attached !== "" | Polled once per second; updates capture.data with accumulated tokens |
| useStopSequencerCapture() | /api/sequencer/stop-capture | Stop capture button click | stopCapture.mutate() |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| source | "paste" | Tabs onValueChange | report source logic (analysePaste vs analyseTokens), Analyse button action |
| encoding | "" | Select onChange | runPaste/runCaptured payload (blank triggers auto-detect) |
| tokens | "" | Textarea onChange | pastedCount calc, runPaste payload |
| captureId | "" | Capture id input onChange | Attach button disabled check, attached state transition |
| attached | "" | Attach button onClick | capture polling enabled, Stop capture button visibility, polling badge |

### Cross-page effects

| Effect | Trigger | Destination |
|--------|---------|-------------|
| (none identified) | - | - |

### Action flows

**FLOW SEQUENCER-1: Analyse pasted tokens**
1. User pastes token list into textarea (one per line)
2. User optionally selects encoding (default: auto-detect)
3. pastedCount displays line count in badge
4. User clicks "Analyse"
5. runPaste called; analysePaste.mutate({ text: tokens, encoding })
6. Backend analyzes tokens; returns SequencerAnalysis with grade, verdict, entropy, FIPS tests, positions, etc.
7. onSuccess: setReport, toast.success with token count
8. onError: toast.error
9. Visible result: Report component renders with warnings, grade box, metric grid, FIPS tests, character positions table

**FLOW SEQUENCER-2: Capture and analyse from live exchange**
1. User enters capture id and clicks Attach
2. If captureId.trim() empty: toast.error "Give the capture id to attach to"
3. Else: setAttached(captureId), toast.success "Following capture {captureId}"
4. capture query polls /api/sequencer/capture/{attached} once per second
5. capture.isFetching updates polling badge
6. captured derived from capture.data?.tokens ?? []
7. User waits for tokens to accumulate
8. User clicks "Analyse" (enabled if captured.length > 0 && !pending)
9. runCaptured called; analyseTokens.mutate({ tokens: captured, encoding })
10. Backend analyzes; returns SequencerAnalysis
11. onSuccess: report displayed, toast.success with captured token count
12. Visible result: Same Report component as paste flow

**FLOW SEQUENCER-3: Stop live capture**
1. User clicks "Stop capture"
2. stopCapture.mutate()
3. Backend stops accumulating tokens for this capture id
4. onSuccess: toast.success "Capture stopped"
5. onError: toast.error
6. Visible result: Stop button disabled; polling ceases

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| source === "paste" && pastedCount === 0 && !report | Empty below textarea | (implicit: textarea empty, Analyse button disabled) |
| source === "live" && !attached | field-hint | "Not following a capture." |
| source === "live" && attached && capture.isLoading | Empty component | "No tokens accumulated" / "Capture {attached} is being polled once a second and has produced nothing yet." |
| !report && !pending | Empty component | "No analysis yet" / "Paste a representative sample of session ids or CSRF tokens — a hundred is the conventional floor — then analyse it." |
| analysePaste.isPending or analyseTokens.isPending | Button text | "Analysing…" |
| error (either source) | ErrorNotice | (error.message) with onRetry |
| capture.error | ErrorNotice | (error.message) with onRetry |
| report.fips.tests === null | notice-warn | "Not run. Every FIPS 140-2 threshold is defined on a {block_bits}-bit sample, so running them against a shorter one would produce a confident answer that means nothing. Capture more tokens." |
| characters.positions.length === 0 | Empty component (Positions) | "Nothing to show" / "Analyse a token sample to get a per-position breakdown." |
| characters.positions_truncated | notice-warn | "Only the first {positions.length} of {max_len} positions are reported by the server." |
| Capture tab initial state (Go port) | notice-warn | "This build has no capture loop. The server answers the accumulator for a capture id and accepts a stop, but nothing fills it yet, so attaching will honestly report zero tokens until the backend grows a capture phase." |

---

## Session (`pages/session.tsx`)

### Interactive elements

| Element | Type | Label/aria-label | Enabled when | What it does |
|---------|------|------------------|--------------|-------------|
| New rule button | button | (no explicit label) | wired && !editing | Calls startNew(); opens empty rule editor |
| Refresh button (rules) | button | (no explicit label) | always | Calls rulesQuery.refetch() |
| Refresh button (cookies) | button | (no explicit label) (label="Refresh jar") | always | Calls cookiesQuery.refetch() |
| Rule enable/disable switch | switch | `"Enable ${rule.name \|\| 'rule X'}"` | always | Calls toggleEnabled(rule, checked); saves rule with enabled={checked} |
| Edit rule icon button | icon-button | `"Edit ${rule.name \|\| 'rule X'}"` | always | Calls open(rule); opens editor with ruleIn(rule) |
| Delete rule icon button | icon-button | `"Delete ${rule.name \|\| 'rule X'}"` | id !== undefined | Opens confirmDelete modal |
| Rule name input | input | (no explicit label) | always | Edits editing.name |
| Rule enabled switch | switch | "Rule enabled" (id="session-rule-enabled") | always | Edits editing.enabled |
| Max attempts input | input | (no explicit label) | always | Edits editing.maxAttempts; inputMode="numeric" |
| Scope host input (inline) | input | (no explicit label) | always | Edits each host in editing.hosts by index |
| Remove scope host icon button | icon-button | `"Remove scope host ${index + 1}"` | always | Filters host from editing.hosts |
| Add host button | button | (no explicit label) | newHost.trim() !== "" | Appends newHost to editing.hosts; clears newHost |
| New scope host input | input | "New scope host" | always | Edits newHost; placeholder="target.test" |
| Status is input (Validity) | input | (no explicit label) | always | Edits editing.validity.status_is; inputMode="numeric"; blank means undefined |
| Body contains input (Validity) | input | (no explicit label) | always | Edits editing.validity.body_contains |
| Body does not contain input (Validity) | input | (no explicit label) | always | Edits editing.validity.body_not_contains |
| Header present input (Validity) | input | (no explicit label) | always | Edits editing.validity.header_present |
| Header absent input (Validity) | input | (no explicit label) | always | Edits editing.validity.header_absent |
| Add step button | button | (no explicit label) | wired | Appends empty StepDraft to editing.steps |
| Step method input | input | `"Step ${index + 1} method"` | always | Edits step.method |
| Step URL input | input | `"Step ${index + 1} URL"` | always | Edits step.url |
| Move step up icon button | icon-button | `"Move step ${index + 1} up"` | !disabled && index > 0 | Calls moveStep(-1); swaps step with prior |
| Move step down icon button | icon-button | `"Move step ${index + 1} down"` | !disabled && index < total-1 | Calls moveStep(1); swaps step with next |
| Remove step icon button | icon-button | `"Remove step ${index + 1}"` | always | Filters step from editing.steps |
| Step header name input (HeaderPairs) | input | `"${scope} header ${index + 1} name"` | always | Edits header[0] at index |
| Step header value input (HeaderPairs) | input | `"${scope} header ${index + 1} value"` | always | Edits header[1] at index |
| Remove header icon button | icon-button | `"Remove ${scope} header ${index + 1}"` | always | Filters header from headers array |
| Add header button | button | (no explicit label) | !disabled | Appends ["", ""] to headers |
| Step body textarea | textarea | (no explicit label in Field) | always | Edits step.body |
| Extraction name input (ExtractionRows) | input | `"Step ${index + 1} extraction ${pos + 1} name"` | always | Edits entry.name |
| Extraction source select | select | `"Step ${index + 1} extraction ${pos + 1} source"` | always | Edits entry.fromKind: "body" or "header" |
| Extraction header name input | input | `"Step ${index + 1} extraction ${pos + 1} header name"` | entry.fromKind === "header" | Edits entry.header |
| Extraction method select | select | `"Step ${index + 1} extraction ${pos + 1} method"` | always | Edits entry.how: "regex", "json_path", "whole" |
| Extraction pattern input | input | `"Step ${index + 1} extraction ${pos + 1} pattern"` | !disabled && (how !== "whole") | Edits entry.pattern |
| Extraction capture group input | input | `"Step ${index + 1} extraction ${pos + 1} capture group"` | !disabled && how === "regex" | Edits entry.group |
| Remove extraction icon button | icon-button | `"Remove step ${index + 1} extraction ${pos + 1}"` | always | Filters extraction from step.extract |
| Add extraction button | button | (no explicit label) | !disabled | Appends empty ExtractDraft to step.extract |
| Revert button (editor) | button | (no explicit label) | dirty && baseline !== "" | Reverts editing to baseline JSON parse; toast.success |
| Save rule button | button | (no explicit label) | !wired \|\| saveRule.isPending | Calls onSave(); saves rule to server |
| Close editor icon button | icon-button | "Close the rule editor" | always | Clears editing and baseline; closes editor panel |
| Probe method input | input | "Probe method" | always | Edits probe.method |
| Probe URL input | input | "Probe URL" | always | Edits probe.url |
| Probe header name input (HeaderPairs) | input | "Probe header {index + 1} name" | always | Edits probe.headers[index][0] |
| Probe header value input (HeaderPairs) | input | "Probe header {index + 1} value" | always | Edits probe.headers[index][1] |
| Remove probe header icon button | icon-button | "Remove Probe header {index + 1}" | always | Filters header from probe.headers |
| Add probe header button | button | (no explicit label) | !disabled | Appends ["", ""] to probe.headers |
| Probe body textarea | textarea | (no explicit label) | always | Edits probe.body |
| Run login button | button | (no explicit label) | !wired \|\| login.isPending | Calls runLogin(); sends probe via login.mutate() |
| Update macro button (promotable) | button | (no explicit label) | !promoteMacro.isPending | Calls promoteMacro.mutate(promotable.id); replaces rule macro with observed steps |
| Confirm delete modal | modal | "Delete this session rule?" | confirmDelete !== null | Two buttons: Keep it, Delete rule |
| Keep it button | button | (no explicit label) | always | Closes modal; setConfirmDelete(null) |
| Delete rule button (modal) | button | (no explicit label) | !deleteRule.isPending | Calls onDelete(confirmDelete) |

### Sub-tabs

| Sub-tab | Renders when | Contents summary |
|---------|--------------|------------------|
| Login rules list | always (top of page) | SimpleTable with switches, name, hosts, steps, extractions, max attempts, edit/delete buttons |
| Rule editor | editing !== null | Multi-section form: name, enabled, max attempts, scope hosts, validity check fields, macro steps with headers/body/extractions, revert/save/close buttons |
| Login probe section | always (middle) | Method and URL inputs, headers editor, body textarea, run login button, result detail list, promoted macro offer |
| Cookie jar section | always (bottom) | SimpleTable with host, name, value; refresh button |
| Delete confirmation modal | confirmDelete !== null | Modal with description and two buttons |

### Keyboard shortcuts

| Keys | Scope | Condition | Action |
|------|-------|-----------|--------|
| (none defined) | - | - | - |

### Data hooks

| Hook | Endpoint or key | Enabled when | Consumed by |
|------|-----------------|--------------|------------|
| useSessionRulesFull() | /api/session/rules | always (onLoad) | rulesQuery; displays in table; open() uses |
| useSessionCookies() | /api/session/cookies | always (onLoad) | cookiesQuery; displays cookie jar table |
| useSaveSessionRule() | /api/session/rules (POST or PUT) | save button click | saveRule.mutate() in onSave and toggleEnabled |
| useDeleteSessionRule() | /api/session/rules/{id} (DELETE) | delete confirmation | deleteRule.mutate() in onDelete |
| useSessionLogin() | /api/session/login | run login button click | login.mutate() in runLogin |
| useUpdateSessionMacro() | /api/session/macro/{id} | promote button click | promoteMacro.mutate() in promotion action |

### Local state

| State | Initial value | Set by | Read by |
|-------|---------------|--------|---------|
| editing | null | open(), startNew(), null on close | RuleDraft form fields, dirty calc, all editors disabled if falsy |
| baseline | "" | open(), startNew(), onSave success | dirty calc, revert button |
| confirmDelete | null | delete button click, modal close | modal open condition, onDelete call |
| newHost | "" | Add host input, cleared after append | Add host button disabled, inline-add input value |
| probe | {method, url, headers, body, extract} | Probe inputs, runLogin success updates | Run login button, probe display |
| loginResult | null | runLogin.onSuccess | loginRows useMemo, DetailList display, probe response editor display, promotable offer |
| promotable | null | runLogin success (if outcome === "recovered") | Update macro button visibility, promoteMacro action |
| wired | rulesQuery.data?.wired ?? true | rulesQuery.data | Edit controls disabled if false; notice shown if false |
| rules | rulesQuery.data?.rules ?? [] | rulesQuery | Table rows, useEffect re-adoption of fresh rule on server change |
| dirty | editing !== null && JSON.stringify(editing) !== baseline | editing/baseline change | Save button disabled, badge tone, revert button enabled |

### Cross-page effects

| Effect | Trigger | Destination |
|--------|---------|-------------|
| (none identified; session rules are self-contained) | - | - |

### Action flows

**FLOW SESSION-1: Edit and save a login rule**
1. User clicks "New rule" or "Edit" on existing rule
2. startNew() or open(rule) called
3. RuleDraft created via emptyRule() or ruleIn(rule)
4. baseline = JSON.stringify(draft)
5. editing state set; editor panel renders
6. User edits name, enabled, max attempts, hosts, validity fields, macro steps
7. dirty = true (JSON differs from baseline)
8. User clicks "Save rule"
9. onSave validates: name.trim() !== "", steps.length > 0
10. ruleOut(editing) converts draft back to SessionRuleFull (flatten extractions, scope, etc.)
11. saveRule.mutate(payload) (POST for new, PUT for existing)
12. Backend creates/updates rule; returns { rule: { id, ... } }
13. onSuccess: Extract assigned id; re-encode to RuleDraft; update baseline; toast.success
14. onError: toast.error
15. Visible result: Rule appears in table; if new, id assigned; editor closed on success or error swallows on failure (user can retry)

**FLOW SESSION-2: Revert unsaved edits**
1. User makes changes; dirty becomes true
2. Revert button enabled
3. User clicks "Revert"
4. setEditing(JSON.parse(baseline)) restores prior state
5. dirty becomes false
6. toast.success "Reverted to the saved rule"
7. Visible result: Form fields revert to last-saved values

**FLOW SESSION-3: Delete a login rule**
1. User clicks delete icon on rule row
2. setConfirmDelete(id) opens modal
3. User clicks "Delete rule" in modal
4. onDelete(id) called
5. deleteRule.mutate(id)
6. Backend deletes rule; returns success
7. onSuccess: If editing?.id === id, clear editor; if promotable?.id === id, clear promotable; toast.success
8. zustand store updates rules list (refetch or immediate update)
9. Visible result: Rule disappears from table; editor closes if was open; modal closes

**FLOW SESSION-4: Test session validity with probe**
1. User fills probe method, URL, optional headers/body
2. User clicks "Run login now"
3. runLogin() validates probe.url.trim() !== ""
4. If empty: toast.error "The probe needs a URL…"
5. Else: login.mutate(step) where step = { method, url, headers (filtered), body }
6. Backend runs probe against all matching rules; replays macros if session invalid; checks validity
7. Returns SessionLoginResponse { outcome, rule_id, rule, url, rules, login_attempts, step_index, validity, response, hint, error }
8. onSuccess: setLoginResult(result), tone = OUTCOME_TONE[outcome], toast (success if tone==="good", error else)
9. If outcome === "recovered" && rule_id is number: setPromotable({ id: rule_id, name })
10. onError: setLoginResult(null), toast.error
11. Visible result: loginRows useMemo builds DetailList; probe response shown if response.body exists; Update macro button appears if promotable

**FLOW SESSION-5: Promote observed login steps to macro**
1. User runs login that recovers session (outcome === "recovered")
2. promotable button appears with rule id and name
3. User clicks "Update macro from this run"
4. promoteMacro.mutate(promotable.id)
5. Backend replaces rule's macro steps with steps observed during recovery
6. Returns { steps: [...] }
7. onSuccess: toast.success with step count; setPromotable(null) hides button
8. onError: toast.error
9. Visible result: Rule's macro now matches the observed login flow; editor will show new steps if opened

**FLOW SESSION-6: Enable/disable rule (toggle without editing)**
1. User clicks switch on rule row
2. toggleEnabled(rule, checked) called
3. saveRule.mutate({ ...rule, enabled: checked })
4. Backend updates rule.enabled
5. onSuccess: toast.success with enabled/paused message
6. onError: toast.error
7. Visible result: Rule's enabled state toggled; switch reflects new value; no editor opens

### Empty / loading / error states

| Condition | What renders | Exact copy |
|-----------|--------------|-----------|
| rulesQuery.isLoading | LoadingPanel | "Loading session rules" |
| rulesQuery.error | ErrorNotice | (error.message) with onRetry |
| !wired | notice-warn | (rulesQuery.data?.hint \|\| "Session re-login is not attached to this process, so nothing here can run.") |
| rules.length === 0 | Empty component | "No session rules" / "Create a rule to describe how to log in again when the proxy sees an expired session." |
| !editing | Rule editor Card not rendered | (rule editor only shows when editing !== null) |
| dirty | Badge | "unsaved changes" (tone="warn") |
| !dirty && editing | Badge | "saved" (tone="good") |
| saveRule.isPending | Button text | "Saving…" |
| login.isPending | Button text | "Running…" |
| promoteMacro.isPending | Button text on Update macro | (disabled) |
| !loginResult | DetailList/HttpEditor not rendered | (hidden until login run returns) |
| loginResult && !promotable | Update macro button hidden | (button hidden when promotable === null) |
| cookiesQuery.isFetching | RefreshButton showing loading state | (refresh button animated) |
| cookiesQuery.error | ErrorNotice | (error.message) with onRetry |
| cookiesQuery.data?.wired === false | notice-warn | (cookiesQuery.data.hint \|\| "The cookie jar is not attached to this process.") |
| cookieRows.length === 0 | Empty component | "No cookies to show" / "The coordinator's jar has no enumeration API in this build, so it reports as attached with an empty table rather than inventing entries." |
| !wired on rule editor | All controls disabled | (disabled prop on all inputs/buttons/selects/switches) |
| nested validity | notice-warn | "This rule combines conditions with all / any / not. Those nested branches are kept exactly as saved — the fields above edit the flat conditions only." |
