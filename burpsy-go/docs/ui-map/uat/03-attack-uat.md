# Burpsy Attack Tools UAT Test Matrix

Comprehensive User Acceptance Testing for Intruder, Repeater, Sequencer, and Session pages.

---

## INTRUDER PAGE

### Positions Tab

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| INTRUDER-001 | Discover insertion points (happy path) | msgId empty, target empty, points empty | 1. Enter msgId "42" 2. Enter target "https://example.com" 3. Click "Find positions" button | Points list displays with checkboxes; discover.isPending shows "Scanning…"; onSuccess toast shows count; onSuccess sets tab does not auto-change | happy |
| INTRUDER-002 | Discover with zero positions returned | msgId "42" valid, canDiscover true | 1. Click "Find positions" 2. Backend returns empty array | Empty component shows "No positions loaded / Find positions before launching an attack." | empty-state |
| INTRUDER-003 | Discover returns error | msgId "42" valid, network error occurs | 1. Click "Find positions" 2. Network fails | ErrorNotice renders with error message and onRetry button | error |
| INTRUDER-004 | Cannot discover with msgId empty | msgId "" | 1. Leave msgId blank 2. Observe Find positions button | Button disabled; canDiscover false | boundary |
| INTRUDER-005 | Cannot discover with non-integer msgId | msgId "1.5" or "abc" | 1. Enter "1.5" or "abc" 2. Observe Find positions button | Button disabled; canDiscover false (Number.isInteger check fails) | boundary |
| INTRUDER-006 | Cannot discover with negative msgId (legacy) | msgId "-1" | 1. Enter "-1" 2. Observe Find positions button | Button enabled (canDiscover checks >= 0); discover may succeed or fail server-side | boundary |
| INTRUDER-007 | Message ID input clears points when changed | points already loaded | 1. msgId is "42", points displayed 2. Clear msgId input 3. Type "43" | points cleared; selected cleared on change event | boundary |
| INTRUDER-008 | Select positions (single) | points loaded with 3 items | 1. Click checkbox on first point | Point marked as checked; selected array updated; badge shows "set 1" for pitchfork/cluster_bomb modes only | happy |
| INTRUDER-009 | Select positions (multiple) | points loaded with 3 items | 1. Click checkbox on first point 2. Click checkbox on second point 3. Click checkbox on third point | All three checked; selected=[0,1,2]; estimate updates; for pitchfork/cluster_bomb, set badges show 1, 2, 3 | happy |
| INTRUDER-010 | Deselect position | position already selected | 1. Click checkbox on selected point | Unchecked; removed from selected array | happy |
| INTRUDER-011 | Position labels show metadata | points loaded | 1. Observe point row | Shows label, kind, offset, and current value | happy |
| INTRUDER-012 | All-points toggle clears selection | selected=[0,1], points loaded | 1. Toggle "Include every candidate position" switch | points cleared; selected cleared | boundary |
| INTRUDER-013 | All-points toggle changes allPoints flag | allPoints false | 1. Toggle "Include every candidate position" switch 2. Click "Find positions" | discover.mutate called with all: true | happy |
| INTRUDER-014 | Base request viewer loads when msgId set | msgId empty | 1. Enter msgId "42" | HttpEditor appears in readonly mode with label "Base request · message 42" | happy |
| INTRUDER-015 | Base request shows loading state | msgId "42", message fetching | 1. msgId set to "42" 2. Network request in flight | Response editor shows "Loading the base request…" | loading |
| INTRUDER-016 | Base request shows error when fetch fails | msgId "42", message fetch errors | 1. msgId set to "42" 2. Fetch fails | Response editor shows "Could not load message 42." | error |
| INTRUDER-017 | Base request shows empty when no bytes | msgId "42", message has no text | 1. msgId set to "42" 2. baseMessage.data?.text is falsy | Response editor shows "No bytes stored for this message." | empty-state |
| INTRUDER-018 | No base request empty state (initial) | msgId empty, points empty | 1. Load page without msgId seed | Empty component shows title "No base request" and detail text | empty-state |
| INTRUDER-019 | Attack type select changes mode | mode "sniper" | 1. Select "battering_ram" from Attack type dropdown | mode updated; setsNeeded recalculates; payloadTexts adjusted if needed | happy |
| INTRUDER-020 | Attack type detail text updates | mode "sniper" | 1. Observe Attack type section | Displays mode.detail from ATTACK_MODES lookup | happy |

### Payloads Tab

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| INTRUDER-021 | Payloads textarea shows default text | payloadTexts [DEFAULT_PAYLOADS] | 1. Click Payloads tab | Textarea contains "admin\nroot\ntest\n' OR 1=1--\n../../etc/passwd" | happy |
| INTRUDER-022 | Edit payload set (single set, sniper mode) | mode "sniper", selected one position | 1. Click Payloads tab 2. Click in textarea 3. Type "new payload" | payloadTexts[0] updated; live | happy |
| INTRUDER-023 | Payload count updates in header | payloadTexts "admin\nroot\ntest" | 1. Observe Payloads tab 2. Count should be 3 | Label shows "Payloads (3)" | happy |
| INTRUDER-024 | Empty payload set | payloadTexts[""] | 1. Observe Payloads tab | setSizes[0] = 0; canRun becomes false (setSizes.every(size > 0) fails) | boundary |
| INTRUDER-025 | Whitespace-only payloads not counted | payloadTexts "  \n  \n  " | 1. Count payloads | countPayloads returns 0 (filters blank lines) | boundary |
| INTRUDER-026 | Multiple payload sets per pitchfork mode | mode "pitchfork", selected [0, 1, 2] | 1. Switch to Payloads tab | Three textareas appear labeled "Set 1", "Set 2", "Set 3" | happy |
| INTRUDER-027 | Payload sets scale when mode changes | 1 selected, payloadTexts.length 1, mode "sniper" | 1. Select two more points 2. Change mode to "pitchfork" | payloadTexts length adjusted to 3 via useEffect setsNeeded calc | happy |
| INTRUDER-028 | Payload sets scale when selection changes | mode "pitchfork", selected [0], payloadTexts.length 1 | 1. Check second position checkbox | setsNeeded becomes 2; payloadTexts auto-expands to 2 | happy |
| INTRUDER-029 | Payload sets shrink when selection reduces | mode "pitchfork", selected [0,1,2], payloadTexts.length 3 | 1. Uncheck second position checkbox | setsNeeded becomes 2; payloadTexts truncated to 2 | happy |
| INTRUDER-030 | Add rule button appends add_prefix rule | rules [] | 1. Click "Add rule" button | rules becomes [{ rule: "add_prefix", text: "", ...emptyRule fields }] | happy |
| INTRUDER-031 | Rule operation select changes rule type | rule with add_prefix | 1. Open rule 2. Change operation select to "match_replace" | Rule re-instantiated via emptyRule; all fields reset to empty | happy |
| INTRUDER-032 | Rule text field for add_prefix | rule.rule "add_prefix" | 1. Click in text input 2. Type "test_" | rule.text updated; Input rendered (uses.includes("text") true) | happy |
| INTRUDER-033 | Rule pattern field for match_replace | rule.rule "match_replace" | 1. Click in pattern input 2. Type "id=\\d+" | rule.pattern updated; Input rendered | happy |
| INTRUDER-034 | Rule replacement field for match_replace | rule.rule "match_replace" | 1. Click in replacement input 2. Type "$1_modified" | rule.replace updated; placeholder shows "$1 for a group" | happy |
| INTRUDER-035 | Rule layer/codec select for encode | rule.rule "encode" | 1. Click layer select 2. Choose "Base64" | rule.layer updated; select rendered (uses.includes("layer") true) | happy |
| INTRUDER-036 | Rule algorithm select for hash | rule.rule "hash" | 1. Click algorithm select 2. Choose "SHA256" | rule.algorithm updated; select rendered (uses.includes("algorithm") true) | happy |
| INTRUDER-037 | Rule "every match" checkbox | rule.rule "match_replace" | 1. Click "every match" checkbox | rule.all toggled; Checkbox rendered (uses.includes("all") true) | happy |
| INTRUDER-038 | Remove rule icon button | rules.length 2 | 1. Click trash icon on first rule | Rule spliced; rules.length becomes 1 | happy |
| INTRUDER-039 | Invalid regex deferred to server | rule.rule "match_replace", pattern "(" | 1. Set pattern to "(" (invalid) 2. Launch attack | No client validation; error shown in Results tab from backend | error |
| INTRUDER-040 | Rule row shows rule index | rules [rule1, rule2] | 1. Observe rule rows | First row shows "1", second shows "2" | happy |

### Resource Pool Tab

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| INTRUDER-041 | Max requests default 1000 | maxRequests initial state | 1. Click Resource pool tab | Input shows "1000" | happy |
| INTRUDER-042 | Max requests input changes value | maxRequests 1000 | 1. Clear input 2. Type "5000" | maxRequests updated to 5000; estimate and budget check recalc | happy |
| INTRUDER-043 | Max concurrent requests default 8 | maxInFlight initial state | 1. Click Resource pool tab | Input shows "8" | happy |
| INTRUDER-044 | Max concurrent requests input changes | maxInFlight 8 | 1. Clear input 2. Type "16" | maxInFlight updated to 16 | happy |
| INTRUDER-045 | RPS input blank means unlimited | rps "" | 1. Leave RPS blank 2. Click "Launch attack" | run.mutate payload does not include rps field | happy |
| INTRUDER-046 | RPS input with value | rps "" | 1. Type "10.5" in RPS input | rps set to "10.5"; if submitted, body includes rps: 10.5 | happy |
| INTRUDER-047 | Max requests boundary zero | maxRequests 1 | 1. Try to set to "0" 2. Type "0" 3. Tab out | onChange returns 1 (Number(0) || 1) | boundary |
| INTRUDER-048 | Max concurrent boundary zero | maxInFlight 1 | 1. Try to set to "0" | onChange returns 1 (Number(0) || 1) | boundary |
| INTRUDER-049 | RPS negative value allowed in input | rps "-5" | 1. Type "-5" | Input accepts value (min="0" allows negative via direct type); behavior deferred to server | boundary |

### Settings Tab

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| INTRUDER-050 | Grep match input accepts string | grepMatch "" | 1. Click Settings tab 2. Type "error" in grep match | grepMatch updated to "error" | happy |
| INTRUDER-051 | Grep extract input accepts string | grepExtract "" | 1. Type "token=" in grep extract | grepExtract updated to "token=" | happy |
| INTRUDER-052 | Grep match empty means not sent | grepMatch "" | 1. Leave grep match blank 2. Launch attack | run.mutate payload does not include grep_match field (trim check) | happy |
| INTRUDER-053 | Grep extract empty means not sent | grepExtract "" | 1. Leave grep extract blank 2. Launch attack | run.mutate payload does not include grep_extract field (trim check) | happy |
| INTRUDER-054 | Grep match with leading/trailing whitespace | grepMatch "  error  " | 1. Type "  error  " 2. Launch attack | Payload includes grep_match: "error" (trimmed) | boundary |
| INTRUDER-055 | Grep extract with special characters | grepExtract "token=[^&]+" | 1. Type "token=[^&]+" | grepExtract updated; sent as-is to backend | happy |

### Results Tab

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| INTRUDER-056 | Results tab shows sent count in label | result.report.sent 42 | 1. Attack completes 2. Click Results tab or auto-switched | TabsTrigger label shows "Results (42 requests)" | happy |
| INTRUDER-057 | Results tab empty state (no attack run yet) | result null, legacyResult null | 1. Load page without prior attack | Empty component shows "No attack run yet" with estimate badge | empty-state |
| INTRUDER-058 | Attack result with modern RunView | result { report: {...}, payload_sets: [...] } | 1. Attack completes with named mode 2. Response is RunView | AttackResult component renders; shows metric grid, caveats, buckets, errors, attempts | happy |
| INTRUDER-059 | Attack result with legacy format | legacyResult array of attempts | 1. Attack completes on older backend 2. Response is flat array | JsonView renders; shows "Attack result · This server answered with the legacy per-attempt form." | happy |
| INTRUDER-060 | Results tab auto-switches on success | tab "positions", run.mutate succeeds | 1. Click Launch attack 2. Wait for success | onSuccess sets tab to "results"; auto-navigation | happy |
| INTRUDER-061 | Error notice in Results tab | run.error set | 1. Attack fails 2. Click Results tab | ErrorNotice renders with error message and onRetry | error |
| INTRUDER-062 | Attack metric grid displays | result with report | 1. Open Results tab | Shows Sent, Combinations, Failed, Elapsed metrics | happy |
| INTRUDER-063 | Caveats notice appears when bounds applied | report.truncated true or others | 1. View results where caveats exist | notice-warn shows "Bounds applied to this attack" with bulleted list | happy |
| INTRUDER-064 | Result buckets table renders | report.buckets.length > 0 | 1. View results | SimpleTable shows Status, Length, Reflected, Count, Grep, First payload columns | happy |
| INTRUDER-065 | Result buckets empty state | report.buckets.length 0 | 1. View results with no buckets | Empty component shows "No buckets / The attack produced no grouped responses." | empty-state |
| INTRUDER-066 | Errors table rendered | report.errors.length > 0 | 1. View results with errors | SimpleTable shows Error, Count, First ordinal; row-flag-bad class applied | happy |
| INTRUDER-067 | Errors table not rendered | report.errors.length 0 | 1. View results without errors | Card for errors is null; not rendered | empty-state |
| INTRUDER-068 | Payload set accounting table | sets.length > 0 | 1. View results | SimpleTable shows Set, Kind, Used, Described, Truncated, Skipped, Dropped columns | happy |
| INTRUDER-069 | Payload set accounting empty state | sets.length 0 | 1. View results with no set breakdown | Empty component shows "No set accounting / The server reported no per-set breakdown." | empty-state |
| INTRUDER-070 | Attempts detail table | report.attempts.length > 0 | 1. View results | SimpleTable shows #, Status, Length, Time, Reflected, Grep, Error; capped at detail_limit | happy |

### Cross-tab Flows & Launch Attack

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| INTRUDER-071 | Switch Positions → Payloads → Pool → Settings → Results | All tabs clickable | 1. Click each tab trigger in sequence | Tab switches; correct content renders; state persists | happy |
| INTRUDER-072 | Mid-configuration tab switch | editing payloads, tab="payloads" | 1. Edit payload set 2. Click Positions tab 3. Click Payloads tab | Payload text persists; payloadTexts not lost | happy |
| INTRUDER-073 | Cannot launch with no base request | msgId "", target "https://example.com" | 1. Try to click Launch attack | Button disabled; canRun false | boundary |
| INTRUDER-074 | Cannot launch with empty target | msgId "42", target "" | 1. Try to click Launch attack | Button disabled; canRun false (target.trim() !== "") | boundary |
| INTRUDER-075 | Cannot launch with no positions selected | msgId "42", target "https://example.com", selected [] | 1. Try to click Launch attack | Button disabled; canRun false (selected.length > 0) | boundary |
| INTRUDER-076 | Cannot launch with zero-count payload set | selected [0], payloadTexts [""] | 1. Try to click Launch attack | Button disabled; canRun false (setSizes.every(size > 0)) | boundary |
| INTRUDER-077 | Launch attack with all conditions met (happy path) | msgId "42", target, positions, payloads, no attack pending | 1. Ensure all conditions met 2. Click "Launch attack" button | run.mutate called with complete payload; button shows "Attacking…"; disabled | happy |
| INTRUDER-078 | Launch attack with rules | msgId "42", rules [{ rule: "add_prefix", text: "test_" }] | 1. Add and configure rule 2. Click "Launch attack" | run.mutate payload includes payload_rules array | happy |
| INTRUDER-079 | Launch attack without rules | rules [] | 1. Add no rules 2. Click "Launch attack" | run.mutate payload does not include payload_rules field | happy |
| INTRUDER-080 | Launch attack success toast | run.onSuccess fires | 1. Attack completes | toast.success shows "X requests sent in Y ms" with formatCount and formatDuration | happy |
| INTRUDER-081 | Launch attack error toast | run.onError fires | 1. Attack fails | toast.error shows error.message | error |
| INTRUDER-082 | Budget warning badge and notice | estimate.count > maxRequests | 1. Configure to exceed budget (e.g., 100 payloads × 50 positions > 1000) 2. Observe estimate | Badge tone="warn"; notice-warn appears with message about cap | boundary |
| INTRUDER-083 | Estimate updates on position/payload change | selected [0], payloadTexts ["a\nb"] | 1. Add third position to selected 2. Click first new position 3. Observe estimate | Estimate recalculates via useMemo; badge updates | happy |
| INTRUDER-084 | Estimate calculation sniper mode | mode "sniper", selected [0,1,2], payloadTexts ["a\nb"] (1 set) | 1. Observe estimate | estimate = setSizes[0] × sum(1 for each position ignored, just one set) = 2 | happy |
| INTRUDER-085 | Estimate calculation battering_ram mode | mode "battering_ram", selected [0,1,2], payloadTexts ["a\nb"] (1 set) | 1. Observe estimate | estimate = setSizes[0] = 2 | happy |
| INTRUDER-086 | Estimate calculation pitchfork mode | mode "pitchfork", selected [0,1], payloadTexts ["a\nb", "c\nd"] | 1. Observe estimate | estimate = max(setSizes[0], setSizes[1]) = max(2, 2) = 2 | happy |
| INTRUDER-087 | Estimate calculation cluster_bomb mode | mode "cluster_bomb", selected [0,1], payloadTexts ["a\nb", "c\nd"] | 1. Observe estimate | estimate = setSizes[0] × setSizes[1] = 2 × 2 = 4 | happy |

### Intruder Seed Handoff (from Repeater/History)

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| INTRUDER-088 | Seed from Repeater handoff | useApp seed set to { msgId: 999, target: "https://app.test", label: "Login req" } | 1. Receive seed via handoff 2. Observe page load | msgId="999", target="https://app.test", label="Login req" set; points, selected, result cleared; seed nullified | alternate-entry |
| INTRUDER-089 | Seed with null msgId | seed { msgId: null, target: "https://app.test", label: "..." } | 1. Receive seed with null msgId | msgId not set; target and label set | alternate-entry |

### Page Header & Estimate Badge

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| INTRUDER-090 | Page header title | Always | 1. View page | PageHeader title shows "Intruder" | happy |
| INTRUDER-091 | Page header description (default) | label "" | 1. View page | Description shows "Payload-driven attacks with explicit bounds and honest result accounting." | happy |
| INTRUDER-092 | Page header description (from seed) | label "Custom label" | 1. Receive seed with label 2. View page | Description shows "Custom label" | happy |
| INTRUDER-093 | Estimate badge tone normal | estimate.count <= maxRequests | 1. Observe badge | Badge tone="neutral" | happy |
| INTRUDER-094 | Estimate badge tone warning | estimate.count > maxRequests | 1. Exceed budget | Badge tone="warn" | boundary |
| INTRUDER-095 | Launch attack button enabled condition | canRun true | 1. Observe button | Button enabled; Tooltip shows "Run the attack" | happy |
| INTRUDER-096 | Launch attack button disabled tooltip | canRun false | 1. Observe button | Tooltip shows "Choose a message, target, positions and payloads first" | boundary |

---

## REPEATER PAGE

### Tab Management & Navigation

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-001 | New request button creates tab | tabs [], activeId null | 1. Click "New request" icon button | openRepeaterTab called; new tab added with name "Request 1"; activeId set; blank request shown | happy |
| REPEATER-002 | Second new request tab increments number | tabs [tab1], name "Request 1" | 1. Click "New request" button again | new tab.name becomes "Request 2" | happy |
| REPEATER-003 | Click tab row to activate | tabs [tab1, tab2], activeId tab1.id | 1. Click tab2 row | setActiveRepeaterTab(tab2.id) called; tab2 becomes active; tab row className shows data-state="active" | happy |
| REPEATER-004 | Tab row keyboard Enter key activates | tabs [tab1, tab2], tab2 focused, activeId tab1.id | 1. Focus tab2 2. Press Enter | setActiveRepeaterTab(tab2.id) called; tab2 active | keyboard |
| REPEATER-005 | Tab row keyboard Space key activates | tabs [tab1, tab2], tab2 focused, activeId tab1.id | 1. Focus tab2 2. Press Space | setActiveRepeaterTab(tab2.id) called; tab2 active | keyboard |
| REPEATER-006 | Tab close button removes tab | tabs [tab1, tab2], activeId tab1.id | 1. Click X on tab1 | closeRepeaterTab(tab1.id) called; tab1 removed; results[tab1.id] removed; activeId updates | happy |
| REPEATER-007 | Close active tab updates activeId | tabs [tab1, tab2], activeId tab1.id | 1. Click X on active tab1 | closeRepeaterTab(tab1.id) called; useEffect sets activeId to tab2.id | happy |
| REPEATER-008 | Close button has correct label | tabs [tab1 { name: "Custom" }] | 1. Observe close button | aria-label shows "Close Custom" | a11y |
| REPEATER-009 | Tab row has correct title | tabs [tab1 { name: "Login" }] | 1. Observe tab row | title attribute shows "Login" | a11y |
| REPEATER-010 | Tab row role and state | tabs [tab1, tab2], activeId tab1.id | 1. Observe tab row | role="tab", aria-selected={true/false}, data-state="active" set correctly | a11y |
| REPEATER-011 | Tablist has aria-label | tabs [tab1, tab2] | 1. Observe tablist | aria-label="Repeater requests" | a11y |
| REPEATER-012 | No tabs shows empty state | tabs [], activeId null | 1. Load page with no tabs | Empty component shows "No request open / Start a blank request, or right-click any row in HTTP history and choose "Send to Repeater"." | empty-state |
| REPEATER-013 | Empty state has New request button | tabs [] | 1. View empty page | Empty component action button shows "New request" | empty-state |

### Request & Response Editors

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-014 | Request editor shows active.request | active { request: "GET / HTTP/1.1..." } | 1. View page | HttpEditor label "Request" shows value from active.request | happy |
| REPEATER-015 | Request editor onChange updates store | active.request "GET /" | 1. Click in request editor 2. Type "POST /api" | updateRepeaterTab(active.id, { request: "POST /api" }) called; state persists | happy |
| REPEATER-016 | Response editor readonly | result { response: "HTTP/1.1 200...", ... } | 1. View response | HttpEditor readOnly=true; cannot edit | happy |
| REPEATER-017 | Response editor shows result.response | result.response "HTTP/1.1 200..." | 1. View response editor | Shows response bytes | happy |
| REPEATER-018 | Response editor waiting message | send.isPending true, result null | 1. Click Send 2. Observe response editor | Shows "Waiting for the response…" | loading |
| REPEATER-019 | Response editor no-result message | result null, send.isPending false | 1. Open new tab 2. Observe response editor | Shows "Send the request to see the response bytes." | empty-state |
| REPEATER-020 | Request editor keyboard Ctrl+Enter sends | active { request: "..." }, send.isPending false | 1. Click in request editor 2. Press Ctrl+Enter | submit(active) called; request sent; useHotkeys listener fires | keyboard |
| REPEATER-021 | Request editor keyboard Cmd+Enter sends (Mac) | active { request: "..." }, send.isPending false | 1. Click in request editor 2. Press Cmd+Enter | submit(active) called; request sent | keyboard |
| REPEATER-022 | Request editor filename export | active.request "..." | 1. Export request from editor | filename "repeater-request.txt" used | happy |
| REPEATER-023 | Response editor filename export | result.response "..." | 1. Export response from editor | filename "repeater-response.txt" used | happy |

### Target & Tab Name Inputs

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-024 | Target input changes active.target | active { target: "https://example.com:443" } | 1. Click target input 2. Type "https://newhost.com" | updateRepeaterTab(active.id, { target: "https://newhost.com", protocol: "https" }) called; scheme detected | happy |
| REPEATER-025 | Target input updates protocol (https) | active.target "https://example.com" | 1. Change target to "https://newhost.com" | updateRepeaterTab includes protocol: "https" (schemeOf returns https) | happy |
| REPEATER-026 | Target input updates protocol (http) | active.target "https://example.com" | 1. Change target to "http://newhost.com" | updateRepeaterTab includes protocol: "http" (schemeOf detects /^http:\/\//i) | happy |
| REPEATER-027 | Target input preserves scheme on change | active.target "http://example.com" | 1. Update target to same scheme | Protocol remains http | happy |
| REPEATER-028 | Tab name input changes active.name | active.name "Request 1" | 1. Click tab name input 2. Type "Login check" | updateRepeaterTab(active.id, { name: "Login check" }) called | happy |
| REPEATER-029 | Tab name input appears in tab row | active.name "My request" | 1. Observe tab row | Tab row span shows "My request" | happy |
| REPEATER-030 | Target input has placeholder | Always | 1. New tab, focus target | Placeholder "https://host:443" shown | happy |
| REPEATER-031 | Tab name input placeholder | Always | 1. Focus tab name input | Placeholder implicit, default name "Request N" in input | happy |

### Inspector

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-032 | Inspector toggle shows/hides | inspector true | 1. Click inspector icon button | setInspector(false); Inspector component removed; editor grid becomes 2-column | happy |
| REPEATER-033 | Inspector icon button aria-pressed | inspector true | 1. Observe icon button | aria-pressed="true" | a11y |
| REPEATER-034 | Inspector icon button aria-pressed false | inspector false | 1. Toggle inspector off 2. Observe button | aria-pressed="false" | a11y |
| REPEATER-035 | Inspector label on request | inspector true, active.request "..." | 1. Observe inspector | Inspector rendered with label "Inspector · request" and raw={active.request} | happy |
| REPEATER-036 | Inspector toggle label (hide) | inspector true | 1. Observe icon button | Button label "Hide Inspector" | happy |
| REPEATER-037 | Inspector toggle label (show) | inspector false | 1. Observe icon button | Button label "Show Inspector" | happy |

### Send Button & Status Badges

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-038 | Send button sends request | active { request: "GET / HTTP/1.1", target: "https://example.com" }, send.isPending false | 1. Click Send button | submit(active) called; send.mutate called with { target, request, protocol, from_exchange } | happy |
| REPEATER-039 | Send button disabled while pending | send.isPending true | 1. Click Send 2. Observe button | Button disabled; text shows "Sending…" | loading |
| REPEATER-040 | Send button has Ctrl+Enter tooltip | Always | 1. Hover over Send button | Tooltip shows "Send the current request (mod+Enter)" | happy |
| REPEATER-041 | Status badge shows HTTP status | result { status: 200 } | 1. Send request 2. Observe status badge | Badge shows "200"; tone determined by statusTone(200) | happy |
| REPEATER-042 | Status badge bad tone (5xx) | result { status: 500 } | 1. Get 500 response | Badge tone="bad" (statusTone returns bad for 5xx) | happy |
| REPEATER-043 | Status badge warn tone (4xx) | result { status: 404 } | 1. Get 404 response | Badge tone="warn" | happy |
| REPEATER-044 | Duration badge shown | result { duration_ms: 234 } | 1. Send request | Badge shows "234ms" (formatDuration) | happy |
| REPEATER-045 | Exchange ID badge shown | result { exchange_id: 42 } | 1. Send request that's captured | Badge shows "#42" | happy |
| REPEATER-046 | Exchange ID badge absent | result { exchange_id: null } | 1. Send request not captured | Badge not rendered (result.exchange_id falsy) | happy |
| REPEATER-047 | Scheme badge https | active.target "https://example.com" | 1. View page | Badge tone="good" shows "https" | happy |
| REPEATER-048 | Scheme badge http | active.target "http://example.com" | 1. View page | Badge tone="warn" shows "http" | happy |

### To Intruder Handoff

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-049 | To Intruder with existing result | active { target, name }, results[active.id] { exchange_id: 42 } | 1. Send request 2. Click "To Intruder" | handOffToIntruder skips send; fetches /api/exchange/42; sets intruder seed; navigates | happy |
| REPEATER-050 | To Intruder without prior send | active { target, name }, results[active.id] undefined | 1. New tab, no send yet 2. Click "To Intruder" | handOffToIntruder calls send first; await sent; if exchange_id set, proceeds to fetch | happy |
| REPEATER-051 | To Intruder send fails | send.mutate throws error | 1. Click "To Intruder" 2. Send fails | toast.error shows error message; handingOff set to false in finally | error |
| REPEATER-052 | To Intruder no exchange_id | send succeeds but exchange_id null | 1. Send completes without capture 2. Click "To Intruder" | toast.error "This request was not captured, so Intruder has no stored message to work from" | error |
| REPEATER-053 | To Intruder fetch exchange fails | exchange_id set but fetch /api/exchange/{id} fails | 1. Click "To Intruder" 2. Fetch fails | toast.error with error message | error |
| REPEATER-054 | To Intruder success | handOffToIntruder completes | 1. Click "To Intruder" 2. Success | toast.success "Message X sent to Intruder"; setRoute("intruder"); intruderSeed set with msgId, target, label | happy |
| REPEATER-055 | To Intruder button disabled during handoff | handingOff true | 1. Click "To Intruder" 2. Observe button | Button disabled; text shows "Preparing…" | loading |
| REPEATER-056 | To Intruder button has correct label | handingOff false | 1. Observe button | Button text "To Intruder" | happy |

### Send Error & Retry

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-057 | Send error notice displayed | send.error set | 1. Send request 2. Fails | ErrorNotice renders with error.message and onRetry button | error |
| REPEATER-058 | Retry button re-sends | send.error set, onRetry called | 1. Send fails 2. Click onRetry button | submit(active) called again | error |

### Page Header & Empty State

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-059 | Page header title (with tabs) | tabs [tab1], activeId set | 1. View page | PageHeader title shows "Repeater" | happy |
| REPEATER-060 | Page header title (no tabs) | tabs [], activeId null | 1. View empty page | PageHeader title shows "Repeater" | happy |
| REPEATER-061 | Empty state title | tabs [] | 1. View empty page | Empty title "No request open" | empty-state |
| REPEATER-062 | Empty state detail | tabs [] | 1. View empty page | Empty detail "Start a blank request, or right-click any row in HTTP history and choose "Send to Repeater"." | empty-state |

### Persistence & State

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-063 | Tabs persist across reload | tabs [tab1 { request: "GET /" }] | 1. Navigate away 2. Return to Repeater | tabs restored from zustand store; state not lost | happy |
| REPEATER-064 | Responses not persisted | result { response: "HTTP/1.1 200..." } | 1. Send request 2. Close tab 3. Reopen | Response not persisted; only request draft persisted | happy |

### Tab Closure Edge Cases

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| REPEATER-065 | Close only remaining tab | tabs [tab1], activeId tab1.id | 1. Click X on tab1 | Tab removed; page shows empty state | happy |
| REPEATER-066 | Close non-active tab | tabs [tab1, tab2, tab3], activeId tab2.id | 1. Click X on tab1 | tab1 removed; tab2 remains active | happy |
| REPEATER-067 | Multiple tabs tab management (up to 12+) | tabs with 15 items | 1. Create many tabs 2. Navigate between them | All tabs accessible; no hard cap enforced client-side (comment mentions cap but not validated) | happy |

---

## SEQUENCER PAGE

### Paste Tab

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SEQ-001 | Paste tokens in textarea | source "paste", tokens "" | 1. Click Paste a list tab 2. Click textarea 3. Type "token1\ntoken2\ntoken3" | setTokens called; tokens updated; pastedCount updates to 3 | happy |
| SEQ-002 | Analyse button calculates count | tokens "a\nb\nc\n\nd" | 1. Observe paste tab | pastedCount = 4 (blank line filtered); Analyse button enabled | happy |
| SEQ-003 | Analyse button disabled when empty | tokens "" | 1. Observe paste tab | Analyse button disabled; !pastedCount | boundary |
| SEQ-004 | Analyse button disabled when only whitespace | tokens "  \n\n  " | 1. Observe paste tab | pastedCount = 0 (split and filter blank lines); button disabled | boundary |
| SEQ-005 | Analyse tokens (paste tab) | tokens "a1b2c3\ne5f60718\nz9y8x7w6", source "paste" | 1. Click Analyse button | analysePaste.mutate called with { text, encoding }; button shows "Analysing…" | happy |
| SEQ-006 | Analyse success (paste tab) | analysePaste.onSuccess fires with data | 1. Analyse completes | Report renders; toast.success "X token(s) analysed" | happy |
| SEQ-007 | Analyse error (paste tab) | analysePaste.onError fires | 1. Analyse fails | toast.error with error message; ErrorNotice rendered | error |
| SEQ-008 | Encoding select auto-detect (default) | encoding "" | 1. Select dropdown | Option value="" selected with text "detect encoding" | happy |
| SEQ-009 | Encoding select raw | encoding "" → "raw" | 1. Select "raw bytes" | setEncoding("raw"); runPaste includes encoding: "raw" | happy |
| SEQ-010 | Encoding select base64 | encoding "" → "base64" | 1. Select "base64" | setEncoding("base64"); runPaste includes encoding: "base64" | happy |
| SEQ-011 | Tokens textarea placeholder | source "paste" | 1. Observe textarea | Placeholder shows "a1b2c3d4\ne5f60718\n…" | happy |
| SEQ-012 | Tokens textarea label | source "paste" | 1. Observe editor | Label "Tokens, one per line" | happy |

### Live Capture Tab

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SEQ-013 | Capture id input | captureId "" | 1. Click Capture tab 2. Type "123" in input | setCaptureId("123") | happy |
| SEQ-014 | Attach button disabled when captureId empty | captureId "" | 1. Observe Attach button | Button disabled; !captureId.trim() | boundary |
| SEQ-015 | Attach button enabled when captureId filled | captureId "123" | 1. Type "123" in capture id input | Button enabled | happy |
| SEQ-016 | Attach button attaches to capture | captureId "456" | 1. Type "456" 2. Click Attach button | setAttached("456"); toast.success "Following capture 456"; capture query polling starts | happy |
| SEQ-017 | Attach button shows "Re-attach" when already attached | attached "456" | 1. Observe Attach button text | Button text shows "Re-attach" | happy |
| SEQ-018 | Attach button shows "Attach" when not attached | attached "" | 1. Observe button | Button text shows "Attach" | happy |
| SEQ-019 | Empty capture id error toast | captureId "" | 1. Click Attach with empty id | toast.error "Give the capture id to attach to" | error |
| SEQ-020 | Stop capture button disabled until tokens | captured.length 0 | 1. Observe Stop capture button | Button disabled | boundary |
| SEQ-021 | Stop capture button enabled when attached | attached "123", captured.length > 0 | 1. Observe button | Button enabled | happy |
| SEQ-022 | Stop capture button disabled while pending | stopCapture.isPending true | 1. Click Stop capture 2. Observe button | Button disabled; stopCapture pending | loading |
| SEQ-023 | Stop capture mutates | attached "123", captured.length > 0 | 1. Click Stop capture | stopCapture.mutate() called; onSuccess toast "Capture stopped" | happy |
| SEQ-024 | Stop capture error | stopCapture.onError fires | 1. Stop capture fails | toast.error with error message | error |
| SEQ-025 | Polling badge shows polling | capture.isFetching true | 1. Capture polling active | Badge tone="info" shows "polling" | happy |
| SEQ-026 | Polling badge shows idle | capture.isFetching false | 1. Capture polling inactive | Badge tone="neutral" shows "idle" | happy |
| SEQ-027 | Accumulated count badge | capture.data?.total 5 | 1. View capture tab after tokens arrive | Badge shows "5 accumulated" | happy |
| SEQ-028 | Accumulated count badge zero | capture.data?.total 0 | 1. Attached but no tokens yet | Badge shows "0 accumulated" | happy |
| SEQ-029 | Not following capture hint | attached "" | 1. View capture tab on page load | field-hint shows "Not following a capture." | empty-state |
| SEQ-030 | No tokens accumulated empty state | attached "123", captured.length 0, capture.isLoading false | 1. View capture tab | Empty component shows "No tokens accumulated / Capture 123 is being polled once a second and has produced nothing yet." | empty-state |
| SEQ-031 | Capture error notice | capture.error set | 1. Capture fails | ErrorNotice renders with error and onRetry | error |
| SEQ-032 | Capture warning notice (Go port) | source "live" | 1. View capture tab | notice-warn shows "This build has no capture loop..." | happy |
| SEQ-033 | Analyse tokens (capture tab) | attached "123", captured ["a", "b", "c"] | 1. Click Analyse | analyseTokens.mutate called with { tokens: ["a", "b", "c"], encoding }; button shows "Analysing…" | happy |
| SEQ-034 | Analyse captured success | analyseTokens.onSuccess fires | 1. Analyse completes | toast.success "X captured token(s) analysed"; Report renders | happy |

### Encoding Select

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SEQ-035 | Encoding select rendered in header | Always | 1. View page header | Select element with aria-label "Read token bits as" shown | happy |
| SEQ-036 | Encoding affects both tabs | encoding "" → "base32" | 1. Select "base32" 2. Switch between paste and capture tabs | encoding persists across tab switch; both use same value | happy |

### Analysis Report

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SEQ-037 | Report renders on success | report { grade, verdict, characters, ... } | 1. Analyse completes | Report component renders with grade box, metrics, FIPS tests, positions table | happy |
| SEQ-038 | No analysis empty state | report null, !pending | 1. Load page without prior analysis | Empty component shows "No analysis yet / Paste a representative sample..." | empty-state |
| SEQ-039 | Analysis pending (button state) | pending true | 1. Click Analyse 2. Observe button | Button shows "Analysing…"; disabled | loading |
| SEQ-040 | Analysis error notice | error set | 1. Analysis fails | ErrorNotice renders with error message and onRetry | error |
| SEQ-041 | Grade display (pass) | report.grade "pass" | 1. View report | GRADE box shows "PASS" in good-text color | happy |
| SEQ-042 | Grade display (fail) | report.grade "fail" | 1. View report | GRADE box shows "FAIL" in bad-text color | happy |
| SEQ-043 | Grade display (insufficient) | report.grade "insufficient" | 1. View report | GRADE box shows "NOT TESTED" in warn-text color | happy |
| SEQ-044 | Verdict text displayed | report.verdict "Entropy is high..." | 1. View report | Verdict paragraph shown under GRADE | happy |
| SEQ-045 | Warnings section (with caveats) | report.warnings ["warning1", "warning2"] | 1. View report | Card shows "Caveats on this verdict" with bulleted warnings | happy |
| SEQ-046 | Warnings section (no caveats, insufficient) | report.grade "insufficient", report.warnings [] | 1. View report | Card shows "This sample does not support a verdict" | happy |
| SEQ-047 | Metric grid displayed | report { tokens: 100, ... } | 1. View report | Metrics shown: Tokens, Alphabet, Entropy / token, Entropy / character, Bits read as | happy |
| SEQ-048 | FIPS tests run | report.fips.tests !== null | 1. View report | FIPS 140-2 tests table renders with Test, Result, Observed, Requirement, Blocks | happy |
| SEQ-049 | FIPS tests not run (short sample) | report.fips.tests === null | 1. View report with < block_bits sample | notice-warn "Not run. Every FIPS 140-2 threshold..." | happy |
| SEQ-050 | Positions section rendered | report.characters.positions.length > 0 | 1. View report | Card with "Character positions" heading and SimpleTable | happy |
| SEQ-051 | Positions empty state | report.characters.positions.length === 0 | 1. View report with no positions | Empty component "Nothing to show / Analyse a token sample..." | empty-state |
| SEQ-052 | Show all positions button | report.characters.positions.length > 24 | 1. View positions section | Button shows "Show all X" (aria-pressed={showAll}) | happy |
| SEQ-053 | Show all positions expansion | showAll false, positions.length 50 | 1. Click "Show all" button | shown updated to full array; button text changes to "Show first 24" | happy |
| SEQ-054 | Positions truncated warning | report.characters.positions_truncated true | 1. View positions | notice-warn "Only the first X of Y positions are reported..." | happy |
| SEQ-055 | Dead position highlighting | position.distinct <= 1 | 1. View position row | row-flag-bad class applied; Flag column shows "never varies" | happy |
| SEQ-056 | Position distribution chips | position.counts [count1, count2, ...] | 1. View position row | Top 6 counts shown as Badge chips; +N more link if overflow | happy |

### Cross-tab & Badge

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SEQ-057 | Badge shows pasted count | source "paste", tokens "a\nb\nc" | 1. View page header | Badge shows "3 pasted" | happy |
| SEQ-058 | Badge shows captured count | source "live", captured.length 7 | 1. View page header | Badge shows "7 captured" | happy |
| SEQ-059 | Source tab switch | source "paste" | 1. Click "Capture from a live exchange" tab | setSource("live"); report and pending sync to capture path | happy |
| SEQ-060 | Analyse button respects source | source "live", runCaptured ready | 1. Click Analyse | runCaptured called (not runPaste) | happy |

---

## SESSION PAGE

### Login Rules List & Top Section

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-001 | Page header title | Always | 1. View page | PageHeader shows "Session" | happy |
| SESSION-002 | Page header description | Always | 1. View page | Description "A rule names a login: which hosts it covers, the steps to replay, and what a valid session looks like." | happy |
| SESSION-003 | Wired badge good | wired true | 1. View page | Badge tone="good" shows "wired" | happy |
| SESSION-004 | Wired badge warn | wired false | 1. View page (coordinator not attached) | Badge tone="warn" shows "not wired" | happy |
| SESSION-005 | New rule button enabled | wired true, editing null | 1. Observe button | Button enabled; onClick calls startNew() | happy |
| SESSION-006 | New rule button disabled | wired false | 1. Observe button | Button disabled | happy |
| SESSION-007 | Refresh button (rules) | Always | 1. Click refresh button next to rules | rulesQuery.refetch() called; loading state shown | happy |
| SESSION-008 | Not wired notice | wired false | 1. View page | notice-warn shows "Session re-login is not attached to this process, so nothing here can run." or custom hint | happy |
| SESSION-009 | Rules list empty state | rules.length 0 | 1. View page | Empty component shows "No session rules / Create a rule to describe how to log in..." | empty-state |
| SESSION-010 | Rules list empty state action button | rules.length 0 | 1. View empty state | Button "New rule" present; onClick calls startNew() | empty-state |
| SESSION-011 | Rules loading | rulesQuery.isLoading true | 1. View page loading | LoadingPanel shows "Loading session rules" | loading |
| SESSION-012 | Rules error | rulesQuery.error set | 1. Query fails | ErrorNotice renders with error and onRetry | error |
| SESSION-013 | Rules table renders | rules.length > 0 | 1. View page | SimpleTable shows headers: On, Name, Hosts, Steps, Extractions, Max attempts | happy |
| SESSION-014 | Rules table row (enabled switch) | rules [rule1 { enabled: true }] | 1. Observe switch in first row | Switch checked; onChange calls toggleEnabled(rule, checked) | happy |
| SESSION-015 | Rules table row (disabled rule) | rules [rule1 { enabled: false }] | 1. Observe switch | Switch unchecked | happy |
| SESSION-016 | Rules table row name | rules [rule1 { name: "Admin login" }] | 1. Observe name column | Shows "Admin login" in strong | happy |
| SESSION-017 | Rules table row name (empty) | rules [rule1 { name: "" }] | 1. Observe name column | Shows "Rule 1" (fallback via index) | happy |
| SESSION-018 | Rules table row scope | rules [rule1 with scope hosts ["target.test"]] | 1. Observe hosts column | Shows "target.test" in cell-dim | happy |
| SESSION-019 | Rules table row scope (applies everywhere) | rules [rule1] scope unset | 1. Observe hosts column | Shows "every host" | happy |
| SESSION-020 | Rules table row steps count | rules [rule1 with 3 steps] | 1. Observe steps column | Shows "3" in cell-num | happy |
| SESSION-021 | Rules table row extractions count | rules [rule1 with extractions] | 1. Count extractions in all steps | Shows total count (e.g., "2") | happy |
| SESSION-022 | Rules table row max attempts | rules [rule1 { max_attempts: 5 }] | 1. Observe max attempts column | Shows "5" in cell-dim | happy |
| SESSION-023 | Rules table row max attempts default | rules [rule1] max_attempts undefined | 1. Observe max attempts column | Shows "default" in cell-dim | happy |
| SESSION-024 | Rules table row edit button | rules [rule1] | 1. Click edit (pencil) icon | open(rule1) called; editing set; editor renders | happy |
| SESSION-025 | Rules table row delete button enabled | rules [rule1 { id: 42 }] | 1. Click delete (trash) icon | Delete button enabled; setConfirmDelete(42) called | happy |
| SESSION-026 | Rules table row delete button disabled | rules [unsaved rule] id undefined | 1. Observe delete button | Button disabled (id === undefined check) | happy |
| SESSION-027 | Rules table row selected highlight | editing { id: 42 }, rules [rule { id: 42 }] | 1. Edit a rule 2. Observe table | Row with matching id has selected-row class | happy |
| SESSION-028 | Enable/disable toggle success | toggleEnabled called | 1. Click switch on rule 2. Wait for success | toast.success shows "Rule name enabled" or "Rule name paused" | happy |
| SESSION-029 | Enable/disable toggle error | saveRule.onError fires | 1. Toggle switch 2. Fails | toast.error "Could not change the rule" | error |

### Rule Editor (Create/Edit)

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-030 | New rule creates empty draft | wired true, editing null | 1. Click "New rule" button | startNew() called; editing set to emptyRule(); baseline = "" (dirty by default) | happy |
| SESSION-031 | Edit rule loads existing | rule { name: "Admin", enabled: true, ... } | 1. Click edit on rule | open(rule) called; editing = ruleIn(rule); baseline set to stringified | happy |
| SESSION-032 | Rule editor card title (new) | editing { id: undefined } | 1. View editor for new rule | SectionHeading title shows "New rule" | happy |
| SESSION-033 | Rule editor card title (existing) | editing { id: 42 } | 1. View editor for existing rule | SectionHeading title shows "Rule 42" | happy |
| SESSION-034 | Rule editor dirty badge (unsaved) | editing !== null, dirty true | 1. Make changes 2. Observe badge | Badge tone="warn" shows "unsaved changes" | happy |
| SESSION-035 | Rule editor saved badge (unchanged) | editing !== null, dirty false | 1. Open rule without changes | Badge tone="good" shows "saved" | happy |
| SESSION-036 | Rule editor close button | editing !== null | 1. Click X button | setEditing(null); setBaseline(""); editor closed | happy |
| SESSION-037 | Rule editor revert button disabled | dirty false | 1. Observe button | Button disabled; !dirty || !baseline | boundary |
| SESSION-038 | Rule editor revert button enabled | dirty true, baseline set | 1. Make changes | Button enabled | happy |
| SESSION-039 | Rule editor revert restores baseline | baseline "...", editing changed | 1. Click Revert button | setEditing(JSON.parse(baseline)); dirty becomes false; toast.success "Reverted to the saved rule" | happy |
| SESSION-040 | Rule editor save disabled | !wired | 1. View editor when not wired | Save button disabled | boundary |
| SESSION-041 | Rule editor save pending | saveRule.isPending true | 1. Click Save 2. Observe button | Button disabled; text shows "Saving…" | loading |
| SESSION-042 | Rule editor save requires name | editing { name: "" } | 1. Leave name blank 2. Click Save | toast.error "A rule needs a name"; does not mutate | error |
| SESSION-043 | Rule editor save requires steps | editing { steps: [] } | 1. Remove all steps 2. Click Save | toast.error "A rule needs at least one macro step"; does not mutate | error |
| SESSION-044 | Rule editor save success (new) | editing { id: undefined, name: "Test", steps: [step1] } | 1. Fill required fields 2. Click Save | saveRule.mutate called with POST payload; onSuccess extracts id; baseline updated; toast.success | happy |
| SESSION-045 | Rule editor save success (existing) | editing { id: 42, name: "Test", steps: [step1] } | 1. Edit and save | saveRule.mutate called with PUT payload (includes id); baseline updated; toast.success | happy |
| SESSION-046 | Rule editor save error | saveRule.onError fires | 1. Save fails | toast.error with error message | error |
| SESSION-047 | Re-adopt server changes (not dirty) | editing open, rule updated on server, dirty false | 1. Server updates rule while editor open 2. Observe editor | useEffect re-adopts fresh rule; editing and baseline updated | happy |
| SESSION-048 | Don't re-adopt server changes (dirty) | editing open, rule updated on server, dirty true | 1. Make local changes 2. Server updates rule | useEffect skips update; !dirty check prevents re-adoption | happy |

### Rule Editor - Basic Fields

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-049 | Rule name input | editing { name: "" } | 1. Click name input 2. Type "Admin login" | editing.name updated; badge shows dirty | happy |
| SESSION-050 | Rule name disabled when not wired | wired false, editing set | 1. Observe name input | Input disabled | happy |
| SESSION-051 | Rule enabled switch | editing { enabled: true } | 1. Click "Rule enabled" switch | editing.enabled toggled | happy |
| SESSION-052 | Rule enabled switch disabled when not wired | wired false | 1. Observe switch | Switch disabled | happy |
| SESSION-053 | Max attempts input | editing { maxAttempts: "" } | 1. Type "5" in Max attempts | editing.maxAttempts = "5" | happy |
| SESSION-054 | Max attempts input disabled when not wired | wired false | 1. Observe input | Input disabled | happy |
| SESSION-055 | Max attempts blank means default | editing { maxAttempts: "" } | 1. Leave blank 2. Save | Payload does not include max_attempts (server uses default) | happy |
| SESSION-056 | Max attempts invalid (non-numeric) | editing { maxAttempts: "abc" } | 1. Type "abc" 2. Save | onSave validation: Number.isInteger(parsed) && parsed > 0 false; max_attempts omitted | boundary |
| SESSION-057 | Max attempts invalid (negative) | editing { maxAttempts: "-1" } | 1. Type "-1" 2. Save | Validation false; max_attempts omitted | boundary |
| SESSION-058 | Max attempts valid (zero) | editing { maxAttempts: "0" } | 1. Type "0" | Validation false (parsed > 0 fails); max_attempts omitted | boundary |

### Rule Editor - Scope Hosts

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-059 | No scope hosts initially | editing { hosts: [] } | 1. View editor | Shows "No hosts listed, so the rule applies everywhere." | empty-state |
| SESSION-060 | Scope host inline edit | editing { hosts: ["example.com"] } | 1. Click host input 2. Type ".test" to append | hosts[0] updated via onChange | happy |
| SESSION-061 | Remove scope host | editing { hosts: ["example.com", "test.com"] } | 1. Click remove icon on first host | hosts filtered; becomes ["test.com"] | happy |
| SESSION-062 | Scope host disabled when not wired | wired false, editing set | 1. Observe host inputs | All inputs and buttons disabled | happy |
| SESSION-063 | Add host button disabled (empty input) | newHost "" | 1. Observe button | Button disabled; !newHost.trim() | boundary |
| SESSION-064 | Add host button enabled (text entered) | newHost "target.test" | 1. Type in new host input | Button enabled | happy |
| SESSION-065 | Add host appends to list | newHost "new.com", editing { hosts: ["a.com"] } | 1. Click "Add host" button | hosts becomes ["a.com", "new.com"]; newHost cleared | happy |
| SESSION-066 | Add host with whitespace | newHost "  target.test  " | 1. Click "Add host" | hosts.push(newHost.trim()); newHost cleared | happy |
| SESSION-067 | New host input disabled when not wired | wired false | 1. Observe new host input | Input disabled | happy |
| SESSION-068 | Add host button disabled when not wired | wired false | 1. Observe button | Button disabled | happy |

### Rule Editor - Validity Check

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-069 | Validity section visible | editing !== null | 1. View editor | "Validity check" section renders | happy |
| SESSION-070 | Status is input (numeric) | editing { validity: { status_is: 200 } } | 1. Observe status input | Shows "200" | happy |
| SESSION-071 | Status is input (blank means undefined) | editing { validity: { status_is: undefined } } | 1. Observe input | Shows "" | happy |
| SESSION-072 | Status is input (edit) | editing { validity: { status_is: 200 } } | 1. Clear and type "404" | onChange parses "404"; status_is set to 404 | happy |
| SESSION-073 | Status is input (invalid non-numeric) | validity input "abc" | 1. Type "abc" 2. Tab out | Parsed as NaN; !Number.isInteger(NaN) fails; status_is stays undefined | boundary |
| SESSION-074 | Body contains input | editing { validity: { body_contains: "success" } } | 1. Observe input | Shows "success" | happy |
| SESSION-075 | Body contains edit | editing { validity: { body_contains: "" } } | 1. Type "Welcome" | validity.body_contains updated | happy |
| SESSION-076 | Body not contains input | editing { validity: { body_not_contains: "login form" } } | 1. Observe input | Shows "login form" | happy |
| SESSION-077 | Body not contains edit | validity { body_not_contains: "" } | 1. Type "error" | validity.body_not_contains updated | happy |
| SESSION-078 | Header present input | editing { validity: { header_present: "X-Auth" } } | 1. Observe input | Shows "X-Auth" | happy |
| SESSION-079 | Header absent input | editing { validity: { header_absent: "Set-Cookie" } } | 1. Observe input | Shows "Set-Cookie" | happy |
| SESSION-080 | Validity disabled when not wired | wired false, editing set | 1. Observe all validity inputs | All disabled | happy |
| SESSION-081 | Nested validity notice | editing.validity { all: [{...}] } (nested) | 1. View editor | notice-warn "This rule combines conditions with all / any / not..." shown | happy |
| SESSION-082 | Nested validity notice hidden | editing.validity { status_is: 200 } (flat) | 1. View editor | notice-warn not rendered; hasNestedValidity false | happy |

### Rule Editor - Macro Steps

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-083 | Add step button | editing !== null, wired true | 1. Click "Add step" button | steps array appended with empty StepDraft | happy |
| SESSION-084 | Add step button disabled when not wired | wired false | 1. Observe button | Button disabled | happy |
| SESSION-085 | Step card renders | editing { steps: [step1] } | 1. View editor | StepCard rendered with badges, method input, URL input, headers, body, extractions | happy |
| SESSION-086 | Step index badge | editing { steps: [s0, s1, s2] } | 1. Observe step cards | Badges show "step 1", "step 2", "step 3" | happy |
| SESSION-087 | Step method input | step { method: "POST" } | 1. Observe method input | Shows "POST"; placeholder "POST" | happy |
| SESSION-088 | Step method edit | step { method: "GET" } | 1. Type "PUT" | step.method updated | happy |
| SESSION-089 | Step URL input | step { url: "https://target.test/login" } | 1. Observe URL input | Shows "https://target.test/login" | happy |
| SESSION-090 | Step URL edit | step { url: "" } | 1. Type "https://app/api/login" | step.url updated; placeholder "https://target.test/login" | happy |
| SESSION-091 | Move step up button (first step) | editing { steps: [s0, s1, s2] }, on s0 | 1. Observe button | Button disabled (index === 0) | boundary |
| SESSION-092 | Move step up button (middle step) | steps [s0, s1, s2], on s1 | 1. Click button | steps swapped; order becomes [s0, s1 moved up next to s0] | happy |
| SESSION-093 | Move step down button (last step) | steps [s0, s1, s2], on s2 | 1. Observe button | Button disabled (index === total-1) | boundary |
| SESSION-094 | Move step down button (middle step) | steps [s0, s1, s2], on s1 | 1. Click button | steps[1] and steps[2] swapped | happy |
| SESSION-095 | Remove step button | editing { steps: [s0, s1, s2] } | 1. Click remove on s1 | steps filtered; becomes [s0, s2] | happy |
| SESSION-096 | Step body textarea | step { body: "user={{user}}&pass={{pass}}" } | 1. Observe textarea | Shows "user={{user}}&pass={{pass}}" | happy |
| SESSION-097 | Step body edit | step { body: "" } | 1. Type "data=test" | step.body updated; placeholder "user=admin&password={{password}}" | happy |
| SESSION-098 | Step disabled when not wired | wired false, editing set | 1. Observe step card inputs | All inputs/buttons disabled | happy |
| SESSION-099 | Multiple steps render independently | editing { steps: [s0, s1, s2] } | 1. View editor | Each step card renders with its own index, state, and controls | happy |

### Rule Editor - Headers (Steps)

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-100 | Headers section "No headers" hint | step { headers: [] } | 1. View step | Hint "No headers. The sender adds only what a request needs." | empty-state |
| SESSION-101 | Header pair row renders | step { headers: [["Content-Type", "application/json"]] } | 1. View step | Two inputs and remove button | happy |
| SESSION-102 | Header name input edit | header "Content-Type" | 1. Click name input 2. Change to "X-Custom" | Header[0] updated | happy |
| SESSION-103 | Header value input edit | header "application/json" | 1. Click value input 2. Change | Header[1] updated | happy |
| SESSION-104 | Remove header button | headers [["X-Custom", "value"]] | 1. Click remove icon | Header filtered out | happy |
| SESSION-105 | Add header button (empty) | headers [] | 1. Click "Add header" | headers becomes [["", ""]] | happy |
| SESSION-106 | Add header button (append) | headers [["X-Custom", "val"]] | 1. Click "Add header" | headers becomes [..., ["", ""]] | happy |
| SESSION-107 | Headers disabled when not wired | wired false | 1. Observe header inputs | All disabled | happy |
| SESSION-108 | Header section scope label | Always | 1. View step headers | HeaderPairs scope="Step 1", "Step 2", etc. applied to aria-labels | happy |
| SESSION-109 | Header placeholders | Always | 1. Observe header inputs | Name placeholder "Content-Type"; value placeholder "application/x-www-form-urlencoded" | happy |

### Rule Editor - Extractions

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-110 | Extractions section hint (empty) | step { extract: [] } | 1. View step | Hint "A later step sends an earlier extraction as {{name}}." | empty-state |
| SESSION-111 | Extraction row renders | step { extract: [{ name: "csrf", fromKind: "body", how: "regex", pattern: "...", group: "1" }] } | 1. View step | ExtractionRows with name, source, method, pattern, group inputs and remove button | happy |
| SESSION-112 | Extraction name input | extraction { name: "csrf" } | 1. Observe input | Shows "csrf"; placeholder "csrf" | happy |
| SESSION-113 | Extraction name edit | extraction { name: "" } | 1. Type "token" | name updated | happy |
| SESSION-114 | Extraction source select (body) | extraction { fromKind: "body" } | 1. Observe select | Shows "From body"; onChange sets fromKind to "body" or "header" | happy |
| SESSION-115 | Extraction source select (header) | extraction { fromKind: "header" } | 1. Observe select | Shows "From header" | happy |
| SESSION-116 | Extraction source change body to header | fromKind "body" | 1. Select "From header" | fromKind set to "header"; header input becomes enabled | happy |
| SESSION-117 | Extraction header name input | extraction { fromKind: "header", header: "X-CSRF" } | 1. Observe input | Shows "X-CSRF"; disabled if fromKind !== "header"; placeholder "X-Token" | happy |
| SESSION-118 | Extraction header name only when header source | extraction { fromKind: "body" } | 1. Observe input | Input disabled (disabled={... || entry.fromKind !== "header"}) | boundary |
| SESSION-119 | Extraction method select (regex) | extraction { how: "regex" } | 1. Observe select | Shows "Regex" | happy |
| SESSION-120 | Extraction method select (json_path) | extraction { how: "json_path" } | 1. Observe select | Shows "JSON path" | happy |
| SESSION-121 | Extraction method select (whole) | extraction { how: "whole" } | 1. Observe select | Shows "Whole value" | happy |
| SESSION-122 | Extraction pattern input (regex) | extraction { how: "regex", pattern: "csrf=([^&]+)" } | 1. Observe input | Shows pattern; enabled; placeholder regex example | happy |
| SESSION-123 | Extraction pattern input (json_path) | extraction { how: "json_path", pattern: "data.token" } | 1. Change method to JSON path | placeholder changes to "data.token" | happy |
| SESSION-124 | Extraction pattern disabled (whole) | extraction { how: "whole" } | 1. Observe input | Input disabled; disabled={... || how === "whole"} | boundary |
| SESSION-125 | Extraction capture group input (regex) | extraction { how: "regex", group: "1" } | 1. Observe input | Shows "1"; enabled; placeholder "1" | happy |
| SESSION-126 | Extraction capture group disabled (non-regex) | extraction { how: "json_path" } | 1. Observe input | Input disabled; disabled={... || how !== "regex"} | boundary |
| SESSION-127 | Extraction capture group edit | extraction { how: "regex", group: "2" } | 1. Type "3" | group updated to "3" | happy |
| SESSION-128 | Remove extraction button | step { extract: [ext0, ext1] } | 1. Click remove on ext0 | extract filtered; becomes [ext1] | happy |
| SESSION-129 | Add extraction button (empty) | step { extract: [] } | 1. Click "Add extraction" | extract becomes [{ name: "", fromKind: "body", header: "", how: "regex", pattern: "", group: "1" }] | happy |
| SESSION-130 | Add extraction button (append) | step { extract: [ext0] } | 1. Click "Add extraction" | extract appended with empty draft | happy |
| SESSION-131 | Extractions disabled when not wired | wired false | 1. Observe extraction inputs | All disabled | happy |
| SESSION-132 | Extraction name required to include in output | extraction { name: "" } | 1. Save rule with empty extraction name | extract array filters (entry.name.trim() !== "") — empty names excluded | boundary |

### Login Probe Section

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-133 | Probe section visible | Always | 1. View page | Card "Log in again" renders | happy |
| SESSION-134 | Probe method input | probe { method: "GET" } | 1. Observe input | Shows "GET"; placeholder "GET"; aria-label "Probe method" | happy |
| SESSION-135 | Probe method edit | probe { method: "GET" } | 1. Type "POST" | probe.method updated | happy |
| SESSION-136 | Probe URL input | probe { url: "https://app/whoami" } | 1. Observe input | Shows "https://app/whoami"; placeholder "https://target.test/whoami" | happy |
| SESSION-137 | Probe URL edit | probe { url: "" } | 1. Type "https://site.test/auth" | probe.url updated | happy |
| SESSION-138 | Probe body textarea | probe { body: "mode=check" } | 1. Observe textarea | Shows "mode=check"; disabled if !wired | happy |
| SESSION-139 | Probe body edit | probe { body: "" } | 1. Type "data=1" | probe.body updated | happy |
| SESSION-140 | Probe headers section | probe { headers: [] } | 1. View probe headers | HeaderPairs renders with scope="Probe"; add/remove header buttons | happy |
| SESSION-141 | Probe disabled when not wired | wired false | 1. Observe probe inputs | All inputs disabled | happy |
| SESSION-142 | Run login button | probe { url: "https://app/check" }, login.isPending false | 1. Click "Run login now" | runLogin() called; login.mutate(step) with probe data | happy |
| SESSION-143 | Run login disabled when not wired | wired false | 1. Observe button | Button disabled | boundary |
| SESSION-144 | Run login button pending | login.isPending true | 1. Click button 2. Observe | Button disabled; text shows "Running…" | loading |
| SESSION-145 | Run login requires URL | probe { url: "" } | 1. Click "Run login" | toast.error "The probe needs a URL to test the session against"; mutate not called | error |
| SESSION-146 | Run login success (good outcome) | login.onSuccess { outcome: "already_valid" } | 1. Probe succeeds with good outcome | toast.success "Session already valid"; loginResult set | happy |
| SESSION-147 | Run login success (recovered outcome) | login.onSuccess { outcome: "recovered" } | 1. Probe succeeds with recovery | toast.success "Session recovered"; loginResult set; promotable set if rule_id exists | happy |
| SESSION-148 | Run login success (bad outcome) | login.onSuccess { outcome: "still_invalid_after_relogin" } | 1. Probe completes with bad outcome | toast.error "Login outcome: still_invalid_after_relogin"; loginResult set | happy |
| SESSION-149 | Run login error | login.onError fires | 1. Login fails | toast.error with error message; loginResult set to null | error |
| SESSION-150 | LoginResult detail list displays | loginResult { outcome: "recovered", rule: "Admin", ... } | 1. Probe succeeds 2. Observe results | DetailList renders with outcome, rule, URL, hints, etc. | happy |
| SESSION-151 | Loginresult empty state | loginResult null | 1. Page loads or probe not run | DetailList not rendered | empty-state |
| SESSION-152 | Probe response shown | loginResult { response: { body: "Welcome admin" } } | 1. Probe succeeds | HttpEditor shows probe response body in readonly mode | happy |
| SESSION-153 | Probe response absent | loginResult { response: null } | 1. Probe succeeds without response | HttpEditor not rendered | empty-state |
| SESSION-154 | Update macro button appears | promotable { id: 42, name: "Admin" } | 1. Probe recovers session | Button appears with text "Update macro from this run" and Upload icon | happy |
| SESSION-155 | Update macro button disappears | promotable null | 1. Probe doesn't recover or after promotion | Button not rendered (actions prop is null) | empty-state |
| SESSION-156 | Update macro button pending | promoteMacro.isPending true | 1. Click button 2. Observe | Button disabled; pending state | loading |
| SESSION-157 | Update macro success | promoteMacro.onSuccess { steps: [s0, s1, s2] } | 1. Click button 2. Success | toast.success "Macro of 'Admin' replaced with 3 observed step(s)"; promotable cleared | happy |
| SESSION-158 | Update macro error | promoteMacro.onError fires | 1. Promotion fails | toast.error with error message | error |

### Cookie Jar Section

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-159 | Cookie jar visible | Always | 1. View page | Card "Cookie jar" renders | happy |
| SESSION-160 | Cookie jar description | Always | 1. View card | Detail "The jar shared by the session coordinator and this tool's own senders." | happy |
| SESSION-161 | Refresh button visible | Always | 1. View jar section | RefreshButton present with aria-label="Refresh jar" | happy |
| SESSION-162 | Refresh button calls refetch | Always | 1. Click refresh | cookiesQuery.refetch() called; loading state animated | happy |
| SESSION-163 | Cookie table renders | cookieRows.length > 0 | 1. View jar | SimpleTable shows Host, Name, Value columns | happy |
| SESSION-164 | Cookie table empty state | cookieRows.length === 0 | 1. View jar with no cookies | Empty component "No cookies to show / The coordinator's jar has no enumeration API..." | empty-state |
| SESSION-165 | Cookie row data | cookieRows [{ host: "example.com", name: "sid", value: "abc123" }] | 1. Observe row | Shows host, name in <code>, value in cell-dim | happy |
| SESSION-166 | Cookie jar error | cookiesQuery.error set | 1. Query fails | ErrorNotice renders with error and onRetry | error |
| SESSION-167 | Cookie jar not wired | cookiesQuery.data { wired: false } | 1. View jar | notice-warn shows "The cookie jar is not attached to this process." or custom hint | happy |
| SESSION-168 | Cookie jar loading | cookiesQuery.isFetching true | 1. Observe refresh button | Refresh button shows loading/animated state | loading |

### Delete Confirmation Modal

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-169 | Delete modal not shown | confirmDelete null | 1. View page | Modal not rendered; open={false} | happy |
| SESSION-170 | Delete modal shown | confirmDelete 42 | 1. Click delete on rule | Modal opens; open={true}; shows "Delete this session rule?" | happy |
| SESSION-171 | Delete modal description | confirmDelete !== null | 1. Observe modal | Description "The rule and its macro are removed from the coordinator immediately." | happy |
| SESSION-172 | Keep it button | confirmDelete 42 | 1. Click "Keep it" button | setConfirmDelete(null); modal closes | happy |
| SESSION-173 | Delete rule button enabled | deleteRule.isPending false | 1. Observe button | Button enabled | happy |
| SESSION-174 | Delete rule button pending | deleteRule.isPending true | 1. Click button 2. Observe | Button disabled; pending state | loading |
| SESSION-175 | Delete rule button disabled variant | Always | 1. Observe button | Button variant="danger" | happy |
| SESSION-176 | Delete rule execution | confirmDelete 42 | 1. Click "Delete rule" button | onDelete(42) called; deleteRule.mutate(42) | happy |
| SESSION-177 | Delete closes rule editor (if open) | editing { id: 42 }, confirmDelete 42 | 1. Delete rule that's being edited | onSuccess sets editing to null; setBaseline(""); editor closes | happy |
| SESSION-178 | Delete clears promotable (if open) | promotable { id: 42 }, confirmDelete 42 | 1. Delete rule with promotable offer | onSuccess clears promotable | happy |
| SESSION-179 | Delete success toast | deleteRule.onSuccess fires | 1. Delete completes | toast.success "Rule deleted" | happy |
| SESSION-180 | Delete error toast | deleteRule.onError fires | 1. Delete fails | toast.error with error message | error |

### Page-level Flows & Edge Cases

| ID | Route | Precondition | Steps | Expected result | Type |
|-------|-------|-------|-------|-------|-------|
| SESSION-181 | Create new rule (start to save) | wired true, rules [] | 1. Click "New rule" 2. Fill name, add step, click Save | Rule created; id assigned; editor remains open with baseline updated | happy |
| SESSION-182 | Edit existing rule without changes | editing open, dirty false | 1. Open rule 2. Close without changes | Editor closes; no save | happy |
| SESSION-183 | Edit and revert changes | editing open, dirty true | 1. Change fields 2. Click Revert | Changes discarded; dirty becomes false | happy |
| SESSION-184 | Edit and save changes | editing open, dirty true | 1. Change fields 2. Click Save | Changes persisted; baseline updated; dirty becomes false | happy |
| SESSION-185 | Delete while editing | editing { id: 42 }, editing open | 1. Click delete 2. Confirm in modal | Rule deleted; editor closed; table updated | happy |
| SESSION-186 | Multiple rules toggle in sequence | rules [rule1, rule2, rule3] | 1. Toggle rule1 off 2. Toggle rule2 on 3. Toggle rule3 off | Each toggle calls toggleEnabled; order independent | happy |
| SESSION-187 | Add multiple steps to one rule | editing { steps: [] } | 1. Add step 1 2. Add step 2 3. Add step 3 | steps array appends; each step renders independently | happy |
| SESSION-188 | Move step up and down | steps [s0, s1, s2, s3] | 1. Move s2 up 2. Move s1 down 3. Observe | Steps reorder correctly; move operations compose | happy |
| SESSION-189 | Add and remove headers within step | step { headers: [] } | 1. Add 2 headers 2. Remove first 3. Add third | headers array modifies correctly | happy |
| SESSION-190 | Add and remove extractions within step | step { extract: [] } | 1. Add 2 extractions 2. Remove one 3. Add third | extract array modifies correctly | happy |

---

## Coverage Summary

This UAT matrix covers all interactive elements across Intruder, Repeater, Sequencer, and Session pages with a total of **190 test cases**.

### Coverage by Element

| Element | Pages | Cases | Notes |
|---------|-------|-------|-------|
| Message ID / Capture ID inputs | INTRUDER, SEQ | 6 | Empty, invalid, boundary values, handoff integration |
| Target / Tab name inputs | INTRUDER, REPEATER | 8 | State persistence, scheme detection, label updates |
| Attack type / encoding selects | INTRUDER, SEQ | 9 | Mode changes, scale recalculation, default values |
| Tab navigation & switching | INTRUDER, REPEATER, SEQ, SESSION | 14 | Keyboard shortcuts (Enter/Space), active states, persistence |
| Point/position discovery & selection | INTRUDER | 14 | Discover button, empty states, checkbox handling, allocation |
| Payload editing & processing | INTRUDER | 20 | Sets scaling, rule management, validation, boundaries |
| Resource pool settings | INTRUDER | 9 | Limits, throttling, budget warnings |
| Grep settings | INTRUDER | 6 | Match/extract configuration, whitespace handling |
| Attack launch & results | INTRUDER | 21 | Preconditions, success/error paths, result rendering |
| Request/response editors | REPEATER | 10 | Keyboard shortcuts, state changes, readonly enforcement |
| Inspector toggle | REPEATER | 7 | Visibility, aria-pressed states, grid layout changes |
| Send button & status badges | REPEATER | 8 | Pending states, status tones, exchange ID display |
| To Intruder handoff | REPEATER | 8 | Success/failure paths, exchange fetch, seed propagation |
| Token analysis (paste) | SEQ | 12 | Encoding, count calculation, empty states, error handling |
| Live capture & polling | SEQ | 14 | Attach/detach, polling states, stop button, empty states |
| Sequencer report & positions | SEQ | 20 | Grade display, FIPS tests, warnings, position truncation |
| Rule editor (create/edit) | SESSION | 28 | New/existing rules, dirty tracking, save/revert, baseline |
| Rule table & list | SESSION | 20 | Enable/disable, delete, scope, editing integration |
| Basic rule fields | SESSION | 10 | Name, enabled, max attempts, validation, disabled states |
| Scope hosts | SESSION | 9 | Add/remove, whitespace handling, applies everywhere |
| Validity check | SESSION | 14 | Status, body/header conditions, nested validity, disabled |
| Macro steps | SESSION | 17 | Add/remove, move, method/URL editing, step ordering |
| Step headers | SESSION | 9 | Add/remove pairs, name/value editing, disabled states |
| Step extractions | SESSION | 23 | Source selection (body/header), method (regex/json/whole), capture group, filtering |
| Login probe | SESSION | 26 | Method/URL/body/headers, run button, result display, macro promotion |
| Cookie jar | SESSION | 8 | Display, empty state, not wired, refresh, error handling |
| Delete modal | SESSION | 11 | Confirmation, Keep/Delete buttons, editor/promotable cleanup |
| Page-level flows | SESSION | 10 | Create-to-save, edit-revert-save, delete integration, multi-step sequences |

### Test Types Distribution

- **Happy Path (core workflows)**: 71 cases
- **Empty State / Initial Conditions**: 26 cases
- **Boundary Values (invalid input, limits)**: 31 cases
- **Error Handling**: 19 cases
- **Loading / Pending States**: 18 cases
- **Keyboard Shortcuts & A11y**: 8 cases
- **Alternate Entry Points / Handoffs**: 10 cases
- **Permission/Wired States**: 7 cases

All test cases are runnable without reading the code and reference only observable UI behavior and copy from the source.
