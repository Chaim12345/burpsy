# UAT Matrix: Proxy tools (Intercept, History, WebSocket, Match/Replace)

Exhaustive test cases for every route through interactive elements on the four proxy pages.

---

## Intercept Page Tests

| ID | Route | Precondition | Steps | Expected result | Type |
|-----|-------|-------------|-------|-----------------|------|
| INTERCEPT-001 | Switch → toggle on | data.wired=true, data.enabled=false | Click "Intercept is on" toggle | data.enabled becomes true; switch shows checked state; toast shows "Intercept is on"; metrics update to "Holding" | happy |
| INTERCEPT-002 | Switch → toggle off | data.wired=true, data.enabled=true | Click "Intercept is on" toggle | data.enabled becomes false; switch shows unchecked state; toast shows "Intercept is off"; metrics update to "Passing" | happy |
| INTERCEPT-003 | Alt+T keyboard shortcut | data.wired=true, any enabled state | Press Alt+T | toggle() executes; switch state flips; event.preventDefault() fires; browser Alt+T menu not shown | keyboard |
| INTERCEPT-004 | Alt+T when not wired | data.wired=false, any enabled state | Press Alt+T on intercept page | Event preventDefault still fires; toggle() checks data?.wired and returns early; toast.error shows "Interception is not wired up on this server" | error |
| INTERCEPT-005 | Switch → error response | data.wired=true, data.enabled=true, mutation error | Click switch; server returns 500 error | Switch reverts to previous state; toast.error shows server error message; controls.setEnabled.isPending becomes false | error |
| INTERCEPT-006 | Switch when wired=false | data.wired=false, any enabled state | Click "Intercept is on" toggle | toast.error("Interception is not wired up on this server"); switch does not change state | error |
| INTERCEPT-007 | Rules tab → Queue tab | on rules tab view | Click "Queue" tab trigger | TabsContent value changes to "queue"; held messages table becomes visible; rules editor hidden | happy |
| INTERCEPT-008 | Queue tab → Rules tab | on queue tab view | Click "Interception rules" tab trigger | TabsContent value changes to "rules"; two-column RuleEditor view becomes visible; queue and detail hidden | happy |
| INTERCEPT-009 | Add rule (requests) | on Interception rules tab, rules=[] | Click "Add rule" button in requests RuleEditor | New rule appended to requests rules list with field="host", enabled=true, string_match="", category="regex", comment=""; dirty=true; Save button enabled | happy |
| INTERCEPT-010 | Add rule (responses) | on Interception rules tab, rules=[] | Click "Add rule" button in responses RuleEditor | New rule appended to responses rules list with field="status_code", enabled=true, string_match="", category="regex", comment=""; dirty=true | happy |
| INTERCEPT-011 | Add rule count | rules=[R1, R2] exist | Click "Add rule" button | Third rule appended; rules array now has length 3; field hint shows "on with 3 condition(s)" | happy |
| INTERCEPT-012 | Rule enabled checkbox → toggle | rule at index 0, enabled=false | Click Checkbox in rule row | rule.enabled becomes true; marked dirty=true; field hint updates if this was the only disabled rule | happy |
| INTERCEPT-013 | Rule enabled checkbox → all disabled | rules=[R1, R2] where all enabled=true | Click checkbox on every rule to disable them | All rules have enabled=false; field hint shows "on, but every condition is unchecked — no requests is held"; marked dirty=true | happy |
| INTERCEPT-014 | Field select change | rule with field="host" | Open field select, choose "Path" | rule.field becomes "path"; marked dirty=true; select shows "Path" label | happy |
| INTERCEPT-015 | Field select cycle through | rule.field="host" | Cycle through all FIELDS options: Host, Path, File extension, Method, URL, Status code, Content type | Each selection updates rule.field and marks dirty; final value reflects last selection | happy |
| INTERCEPT-016 | Match pattern input | rule.string_match="" | Type "example.com" into match input | rule.string_match becomes "example.com"; marked dirty=true; input value reflects typed text | happy |
| INTERCEPT-017 | Match pattern → empty | rule.string_match="pattern" | Clear the input field | rule.string_match becomes ""; marked dirty=true; field hint shows condition count unchanged (still counted if enabled) | happy |
| INTERCEPT-018 | Match pattern → boundary (very long) | rule.string_match="" | Type 5000 character string into match input | rule.string_match accepts all 5000 characters; input field scrolls/shows all text; marked dirty=true | boundary |
| INTERCEPT-019 | Match pattern → regex with special chars | rule.string_match="" | Type regex pattern "^https?://[a-z]+\\.example\\.com$" | rule.string_match stores exact string including backslashes; marked dirty=true | boundary |
| INTERCEPT-020 | Match pattern → unicode | rule.string_match="" | Type "café你好" into match input | rule.string_match stores unicode string; marked dirty=true | boundary |
| INTERCEPT-021 | Match kind select → regex | rule.category="literal" | Open category select, choose "Regex" | rule.category becomes "regex"; marked dirty=true; select shows "Regex" label | happy |
| INTERCEPT-022 | Match kind select → literal | rule.category="regex" | Open category select, choose "Literal" | rule.category becomes "literal"; marked dirty=true; select shows "Literal" label | happy |
| INTERCEPT-023 | Comment input | rule.comment="" | Type "block-all-images" into comment field | rule.comment becomes "block-all-images"; marked dirty=true; input value reflects text | happy |
| INTERCEPT-024 | Comment input → empty | rule.comment="old comment" | Clear comment field | rule.comment becomes ""; marked dirty=true | happy |
| INTERCEPT-025 | Delete rule button | rules=[R1, R2, R3], index=1 | Click "Remove rule 2" button | rule at index 1 removed; rules becomes [R1, R3]; marked dirty=true; table re-renders without row 2 | happy |
| INTERCEPT-026 | Delete rule → last remaining | rules=[R1], index=0 | Click "Remove rule 1" button | rule removed; rules becomes []; marked dirty=true; table shows "no rules — every request is held while this list is on" | happy |
| INTERCEPT-027 | Save rules → success | dirty=true, rules=[R1, R2] | Click "Save" button | save.mutate fires with {active, rules}; Save button shows "Saving…" and becomes disabled; on success: dirty=false, toast.success("Request/Response rules saved"), field hint updates, Save button re-enabled | happy |
| INTERCEPT-028 | Save rules → error | dirty=true, rules=[R1] | Click "Save" button; server returns 400 | toast.error with error message; dirty remains true; Save button becomes enabled again for retry | error |
| INTERCEPT-029 | Save rules → validation error | dirty=true, invalid rule state | Click "Save" button; server validation fails | toast.error with validation message; dirty=true; rules remain in editor | error |
| INTERCEPT-030 | Save button disabled when clean | dirty=false | Attempt click on "Save" button | Button is disabled (no-pointer-events); click has no effect | happy |
| INTERCEPT-031 | Save button disabled while pending | dirty=true, save.isPending=true | Observe save button state | Button shows "Saving…" and is disabled; cannot click | happy |
| INTERCEPT-032 | Field hint → off state | active=false | Read field count hint text | Hint displays "off — no requests is held" or "off — no responses is held" | happy |
| INTERCEPT-033 | Field hint → on no conditions | active=true, rules=[] | Read field count hint text | Hint displays "on with no conditions — every request is held" | happy |
| INTERCEPT-034 | Field hint → on all disabled | active=true, rules=[R1, R2], all disabled | Read field count hint text | Hint displays "on, but every condition is unchecked — no requests is held" | happy |
| INTERCEPT-035 | Field hint → on with N conditions | active=true, rules=[R1, R2, R3], 2 enabled | Read field count hint text | Hint displays "on with 3 condition(s)" (shows total rules, not just enabled) | happy |
| INTERCEPT-036 | Status badge → wired | data.wired=true | Observe status badge in header | Badge shows "wired" with good tone | happy |
| INTERCEPT-037 | Status badge → not wired | data.wired=false | Observe status badge in header | Badge shows "not wired" with warn tone | happy |
| INTERCEPT-038 | Metrics display | data with various values | Observe metric grid below header | Metrics show: Pending (data.pending), Mode (Holding/Passing), Transport (Connected/Unavailable), Queue depth (held.length) | happy |
| INTERCEPT-039 | Queue table columns | held=[{...}] | View held messages table | Columns render: #, Dir, Method, Host, Path, Status, Held, Len with proper formatting (badges for direction/status, formatted duration, formatted bytes) | happy |
| INTERCEPT-040 | Queue table empty state | held=[], enabled=true | View queue tab with no messages | Empty state shows title "Queue is clear", detail "Requests will stop here when a rule matches." | empty-state |
| INTERCEPT-041 | Queue table empty state (disabled) | held=[], enabled=false | View queue tab with no messages | Empty state shows title "Queue is clear", detail "Enable interception to hold matching traffic." | empty-state |
| INTERCEPT-042 | Select message from table | held=[{id:1, method:"GET"}, {id:2, method:"POST"}] | Click row with id=2 | setSelectedId(2); row highlights; useEffect sets raw from selected?.raw; detail pane appears with message info | happy |
| INTERCEPT-043 | Message detail header | selected={id:1, method:"GET", host:"api.example.com", port:443, path:"/users"} | View detail pane header | Eyebrow shows "HELD #1"; title shows "GET api.example.com:443/users"; direction badge shown | happy |
| INTERCEPT-044 | Message detail header (response) | selected={id:5, direction:"response", status:500, method:"GET", ...} | View detail pane header | Title shows "500 response to GET ..."; direction badge shows "response" with good tone | happy |
| INTERCEPT-045 | Clear selection button | selected={id:1} | Click "Clear selection" icon-button | setSelectedId(null); detail pane becomes empty state; table selection clears | happy |
| INTERCEPT-046 | HttpEditor loads raw bytes | selected={id:1, raw:"GET / HTTP/1.1..."} | Detail view renders with selection | HttpEditor displays raw bytes; can scroll and view full content; filename shows "held-1.txt" | happy |
| INTERCEPT-047 | HttpEditor edit bytes | raw="GET / HTTP/1.1...", user edits | User modifies raw bytes in editor (e.g., change method to POST) | setRaw updates local state; marked as changed but not dirty for intercept rules; Forward button uses edited raw | happy |
| INTERCEPT-048 | HttpEditor → very long content | raw with 100KB of data | View detail pane | HttpEditor renders with scrolling; performance acceptable; all bytes accessible | boundary |
| INTERCEPT-049 | Fix Content-Length checkbox | selected={...}, fixContentLength=true | Toggle "Fix Content-Length when forwarding" | setFixContentLength toggles; when true, Forward will request server fix header on forward | happy |
| INTERCEPT-050 | Forward button → success | selected={id:1}, raw edited, fixContentLength=true | Click "Forward" button | forward() executes; forwardHeld.mutate({id, raw, fixContentLength}) fires; button shows "pending" state; on success: setSelectedId(null), toast.success("Held message #1 forwarded"), table refreshes | happy |
| INTERCEPT-051 | Forward button → error | selected={id:1}, mutation fails with error | Click "Forward" button | forwardHeld.mutate fires; button shows "pending"; on error: toast.error with message; selectedId remains set; editor still shows message for retry | error |
| INTERCEPT-052 | Forward button disabled | selected=null | View Forward button state | Button is disabled; no click effect | happy |
| INTERCEPT-053 | Forward button disabled while pending | selected={id:1}, forwardHeld.isPending=true | Observe button state | Button shows "pending"; disabled attribute set; click has no effect | happy |
| INTERCEPT-054 | Ctrl+F keyboard shortcut | selected={id:1} | Press Ctrl+F on intercept page | event.preventDefault() fires (browser Find dialog not shown); forward() executes | keyboard |
| INTERCEPT-055 | Ctrl+F when no selection | selected=null | Press Ctrl+F on intercept page | forward() checks selected and returns early; no mutation fires | keyboard |
| INTERCEPT-056 | Drop button → success | selected={id:1} | Click "Drop" button | drop() executes; controls.drop.mutate(id) fires; button shows "pending"; on success: setSelectedId(null), toast.success("Held message #1 dropped"), table refreshes | happy |
| INTERCEPT-057 | Drop button → error | selected={id:1}, mutation fails | Click "Drop" button | controls.drop.mutate fires; on error: toast.error shows message; selectedId remains set | error |
| INTERCEPT-058 | Drop button disabled | selected=null | View Drop button state | Button is disabled | happy |
| INTERCEPT-059 | Drop button disabled while pending | selected={id:1}, controls.drop.isPending=true | Observe button state | Button disabled; click has no effect | happy |
| INTERCEPT-060 | Nothing selected empty state | selectedId=null | View detail pane when no row selected | Empty state shows title "Nothing selected", detail "Select a held message to view and edit its exact bytes before forwarding or dropping it." | empty-state |
| INTERCEPT-061 | Selection drops on background refresh | selectedId=1, message is deleted | useInterceptDetailed refetches and message no longer exists | useEffect detects held.some(h => h.id === 1) is false; setSelectedId(null); detail pane shows empty state | happy |
| INTERCEPT-062 | Error in useInterceptDetailed | mutation fails, error={message:"Server error"} | View page when data.error exists | ErrorNotice component renders with error message; "Retry" button visible and clickable | error |
| INTERCEPT-063 | Loading state | !data && isFetching | View intercept page during initial load | Metrics show skeleton/loading state; RuleEditor in rules tab shows Card with "Loading…" text; queue table shows loading prop | happy |
| INTERCEPT-064 | Not wired warning → requests | data.wired=false on Interception rules tab | View rules tab | Notice banner shows "Request interception rules are not wired up." | happy |
| INTERCEPT-065 | Not wired warning → responses | data.wired=false on Interception rules tab | View rules tab | Notice banner shows "Response interception rules are not wired up." | happy |
| INTERCEPT-066 | No rules empty message (request) | rules=[], active=true on requests RuleEditor | View rules table | Single row shows colSpan=6 with "no rules — every request is held while this list is on" in cell-dim class | empty-state |
| INTERCEPT-067 | No rules empty message (response) | rules=[], active=true on responses RuleEditor | View rules table | Single row shows colSpan=6 with "no rules — every response is held while this list is on" in cell-dim class | empty-state |
| INTERCEPT-068 | Data sync effect → prevents re-sync while dirty | dirty=false, data changes | useEffect re-syncs active and rules from data | Sync occurs, dirty remains false | happy |
| INTERCEPT-069 | Data sync effect → blocks sync while dirty | dirty=true, data changes via background refetch | useEffect detects dirty condition | Re-sync is skipped; unsaved edits preserved | happy |
| INTERCEPT-070 | Selection persists across table refresh | selectedId=1, data refetches with different row order | useEffect maintains selectedId | selected memo re-queries held list by id; same row still selected even if moved to different index | happy |
| INTERCEPT-071 | Exchange id boundary → 0 | held with id=0 | Click row with id=0 | setSelectedId(0); detail shows HELD #0 | boundary |
| INTERCEPT-072 | Exchange id boundary → negative | held with id=-1 | Click row with id=-1 | setSelectedId(-1); detail shows HELD #-1 | boundary |
| INTERCEPT-073 | Exchange id boundary → very large | held with id=999999999 | Click row with id=999999999 | setSelectedId(999999999); detail shows correct ID | boundary |

---

## History Page Tests

| ID | Route | Precondition | Steps | Expected result | Type |
|-----|-------|-------------|-------|-----------------|------|
| HISTORY-001 | Filter input → type query | term="" | Type "host = api.example.com" into filter input | onChange updates term state; field shows typed text | happy |
| HISTORY-002 | Filter input → debounce | term="host = api" entered | Wait 260ms (debounce interval) | debouncedTerm updates after 260ms delay; useHistory refetch fires with new query; results update | happy |
| HISTORY-003 | Filter input → immediate visual feedback | term="" | Type "host = api.example" | Filter input shows typed text immediately; table may still show old results until debounce fires | happy |
| HISTORY-004 | Clear filter button | term="host = api.example" | Click "Clear filter" icon-button | setTerm(""); filter input becomes empty; debouncedTerm updates; table shows full capture again | happy |
| HISTORY-005 | Clear filter button disabled | term="" | Observe clear filter button state | Button is hidden or disabled when term is empty | happy |
| HISTORY-006 | Filter syntax help modal → open | helpOpen=false | Click "Filter syntax" button (?) | setHelpOpen(true); Modal opens showing example queries and field reference | happy |
| HISTORY-007 | Filter syntax help modal → close | helpOpen=true | Click close button or press Escape | setHelpOpen(false); Modal closes | happy |
| HISTORY-008 | Filter DSL → host equals | term="host = api.example.com" | Submit filter query | Query executes on server; rows show only exchanges where host exactly matches "api.example.com" | happy |
| HISTORY-009 | Filter DSL → host contains | term="host ~ example" | Submit filter query | Query executes; rows show exchanges where host contains "example" substring (case-insensitive per map) | happy |
| HISTORY-010 | Filter DSL → status equals | term="status = 200" | Submit filter query | Rows show only exchanges with status code 200 | happy |
| HISTORY-011 | Filter DSL → status greater-or-equal | term="status >= 400" | Submit filter query | Rows show exchanges with status >= 400 (client and server errors) | happy |
| HISTORY-012 | Filter DSL → status less-than | term="status < 300" | Submit filter query | Rows show exchanges with status < 300 (success and redirects) | happy |
| HISTORY-013 | Filter DSL → method equals | term="method = POST" | Submit filter query | Rows show only POST exchanges | happy |
| HISTORY-014 | Filter DSL → path contains | term="path ~ /admin" | Submit filter query | Rows show exchanges where path contains "/admin" substring (case-sensitive per map) | happy |
| HISTORY-015 | Filter DSL → body contains | term="body ~ password" | Submit filter query | Rows show exchanges where request or response body contains "password" | happy |
| HISTORY-016 | Filter DSL → mime type | term="mime = application/json" | Submit filter query | Rows show exchanges with MIME type "application/json" (case-insensitive) | happy |
| HISTORY-017 | Filter DSL → AND operator | term="host = api.example AND status >= 400" | Submit filter query | Rows must match both conditions (AND logic); shows only 4xx/5xx responses from api.example | happy |
| HISTORY-018 | Filter DSL → OR operator | term="method = POST OR method = PUT" | Submit filter query | Rows match either condition (OR logic); shows POST and PUT requests | happy |
| HISTORY-019 | Filter DSL → combined AND/OR | term="(method = POST OR method = PUT) AND status >= 400" | Submit filter query | Rows match complex expression with parentheses grouping | happy |
| HISTORY-020 | Filter DSL → unknown field | Any capture | 1. Type `unknown_field = value` into the filter | 400. ErrorNotice reads ``query parse error at byte 0: 'unknown_field' is not a field this grammar has — the fields are host, status, method, path, mime and body``, with the caret line under byte 0. Table shows 0 rows. | error |
| HISTORY-021 | Filter DSL → operator the field does not take | Any capture | 1. Type `host >= api.example.com` | 400. ErrorNotice reads ``query parse error at byte 5: '>=' does not apply to host — host supports =, != (case-insensitive for host and mime) and ~ (contains)``. Ordering operators are status-only. | boundary |
| HISTORY-022 | Filter DSL → single quote is not a string delimiter | Any capture | 1. Type `host = 'unclosed` | **200, not an error.** The grammar quotes with `"` only, so `'unclosed` is a bare word and a legal host value. The query is well-typed and matches nothing — table shows 0 rows with no ErrorNotice. This is the "a query that selects nothing is not a malformed query" distinction. | boundary |
| HISTORY-023 | Filter DSL → unbalanced parenthesis | Any capture | 1. Type `(method = POST` | 400. ErrorNotice reads ``query parse error at byte 14: the group opened at byte 0 is never closed — expected ')'``. | error |
| HISTORY-023b | Filter DSL → wrong-typed comparison | Any capture | 1. Type `status > "abc"` | 400. ErrorNotice reads ``query parse error at byte 9: status expects a number but found a quoted string — a comparison whose types do not fit is rejected here rather than silently matching nothing``. | error |
| HISTORY-023c | Filter DSL → path field | At least one `/login` exchange captured | 1. Type `path ~ /login` | 200. Table shows only exchanges whose path contains `/login`. Path is case-sensitive per RFC 3986, so `path ~ /LOGIN` returns 0 rows. | happy |
| HISTORY-024 | Filter DSL → empty query | term="" | Submit (clear previous filter) | debouncedTerm becomes ""; useHistory query parameter removes query filter; table shows full capture | happy |
| HISTORY-025 | Filter DSL → whitespace only | term="   " | Submit query | debouncedTerm=" "; server receives whitespace; may return error or treat as no filter | boundary |
| HISTORY-026 | Filter DSL → quoted string with special chars | term='host = "api.ex@mple.com"' | Submit query | Server parses quoted string; rows match host literally including special chars | happy |
| HISTORY-027 | Filter DSL → case sensitivity host | term="host = API.EXAMPLE.COM" | Submit query (host case-insensitive) | Rows match ignoring case (per map: "host...ignore case") | happy |
| HISTORY-028 | Filter DSL → case sensitivity method | term="method = post" | Submit query (method case-sensitive) | Server may reject or treat as no match (per map: "method and path do not" ignore case) | boundary |
| HISTORY-029 | Filter persist on cross-page return | another page sets historyQuery="host = api" | Effect detects historyQuery | setTerm("host = api"); historyQuery cleared from store; filter input updated | happy |
| HISTORY-030 | Status filter select → all | status="all" | View select value | Shows "All statuses"; no status filtering applied on top of DSL | happy |
| HISTORY-031 | Status filter select → 2xx | status="2" | Select "2xx success" | rows memo filters to status.startsWith("2"); shows only 2xx responses | happy |
| HISTORY-032 | Status filter select → 3xx | status="3" | Select "3xx redirect" | rows memo filters to status.startsWith("3") | happy |
| HISTORY-033 | Status filter select → 4xx | status="4" | Select "4xx client" | rows memo filters to status.startsWith("4") | happy |
| HISTORY-034 | Status filter select → 5xx | status="5" | Select "5xx server" | rows memo filters to status.startsWith("5") | happy |
| HISTORY-035 | Status filter select → none | status="none" | Select "No response" | rows memo filters to status===null; shows only pending exchanges | happy |
| HISTORY-036 | Method filter select → all | method="all" | View select value | Shows "All methods"; no method filtering applied | happy |
| HISTORY-037 | Method filter select → GET | method="GET" | Select "GET" | rows memo filters to row.method === "GET" | happy |
| HISTORY-038 | Method filter select → POST | method="POST" | Select "POST" | rows memo filters to row.method === "POST" | happy |
| HISTORY-039 | Method filter select → other methods | method cycles through PUT, PATCH, DELETE, HEAD, OPTIONS | Select each method | Each filters rows by exact method name match | happy |
| HISTORY-040 | Row limit select → 200 | limit=500 | Select "last 200" | setLimit(200); useHistory query updates with new limit; table shows max 200 most recent rows | happy |
| HISTORY-041 | Row limit select → 500 | limit=200 | Select "last 500" | setLimit(500); query updates; shows up to 500 rows | happy |
| HISTORY-042 | Row limit select → 1000 | limit=500 | Select "last 1000" | setLimit(1000); query updates; shows up to 1000 rows | happy |
| HISTORY-043 | Row limit select → 5000 | limit=500 | Select "last 5000" | setLimit(5000); query updates; shows up to 5000 rows | happy |
| HISTORY-044 | Refresh button click | data loaded | Click refresh icon-button | refetch() executes; isFetching becomes true; table shows loading state; exchanges re-fetched from server | happy |
| HISTORY-045 | Exchanges table columns | data=[{id:1, method:"GET", ...}] | View table | Columns render: #, Method (badge), Host, Path (code), Status (badge), Type (dim), Length, Time, Age with proper formatting | happy |
| HISTORY-046 | Table row click → select | data=[{id:5, ...}], selectedId=null | Click row with id=5 | onSelect sets selectedId=5; row highlights; useMessage calls fire for request/response; detail pane loads | happy |
| HISTORY-047 | Table row highlight | selectedId=5 | Observe table row styling | Row with id=5 shows selected/active visual state (bg, border, etc.) | happy |
| HISTORY-048 | Select and scroll to exchange | table has 500 rows, selectedId=null | Click row with id=350 | Row scrolls into view (or was already visible); selectedId set; detail loads | happy |
| HISTORY-049 | Selection context → exchange focus from another page | another page calls focusExchange(42) | Effect detects historyFocus=42 | setSelectedId(42); focusExchange(null) clears store; table highlights row 42; detail loads | happy |
| HISTORY-050 | Row styling → 5xx error | row.status=500 | View table row | Row has class "row-flag-bad" (red styling) | happy |
| HISTORY-051 | Row styling → 4xx error | row.status=404 | View table row | Row has class "row-flag-warn" (yellow styling) | happy |
| HISTORY-052 | Row styling → 2xx success | row.status=200 | View table row | Row has neutral/no special styling | happy |
| HISTORY-053 | Row styling → pending (no response) | row.status=null | View table row | Row has neutral styling | happy |
| HISTORY-054 | Empty state → no filter, no capture | rows=[], data=[], term="" | View table with empty history | Empty state shows title "No traffic captured yet", detail "Point a client at the proxy and install the CA certificate to start capturing HTTPS." | empty-state |
| HISTORY-055 | Empty state → filter with no results | rows=[], data=[...many...], term="host = nonexistent" | View table after filtering | Empty state shows title "No exchange matches this filter", detail "Relax the filter, or clear it to see the whole capture." | empty-state |
| HISTORY-056 | Badge display → rows vs total | data=100 rows, filtered to 50 | View status badge | Badge shows "50 / 100 rows" in info tone | happy |
| HISTORY-057 | Badge display → all rows match filter | data=100 rows, all match filter | View status badge | Badge shows "100 rows" (no slash notation) | happy |
| HISTORY-058 | Loading state | isFetching=true, !data | View table | VirtualTable loading prop set; visual loading indicator shown | happy |
| HISTORY-059 | Error state | error from useHistory | View page | ErrorNotice renders with error message; "Retry" button visible | error |
| HISTORY-060 | Select exchange → detail view | selectedId=5, data loaded | View detail pane | Eyebrow shows "#5"; title shows "GET {url}"; status badge, duration, protocol, action buttons visible | happy |
| HISTORY-061 | Request editor → displays bytes | selected row loaded | View request editor | HttpEditor shows request.data?.text with raw HTTP request; filename "exchange-5-request.txt" | happy |
| HISTORY-062 | Request editor → loading | selected row, request.isFetching=true, !request.data | View request editor | Label shows "Loading request bytes…" | happy |
| HISTORY-063 | Request editor → no bytes | selected row, !request.data, !request.isFetching | View request editor | Label shows "No request bytes captured." | happy |
| HISTORY-064 | Response editor → displays bytes | selected row, response loaded | View response editor | HttpEditor shows response.data?.text; filename "exchange-5-response.txt" | happy |
| HISTORY-065 | Response editor → loading | selected row, response.isFetching=true, !response.data | View response editor | Label shows "Loading response bytes…" | happy |
| HISTORY-066 | Response editor → no bytes | selected row, !response.data, !response.isFetching | View response editor | Label shows "No response bytes captured." | happy |
| HISTORY-067 | Response editor → no response (null) | selected row, row.response=null | View response editor | Label shows "No response was captured for this exchange." | happy |
| HISTORY-068 | Repeater button click | selectedId=5 | Click "Repeater" button | actions.sendToRepeater(selected) fires; zustand store updates; route changes to "repeater"; exchange loaded in repeater | happy |
| HISTORY-069 | Repeater button disabled | selectedId=null | View button state | Button is disabled | happy |
| HISTORY-070 | Ctrl+R keyboard shortcut | selectedId=5 | Press Ctrl+R on history page | event.preventDefault() fires (browser reload cancelled); actions.sendToRepeater(selected) executes | keyboard |
| HISTORY-071 | Ctrl+R when no selection | selectedId=null | Press Ctrl+R | Shortcut checks selected and returns early; no action fires | keyboard |
| HISTORY-072 | Intruder button click | selectedId=5 | Click "Intruder" button | actions.sendToIntruder(selected) fires; route changes; intruder page loads with exchange as seed | happy |
| HISTORY-073 | Intruder button disabled | selectedId=null | View button state | Button is disabled | happy |
| HISTORY-074 | Ctrl+I keyboard shortcut | selectedId=5 | Press Ctrl+I on history page | event.preventDefault() fires; actions.sendToIntruder(selected) executes | keyboard |
| HISTORY-075 | Ctrl+I when no selection | selectedId=null | Press Ctrl+I | Shortcut checks selected and returns early | keyboard |
| HISTORY-076 | Compare button click | selectedId=5 | Click "Compare" button | actions.sendToComparer(selected, "a") fires; comparer slot "a" updated; route changes to "comparer" | happy |
| HISTORY-077 | Compare button disabled | selectedId=null | View button state | Button is disabled | happy |
| HISTORY-078 | Inspector toggle on | selectedId=5, inspector=false | Click inspector icon-button | setInspector(true); inspector panel appears below editors in "editor-grid-inspected" layout | happy |
| HISTORY-079 | Inspector toggle off | selectedId=5, inspector=true | Click inspector icon-button | setInspector(false); inspector panel hidden; grid changes to "editor-grid" layout | happy |
| HISTORY-080 | Inspector aria-pressed | inspector=true | Observe icon-button aria-pressed | aria-pressed="true" when inspector is open | a11y |
| HISTORY-081 | Inspector aria-pressed | inspector=false | Observe icon-button aria-pressed | aria-pressed="false" when inspector is closed | a11y |
| HISTORY-082 | Inspector label → show | inspector=false | Observe icon-button label | label="Show Inspector" | a11y |
| HISTORY-083 | Inspector label → hide | inspector=true | Observe icon-button label | label="Hide Inspector" | a11y |
| HISTORY-084 | Inspector panel content | selectedId=5, inspector=true, request.data="GET / HTTP..." | View inspector panel | Inspector renders with label "Inspector · request"; parsed structure displayed | happy |
| HISTORY-085 | Clear selection button | selectedId=5 | Click "Clear selection" icon-button | setSelectedId(null); detail pane shows empty state; table row deselects | happy |
| HISTORY-086 | No exchange selected empty | selectedId=null | View detail pane | Empty state shows title "No exchange selected", detail "Choose a row to read its exact request and response bytes. Arrow keys move through the table; right-click a row for send-to actions." | empty-state |
| HISTORY-087 | Exchange URL construction | row={host:"api.example.com", port:443, path:"/users"} | View detail title | exchangeUrl() returns "https://api.example.com:443/users" (uses protocol from row.protocol field) | happy |
| HISTORY-088 | Right-click context menu | row selected | Right-click row in table | Context menu appears with send-to options (sendToRepeater, sendToIntruder, sendToComparer) | happy |
| HISTORY-089 | Menu action → copy response bytes no response | row.response=null | Right-click "Copy response bytes" | toast.error("This exchange has no response"); no copy action | error |
| HISTORY-090 | Menu action → copy response bytes with response | row.response=5 | Right-click "Copy response bytes" | Selection set to row; response bytes can be read | happy |
| HISTORY-091 | Selection persists across filter change | selectedId=5, row 5 still in filtered results | Change status filter | selectedId remains 5; row still selected; detail view persists | happy |
| HISTORY-092 | Selection clears on filter mismatch | selectedId=5, filter changes and row 5 no longer matches | Change filter to exclude row 5 | rows memo dependency triggers; selected memo re-evaluates; if row no longer in rows, selected becomes null; detail clears | happy |
| HISTORY-093 | Method all → shows all methods | data has GET, POST, PUT, etc. | Select "All methods" from method filter | rows shows all methods without filtering by method | happy |

---

## WebSocket History Page Tests

| ID | Route | Precondition | Steps | Expected result | Type |
|-----|-------|-------------|-------|-----------------|------|
| WSHIST-001 | Connection row click → select | conns=[{exchange:5, ...}, {exchange:10, ...}], selectedExchange=null | Click connection row with exchange=5 | onSelect() calls setSelectedExchange(5); row highlights with "active" class; setSelectedFrameId(null); useWsHistory fires with selectedExchange=5 | happy |
| WSHIST-002 | Connection row → frame table load | selectedExchange=null | Click connection | Frame table populates with rows from useWsHistory(selectedExchange); table loading state shows while fetching | happy |
| WSHIST-003 | Connection styling → active | selectedExchange=5, conns contains conn with exchange=5 | View connection list | Connection row with exchange=5 has class "active" (highlighted) | happy |
| WSHIST-004 | Connection row displays info | conn={host:"ws.example.com", port:8080, path:"/chat", sent:42, received:15, messages:57, last_ms:1000} | View connection row | Row shows "ws.example.com:8080/chat"; subtitle shows "42 sent · 15 recv · {relativeTime(1000)}"; badge shows "57" | happy |
| WSHIST-005 | Connection row title attribute | conn with long host | Hover over host in row | Title attribute shows full "host:port/path" for tooltip on overflow | happy |
| WSHIST-006 | Frame table columns | rows=[{id:1, direction:"client_to_server", opcode:"text", len:256, at_ms:1000, truncated:false}] | View frame table | Columns render: #, Dir (with arrow badge), Opcode (code), Length (with truncated badge if applicable), Age | happy |
| WSHIST-007 | Frame direction badge → client_to_server | direction="client_to_server" | View frame row | Badge shows arrow-up-right icon with "sent" label, tone="info" | happy |
| WSHIST-008 | Frame direction badge → server_to_client | direction="server_to_client" | View frame row | Badge shows arrow-down-left icon with "recv" label, tone="good" | happy |
| WSHIST-009 | Frame truncated badge | row with truncated=true | View frame row | Length column shows badge "truncated" in warn tone | happy |
| WSHIST-010 | Frame select from table | selectedFrameId=null, rows=[{id:101, ...}] | Click frame row with id=101 | onSelect sets selectedFrameId=101; row highlights; useWsMessageDetailed fires with selectedFrameId=101 | happy |
| WSHIST-011 | Frame detail header | selectedFrame={id:101, opcode:"text", len:512} | View detail pane header | Eyebrow shows "#101"; title shows "{connection_info} · text"; length badge shows "512 B" | happy |
| WSHIST-012 | Frame detail header close frame | selectedFrame={id:50, opcode:"close"} | View detail pane header | Title shows connection info and opcode "close" | happy |
| WSHIST-013 | Frame clear selection button | selectedFrameId=101 | Click "Clear selection" icon-button in detail header | setSelectedFrameId(null); detail pane shows empty state; table deselects | happy |
| WSHIST-014 | Payload view → text opcode | message={opcode:"text", text:"Hello world", hex:null, close:null, truncated:false} | View detail pane | HttpEditor shows "Text payload" label; displays message.text content | happy |
| WSHIST-015 | Payload view → hex opcode | message={opcode:"binary", text:null, hex:"48656c6c6f", close:null, truncated:false} | View detail pane | HttpEditor shows "Hex payload" label; displays message.hex content | happy |
| WSHIST-016 | Payload view → close frame | message={opcode:"close", close:{code:1000, reason:"Normal closure"}, text:null, hex:null, truncated:false} | View detail pane | DetailList renders with "Close code" badge showing "1000" and "Reason" showing "Normal closure" | happy |
| WSHIST-017 | Payload view → close frame no reason | message={opcode:"close", close:{code:1000, reason:""}, ...} | View detail pane | DetailList shows close code "1000"; reason shows "(no reason given)" in cell-dim style | happy |
| WSHIST-018 | Payload view → truncated warning | message={opcode:"text", truncated:true, dropped:256, text:"partial..."} | View detail pane | Notice shows "256 byte(s) were dropped from this frame; showing only what was kept." above editor | happy |
| WSHIST-019 | Payload view → truncated hex | message={opcode:"binary", truncated:true, dropped:512, hex:"partial..."} | View detail pane | Hex editor shown with truncation warning | happy |
| WSHIST-020 | Frame loading state | selectedFrameId=101, frame.isFetching=true, !frame.data | View detail pane | Empty state shows "Loading payload…" title, "Fetching the frame's bytes." detail | happy |
| WSHIST-021 | No frame selected empty | selectedFrameId=null | View detail pane | Empty state shows "No frame selected", "Choose a row in the frame table to read its exact payload." | empty-state |
| WSHIST-022 | No upgrades empty state | conns=[], conns.length===0 | View connection list | Empty state shows "No upgrades observed", "WebSocket connections appear here once a client upgrades through the proxy." | empty-state |
| WSHIST-023 | No frames empty (no selection) | selectedExchange=null | View frame table | Empty state shows "No WebSocket traffic captured yet", "Point a client at the proxy and upgrade a connection to start capturing frames." | empty-state |
| WSHIST-024 | No frames empty (selected, no frames) | selectedExchange=5, rows=[], history data loaded | View frame table | Empty state shows "No frames on this connection", "Select another connection, or clear the selection to see every frame." | empty-state |
| WSHIST-025 | Refresh button click | connections loaded | Click RefreshButton | connections.refetch() executes; isFetching becomes true; connection list reloads | happy |
| WSHIST-026 | Metrics display | conns=[{messages:50}, {messages:30}], various sent/recv counts | View metric grid | Metrics show: Connections (conns.length), Frames (sum of messages), Sent (sum of sent), Received (sum of received) | happy |
| WSHIST-027 | Context menu → minimal (not loaded) | selectedExchange !== conn.exchange | Right-click connection where exchangeDetail not loaded | Menu shows "Copy exchange id" and "Show this exchange in HTTP history" options (id-only menu) | happy |
| WSHIST-028 | Context menu → full (loaded) | selectedExchange === conn.exchange, exchangeDetail.data available | Right-click selected connection | Menu shows sendToRepeater, sendToIntruder, sendToComparer options via actions.menu() | happy |
| WSHIST-029 | Context menu copy id | conn.exchange=42 | Click "Copy exchange id (#42)" menu item | copyToClipboard("42") executes; exchange id copied to system clipboard | happy |
| WSHIST-030 | Context menu show in history | conn.exchange=42 | Click "Show this exchange in HTTP history" menu item | focusExchange(42) called; setRoute("history") called; UI navigates to history page; history page effect highlights exchange 42 | happy |
| WSHIST-031 | Context menu send to repeater | selectedExchange===conn.exchange, menu has full actions | Right-click, click "Send to Repeater" | actions.sendToRepeater(exchangeDetail.data) fires; zustand store updated; route changes to "repeater" | happy |
| WSHIST-032 | Context menu send to intruder | menu has full actions | Right-click, click "Send to Intruder" | actions.sendToIntruder(exchangeDetail.data) fires; route changes to "intruder" | happy |
| WSHIST-033 | Context menu send to comparer | menu has full actions | Right-click, click "Send to Comparer" | actions.sendToComparer(exchangeDetail.data, slot) fires; route changes to "comparer" | happy |
| WSHIST-034 | Error in useWsConnections | connections.error exists | View page | ErrorNotice renders with error message; "Retry" button visible and clickable | error |
| WSHIST-035 | Error in useWsHistory | history.error exists | View page | ErrorNotice renders with error message; "Retry" button visible | error |
| WSHIST-036 | Frame table loading | selectedExchange set, history.isFetching=true, !history.data | View frame table | VirtualTable loading prop set; visual loading state shown | happy |
| WSHIST-037 | Frame row truncated styling | row.truncated=true | View frame table | Row has class "row-flag-warn" (yellow styling) | happy |
| WSHIST-038 | Frame row normal styling | row.truncated=false | View frame table | Row has no special class | happy |
| WSHIST-039 | Exchange preload on select | selectedExchange=5, useExchange fetches | Select connection | exchangeDetail.data loaded on-demand for right-click menu fullness; no blocking on initial select | happy |
| WSHIST-040 | Cross-page effect → history tab highlight | focusExchange called from menu | Menu click "Show in HTTP history" | history page useEffect detects historyFocus, selects and highlights exchange | happy |

---

## Match / Replace Page Tests

| ID | Route | Precondition | Steps | Expected result | Type |
|-----|-------|-------------|-------|-----------------|------|
| MATCHREP-001 | Add rule → first rule | rules=[], direction="request" | Click "Add rule" button | New rule appended: {rule_type:"request_header", enabled:true, string_match:"", string_replace:"", category:"literal", comment:""}; dirty=true | happy |
| MATCHREP-002 | Add rule → response direction | rules=[], direction="response" | Click "Add rule" button | New rule appended: {rule_type:"response_header", ...}; dirty=true | happy |
| MATCHREP-003 | Add rule → with existing | rules=[R1, R2], direction="request" | Click "Add rule" button | New rule appended at end; index=2; dirty=true | happy |
| MATCHREP-004 | Rule table columns | rules=[R1, R2] | View rules table | Columns render: On (checkbox), Target (select), Match kind (select), Match (input), Replace with (input), Comment (input), Order (move buttons), (delete/duplicate buttons) | happy |
| MATCHREP-005 | Rule enabled checkbox → toggle | rule.enabled=false | Click checkbox for rule | rule.enabled becomes true; patch marks dirty=true; enabled count badge updates | happy |
| MATCHREP-006 | Rule enabled count badge | rules=[R1, R2, R3], 2 enabled | View enabled badge | Badge shows "2 of 3 enabled" | happy |
| MATCHREP-007 | Saved affects badge → requests yes | data.affects_requests=true | View badges | Badge shows "saved · requests yes" in info tone | happy |
| MATCHREP-008 | Saved affects badge → requests no | data.affects_requests=false | View badges | Badge shows "saved · requests no" in neutral tone | happy |
| MATCHREP-009 | Saved affects badge → responses yes | data.affects_responses=true | View badges | Badge shows "saved · responses yes" in info tone | happy |
| MATCHREP-010 | Saved affects badge → responses no | data.affects_responses=false | View badges | Badge shows "saved · responses no" in neutral tone | happy |
| MATCHREP-011 | Draft affects badge → visible when dirty | dirty=true, draft has request rules enabled | View badges | Draft affects badge shows "draft · requests yes / responses no" in warn tone | happy |
| MATCHREP-012 | Draft affects badge → hidden when clean | dirty=false | View badges | Draft affects badge not rendered | happy |
| MATCHREP-013 | Rule target select → cycle | rule.rule_type="request_header" | Change target select through all options | Targets cycle through: Request line, Request header, Request body, Response header, Response body; patch updates rule_type each time | happy |
| MATCHREP-014 | Rule target select → response body | rule.rule_type="request_header" | Select "Response body" | rule.rule_type becomes "response_body"; patch marks dirty=true | happy |
| MATCHREP-015 | Rule match kind select → regex | rule.category="literal" | Select "Regex" | rule.category becomes "regex"; patch marks dirty=true | happy |
| MATCHREP-016 | Rule match kind select → literal | rule.category="regex" | Select "Literal" | rule.category becomes "literal"; patch marks dirty=true | happy |
| MATCHREP-017 | Rule match input | rule.string_match="" | Type "Content-Type: application/json" | rule.string_match becomes "Content-Type: application/json"; patch marks dirty=true | happy |
| MATCHREP-018 | Rule match input → empty | rule.string_match="old pattern" | Clear input | rule.string_match becomes ""; patch marks dirty=true | happy |
| MATCHREP-019 | Rule match input → placeholder | input empty | Observe match field | Placeholder shows "empty = add this header" | happy |
| MATCHREP-020 | Rule replace input | rule.string_replace="" | Type "Content-Type: application/xml" | rule.string_replace becomes "Content-Type: application/xml"; patch marks dirty=true | happy |
| MATCHREP-021 | Rule replace input → empty | rule.string_replace="old" | Clear input | rule.string_replace becomes ""; patch marks dirty=true | happy |
| MATCHREP-022 | Rule replace input → placeholder | input empty | Observe replace field | Placeholder shows "empty = delete the match" | happy |
| MATCHREP-023 | Rule comment input | rule.comment="" | Type "Fix JSON content type" | rule.comment becomes "Fix JSON content type"; patch marks dirty=true | happy |
| MATCHREP-024 | Rule comment input → placeholder | input empty | Observe comment field | Placeholder shows "why this rule exists" | happy |
| MATCHREP-025 | Move rule up → success | rules=[R1, R2, R3], index=1 | Click "Move rule 2 up" button | Rule at index 1 moves to index 0; rules becomes [R2, R1, R3]; dirty=true | happy |
| MATCHREP-026 | Move rule up → first rule disabled | index=0 | Observe "Move up" button | Button disabled (index === 0); click has no effect | happy |
| MATCHREP-027 | Move rule down → success | rules=[R1, R2, R3], index=1 | Click "Move rule 2 down" button | Rule at index 1 moves to index 2; rules becomes [R1, R3, R2]; dirty=true | happy |
| MATCHREP-028 | Move rule down → last rule disabled | index=rules.length-1 | Observe "Move down" button | Button disabled; click has no effect | happy |
| MATCHREP-029 | Duplicate rule → creates copy | rules=[R1], index=0 | Click "Duplicate rule 1" button | Copy of R1 inserted at index 1; rules becomes [R1, R1-copy]; dirty=true | happy |
| MATCHREP-030 | Duplicate rule → copy is independent | rules=[R1, R1-copy], edit R1-copy | Change R1-copy.comment to "modified" | R1.comment unchanged; only R1-copy modified; both persist | happy |
| MATCHREP-031 | Delete rule button → opens modal | rules=[R1, R2], index=0 | Click "Delete rule 1" button | setConfirmDelete(0); modal opens with title "Delete this rule?" | happy |
| MATCHREP-032 | Delete confirmation modal → keep it | confirmDelete=0 | Click "Keep it" button in modal | setConfirmDelete(null); modal closes; rules unchanged | happy |
| MATCHREP-033 | Delete confirmation modal → delete | confirmDelete=0, rules=[R1, R2] | Click "Delete rule" button in modal | Rule at index 0 removed; rules becomes [R2]; dirty=true; modal closes | happy |
| MATCHREP-034 | Delete rule → single rule | rules=[R1], index=0 | Click delete; confirm | R1 removed; rules becomes []; modal closes; rules table shows empty state | happy |
| MATCHREP-035 | Update Content-Length switch → on | draft.update_content_length=false | Toggle switch "Update Content-Length..." | draft.update_content_length becomes true; dirty=true (if it wasn't already) | happy |
| MATCHREP-036 | Update Content-Length switch → off | draft.update_content_length=true | Toggle switch | draft.update_content_length becomes false; dirty=true | happy |
| MATCHREP-037 | Save rules → success | dirty=true, rules=[R1, R2] | Click "Save rules" button | save.mutate fires with {rules, update_content_length}; button shows "Saving…"; on success: baseline synced, dirty=false, toast.success("Saved 2 rules"), page updates | happy |
| MATCHREP-038 | Save rules → singular | dirty=true, rules=[R1] | Click "Save rules" button | toast.success shows "Saved 1 rule" (no 's') | happy |
| MATCHREP-039 | Save rules → error | dirty=true, mutation fails | Click "Save rules" button | toast.error shows error message; dirty remains true; button becomes enabled for retry | error |
| MATCHREP-040 | Save button disabled when clean | dirty=false | Observe "Save rules" button | Button is disabled | happy |
| MATCHREP-041 | Save button disabled while pending | dirty=true, save.isPending=true | Observe button state | Button shows "Saving…" and is disabled | happy |
| MATCHREP-042 | Revert button → success | dirty=true, baseline set | Click "Revert" button | draft = JSON.parse(baseline); dirty=false; table resets to saved state; toast.success("Reverted to the saved rule set") | happy |
| MATCHREP-043 | Revert button disabled | dirty=false | Observe "Revert" button | Button is disabled | happy |
| MATCHREP-044 | Refresh button click | page loaded | Click RefreshButton | refetch() executes on useMatchReplace; isFetching=true; data re-fetches | happy |
| MATCHREP-045 | Dirty status badge | dirty=false | View badge in header | Badge shows "saved" in good tone | happy |
| MATCHREP-046 | Dirty status badge → unsaved | dirty=true | View badge in header | Badge shows "unsaved changes" in warn tone | happy |
| MATCHREP-047 | Test direction select → request | direction="response" | Select "Request rules" | setDirection("request"); setOutput(null) clears previous test result; subsequent test uses request direction | happy |
| MATCHREP-048 | Test direction select → response | direction="request" | Select "Response rules" | setDirection("response"); setOutput(null); subsequent test applies to response | happy |
| MATCHREP-049 | Sample input editor | sample="" | Type raw HTTP request into editor | setSample updates; onChange also calls setOutput(null) to clear previous test result | happy |
| MATCHREP-050 | Sample input placeholder | sample="" | Observe editor | Placeholder shows "Paste a raw request or response to run the draft rules against." | happy |
| MATCHREP-051 | Test draft button → requires sample | sample="" | Observe "Test draft" button | Button is disabled (disabled={!sample}) | happy |
| MATCHREP-052 | Test draft button → disabled while testing | sample="content", test.isPending=true | Observe button | Button shows "Testing…" and is disabled | happy |
| MATCHREP-053 | Test draft success → request | sample="GET / HTTP/1.1...", direction="request" | Click "Test draft" button | test.mutate fires with {input, direction, draft_rules}; on success: setOutput({text, changed}); output editor updates; badge shows "changed" or "no change" | happy |
| MATCHREP-054 | Test draft success → response | sample="HTTP/1.1 200 OK...", direction="response" | Click "Test draft" button | test.mutate fires with direction="response"; server applies draft rules to response; output updates | happy |
| MATCHREP-055 | Test draft error | sample="content", test mutation fails | Click "Test draft" button | test.mutate fires; on error: setOutput(null), toast.error shows message; output editor reverts to placeholder | error |
| MATCHREP-056 | Output editor value → changed | output={text:"modified content", changed:true} | View output editor after successful test | Output shows test result text; badge shows "changed" in info tone | happy |
| MATCHREP-057 | Output editor value → no change | output={text:"same content", changed:false} | View output editor after test | Badge shows "no change" in neutral tone | happy |
| MATCHREP-058 | Output editor value → before test | output=null | View output editor before running test | Value shows "Run the test to see what the draft rules would produce." | happy |
| MATCHREP-059 | Output editor readonly | output set | View output editor | Editor is readOnly; cannot edit content | happy |
| MATCHREP-060 | Empty state → no rules | rules=[], draft loaded | View page | Empty state shows title "No rules", detail "Add a rule to rewrite a header, a request line, or a body on the way through the proxy.", action button "Add rule" | empty-state |
| MATCHREP-061 | Loading state | !draft, isFetching | View page | LoadingPanel shows label "Loading rule set" | happy |
| MATCHREP-062 | Error state | error from useMatchReplace | View page | Page renders with ErrorNotice; error message shown; "Retry" button visible | error |
| MATCHREP-063 | Wired rules warning → scope | rules some have scope defined | View page | Warning notice shows "A rule carries a scope or query condition. This build's rule endpoint does not persist either, so saving from here drops it." | happy |
| MATCHREP-064 | Wired rules warning → query | rules some have query defined | View page | Warning notice displays with same message | happy |
| MATCHREP-065 | Wired rules warning → hidden when clean | no rules have scope or query | View page | Warning notice not rendered | happy |
| MATCHREP-066 | Data sync effect → initial load | data loaded | useEffect runs | draft and baseline synced from data; dirty=false | happy |
| MATCHREP-067 | Data sync effect → blocks on dirty | dirty=true, data changes | useEffect checks dirty condition | Re-sync skipped; unsaved edits preserved | happy |
| MATCHREP-068 | Dirty check → baseline comparison | baseline='{"rules":[R1]}', draft still equals JSON.parse(baseline) | Dirty check | dirty = false (strings are identical) | happy |
| MATCHREP-069 | Dirty check → after first edit | baseline set, user changes rule.comment | Dirty check | dirty = true (JSON.stringify(draft) !== baseline) | happy |
| MATCHREP-070 | Draft affects memo → request | rules=[{rule_type:"request_header", enabled:true}] | Calculate draftAffects | draftAffects.request=true, draftAffects.response=false | happy |
| MATCHREP-071 | Draft affects memo → response | rules=[{rule_type:"response_body", enabled:true}] | Calculate draftAffects | draftAffects.response=true, draftAffects.request=false | happy |
| MATCHREP-072 | Draft affects memo → both | rules have both request and response targets enabled | Calculate draftAffects | draftAffects.request=true, draftAffects.response=true | happy |
| MATCHREP-073 | Draft affects memo → ignores disabled | rules=[{rule_type:"request_header", enabled:false}] | Calculate draftAffects | draftAffects.request=false (disabled rules not counted) | happy |
| MATCHREP-074 | Target field conversion → unknown | rule.rule_type="unknown_target" | Component renders | asTarget("unknown_target") returns "request_header" (default fallback) | boundary |
| MATCHREP-075 | Category field conversion → unknown | rule.category="unknown_cat" | Component renders | asCategory("unknown_cat") returns "literal" (default fallback) | boundary |
| MATCHREP-076 | Move rule bounds → move first up | rules=[R1, R2], index=0, move(0, -1) | Attempt move | target=0-1=-1; bounds check (target < 0) returns early; rules unchanged | boundary |
| MATCHREP-077 | Move rule bounds → move last down | rules=[R1, R2], index=1, move(1, 1) | Attempt move | target=1+1=2; bounds check (target >= rules.length) returns early; rules unchanged | boundary |
| MATCHREP-078 | Rule index in loop → identity | rules=[] then [R1, R2, R3], edit R2 | Edit rule at index 1 | patch(1, {...}) updates rules[1]; no key prop on rows means index is the identity | happy |
| MATCHREP-079 | Duplicate rule → independent mutations | duplicate R1, then edit both | Modify R1 and duplicate independently | Changes to R1 do not affect the duplicate; they are separate objects in the array | happy |
| MATCHREP-080 | Sample input boundary → empty | sample="" | Attempt test | Test button disabled; test does not fire | boundary |
| MATCHREP-081 | Sample input boundary → very large | sample with 1MB of data | Click "Test draft" button | Server receives large input; test processes (performance may vary); result or error returned | boundary |
| MATCHREP-082 | Match pattern boundary → regex invalid | string_match="[invalid regex", category="regex", save and test | Save and test run | Server may accept pattern as literal if not compiled as regex, or reject with error | boundary |
| MATCHREP-083 | Match pattern boundary → unicode | string_match="café🎉", category="literal" | Test rule | Pattern stored and matched against content; unicode handled correctly | boundary |
| MATCHREP-084 | Replace string boundary → empty | string_replace="", string_match="old" | Test rule | Replacement is empty; matched text deleted from output (per placeholder: "empty = delete the match") | boundary |
| MATCHREP-085 | Replace string boundary → backreferences | string_replace="$1", string_match="([a-z]+)", category="regex" | Test rule | Backreference syntax handled by server (may work or fail depending on implementation) | boundary |
| MATCHREP-086 | Replace string boundary → very long | string_replace with 10KB of replacement text | Save rule | Pattern accepted; test applies replacement; output grows accordingly | boundary |

---

## Coverage

| Element | References |
|---------|-----------|
| Hold requests/responses checkbox (RuleEditor) | INTERCEPT-013, INTERCEPT-032 |
| Field count hint (RuleEditor) | INTERCEPT-010, INTERCEPT-032, INTERCEPT-033, INTERCEPT-034, INTERCEPT-035 |
| Add rule button (RuleEditor) | INTERCEPT-009, INTERCEPT-010, INTERCEPT-011, MATCHREP-001, MATCHREP-002, MATCHREP-003, MATCHREP-060 |
| Save rules button (RuleEditor) | INTERCEPT-027, INTERCEPT-028, INTERCEPT-029, INTERCEPT-030, INTERCEPT-031 |
| Rule enabled checkbox (per row) | INTERCEPT-012, INTERCEPT-013, MATCHREP-005, MATCHREP-006 |
| Field select (per row) | INTERCEPT-014, INTERCEPT-015 |
| Match pattern input (per row) | INTERCEPT-016, INTERCEPT-017, INTERCEPT-018, INTERCEPT-019, INTERCEPT-020 |
| Match kind select (per row) | INTERCEPT-021, INTERCEPT-022 |
| Comment input (per row) | INTERCEPT-023, INTERCEPT-024, MATCHREP-023, MATCHREP-024 |
| Delete rule button (per row) | INTERCEPT-025, INTERCEPT-026 |
| Intercept on/off switch | INTERCEPT-001, INTERCEPT-002, INTERCEPT-003, INTERCEPT-004, INTERCEPT-005, INTERCEPT-006 |
| Status badge (wired/not wired) | INTERCEPT-036, INTERCEPT-037 |
| Queue tab | INTERCEPT-007 |
| Interception rules tab | INTERCEPT-008 |
| Held messages table | INTERCEPT-039, INTERCEPT-042, INTERCEPT-046, INTERCEPT-050 |
| Message detail view header | INTERCEPT-043, INTERCEPT-044 |
| Clear selection button (intercept) | INTERCEPT-045 |
| HttpEditor held bytes | INTERCEPT-046, INTERCEPT-047, INTERCEPT-048 |
| Fix Content-Length checkbox | INTERCEPT-049 |
| Forward button | INTERCEPT-050, INTERCEPT-051, INTERCEPT-052, INTERCEPT-053 |
| Drop button | INTERCEPT-056, INTERCEPT-057, INTERCEPT-058, INTERCEPT-059 |
| Filter input (history) | HISTORY-001, HISTORY-002, HISTORY-003, HISTORY-008, HISTORY-009, HISTORY-010, HISTORY-011, HISTORY-012, HISTORY-013, HISTORY-014, HISTORY-015, HISTORY-016, HISTORY-017, HISTORY-018, HISTORY-019, HISTORY-020, HISTORY-021, HISTORY-022, HISTORY-023, HISTORY-024, HISTORY-025, HISTORY-026, HISTORY-027, HISTORY-028, HISTORY-029 |
| Clear filter button | HISTORY-004, HISTORY-005 |
| Filter syntax button/modal | HISTORY-006, HISTORY-007 |
| Status filter select | HISTORY-030, HISTORY-031, HISTORY-032, HISTORY-033, HISTORY-034, HISTORY-035 |
| Method filter select | HISTORY-036, HISTORY-037, HISTORY-038, HISTORY-039, HISTORY-093 |
| Row limit select | HISTORY-040, HISTORY-041, HISTORY-042, HISTORY-043 |
| Refresh button (history) | HISTORY-044 |
| Exchanges table | HISTORY-045, HISTORY-046, HISTORY-047, HISTORY-048, HISTORY-050, HISTORY-051, HISTORY-052, HISTORY-053, HISTORY-054, HISTORY-055 |
| Repeater button | HISTORY-068, HISTORY-069 |
| Intruder button | HISTORY-072, HISTORY-073 |
| Compare button | HISTORY-076, HISTORY-077 |
| Inspector toggle | HISTORY-078, HISTORY-079, HISTORY-080, HISTORY-081, HISTORY-082, HISTORY-083, HISTORY-084 |
| Clear selection button (history) | HISTORY-085 |
| Request editor | HISTORY-061, HISTORY-062, HISTORY-063 |
| Response editor | HISTORY-064, HISTORY-065, HISTORY-066, HISTORY-067 |
| Connection row | WSHIST-001, WSHIST-002, WSHIST-003, WSHIST-004, WSHIST-005 |
| Context menu on connection | WSHIST-027, WSHIST-028, WSHIST-029, WSHIST-030, WSHIST-031, WSHIST-032, WSHIST-033 |
| WebSocket frames table | WSHIST-006, WSHIST-007, WSHIST-008, WSHIST-009, WSHIST-010, WSHIST-037, WSHIST-038 |
| Frame detail header | WSHIST-011, WSHIST-012 |
| Clear frame selection button | WSHIST-013 |
| Payload view (text/hex) | WSHIST-014, WSHIST-015, WSHIST-016, WSHIST-017, WSHIST-018, WSHIST-019 |
| Truncation warning | WSHIST-018, WSHIST-019 |
| Refresh button (websocket) | WSHIST-025 |
| Revert button (matchreplace) | MATCHREP-042, MATCHREP-043 |
| Save rules button (matchreplace) | MATCHREP-037, MATCHREP-038, MATCHREP-039, MATCHREP-040, MATCHREP-041 |
| Refresh button (matchreplace) | MATCHREP-044 |
| Enabled count badge | MATCHREP-006 |
| Saved affects badges | MATCHREP-007, MATCHREP-008, MATCHREP-009, MATCHREP-010 |
| Draft affects badge | MATCHREP-011, MATCHREP-012 |
| Rule target select (matchreplace) | MATCHREP-013, MATCHREP-014 |
| Rule match kind select (matchreplace) | MATCHREP-015, MATCHREP-016 |
| Rule match input (matchreplace) | MATCHREP-017, MATCHREP-018, MATCHREP-019, MATCHREP-050, MATCHREP-082 |
| Rule replace input (matchreplace) | MATCHREP-020, MATCHREP-021, MATCHREP-022, MATCHREP-084 |
| Move rule up button | MATCHREP-025, MATCHREP-026 |
| Move rule down button | MATCHREP-027, MATCHREP-028 |
| Duplicate rule button | MATCHREP-029, MATCHREP-030 |
| Delete rule button (matchreplace) | MATCHREP-031, MATCHREP-032, MATCHREP-033, MATCHREP-034 |
| Test direction select | MATCHREP-047, MATCHREP-048 |
| Test draft button | MATCHREP-049, MATCHREP-051, MATCHREP-052, MATCHREP-053, MATCHREP-054, MATCHREP-055 |
| Sample input editor | MATCHREP-049, MATCHREP-050 |
| Output editor | MATCHREP-056, MATCHREP-057, MATCHREP-058, MATCHREP-059 |
| Test changed badge | MATCHREP-056, MATCHREP-057 |
| Delete confirmation modal | MATCHREP-031, MATCHREP-032, MATCHREP-033 |
| Keep it button (modal) | MATCHREP-032 |
| Delete rule modal button | MATCHREP-033 |
| Wired rules warning | MATCHREP-063, MATCHREP-064, MATCHREP-065 |
| Dirty status badge (matchreplace) | MATCHREP-045, MATCHREP-046 |
| Metrics display (intercept) | INTERCEPT-038, WSHIST-026 |
| Metrics display (history) | HISTORY-056, HISTORY-057 |
| Row styling (4xx/5xx) | HISTORY-050, HISTORY-051, HISTORY-052, HISTORY-053 |
| Empty states (intercept) | INTERCEPT-040, INTERCEPT-041, INTERCEPT-062, INTERCEPT-064, INTERCEPT-065, INTERCEPT-066, INTERCEPT-067 |
| Empty states (history) | HISTORY-054, HISTORY-055, HISTORY-086 |
| Empty states (websocket) | WSHIST-020, WSHIST-021, WSHIST-022, WSHIST-023, WSHIST-024 |
| Empty states (matchreplace) | MATCHREP-060, MATCHREP-061 |
| Error states (intercept) | INTERCEPT-062 |
| Error states (history) | HISTORY-059 |
| Error states (websocket) | WSHIST-034, WSHIST-035 |
| Error states (matchreplace) | MATCHREP-062 |
| Keyboard shortcuts (intercept) | INTERCEPT-003, INTERCEPT-004, INTERCEPT-054, INTERCEPT-055 |
| Keyboard shortcuts (history) | HISTORY-070, HISTORY-071, HISTORY-074, HISTORY-075 |
| Cross-page effects (intercept) | None documented |
| Cross-page effects (history) | HISTORY-029, HISTORY-089, HISTORY-090, HISTORY-091, HISTORY-092 |
| Cross-page effects (websocket) | WSHIST-030, WSHIST-040 |
| Cross-page effects (matchreplace) | None documented |
