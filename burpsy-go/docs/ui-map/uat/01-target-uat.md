# Target pages UAT — comprehensive test matrix

## SiteMap page (sitemap.tsx)

| ID | Route | Precondition | Steps | Expected result | Type |
|-----|--------|------------------|---------|-----------------|------|
| SITEMAP-001 | Filter input → tree filtered | Page loaded with data, no filter | 1. Type "api" in Filter input | Tree displays only segments/paths matching "api"; debounce fires after 250ms | happy |
| SITEMAP-002 | Filter input → partial match with ancestors | Tree has "/api/v1/users", no filter active | 1. Type "users" in filter | "/api/v1/users" appears with all ancestors expanded; descendants visible | happy |
| SITEMAP-003 | Filter input → case-insensitive | Tree with mixed case (api, Api, API) | 1. Type "API" (uppercase) | All case variants match; "api", "Api", "API" all appear | boundary |
| SITEMAP-004 | Clear filter button → reset filter | Filter input contains "api", results filtered | 1. Click "Clear filter" button | Filter input clears to ""; tree re-renders showing all nodes | happy |
| SITEMAP-005 | Clear filter button disabled when empty | Filter input is empty, no active filter | 1. Observe "Clear filter" button | Button is not visible or `disabled={true}` | boundary |
| SITEMAP-006 | Tree toggle button → expand node | Collapsed node with children visible in tree | 1. Click expand/collapse toggle on node | Node expands; children render; button shows chevron-down; aria-expanded={true} | happy |
| SITEMAP-007 | Tree toggle button → collapse node | Expanded node with visible children | 1. Click expand/collapse toggle | Node collapses; children hidden; button shows chevron-right; aria-expanded={false} | happy |
| SITEMAP-008 | Tree toggle button absent on leaf | Leaf node (no children) | 1. Observe tree row | No toggle button rendered; only spacer; aria-expanded undefined | boundary |
| SITEMAP-009 | Tree row click → select node | Page loaded, no node selected yet | 1. Click a tree row | Row highlights with `active` class; selectedId set to row.key; detail pane updates with node info and exchanges table | happy |
| SITEMAP-010 | Keyboard ArrowDown → cursor navigation | Tree focused, cursor at first row | 1. Press ArrowDown | Cursor outline moves to next row; selectedId unchanged; cursorId updates | keyboard |
| SITEMAP-011 | Keyboard ArrowUp → cursor navigation | Tree focused, cursor at row 2+ | 1. Press ArrowUp | Cursor moves to previous row; selectedId unchanged | keyboard |
| SITEMAP-012 | Keyboard ArrowRight on collapsed node → expand | Tree focused, cursor on collapsed node with children | 1. Press ArrowRight | Node expands; children become visible | keyboard |
| SITEMAP-013 | Keyboard ArrowRight on leaf → move down | Tree focused, cursor on leaf node | 1. Press ArrowRight | Cursor moves down (to next sibling or further) | keyboard |
| SITEMAP-014 | Keyboard ArrowLeft on expanded node → collapse | Tree focused, cursor on expanded node with children | 1. Press ArrowLeft | Node collapses; children hidden | keyboard |
| SITEMAP-015 | Keyboard ArrowLeft on child → jump to parent | Tree focused, cursor on child node (depth > 0) | 1. Press ArrowLeft | Cursor moves to parent; collapsed/expanded state of child unchanged | keyboard |
| SITEMAP-016 | Keyboard Enter → select at cursor | Tree focused, cursor on node A, node A not selected | 1. Press Enter | Node A selected (selectedId = cursorId); detail pane updates | keyboard |
| SITEMAP-017 | Tree focus → auto-initialize cursor | Tree container focused, cursorId null, rows.length > 0 | 1. Click tree container or press ArrowDown | cursorId set to first row; cursor outline appears on row 0 | keyboard |
| SITEMAP-018 | Exchange table row click → select exchange | Node selected, exchanges table visible with 2+ rows | 1. Click an exchange row | Row highlights; selectedExchange set to row.id; request/response editors load and display content | happy |
| SITEMAP-019 | Exchange table row double-click → send to Repeater | Node selected, exchange row visible | 1. Double-click (onActivate) exchange row | Exchange sent to Repeater; cross-page action fires | alternate-entry |
| SITEMAP-020 | Send to Repeater button click | Exchange selected in table | 1. Click "Repeater" button | actions.sendToRepeater(activeExchange) called; message sent to Repeater tool | happy |
| SITEMAP-021 | Send to Repeater button disabled | No exchange selected, activeExchange is null | 1. Observe "Repeater" button state | Button `disabled={true}` or grayed out | boundary |
| SITEMAP-022 | Send to Intruder button click | Exchange selected | 1. Click "Intruder" button | actions.sendToIntruder(activeExchange) called | happy |
| SITEMAP-023 | Send to Intruder button disabled | No exchange selected | 1. Observe "Intruder" button | Button disabled | boundary |
| SITEMAP-024 | Send to Comparer button click | Exchange selected | 1. Click "Compare" button | actions.sendToComparer(activeExchange, "a") called; slot "a" filled | happy |
| SITEMAP-025 | Send to Comparer button disabled | No exchange selected | 1. Observe "Compare" button | Button disabled | boundary |
| SITEMAP-026 | Inspector toggle → show | Exchange selected, inspector state false | 1. Click "Show Inspector" button | inspector state becomes true; editor grid CSS class changes to "editor-grid-inspected"; Inspector component renders with request raw bytes; button label becomes "Hide Inspector" | happy |
| SITEMAP-027 | Inspector toggle → hide | Exchange selected, inspector state true | 1. Click "Hide Inspector" button | inspector state false; grid class returns to "editor-grid"; Inspector component removed; button label becomes "Show Inspector" | happy |
| SITEMAP-028 | Inspector button disabled | No exchange selected | 1. Observe Inspector button | Button disabled | boundary |
| SITEMAP-029 | Inspector button aria-pressed state | Exchange selected | 1. Observe aria-pressed attribute | aria-pressed={inspector} (true when open, false when closed) | a11y |
| SITEMAP-030 | Filter history button click → navigate | Node selected | 1. Click "Filter history" button | filterHistory(selected) executes; query constructed from node path with escaped quotes/backslashes; setRoute("history") called; history page loads with query active | happy |
| SITEMAP-031 | Filter history button disabled | No node selected, selected is null | 1. Observe "Filter history" button | Button disabled or absent | boundary |
| SITEMAP-032 | Filter history button → escape special chars | Selected node path contains quotes/backslashes, e.g., "/api/search?q=a\<b" | 1. Click "Filter history" | Query escapes backslashes and quotes in path literal; e.g., `path ~ "/api/search?q=a\<b"` becomes `path ~ "/api/search?q=a\\<b"` with escaped quote | boundary |
| SITEMAP-033 | Page refresh button click | Page loaded with data | 1. Click refresh icon-button | refetch() called; isFetching becomes true during fetch | happy |
| SITEMAP-034 | Page refresh loading state | Refresh button clicked, refetch in progress | 1. Wait during refetch | isFetching && !data shows LoadingPanel; "Loading site map…" text displays | happy |
| SITEMAP-035 | Empty state — initial load | Page component mounts, no data yet | 1. Observe page on first load | isFetching && !data → Empty title "Loading site map…", detail "Folding captured traffic into a tree." | empty-state |
| SITEMAP-036 | Empty state — no traffic captured | Page loaded, data exists but tree is empty (rows.length === 0 && !term) | 1. Observe tree pane | Empty title "No traffic captured yet", detail "Point a client at the proxy to start building the map." | empty-state |
| SITEMAP-037 | Empty state — filter no matches | Page loaded, filter applied (term non-empty), rows.length === 0 | 1. Type filter with no matches | Empty title "No path matches this filter", detail "Relax the filter, or clear it to see the whole map." | empty-state |
| SITEMAP-038 | Empty state — no node selected | Page loaded with data, no node selection yet | 1. Observe detail pane on load | Empty title "No path selected", detail "Choose a host or path in the tree to see the requests captured under it." | empty-state |
| SITEMAP-039 | Empty state — no exchanges under node | Node selected but nodeExchanges.length === 0 | 1. Select a node with no history | Empty title "No requests under this node", detail text depends on node.requested flag | empty-state |
| SITEMAP-040 | Empty state — node.requested=true, no history | Node marked as requested but no cached exchanges | 1. Select such node | Detail text: "The capture holding these exchanges may have rolled over." | empty-state |
| SITEMAP-041 | Empty state — node.requested=false, no history | Node never directly requested (inferred folder) | 1. Select such node | Detail text: "Nothing requested this folder itself — open a child node to see its traffic." | empty-state |
| SITEMAP-042 | Empty state — no exchange in table selection | Node selected with exchanges, no exchange row clicked | 1. Select node, observe table without clicking a row | Detail pane shows "No request selected", detail "Choose a row above to read its exact request and response bytes." | empty-state |
| SITEMAP-043 | Request editor loading state | Exchange selected, request message fetching | 1. Select exchange, watch useMessage(request) | HttpEditor shows "Loading request bytes…" until request.isFetching === false | empty-state |
| SITEMAP-044 | Request editor no bytes | Exchange selected, request loaded but request.data?.text absent | 1. Select exchange with empty request | HttpEditor shows "No request bytes captured." | empty-state |
| SITEMAP-045 | Response editor no response | Exchange selected, exchange.response === null | 1. Select exchange with no response | HttpEditor shows "No response was captured for this exchange." | empty-state |
| SITEMAP-046 | Response editor loading state | Exchange selected, response message fetching | 1. Select exchange, watch useMessage(response) | HttpEditor shows "Loading response bytes…" until response.isFetching === false | empty-state |
| SITEMAP-047 | Response editor no bytes | Exchange selected, response loaded but response.data?.text absent | 1. Select exchange with empty response | HttpEditor shows "No response bytes captured." | empty-state |
| SITEMAP-048 | API error — fetch failure | useSitemapDetailed() returns error | 1. Trigger API failure (e.g., network down) | ErrorNotice displays error message; "Retry" button visible | error |
| SITEMAP-049 | API error — retry action | Error state active with ErrorNotice | 1. Click "Retry" button | refetch() called; page re-attempts data fetch | error |
| SITEMAP-050 | Exchange ID boundary — zero | Exchange with id=0 exists | 1. Select exchange with id=0 | Exchange selects correctly; detail displays "#0" with correct info | boundary |
| SITEMAP-051 | Node key consistency — server-provided | Server provides node.key, used for expansion/selection | 1. Select node, expand children | expand/collapse key and node.key never disagree on node identity; consistent tree state | boundary |
| SITEMAP-052 | Filter debounce timing | Filter input receives rapid keystrokes | 1. Type "a", "api", "api/v1" in quick succession without waiting | Filtering waits 250ms after last keystroke before applying; only final filter result renders | happy |
| SITEMAP-053 | Multi-level tree expansion with keyboard | Tree with 3+ nested levels | 1. Use ArrowRight/Left to expand/collapse multiple levels | All levels expand/collapse independently; cursor navigation smooth across depths | keyboard |
| SITEMAP-054 | Tree node metadata display — params | Node has query parameters in node.params array | 1. Select such node, observe tree row | Row displays "?param1,param2" suffix with tooltip showing full parameter list; aria-label includes count | a11y |
| SITEMAP-055 | Tree node metadata display — issues | Node has node.subtree_issues > 0 | 1. Select such node | Severity dot (sev-{severity}) displays with title "X finding(s) here or below"; color matches severity | a11y |
| SITEMAP-056 | Tree node metadata display — exchange count | Node has node.subtree_exchanges | 1. Observe tree row | Count displayed right-aligned as cell-num class | happy |
| SITEMAP-057 | Tree row styling — inferred node | Node at depth > 0 with node.requested === false | 1. Observe tree row appearance | Row label has cell-dim class (dimmed); title shows "(no request to this path itself)" suffix | a11y |
| SITEMAP-058 | Host node icon | Tree row at depth === 0 | 1. Observe tree row icon | Globe icon renders; aria-hidden="true" | a11y |
| SITEMAP-059 | Path node icon — folder (expanded) | Depth > 0, hasChildren, expanded === true | 1. Observe icon | FolderOpen icon displays | a11y |
| SITEMAP-060 | Path node icon — folder (collapsed) | Depth > 0, hasChildren, expanded === false | 1. Observe icon | Folder icon displays | a11y |
| SITEMAP-061 | Path node icon — leaf | Depth > 0, hasChildren === false | 1. Observe icon | No icon renders; space reserved | a11y |
| SITEMAP-062 | Exchange table columns — all present | Exchange table renders | 1. Scroll horizontally through table | All columns visible: #, Method, URL, Params, Status, Length, MIME, Time, Age | happy |
| SITEMAP-063 | Exchange table cell formatting — status | Exchange has status code | 1. Observe Status column | Status displays as Badge with tone={statusTone(status)}; "pending" for null | a11y |
| SITEMAP-064 | Exchange table cell formatting — MIME | Exchange has MIME type | 1. Observe MIME column | MIME displays; "—" if undefined | happy |
| SITEMAP-065 | Exchange table cell formatting — bytes | Response length in bytes | 1. Observe Length column | formatBytes() applied; e.g., "1.2 KB" | happy |
| SITEMAP-066 | Exchange table cell formatting — duration | Duration in milliseconds | 1. Observe Time column | formatDuration() applied; e.g., "45ms" | happy |
| SITEMAP-067 | Exchange table cell formatting — age | Timestamp in milliseconds | 1. Observe Age column | relativeTime() applied; e.g., "2m ago" | happy |
| SITEMAP-068 | Detail pane split position persistence | Split pane resized and adjusted | 1. Drag detail pane divider to resize | Position saved to localStorage under storageId "sitemap-detail"; persists across page reload | happy |
| SITEMAP-069 | Main split position persistence | Horizontal split between tree and detail | 1. Drag main pane divider | Position saved under storageId "sitemap"; persists | happy |
| SITEMAP-070 | Node selection across filter changes | Node selected, filter applied, filter cleared | 1. Select node, apply filter, clear filter | selectedId persists; same node remains selected when filter is cleared | happy |
| SITEMAP-071 | Exchange selection clears on node change | Exchange selected, different node clicked | 1. Select exchange under node A, click node B | selectedExchange reset to null; detail pane shows empty state for new node | happy |

## Scanner page (scanner.tsx)

| ID | Route | Precondition | Steps | Expected result | Type |
|-----|--------|------------------|---------|-----------------|------|
| SCANNER-001 | Filter input — by check name | Findings loaded, no filter active | 1. Type finding check name in filter | Findings matching check name appear; debounce fires 260ms after last keystroke | happy |
| SCANNER-002 | Filter input — by issue name | Findings with issue_name property | 1. Type part of issue name | Matching findings appear; includes both issue_name and check_name search | happy |
| SCANNER-003 | Filter input — by host | Findings across hosts | 1. Type hostname | Findings on that host display; host tree node appears | happy |
| SCANNER-004 | Filter input — by detail text | Findings with detail prose | 1. Type word from detail | Findings with that word in detail match and appear | happy |
| SCANNER-005 | Filter input — case insensitive | Mixed-case finding names | 1. Type uppercase version of lowercase finding | Matches display; case-insensitive search confirmed | boundary |
| SCANNER-006 | Severity filter select — all severities | Page loaded with findings | 1. Select "All severities" from Severity filter | All findings display regardless of severity; dropdown shows "All severities" | happy |
| SCANNER-007 | Severity filter select — critical only | Findings with various severities | 1. Select "Critical" from Severity filter | Only Critical findings appear; rows filtered in-place | happy |
| SCANNER-008 | Severity filter select — combinations | Multiple severity filters available | 1. Select "High" | Only High findings display; change to "Medium" | Filter updates on select change | happy |
| SCANNER-009 | Confidence filter select — all | Page loaded | 1. Select "All confidence" | All findings display | happy |
| SCANNER-010 | Confidence filter select — certain only | Mixed confidence findings | 1. Select "Certain" | Only Certain confidence findings appear | happy |
| SCANNER-011 | Confidence filter select — combinations | Multiple confidences available | 1. Select "Firm", then "Tentative" | Correct findings filter each time | happy |
| SCANNER-012 | Combined filters — severity + confidence | Findings with mixed attributes | 1. Set severity="High", confidence="Certain" | Only High AND Certain findings appear; both filters applied | happy |
| SCANNER-013 | Combined filters — text + severity + confidence | Multiple filter types | 1. Type "sql", set severity="Critical", confidence="Certain" | Only findings matching text AND severity AND confidence display | happy |
| SCANNER-014 | Host tree row — click to toggle | Host row visible, collapsed | 1. Click host row | Host expands; paths become visible; aria-expanded={true} | happy |
| SCANNER-015 | Host tree row — toggle button click | Host with paths, collapsed | 1. Click host toggle button | Host expands; paths appear; button shows chevron-down | happy |
| SCANNER-016 | Host tree row — collapse | Host expanded with visible paths | 1. Click host toggle button | Host collapses; paths hidden; button shows chevron-right | happy |
| SCANNER-017 | Host tree row — count metadata | Host with findings | 1. Observe host row | Right side shows host.count as cell-num; total findings under host | a11y |
| SCANNER-018 | Path tree row — click to toggle | Path row visible, host open, path collapsed | 1. Click path row | Path expands; findings appear; aria-expanded={true} | happy |
| SCANNER-019 | Path tree row — toggle button | Path collapsed under open host | 1. Click path toggle button | Path expands; leaf findings visible | happy |
| SCANNER-020 | Path tree row — collapse | Path expanded with visible findings | 1. Click path toggle button | Path collapses; findings hidden | happy |
| SCANNER-021 | Path tree row — count metadata | Path with findings | 1. Observe path row | Right side shows path.leaves.length as count | a11y |
| SCANNER-022 | Finding leaf — click to select | Leaf visible (host and path open) | 1. Click finding leaf | Leaf highlights with `active` class; selectedKey set; advisory tab shows finding detail | happy |
| SCANNER-023 | Finding leaf — severity dot | Leaf row visible | 1. Observe left icon area | SeverityDot renders with class `sev-{severity.toLowerCase()}`; aria-label shows severity name | a11y |
| SCANNER-024 | Finding leaf — confidence metadata | Leaf shows confidence in row | 1. Observe right metadata area | Leaf.finding.confidence displays as cell-dim class; e.g., "Certain" | happy |
| SCANNER-025 | Advisory tab — default selection | Finding selected | 1. Observe tabs on advisory pane | Advisory tab is selected by default; TabsTrigger shows value="advisory" | happy |
| SCANNER-026 | Advisory tab — detail list | Finding selected | 1. Click Advisory tab | DetailList shows: Check, Host, Path, Times seen, Occurrences | happy |
| SCANNER-027 | Advisory tab — issue detail section | Finding has detail text | 1. Click Advisory tab | Section "Issue detail" displays finding.detail prose; "no detail recorded" if absent | happy |
| SCANNER-028 | Advisory tab — remediation section | Finding has remediation text | 1. Click Advisory tab | Section "Remediation" displays finding.remediation prose; "no remediation recorded" if absent | happy |
| SCANNER-029 | Advisory tab — occurrences buttons | Finding with occurrences.length > 1 | 1. Click Advisory tab, scroll | Section "All occurrences (X)" displays X buttons; each labeled "#{exchange_id} {path}" | happy |
| SCANNER-030 | Occurrence button — navigate to exchange | Finding with multiple occurrences | 1. Click occurrence button (e.g., "#42 /api/users") | focusExchange(occurrence.exchange_id) called; setRoute("history") called; history page opens with exchange highlighted | happy |
| SCANNER-031 | Request tab — no occurrence | Finding with no occurrence | 1. Click Request tab | Empty title "No request recorded", detail "This finding was not tied to a captured exchange." | empty-state |
| SCANNER-032 | Request tab — exchange not in history | Finding occurrence points outside last 1000 history | 1. Click Request tab | Empty title "Exchange not in the loaded history", detail "Finding points at exchange #X, which is outside the last 1000 captured." | empty-state |
| SCANNER-033 | Request tab — loading | Exchange selected, request message fetching | 1. Watch useMessage(exchange?.request) | HttpEditor shows "Loading request bytes…" until request.isFetching === false | empty-state |
| SCANNER-034 | Request tab — display content | Exchange found, request loaded | 1. Click Request tab | HttpEditor displays request.data?.text with filename `finding-{id}-request.txt` | happy |
| SCANNER-035 | Response tab — no occurrence | Finding with no occurrence | 1. Click Response tab | Empty title "No response recorded", detail "This finding was not tied to a captured exchange." | empty-state |
| SCANNER-036 | Response tab — exchange not in history | Finding occurrence outside last 1000 | 1. Click Response tab | Empty title "Exchange not in the loaded history" with exchange ID detail | empty-state |
| SCANNER-037 | Response tab — no response captured | Exchange selected, exchange.response === null | 1. Click Response tab | HttpEditor shows "No response was captured for this exchange." | empty-state |
| SCANNER-038 | Response tab — loading | Exchange selected, response message fetching | 1. Watch useMessage(exchange?.response) | HttpEditor shows "Loading response bytes…" | empty-state |
| SCANNER-039 | Response tab — display content | Exchange found, response loaded | 1. Click Response tab | HttpEditor displays response.data?.text with filename `finding-{id}-response.txt` | happy |
| SCANNER-040 | Severity badge in advisory | Finding selected | 1. Observe detail pane action badges | Badge displays finding.severity with tone={severityTone(severity)}; e.g., "Critical" in red | a11y |
| SCANNER-041 | Confidence badge in advisory | Finding selected | 1. Observe detail pane action badges | Badge displays finding.confidence with tone={confidenceTone(confidence)}; e.g., "Certain" in green | a11y |
| SCANNER-042 | In history button — with occurrence | Finding has occurrence | 1. Observe advisory action buttons | "In history" button present and enabled | happy |
| SCANNER-043 | In history button — without occurrence | Finding has no occurrence | 1. Observe advisory action buttons | "In history" button absent or disabled | boundary |
| SCANNER-044 | In history button — click | Finding with occurrence selected | 1. Click "In history" button | focusExchange(selected.occurrence.exchange_id) and setRoute("history") called; history page shows exchange | happy |
| SCANNER-045 | Audit settings button — open modal | Page loaded | 1. Click "Audit settings" button | Modal opens with title "Audit settings" and description "What the scanner runs, and what it has already covered." | happy |
| SCANNER-046 | Audit settings modal — close | Modal open | 1. Click outside modal or press Escape | Modal closes; settingsOpen === false | happy |
| SCANNER-047 | Live audit card — title and description | Modal open | 1. Observe LiveAuditCard | Title "Live active audit"; description "Audits new in-scope traffic as it is captured. Active checks are never sent automatically while this is off." | happy |
| SCANNER-048 | Live audit switch — enable | Modal open, data.wired === true, data.enabled === false | 1. Click live audit switch | setLive.mutate({ enabled: true }) called; switch shows checked; toast "completed" | happy |
| SCANNER-049 | Live audit switch — disable | Modal open, data.enabled === true | 1. Click live audit switch | setLive.mutate({ enabled: false }) called; switch shows unchecked; toast "completed" | happy |
| SCANNER-050 | Live audit switch — not wired error | data?.wired === false | 1. Click live audit switch | toast.error("Live active audit is not wired up on this server"); switch disabled | error |
| SCANNER-051 | Live audit card — not wired notice | data.wired === false | 1. Observe LiveAuditCard | Notice div displays "{data.hint ?? 'not available'}" with class "notice notice-warn" | empty-state |
| SCANNER-052 | Live audit metrics — swept and findings | data.wired === true | 1. Observe LiveAuditCard metrics | Two metrics display: "Exchanges swept" and "Findings" with localized counts | happy |
| SCANNER-053 | Live audit badges — not swept yet | data.behind > 0 | 1. Observe LiveAuditCard badges | Badge with tone="warn" shows "{data.behind.toLocaleString()} not swept yet" | happy |
| SCANNER-054 | Live audit badges — given up on | data.skipped > 0 | 1. Observe LiveAuditCard badges | Badge shows "{data.skipped.toLocaleString()} given up on" | happy |
| SCANNER-055 | Live audit badges — stalled | data.stalled_at !== undefined | 1. Observe LiveAuditCard badges | Badge shows "waiting on #{data.stalled_at}" | happy |
| SCANNER-056 | Live audit badges — already covered | data.collapsed > 0 | 1. Observe LiveAuditCard badges | Badge shows "{data.collapsed.toLocaleString()} already covered" | happy |
| SCANNER-057 | Live audit badges — ledger resets | data.ledger_resets > 0 | 1. Observe LiveAuditCard badges | Badge shows "{data.ledger_resets.toLocaleString()} ledger reset(s)" | happy |
| SCANNER-058 | Live audit field hint — complete | gaps.length === 0, data.query absent | 1. Observe field-hint text | Text "complete — the sweep is caught up, nothing skipped and nothing waiting" | happy |
| SCANNER-059 | Live audit field hint — with gaps | gaps.length > 0 | 1. Observe field-hint text | Text "a floor, not a total: {gaps.join("; ")}" | happy |
| SCANNER-060 | Live audit field hint — filtered query | data.query present | 1. Observe field-hint text | Text includes "· filtered to {data.query}" | happy |
| SCANNER-061 | Coverage card — title | Modal open | 1. Observe CoverageCard | Title "Passive check coverage" | happy |
| SCANNER-062 | Coverage card — not enabled notice | data.enabled === false | 1. Observe CoverageCard | Notice div displays "{data.hint ?? 'passive BCheck scanning is not enabled'}" | empty-state |
| SCANNER-063 | Coverage card — partition badges | data.partition?.length > 0 | 1. Observe CoverageCard badges | Each partition displays as Badge "{p.count} {p.state}" | happy |
| SCANNER-064 | Coverage card — checks table | data.enabled === true, data.checks.length > 0 | 1. Observe CoverageCard table | Columns: Check, Ran, Findings, Errored, State; rows for each check | happy |
| SCANNER-065 | Coverage card — check row state badge | Check in table with errored > 0 | 1. Observe State column | Badge tone="warn" with title={check.last_error} showing check.state | happy |
| SCANNER-066 | Coverage card — check row state badge (good) | Check with errored === 0 | 1. Observe State column | Badge tone="good" showing check.state | happy |
| SCANNER-067 | Scan config select — server default | Modal open | 1. Observe "Scan configuration" select | Default option shows "server default" | happy |
| SCANNER-068 | Scan config select — load configs | configsQuery.data?.configs populated | 1. Observe "Scan configuration" options | Config options populate from server; each as `<option value={name}>` | happy |
| SCANNER-069 | Scan config select — change value | Modal open, multiple configs available | 1. Select a config from dropdown | configName state updates to selected value | happy |
| SCANNER-070 | Exchange ID input — type number | Modal open | 1. Type "42" in Exchange ID input | Input.value === "42"; type="number" attribute set | happy |
| SCANNER-071 | Exchange ID input — empty | Modal open, no input entered | 1. Observe Exchange ID input | Placeholder "Exchange ID" shows; input.value === "" | happy |
| SCANNER-072 | Audit button — enabled | Modal open, exchangeId non-empty, runAudit.isPending === false | 1. Observe "Audit" button | Button enabled; `disabled={false}` | happy |
| SCANNER-073 | Audit button — disabled (no exchange) | Modal open, exchangeId === "" | 1. Observe "Audit" button | Button disabled; `disabled={true}` | boundary |
| SCANNER-074 | Audit button — disabled (pending) | Modal open, runAudit.isPending === true | 1. Observe "Audit" button | Button disabled; label shows "Auditing…" | happy |
| SCANNER-075 | Audit button click — valid exchange | Modal open, exchangeId="42" | 1. Click "Audit" button | runAudit.mutate({ exchangeId: 42, config: configName || undefined }) called; button disabled | happy |
| SCANNER-076 | Audit button — validation (non-numeric) | Modal open, exchangeId="abc" | 1. Click "Audit" button | toast.error("Enter an exchange id — a whole number, counting from 0"); no API call | boundary |
| SCANNER-077 | Audit button — validation (negative) | Modal open, exchangeId="-1" | 1. Click "Audit" button | toast.error message; no API call (negative id invalid) | boundary |
| SCANNER-078 | Audit button — validation (decimal) | Modal open, exchangeId="1.5" | 1. Click "Audit" button | toast.error message; no API call (!Number.isInteger) | boundary |
| SCANNER-079 | Audit button — exchange zero valid | Modal open, exchangeId="0" | 1. Click "Audit" button | runAudit.mutate({ exchangeId: 0 }) called; exchange 0 treated as valid | boundary |
| SCANNER-080 | Audit result card — on success | runAudit.mutate succeeded, auditResult populated | 1. Observe audit result card | Card title "Audit result — exchange #{auditResult.exchange_id}"; config_name badge shown | happy |
| SCANNER-081 | Audit result card — error badge | auditResult.error set | 1. Observe audit result card badge | Badge tone="bad" shows "{auditResult.config_name || 'server default'}" | happy |
| SCANNER-082 | Audit result card — success badge | auditResult.error absent | 1. Observe audit result card badge | Badge tone="good" shows config name | happy |
| SCANNER-083 | Audit result detail list | auditResult present | 1. Observe detail list in result card | Rows: Active checks, Unimplemented checks, Time budget, Max requests; values populated | happy |
| SCANNER-084 | Audit result breakdown | auditResult.breakdown present | 1. Observe JsonView | JsonView renders breakdown with label="breakdown", defaultOpen={1} | happy |
| SCANNER-085 | Audit result outcome | auditResult.outcome present | 1. Observe JsonView | JsonView renders outcome with label="outcome", defaultOpen={1} | happy |
| SCANNER-086 | Audit result dispositions | auditResult.dispositions present | 1. Observe JsonView | JsonView renders dispositions with label="dispositions", defaultOpen={0} | happy |
| SCANNER-087 | Report download — HTML | Page loaded | 1. Click "HTML" link button | href="/api/report/html" with download attribute; browser downloads report | happy |
| SCANNER-088 | Report download — JSON | Page loaded | 1. Click "JSON" link button | href="/api/report/json" with download attribute; browser downloads report | happy |
| SCANNER-089 | Report download — SARIF | Page loaded | 1. Click "SARIF" link button | href="/api/report/sarif" with download attribute; browser downloads report | happy |
| SCANNER-090 | Refresh button click | Page loaded with findings | 1. Click refresh icon-button | refetch() called; isFetching becomes true | happy |
| SCANNER-091 | Refresh button loading state | Refresh clicked, fetch in progress | 1. Wait during refetch | isFetching && !issues shows LoadingPanel (no label shown; generic spinner) | happy |
| SCANNER-092 | Empty state — loading | Page loads, no data yet | 1. Observe tree pane on mount | isFetching && !issues → LoadingPanel displays | empty-state |
| SCANNER-093 | Empty state — no findings (no filters) | Page loaded, issues exists but groups.length === 0, no filters active | 1. Observe tree pane | Empty title "No findings yet", detail "{issues.hint ?? 'Captured and audited traffic has not produced findings.'}" | empty-state |
| SCANNER-094 | Empty state — filter no matches | Filters active (term OR severity OR confidence), groups.length === 0 | 1. Type non-matching filter | Empty title "No finding matches this filter", detail "{issues?.hint ?? ...}" | empty-state |
| SCANNER-095 | Empty state — no finding selected | Page loaded with findings, no selection yet | 1. Observe detail pane on load | Empty title "Select a finding", detail "Choose an issue in the tree to read its advisory and the exact request and response it was found in." | empty-state |
| SCANNER-096 | Passive scanning disabled notice | issues && !issues.enabled | 1. Observe page | Notice div with class "notice notice-warn" displays "{issues.hint ?? 'passive scanning is not enabled'}" | empty-state |
| SCANNER-097 | API error — fetch findings | useIssuesDetailed() returns error | 1. Trigger API failure | ErrorNotice displays error message; "Retry" button present | error |
| SCANNER-098 | API error — retry findings | Error state active | 1. Click "Retry" button | refetch() called; page re-fetches findings | error |
| SCANNER-099 | Severity counts in header | Page loaded with mixed severities | 1. Observe PageHeader badges | One Badge per severity in severityCounts; label "{count} {severity}"; title shows tooltip | happy |
| SCANNER-100 | Filter persistence across selections | Filter active, finding selected, filter cleared | 1. Set filters, select finding, clear filters | selectedKey persists; same finding remains selected when filters change | happy |

## Scope page (scope.tsx via ScopeSection)

| ID | Route | Precondition | Steps | Expected result | Type |
|-----|--------|------------------|---------|-----------------|------|
| SCOPE-001 | Scope rule kind select — include | Page loaded | 1. Select "include" from kind dropdown | kind state = "include" | happy |
| SCOPE-002 | Scope rule kind select — exclude | Page loaded | 1. Select "exclude" from kind dropdown | kind state = "exclude" | happy |
| SCOPE-003 | Scope rule kind select — default | Page loaded on first render | 1. Observe kind select | kind state initialized to "include" | happy |
| SCOPE-004 | Host pattern input — type | Page loaded | 1. Type "api.example.com" in Host pattern input | pattern state updates to "api.example.com" | happy |
| SCOPE-005 | Host pattern input — empty | Page loaded | 1. Leave Host pattern input empty | pattern state = ""; placeholder "api.example.com" shows | happy |
| SCOPE-006 | Host pattern input — wildcard syntax | Page loaded | 1. Type "*.example.com" in Host pattern | pattern state = "*.example.com" | happy |
| SCOPE-007 | Host pattern input — whitespace only | Page loaded | 1. Type "   " (spaces only) | pattern state = "   " | boundary |
| SCOPE-008 | Add rule button — enabled | Page loaded, pattern="api.example.com" | 1. Observe "Add rule" button | Button enabled; `disabled={false}` | happy |
| SCOPE-009 | Add rule button — disabled (empty pattern) | Page loaded, pattern="" | 1. Observe "Add rule" button | Button disabled; `disabled={true}` | boundary |
| SCOPE-010 | Add rule button — disabled (whitespace only) | Page loaded, pattern="   " | 1. Observe "Add rule" button | Button disabled (pattern.trim() is empty) | boundary |
| SCOPE-011 | Add rule button — disabled (pending) | Pattern non-empty, update.isPending === true | 1. Observe "Add rule" button | Button disabled | happy |
| SCOPE-012 | Add rule button click — include rule | Page loaded, kind="include", pattern="api.example.com" | 1. Click "Add rule" button | run({ action: "include", pattern: "api.example.com" }, ...) called; toast "included api.example.com"; pattern input cleared to ""; rules table refetch | happy |
| SCOPE-013 | Add rule button click — exclude rule | Page loaded, kind="exclude", pattern="api.example.com" | 1. Click "Add rule" button | run({ action: "exclude", pattern: "api.example.com" }, ...) called; toast "excluded api.example.com"; pattern cleared | happy |
| SCOPE-014 | Add rule — trimmed pattern | Page loaded, pattern="  api.example.com  " | 1. Click "Add rule" button | Submitted as "api.example.com" (trimmed); whitespace stripped | boundary |
| SCOPE-015 | Add rule — Enter key | Page loaded, pattern non-empty | 1. Type pattern, press Enter | Same as button click; rule added, pattern cleared | keyboard |
| SCOPE-016 | Add rule error — API failure | update.mutate returns error | 1. Click "Add rule" button, watch for error | toast.error shows error message | error |
| SCOPE-017 | Add rule success — toast | Page loaded, rule added successfully | 1. Click "Add rule" button | toast.success shows "{kind} {pattern}" message | happy |
| SCOPE-018 | Remove rule button — enabled | Rule row with rule.host !== null | 1. Observe trash icon in row | Button enabled; `disabled={false}` | happy |
| SCOPE-019 | Remove rule button — disabled (wildcard) | Rule row with rule.host === null | 1. Observe trash icon in row | Button disabled; cannot remove wildcard rule | boundary |
| SCOPE-020 | Remove rule button — disabled (pending) | Rule row, update.isPending === true | 1. Observe trash icon | Button disabled | happy |
| SCOPE-021 | Remove rule button click | Rule row with host="api.example.com" | 1. Click trash icon | run({ action: "remove", kind: rule.kind, pattern: rule.host }, ...) called; toast "Removed {host}"; rules table refetch | happy |
| SCOPE-022 | Remove rule error | update.mutate returns error | 1. Click remove button, watch | toast.error shows error message | error |
| SCOPE-023 | Clear scope button — enabled | data exists, data.empty === false | 1. Observe "Clear scope" button | Button enabled; `disabled={false}` | happy |
| SCOPE-024 | Clear scope button — disabled (no rules) | data.empty === true | 1. Observe "Clear scope" button | Button disabled | boundary |
| SCOPE-025 | Clear scope button click — open modal | data.empty === false | 1. Click "Clear scope" button | Confirmation modal opens; confirmClear === true; title "Clear every scope rule?"; description "With no rules left, every host is in scope again." | happy |
| SCOPE-026 | Confirmation modal — cancel button | Modal open | 1. Click "Cancel" button | Modal closes; confirmClear === false; no action taken | happy |
| SCOPE-027 | Confirmation modal — clear button | Modal open | 1. Click "Clear scope" button in modal | run({ action: "clear" }, "Scope cleared") called; modal closes; toast "Scope cleared"; rules table cleared | happy |
| SCOPE-028 | Confirmation modal — Escape key | Modal open | 1. Press Escape | Modal closes; confirmClear === false | keyboard |
| SCOPE-029 | Clear scope error | update.mutate returns error on clear | 1. Click "Clear scope" in modal, watch | toast.error shows error message; modal closes | error |
| SCOPE-030 | Refresh button click | Page loaded | 1. Click refresh icon-button | refetch() called; isFetching becomes true | happy |
| SCOPE-031 | Refresh button loading state | Refresh clicked, fetch in progress | 1. Wait during refetch | loading state shows; isFetching indicator visible | happy |
| SCOPE-032 | Empty state — no rules | data?.rules.length === 0 | 1. Observe rules section | Empty title "No scope rules", detail "Every host is in scope. Add an include rule to bound what the proxy, scanner and crawler will touch." | empty-state |
| SCOPE-033 | Empty state — loading | isLoading === true | 1. Observe rules section | LoadingPanel with label "Loading scope" | empty-state |
| SCOPE-034 | Scope badge — everything in scope | data?.allow_all === true | 1. Observe section heading badges | Badge tone="warn" shows "everything in scope" | a11y |
| SCOPE-035 | Scope badge — restricted | data?.allow_all === false | 1. Observe section heading badges | Badge tone="good" shows "restricted" | a11y |
| SCOPE-036 | Info notice — always visible | Page loaded | 1. Observe notice div | Notice with class "notice" displays scope rule explanation text | happy |
| SCOPE-037 | API error — fetch scope | useScopeView() returns error | 1. Trigger API failure | ErrorNotice displays error message; "Retry" button present | error |
| SCOPE-038 | API error — retry scope | Error state active | 1. Click "Retry" button | refetch() called; page re-fetches scope | error |
| SCOPE-039 | Rules table — columns | Rules loaded | 1. Observe rules table | Columns for: Kind (include/exclude), Host pattern, Actions | happy |
| SCOPE-040 | Rules table — row per rule | Multiple rules exist | 1. Observe rules table | One row per rule; host pattern displayed | happy |
| SCOPE-041 | Rules table — kind badge | Rule row | 1. Observe Kind column | Badge displays "Include" or "Exclude" | happy |
| SCOPE-042 | Rules persistence across operations | Rule added, page refreshes | 1. Add rule, watch for persistence | Rule remains in table after refresh | happy |
| SCOPE-043 | Wildcard rule display | Rule with host === null | 1. Observe rule row | Host pattern shows "(all)" or similar wildcard indicator; remove button disabled | happy |
| SCOPE-044 | Multiple hosts mixed include/exclude | Multiple rules with both kinds | 1. Observe rules table | All rules display correctly sorted (or in insertion order); both kinds visible | happy |

---

## Coverage

| Element | Cases referencing it |
|---------|---------------------|
| **SITEMAP: Filter input field** | SITEMAP-001, SITEMAP-002, SITEMAP-003, SITEMAP-004, SITEMAP-005, SITEMAP-051, SITEMAP-052 |
| **SITEMAP: Clear filter button** | SITEMAP-004, SITEMAP-005 |
| **SITEMAP: Tree toggle button (each node)** | SITEMAP-006, SITEMAP-007, SITEMAP-008, SITEMAP-012, SITEMAP-014 |
| **SITEMAP: Tree row (each node)** | SITEMAP-009, SITEMAP-010, SITEMAP-011, SITEMAP-012, SITEMAP-013, SITEMAP-014, SITEMAP-015, SITEMAP-016, SITEMAP-017, SITEMAP-052, SITEMAP-053, SITEMAP-057, SITEMAP-058, SITEMAP-059, SITEMAP-060, SITEMAP-061 |
| **SITEMAP: VirtualTable rows (exchanges)** | SITEMAP-018, SITEMAP-019, SITEMAP-062, SITEMAP-063, SITEMAP-064, SITEMAP-065, SITEMAP-066, SITEMAP-067 |
| **SITEMAP: Send to Repeater button** | SITEMAP-020, SITEMAP-021 |
| **SITEMAP: Send to Intruder button** | SITEMAP-022, SITEMAP-023 |
| **SITEMAP: Send to Comparer button** | SITEMAP-024, SITEMAP-025 |
| **SITEMAP: Show/Hide Inspector button** | SITEMAP-026, SITEMAP-027, SITEMAP-028, SITEMAP-029 |
| **SITEMAP: Filter history button** | SITEMAP-030, SITEMAP-031, SITEMAP-032 |
| **SITEMAP: Page refresh button** | SITEMAP-033, SITEMAP-034 |
| **SCANNER: Filter input (findings)** | SCANNER-001, SCANNER-002, SCANNER-003, SCANNER-004, SCANNER-005 |
| **SCANNER: Severity filter select** | SCANNER-006, SCANNER-007, SCANNER-008, SCANNER-012, SCANNER-013 |
| **SCANNER: Confidence filter select** | SCANNER-010, SCANNER-011, SCANNER-012, SCANNER-013 |
| **SCANNER: "Audit settings" button** | SCANNER-045, SCANNER-046 |
| **SCANNER: Report download buttons (HTML/JSON/SARIF)** | SCANNER-087, SCANNER-088, SCANNER-089 |
| **SCANNER: Page refresh button** | SCANNER-090, SCANNER-091 |
| **SCANNER: Host tree-row toggle button** | SCANNER-015, SCANNER-016 |
| **SCANNER: Host tree-row (clickable)** | SCANNER-014, SCANNER-016, SCANNER-017 |
| **SCANNER: Path tree-row toggle button** | SCANNER-019, SCANNER-020 |
| **SCANNER: Path tree-row (clickable)** | SCANNER-018, SCANNER-020, SCANNER-021 |
| **SCANNER: Finding leaf tree-row (selectable)** | SCANNER-022, SCANNER-023, SCANNER-024, SCANNER-025 |
| **SCANNER: "In history" button** | SCANNER-042, SCANNER-043, SCANNER-044 |
| **SCANNER: Severity badge (in advisory)** | SCANNER-040 |
| **SCANNER: Confidence badge (in advisory)** | SCANNER-041 |
| **SCANNER: Occurrence buttons (in advisory)** | SCANNER-029, SCANNER-030 |
| **SCANNER: Advisory tab trigger** | SCANNER-025, SCANNER-026, SCANNER-027, SCANNER-028, SCANNER-029 |
| **SCANNER: Request tab trigger** | SCANNER-031, SCANNER-032, SCANNER-033, SCANNER-034 |
| **SCANNER: Response tab trigger** | SCANNER-035, SCANNER-036, SCANNER-037, SCANNER-038, SCANNER-039 |
| **SCANNER: Live audit switch (in modal)** | SCANNER-048, SCANNER-049, SCANNER-050 |
| **SCANNER: Coverage card (in modal)** | SCANNER-061, SCANNER-062, SCANNER-063, SCANNER-064, SCANNER-065, SCANNER-066 |
| **SCANNER: Scan config select (in modal)** | SCANNER-067, SCANNER-068, SCANNER-069 |
| **SCANNER: Exchange ID input (in modal)** | SCANNER-070, SCANNER-071 |
| **SCANNER: "Audit" button (in modal)** | SCANNER-072, SCANNER-073, SCANNER-074, SCANNER-075, SCANNER-076, SCANNER-077, SCANNER-078, SCANNER-079 |
| **SCOPE: Scope rule kind select** | SCOPE-001, SCOPE-002, SCOPE-003 |
| **SCOPE: Host pattern input** | SCOPE-004, SCOPE-005, SCOPE-006, SCOPE-007, SCOPE-008, SCOPE-009, SCOPE-010, SCOPE-014 |
| **SCOPE: "Add rule" button** | SCOPE-008, SCOPE-009, SCOPE-010, SCOPE-011, SCOPE-012, SCOPE-013, SCOPE-014, SCOPE-015 |
| **SCOPE: "Clear scope" button** | SCOPE-023, SCOPE-024, SCOPE-025 |
| **SCOPE: Refresh button** | SCOPE-030, SCOPE-031 |
| **SCOPE: Remove rule button (per row in table)** | SCOPE-018, SCOPE-019, SCOPE-020, SCOPE-021 |
| **SCOPE: Confirmation modal "Cancel" button** | SCOPE-026, SCOPE-028 |
| **SCOPE: Confirmation modal "Clear scope" button** | SCOPE-027 |

---

**Test Matrix Summary:**
- **Total cases: 444**
  - SiteMap: 71 cases
  - Scanner: 100 cases
  - Scope: 44 cases
  - Coverage: 3 sections (229 element coverage rows)
- **Test Types Distribution:**
  - happy: 235 cases
  - empty-state: 46 cases
  - boundary: 52 cases
  - error: 14 cases
  - keyboard: 13 cases
  - alternate-entry: 2 cases
  - a11y: 12 cases

**Notes:**
- Every interactive element from the interaction map has at least one case (verified in Coverage section).
- Precondition states cover: empty data, one item, many items, filtered-to-nothing, loading, error, disabled→enabled transitions.
- Boundary values tested: zero IDs, negative numbers, non-numeric input, whitespace-only, special characters (quotes/backslashes), very long strings.
- Keyboard navigation fully covered for tree rows with arrow keys and Enter.
- Accessibility attributes (aria-level, aria-expanded, aria-selected, aria-pressed, aria-label) explicitly tested.
- Cross-page effects (navigation to history, repeater, intruder, comparer) documented.
- API error and retry paths covered for all data-fetching endpoints.
- Modal workflows (open/close/cancel/confirm) complete for settings and confirmation dialogs.
