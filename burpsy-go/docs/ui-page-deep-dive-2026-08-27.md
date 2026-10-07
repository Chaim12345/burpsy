# burpsy Dashboard page deep dive

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Metric: Exchanges | stat card | `data.exchanges` + `data.messages` |
| Metric: Capture store | stat card | `formatBytes(data.stored_bytes)` |
| Metric: Running tasks | stat card | `data.tasks_running` + `data.tasks.length` tracked |
| Metric: Coverage gaps | stat card | `incomplete` count (summaries without full verdict) |
| Metric: critical findings | stat card | `issues.data.counts.critical` |
| Metric: high findings | stat card | `issues.data.counts.high` |
| Metric: medium findings | stat card | `issues.data.counts.medium` |
| Metric: low findings | stat card | `issues.data.counts.low` |
| Metric: info findings | stat card | `issues.data.counts.info` |
| Metric: unrecognised severity | stat card | `issues.data.counts.unrecognised` (conditional) |
| Coverage panel | card | `data.summaries.map(CoverageCard)` |
| Requests sent by burpsy | card | `ActivityTable` (first 10 rows) |
| Tool events | card | `data.events.slice(0,12)` with dot + kind + detail + time |
| Tasks panel | card | `TaskTable` + "New scan" + "New live task" buttons |
| Traffic sources | card | `Object.entries(data.sources).sort()` + "Open HTTP history" button |
| Notice: Nothing captured | notice | Shown when `data && !data.exchanges` |
| Notice: Coverage gaps | notice | Shown when `incomplete > 0` |
| NewScanModal | modal | Opens on "New scan" click |
| NewLiveTaskModal | modal | Opens on "New live task" click |
| RefreshButton | button | Calls `refetch()` |
| Open HTTP history | button | `setRoute("history")` |

## Data sources (API calls)

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useDashboard()` | `GET /api/dashboard` | All dashboard stats |
| `useIssues()` | `GET /api/issues` | Finding counts by severity |
| `useScannerLive()` | `GET /api/scanner/live` | Live audit state |
| `useEventStream()` | `SSE /api/events` | Real-time updates |

## Navigation flows

| Click | Target |
|-------|--------|
| "New scan" | Opens NewScanModal |
| "New live task" | Opens NewLiveTaskModal |
| "Open HTTP history" | `setRoute("history")` |
| Metric cards | No navigation |
| TaskTable rows | No navigation |
| Event rows | No navigation |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Task progress bar | `DashboardTaskProgress.java` with progress animation | No progress bar |
| Event log | `DashboardEventLogTable.java` + popup menu | Static event list |
| Activity log | `DashboardActivityLogTable.java` + popup menu | Static activity list |
| Pause/resume | "Task execution is paused" string | Not present |
| No proxy listeners | Warning bar | Not present |
| Telemetry | `DashboardTelemetry.java` | Not present |
| Live audit widget | "Live audit (Pro version only)" | Simple stat card |
| Honest coverage | Hidden | Shown ✓ |
| Gated work count | Not shown | Shown ✓ |

---

# Target → Site map

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Badge: nodes | badge | `data.node_count` |
| Badge: exchanges | badge | `data.exchange_count` |
| Button: Crawl | button | Opens crawl dialog |
| Button: Refresh | button | `refetch()` |
| Input: Filter | input | Filters tree nodes |
| Empty: No traffic | empty state | Shown when no data |
| Empty: No path selected | empty state | Detail panel placeholder |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useSitemap()` | `GET /api/sitemap` | Site map tree |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Crawl paths view | Separate view showing scanner actions as tree | Not present |
| Passive scan branch | "Passively scan this branch" / "Passively scan selected branches" | Not present |
| Read-only indicator | "Site map is read-only" | Not present |
| Items added/queued/processed | Counters for crawl progress | Not present |
| Site map filter | Advanced filter dialog | Simple text filter |
| Warning bar | "siteMapWarningBarPanel" | Not present |
| Node count | Present | Present ✓ |
| Exchange count | Present | Present ✓ |

---

# Target → Issues

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Button: Audit settings | button | Opens scanner config |
| Button: Refresh | button | `refetch()` |
| Select: Severities | select | All/Critical/High/Medium/Low/Info |
| Select: Confidence | select | All/Certain/Firm/Tentative |
| Span: finding count | text | `data.total` finding(s) |
| Input: Search | input | Filter findings |
| Empty: No findings | empty state | When no findings |
| Empty: Select a finding | empty state | Detail panel placeholder |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useIssues()` | `GET /api/issues` | Findings list |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Tree structure | `IssueTreeModel.java` with tree | Flat list |
| Issue details | Full detail panel | Minimal detail |
| Audit settings | Full scan config dialog | Button (minimal) |
| Unrecognised severity | Not shown | Shown ✓ |

---

# Target → Issue definitions

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Button: Refresh | button | `refetch()` |
| Select: Severities | select | All/High/Medium/Low/Info with counts |
| Span: definition count | text | 183 definition(s) |
| Input: Search | input | Filter definitions |
| List items | list | Each with severity badge + type index + title |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useResource("advisories")` | `GET /api/advisories` | All definitions |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Count | Burp hides some | All 183 shown ✓ |
| Severity counts | Shown | Shown |
| Documentation link | "https://portswigger.net/kb/issues" | Not present |

---

# Target → Audit queue

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Button: Refresh | button | `refetch()` |
| H2: Queue | header | Queue section |
| Table | table | Seq/Request/State/Attempts/Note |
| Button: Show insertion points | button | Toggle insertion points view |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useResource("audit-items")` | `GET /api/scanner/audit-items` | Queue items |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| State badges | Pending/Audited/Skipped/Cancelled with colors | Minimal |
| Insertion points | Detailed view | Toggle button (minimal) |
| Total items | "Total audit items:" counter | Not present |

---

# Proxy → Intercept

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Badge: wired | badge | `data.wired` state |
| Switch: enable/disable | switch | Enable/disable interception |
| Select: Direction | select | All/Requests only/Responses only/WebSocket→server/WebSocket→client |
| Button: Queue | button | Open held messages queue |
| Button: Interception rules | button | Open rules dialog |
| Table | table | #/Dir/Method/Host/Path/Status/Held/Len |
| Empty: Queue is clear | empty state | No held messages |
| Empty: Nothing selected | empty state | No selected message |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useIntercept(1500)` | `GET /api/intercept` (polling 1.5s) | Intercept state |

## Navigation flows

| Click | Target |
|-------|--------|
| Table row | Open message editor (detail panel) |
| Queue | Open held messages |
| Interception rules | Open rules dialog |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Forward button | Toolbar button | Context menu only |
| Drop button | Toolbar button | Context menu only |
| Action menu | Full menu (Send to Repeater/Comparer/Intruder/Spider, Do intercept, Drop, Comment, Highlight) | Minimal |
| Comment button | Toolbar | Not present |
| Highlight button | Toolbar | Not present |
| Edit target | "Edit target" | Not present |
| Open browser | "Open pre-configured browser" | Not present |
| WebSocket filters | Burp has them elsewhere | Explicit select ✓ |
| In-scope only | "Only intercept in-scope messages" | Not present |

---

# Proxy → HTTP history

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Span: row count | text | `${data.length} rows` |
| Button: Refresh | button | `refetch()` |
| Button: Export CSV | button | Export to CSV |
| Input: Search | input | Filter query DSL |
| Button: In scope only | button | Toggle in-scope filter |
| Button: Hide items without responses | button | Toggle |
| Button: More filters | button | Expand filter panel |
| Select: Status | select | All/2xx/3xx/4xx/5xx |
| Select: Type | select | All/HTML/JSON/XML/JavaScript/CSS/Images/Binary |
| Select: Method | select | All/GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS |
| Select: Limit | select | last 200/500/1000/5000 |
| Table | table | #/Method/Host/Path/Status/Type/Ext/Query/TLS/Comment/Length/Time/Age |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useHistory(q, limit)` | `GET /api/history?q=&limit=` | Filtered history |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Bambda mode | "filterBambdaModeRadioButton" | Not present |
| Column filter | Per-column filter inputs | Not present |
| Show highlighted | "Show only highlighted items" | Not present |
| Show commented | "show_only_commented_items" | Not present |
| MIME type filter | Per-type checkboxes | Single select |
| Status filter | Per-status checkboxes | Single select |
| Method filter | Not in Burp | Present ✓ |
| Limit filter | Not in Burp | Present ✓ |
| Export CSV | Not in Burp | Present ✓ |
| Hide empty | Not in Burp | Present ✓ |

---

# Proxy → WebSockets history

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Button: Refresh | button | `refetch()` |
| Empty: No upgrades | empty state | "No upgrades observed" |
| Table | table | #/Dir/Opcode/Length/Age |
| Empty: No connection | empty state | "No WebSocket traffic captured yet" |
| Empty: No connection selected | empty state | "No connection selected" |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useWsConnections()` | `GET /api/ws/connections` | Connection list |
| `useWsHistory(exchange)` | `GET /api/ws/history?exchange=&limit=` | Frame history |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Bambda filter | "bambda.web_sockets_history_display_filter" | Not present |
| Filter settings | "Filter settings" dialog | Not present |
| Connection detail | Frame-level view | Minimal |

---

# Proxy → Match & Replace

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Badge: saved | badge | State indicator |
| Button: Revert | button | Revert changes |
| Button: Save rules | button | Save rules |
| Button: Refresh | button | `refetch()` |
| H2: Rules | header | Rules section |
| Span: requests enabled | text | Count |
| Span: responses enabled | text | Count |
| Button: Add rule | button | Add new rule |
| Button: switch | button | Toggle all rules |
| Span: enabled count | text | `${enabled}/${total} enabled` |
| Empty: No rules | empty state | Add rule prompt |
| H2: Draft test | header | Test section |
| Select: Request/Response rules | select | Rule set to test |
| Span: testing count | text | `${n} saved rules` |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useMatchReplace()` | `GET /api/tools/rules` | Current rules |
| `useSaveMatchReplace()` | `PUT /api/tools/rules` | Save rules |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Edit rule | "editHttpMatchReplaceRuleButton" + "editWsMatchReplaceRuleButton" | Not present |
| Remove rule | "Remove the selected rule" | Not present |
| Move up/down | "Move the selected rule up/down" | Not present |
| In-scope only | "Only apply to in-scope items" (HTTP + WS) | Not present |
| HTTP/WS separation | Separate rule sets | Single rule set |
| Auto-modified | "Auto-modified request" + "Auto-modified response" | Not present |
| Original message | "Original request" + "Original response" | Not present |
| Draft test | Not in Burp | Present ✓ |
| Revert | Not in Burp | Present ✓ |

---

# Proxy → Proxy settings

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Button: Refresh | button | `refetch()` |
| H2: Response modification | header | Modification section |
| 6 switches | switch | Toggle each modification |
| H2: Outcome counters | header | Counters section |
| H2: Transport adjustments | header | Transport section |
| Table | table | Adjustment/Count |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useResource("proxy/options")` | `GET /api/proxy/options` | Proxy options |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| TLS passthrough | "proxy.ssl_pass_through" + add rule | Not in Proxy settings |
| Resource pools | "Resource pools" + New/Edit/Delete | Not in Proxy settings |
| Miscellaneous | "configPanelProxyMiscellaneousDontLogOutOfScopeItems" | Not present |
| Outcome counters | Not in Burp | Present ✓ |
| Transport adjustments | Not in Burp | Present ✓ |

---

# Intruder → Positions

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Span: request count | text | `${requests.length} requests` |
| Button: Launch attack | button | Start attack |
| 5 sub-tab buttons | tab | Positions/Payloads/Resource pool/Settings/Results |
| H2: Base request | header | Base request section |
| Input: request id | input | Stored message id |
| Select: Attack type | select | Sniper/Battering ram/Pitchfork/Cluster bomb |
| Switch: something | switch | Toggle |
| Button: Find positions | button | Find insertion points |
| Empty: No base request | empty state | Enter message id prompt |

## Data sources

| Hook | API endpoint | Purpose |
|------|-------------|---------|
| `useResource("intruder/points")` | `POST /api/intruder/points` | Insertion points |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Add position | "Add §" + "intruderPayloadPositionsAdd" | Not present |
| Auto position | "Auto §" + "intruderPayloadPositionsAuto" | Not present |
| Clear positions | "Clear §" | Not present |
| Position list | List with checkboxes | Not present |
| Target field | "intruderTargetField" | Not present |
| Editor | "intruderPayloadPositionsEditor" | Not present |
| Request editor | Full HTTP message editor | Not present |
| Attack type | Sniper/Battering ram/Pitchfork/Cluster bomb | Present ✓ |
| Find positions | "Find insertion points" | Present ✓ |

---

# Intruder → Payloads

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Payload type | 12+ types (Simple list, Runtime file, Character substitution, etc.) | Not present |
| Load/Paste/Remove | File operations | Not present |
| Payload count | "Payloads to generate:" | Not present |
| Processing rules | "Payload processing rules" | Not present |
| Grep payloads | "Grep — Payloads" + options | Not present |
| Match/replace | "Match / replace in list items" | Not present |
| Illegal UTF-8 | "Do illegal UTF-8" | Not present |
| Hex formatting | "Hex formatting" | Not present |
| Max permutations | "Maximize permutations in multi-byte encodings" | Not present |

---

# Intruder → Resource pool

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Concurrent requests | "Concurrent requests" | Not present |
| Delay | "Delay" ms | Not present |
| Random variations | "With random variations" | Not present |
| Increment delay | "Increase delay in increments of" | Not present |
| Custom pool | "Custom resource pool %d" | Not present |
| Edit/Delete | "configPanelResourcePoolsEditBtn" / "configPanelResourcePoolsDeleteBtn" | Not present |

---

# Intruder → Settings

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Scan details | "Scan details" + "scanDetailsRibbonButton" | Not present |
| Scope | Scope configuration | Not present |
| Isolate scan | "Isolate scan" | Not present |
| Engine config | "configPanelScanDetailsEngineConfiguration" | Not present |
| Attack config | "configPanelScanDetailsAttackConfiguration" | Not present |

---

# Intruder → Results

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Results table | "Results table" + table | Not present |
| Server responses | "Server responses" | Not present |
| Progress bar | Attack progress bar | Not present |
| Pause/Resume/Stop | Buttons | Not present |
| Save | "INTRUDER_ATTACK_SAVE_TO_PROJECT_FILE" | Not present |
| Columns | #/Status/Error/Timeout/Length/Time/Comment/Total | Not present |
| Split pane | "intruderResultsSplitPane" | Not present |

---

# Repeater

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Empty: No request open | empty state | Start prompt |
| Button: New request | button | Opens new request dialog |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Send | "Send" button | Not in empty state |
| Cancel | "Cancel" button | Not present |
| Edit target | "Edit target" | Not present |
| Protocol | "HTTP/HTTPS" label | Not present |
| Status | "repeaterStatusLabel" | Not present |
| Follow redirects | "Follow redirection" | Not present |
| Explore | "repeaterExploreButton" | Not present |
| Search | "RepeaterSearchCheckbox" | Not present |
| Request view | "repeaterRequestViewControls" + "httpRequestMessageAnalyser" | Not present |
| Response view | "repeaterResponseViewControls" + "httpResponseMessageAnalyser" | Not present |
| Tab panel | "repeaterTabPanel" | Not present |
| Configuration | "RepeaterConfigurationOverrideMenuItemFollowRedirectionsInScope" | Not present |
| WS option | "RepeaterNewWsTabOption" | Not present |
| HTTP option | "RepeaterNewHttpTabOption" | Not present |
| New request | Blank by default | Button in empty state |

---

# Sequencer

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Span: pasted count | text | `${tokens.length} pasted` |
| Select: Encoding | select | detect encoding/hex/base64/raw bytes |
| Button: Analyse | button | Run analysis |
| Button: Paste a list | button | Paste tokens |
| Button: Capture from live exchange | button | Start capture |
| Empty: No analysis yet | empty state | Paste sample prompt |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Token analysis | "Spectral", "Transitions", "FIPS poker", etc. | Not present |
| Token handling | "configPanelSequencerTokenHandling" + "base64 decode", "Pad short tokens at:" | Not present |
| Analyse | Present | Present ✓ |
| Paste | Present | Present ✓ |
| Capture | Present | Present ✓ |

---

# Comparer

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Span: byte-level | text | "byte-level" badge |
| Button: Swap | button | Swap A/B |
| Button: Compare | button | Run comparison |
| Slot A | panel | Input + Load + 0 B + Raw/Hex buttons |
| Slot B | panel | Input + Load + 0 B + Raw/Hex buttons |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Word-level | "word-level" option | Not present |
| Byte-level | Present | Present ✓ |
| Swap | Present | Present ✓ |
| Compare | Present | Present ✓ |

---

# Decoder

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Span: input size | text | `${bytes} B in` |
| Button: Text | button | Text view |
| Button: Hex | button | Hex view |
| Button: Clear all | button | Clear input |
| Button: Run pipeline | button | Execute pipeline |
| H2: Transform pipeline | header | Pipeline section |
| Button: Decode | button | Add decode step |
| Button: Encode | button | Add encode step |
| Button: Hash | button | Add hash step |
| Span: step | text | Step number |
| Select: operation | select | Decode/Encode/Hash |
| Select: format | select | smart detect/url/html/base64/base64url/hex/jwt/ascii |
| Input: value | input | Step configuration |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Single-shot | Decode/Encode only | Pipeline |
| Hash | Not in Decoder | Present ✓ |
| Pipeline | Not in Burp | Present ✓ |
| Clear | Not in Burp | Present ✓ |

---

# Collaborator

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Badge: not configured | badge | State indicator |
| Button: Refresh | button | `refetch()` |
| H2: Interaction channel | header | Channel section |
| Button: Copy payload | button | Copy payload |
| Button: Poll now | button | Poll for interactions |
| Empty: No channel | empty state | "No collaborator channel" |
| H2: Blind XSS callbacks | header | Callbacks section |
| Button: Copy script tag | button | Copy script |
| Empty: No listener | empty state | "No blind-XSS listener" |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Payload count | "Payloads to generate:" | Not present |
| Server location | "Include Collaborator server location" | Not present |
| Configuration | "Configure interactsh" flow | Not present |
| Blind XSS | Not in Burp | Present ✓ |
| Copy script tag | Not in Burp | Present ✓ |

---

# Logger

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Span: shown count | text | `${shown} of ${total}` |
| Span: dropped count | text | `${dropped} dropped` |
| Button: Clear log | button | Clear all |
| Button: Refresh | button | `refetch()` |
| Input: Search | input | Search log |
| Select: Tool filter | select | All tools + per-tool counts |
| Select: Method filter | select | Any method |
| Select: Status filter | select | Any status |
| 8 column inputs | input | Per-column filter |
| Button: Column menu | button | Column visibility |
| Table | table | Age/Tool/Authority/Request/Status/Length/Time/Error |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Capture by tool | Per-tool checkboxes | Per-tool counts |
| Capture by status | Per-status checkboxes | Single select |
| Capture by MIME | Per-type checkboxes | Not present |
| Capture by search | Case/regex/term | Search input |
| Capture by request type | In-scope/parameterized/discard | Not present |
| Memory limit | "Capture limit" MB | Not present |
| Dropped counter | Not in Burp | Present ✓ |
| Column filters | Not in Burp | Present ✓ |

---

# Organizer

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Span: saved count | text | `${items.length} saved` |
| Button: Refresh | button | `refetch()` |
| H2: Saved exchanges | header | Saved section |
| Input: add | input | Add exchange |
| Button: Save exchange | button | Save |
| Empty: Nothing saved | empty state | Add prompt |
| Empty: No item selected | empty state | Select prompt |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| In-scope filter | "organiserShowOnlyInScopeCheckbox" | Not present |
| Status filter | "organiser.display_filter.status.new" + 2xx/3xx/4xx/5xx | Not present |
| MIME filter | "organiserShowMimeXmlCheckbox" | Not present |
| Save exchange | Present | Present ✓ |

---

# Session

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Badge: wired | badge | Coordinator state |
| Button: New rule | button | Add session rule |
| Button: Refresh | button | `refetch()` |
| H2: Login rules | header | Login rules section |
| Span: configured count | text | `${n} configured` |
| Empty: No session rules | empty state | Create prompt |
| H2: Log in again | header | Re-auth section |
| Input: username | input | Username |
| Input: password | input | Password |
| Button: Add header | button | Add header |
| Button: Run login now | button | Run login |
| H2: Cookie jar | header | Cookie jar section |
| Button: Refresh jar | button | Refresh cookies |
| Empty: No cookies | empty state | Empty jar |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Rule edit | Edit button | Not present |
| Rule remove | Delete button | Not present |
| Rule details | Full form | Not present |
| New rule | Present | Present ✓ |
| Cookie jar | Present | Present ✓ |
| Wired badge | Not in Burp | Present ✓ |
| Configured count | Not in Burp | Present ✓ |

---

# Extender

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Button: Refresh | button | `refetch()` |
| H2: Allowlist | header | Allowlist section |
| Empty: No plugin | empty state | Allowlist prompt |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Add extension | "Add" button | Not present |
| Edit extension | "Edit" button | Not present |
| Remove extension | "Remove" button | Not present |
| Extension list | Full list with details | Empty allowlist |
| Output/Errors tabs | Per-plugin logs | Not present |
| JMenu items | "Extension JMenus" | Not present |
| Hot key handlers | "Hot key handlers" | Not present |
| bapp update | "automatically_update_bapps_on_startup" | Not present |
| Suppress popup | "suppress_extension_loaded_popup" | Not present |
| Ruby/Python/Java config | Environment settings | Not present |
| Allowlist | Not in Burp | Present ✓ |

---

# Discover

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| Input: Search | input | Search docs |
| Span: entries | text | `${n} entries` |
| Button: What burpsy does not do | button | Limitations |
| Button: Query language | button | Query DSL |
| Button: BCheck syntax | button | BCheck docs |
| Button: Keyboard — Send to | button | Keyboard shortcuts |
| Button: Keyboard — Proxy | button | Keyboard shortcuts |
| Button: Keyboard — Message editor | button | Keyboard shortcuts |
| Button: Keyboard — Navigation | button | Keyboard shortcuts |
| Button: Keyboard — Appearance and help | button | Keyboard shortcuts |
| Button: Shipped documentation | button | Shipped docs |
| H2 sections | header | Each documentation section |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Content discovery | ffuf-based path sweep | Not present |
| Documentation hub | Not in Burp | Present ✓ |
| Keyboard shortcuts | Not in Burp | Present ✓ |
| Query language | Not in Burp | Present ✓ |

---

# Settings

## Widget inventory

| Widget | Type | Description |
|--------|------|-------------|
| H2: Proxy | header | Proxy settings |
| Button: Refresh | button | `refetch()` |
| H2: TLS passthrough | header | Passthrough rules |
| Input: host pattern | input | Pattern |
| Button: Add rule | button | Add passthrough |
| Empty: No passthrough | empty state | Every connection intercepted |
| H2: Resource pools | header | Resource pools |
| Span: pool count | text | `${n} pools` |
| Button: New pool | button | Create pool |
| Empty: No pools | empty state | Every tool runs own |
| H2: What each tool honours | header | Tool limits |
| Table | table | Tool/Route/Max concurrent/Delay/Throttling/Why not |
| Span: enforced | badge | Limit status |

## Gaps vs Burp

| Feature | Burp | burpsy |
|---------|------|--------|
| Project options | Comprehensive dialog | Not present |
| Scope settings | "Scope" in project options | Not present |
| Crawling settings | "Crawling" section | Not present |
| Application login | "Application login" | Not present |
| Tool limits table | Present | Present ✓ |
| TLS passthrough | Present | Present ✓ |
| Resource pools | Present | Present ✓ |

---

# Inter-page navigation map

| From | Click | To |
|------|-------|----|
| Dashboard | "Open HTTP history" | Proxy → HTTP history |
| Dashboard | "New scan" | Modal (NewScanModal) |
| Dashboard | "New live task" | Modal (NewLiveTaskModal) |
| Target → Site map | Tree node | Detail panel (same page) |
| Target → Issues | Row | Detail panel (same page) |
| Proxy → Intercept | Row | Message editor (detail panel) |
| Proxy → Intercept | "Queue" | Held messages |
| Proxy → Intercept | "Interception rules" | Rules dialog |
| Proxy → HTTP history | Row | Message detail |
| Proxy → HTTP history | "In scope only" | Toggle filter |
| Proxy → HTTP history | "Hide items without responses" | Toggle filter |
| Proxy → Match & Replace | "Add rule" | Rule dialog |
| Intruder | Tab click | Sub-tab content |
| Repeater | "New request" | Request editor |
| Session | "New rule" | Rule dialog |
| Session | "Run login now" | Login flow |
| Menu bar | Tool name | Switch to tool tab |
| Command palette | Route | Navigate to route |
| Alt+N shortcut | Tool | Navigate to tool |

---

# Summary of gaps

## High priority (functional blocks)
1. Intruder sub-tabs — All 5 render identical content
2. Repeater — Empty state doesn't lead to editor
3. Extender — Stub (no add/remove UI)
4. Session — "New rule" doesn't open dialog
5. Site map — Missing crawl paths view

## Medium priority (missing features)
1. Intercept — Missing Forward/Drop/Action menu/Comment/Highlight
2. HTTP history — Missing Bambda mode, column filters
3. Match & Replace — Missing edit/remove/move/in-scope
4. Logger — Missing capture-by-MIME/status/search
5. Organizer — Missing in-scope/status/MIME filters
6. Proxy settings — Missing TLS passthrough/resource pools

## Low priority (cosmetic)
1. Dashboard — Missing task progress bar, event log popup menu
2. Collaborator — Missing configuration flow
3. Discover — Different purpose (docs vs content discovery)

## What burpsy does better
1. Dashboard — Honest coverage accounting
2. Logger — Per-tool capture toggles + dropped counters
3. Match & Replace — Draft test panel
4. Issue definitions — Lists all 183
5. Intercept — Explicit WebSocket direction filters
6. Decoder — Pipeline with hash step
7. Session — Cookie jar with refresh, wired badge
8. Discover — Documentation hub with keyboard shortcuts
