# burpsy vs Burp — complete feature parity audit

> ## ⚠️ Re-verification pass in progress — 2026-09-14
>
> This audit dates from 2026-08-27 and most of its "missing" rows are **false**: the capabilities
> shipped afterwards. Two live sweeps were run on 2026-09-14 and are recorded in full beside this
> file:
>
> * [`ui-parity-verify-2026-09-14-target-proxy.md`](./ui-parity-verify-2026-09-14-target-proxy.md) —
>   Target, Scope, Proxy: **57 claims, 45 closed, 5 not-applicable, 1 unverified, 6 still open**, and
>   its one HIGH item (Proxy settings shows one listener rather than Burp's listener list) was missed
>   by this audit entirely.
> * [`ui-parity-verify-2026-09-14-shell-settings.md`](./ui-parity-verify-2026-09-14-shell-settings.md) —
>   the shell, Session, Discover, Extensions, Extender options/APIs, Settings, Collaborator. It also
>   corrects this audit in the other direction: "context menus: burpsy 0" is false (a history row's
>   menu has 28 items), Extender load/unload is served, and content discovery exists as
>   `Target › Content discovery`. Its ranked list starts with the Settings page having no navigation
>   tree, no search and no filter — the largest visible divergence from Burp on any page — then the
>   absent **Intruder** menu, Burp's tab-visibility **View** menu, the tool-tab context menu, and
>   `Send to…` on the message-editor context menu.
>
> Those two documents are the accurate record for the pages they cover; this one remains the
> checklist for the pages no sweep has reached. A third sweep covers the tool pages —
> [`ui-parity-verify-2026-09-14-intruder-tools.md`](./ui-parity-verify-2026-09-14-intruder-tools.md)
> (Intruder, Repeater, Sequencer, Decoder, Comparer, Logger, Organizer). It corrects this audit
> again — Intruder's Settings section describes the *scanner's* launch dialog (three of its six rows
> have zero hits in Burp's own strings), "Max permutations" does not exist in Burp at all, and it
> calls Sequencer's two HIGH rows already-shipped — and its top finding is a live defect this audit
> could not have seen: a running Intruder attack cannot be paused or stopped from the console
> (Pause/Resume/Stop never render, no progress indicator) because the page never identifies its own
> attack id, while the backend serves both the counts and the control routes.
>
> Re-verified against the running console (`./ui-live.sh`, port 18281, seeded
> traffic) on 2026-09-14, reading the rendered DOM rather than the source:
>
> | Row this audit calls missing | Live finding (2026-09-14) |
> |---|---|
> | Scope → "Advanced scope control | No" | **Present.** A checkbox labelled "Advanced scope control" with Host match (Wildcard / Regular expression / IP range) and Path match (Prefix / Regular expression) selectors in the add form and the edit dialog. |
> | Intruder → "All five sub-tabs render the same Base request panel" | **False.** Clicking a tab sets `aria-selected` on it and swaps the tabpanel: Positions (base request, attack type, Find positions, Auto § / Clear §), Payloads (18 payload-set types, list editor, processing rules, URL-encode box), Results (own empty state, "N requests planned"). |
> | Intruder → Payloads → "Payload type selector | 12+ types | No" | **Present:** Simple list, Numbers, File (server path), Brute force, Dates, Custom iterator, Null payloads, Character substitution, Case modification, Illegal Unicode, Character blocks (frobber), Bit flipper, Username generator, ECB block shuffler, Copy other payload, Recursive grep, Collaborator payloads. |
> | Intruder → Results → "Results table … | No" | **Present, wider than Burp's.** Burp's attempt table is Request / Payload / Status code / Response received / Error / Timeout (`intruder-enumerating-sorting-results.png`); burpsy's carries `#`, Payload, Status, Time of day, Length, Time, Reflected, Grep, Error, Timeout, Cookies, Response and Comment (`pages/intruder.tsx`'s `attemptColumns`), plus bucket, error-bucket and payload-set-accounting tables Burp groups into menus. The only naming difference is `#` for Burp's "Request", and Burp's "Response received" is a per-request count with no equivalent column here (burpsy's `Response` column opens the stored response instead). |
> | Target → Site map → "Crawl paths view | Yes | No | HIGH" | **Present.** The site map has a "URL view / Crawl paths" mode pair plus Engagement tools, Passive scan branch, Crawl and Refresh. Selecting Crawl paths shows its own pane, whose empty state says "No crawl has run — Crawl paths show how the crawler reached each location, so there is nothing to show until a crawl has run", which is the same condition Burp's tree needs (`crawl-paths-view.png` shows it populated on a crawled site). The fixture here has no crawl, so the mode's *populated* form is the one thing still unverified. |
> | Target → Issues → "Tree structure | Host→Path→Finding | Flat list | HIGH" | **Present.** The page renders a host/path tree — `Collapse 127.0.0.1`, then `Collapse /zebra`, `/alpha?q=1`, `/beta`, `/held-test?x=1`, `/mango/deep/path`, `/quokka?size=8` — over the findings, with severity and confidence filters, "Hide false positives", a finding count, and HTML/JSON/SARIF export. Not a flat list. |
> | Proxy → Proxy settings → "Resource pools | Yes | No | HIGH" | **Capability present, in the place this engine puts it:** `#proxysettings` is response-modification rules (nine Burp-shaped rewrite toggles, in-scope-only, live outcome counters), and resource pools live under Settings → Resource pools — which is where the Intruder page's "Saved resource pool" selector points ("Bind this attack to a pool created in Settings → Resource pools"). Burp nests pools under Proxy options; this is a placement divergence, not an absent capability, and the audit's row should say which. |
> | Proxy → Match & Replace → "Edit rule | Yes | No | HIGH", "Remove rule | Yes | No | HIGH" | **Not verified here.** The page has Add rule (requests and responses lists), Save rules, Revert, the in-scope-only toggle and a draft tester; per-row Edit and Remove were not visible in the rendered DOM of an empty rule list, and this pass did not create a rule to look. Left open deliberately rather than called closed. |
> | Dashboard → "Pause/resume controls | Yes | No | MEDIUM" | **Closed.** `Pause all tasks` is a toolbar button, and each task row carries its own `Options for task N` control; the page also has `New scan` and `New live task`. |
> | Dashboard → "Task progress bar | Animated with ETA | Static text | HIGH" | **Partly open, and LOW rather than HIGH.** No progress-bar element exists (`[role=progressbar], progress, .progress` finds none); the task row renders `10/10 (100%)` as text beside `Issues: 10` and "found, and nothing was skipped, errored or gated". Nothing is misreported by the absence — it is a look difference, not the "text where a task is stuck" defect the HIGH ranking implies. |
> | Dashboard → "Event log | Table with popup menu | Static list | MEDIUM", "Activity log | … | MEDIUM" | **Unverified.** The tabs exist (`Summary`, `Issue activity`, `Event log`, `Activity`) but this harness's synthetic clicks do not switch Radix tabs, and the pass did not drive them with real input; the tab contents were not read. |
>
> Rows **not** listed above are still as this document left them until the sweep covering them
> finishes. Do not quote a row as a gap without re-checking it against the live console first —
> that is what this section exists to stop.
>
> Starting point for the sweep: `burps-layout` + `desktop/images/*.png` in the bundled Burp docs are
> real screenshots of Burp's panes (e.g. `intruder-enumerating-positions-940.png`,
> `intruder-enumerating-sorting-results.png`), so a layout comparison has a picture on both sides.

## Summary

| Metric | Burp | burpsy | Parity |
|--------|------|--------|--------|
| Top-level tabs | 15 | 15 | 100% |
| Scanner tab | Yes | No | 0% |
| Sub-tabs | ~25 | ~25 | 80% |
| API endpoints | ~80 | 83 | 100% |
| UI-exposed features | ~60 | ~26 | 43% |
| Context menus | ~12 | 0 | 0% |
| Dialogs/windows | ~8 | 2 | 25% |

---

## 1. Pages burpsy has that Burp doesn't

| Page | burpsy | Notes |
|------|--------|-------|
| Discover (top-level) | Yes | Documentation hub. Burp has content discovery under Target→Site map |
| Session (top-level) | Yes | Burp has session handling under menu, not tab |
| Decoder (top-level) | Yes | Burp has it as utility accessible from menus |
| Settings (top-level) | Yes | Burp has Project Options as menu, not tab |

## 2. Pages Burp has that burpsy doesn't

| Page | Burp | burpsy status |
|------|------|---------------|
| Scanner | Full tab with config, live audit, crawl/audit launch | Missing — biggest gap |
| Burp AI | AI-powered explanations | Missing |
| Replayer | Replay captured traffic | Missing |

## 3. Feature-by-feature comparison

### Dashboard

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Task progress bar | Animated with ETA | Static text | HIGH |
| Event log | Table with popup menu | Static list | MEDIUM |
| Activity log | Table with popup menu | Static list | MEDIUM |
| Pause/resume controls | Yes | No | MEDIUM |
| No proxy listeners warning | Yes | No | LOW |
| Telemetry | OpenTelemetry | No | LOW |
| Tab label | Custom | No | LOW |
| Task query | Yes | No | LOW |
| Paused warning bar | Yes | No | LOW |
| Panel builder | Yes | No | LOW |
| Crawl errors | Yes | No | LOW |
| Live audit widget | Full controls | Simple stat | MEDIUM |
| **Honest coverage** | Hidden | **Shown** | burpsy wins |
| **Gated work count** | Not shown | **Shown** | burpsy wins |
| **Unrecognised severity** | Not shown | **Shown** | burpsy wins |

### Target → Site map

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Crawl paths view | Yes | No | HIGH |
| Passive scan branch | Yes | No | MEDIUM |
| Passive scan selected | Yes | No | MEDIUM |
| Read-only indicator | Yes | No | LOW |
| Items added counter | Yes | No | LOW |
| Responses queued counter | Yes | No | LOW |
| Responses processed counter | Yes | No | LOW |
| Site map filter | Advanced dialog | Simple text | MEDIUM |
| Warning bar | Yes | No | LOW |
| URL view | Yes | Yes (only view) | LOW |
| **Node count** | Yes | **Yes** | ✓ |
| **Exchange count** | Yes | **Yes** | ✓ |

### Target → Issues

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Tree structure | Host→Path→Finding | Flat list | HIGH |
| Issue details | Full detail panel | Minimal | MEDIUM |
| Audit settings | Full scan config | Button only | MEDIUM |
| Severity counts | Yes | Yes | ✓ |
| Confidence filter | Yes | Yes | ✓ |
| **Unrecognised severity** | Not shown | **Shown** | burpsy wins |

### Target → Issue definitions

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Count | Hides some | All 183 shown | burpsy wins |
| Severity counts | Yes | Yes | ✓ |
| Search | Yes | Yes | ✓ |
| Documentation link | Yes | No | LOW |

### Target → Audit queue

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| State badges | Color-coded | Minimal | MEDIUM |
| Insertion points | Detailed view | Toggle only | MEDIUM |
| Total items counter | Yes | No | LOW |
| Seq/Request/State/Attempts/Note | Yes | Yes | ✓ |

### Scope

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Add rule | Yes | Yes | ✓ |
| Edit rule | Yes | Yes | ✓ |
| Remove rule | Yes | Yes | ✓ |
| Include/Exclude | Yes | Yes | ✓ |
| Protocol select | Yes | Yes | ✓ |
| Port/Path | Yes | Yes | ✓ |
| Advanced scope control | Yes | No | MEDIUM |
| Save to library | Yes | No | LOW |
| URL scope | Yes | No | LOW |
| Use suite scope | Yes | No | LOW |
| Custom scope | Yes | No | LOW |

### Proxy → Intercept

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Forward button | Toolbar | Context menu only | HIGH |
| Drop button | Toolbar | Context menu only | HIGH |
| Action menu | Full menu | Minimal | HIGH |
| Comment button | Toolbar | No | MEDIUM |
| Highlight button | Toolbar | No | MEDIUM |
| Edit target | Yes | No | MEDIUM |
| Open browser | Yes | No | LOW |
| WebSocket direction filters | Burp elsewhere | Explicit select | burpsy wins |
| In-scope only | Yes | No | MEDIUM |
| **Enable/disable** | Yes | **Yes** | ✓ |
| **Queue table** | Yes | **Yes** | ✓ |

### Proxy → HTTP history

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Bambda mode | Yes | No | HIGH |
| Per-column filters | Yes | No | MEDIUM |
| Show highlighted | Yes | No | LOW |
| Show commented | Yes | No | LOW |
| MIME type filter | Per-type checkboxes | Single select | MEDIUM |
| Status filter | Per-status checkboxes | Single select | LOW |
| Auto-scroll | Yes | No | LOW |
| DSL query builder | No | Yes | burpsy wins |
| **Export CSV** | No | **Yes** | burpsy wins |
| **Hide empty** | No | **Yes** | burpsy wins |
| **Method filter** | No | **Yes** | burpsy wins |
| **Limit filter** | No | **Yes** | burpsy wins |
| **Row count** | Yes | **Yes** | ✓ |
| **Search** | Yes | **Yes** | ✓ |

### Proxy → WebSockets history

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Bambda filter | Yes | No | MEDIUM |
| Filter settings dialog | Yes | No | MEDIUM |
| Connection detail | Frame-level | Minimal | HIGH |
| **Refresh** | Yes | **Yes** | ✓ |
| **Table** | Yes | **Yes** | ✓ |

### Proxy → Match & Replace

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Edit rule | Yes | No | HIGH |
| Remove rule | Yes | No | HIGH |
| Move up/down | Yes | No | MEDIUM |
| In-scope only | Yes | No | MEDIUM |
| HTTP/WS separation | Yes | No | MEDIUM |
| Auto-modified preview | Yes | No | LOW |
| Original message preview | Yes | No | LOW |
| **Draft test** | No | **Yes** | burpsy wins |
| **Revert** | No | **Yes** | burpsy wins |
| **Save indicator** | Yes | **Yes** | ✓ |

### Proxy → Proxy settings

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| TLS passthrough | Yes | No | HIGH |
| Resource pools | Yes | No | HIGH |
| Miscellaneous settings | Yes | No | LOW |
| Web interface disable | Yes | No | LOW |
| **Outcome counters** | No | **Yes** | burpsy wins |
| **Transport adjustments** | No | **Yes** | burpsy wins |
| **Response modification** | Yes | **Yes** | ✓ |

### Intruder → Positions

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Add position (Add §) | Yes | No | HIGH |
| Auto position (Auto §) | Yes | No | HIGH |
| Clear positions (Clear §) | Yes | No | HIGH |
| Position list | Yes | No | HIGH |
| Target field | Yes | No | HIGH |
| Request editor | Full HTTP editor | No | HIGH |
| **Attack type selector** | Yes | **Yes** | ✓ |
| **Find positions** | Yes | **Yes** | ✓ |

### Intruder → Payloads

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Payload type selector | 12+ types | No | HIGH |
| Load/Paste/Remove | Yes | No | HIGH |
| Payload count | Yes | No | HIGH |
| Processing rules | Yes | No | HIGH |
| Grep payloads | Yes | No | HIGH |
| Match/replace in list | Yes | No | HIGH |
| Illegal UTF-8 | Yes | No | LOW |
| Hex formatting | Yes | No | LOW |
| Max permutations | Yes | No | LOW |
| **Attack result accounting** | No | **Yes** | burpsy wins |

### Intruder → Resource pool

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Concurrent requests | Yes | No | HIGH |
| Delay | Yes | No | HIGH |
| Random variations | Yes | No | HIGH |
| Increment delay | Yes | No | HIGH |
| Custom pool | Yes | No | HIGH |
| Edit/Delete pool | Yes | No | HIGH |

### Intruder → Settings

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Scan details | Yes | No | HIGH |
| Scope configuration | Yes | No | HIGH |
| Isolate scan | Yes | No | HIGH |
| Engine configuration | Yes | No | HIGH |
| Attack configuration | Yes | No | HIGH |
| Duplicate attacks | Yes | No | HIGH |

### Intruder → Results

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Results table | Yes | No | HIGH |
| Server responses | Yes | No | HIGH |
| Progress bar | Yes | No | HIGH |
| Pause/Resume/Stop | Yes | No | HIGH |
| Save to project | Yes | No | MEDIUM |
| 8 result columns | Yes | No | HIGH |
| Split pane | Yes | No | LOW |

### Repeater

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Send button | Yes | Yes (after new request) | LOW |
| Cancel button | Yes | No | MEDIUM |
| Edit target | Yes | No | MEDIUM |
| Protocol selector | Yes | No | LOW |
| Status label | Yes | No | LOW |
| Follow redirects | Yes | No | LOW |
| Explore (AI) | Yes | No | LOW |
| Search | Yes | No | LOW |
| Request view controls | Yes | No | MEDIUM |
| Response view controls | Yes | No | MEDIUM |
| Tab panel | Multiple tabs | Yes | ✓ |
| Configuration override | Yes | Yes (SendOptionsPanel) | ✓ |
| WS tab option | Yes | No | LOW |
| HTTP tab option | Yes | Yes | ✓ |
| Streaming config | Yes | No | LOW |
| Validation warnings | Yes | No | LOW |
| **Tab groups** | No | **Yes** | burpsy wins |
| **Reopen stack** | No | **Yes** | burpsy wins |
| **Inspector panel** | No | **Yes** | burpsy wins |

### Sequencer

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Token analysis | Spectral/Transitions/FIPS | No | HIGH |
| Token handling | base64 decode/pad | No | HIGH |
| **Analyse** | Yes | **Yes** | ✓ |
| **Paste list** | Yes | **Yes** | ✓ |
| **Capture from live** | Yes | **Yes** | ✓ |
| **Encoding select** | Yes | **Yes** | ✓ |

### Comparer

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Word-level | Yes | No | MEDIUM |
| **Byte-level** | Yes | **Yes** | ✓ |
| **Swap** | Yes | **Yes** | ✓ |
| **Compare** | Yes | **Yes** | ✓ |
| **Slot A/B** | Yes | **Yes** | ✓ |

### Decoder

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Single-shot decode | Yes | Yes | ✓ |
| Single-shot encode | Yes | Yes | ✓ |
| **Hash step** | No | **Yes** | burpsy wins |
| **Pipeline** | No | **Yes** | burpsy wins |
| **Clear all** | No | **Yes** | burpsy wins |
| **Run pipeline** | No | **Yes** | burpsy wins |

### Collaborator

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Payload count | Yes | No | MEDIUM |
| Server location | Yes | No | MEDIUM |
| Configure interactsh | Yes | No | HIGH |
| **Blind XSS** | No | **Yes** | burpsy wins |
| **Copy script tag** | No | **Yes** | burpsy wins |
| **Copy payload** | Yes | **Yes** | ✓ |
| **Poll now** | Yes | **Yes** | ✓ |

### Logger

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Capture by tool | Checkboxes | Yes | ✓ |
| Capture by status | Per-status | Single select | MEDIUM |
| Capture by MIME | Per-type | No | MEDIUM |
| Capture by search | Case/regex/term | Search input | LOW |
| Capture by request type | In-scope/parameterized | No | MEDIUM |
| Memory limit | Yes | No | LOW |
| **Dropped counter** | No | **Yes** | burpsy wins |
| **Per-tool capture toggles** | No | **Yes** | burpsy wins |
| **Context menu** | No | **Yes** | burpsy wins |
| **Column visibility** | No | **Yes** | burpsy wins |
| **Show in history** | No | **Yes** | burpsy wins |

### Organizer

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| In-scope filter | Yes | No | MEDIUM |
| Status filter | Yes | No | MEDIUM |
| MIME filter | Yes | No | MEDIUM |
| **Save exchange** | Yes | **Yes** | ✓ |
| **Refresh** | Yes | **Yes** | ✓ |

### Session

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Session rules | Yes | Yes | ✓ |
| Login rules | Yes | Yes | ✓ |
| Run login macro | Yes | Yes | ✓ |
| Add header | Yes | Yes | ✓ |
| Run login now | Yes | Yes | ✓ |
| Cookie jar | Yes | Yes | ✓ |
| **Rule extraction** | No | **Yes** | burpsy wins |
| **Macro steps** | No | **Yes** | burpsy wins |
| **Validity conditions** | No | **Yes** | burpsy wins |

### Extender

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Add extension | Yes | No | HIGH |
| Edit extension | Yes | No | HIGH |
| Remove extension | Yes | No | HIGH |
| Extension list | Yes | Yes | ✓ |
| Extension details | Yes | Yes | ✓ |
| Output tab | Yes | Yes | ✓ |
| Errors tab | Yes | Yes | ✓ |
| JMenu items | Yes | No | MEDIUM |
| Hot key handlers | Yes | No | MEDIUM |
| bapp update | Yes | No | LOW |
| Suppress popup | Yes | No | LOW |
| Ruby/Python/Java config | Yes | No | MEDIUM |
| **API contracts** | No | **Yes** | burpsy wins |

### Discover

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Content discovery (ffuf) | Yes | No | HIGH |
| **Documentation hub** | No | **Yes** | burpsy wins |
| **Keyboard shortcuts** | No | **Yes** | burpsy wins |
| **Query language** | No | **Yes** | burpsy wins |

### Settings

| Feature | Burp | burpsy | Gap |
|---------|------|--------|-----|
| Project options | Comprehensive | No | HIGH |
| Scope settings | Yes | No | HIGH |
| Crawling settings | Yes | No | HIGH |
| Application login | Yes | No | HIGH |
| **Tool limits table** | Yes | **Yes** | ✓ |
| **TLS passthrough** | Yes | **Yes** | ✓ |
| **Resource pools** | Yes | **Yes** | ✓ |

---

## 4. Cross-cutting gaps

### Context menus (Burp has ~12, burpsy has 0)

| Location | Burp menu items |
|----------|-----------------|
| Dashboard event log | Copy column, Hide column, Sort |
| Dashboard activity log | Copy column, Hide column, Sort |
| Table headers | Copy column, Hide column, Sort Asc/Desc/Cancel |
| Scan check tester | Enable, Disable, Duplicate, Remove |
| Proxy intercept | Forward, Drop, Send to Repeater/Comparer/Intruder/Spider, Do intercept, Comment, Highlight |
| History row | Send to Repeater/Comparer/Intruder/Spider, Do intercept, Drop, Comment, Highlight |
| WebSocket | Send to Repeater/Comparer |
| Audit issue | Various |
| Extension | Plugin-specific menus |

### Dialogs/windows (Burp has ~8, burpsy has ~2)

| Dialog | Burp | burpsy |
|--------|------|--------|
| Scan configuration editor | Zgfr.java (JDialog) | No |
| Documentation/help | Zs12.java (JDialog) | No |
| Message editor | Zxst.java (JDialog) | No |
| Floating tool window | Zeeh.java (JWindow) | No |
| Floating tool window | Zmt1.java (JWindow) | No |
| **New scan** | No | **Yes** |
| **New live task** | No | **Yes** |

### Keyboard shortcuts

| Feature | Burp | burpsy |
|---------|------|--------|
| Global shortcuts | ~30 | ~10 |
| Send request | Ctrl+Enter | Yes |
| Navigate tabs | Ctrl+1-9 | Yes |
| Command palette | Ctrl+K | Yes |
| Find | Ctrl+F | No |
| Various tool-specific | Many | Few |

---

## 5. Priority ranking

### P0 — Functional blocks (tools unusable without these)

1. Scanner tab — no scan configuration UI
2. Intruder sub-tab content — all 5 tabs render identically
3. Intercept Forward/Drop/Action toolbar — can't forward/drop from toolbar
4. Extender Add/Edit/Remove — can't manage extensions

### P1 — Major UX gaps (tools functional but painful)

5. Repeater empty state — no blank editor by default
6. History Bambda mode — no advanced filtering
7. History per-column filters — no precise filtering
8. WebSocket connection detail — can't inspect frames
9. Discover content discovery — no ffuf integration
10. Proxy settings TLS passthrough — missing section
11. Proxy settings resource pools — missing section
12. Match & Replace edit/remove — can't manage rules

### P2 — Medium gaps (noticeable but not blocking)

13. Dashboard task progress bar — static text
14. Dashboard event log popup — no context menu
15. Dashboard activity log popup — no context menu
16. Site map crawl paths view — missing second view
17. Site map passive scan — missing controls
18. HTTP history context menus — no right-click
19. Intercept Comment/Highlight — missing buttons
20. Intercept Edit target — missing
21. Intruder payload type selector — missing
22. Intruder resource pool — missing
23. Intruder scan settings — missing
24. Intruder results table — missing
25. Repeater Cancel button — missing
26. Repeater Edit target — missing
27. Sequencer token analysis — missing
28. Sequencer token handling — missing
29. Organizer in-scope filter — missing
30. Organizer status filter — missing
31. Organizer MIME filter — missing

### P3 — Low gaps (cosmetic or rare use)

32. Dashboard pause/resume — missing
33. Dashboard listener status — missing
34. Dashboard telemetry — missing
35. Site map read-only indicator — missing
36. Site map items/queued/processed — missing
37. Scope advanced scope control — missing
38. Scope save to library — missing
39. History show highlighted — missing
40. History show commented — missing
41. History auto-scroll — missing
42. WebSockets Bambda filter — missing
43. WebSockets filter settings — missing
44. Match & Replace auto-modified preview — missing
45. Match & Replace original message preview — missing
46. Proxy settings miscellaneous — missing
47. Proxy settings web interface — missing
48. Collaborator payload count — missing
49. Collaborator server location — missing
50. Comparer word-level — missing
51. Extender JMenu items — missing
52. Extender hot key handlers — missing
53. Extender bapp update — missing
54. Extender suppress popup — missing
55. Extender Ruby/Python/Java config — missing
56. Repeater status label — missing
57. Repeater follow redirects — missing
58. Repeater explore (AI) — missing
59. Repeater search — missing
60. Repeater WS tab option — missing
61. Repeater streaming config — missing
62. Repeater validation warnings — missing

---

## 6. Summary

| Priority | Count | Description |
|----------|-------|-------------|
| P0 | 4 | Functional blocks — tools unusable |
| P1 | 8 | Major UX gaps — tools painful to use |
| P2 | 14 | Medium gaps — noticeable |
| P3 | 30 | Low gaps — cosmetic |
| **Total** | **56** | **Total missing features** |

| Category | Burp has | burpsy has | Parity |
|----------|----------|-----------|--------|
| Top-level tabs | 15 | 15 | 100% |
| Scanner tab | Yes | No | 0% |
| Sub-tabs | ~25 | ~25 | 80% |
| API endpoints | ~80 | 83 | 100% |
| UI-exposed features | ~60 | ~26 | 43% |
| Context menus | ~12 | 0 | 0% |
| Dialogs/windows | ~8 | 2 | 25% |
| Keyboard shortcuts | ~30 | ~10 | 33% |

---

— PlumOtter, comprehensive parity audit 2026-08-27
