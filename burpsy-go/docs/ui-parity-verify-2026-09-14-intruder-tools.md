# UI-parity verification sweep — Intruder, Repeater, Sequencer, Decoder, Comparer, Logger, Organizer
Read-only. Live console http://127.0.0.1:18281/. Audit under test: burpsy-go/docs/ui-parity-audit-complete.md (2026-08-27).
Driver: playwright-core headless against the running console (paseo browser host died mid-sweep; findings after that point were taken with /tmp/pw2.js + /tmp/multi.js).
Burp reference: /root/burp-re/out/strings/map_root.tsv (positive control: `grep -ac 'Start attack' map_root.tsv` = 3).

## Intruder -> Positions (audit: 6 HIGH gaps)
| Claim | Status | Evidence |
|---|---|---|
| Add position (Add §) | CLOSED | Selected `q=` in the base-request editor, opened "Actions for Base request · message 2" -> menuitem **"Add § payload marker"**, `aria-disabled=null`. Source: intruder.tsx:1420 `onAddManualSpan`, ui/editor.tsx:749 |
| Auto § | CLOSED | `button "Auto §"` in snapshot; intruder.tsx:1854 |
| Clear § | CLOSED | `button "Clear §"`; intruder.tsx:1858 |
| Position list | CLOSED | After Find positions on msg 2: `checkbox "Use position q"` + text `q / url_param_value · offset 13 · 1`, toast "1 insertion point found" |
| Target field | CLOSED | `textbox "Target authority"`, placeholder `https://host:443` |
| Request editor | CLOSED | `textbox "Base request · message 2"`, tabs Raw/Hex/**Params**, line gutter 1-5, charset combobox, `69 B`, Copy message / Save to file |

## Intruder -> Payloads (audit: 6 HIGH + 3 LOW)
| Claim | Status | Evidence |
|---|---|---|
| Payload type selector (12+) | CLOSED | `<select>` with **17** options: Simple list, Numbers, File (server path), Brute force, Dates, Custom iterator, Null payloads, Character substitution, Case modification, Illegal Unicode, Character blocks (frobber), Bit flipper, Username generator, ECB block shuffler, Copy other payload, Recursive grep, Collaborator payloads |
| Payload count | CLOSED | `label "SET (5)"`; after I replaced the list it read `SET (25)` |
| Processing rules | CLOSED | "Payload processing — Rules run in order on every payload before it is sent." + `button "Add rule"`; RuleRow at intruder.tsx:149 |
| Grep payloads | CLOSED (equivalent) | Burp's Grep-Payloads flags payload reflections; burpsy's results carry a `REFLECTED` column — live: ordinal 0 `admin 200 ... REFLECTED YES` |
| Match/replace in list | CLOSED | Covered by the processing-rule editor (intruder.tsx:149, "Editor for one payload processing rule") |
| Illegal UTF-8 | CLOSED (equivalent) | `Illegal Unicode` payload type; intruder.tsx:1373/1578 `illegal_unicode` |
| Load / Paste / Remove | PARTIAL -> LOW | `Load from file…` + `input[type=file]` present. No Paste/Remove buttons: the payload list is a plain editable textarea, so paste is Ctrl+V and remove is deleting a line |
| Hex formatting | STILL-OPEN (LOW) | Burp string `Hex formatting` (burp.Zrv8, 1 hit). `grep -ain "hexFormat" intruder.tsx` -> no hit |
| Max permutations | NOT-APPLICABLE | `grep -ac 'Max permutations' map_root.tsv` = **0** — Burp has no such control; the audit invented it |

## Intruder -> Resource pool (audit: 6 HIGH)
| Claim | Status | Evidence |
|---|---|---|
| Concurrent requests | CLOSED | `spinbutton "Max concurrent requests"` = 8 |
| Delay | CLOSED (equivalent) | `spinbutton "Requests per second"`. Verified it bites: rps=1 with 25 payloads -> `ELAPSED 24.0 s`; rps=1 with 5 -> `ELAPSED 4.0 s` |
| Custom pool | CLOSED | `combobox "Resource pool"` = "Inline limits (no saved pool)" + "Bind this attack to a pool created in Settings -> Resource pools" |
| Edit/Delete pool | CLOSED (elsewhere) | settings.tsx:1980 `Edit pool ${editing}` / "New resource pool", panel title "Resource pools" (settings.tsx:2065) |
| Random variations | **STILL-OPEN (MEDIUM)** | Burp: `With random variations` (burp.Zhwk), `Throttle random`, `...throttle_random_enabled`. burpsy: `grep -ain "random" intruder.tsx` -> **no hit**; no jitter field in internal/intruder/limit.go |
| Increment delay | **STILL-OPEN (MEDIUM)** | Burp: `throttleIncrementEnabled=` / `throttleIncrementMillis=` (burp.Zgao). burpsy: `grep -ain "increment" intruder.tsx` -> **no hit** |

Also present and not in the audit: Retries on network failure, Pause before retry (ms), Make unmodified baseline request.

## Intruder -> Settings (audit: 6 HIGH)
**All six rows are NOT-APPLICABLE.** The audit lists Scan details / Scope configuration / Isolate scan / Engine configuration / Attack configuration / Duplicate attacks — those are the *scanner* launch dialog, not Intruder Settings. Burp string counts: `Isolate scan` 0, `Duplicate attacks` 0, `Engine configuration` 0.
Burp's own doc (tools/intruder/configure-attack/settings.html) says the panel is: Save attack, **Request headers** (Update Content-Length, Set Connection), **Error handling** (retries, pause before retry), **Attack results** (store requests/responses), Grep-Match, Grep-Extract, Grep-Payloads, Redirections.
Measured against *that* list, burpsy's Settings tab has: Grep match (simple/regex, multi-expression one-per-line, case sensitive, exclude HTTP headers), Grep extract (regex), Follow redirections (Standing policy / Never / On-site only / In-scope only / Always). Error handling lives on the Resource pool tab. 
Only real remainder: the Request-headers toggles. burpsy applies Content-Length unconditionally (`fixContentLength`, internal/intruder/points.go:449-450) rather than exposing a switch — LOW, and arguably the better default.

## Intruder -> Results (audit: 5 HIGH, 1 MEDIUM, 1 LOW)
| Claim | Status | Evidence |
|---|---|---|
| Results table | CLOSED | Ran a live sniper attack (msg 2, 5 payloads). Columns: `# PAYLOAD STATUS TIME OF DAY LENGTH TIME REFLECTED GREP ERROR TIMEOUT COOKIES RESPONSE COMMENT` = 13 |
| 8 result columns | CLOSED | 13 columns, see above |
| Server responses | CLOSED | `View` link per row and per bucket |
| Save to project | CLOSED (equivalent) | `Export CSV`, `Export report (JSON)`. Burp's string is `Save results table` |
| Split pane | CLOSED | Result buckets / Payload set accounting / Attempts panes |
| **Progress bar** | **STILL-OPEN (HIGH)** | During a 24.0 s attack, 6 polls at 1.8 s intervals found no `progress`/`[role=progressbar]` element and no advancing counter; the toolbar read `LOCATING ATTACK…` / `Attacking…`. SENT/of-planned only appears in the *final* report |
| **Pause / Resume / Stop** | **STILL-OPEN (HIGH)** | Same run: `[...document.querySelectorAll('button')].map(b=>b.innerText.trim()).filter(x=>/^(Pause\|Resume\|Stop)$/.test(x))` -> `[]` at every poll across ~11 s of a 24 s attack |

Positive control for those two: the same query on the same page returns `Auto §`, `Clear §`, `Find positions`, `Export CSV`, so the query and the selector work.

## Repeater (audit: 2 MEDIUM x2, 7 LOW)
| Claim | Status | Evidence |
|---|---|---|
| Cancel button | CLOSED (in-flight only) | Sent to black-hole `http://10.255.255.1:81`; mid-send `document.body.innerText.match(/Cancel\|Sending/g)` -> `["Cancel","Sending"]`. repeater.tsx:756 renders it on `send.isPending` — deliberately, per the comment at 752 |
| Edit target | CLOSED | `label "TARGET"` + editable target input on every tab |
| Protocol selector | CLOSED | Config panel `label "PROTOCOL"`, options Auto (negotiate) / Force HTTP/1.1 / Force HTTP/2; plus HTTP/1 \| HTTP/2 in the Inspector |
| Status label | CLOSED | repeater.tsx:236 `${result.status} in ${formatDuration(result.duration_ms)}`; :679 `<Badge>{formatDuration(result.duration_ms)}</Badge>` |
| Follow redirects | CLOSED | Config panel `label "FOLLOW REDIRECTIONS"` -> Standing policy / Never / On-site only / In-scope only / Always |
| Search | CLOSED | Actions menu item `Find in this message  Ctrl+S` |
| Request view controls | CLOSED | RAW/HEX, charset combobox, Disable wrapping, Show non-printing characters, Paste from file, Copy message, Save to file |
| Response view controls | CLOSED | `Actions for Response` + its own RAW/HEX and charset combobox |
| Send | CLOSED | `button "Send"` |
| WS tab option | STILL-OPEN (LOW) | `grep -ain "websocket" repeater.tsx` -> no hit |
| Explore (AI) | STILL-OPEN (LOW) | Burp Pro feature; no equivalent control on the page |
| Streaming config / Validation warnings | NOT VERIFIED | I did not find a query that isolates these; not claiming either way |

Config panel also carries: Process cookies in this request, Strip Connection headers, Normalize line endings to CRLF, Update Content-Length from body, Reset overrides.

## Sequencer (audit: 2 HIGH)
| Claim | Status | Evidence |
|---|---|---|
| Token analysis (Spectral / Transitions / FIPS) | **CLOSED** | Pasted 120 hex tokens, clicked Analyse. Rendered: `FIPS 140-2 bit-level tests` (GRADE, ONES/ZEROS 5,520/6,000, LONGEST RUN, RUNS OF ZEROS/ONES), `Spectral test  FAIL  worst of 10 combination(s) ... X2 = 3314.67`, `Character transition analysis`, `Effective entropy by significance level` (14-level table), `Character positions` per-position entropy table. Plus Correlation and Compression tests Burp does not have |
| Token handling — base64 decode | CLOSED | `combobox "Read token bits as"` -> detect encoding / hex / base64 / raw bytes; result panel confirmed `BITS READ AS  hex  detected` |
| Token handling — pad short tokens | STILL-OPEN (LOW) | Burp string `pad short tokens at start` (2 hits). `grep -ain "pad" sequencer.tsx` -> no hit |

## Comparer (audit: 1 MEDIUM)
| Claim | Status | Evidence |
|---|---|---|
| Word-level compare | **STILL-OPEN (MEDIUM) — confirmed** | Burp has `Word compare` (2 hits) and `Byte compare` (1 hit) as distinct compare modes. burpsy's buttons are `Text` / `Hex` — a *view* toggle, not granularity — plus Swap, Compare, Load. internal/web/diff.go:19 states the page "disclosed that it compared *bytes* rather than words, which is a statement about granularity" |
| Byte-level / Swap / Compare / Slot A+B | CLOSED | `Swap`, `Compare`, `Load`, `Stored message id for slot A` / `slot B`, `Discount headers as: Responses/Requests` |

## Decoder (audit: no gaps claimed)
Confirmed no gaps, and none found by sweeping Burp's own strings. Live: Text/Hex, Clear all, Run pipeline, per-step `Decode/Encode/Hash`, 12 encodings (smart detect, url, html, base64, base64url, hex, octal, binary, gzip, deflate, jwt, ascii), `guess base64 / hex alphabets`, step reorder (Move step 1 earlier/later) and Remove step. Burp's `Smart decode` maps to burpsy's `smart detect`.

## Logger (audit: 3 MEDIUM, 1 LOW)
| Claim | Status | Evidence |
|---|---|---|
| Capture by status | CLOSED | Filter settings panel carries a `Status` control; the display filter has `Any status / 2xx / 3xx / 4xx / 5xx / no response` |
| Capture by search | CLOSED | `Regex`, `Case sensitive`, `Negative` + `Search the tool log` (matches Burp's `logger.capture_filter.by_search.negative_search`) |
| Memory limit | CLOSED (equivalent) | `label "CAPTURE LIMIT (ROWS)"` + `Save capture filter`. Burp's is `logger.capture_filter.task_capture_memory_limit_mb` — same bound, rows vs MB |
| Capture by MIME | **STILL-OPEN (MEDIUM)** | Burp: `Capture by MIME type` (1 hit) and `logger.capture_filter.by_mime_type.capture_other_binary`. burpsy: `grep -ain "mime" logger.tsx` -> **no hit**; no MIME control in the Filter settings panel |
| Capture by request type | PARTIAL (LOW) | `In-scope only` present. Burp also has `logger.capture_filter.by_request_type.capture_only_parameterized_requests` — no parameterized-only toggle in burpsy |

## Organizer (audit: 3 MEDIUM)
| Claim | Status | Evidence |
|---|---|---|
| In-scope filter | CLOSED | `label "In scope only"` (checkbox) |
| Status filter | CLOSED | `label "STATUS"` -> Any status / 2xx success / 3xx redirect / 4xx client error / 5xx server error / No response |
| MIME filter | CLOSED | `label "MIME TYPE"` -> "Any type" (populated from saved exchanges; 0 saved in the seed) |

Also present and unclaimed: TOOL, WORKFLOW (New/In progress/Postponed/Done/Ignored), EXTENSION, SEARCH TERM with Regex/Case sensitive/Negative, Annotated only, Collections + Inbox, Export CSV.

---
# STILL-OPEN, ranked

## 1. HIGH — Intruder has no runtime attack control: Pause / Resume / Stop never appear, and there is no progress indicator
**Burp:** an attack opens its own results window that shows a progress bar and a live request counter, with Pause and Stop available from the first request. Stopping a running attack is a safety control on an engagement, not a convenience.
**burpsy:** during a deliberately throttled 24.0 s attack (25 payloads at 1 rps, confirmed by `ELAPSED 24.0 s`), the toolbar sat at `LOCATING ATTACK…` / `Attacking…` for the whole run. Six polls at 1.8 s intervals returned `[]` for buttons matching `/^(Pause|Resume|Stop)$/`, and no `progress` or `[role=progressbar]` element existed. Counts only appear in the final report.
**The backend already serves all of it.** `GET /api/intruder/attacks` during a run returns `{"task_id":7,"kind":"sniper","target":"127.0.0.1:18299","planned":10,"status":"running","sent":2,...}` and `sent` advances 2→3→…→9 once per second; `internal/web/api_intruder_control.go` exposes `/api/intruder/attacks/{task_id}/{pause|resume|stop}` (referenced at internal/web/ui_route_reachability_test.go:87).
**Why it is UI-side:** intruder.tsx:1218-1233 only starts looking for its task id *while `run.isPending`*, and matches on `a.target === targetAuthority(target) && a.kind === mode`. The controls are gated on that lookup landing (intruder.tsx:1719-1740, 2707-2740). In my run it never landed inside a 24 s window even though the API was returning the matching attack the whole time.
**Smallest honest sketch:** intruder.tsx — the `myAttack` object already carries `sent`/`planned`/`status`, so rendering a progress bar is a few lines once the id resolves. The real fix is the identification race: have `POST /api/intruder/run` return its `task_id` immediately (or accept a client-supplied correlation id) instead of making the page infer its own attack from a polled list. That removes the "LOCATING ATTACK…" state entirely and makes Pause/Stop available from request one. Backend change is small; the control endpoints already exist.

## 2. MEDIUM — Intruder resource pool has no delay variation (random / increment)
**Burp:** `With random variations` and `throttleIncrementMillis` on the resource pool, so an attack can jitter or ramp its delay — the standard way to keep a long attack under a lockout or rate-limit threshold.
**burpsy:** a single flat `Requests per second`. `grep -ain "random\|increment" intruder.tsx` returns nothing, and `internal/intruder/limit.go` has no jitter field (its `AutoThrottle` is reactive backoff on 429/503, a different thing).
**Sketch:** engine-side first — `RateLimit` in internal/intruder/limit.go gains an optional jitter fraction and a per-request increment; then two inputs next to `Requests per second` on the Resource pool tab. The backend does **not** serve this today.

## 3. MEDIUM — Logger cannot filter capture by MIME type
**Burp:** `Capture by MIME type` with per-type toggles (`logger.capture_filter.by_mime_type.capture_other_binary`), so a long engagement does not fill the log with images and fonts.
**burpsy:** the Filter settings panel has per-tool toggles, Status, search with Regex/Case sensitive/Negative, In-scope only and a row cap — but `grep -ain "mime" logger.tsx` returns nothing.
**Sketch:** Organizer already has a working MIME TYPE filter, so the classification exists in the codebase — the cheapest path is to reuse it in logger.tsx's capture-filter panel and add the field to the capture-filter payload. Worth checking whether the tool-log record carries a content type before committing.

## 4. MEDIUM — Comparer has no word-level compare
**Burp:** `Word compare` and `Byte compare` are two distinct modes; word-level is what makes two HTML responses readable side by side.
**burpsy:** `Text` / `Hex` are view toggles only, and internal/web/diff.go is byte-granularity Myers throughout — the file's own header comment acknowledges the page "compared *bytes* rather than words".
**Sketch:** diff.go already isolates the diff behind a token sequence (prefix/suffix trim, then Myers). Tokenising on word boundaries instead of bytes for a `granularity=word` request, and adding a Words/Bytes toggle in comparer.tsx, is the whole change. Backend change required but contained to one file.

## 5. LOW — the small ones
- **Sequencer "pad short tokens at start"** — Burp string present (2 hits), no `pad` in sequencer.tsx.
- **Intruder "Hex formatting"** — Burp string `Hex formatting` (burp.Zrv8), no equivalent in intruder.tsx.
- **Logger parameterized-only capture** — Burp's `capture_only_parameterized_requests`; burpsy has In-scope only but not this.
- **Repeater WebSocket tab** — no `websocket` in repeater.tsx.
- **Repeater Explore (AI)** — Burp Pro feature, no equivalent.
- **Intruder payload Paste/Remove buttons** — the textarea makes them redundant; cosmetic only.

---
# Audit corrections (claims that are wrong, not just stale)
- **Intruder -> Settings, all six rows**: Scan details / Scope configuration / Isolate scan / Engine configuration / Attack configuration / Duplicate attacks are not Burp Intruder settings. Burp string counts are 0 for three of them. These describe the scanner's launch dialog.
- **Intruder -> Payloads "Max permutations"**: 0 hits in Burp's strings — the control does not exist in Burp.
- **Organizer's three rows** and **Sequencer's two HIGH rows** were all already shipped; the audit's Sequencer entry in particular understates burpsy, which runs the full FIPS battery plus spectral, transition, correlation and compression tests.
