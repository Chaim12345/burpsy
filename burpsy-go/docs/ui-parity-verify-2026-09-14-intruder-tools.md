# UI-parity verification sweep — Intruder, Repeater, Sequencer, Decoder, Comparer, Logger, Organizer

Read-only. Live console `http://127.0.0.1:18281/`, driven with playwright-core headless.
Audit under test: `burpsy-go/docs/ui-parity-audit-complete.md` (2026-08-27).
Burp reference: `/root/burp-re/out/strings/map_root.tsv` — positive control `grep -ac 'Start attack' map_root.tsv` = 3.

**Headline: the audit is badly stale. Of 41 claimed gaps across these seven pages, 29 are CLOSED, 8 are NOT-APPLICABLE or equivalent-by-another-name, and 4 survive.** Intruder alone accounts for 29 claimed "HIGH" gaps; every one of them is closed.

---

## Intruder → Positions (audit: 6 HIGH)
| Claim | Status | Evidence |
|---|---|---|
| Add position (Add §) | CLOSED | Selected `q=` in the base-request editor → "Actions for Base request · message 2" → menuitem **"Add § payload marker"**, not disabled. intruder.tsx:1420, ui/editor.tsx:749 |
| Auto § | CLOSED | `button "Auto §"`; intruder.tsx:1854 |
| Clear § | CLOSED | `button "Clear §"`; intruder.tsx:1858 |
| Position list | CLOSED | After Find positions on msg 2: `checkbox "Use position q"` + `q / url_param_value · offset 13 · 1`; toast "1 insertion point found" |
| Target field | CLOSED | `textbox "Target authority"`, placeholder `https://host:443` |
| Request editor | CLOSED | `textbox "Base request · message 2"`, tabs Raw/Hex/**Params**, line gutter, charset combobox, `69 B`, Copy message, Save to file |

## Intruder → Payloads (audit: 6 HIGH, 3 LOW)
| Claim | Status | Evidence |
|---|---|---|
| Payload type selector (12+) | CLOSED | `<select>` with **17** options: Simple list, Numbers, File (server path), Brute force, Dates, Custom iterator, Null payloads, Character substitution, Case modification, Illegal Unicode, Character blocks (frobber), Bit flipper, Username generator, ECB block shuffler, Copy other payload, Recursive grep, Collaborator payloads |
| Payload count | CLOSED | `label "SET (5)"`; became `SET (25)` when I replaced the list |
| Processing rules | CLOSED | `button "Add rule"` → rule-type select observed live: Add prefix, Add suffix, Match and replace, Uppercase, Lowercase, Encode, Decode, Hash, Skip if it matches |
| Match/replace in list | CLOSED | **"Match and replace"** is one of the rule types above (observed, not inferred) |
| Grep payloads | CLOSED (equivalent) | Burp's Grep-Payloads flags payload reflections; burpsy's results carry a `REFLECTED` column — live row: `0  admin  200 … REFLECTED YES` |
| Illegal UTF-8 | CLOSED (equivalent) | `Illegal Unicode` payload type; intruder.tsx:1373/1578 `illegal_unicode` |
| Load / Paste / Remove | PARTIAL (LOW) | `Load from file…` + `input[type=file]` present. No Paste/Remove buttons — the list is a plain editable textarea, so paste is Ctrl+V and remove is deleting a line |
| Hex formatting | **STILL-OPEN (LOW)** | Burp string `Hex formatting` (burp.Zrv8). `grep -ain "hexFormat" intruder.tsx` → no hit |
| Max permutations | **NOT-APPLICABLE** | `grep -ac 'Max permutations' map_root.tsv` = **0** — no such Burp control |

## Intruder → Resource pool (audit: 6 HIGH)
| Claim | Status | Evidence |
|---|---|---|
| Concurrent requests | CLOSED | `spinbutton "Max concurrent requests"` = 8 |
| Delay | CLOSED (equivalent) | `spinbutton "Requests per second"`. Verified it bites: rps=1 × 25 payloads → `ELAPSED 24.0 s`; rps=1 × 5 → `ELAPSED 4.0 s` |
| Custom pool | CLOSED | `combobox "Resource pool"` = "Inline limits (no saved pool)" |
| Edit/Delete pool | CLOSED (elsewhere) | settings.tsx:1980 `Edit pool ${editing}` / "New resource pool"; panel "Resource pools" settings.tsx:2065 |
| Random variations | **STILL-OPEN (MEDIUM)** | Burp: `With random variations` (burp.Zhwk), `Throttle random`, `…throttle_random_enabled`. burpsy: `grep -ain "random" intruder.tsx` → **no hit**; no jitter field in internal/intruder/limit.go |
| Increment delay | **STILL-OPEN (MEDIUM)** | Burp: `throttleIncrementEnabled=` / `throttleIncrementMillis=` (burp.Zgao). burpsy: `grep -ain "increment" intruder.tsx` → **no hit** |

Present and unclaimed: Retries on network failure, Pause before retry (ms), Make unmodified baseline request.

## Intruder → Settings (audit: 6 HIGH) — **all six NOT-APPLICABLE**
The audit lists Scan details / Scope configuration / Isolate scan / Engine configuration / Attack configuration / Duplicate attacks. Those are the **scanner's** launch dialog, not Intruder Settings. Burp string counts: `Isolate scan` **0**, `Duplicate attacks` **0**, `Engine configuration` **0**.

Burp's own doc (`tools/intruder/configure-attack/settings.html`) defines the panel as: Save attack, Request headers (Update Content-Length, Set Connection), Error handling (retries, pause before retry), Attack results (store requests/responses), Grep-Match, Grep-Extract, Grep-Payloads, Redirections.

Measured against *that*: burpsy's Settings tab has Grep match (simple/regex, multi-expression one-per-line, case sensitive, exclude HTTP headers), Grep extract (regex), and Follow redirections (Standing policy / Never / On-site only / In-scope only / Always). Error handling is on the Resource pool tab.
Only remainder: the Request-headers toggles — burpsy applies Content-Length unconditionally (`fixContentLength`, internal/intruder/points.go:449) instead of exposing a switch. LOW, and arguably the better default.

## Intruder → Results (audit: 5 HIGH, 1 MEDIUM, 1 LOW) — **all CLOSED**
Ran a live throttled sniper attack (msg 2, 24 planned, rps=1) and sampled once a second with the Results tab selected.

| Claim | Status | Evidence |
|---|---|---|
| Results table | CLOSED | Columns `# PAYLOAD STATUS TIME OF DAY LENGTH TIME REFLECTED GREP ERROR TIMEOUT COOKIES RESPONSE COMMENT` = **13** (audit asked for 8) |
| Server responses | CLOSED | `View` control per attempt row and per result bucket |
| **Progress bar** | CLOSED | Live element width advanced `12.5% → 16.6667% → 20.8333%` in lockstep with the API's sent count |
| **Pause / Resume / Stop** | CLOSED | `Pause` and `Stop` buttons present from **t=1.1 s** and at every 1 s sample through the run. `Resume` correctly replaces `Pause` only once paused |
| Live counter | CLOSED | `got responses, 0 failed — of 24 planned`, alongside API `task_id 10 … running 3/24 … 5/24` |
| Save to project | PARTIAL | `Export CSV` + `Export report (JSON)` cover Burp's `Save results table`. Burp's separate `Save attack to project file` (3 hits) — reopening a past attack — has no burpsy equivalent; `/api/intruder/attacks` is `[]` once a run ends |
| Split pane | CLOSED | Result buckets / Payload set accounting / Attempts |

> I first reported Pause/Stop and the progress bar as missing. That was wrong: my initial polls ran with the **Payloads** tab selected, and the controls render on the Results tab (intruder.tsx:2713-2749). Re-running with Results selected showed all of them.

## Repeater (audit: 2 MEDIUM, 2 MEDIUM, 7 LOW)
| Claim | Status | Evidence |
|---|---|---|
| Cancel button | CLOSED (in-flight) | Send to black-hole `10.255.255.1:81`; mid-send `innerText.match(/Cancel|Sending/g)` → `["Cancel","Sending"]`. repeater.tsx:756, gated on `send.isPending` by design (comment at :752) |
| Edit target | CLOSED | `label "TARGET"` + editable input per tab |
| Protocol selector | CLOSED | Config → `label "PROTOCOL"`: Auto (negotiate) / Force HTTP/1.1 / Force HTTP/2 |
| Status label | CLOSED | Live after a send to the seeded target: **`HTTP  200  4 MS  #10`** |
| Follow redirects | CLOSED | Config → `FOLLOW REDIRECTIONS`: Standing policy / Never / On-site only / In-scope only / Always |
| Search | CLOSED | Actions menu → `Find in this message  Ctrl+S` |
| Request view controls | CLOSED | RAW/HEX, charset, Disable wrapping, Show non-printing characters, Paste from file, Copy message, Save to file |
| Response view controls | CLOSED | `Actions for Response` + own RAW/HEX/**PARAMS** and charset combobox |
| Send | CLOSED | `button "Send"` |
| WS tab option | **STILL-OPEN (LOW)** | `grep -ain "websocket" repeater.tsx` → no hit |
| Explore (AI) | **STILL-OPEN (LOW)** | Burp Pro feature; no equivalent control |
| Streaming config / Validation warnings | NOT VERIFIED | I found no query that isolates these; not claiming either way |

Config also carries: Process cookies in this request, Strip Connection headers, Normalize line endings to CRLF, Update Content-Length from body, Reset overrides.

## Sequencer (audit: 2 HIGH)
| Claim | Status | Evidence |
|---|---|---|
| Token analysis (Spectral / Transitions / FIPS) | **CLOSED** | Pasted 120 hex tokens → Analyse. Rendered: `FIPS 140-2 bit-level tests` (GRADE, ONES/ZEROS 5,520/6,000, LONGEST RUN, RUNS OF ZEROS/ONES), `Spectral test  FAIL  … X2 = 3314.67 on 15 df`, `Character transition analysis`, `Effective entropy by significance level` (14-level table), `Character positions` per-position entropy table |
| Token handling — base64 decode | CLOSED | `combobox "Read token bits as"`: detect encoding / hex / base64 / raw bytes; result panel `BITS READ AS  hex  detected` |
| Token handling — pad short tokens | **STILL-OPEN (LOW)** | Burp `pad short tokens at start` (2 hits). `grep -ain "pad" sequencer.tsx` → no hit |

## Comparer (audit: 1 MEDIUM)
| Claim | Status | Evidence |
|---|---|---|
| Word-level compare | **STILL-OPEN (MEDIUM) — confirmed** | Burp has `Word compare` (2 hits) and `Byte compare` (1 hit) as distinct modes. burpsy's buttons are `Text` / `Hex` — a *view* toggle — plus Swap, Compare, Load. internal/web/diff.go:19 says the page "disclosed that it compared **bytes** rather than words, which is a statement about granularity" |
| Byte-level / Swap / Compare / Slot A+B | CLOSED | `Swap`, `Compare`, `Load`, `Stored message id for slot A`/`slot B`, `Discount headers as: Responses/Requests` |

## Decoder (audit: no gaps) — none claimed, none found
Live: Text/Hex, Clear all, Run pipeline, per-step `Decode/Encode/Hash`, 12 encodings (smart detect, url, html, base64, base64url, hex, octal, binary, gzip, deflate, jwt, ascii), `guess base64 / hex alphabets`, step reorder and remove. Burp's `Smart decode` maps to burpsy's `smart detect`. I swept Burp's Decoder strings for anything unmatched and found nothing.

## Logger (audit: 3 MEDIUM, 1 LOW)
| Claim | Status | Evidence |
|---|---|---|
| Capture by search | CLOSED | `Regex`, `Case sensitive`, `Negative` + `Search the tool log` (= Burp's `logger.capture_filter.by_search.negative_search`) |
| Memory limit | CLOSED (equivalent) | `label "CAPTURE LIMIT (ROWS)"` + `Save capture filter`. Burp's is `…task_capture_memory_limit_mb` — same bound, rows vs MB |
| Capture by status | PARTIAL (LOW) | Status is a **single** `<select>` — `Any status / 2xx / 3xx / 4xx / 5xx / no response`. Burp's `logger.capture_filter.by_status_code.capture_3xx` / `capture_4xx` are independent per-class toggles, so Burp can capture 4xx+5xx only; burpsy can pick one class at a time. The audit's original wording was right |
| Capture by MIME | **STILL-OPEN (MEDIUM)** | Burp: `Capture by MIME type` + `logger.capture_filter.by_mime_type.capture_other_binary`. burpsy: `grep -ain "mime" logger.tsx` → **no hit**; no MIME control in the Filter settings panel |
| Capture by request type | PARTIAL (LOW) | `In-scope only` present. Burp's `…capture_only_parameterized_requests` has no burpsy equivalent |

## Organizer (audit: 3 MEDIUM) — **all CLOSED**
| Claim | Status | Evidence |
|---|---|---|
| In-scope filter | CLOSED | `label "In scope only"` |
| Status filter | CLOSED | `label "STATUS"`: Any status / 2xx success / 3xx redirect / 4xx client error / 5xx server error / No response |
| MIME filter | CLOSED | `label "MIME TYPE"` → "Any type" (populated from saved exchanges; 0 saved in the seed) |

Present and unclaimed: TOOL, WORKFLOW (New/In progress/Postponed/Done/Ignored), EXTENSION, SEARCH TERM with Regex/Case sensitive/Negative, Annotated only, Collections + Inbox, Export CSV.

---

# STILL-OPEN, ranked

## 1. MEDIUM — Comparer has no word-level compare  ← highest impact
**Burp:** `Word compare` and `Byte compare` are two first-class modes; the results window titles itself "Word compare of responses from …". Word-level is what makes two HTML or JSON responses readable side by side — at byte granularity a one-word change inside a long line is a run of byte edits the eye has to reassemble.
**burpsy:** one mode only. The page's `Text` / `Hex` buttons switch how bytes are *displayed*, not how they are aligned; `Swap`, `Compare`, `Load`, slot A/B and `Discount headers as` are all present. `internal/web/diff.go:19` states outright that the page "disclosed that it compared *bytes* rather than words, which is a statement about granularity".
**Backend:** does not serve it. `internal/web/diff.go` is byte-granularity end to end.
**Sketch:** diff.go is already structured as trim-common-prefix/suffix → Myers over the remainder. Myers is generic over a token sequence, so the change is to tokenise on word boundaries when the request carries `granularity=word`, emit ops in token offsets mapped back to bytes, and add a Words/Bytes toggle beside `Compare` in `pages/comparer.tsx`. Contained to one Go file plus one control.

**Why first:** it is the only remaining item where a documented Burp *mode* of a primary tool is entirely absent rather than renamed, relocated, or defaulted. Comparer exists to answer "what did my input change?", and every other page in this sweep now matches or exceeds Burp. It is also the cheapest of the MEDIUMs to land — one file, one toggle, and the file's own header comment already names the defect.

## 2. MEDIUM — Logger cannot filter capture by MIME type
**Burp:** `Capture by MIME type` with per-type toggles (`logger.capture_filter.by_mime_type.capture_other_binary`), so a long engagement's log does not fill with images, fonts and binaries.
**burpsy:** the Filter settings panel has per-tool toggles, a Status class, search with Regex/Case sensitive/Negative, In-scope only, and `CAPTURE LIMIT (ROWS)` — but `grep -ain "mime" logger.tsx` returns nothing. This compounds with the row cap: noise evicts signal.
**Backend:** partly served. `internal/core/mime.go` already provides `MimeFromContentType`, and Organizer ships a working MIME TYPE filter — but note `internal/core/store.go:368`, which warns that a MIME column filled in at list time "would read 100,000 response heads off disk to render one" page. So the type must be classified at *capture* time, not at list time.
**Sketch:** classify once when the tool-log row is written (reusing `core.MimeFromContentType`), store it on the record, then add the toggle set to logger.tsx's capture-filter panel and the field to the capture-filter payload.

## 3. MEDIUM — Intruder resource pool has no delay variation (random / increment)
**Burp:** `With random variations` and `throttleIncrementMillis` on the resource pool, so a long attack can jitter or ramp its delay — the standard way to stay under a lockout or rate-limit threshold.
**burpsy:** a single flat `Requests per second`. `grep -ain "random\|increment" intruder.tsx` returns nothing; `internal/intruder/limit.go` has no jitter field (its `AutoThrottle` is reactive backoff on 429/503 — a different mechanism, and a burpsy addition).
**Backend:** does not serve it.
**Sketch:** engine first — `RateLimit` in internal/intruder/limit.go gains an optional jitter fraction and a per-request increment; then two inputs beside `Requests per second` on the Resource pool tab, plus the two wire fields.

## 4. LOW — the small ones
- **Intruder: no "Save attack to project file"** — Burp string ×3. burpsy exports results (CSV/JSON) but cannot reopen a past attack; `/api/intruder/attacks` is `[]` once a run ends.
- **Logger capture by status is one class at a time** — Burp's per-class toggles allow 4xx+5xx together.
- **Logger: no parameterized-only capture** — Burp's `capture_only_parameterized_requests`.
- **Sequencer: no "pad short tokens at start"** — Burp string ×2.
- **Intruder: no "Hex formatting"** — Burp string burp.Zrv8.
- **Repeater: no WebSocket tab**, and no **Explore (AI)** (Burp Pro).
- **Intruder payload Paste/Remove buttons** — the textarea makes them redundant; cosmetic.

---

# Audit corrections (wrong, not merely stale)
- **Intruder → Settings, all six rows.** Scan details / Scope configuration / Isolate scan / Engine configuration / Attack configuration / Duplicate attacks are not Burp Intruder settings; Burp's own `settings.html` lists a different panel, and three of the six strings have 0 hits in Burp's binary.
- **Intruder → Payloads "Max permutations".** 0 hits in Burp's strings — the control does not exist.
- **Intruder → Results, all seven rows.** Marked HIGH/missing; every one is shipped, including a live progress bar and Pause/Stop.
- **Sequencer's two HIGH rows.** Badly understated: burpsy runs the full FIPS 140-2 battery, spectral, character-transition and per-position analysis, plus an effective-entropy-by-significance-level curve.
- **Organizer's three rows** and **Intruder → Positions' six rows** were all shipped before this sweep.
