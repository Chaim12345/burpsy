# Task Breakdown — burpsy Issue Closure
## Overview
- **Total Phases**: 6
- **Total Tasks (open issues)**: 126
- **Tracking Mode**: GITHUB_STANDARD
- **Repo**: Chaim12345/burpsy
- **Worktree**: /root/burpsy-issue-sweep (branch issue-sweep)

## S.U.P.E.R Design Constraints
- **S**: Each fix scoped to one tool/page/endpoint
- **U**: API data flows server → JSON → React; no reverse deps
- **P**: Wire shapes defined in `burpsy-go/internal/web/*.go` before UI consumes
- **E**: No hardcoded paths; config via existing settings store
- **R**: Tool modules replaceable without touching core

## Testing & Governance Constraints
- Go tests (`*_test.go`) for every backend change
- React tests (`*.test.ts`) for every UI behavior change
- Update `.beads/issues.jsonl` status to closed with close_reason citing commit hash
- Update AGENTS.md/CLAUDE.md only if a durable rule emerges

## Phase 1: Security & Scope Foundation
**Goal**: Close 11 issues in this area
| # | Issue ID | Priority | Title |
|:--|:---------|:---------|:------|
| 1 | burpsy-react-ui-cj7x | P0 | scope: MayContainHost allows a host matching no include rule, so Repea |
| 2 | burpsy-react-ui-oco4 | P0 | Scanner & scope: config parity and re-triage |
| 3 | burpsy-react-ui-5j4i | P1 | scope: no 'Drop all out-of-scope requests' — burpsy will still issue r |
| 4 | burpsy-react-ui-k5l | P1 | scope: an existing rule cannot be edited — only removed and retyped |
| 5 | burpsy-react-ui-so3 | P1 | session: rules have no tools scope, so a rule cannot be restricted to  |
| 6 | burpsy-react-ui-1xb | P2 | scope: a rule cannot be disabled without deleting it |
| 7 | burpsy-react-ui-7nh2 | P2 | session: rules have no URL scope (suite scope / custom URL path-port-p |
| 8 | burpsy-react-ui-9hip | P2 | session: rules have no parameter scope — cannot restrict a rule to req |
| 9 | burpsy-react-ui-c09 | P2 | ui: Scope advanced scope control and save-to-library absent |
| 10 | burpsy-react-ui-dao | P2 | scope: no Paste URL and no load-from-file for bulk scope entry |
| 11 | burpsy-react-ui-rfgs | P2 | match & replace: no 'Only apply to in-scope items' toggle, and per-rul |

## Phase 2: Intruder Parity
**Goal**: Close 16 issues in this area
| # | Issue ID | Priority | Title |
|:--|:---------|:---------|:------|
| 1 | burpsy-react-ui-i4fa | P0 | Intruder: attack engine, positions, payloads and results parity |
| 2 | burpsy-react-ui-016 | P1 | intruder: payload files can only be loaded from a path on the burpsy s |
| 3 | burpsy-react-ui-79u | P1 | intruder: a result cannot be sent to Repeater or Comparer — the Result |
| 4 | burpsy-react-ui-hi8 | P1 | collaborator: no "Insert Collaborator payload" action in Repeater or I |
| 5 | burpsy-react-ui-irt | P1 | intruder: Grep - match takes one expression and reports a boolean, not |
| 6 | burpsy-react-ui-kal | P1 | intruder: no payload wordlists at all — 0 of Burp's 48, and the fix is |
| 7 | burpsy-react-ui-n39 | P1 | intruder: a network failure is never retried — no retry count and no p |
| 8 | burpsy-react-ui-v34 | P1 | intruder: no Make unmodified baseline request, so no attack has a base |
| 9 | burpsy-react-ui-ztuu | P1 | intruder: no Recursive grep payload type — a payload cannot be derived |
| 10 | burpsy-react-ui-2g13 | P2 | intruder: 9 payload generator types absent — character substitution, c |
| 11 | burpsy-react-ui-8cbc | P2 | intruder: no 'URL-encode these characters' payload encoding — the defa |
| 12 | burpsy-react-ui-8f2 | P2 | intruder: no Auto-pause — an attack cannot stop itself when an express |
| 13 | burpsy-react-ui-c7w6 | P2 | intruder: results table lacks Time-of-day, Cookies, Comment and a Time |
| 14 | burpsy-react-ui-sn3j | P2 | session: cookie-jar monitored-tool set is hardcoded to Proxy — cannot  |
| 15 | burpsy-react-ui-tirx | P2 | intruder: no redirection handling — the attack never follows a 3xx and |
| 16 | burpsy-react-ui-fmxv | P2 | intruder: attack settings absent — Set Connection: close header, denia |

## Phase 3: Sequencer Parity
**Goal**: Close 15 issues in this area
| # | Issue ID | Priority | Title |
|:--|:---------|:---------|:------|
| 1 | burpsy-react-ui-3f3 | P1 | sequencer: FIPS tests run over the flattened bit stream, not per bit p |
| 2 | burpsy-react-ui-3fr | P1 | ui: Issues, Organizer, Content discovery and Dashboard tables have no  |
| 3 | burpsy-react-ui-d2g | P1 | sequencer: character transition, spectral, correlation and compression |
| 4 | burpsy-react-ui-fhp | P1 | sequencer: no "Send to Sequencer" action exists, so every capture star |
| 5 | burpsy-react-ui-vh0p | P1 | Sequencer: randomness battery completeness |
| 6 | burpsy-react-ui-3sq | P2 | sequencer: chi-square, serial-correlation, Monte-Carlo-pi and duplicat |
| 7 | burpsy-react-ui-5kx | P2 | sequencer: a live capture cannot be paused, and captured tokens cannot |
| 8 | burpsy-react-ui-6t8 | P2 | sequencer: token location is free-text only, with no picker over the r |
| 9 | burpsy-react-ui-9t1 | P2 | sequencer: live capture has no thread/concurrency control — only a per |
| 10 | burpsy-react-ui-boq | P2 | sequencer: no significance level and no effective-entropy chart — entr |
| 11 | burpsy-react-ui-i4u | P2 | sequencer: no token-handling settings — short tokens cannot be padded  |
| 12 | burpsy-react-ui-qpl | P2 | sequencer: no Auto-analyze — the battery is never re-run periodically  |
| 13 | burpsy-react-ui-rcs | P2 | sequencer: no 'ignore tokens whose length deviates by X characters' ca |
| 14 | burpsy-react-ui-ts3v | P2 | sequencer: Manual load has no load-from-file — a token sample can only |
| 15 | burpsy-react-ui-vhs0 | P2 | sequencer: live capture capped at 5000 tokens, below Burp's 20,000 FIP |

## Phase 4: Session & Match/Replace
**Goal**: Close 14 issues in this area
| # | Issue ID | Priority | Title |
|:--|:---------|:---------|:------|
| 1 | burpsy-react-ui-a09g | P1 | Session handling & Match/Replace parity |
| 2 | burpsy-react-ui-ayi | P1 | session: a rule can only replay a macro on invalid session — 8 of Burp |
| 3 | burpsy-react-ui-c05 | P1 | history: original message bytes are not retained, so a Match & Replace |
| 4 | burpsy-react-ui-dkb | P1 | session: the cookie jar is read-only — no way to edit, remove or empty |
| 5 | burpsy-react-ui-escl | P1 | session: cannot record a macro from Proxy history — macro steps are ha |
| 6 | burpsy-react-ui-7zdm | P2 | session: no Test macro dry-run showing each step's request/response, c |
| 7 | burpsy-react-ui-9prk | P2 | session: validity check has no regex/case-sensitive matching and no re |
| 8 | burpsy-react-ui-d18r | P2 | session: cookie jar shows only host/name/value — no path, domain, expi |
| 9 | burpsy-react-ui-e23c | P2 | session: no automatic macro parameter analysis / Re-analyze — every cr |
| 10 | burpsy-react-ui-js5y | P2 | ui: no 'Show response in browser' and no 'Request in browser (original |
| 11 | burpsy-react-ui-n29 | P2 | session: no session-handling tracer — nothing shows which rules and ac |
| 12 | burpsy-react-ui-ruw | P2 | ui: Match & Replace original/auto-modified message preview absent |
| 13 | burpsy-react-ui-t94i | P2 | ui: message-editor tabs cannot be shown/hidden/reordered and Headers/C |
| 14 | burpsy-react-ui-us12 | P2 | session: cannot validate only after a set number of requests (no valid |

## Phase 5: Core Tools (Logger/History/Scanner/Sitemap/Dashboard)
**Goal**: Close 31 issues in this area
| # | Issue ID | Priority | Title |
|:--|:---------|:---------|:------|
| 1 | burpsy-react-ui-mrjw | P0 | Logger & history: message viewer, search wiring and unified traffic lo |
| 2 | burpsy-react-ui-10e | P1 | site map: nothing can be deleted from the map — /api/sitemap is read-o |
| 3 | burpsy-react-ui-36d | P1 | site map: no filter bar — substring match on path is the only filter |
| 4 | burpsy-react-ui-49g | P1 | ui: Highlight and Add comment are missing from the row context menu, a |
| 5 | burpsy-react-ui-6dt | P1 | logger: proxy traffic is excluded, so the tool log is not a unified tr |
| 6 | burpsy-react-ui-bc2 | P1 | ui: Ctrl+R reloads the browser on every table page, including HTTP his |
| 7 | burpsy-react-ui-dpk | P1 | site map: tree rows have no context menu, so no action can be aimed at |
| 8 | burpsy-react-ui-e2j6 | P1 | dashboard: 'Crawl and audit' and 'API-only scan' scan types are disabl |
| 9 | burpsy-react-ui-f3k | P1 | dashboard: New scan takes one seed URL though the engine and the site- |
| 10 | burpsy-react-ui-i18 | P1 | dashboard: no Issue activity feed — findings appear only as aggregate  |
| 11 | burpsy-react-ui-r6q | P1 | dashboard: a task can only be cancelled — no rename, delete, scan-agai |
| 12 | burpsy-react-ui-vs9k | P1 | ui: no suite-wide Search dialog — search is per-tool only, no cross-to |
| 13 | burpsy-react-ui-4d5c | P2 | scanner: Issues filter is single-select — severity and confidence are  |
| 14 | burpsy-react-ui-5k4 | P2 | wshistory: no filter surface at all — not just Bambda |
| 15 | burpsy-react-ui-5q8u | P2 | intercept: held messages cannot be annotated or highlighted — no Comme |
| 16 | burpsy-react-ui-6a2l | P2 | organizer: filter lacks search-term (regex/case/negative), file-extens |
| 17 | burpsy-react-ui-8gw | P2 | ui: Dashboard pause/resume and listener-status controls absent |
| 18 | burpsy-react-ui-8r6 | P2 | issues: report export cannot be filtered — always the whole finding st |
| 19 | burpsy-react-ui-a13 | P2 | scan launch: no pre-scan filter step to drop duplicates, static assets |
| 20 | burpsy-react-ui-he81 | P2 | history: no Listener port column — multiple listeners are indistinguis |
| 21 | burpsy-react-ui-hmp1 | P2 | history: no custom columns (Bambda/Montoya script-defined column) |
| 22 | burpsy-react-ui-i3l | P2 | organizer: cannot show a saved exchange's request and response — only  |
| 23 | burpsy-react-ui-ldfk | P2 | organizer: no originating-Tool column and no filter-by-tool |
| 24 | burpsy-react-ui-mr4p | P2 | history: no IP column (destination server IP address) |
| 25 | burpsy-react-ui-n10e | P2 | history: no Edited column — an intercept/match-replace modified exchan |
| 26 | burpsy-react-ui-r6li | P2 | history: no Delete items or Clear — capture rows cannot be removed fro |
| 27 | burpsy-react-ui-uxi | P2 | ui: Dashboard telemetry (task throughput / bytes / requests) absent |
| 28 | burpsy-react-ui-voc | P2 | dashboard: event feed has no clear action and is capped at 12 rows |
| 29 | burpsy-react-ui-amu | P2 | ui: no 'Add to site map' action — the site map is populated only by ob |
| 30 | burpsy-react-ui-jcdm | P2 | history: Time is one total duration — no start/end response-timer (TTF |
| 31 | burpsy-react-ui-sf8o | P2 | wshistory: frame table has no Edited / TLS / Notes / Listener-port / W |

## Phase 6: UI Shell, Editor & Extensibility
**Goal**: Close 39 issues in this area
| # | Issue ID | Priority | Title |
|:--|:---------|:---------|:------|
| 1 | burpsy-react-ui-takx | P0 | Proxy & proxy settings: listener config and response-modification pari |
| 2 | burpsy-react-ui-akv | P1 | intercept: the target host/port/TLS of a held request cannot be edited |
| 3 | burpsy-react-ui-n7n | P1 | ui: the Render view does not render image responses, only HTML |
| 4 | burpsy-react-ui-srzn | P1 | Cross-tool UI shell: search, extender hooks, context menus and attenti |
| 5 | burpsy-react-ui-ww5 | P1 | extender: plugin-registered context-menu items and editor tabs never a |
| 6 | burpsy-react-ui-xvo | P1 | ui: tool tabs never signal attention — a held intercepted request is i |
| 7 | burpsy-react-ui-1s07 | P2 | ui: no Engagement tools 'Find comments' / 'Find scripts' / 'Find refer |
| 8 | burpsy-react-ui-446 | P2 | ui: no request/response layout switcher — split orientation is hardcod |
| 9 | burpsy-react-ui-4qqz | P2 | ui: no 'Record an issue' — a request/response pair cannot be manually  |
| 10 | burpsy-react-ui-6ex | P2 | repeater: no WebSocket messages in Repeater — a frame cannot be sent,  |
| 11 | burpsy-react-ui-6fq | P2 | ui: message-editor syntax colouring stops at the headers — bodies are  |
| 12 | burpsy-react-ui-6s2 | P2 | ui: Proxy settings miscellaneous and web-interface sections absent |
| 13 | burpsy-react-ui-745 | P2 | repeater: the Protocol override cannot force HTTP/2 — only auto or for |
| 14 | burpsy-react-ui-7bd | P2 | settings: no font-size or UI-scaling control — editor text is hardcode |
| 15 | burpsy-react-ui-7vy | P2 | proxy settings: the interception state at startup cannot be configured |
| 16 | burpsy-react-ui-8o6 | P2 | collaborator: interaction table has no protocol filter, search, annota |
| 17 | burpsy-react-ui-b2nt | P2 | ui: convert-selection offers only key-char URL/HTML/Base64 — no all-ch |
| 18 | burpsy-react-ui-c6y | P2 | proxy settings: TLS pass-through is built but lives on the Settings pa |
| 19 | burpsy-react-ui-ce8 | P2 | ui: no 'paste URL as request' — a new Repeater tab always starts from  |
| 20 | burpsy-react-ui-f6a | P2 | settings: no search across settings and no category tree — 20 sections |
| 21 | burpsy-react-ui-j7t | P2 | certificate: the CA cannot be regenerated from the console — only impo |
| 22 | burpsy-react-ui-js1 | P2 | ui: no 'URL-encode as you type' mode in the message editor |
| 23 | burpsy-react-ui-k3a7 | P2 | ui: no 'Compare site maps' action — Comparer works only on two message |
| 24 | burpsy-react-ui-ku62 | P2 | decoder: no Octal or Binary encode/decode function — 2 of Burp's 8 cod |
| 25 | burpsy-react-ui-l7xj | P2 | ui: convert-selection on a read-only message shows no result dialog (B |
| 26 | burpsy-react-ui-luu3 | P2 | ui: Inspector selection has no code-point (decimal/hex) view — cannot  |
| 27 | burpsy-react-ui-mem3 | P2 | ui: table columns cannot be reordered by drag (no columnOrder in Virtu |
| 28 | burpsy-react-ui-mwq | P2 | ui: Comparer has no word-level diff mode |
| 29 | burpsy-react-ui-p836 | P2 | ui: no character-set control for message body display (auto / platform |
| 30 | burpsy-react-ui-sel6 | P2 | settings.network: platform authentication supports only Basic and Dige |
| 31 | burpsy-react-ui-ufn | P2 | comparer: no hex view of the compared items |
| 32 | burpsy-react-ui-v8q | P2 | collaborator: mints one payload per click, with no batch generation an |
| 33 | burpsy-react-ui-whr | P2 | ui: no hide-headers toggle in the message editor (and Settings' 'Unint |
| 34 | burpsy-react-ui-wkkz | P2 | extender: no BApp Store and no Java/Python/Ruby (Montoya) extension mo |
| 35 | burpsy-react-ui-wv5 | P2 | ui: 'Change body encoding' only toggles chunked framing — no form-urle |
| 36 | burpsy-react-ui-yy2 | P2 | comparer: only two overwritable slots — no item tables, so each send-t |
| 37 | burpsy-react-ui-adrh | P2 | decoder: transforms apply to the whole input only — no per-selection t |
| 38 | burpsy-react-ui-fkj | P2 | repeater: tab strip has no scrolling/wrapped view toggle, no drag-reor |
| 39 | burpsy-react-ui-wvcl | P2 | ui: no 'Show details in new window' — items are only shown in the page |

