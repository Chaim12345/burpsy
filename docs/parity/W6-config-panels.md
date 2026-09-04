# W6 — Burp's ~90 Top-Level Config Panels vs burpsy

Baseline (this worktree): see BASELINE section below.
Reference corpus: `/root/burp-re/out/strings/map_root.tsv` (Burp 2026.7.1 teardown).
Taxonomy: `/root/burpsy-parity/TAXONOMY.md` (six states, cited per RULES 1-8).

Already settled by prior work — SKIPPED here, not recounted:
- `configPanelUpstreamProxyServers`, `configPanelSocksProxy` — STATE 4 (conditionally),
  merged into `UpstreamProxySection` at `settings.tsx:1448`, honest wired/attached/persisted
  disclosure at `settings.tsx:1610-1624`.
- `configPanelPlatformAuthentication` — STATE 4 at `settings.network.tsx:44`, persistence
  undisclosed in the UI.

## BASELINE

```
$ git rev-parse --short HEAD
9194df6
$ git status --short --branch
## orchestry/tsk_ME-uK_h/parity-w6-enumerate-burp-s-90-top-level-  (clean, 0 changed files)
```
Worktree: `/root/burpsy-react-ui/.orchestry/workspaces/tsk_ME-uK_h` (linked worktree of `burpsy-react-ui`; production code is under `burpsy-go/`). READ-ONLY — no production file was edited to produce this report.

## THE COLLAPSE RULE (denominator derivation, fully reproducible)

Start: 134 distinct `configPanel*` identifiers in `map_root.tsv` (135 raw occurrences, 1 duplicate
row `configPanelClosingBehavior` — matches `verified_configpanel_count`).

**Step 1 — remove leaf widgets by suffix.** A leaf widget is a control INSIDE a panel
(a table, textfield, checkbox, button, combo, radio, label, or the settings-gear icon), not
a panel itself. Exact-suffix match, case-sensitive, against:
`Table TextField ToggleCheckBox CheckBox Checkbox AddButton RemoveButton DeleteBtn EditBtn NewBtn ComboBox Radio Label Cog IconButton`.

```
$ grep -o 'configPanel[A-Za-z0-9_]*' map_root.tsv | sort -u > configpanel_unique.txt   # 134 lines
$ grep -E '(Table|TextField|ToggleCheckBox|CheckBox|Checkbox|AddButton|RemoveButton|DeleteBtn|EditBtn|NewBtn|ComboBox|Radio|Label|Cog|IconButton)$' configpanel_unique.txt
```
Result: **25** leaf widgets (prior docs said 26 — I recount 25; the discrepancy is one
identifier, `configPanelIntruderSettingsGrepExtractAdd`, which ends in `Add` not `AddButton`
and I instead grouped it semantically in Step 3, not by suffix — see below. Net effect on the
final denominator is the same either way since it's absorbed downstream.)
Leaving **109** panel candidates.

**Step 2 — mechanical prefix collapse.** For each of the 109 candidates, if another candidate
in the same 109 is a strict string-prefix of it, the longer one is a documented SUB-CONTROL of
the shorter one's panel (e.g. `configPanelProxyMessageDisplayEditedReq` is one of nine tabs
inside the single `configPanelProxyMessageDisplay` panel), not a separate panel. Script: for
every c in candidates, parent(c) = the longest other candidate p such that c.startswith(p);
c is top-level iff parent(c) is None.

Result: **95** top-level, **14** absorbed as documented sub-controls of 5 parents:
`configPanelHotkeys` (+1: `HotkeysSettingsPanel`), `configPanelProxyMessageDisplay` (+9: the
Edited/Modified/Original × Req/Res/Ws grid), `configPanelProxyMiscellaneous` (+2),
`configPanelProxyTlsPassThrough` (+1), `configPanelRepeaterStreamingResponses` (+1).

**Step 3 — manual semantic collapse (documented, not mechanical).** Two clusters share a
common multi-segment prefix denoting ONE settings screen but have NO bare parent identifier
in the corpus, so Step 2's rule doesn't catch them:
- `configPanelIntruderPayloadSettings{NullCount,NumbersBaseHex,NumbersFrom,NumbersMaxIntegerDigits,NumbersMinIntegerDigits,NumbersTo,RecursiveGrepList}`
  (7 identifiers) → **1** panel: Intruder's built-in payload-generator settings (Numbers /
  Null generators + recursive grep list), reached from the attack config dialog.
- `configPanelIntruderSettingsGrepExtract{Add,EndAtDelimiter,StartAfterExpression}`
  (3 identifiers, including the one suffix-mismatch from Step 1) → **1** panel: the
  grep-extract rule editor.
This removes 8 more entries: **95 − 8 = 87**.

**Step 4 — structural chrome, not screens.** `configPanelTitle` and `configPanelDescription`
survive Steps 1-3 as top-level (no other candidate is their prefix), but both read as generic
per-panel template chrome (every settings screen has a title and a description string), not a
distinct settings screen in their own right. I exclude these 2 from the panel-mapping
denominator, flagged explicitly rather than silently dropped: **87 − 2 = 85**.

**FINAL DENOMINATOR: 85 top-level config panels.** This is lower than the "~90" estimate in
the task brief; I show the rule rather than force the number. If Step 4 is rejected (Title/
Description count as panels), the denominator is 87. If Step 3's manual clustering is rejected
in favor of pure mechanical Step 2, the denominator is 95. All three numbers and their exact
derivation are reproducible from the commands above — pick the one that matches your definition
of "panel"; I use **85** for the table below and say so at every total.


---

# W6b — THE MAPPING TABLE (analyst W6b, continuation pass)

The predecessor's derivation above establishes the DENOMINATOR (85). This pass supplies the
NUMERATOR: one row per panel, with a TAXONOMY state.

## BASELINE (W6b pass)

```
$ git rev-parse --short HEAD
638c480
$ git status --short --branch
## orchestry/tsk_KBUxW7m/auto-cto-burp-parity-gap-analysis-measur
(no modified files — clean tree)
```
Worktree: `/root/burpsy-react-ui/.orchestry/workspaces/tsk_KBUxW7m` (linked worktree of
`burpsy-react-ui`). All `file:line` citations below are relative to the repo root and were
read at `638c480` with a clean tree. READ-ONLY: no production file was edited.

**Denominator re-derived independently by W6b** (RULE 2 — I did not take 85 on trust):
```
$ grep -o 'configPanel[A-Za-z0-9_]*' /root/burp-re/out/strings/map_root.tsv | sort -u | wc -l
134
$ python3 <steps 1-4 of the collapse rule above>
leaf 25   cand 109   top 95   -> step3 -8 = 87   -> step4 -2 = 85
FINAL 85
```
Reproduces exactly. The 85-name list is the one enumerated in the table below; every row
name is a literal identifier from `map_root.tsv` (or a documented Step-3 cluster, marked `*`).

## READING THE STATE COLUMN IN THIS TABLE

The unit being measured is **a Burp config panel** — a settings screen an operator opens to
change behaviour. So a row is STATE 0 when burpsy has **no configuration surface** for that
knob, *even where the underlying capability exists and works*. Where that distinction bites,
the note says so explicitly (e.g. the message-editor views exist and are excellent; what is
absent is a panel that lets you turn them on and off). Per TAXONOMY RULE 7 those are
CAPABILITY GAPS, not defects, and I mark them `[cap-gap]`.

`4-c` = STATE 4 with a caveat recorded in the note (behaviour observed or covered by a green
package test, but the panel is narrower than Burp's).

All paths are relative to repo root; the React tree is
`burpsy-go/internal/web/ui/src/` — abbreviated **`ui/`** below. Go paths given in full.

> **Counting caveat, added 2026-08-27.** Do not count `[cap-gap]` with an `awk` that reads a single
> field. Several notes contain a literal `|` inside backticked commands — row #80's holds
> `'MinVersion\|CipherSuites'` — so the note splits across fields and a field-7 test misses the
> marker. Counting that way gives 27 cap-gap / 9 candidates; the correct figures are **28 cap-gap /
> 8 candidates**. Join every field after the state column before testing:
>
> ```python
> parts = line.split("|"); state = parts[5].strip().strip("*"); note = "|".join(parts[6:])
> ```
>
> I quoted the broken command to two other agents before catching this.

## THE TABLE — 85 rows

| # | Burp panel identifier | What it configures | burpsy equivalent | State | Note |
|---|---|---|---|---|---|
| 1 | configPanelAi | Burp AI features, key, opt-in | none | 0 | No AI/LLM surface anywhere in the tree. `grep -rEil 'openai\|anthropic\|\bllm\b' internal/ cmd/` → only false positives in `hex-editor.tsx` ("small"), `data.*.ts`. |
| 2 | configPanelAutomaticProjectBackup | Periodic project-file backup | none | 4 | Delivered 2026-08-27 (`f16675c`). `Store.Backup` uses SQLite `VACUUM INTO` — not a file copy, which on a WAL database yields a file of plausible size that opens to a corrupt schema. Schedule kind `backup` plus POST `/api/backup`; retention prunes oldest-first and only files matching the pattern this feature writes. 19 tests, including opening the snapshot and reading a seeded row back. |autosave\|auto.?save' internal/ cmd/` → **0 files**. Persistence exists (`-db`, `internal/persist`) but nothing schedules a copy. |
| 3 | configPanelCharacterSets | Charset used to render message bytes | none | 0 | Editor decodes as UTF-8/latin-1 implicitly; no charset selector. `[cap-gap]` |
| 4 | configPanelClientTlsCertificates | Per-host client certs | `ui/pages/settings.network.tsx:215` (`ClientCertificatesSection`), API `/api/network/client-certs` | 4 | Carried over from prior work (settled). |
| 5 | configPanelClosingBehavior | What Burp does when you close it | none | 0 | Browser console; no process-close dialog. Deliberate. `[cap-gap]` |
| 6 | configPanelCollaboratorServer | Which Collaborator server to use / private server | `-collaborator-server` / `-collaborator-client` flags, `cmd/burpsy/main.go:97-99`; UI is read-only at `ui/pages/collaborator.tsx:63` | 4 | Delivered 2026-08-27 (`65166fd`). POST `/api/collaborator/server` sets it without a restart; refuses with 409 once a channel has registered a domain, because payload addresses already referenced by findings would be orphaned. `riskScope` in the route manifest. |
| 7 | configPanelComparer | Comparer display options | `ui/pages/comparer.tsx:238` — tool exists, no settings panel | 0 | `[cap-gap]` The tool works; the *config panel* has no counterpart. |
| 8 | configPanelConfigurationLibrary | Named saved configurations | `/api/config/export` + `/api/config/import`, `internal/web/api_config.go:43`; menu at `ui/src/app.tsx:448` | 4-c | **Loud caveat:** the bundle carries exactly three subsystems — scope, intercept lists, session rules (`api_config.go:48-67`). Network settings, proxy options, match/replace rules, resource pools, schedules, scanner config, platform auth and client certs are all **silently omitted** from a file named `burpsy-config.json`. Nothing in the UI says so. |
| 9 | configPanelCookieJar | Which tools update the jar; view/edit cookies | `ui/pages/session.tsx:1005` | 4-c | View only. The jar is read (`/api/session/cookies`) and honestly reports "not attached"/"attached and empty". No per-tool monitor selection, no add/edit/delete. |
| 10 | configPanelCustomCACertificates | Import your own CA cert+key | `internal/proxy/proxy.go:271` `LoadOrGenerateCA` reads `ca.crt`/`ca.key` from `-ca-dir` (`cmd/burpsy/main.go:46`) | 4 | Delivered 2026-08-27 (`08d55d8`). POST `/api/proxy/ca/import` validates the pair before replacing anything, empties the per-host leaf cache (every cached leaf was signed by the CA being replaced), and `/ca.crt` now serves whichever CA is in force. `riskCredential`. |
| 11 | configPanelDNSLookupPolicy | System vs custom resolver, DNS timeout | `ui/pages/settings.tsx:919`; wire `internal/web/api_network.go:92-105`; consumed `internal/sender/network.go:515-517` | 4 | Proof: `go test ./internal/sender/...` → `ok …/internal/sender 4.619s`. |
| 12 | configPanelDefaultInspectorPanelState | Whether Inspector sections start open | `ui/lib/store.ts:18,103,161,178,328`; read `ui/ui/inspector.tsx:475,550`, written `:477`, applied `:769` | 4 | **RETRACTED 2026-08-27 — this row was a false positive, and so was the "flagship finding" framing built on it.** The panel is fully wired: `SettingsPanel` (`inspector.tsx:466-520`) offers "Sections open by default / Start collapsed" radios, and `isOpen` at `:769` reads the value — `section.id in toggled ? toggled[section.id] : panelState === "auto" && section.rows.length > 0`. `inspectorDock` is wired too: radios at `:505,509`, and it drives a className at `:784`. <br><br>**Root cause of the error.** `ui/ui/inspector.tsx` contained a single literal NUL byte, at line 190, used as a field delimiter in `rowFingerprint`. `grep` (ugrep on this machine) therefore classified the whole 826-line file as binary and **silently reported zero matches in it, exiting 0** — no warning, no "binary file matches" line. Every grep in this row, including the one quoted as evidence, was blind to the one file that contained the answer. The `density` positive control did not catch it because `density`'s readers live in files grep *could* read, so the control confirmed the method worked in general while the specific target stayed invisible. Fixed by writing the delimiters as `\u0000`/`\u0001` escapes; the file is now greppable and the behaviour is unchanged. Verified: exactly 1 of 1102 tracked source files was affected. |
| 13 | configPanelExtensionsSettings | Extension load list, folders, options | `ui/pages/extensions.tsx:296` + `/api/extensions/{load,unload}`; allowlist gate `-plugins` at `cmd/burpsy/main.go:70` | 4-c | Load/unload from the UI works, but only within a CLI allowlist. No extension-folder or per-extension option panel. Protocol gap is self-documented at `internal/extension/protocol.go:19-33` (3-of-13). `[cap-gap]` |
| 14 | configPanelHostnameResolution | Static host→address overrides | `ui/pages/settings.tsx:836`; `internal/sender/network.go:418-439` | 4 | Editable table with add/enable/remove; draft-then-Save with a dirty badge. |
| 15 | configPanelHotkeys | Rebind keyboard shortcuts | `ui/pages/settings.tsx:1239` (`HotkeysSection`) | 4 | Search, per-row rebind, "Reset all", and an honest reassignable/fixed/changed count. Browser-local (`useKeymap`), disclosed in the section detail. |
| 16 | configPanelHtmlRendering | Enable/disable HTML rendering of responses | Render view exists (`ui/ui/editor.tsx:186`, sandboxed iframe), no config | 0 | `[cap-gap]` Render tab appears conditionally for HTML responses; nothing lets you disable it. |
| 17 | configPanelHttp1 | HTTP/1 connection behaviour | Per-send pin only: `protocol_preference:"http1"`, `internal/web/repeater_options.go:29`; UI `ui/pages/repeater.tsx:509` | 4-c | Reachable only as a Repeater per-send override, not as a global panel. No HTTP/1 header-normalisation knobs. |
| 18 | configPanelHttp2 | Enable HTTP/2, h2 behaviour | `internal/http2`, `/api/http2/program`; report at `ui/pages/settings.tsx:198` (`ProtocolSection`) | 4-c | The Protocols section is a **report plus a probe**, not a switch: it shows what was negotiated and lets you probe an authority. There is no "use HTTP/2" toggle. `internal/proxy` counts `relayed_http2` responses it declines to rewrite (`ui/pages/proxysettings.tsx:135`). |
| 19 | configPanelHttpMessageDisplay | Font, word wrap, non-printables in the editor | none | 0 | `[cap-gap]` |
| 20 | configPanelHttpMessageSearch | Search behaviour in message editors | Search exists (`ui/ui/editor.tsx:157` `openSearchPanel`), no config | 0 | `[cap-gap]` |
| 21 | configPanelHttpRedirections | Which redirects to follow, hop budget | `ui/pages/settings.tsx:1012`; `internal/web/api_network.go:114-124`; `internal/sender/network.go:380-384` | 4 | Four modes (never/on_site/in_scope/always) + max hops. `sender.RedirectAlways` is scope-bounded — a documented divergence from Burp's "anywhere" (`internal/web/repeater_options.go:26-27`). `[cap-gap]` |
| 22 | configPanelInspectorWidgets | Which Inspector widgets are shown | `ui/ui/inspector.tsx` builds all sections unconditionally | 0 | `[cap-gap]` Inspector itself is full (start line, headers, cookies, query params, body params, editable in place). No widget-selection panel. |
| 23 | configPanelIntruderAutomaticPayloadPlacement | Which position families get auto-marked | `internal/intruder/points.go:82` `DefaultPointConfig`; API `internal/web/api_tools.go:307`; UI `ui/pages/intruder.tsx:356` | 4-c | Reached from the UI, but exposed as a **binary** (`req.All` at `api_tools.go:327`) — Burp's per-family checkboxes (param names, path folders, headers, cookies…) collapse to one all/default switch. |
| 24 | configPanelIntruderBehaviourWhenClosingAttacks | Prompt/discard on closing an attack tab | none | 0 | burpsy Intruder has no attack tabs to close. `[cap-gap]` |
| 25 | configPanelIntruderDefaultPanelState | Default open/closed panels in Intruder | none | 0 | `[cap-gap]` |
| 26 | configPanelIntruderNewTabConfiguration | What a new Intruder tab inherits | none | 0 | Single-attack page, no tab model. `[cap-gap]` |
| 27 | configPanelIntruderPayloadListLocation | Directory Burp reads payload lists from | `internal/intruder/intruder.go:370` `GenerateFromFile` | 4-c | Capability delivered 2026-08-27 by SnowyMink (`0def353`, `7f5b3b1`): payload types reach the engine via `PayloadSource.Resolve` (`internal/intruder/payload.go:280`) from `internal/web/api_tools.go:566`. **Caveat, verified 2026-08-27:** `PayloadGenerator.GenerateFromFile` is still called only from `intruder_test.go` — the delivered path is different code, so the generator now sits beside it as a second, unreachable implementation. Filed as a defect (dead duplicate), not a parity gap. |
| 28 | configPanelIntruderPayloadSettings\* (Step-3 cluster: Numbers from/to/base-hex/min-max digits, Null count, recursive-grep list) | Built-in payload generators | `internal/intruder/intruder.go:346-387` `PayloadGenerator` (`GenerateNumbers`, `GenerateFromFile`, `GenerateCustom`) | 4-c | As #27. `GenerateNumbers` has test-only callers and `GenerateCustom` has **zero references anywhere**, tests included. Note `intruder_test.go:216` asserts an inverted-range fix on a function production never calls, so that protection does not apply to the live path — whether `PayloadSource.Resolve` handles an inverted range is currently unasserted. |NewPayloadGenerator\|GenerateCustom' --include=*.go .` matches **only** `internal/intruder/intruder_test.go` (lines 27-29, 41-62, 212-216). The whole generator subsystem — including a fix for an inverted-range panic (`intruder_test.go:212`) — has no production caller. The UI takes payloads as pasted text only (`ui/pages/intruder.tsx:345` `payloadTexts`). There is no Null generator and no recursive-grep payload source at all. |
| 29 | configPanelIntruderSettingsGrepExtract\* (Step-3 cluster: Add, start-after-expression, end-at-delimiter) | Grep-extract rule editor | `ui/pages/intruder.tsx:755`; engine `internal/intruder/engine.go:207,228,348` | 4-c | Start-marker only. The field hint is literally *"Captures the text after this marker."* — Burp's **end-at-delimiter** and max-length arms have no counterpart. One rule, not a rule list ("Add" has no equivalent). |
| 30 | configPanelJavaEnvironment | JVM/jar location for Java extensions | none | 0 | burpsy's extension protocol is not the JVM. Documented divergence at `internal/extension/protocol.go:19-33`. `[cap-gap]` |
| 31 | configPanelJavaTlsOptions | JVM TLS switches | none | 0 | `[cap-gap]` |
| 32 | configPanelLogging | Which tools' traffic is logged | `ui/pages/logger.tsx:76,111-119` (`useSetToolLogCapture`); `internal/toollog/toollog.go:250-303` (`Capturing`, `SetCapturing`, `Uncaptured`) | 4 | Two-axis (filter axis + capture axis) per tool, added at HEAD `638c480`. The `Uncaptured` counter means a tool that is not capturing says how much it dropped rather than looking idle. No log-to-file arm. |
| 33 | configPanelMacros | Recorded request macros | `ui/pages/session.tsx:881` (Macro steps) + `internal/session` (`MacroStep`), CLI `cmd/burpsy/cli_session.go:143` | 4 | Steps are URL replays; cookies absorbed back into the jar (`internal/session/recovery.go:264-276`). No parameter-derivation or custom-parameter arm. |
| 34 | configPanelMessageEditorRequestViews | Which request views are enabled | Views exist (`ui/ui/editor.tsx:182-205`: Pretty/Raw/Hex/GraphQL/JWT/Params), no config | 0 | `[cap-gap]` Views appear conditionally by content — a deliberate, documented design choice (`editor.tsx:202-205`) that replaces the panel rather than implementing it. |
| 35 | configPanelMessageEditorResponseViews | Which response views are enabled | Same, plus Render | 0 | `[cap-gap]` |
| 36 | configPanelOutOfScopeRequests | Drop / don't-log out-of-scope traffic | Hardcoded: `internal/proxy/proxy.go:833,866,945,977,1169-1171` | 0 | Behaviour matches Burp's default (out-of-scope is not recorded) but is **not configurable**. There is no "drop all out-of-scope requests" switch. `[cap-gap]` |
| 37 | configPanelOverrideUserOptions | Let a project override user-level options | none | 0 | burpsy has no user-vs-project settings split. `[cap-gap]` |
| 38 | configPanelPerformanceFeedback | Send anonymous perf data to PortSwigger | none | 0 | `grep -rEil 'performance.?feedback\|submit.*anonym'` → **0 files**. Correctly absent. |
| 39 | configPanelPlatformAuthentication | Per-host platform (Basic/NTLM/Digest) creds | `ui/pages/settings.network.tsx:44` | 4 | Carried over from prior work (settled). Persistence is undisclosed in the UI. |
| 40 | configPanelProjectBrowserLogging | Log the embedded browser's traffic | none | 0 | `[cap-gap]` |
| 41 | configPanelProjectEmbeddedBrowser | Project-scoped embedded-browser settings | `ui/pages/settings.tsx:485` (`DomEngineSection`), set by `-dom` at `cmd/burpsy/main.go:81` | 3 | Read-only report ("Changing it takes a restart"). Honest: it names the flag to pass. No UI path changes the engine. |
| 42 | configPanelProxyContainer | The Proxy-settings tab container itself | `ui/pages/proxysettings.tsx:53` (`ProxySettingsPage`) | 4 | Structural chrome; a Proxy settings screen exists and is routed. |
| 43 | configPanelProxyHistoryLogging | What reaches Proxy history | Hardcoded scope gate, `internal/proxy/proxy.go:866,1169-1171` | 0 | Same finding as #36: correct default, no panel. `[cap-gap]` |
| 44 | configPanelProxyHttpMatchAndReplaceRules | HTTP match/replace rule table | `ui/pages/matchreplace.tsx:190,209`; `/api/tools/rules`, `/api/tools/rules/test`; engine `internal/matchreplace/matchreplace.go:36-95` | 4-c | Wired end to end with a draft-test arm. **Caveat, and it is a good one:** only 5 of 7 targets are implemented — `TargetRequestParamName`/`ParamValue` are no-ops. That was previously a live-traffic corruption bug (a param rule ran as a whole-body rewrite); it is now a proven no-op. Proof run at `638c480`: `go test ./internal/matchreplace/ -run 'Param' -v` → `--- PASS: TestAParamNameRuleDoesNotRewriteUnrelatedParameters`, `--- PASS: TestBothParamTargetsAreNoOpsAndAreIndistinguishable`. The UI does **not** offer the two dead targets (`matchreplace.tsx:17-18`: *"The five targets the Go handler compiles"*), so no decorative control. |
| 45 | configPanelProxyInterception | Master intercept on/off | `/api/intercept/enable`; `ui/pages/intercept.tsx:507`; `internal/intercept/intercept.go:436-474` | 4 | Three states (off / on-with-no-rules / selective) documented at `intercept.go:6,150-157`. |
| 46 | configPanelProxyListeners | Add/edit proxy listeners, bind, redirect | Read-only metrics `ui/pages/settings.tsx:375-386`; bind from `-proxy` at `cmd/burpsy/main.go:39` | 3 | One listener, CLI-set. Settings shows `proxy_bind` as a metric. No add/edit/remove, no invisible-proxy or per-listener redirect. |
| 47 | configPanelProxyMessageDisplay | Proxy-specific editor display (9 sub-tabs collapsed in Step 2) | none | 0 | `[cap-gap]` |
| 48 | configPanelProxyMiscellaneous | HTTP/1.0, Connection:close, strip Proxy-* headers, suppress errors | none | 0 | No misc-proxy panel. `[cap-gap]` |
| 49 | configPanelProxyModificationRules | Response-modification rules | `ui/pages/proxysettings.tsx:19-119`; `internal/proxy/options.go:45-104`; `/api/proxy/options` `internal/web/api_proxyoptions.go:39-99` | 4 | All 6 switches live-applied, validated all-before-any, persisted (`api_proxyoptions.go:92-94`). **Behaviourally instrumented**: the page renders considered/modified/unchanged/skipped-compressed/skipped-not-html/skipped-unframed counters (`proxysettings.tsx:101-113`) and states outright when rules have looked at N responses and changed none. Proof: `go test ./internal/proxy/...` → `ok …/internal/proxy 7.001s`, including `options_scope_test.go` which pins the out-of-scope rewrite asymmetry. This is the best-evidenced row in the table. |
| 50 | configPanelProxyRequestInterceptionRules | Request-direction intercept rules | `ui/pages/intercept.tsx:75-95,228,255`; `/api/intercept/rules/requests`; `internal/intercept/intercept.go:103-133,376` | 4 | Field/category/regex rules, malformed regex refused server-side (`intercept.go:376-378`). |
| 51 | configPanelProxyResponseInterceptionRules | Response-direction intercept rules | Same component, `direction="responses"` | 4 | `intercept.Direction` has exactly two members (`intercept.go:24-28`). |
| 52 | configPanelProxyTlsPassThrough | Hosts relayed without interception | `ui/pages/settings.tsx:394`; `/api/proxy/passthrough`; flags `-tls-passthrough*` `cmd/burpsy/main.go:103-105` | 4 | Add/remove, wildcard `*.` support, and an explicit statement that a passthrough host never appears in history. |
| 53 | configPanelProxyWebSocketInterceptionInScopeOnly | Scope-gate WS interception | none | 4 | Delivered 2026-08-27 (`626ac5f`, `c9b71e1`, `5e23370`). WebSocket frames are genuinely held, edited and dropped — `internal/proxy/ws.go` calls `intercept.Hold` per frame. Control, compressed and fragmented frames are relayed untouched and the panel says so. |WebSocket' internal/intercept/` → **0 hits**. Positive control: the same pattern hits `internal/web/api_events.go`, `internal/proxy/ws.go`, `ui/pages/wshistory.tsx`, `internal/vulnapp/vulnapp_stored_dom.go`. WebSocket traffic is proxied and recorded; it is **never held for interception**. |
| 54 | configPanelProxyWebSocketInterceptionRules | WS intercept rule table | none | 4 | Delivered 2026-08-27 — see #53. Two new intercept directions (`websocket_to_server`, `websocket_to_client`) with their own rule lists. |
| 55 | configPanelProxyWsMatchAndReplaceRules | WS match/replace rules | none | 4 | Delivered 2026-08-27 — see #53. Interception only; WS match/replace remains absent. |
| 56 | configPanelPythonEnvironment | Jython jar location | none | 0 | `[cap-gap]` — same divergence as #30. |
| 57 | configPanelRepeaterConnections | Repeater connection behaviour (protocol, Connection header) | `ui/pages/repeater.tsx:509` (`SendOptionsPanel`); `internal/web/repeater_options.go:23-43` | 4-c | `protocol_preference` and `strip_connection` are per-send overrides, not a global panel. **Deliberate, disclosed omission** at `repeater_options.go:17-19`: no ALPN override, because *"offering it would be a switch that does nothing"* — the right instinct, recorded in the code. `[cap-gap]` |
| 58 | configPanelRepeaterMessageModification | Update Content-Length, normalise line endings | Same panel: `normalize_line_endings`, `update_content_length` (`repeater_options.go:36-42`) | 4 | Validate-all-before-apply contract (`repeater_options.go:48-61`). |
| 59 | configPanelRepeaterRedirects | Repeater redirect policy, cookies on hops | Same panel: `redirect_mode` (`repeater_options.go:26`), `process_cookies` (`:32`) | 4-c | **Disclosed gap** at `repeater_options.go:19-21`: "process cookies in redirections" is deliberately *not* offered as a separate switch because `sender.FollowRedirects` does not replay cookies — *"the honest answer is that the feature does not exist yet, not a checkbox that lies."* Exemplary. `[cap-gap]` |
| 60 | configPanelRepeaterStreamingResponses | Per-Repeater streaming-response handling | none (global only: `ui/pages/settings.tsx:1090`) | 0 | `grep -n 'stream' internal/web/repeater_options.go ui/pages/repeater.tsx` → 0 hits. Repeater inherits the global streaming host list; it cannot be set per tab. `[cap-gap]` |
| 61 | configPanelRepeaterTabView | Repeater tab grouping / view | `ui/lib/store.ts` `repeaterGroups` (persisted, `store.ts:291`); UI `ui/pages/repeater.tsx:42-52,231-286,428-463` | 4 | Create/rename/delete/collapse groups, assign tabs, context menu. Groups are explicitly cosmetic — "grouping must never gate sending or scope" (`store.ts:36-38`). Contrast row #12: this store slice **is** read. |
| 62 | configPanelResourcePools | Named concurrency/throttle pools | `ui/pages/settings.tsx:1829` (`ResourcePoolsSection`), `/api/pools` | 4 | Includes a "What each tool honours" support table (`settings.tsx:1932`) served as data by `GET /api/pools` — it discloses that the crawl loop is sequential so a concurrency ceiling above 1 bounds nothing there. A pool panel that documents where its own promise is not kept. |
| 63 | configPanelRestApi | Burp's own REST API: enable, port, API keys | none | 0 | burpsy *is* an HTTP API, but there is no panel to enable/disable it, bind it, or mint keys. `-web` is the only control (`cmd/burpsy/main.go:40`). Security-relevant: no API-key surface exists. `[cap-gap]` |
| 64 | configPanelRubyEnvironment | JRuby jar location | none | 0 | `[cap-gap]` — same divergence as #30. |
| 65 | configPanelScheduledTasks | Scheduled task list | `ui/pages/settings.tsx:2175` (`ScheduledTasksSection`), `/api/schedules`; `internal/schedule/schedule.go:90-146` | 4 | Named in the code as the Burp panel it implements (`internal/web/api_schedules.go:18`, `settings.tsx:2024`). Refuses an unknown kind naming the registered kinds (`schedule.go:328-330`) and records a missed occurrence with a reason (`schedule.go:579-581`). |
| 66 | configPanelSequencerLiveCaptureOptions | Live-capture request, count, thread/delay | `/api/sequencer/capture`, `internal/web/api_sequencer_capture.go:354-366`; UI `ui/pages/sequencer.tsx:509-565` | 4 | `count`, `location`, `delay_ms`; bounded at `maxCaptureCount = 5000` with the reason recorded (`api_sequencer_capture.go:361-364`). Reports shortfall when a capture ends short (`sequencer.tsx:256`). |
| 67 | configPanelSequencerTokenAnalysis | Which statistical tests run | `ui/pages/sequencer.tsx:80` — FIPS 140-2 bit-level tests, always on, with a coverage string | 0 | `[cap-gap]` Tests run and report; there is no panel to select them. The coverage line is the honest substitute. |
| 68 | configPanelSequencerTokenHandling | How token bytes are decoded before analysis | `ui/pages/sequencer.tsx:382` (`Read token bits as` select, `SEQUENCER_ENCODINGS` + "detect encoding") | 4 | |
| 69 | configPanelServerTlsCertificates | Per-host leaf-cert generation behaviour | `internal/proxy/proxy.go:185` (cache), no config | 0 | Leaf certs are minted automatically from the CA. No panel for hostname/serial/self-signed behaviour. `[cap-gap]` |
| 70 | configPanelSessionHandlingRules | Session-handling rule table | `ui/pages/session.tsx:633` (Login rules), `/api/session/rules`; `internal/session` | 4 | Rules with scope hosts, macro steps, re-login trigger. Included in the config export bundle (`api_config.go:65-67`). |
| 71 | configPanelSocksProxy | SOCKS proxy | `ui/pages/settings.tsx:1448` (`UpstreamProxySection`) | 4 | Carried over from prior work (settled). Merged with upstream HTTP proxy into one section; honest wired/attached/persisted disclosure at `settings.tsx:1610-1624`. |
| 72 | configPanelStatus100Responses | Understand 100-continue / strip Expect | `ui/pages/settings.tsx:1056`; `internal/web/api_network.go:125-135`; consumed `internal/sender/sender.go:241,563,693,1009` | 4 | Three controls, all read on the send path. Section carries a plain-English explanation of why reading past a 100 matters (`settings.tsx:1084`). |
| 73 | configPanelStreamingResponses | Host patterns whose responses stream | `ui/pages/settings.tsx:1090`; `internal/web/api_network.go:136-148`; `internal/sender/sender.go:1010` (`Streaming.isStreaming(host)`) | 4 | |
| 74 | configPanelTableAppearance | Row height / striping / table look | `ui/pages/settings.tsx:1320` ("Table density"), consumed at `ui/ui/table.tsx:38-58` (`useFluidRowHeight`) and `styles.css:1157` | 4 | Two values (comfortable/compact). Verified end-to-end by the positive control in row #12. Browser-local, disclosed. |
| 75 | configPanelTargetScope | Include/exclude scope rules | `ui/pages/scope.tsx:136-215` and `ui/pages/settings.tsx:50` (`ScopeSection`), `/api/scope`; `internal/core` scope | 4 | Host+port+path arms, bulk clear with confirm, and an explicit statement that an empty scope means everything is in scope. |
| 76 | configPanelTaskAutoStart | Whether scheduled tasks auto-start | `internal/web/api_schedules.go:18` + `ui/pages/settings.tsx:2024` name this panel explicitly; runner `internal/schedule/schedule.go:513-581` | 4-c | Folded into #65 rather than given its own screen — a schedule's own enabled/interval fields carry it. There is no separate "start these tasks when the project opens" control because there is no project-open event. `[cap-gap]` |
| 77 | configPanelTasks | The task list / task-level settings | `/api/tasks/{id}/cancel`, `ui/pages/dashboard.tsx:69`; queue view `ui/pages/auditqueue.tsx` | 4-c | Tasks are listed and cancellable; there is no per-task settings panel (Burp's per-task scan configuration / resource pool assignment). |
| 78 | configPanelTemporaryFilesLocation | Where Burp writes temp files | none | 0 | `-capture-dir`/`-db` control durable storage (`cmd/burpsy/main.go:41-42`), not temp files. Nothing configures a temp location. `[cap-gap]` |
| 79 | configPanelTimeouts | Connect / read / total timeouts | `ui/pages/settings.tsx:964`; `internal/web/api_network.go:107-113`; `internal/sender/sender.go:192-194,231,239-241,402,466` | 4 | Note the clamp at `sender.go:192-194`: a connect timeout above the total is lowered to the total, so the panel cannot express an impossible pair. |
| 80 | configPanelTlsNegotiation | TLS versions / cipher suites offered | none | 0 | `grep -n 'MinVersion\|CipherSuites' internal/sender/*.go` → the only `tls.Config` is `sender.go:242` and it sets neither. Go's defaults are used, unconfigurable and undisclosed. `internal/tlsprobe` *analyses* a target's ciphers but does not set burpsy's own. `[cap-gap]` |
| 81 | configPanelUninterestingRequestHeaders | Headers hidden from comparisons/analysis | none | 4 | Delivered 2026-08-27 (`5050ca5`). The Comparer tags differences falling inside a discounted header rather than stripping them, and reports `identical` and `identical_ignoring_uninteresting` separately. Request list empty by default. |
| 82 | configPanelUninterestingResponseHeaders | Same, response side | none | 4 | Delivered 2026-08-27 (`5050ca5`) — see #81. `Set-Cookie` is deliberately NOT a default, against Burp: a rotated or fixated session token can be the finding. |
| 83 | configPanelUpstreamProxyServers | Upstream HTTP proxy rules | `ui/pages/settings.tsx:1448` (`UpstreamProxySection`) | 4 | Carried over from prior work (settled). Per-destination rule table at `settings.tsx:1614`; flags `-upstream-proxy`, `-upstream-proxy-rule` (`cmd/burpsy/main.go:111-113`). |
| 84 | configPanelUserEmbeddedBrowser | User-scoped embedded-browser settings | `ui/pages/settings.tsx:485` (`DomEngineSection`), `-dom` flag | 3 | Same surface as #41; burpsy has no user-vs-project split, so both Burp panels land on one read-only report. |
| 85 | configPanelUserInterface | Theme, look and feel | `ui/pages/settings.tsx:1299` (`AppearanceSection`), `ui/lib/store.ts:119,136,282` | 4 | Theme (light/dark/system, resolved at `store.ts:301`) with a hotkey (`app.tsx:270`). Browser-local, disclosed in the section detail: *"Stored in this browser; it does not travel with the capture."* |

## STATE HISTOGRAM (denominator 85)

| State | Count | Share of 85 |
|---|---|---|
| 0 ABSENT | **36** | 42% |
| 1 STUB | **0** | 0% |
| 2 UNWIRED | **3** | 4% |
| 3 UNREACHABLE (from the UI) | **5** | 6% |
| 4 WIRED | **41** | 48% |
| — of which plain STATE 4 | 29 | 34% |
| — of which STATE 4 with a recorded caveat (`4-c`) | 12 | 14% |
| 5 BROKEN | **0** *(none proven — see NOT DETERMINED)* | 0% |
| **Total** | **85** | 100% |

Row indices per state, so the count is checkable against the table:
- **0:** 1, 2, 3, 5, 7, 16, 19, 20, 22, 24, 25, 26, 30, 31, 34, 35, 36, 37, 38, 40, 43, 47, 48, 53, 54, 55, 56, 60, 63, 64, 67, 69, 78, 80, 81, 82
- **2:** 12, 27, 28
- **3:** 6, 10, 41, 46, 84
- **4 / 4-c:** every remaining row (41 of them)

If the alternative denominators from the predecessor's Step 3/4 are preferred: at **87** add
`configPanelTitle` and `configPanelDescription` as two more STATE 4 rows (both are structural
chrome that `SectionHeading` (`ui/ui/layout.tsx:36`) supplies on every panel) → 43/87 wired,
36/87 absent. At **95** the Step-3 clusters split back into 10 separate identifiers, which
moves 7 rows into STATE 2 and 3 into STATE 4-c → 44/95 wired, 36/95 absent, **9/95 unwired**.
The absent count is stable at 36 under all three definitions; only the wired/unwired split moves.

## WHAT THE DISTRIBUTION MEANS

**Roughly half the panels, and the half that matters most, are real.** The 41 wired rows are
not a thin veneer: proxy response-modification (#49) ships live counters that will tell an
operator "these rules have looked at 412 responses and changed none"; resource pools (#62)
render a support table that admits the crawl loop is sequential so its own concurrency ceiling
bounds nothing; the network group (#11, #14, #21, #72, #73, #79) is a single draft-then-save
document with a dirty badge and a server that validates the whole patch before applying any of
it. Repeater's send-options panel (#57-59) *declines* to render an ALPN switch and a
cookies-on-redirect switch, and says in a code comment why: "offering it would be a switch that
does nothing" and "the honest answer is that the feature does not exist yet, not a checkbox
that lies." Several panels are better-instrumented than Burp's.

**The 36 absences are honest and mostly structural, not hidden.** They cluster into four
groups that say something coherent about what burpsy is: (a) *Burp-the-desktop-app* panels with
no meaning in a browser console — closing behaviour, temp-file location, project backup, perf
feedback, user-vs-project option override (5 rows); (b) the *JVM extension estate* — Java,
Python, Ruby environments and Java TLS options — replaced by a different extension protocol
that documents its own 3-of-13 gap at `internal/extension/protocol.go:19-33` (4 rows); (c) the
*message-editor and Inspector display panels* — 8 rows where the underlying capability is
present and good (Pretty/Raw/Hex/Render/GraphQL/JWT/Params views, a fully editable Inspector)
and only the *configurability* is missing, replaced by conditional auto-display that
`editor.tsx:202-205` argues is better; (d) genuine capability holes, chiefly **WebSocket
interception** (#53, #54, #55 — WS traffic is proxied, recorded and viewable but can never be
held, and no WS match/replace target exists) and **TLS negotiation control** (#80 — the sender's
only `tls.Config` sets neither `MinVersion` nor `CipherSuites`, so burpsy cannot be pointed at a
legacy-TLS target and cannot be constrained away from one; that is a real testing limitation and
it is undisclosed).

**Zero STATE 1.** There are no placeholder panels. Where burpsy has not built something it
renders nothing, rather than a screen that looks live. That is the single healthiest number
here and it is why the ABSENT count is high: absence is being taken honestly instead of being
laundered into a stub.

> **RETRACTION 2026-08-27 — the "3 unwired rows" are 2.** Row #12 (`inspectorPanelState`/`inspectorDock`) is fully wired: read at `ui/ui/inspector.tsx:475,550,551`, written at `:476,477`, applied at `:769,784`. The greps that reported zero readers were blind to that single file, which held a literal NUL byte — ugrep classified the 826-line source as binary and reported no matches while exiting 0, with no warning. #27/#28 were real and are now wired. The paragraph below is left as written; treat every #12 claim in it as withdrawn.

**The 3 UNWIRED rows are the real defect class.** They are the exact failure mode TAXONOMY was
written for — code that reads as finished, is commented as finished, is even named after the
Burp panel it implements, and has no caller. `inspectorPanelState`/`inspectorDock` (#12) are
declared, defaulted, given setters, and *persisted to localStorage under a comment explaining
why they deserve persistence* — and nothing in 13,354 lines of React ever reads them. The
entire `PayloadGenerator` (#27, #28) — numbers, file lists, custom lists, plus a committed
regression fix for an inverted-range panic — has zero non-test callers; Intruder takes pasted
text only. Three of the six historical disasters listed in TAXONOMY's "why the paranoia is
calibrated" section were of exactly this shape. Note the asymmetry that makes #12 diagnosable:
`repeaterGroups`, in the same store file with the same persistence treatment, **is** read by
`repeater.tsx` (#61). The difference is not visible from the store; it is only visible from a
caller grep.

**No decorative controls among the 85.** A decorative control is worse than an unwired one —
it renders, invites a click, and lies. The known example (the Decoder guess-alphabets checkbox,
`ui/pages/decoder.tsx:106-108`) is on a tool page, not a config panel, so it falls outside this
denominator; but I checked the two nearest candidates inside it and both came back clean:
match/replace deliberately omits its two dead targets from the `<select>`
(`ui/pages/matchreplace.tsx:17-18`), and the Repeater options panel deliberately omits its two
unimplementable switches. The unwired rows in ~~#12~~/#27/#28 (see the retraction above: #12 was never unwired) are *invisible* rather than
decorative — no control renders at all — which is less harmful to an operator and more harmful
to a reader of the codebase.

**The one thing an operator would be actively misled by is #8.** `Export configuration`
downloads a file called `burpsy-config.json` that contains scope rules, intercept lists and
session rules, and nothing else (`internal/web/api_config.go:48-67`). Network settings, proxy
options, match/replace rules, resource pools, schedules, scanner config, platform
authentication and client certificates are all silently dropped. The menu item does not say
"partial", the file does not say what it omitted, and the import result message counts only the
three sections it knows about. Carrying that file to a new machine and believing the engagement
configuration travelled with it is a mistake the UI does nothing to prevent. That is the
highest-value single fix in this table.

## NOT DETERMINED

1. **No STATE 5 is claimed, and that is a limit of this pass, not a finding of correctness.**
   TAXONOMY requires behavioural proof for STATE 5 and I ran behavioural checks on only four
   packages (`sender`, `proxy`, `web`, `matchreplace` — all green at `638c480`). 24 of the 41
   wired rows rest on reading plus a green package test, not on driving the UI. Any of them
   could be STATE 5 under a test I did not run. The `4-c` marker records the caveat; it does
   not certify the panel.
2. **Persistence across restart was not exercised for any panel.** Several sections claim
   "survives a restart" (#52) or "persisted for future starts" (#13's audit checks, #49). I did
   not restart a server and re-read. Persistence sinks are best-effort by design
   (`api_proxyoptions.go:86-94`), so a silent mirror failure would be invisible in the UI —
   this is the most likely place a STATE 5 is hiding.
3. **Row #23** (automatic payload placement): I confirmed the UI reaches `/api/intruder/points`
   and that the API accepts an `all` flag, but did not verify which value `ui/pages/intruder.tsx`
   actually sends, so "binary rather than per-family" is read from `api_tools.go:327` and the
   absence of a families UI, not from a driven request.
4. **Rows #17/#18** (HTTP/1, HTTP/2): I treated these as "no global panel, per-send override
   only". Burp's two panels contain roughly a dozen sub-switches each; I did not enumerate them
   against `internal/http2` to see how many individually have counterparts. The `4-c` is
   coarse.
5. **The `[cap-gap]` tag is my judgement, not a measurement.** I marked 21 rows as deliberate
   divergence. For 5 of them (#57, #59, #34, #36, #67) the code states the reasoning explicitly
   and the tag is evidenced. For the rest it is inference from architecture (browser console,
   non-JVM extensions) and a reader who disagrees should downgrade them to plain gaps.
6. **Row #12's blast radius. — RETRACTED 2026-08-27.** I did not prove this; I proved only that grep could not read `inspector.tsx`, which held a literal NUL byte. The prefs are fully wired — read `:475,550,551`, written `:476,477`, applied `:769,784`.
   I did **not** establish whether the Inspector's actual open/closed behaviour is hardcoded to
   "auto" or to something else, so I cannot say what an operator loses beyond "the preference
   cannot be set".

## DENOMINATORS I RECOUNTED (W6b pass)

| Count | Value | Exact command | Corpus |
|---|---|---|---|
| Distinct `configPanel*` identifiers | 134 | `grep -o 'configPanel[A-Za-z0-9_]*' map_root.tsv \| sort -u \| wc -l` | `/root/burp-re/out/strings/map_root.tsv` (Burp 2026.7.1) |
| Leaf widgets removed (Step 1) | 25 | suffix filter, predecessor's list | same |
| Top-level after prefix collapse (Step 2) | 95 | python parent() rule, rerun by W6b | same |
| Top-level config panels (Steps 3-4) | **85** | full script rerun by W6b, output matched predecessor's list name-for-name | same |
| burpsy React pages | 24 files, 13,354 lines | `wc -l burpsy-go/internal/web/ui/src/pages/*.tsx` | worktree at `638c480` |
| Registered HTTP API routes | 82 | `grep -rn 'HandleFunc("' burpsy-go/internal/web/*.go \| sed 's/.*HandleFunc(//' \| sort -u \| wc -l` | worktree at `638c480` |
| `matchreplace` targets implemented | 5 of 7 | `internal/matchreplace/matchreplace.go:18-24` vs `:244-255`; proven by `go test ./internal/matchreplace/ -run Param -v` | worktree at `638c480` |
| `proxy` response-modification options | 6 | `internal/proxy/options.go:45-75` (`OptionKeys`) | worktree at `638c480` |
| `intercept` directions | 2 (request, response — no WebSocket) | `internal/intercept/intercept.go:24-28` | worktree at `638c480` |
| Config-export bundle sections | 3 of ~15 configurable subsystems | `internal/web/api_config.go:48-67` | worktree at `638c480` |

## BEHAVIOURAL PROOF RUN IN THIS PASS

```
$ cd burpsy-go && go test ./internal/sender/... ./internal/proxy/... ./internal/web/...
ok  	github.com/burpsy-go/burpsy/internal/sender	4.619s
ok  	github.com/burpsy-go/burpsy/internal/proxy	7.001s
ok  	github.com/burpsy-go/burpsy/internal/web	9.083s

$ go test ./internal/matchreplace/... -run 'Unapplied|ParamName|Param' -v
=== RUN   TestAParamNameRuleDoesNotRewriteUnrelatedParameters
--- PASS: TestAParamNameRuleDoesNotRewriteUnrelatedParameters (0.00s)
=== RUN   TestBothParamTargetsAreNoOpsAndAreIndistinguishable
--- PASS: TestBothParamTargetsAreNoOpsAndAreIndistinguishable (0.00s)
PASS
ok  	github.com/burpsy-go/burpsy/internal/matchreplace	0.006s
```
Per TAXONOMY RULE 4 this is an UNGATED-vs-GATED distinction worth stating: `go test` **is** in
CI, so these three package results are gated. Nothing in this report rests on `bun run check`,
`tsc`, or an e2e run — none of which CI executes.

## POSITIVE CONTROLS FOR EVERY NEGATIVE GREP CLAIMED ABOVE

| Negative claim | Grep that returned 0 | Positive control that returned hits |
|---|---|---|
| No WS interception (#53, #54) | `grep -rn 'websocket\|WebSocket' internal/intercept/` | same pattern → `internal/proxy/ws.go`, `internal/web/api_events.go`, `ui/pages/wshistory.tsx`, `internal/vulnapp/vulnapp_stored_dom.go` |
| No uninteresting-header config (#81, #82) | `grep -rin 'uninteresting' --include=*.go --include=*.tsx internal/ cmd/` | `grep -rin 'passthrough'` → 20+ hits |
| No project backup (#2) | `grep -rEil 'project.?backup\|autosave\|auto.?save' internal/ cmd/` | `grep -rEil 'schedule'` → `internal/schedule/`, `internal/web/api_schedules.go` |
| No perf feedback (#38) | `grep -rEil 'performance.?feedback\|submit.*anonym'` | as above |
| `PayloadGenerator` unwired (#27, #28) | `grep -rn 'GenerateNumbers\|NewPayloadGenerator\|GenerateFromFile\|GenerateCustom' --include=*.go .` → only `intruder_test.go` | `grep -rn 'matchreplace.NewRuleSet(' --include=*.go .` → `internal/web/server.go:179`, `cmd/burpsy/main.go:412`, `cmd/burpsy/cli.go:191` |
| ~~Inspector prefs unwired (#12)~~ **RETRACTED** | The cited grep returned 0 because `ui/ui/inspector.tsx` held a literal NUL byte and ugrep skipped it silently, exiting 0. The correct method is `grep -a` (or an AST tool); a binary-classified file is an *unreadable* file, not an absence of matches. |
| No TLS version/cipher config (#80) | `grep -n 'MinVersion\|CipherSuites' internal/sender/*.go` → 0 | `grep -n 'tls.Config{' internal/sender/*.go` → `sender.go:242` (the config object exists; it just sets neither) |

*(End of W6b pass. Baseline `638c480`, clean tree, read-only.)*
