# Burp Suite 2026.7.1 — Complete UI Files & Definitions Map

All sources: `out/clean/renamed_final/`, `out/clean/root/`, `out/strings/map_root.tsv`,
`out/names/all_renames.tsv`, `out/names/class_map.tsv`, `UI_BACKEND_MAP.md`.

Evidence notation:
- `[str]` = literal found in `map_root.tsv`
- `[rename]` = method/class name recovered from `all_renames.tsv`
- `[heuristic]` = naming-family classifier applied by `ast_rename.py`
- `[infer]` = inferred from code structure, method signatures, or inheritance

---

## 1. Naming-Family Census (19,307 decompiled files)

Heuristic families produced by the rename pipeline, sorted by count:

| Family                  | Count | UI Relevance |
|-------------------------|-------|--------------|
| `BurpClass####`         | 13,942 | Mixed (unclassified) |
| `ExtensionClassLoader####` | 1,085 | Extension loading |
| `ActionHandler####`     | 611   | UI action callbacks |
| `TableColumnModel####`  | 460   | Swing table column models |
| `ColumnModel####`       | 456   | Column display/sorting models |
| `MenuHandler####`       | 324   | Context-menu and menu-bar items |
| `EnumSet####`           | 316   | Typed enum collections |
| `DialogManager####`     | 188   | Modal/non-modal dialog orchestrators |
| `ActionProcessor####`   | 188   | Action-command dispatch |
| `ViewComponent####`     | 175   | Swing panel/view containers |
| `KeyHandler####`        | 118   | Keyboard shortcut handlers |
| `MouseHandler####`      | 102   | Swing mouse listener implementations |
| `WindowHandler####`     | 72    | Frame/window lifecycle handlers |
| `UIComponent####`       | 69    | Generic Swing component wrappers |
| `UIAction####`          | 61    | `AbstractAction` subclasses |
| `CustomException####`   | 60    | UI-layer exceptions |
| `HttpWrapper####`       | 54    | HTTP model wrappers used by UI |
| `TaskHandler####`       | 51    | Scan/crawl task UI controllers |
| `RunnableTask####`      | 49    | Background tasks dispatched from UI |
| `ScanCheck####`         | 42    | Scanner passive/active check implementations |
| `ScannerHandler####`    | 41    | Scanner lifecycle controllers |
| `DocumentHandler####`   | 37    | Swing document listeners |
| `ClassTransformer####`  | 34    | Bytecode/data transformers (internal) |
| `ComponentHandler####`  | 33    | Generic component event handling |
| `RequestFactory####`    | 30    | Request-building helpers |
| `EventDispatcher####`   | 29    | Swing event dispatch helpers |
| `TabRenderer####`       | 26    | `JTable` / `JTabbedPane` cell renderers |
| `ScanReporter####`      | 26    | Issue/result reporting |
| `ScanConfig####`        | 19    | Scan configuration objects |
| `UIStateManager####`    | 17    | Persisted UI state (position, split, tabs) |
| `ListHandler####`       | 16    | `JList` / `JComboBox` data models |
| `ConfigManager####`     | 16    | Settings persistence |
| `TablePanel####`        | 12    | `JPanel` wrapping a `JTable` |
| `CellRenderer####`      | 10    | `TableCellRenderer` / `ListCellRenderer` |
| `PanelHandler####`      | 7     | Unnamed panel orchestrators |
| `FormHandler####`       | 5     | Form validation / submission |
| **Named singletons**    | ~30   | See §2 |

---

## 2. Named Singleton UI Classes

These have recovered or clearly deduced real names:

| Class file (renamed_final) | Obfuscated | Role |
|----------------------------|------------|------|
| `ToolRegistry.java`        | `burp.Zgdx` | Tool enum: DASHBOARD, PROXY, SCANNER, INTRUDER, REPEATER, SEQUENCER, DECODER, COMPARER, LOGGER, ORGANIZER, EXTENDER [str: mainSuiteMenu] |
| `LiveAuditLauncherUI.java` | `burp.Zpne` (approx) | Live-task launcher dialog — live audit / live passive crawl task type radio buttons [str: liveTaskLauncherScanDetailsLiveAuditTaskTypeRadioButton] |
| `IssueTreeModel.java`      | Internal  | Swing `TreeModel` for the Issues panel |
| `ITextEditor.java`         | API bridge | Legacy v1 `ITextEditor` interface |
| `ITab.java`                | API bridge | Legacy v1 `ITab` extension interface |
| `RequestEditor.java`       | `burp.Zc3s` | Raw-tab HTTP request editor component [str: messageEditorRaw] |
| `RepeaterSendButton.java`  | `burp.Zrxx` subset | Repeater Send button [str: repeaterCancelButton, repeaterTabPanel] |
| `RepeaterMenu.java`        | `burp.Zrxx` | Repeater main menu / config override button [str: repeaterConfigurationOverrideMenuButton] |
| `RepeaterNewHttpTabOption.java` | `burp.Zrxx` | Repeater → New HTTP tab action |
| `RepeaterNewWsTabOption.java`   | `burp.Zrxx` | Repeater → New WebSocket tab action |
| `RepeaterSearchCheckbox.java`   | `burp.Zrxx` | Search checkbox in Repeater toolbar |
| `SendToRepeaterAction.java`     | —          | Context-menu "Send to Repeater" |
| `ScanTaskStatus.java`      | Applied rename | Scan task status enum / label |
| `ScannerCheckBridge.java`  | —          | Bridge between Montoya `ScanCheck` API and internal check pipeline |
| `TaskViews.java`           | —          | Dashboard task-views panel |
| `InsertionPointBuilder.java` | —         | Montoya API `InsertionPoint` builder |
| `PersistableIdResolver.java` | —         | Resolves obfuscated IDs to persistence keys |
| `ProgressNormalizer.java`  | —          | Normalizes crawl/audit progress percentages |
| `LivePassiveCrawlTaskListener.java` | —  | Listener wired to live-passive-crawl task UI updates |

---

## 3. Tool-by-Tool UI Breakdown

### 3.1 Main Suite Frame

**Class:** `burp.Zc6t` [str: `mainSuiteMenu`, `mainSuiteMenuExitMenuItem`]

Top-level Swing `JFrame`. Owns:
- The main menu bar (`Burp`, `Settings`, `Search`, `Upgrade to Burp Suite Professional`)
- The top-level `JTabbedPane` routing to each tool
- License-state banner area

String evidence:
```
burp.Zc6t  mainSuiteMenu
burp.Zc6t  mainSuiteMenuExitMenuItem
burp.Zc6t  Burp Clickbandit
burp.Zc6t  Configuration library
burp.Zc6t  Burp Collaborator client
burp.Zc6t  Burp Infiltrator
burp.Zc6t  Exit
burp.Zc6t  [Pro version only]
```

Frame persistence: `burp.Zpoe` stores `framewidth`, `frameheight`, `window_size`, `screen_size`
as telemetry/state keys. [str]

---

### 3.2 Proxy Tool

**Config panel class:** `burp.Zg5l` [str: `proxyListenersConfigDialog`]
**Response-modification panel:** `burp.Zrdw` [str: `configPanelProxyModificationRules`, `proxy.response_modification`]
**Match & Replace config panel:** `burp.Zg5m` [str: `matchReplaceRuleConfigDialog`, `matchReplaceRuleTestButton`, `matchReplaceRuleRefreshButton`, `matchReplaceRuleAutoModifiedMessagePanel`, `matchReplaceRuleOriginalMessagePanel`]
**Filter dialog:** `burp.Zg5f` [str: `filterDialog`]
**History item model:** (heuristic `ColumnModel####`/`TableColumnModel####` families)

Sub-components in `burp.Zg5l`:
- Bind-to-port field, loopback/all-interfaces/specific-address radio group
- TLS-protocol checkboxes
- Redirect-to-host:port fields
- Certificate source selector (self-signed / generate per-host / PKCS#12)
- Invisible-proxy support checkbox
- HTTP/2 support checkbox

String evidence (`burp.Zg5l`):
```
proxyListenersConfigDialog
Add a new proxy listener / Edit proxy listener
Bind to port: / Loopback only / All interfaces / Specific address:
Force use of TLS / TLS Protocols
Support invisible proxying (enable only if needed)
Use a self-signed certificate / Use a custom certificate (PKCS#12):
Support HTTP/2
```

Sub-component names (`burp.Zrxx` — Repeater pane also owns Proxy-side viewer):
```
repeaterCancelButton            repeaterTabPanel
repeaterEditTargetButton        repeaterTargetLabel
repeaterStatusLabel             repeaterProtocolLabel
repeaterConfigurationOverrideMenuButton
repeaterResponseViewControls    repeaterRequestViewControls
repeaterExploreButton           repeaterFollowRedirectButton
repeaterExplorePromptPanel      repeaterAdditionalDataLabel
httpRequestMessageAnalyser      httpResponseMessageAnalyser
```

**Proxy history item** is rendered via the `ColumnModel####` / `TableColumnModel####` families;
each column in the HTTP History table (`#`, Method, URL, Params, Edited, Status, Length,
MIME type, Extension, Title, Comment, TLS, IP, Cookies, Time) corresponds to one of the 456
`ColumnModel####` or 460 `TableColumnModel####` instances.

Proxy-upstream config: `burp.Zbhs` [str: `Upstream proxy server`, `Invalid proxy port`, `Invalid proxy host`]

Proxy → Browser integration: `burp.Zpk5` [str: `Proxy Match and Replace`, `proxy.ssl_pass_through`, `Burp Browser`, `Unable to start Burp Browser - no Proxy listeners available.`]

Response-modification rules (`burp.Zrdw`):
```
unhide hidden form fields       remove <object> tags
remove js from validation       remove all js
convert https links to http     proxy.response_modification
configPanelProxyModificationRules
```

---

### 3.3 Scanner Tool (Dashboard-initiated)

**Audit-item table toggle:** `burp.Zub5` [str: `auditItemsTableInsertionPointsViewToggle`, `Insertion points`]
**Scan config editor — scope expand:** `burp.Zrfg` [str: `scanConfigurationEditorScopeExpandButton`]
**Scan config preset radio panel:** `burp.Zrcr` [str: `scanPresetConfigurationRadioPanelRadioButton`]
**Scan-behavior overrides:** `burp.Zgc2` [str: `scanner.audit_project_option_overrides`, `scanner.audit_optimization`, `scanner.error_handling`, `Audit behaviour`]
**Crawl pause/timeout config:** `burp.Zrfv` [str: `scanConfigurationEditorHandlingRepeatedTimeoutsDuringCrawlConsecutiveRequestsTimedOutField`, `scanConfigurationEditorHandlingRepeatedTimeoutsDuringCrawlPercentageRequestsTimedOutField`, etc.]

Scanner string evidence (insertion-point status messages from `burp.Zq5`):
```
Pending / Auditing / Audited / Light-auditing / Light-audited
Skipped / Cancelled / Failed to scan
Burp Scanner is sending a small number of requests...
Burp Scanner didn't audit this insertion point, because...
Burp Scanner has performed a full audit of this insertion point.
Skipped as limit exceeded / Skipped as parameter movement not enabled
Skipped due to repetitive behavior
HTTP headers / body parameters / JSON parameters / multipart parameter attributes
URL path filenames / IPType
```

Insertion-point status is the `AuditItemStatus` enum (15 states). See `SCAN_ENGINE.md`.

**BCheck custom scan checks:** `burp.Zrjx` [str: `bcheckTitleLabel`, `Custom scan checks`, `bcheckCommunityUpsellPanel`]
**API details panel:** `burp.Zrs6` [str: `apiDetailsPanel`, `apiDetailsPanelEmptyState`, `apiDetailsPanelTabs`, `apiDetailsRibbonButton`, `Upload API definition`, `View and configure the endpoints, authentication methods, and parameters for your scan.`]

---

### 3.4 Intruder Tool

**Payload list UI:** `burp.Zr78` [str: `payloadTable`, `payloadListAddItemField`, `payloadListAddItemButton`, `payloadListRemoveButton`, `payloadListDeduplicateButton`, `payloadListPresetCombo`, `Add from list... [Pro version only]`, `Not available in Community Edition`]

**View filter:** `burp.Zma4` [str: `View filter`, `Intruder view filter`]

Montoya API surface (logged from `burp.Zpfc`):
```
MontoyaApi.Intruder.registerPayloadProcessor
MontoyaApi.Intruder.registerPayloadProvider
MontoyaApi.Intruder.sendToIntruder(HttpRequest)
MontoyaApi.Intruder.sendToIntruder(HttpRequest, String)
MontoyaApi.Intruder.sendToIntruder(HttpService, HttpRequestTemplate)
MontoyaApi.Intruder.sendToIntruder(HttpService, HttpRequestTemplate, String)
```

Payload generator provider bridge: `burp.Zpif` implements `PayloadGeneratorProvider`;
calls `IIntruderPayloadGeneratorFactory.getGeneratorName()`, bridges old v1 API. [code]

---

### 3.5 Repeater Tool

Already fully documented in `UI_BACKEND_MAP.md §3`. Summary:

- Tab panel: `burp.Zrxx` → `repeaterTabPanel`
- Send/Cancel/Follow-redirect buttons
- Target display: protocol, host, port labels
- HTTP/1, HTTP/2, WebSocket tab options
- Config override menu (connection reuse, Content-Length)
- Explore (Burp AI) button: `repeaterExploreButton`
- Request/response `HttpMessageAnalyser` components

---

### 3.6 Sequencer Tool

**Token analysis config:** `burp.Zrdz` [str: `configPanelSequencerTokenAnalysis`, `sequencer.token_analysis`, `Compression`, `Correlation`, `Transitions`, `FIPS poker`, `Spectral`]
**Token handling config:** `burp.Zrdt` [str: `configPanelSequencerTokenHandling`, `sequencer.token_handling`, `Base64-decode before analyzing`, `Pad short tokens at:`, `Start` / `End`]

---

### 3.7 Decoder Tool

No dedicated config panel found — Decoder is a pure transformation pipeline with
`ClassTransformer####` and inline codec dispatch. UI is a split editor pane.

---

### 3.8 Comparer Tool

Response comparison config: `burp.Zr3j`
[str: `Configure the settings below to determine how Burp handles certain features of responses when performing comparisons.`, `Response headers`, `Form field values`, `Include form field values`, `Except for:`]

---

### 3.9 Logger Tool

**Capture filter config:** `burp.Zr7o`

Full config key set from string map:
```
logger.capture_filter.by_search.term / regex / case_sensitive / negative_search
logger.capture_filter.by_request_type.capture_only_in_scope_items
logger.capture_filter.by_request_type.capture_only_parameterized_requests
logger.capture_filter.by_request_type.discard_items_without_responses
logger.capture_filter.by_mime_type.capture_html / css / script / xml / flash / images / other_text / other_binary
logger.capture_filter.by_status_code.capture_2xx / 3xx / 4xx / 5xx
logger.capture_filter.limit_request_response_size.capture_requests_up_to / capture_responses_up_to
logger.capture_filter.session_handling.ignore_session_handling_requests
```

UI labels: `Capture by tool`, `Capture by search term`, `Capture by request type`,
`Capture by MIME type`, `Capture by status code`, `Limit request/response size`,
`Session handling`, `Case sensitive`, `Negative search`, `Regex`, `Ignore session handling requests`.

---

### 3.10 Target Analyzer

**Class:** `burp.Zr8r`
[str: `Target analyzer | `, `Number of dynamic URLs:`, `Static URLs`, `Number of unique parameter names:`, `Total number of parameters:`, `Summary`, `Dynamic URLs`]

---

### 3.11 Extender (Extensions)

**Extensions config — Ruby:** `burp.Zrub` [str: `configPanelRubyEnvironment`, `Ruby environment`, `Location of JRuby JAR file:`, `selectJRubyJarButton`, user_options.extender.ruby.*]

Extension-loader settings (`burp.Zhc9`):
```
user_options.extender.settings.suppress_extension_loaded_popup
user_options.extender.settings.automatically_update_bapps_on_startup
user_options.extender.settings.automatically_reload_extensions_on_startup
user_options.extender.ruby.location_of_jruby_jar_file
user_options.extender.python.location_of_jython_standalone_jar_file
user_options.extender.python.folder_for_loading_modules
user_options.extender.java.folder_for_loading_library_jar_files
```

Legacy v1 extension API interfaces (still present as named singletons):
`IMessageEditor`, `IMessageEditorController`, `IMessageEditorTabFactory`,
`IMessageEditorTab`, `IProxyListener`, `IScannerCheck`, `IScannerListener`,
`IScopeChangeListener`, `ISessionHandlingAction`, `IContextMenuFactory`,
`IContextMenuInvocation`, `IMenuItemHandler`, `IHttpListener`,
`IExtensionStateListener`, `IResponseKeywords`,
`IBurpCollaboratorClientContext`, `IBurpCollaboratorInteraction`

v1 API bridges for message editors (from `burp.Zs2k`):
```
IMessageEditor.getSelectedData   IMessageEditor.getSelectionBounds
IMessageEditor.getComponent      IMessageEditor.getMessage
IMessageEditor.setMessage        IMessageEditor.isMessageModified
```

---

### 3.12 HTTP Message Analyser (shared editor component)

**Class:** `burp.Zrqs` [str: `messageAnalyserTabbedPane`, `messageAnalyserActionsButton`]

Tab names and toggles:
```
messageAnalyserTabbedPane
messageAnalyserToggleLineWrap         (Enable / Disable line wrapping)
messageAnalyserToggleShowNonPrintableCharacters  (Show / Hide non-printable chars)
messageAnalyserToggleHideUninterestingHeaders    (Show / Hide specified headers)
Message actions
```

Raw tab: `burp.Zc3s` [str: `messageEditorRaw`]

---

### 3.13 Settings / Project Configuration

**HTTP message search settings:** `burp.Zrg_`
[str: `configPanelHttpMessageSearch`, `default search settings`, `HTTP message search`, `user_options.misc.http_message_search`, `Auto-scroll to match when text changes`, `Case sensitive`, `Regex`]

**Collapsible panel wrapper:** `burp.Zrcf` [str: `collapsiblePanel`]

**Resource Pool dialog:** `burp.Zxsx`
[str: `resourcePoolDetailsDialogNameTxtField`, `resourcePoolDetailsDialogMaxConcurrentRequestsTxtField`, `resourcePoolDetailsDialogDelayBetweenRequestsTxtField`, `Edit resource pool`, `Name:`, `Max concurrent requests:`, `Delay between requests:`, `Automatic throttling`, `Increase delay in increments of`]

**Auto-update dialog:** `burp.Zg5g` [str: `auto_updates_disabled_dialog_shown_`, `Automatic updates`]

**Split button / combo box UI delegates:** `burp.Zio_` [str: `SplitButtonUI`, `ComboBoxUI`]

**macOS integration:** `burp.Zilx` [str: `FlatLaf.macOS.windowTitleBarHeight`, `apple.laf.useScreenMenuBar`]

**Custom actions panel entries:** `burp.Zro7`
[str: `customActionsEntryPanelNameLabel`, `customActionsEntryPanelEditButton`, `customActionsEntryPanelRunButton`, `customActionsEntryPanelAutoExecuteButton`, `Auto-run on send`]

**CSRF PoC generator:** `burp.Zbxv`
Contains inline JavaScript template strings for CSRF HTML PoC forms. [str: xhr.withCredentials, submitRequest(), POST body assembly literals]

---

### 3.14 Live Task Launcher

**Class:** `burp.Zhwl` [str: many `liveTaskLauncher*` component names]

Full component inventory:
```
liveTaskLauncherScanDetailsLiveAuditTaskTypeRadioButton
liveTaskLauncherScanDetailsLivePassiveCrawlTaskTypeRadioButton
liveTaskLauncherScanDetailsToolsScopeRepeaterCheckbox
liveTaskLauncherPredefinedTaskComboBox
```

Labels: `Task type`, `Scan details`, `Tools scope`, `Deduplication`, `URL scope`,
`Suite scope`, `Custom scope`, `Intruder`, `Repeater`, `Proxy`,
`Live audit`, `Live audit (Pro version only)`, `Live passive crawl`,
`Ignore duplicate items based on URL and parameter names`,
`Choose predefined task...`, `Everything`, `Select whether items...`

---

### 3.15 Cache Deception Check (Web Cache Deception)

**Class:** `burp.Zum9` implements `Zi28` (doCheck interface)

Returns `Zf8g.APR_WebCacheDeception` from `ZB()` — confirming issue type.

Recovered field names:
- `differsFromBaseResponse` — `Zx1p` (response-comparison helper)
- `hasUrlParsingDiscrepancy` — `Zin1` (audit-item state)
- `hasUrlMappingDiscrepancy` — `Zm41`
- `isResourceAuthenticated` — static `List<String>`
- `identifyHostServerCombination` — static `String[]`
- `isDynamicResource` — inferred from bytecode `istore 7`

Check logic (from bytecode reconstruction):
1. Guard: `ZO()` — check resource is not already authenticated-and-safe
2. Guard: `Zm()` — early-exit conditions
3. `differsFromBaseResponse()` → collects `List` of response pairs
4. `ZP(list, true)` — checks if base response differs
5. `identifyHostServerCombination()` — fingerprints CDN/server combo
6. `isResourceAuthenticated()` — boolean check
7. Two dispatch paths: `hasUrlParsingDiscrepancy` → fires parsing-discrepancy issue; else fires `hasUrlMappingDiscrepancy` runnable
8. `hasUrlMappingDiscrepancy(list)` → second dispatch

Cache-indicator string evidence (`burp.Zg1g`):
```
X-Cache        CF-Cache-Status    X-Cache-Hits
CF-RAY         X-Varnish-Cache    X-Drupal-Cache
X-Varnish      Cache              Age
hit / miss
```
→ `burp.Zg1g` is the cache-header detector used by `Zum9`.

Static file-extension denylist literals in `burp.Zum9`:
`BMP`, `MKV`, `PPT`, `%3F`, `immutable` (Cache-Control directive) — part of the
"is static resource" classification.

---

### 3.16 DOM XSS / HTML Injection (Stored & Reflected)

**Class:** `burp.Zwr4` — DOM reflection confirmation stage

Recovered field names:
- `buildConfirmDirectDomReflectionsStage` — `Zflo` typed field (pipeline stage builder)

Methods:
- `lambda$buildConfirmDirectDomReflectionsStage$2(Zgx0, Zin1, Zgtn, Zsz4)` — outer dispatch; checks `Zc.ZP(var1.Zt())` scope guard
- `lambda$buildConfirmDirectDomReflectionsStage$1(Zehl, Zgtn, Zin1, Zgx0, Zwe8, byte, Zh38)` — inner; calls `Zgct.Zv(...)` to execute the DOM probe
- `lambda$buildConfirmDirectDomReflectionsStage$0` — request builder from `Zrb6`

**File-upload XSS (HTML MIME):** `burp.Zi_x` implements `Zrm7` (doSingleCheck)

`doSingleCheck` logic:
1. Normalizes body via `Ze.Zi(var3)` (filter/encoder)
2. Builds response-pair `Zh38` via `Z_y`
3. Resolves reflection `Zuej` with `ZY((byte)2, ...)`
4. If `Zwe8.FILE_UPLOAD_FILE_EXTENSION_HTML_TYPES.contains(var4)`: OR-in `0x80000` flag
5. Content-type override probe: adds `Content-type: text/plain` header, re-sends, checks if reflection survives → flags `0x1000` (content-sniff bypass)
6. If content-type override fails, sets `0x2000` (no bypass)
7. If original response is HTML-ish (`Zw8c.Ze(var17, var18, ...)`): tries `/a.html` and `;a.html` path appended (cache-deception check within file-upload checker)
8. Returns `Zwwb.Zo(...)` with full reflection evidence

---

### 3.17 Template Injection / SSTI

**Payload builder:** `burp.Zprt` implements `Zuw7`

`createInjection` constructs: `"#{random_string_5}" + var0 + "#{random_string_5b}"`
→ SSTI canary pattern wrapping the probe payload. [code]

---

### 3.18 SQL Injection / Reflection Analysis (XSS checks)

**Canary-based XSS reflection:** `burp.Zeyy` [str: `#{random_string_5}`]
**DB connection string scanner:** `burp.Zbjg` (passive check)

`checkForDbConnectionString` logic:
- Scans response body in 20-byte minimum chunks
- For each key=value segment (split on `;`), checks:
  - `Zh(key)` — hostname/server key? (flag bit 1)
  - `Zk(key)` — database name key? (flag bit 2)
  - `ZX(key)` — password key? (`"password"` / `"pwd"`, flag bit 8)
  - `Zq(key)` — user key? (`"uid"` / `"user"` / `"userid"`, flag bit 4)
- Characters `'`, `"`, `<`, `>`, control chars, high-byte → treated as delimiters (`Zd`)
- `ZD(str)` normalizes: `.trim().replaceAll("[ \r\n\t]", "").toLowerCase()`
- Reports issue via `Zxgi.ZN(...)` for each unique connection string found

---

### 3.19 Check-Dispatch Class (`Zg3d`) — doCheck + applicableTechniques

**Class:** `out/clean/root/Zg3d.java`

`applicableTechniquesAndPermutations`:
- Accepts `(boolean param0, Zpmx param1)`
- Returns filtered `List<?>` of check permutations
- Applies filter `burp.Zg3d::lambda$applicableTechniquesAndPermutations$2` via stream

`doCheck`: dispatches to `doCheck.Decompose(Zc58, Zsz4)`, calls `Zcud.ZV(...)` pattern.

---

## 4. Component Hierarchy Snapshot

```
JFrame (burp.Zc6t — mainSuiteMenu)
├── JMenuBar
│   ├── Burp menu (Clickbandit, Collaborator, Infiltrator, Config lib, Exit)
│   ├── Settings menu
│   ├── Search menu
│   └── Upgrade / Pro upsell
└── JTabbedPane (tool tabs)
    ├── Dashboard (burp.Zigd)
    │   ├── Task list panel (TaskViews.java)
    │   ├── Issue activity feed
    │   └── Live task launcher (burp.Zhwl)
    ├── Target (burp.Zr8r — Target analyzer)
    │   ├── Site map tree
    │   └── Issue list table
    ├── Proxy (burp.Zg5l, Zrdw, Zg5m, Zg5f)
    │   ├── HTTP History table (ColumnModel####, TableColumnModel####)
    │   ├── WebSockets History table
    │   ├── Proxy listeners config
    │   ├── Match & Replace rules
    │   └── Response modification rules
    ├── Scanner / Intruder (burp.Zr78, Zma4, Zub5)
    │   ├── Payload list (payloadTable, payloadListAddItemField, ...)
    │   ├── Insertion-point status overlay (AuditItemStatus enum)
    │   ├── BCheck custom checks (burp.Zrjx)
    │   └── API details panel (burp.Zrs6)
    ├── Repeater (burp.Zrxx)
    │   ├── Tab panel (repeaterTabPanel)
    │   ├── Request editor (messageEditorRaw via Zc3s)
    │   ├── Response editor (httpResponseMessageAnalyser)
    │   └── Toolbar: Send, Cancel, Follow redirect, Explore (AI), target label
    ├── Sequencer (burp.Zrdz, Zrdt)
    │   ├── Token analysis config
    │   └── Token handling config
    ├── Decoder (ClassTransformer####)
    ├── Comparer (burp.Zr3j)
    ├── Logger (burp.Zr7o — capture filter)
    ├── Organizer
    └── Extender (burp.Zrub, Zhc9)
        └── Extensions table + BApp Store
```

---

## 5. Shared / Cross-Tool UI Infrastructure

| Component | Class | Key Evidence |
|-----------|-------|--------------|
| HTTP Message Analyser | `burp.Zrqs` | `messageAnalyserTabbedPane`, tab toggle strings |
| Message Editor (Raw tab) | `burp.Zc3s` | `messageEditorRaw` |
| Filter dialog | `burp.Zg5f` | `filterDialog` |
| Collapsible panel | `burp.Zrcf` | `collapsiblePanel` |
| Resource pool dialog | `burp.Zxsx` | `resourcePoolDetailsDialog*` field names |
| Cache header detector | `burp.Zg1g` | `X-Cache`, `CF-Cache-Status`, `hit`/`miss` |
| Bambda filter mode radios | `burp.Zg5m` | `filterBambdaModeRadioButton`, `filterSettingsModeRadioButton` |
| Detached frames | `burp.Zgxy` | `detached-frames` (floating tool windows) |
| Split/combo UI delegates | `burp.Zio_` | `SplitButtonUI`, `ComboBoxUI` (FlatLaf integration) |
| macOS title-bar | `burp.Zilx` | `FlatLaf.macOS.windowTitleBarHeight`, `apple.laf.useScreenMenuBar` |
| Upstream proxy config | `burp.Zbhs` | `Upstream proxy server`, `Invalid proxy port` |
| Custom action entries | `burp.Zro7` | `customActionsEntryPanel*` component names |

---

## 6. Swing Component-Name Registry

Burp calls `setName()` on every testable Swing component. Full recovered list from
`map_root.tsv` (component names only, deduplicated):

```
# Proxy
proxyListenersConfigDialog
configPanelProxyModificationRules
matchReplaceRuleConfigDialog          matchReplaceRuleTestButton
matchReplaceRuleRefreshButton         matchReplaceRuleAutoModifiedMessagePanel
matchReplaceRuleOriginalMessagePanel  matchReplaceRuleOriginalMessageLabel
matchReplaceRuleAutoModifiedMessageLabel
filterBambdaModeRadioButton           filterSettingsModeRadioButton
matchReplaceBambdaUpsellPanel
filterDialog

# Repeater
repeaterCancelButton                  repeaterTabPanel
repeaterEditTargetButton              repeaterTargetLabel
repeaterStatusLabel                   repeaterProtocolLabel
repeaterConfigurationOverrideMenuButton
repeaterResponseViewControls          repeaterRequestViewControls
repeaterExploreButton                 repeaterFollowRedirectButton
repeaterExplorePromptPanel            repeaterAdditionalDataLabel
httpRequestMessageAnalyser            httpResponseMessageAnalyser

# Scanner
scanConfigurationEditorScopeExpandButton
scanPresetConfigurationRadioPanelRadioButton
auditItemsTableInsertionPointsViewToggle
scanConfigurationEditorHandlingRepeatedTimeoutsDuringCrawlConsecutiveRequestsTimedOutField
scanConfigurationEditorHandlingRepeatedTimeoutsDuringCrawlPercentageRequestsTimedOutField
scanConfigurationEditorHandlingRepeatedTimeoutsDuringCrawlAuthenticationFailuresField
scanConfigurationEditorHandlingRepeatedTimeoutsDuringCrawlAuthenticationFailuresValidationLabel
bcheckTitleLabel
apiDetailsPanel                       apiDetailsPanelEmptyState
apiDetailsPanelTabs                   apiDetailsRibbonButton

# Intruder
payloadTable                          payloadListAddItemField
payloadListAddItemButton              payloadListRemoveButton
payloadListDeduplicateButton          payloadListPresetCombo

# Sequencer
configPanelSequencerTokenAnalysis
configPanelSequencerTokenHandling

# Logger
(config keys used as component names — see §3.9)

# Message editor
messageEditorRaw
messageAnalyserTabbedPane             messageAnalyserActionsButton
messageAnalyserToggleLineWrap
messageAnalyserToggleShowNonPrintableCharacters
messageAnalyserToggleHideUninterestingHeaders

# Settings / misc
configPanelRubyEnvironment            selectJRubyJarButton
configPanelHttpMessageSearch
collapsiblePanel
resourcePoolDetailsDialogNameTxtField
resourcePoolDetailsDialogMaxConcurrentRequestsTxtField
resourcePoolDetailsDialogDelayBetweenRequestsTxtField
bcheckCommunityUpsellPanel
contextButtonPanel                    largeButtonPanel
titleLabel
liveTaskLauncherScanDetailsLiveAuditTaskTypeRadioButton
liveTaskLauncherScanDetailsLivePassiveCrawlTaskTypeRadioButton
liveTaskLauncherScanDetailsToolsScopeRepeaterCheckbox
liveTaskLauncherPredefinedTaskComboBox
customActionsEntryPanelNameLabel      customActionsEntryPanelEditButton
customActionsEntryPanelRunButton      customActionsEntryPanelAutoExecuteButton
mainSuiteMenu                         mainSuiteMenuExitMenuItem
```

---

## 7. UI State / Persistence Keys

From `map_root.tsv` — config and user-option keys wired to UI:

```
# Proxy
proxy.ssl_pass_through              proxy.response_modification
# Scanner / Crawler
scanner.audit_optimization.logging_enabled
scanner.audit_optimization.parallel_crawl_and_audit
scanner.audit_optimization.max_items_in_progress
scanner.audit_project_option_overrides
scanner.error_handling
crawler.crawl_optimization.*        (10+ sub-keys for timeouts, thresholds)
# Sequencer
sequencer.token_analysis            sequencer.token_handling
# Extender
user_options.extender.settings.*
user_options.extender.ruby.*
user_options.extender.python.*
user_options.extender.java.*
# Logger
logger.capture_filter.*             (18+ sub-keys)
# Misc
user_options.misc.http_message_search
```

---

## 8. File-Family → Tool Mapping

| Heuristic family | Likely tool(s) |
|------------------|---------------|
| `UIComponent####` | Shared infrastructure / shell |
| `UIAction####` | Context-menu and toolbar actions |
| `UIStateManager####` | Frame/splitter/tab state persistence |
| `DialogManager####` | All modal dialogs across tools |
| `ActionHandler####` | Event handlers for buttons, menus, keyboard |
| `ActionProcessor####` | Command dispatcher (Swing `Action` pattern) |
| `KeyHandler####` | Global keyboard shortcuts |
| `MouseHandler####` | Drag, double-click, right-click handlers |
| `WindowHandler####` | Frame open/close/resize listeners |
| `TabRenderer####` | `JTable` / `JTabbedPane` cell renderers |
| `TableColumnModel####` | HTTP history, issue list, audit item list columns |
| `ColumnModel####` | Same — alternate classifier |
| `MenuHandler####` | Context menus: Proxy history, Scanner results, Repeater |
| `ViewComponent####` | Tool-specific panel containers |
| `TaskHandler####` | Dashboard scan task rows |
| `DocumentHandler####` | `DocumentListener` for live-updating text fields |
| `ListHandler####` | Payload list, extension list, scope list models |
| `PropertyEditor####` | Settings field editors |
| `CellRenderer####` | Custom cell rendering (color, highlight) |
| `TablePanel####` | Panels with embedded `JTable` |
| `PanelHandler####` | Generic panel lifecycle |
| `FormHandler####` | Form validation in config dialogs |
| `ConfigHandler####` | Settings load/save coordination |
| `ConfigManager####` | Global config registry |
| `EventRouter####` | Cross-component event bus |
| `EventDispatcher####` | Swing EDT wrapper / cross-thread dispatch |
| `ComponentHandler####` | Generic `ComponentListener` |
| `StateHandler####` | Undo/redo or state-machine handlers |
| `EntryHandler####` | List/table entry CRUD (add/remove/edit) |
| `RuleHandler####` | Match-replace, scope rule list management |
| `FilterHandler####` | Filter dialog application |
| `TypeHandler####` | Type-discriminated dispatch |
| `ResponseHandler####` | Response processing callbacks |
| `RequestHandler####` | Request processing callbacks |
| `FieldHandler####` | Form-field binding |
| `PropertyModel####` | Bound property models (checkbox, combo) |
| `ScanReporter####` | Issue creation and deduplication |
| `ScanCheck####` | Active / passive check implementations |
| `ScannerHandler####` | Scanner lifecycle orchestration |
| `ScanConfig####` | `ScanConfiguration` data objects |
| `AnalyzerHandler####` | Request/response analysis helpers |
| `TableBuilder####` | Dynamic table construction |
| `TableConfig####` | Column configuration objects |
| `MenuProvider####` | Context-menu factory implementations |
| `ActionMapper####` | Action-key → handler mapping |

---

## 9. Extension API Bridges Summary

| v1 Interface | Montoya equivalent | Bridge class pattern |
|---|---|---|
| `IMessageEditor` | `MessageEditor` | `burp.Zs2k` |
| `IProxyListener` | `ProxyHandler` | `IProxyListener.java` singleton |
| `IScannerCheck` | `ScanCheck` | `ScannerCheckBridge.java` |
| `IScannerListener` | — | `IScannerListener.java` singleton |
| `ITab` | `Tab` | `ITab.java` singleton |
| `IContextMenuFactory` | `ContextMenuItemsProvider` | `IContextMenuFactory.java` |
| `IIntruderPayloadGeneratorFactory` | `PayloadGeneratorProvider` | `burp.Zpif` |
| `IBurpCollaboratorClientContext` | `Collaborator` | `IBurpCollaboratorClientContext.java` |

---

## 10. Evidence Quality Notes

- **High confidence** (direct string literals + class confirmed): §3.1–3.4, §3.6, §3.9, §3.12–3.15, §5
- **Medium confidence** (class identified by string, structure inferred): §3.5 (Repeater already mapped), §3.7–3.8, §3.10
- **Lower confidence / heuristic** (file-family inference only, no direct string): §8 mapping table, §3.11 family counts
- `BurpClass####` (13,942 files): ~74% of codebase remains unnamed; the families above capture the UI-visible ~26%
