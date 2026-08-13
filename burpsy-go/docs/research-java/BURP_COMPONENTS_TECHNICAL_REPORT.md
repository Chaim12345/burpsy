# Comprehensive Reverse Engineering & Architectural Report: Burp Suite Professional v2026.7.1 Components

**Document Version:** 1.0.0  
**Target Platform:** Desktop Client & Core Security Engine  
**Analysis Methodology:** Decompilation (CFR 0.152 / Vineflower 1.12.0), Static AST Analysis, Synthetic Method Lambda Recovery (`lambda$<name>$n`), String Table Analysis (`out/strings/map_root.tsv`), and Runtime Probe Verification.  
**Primary Source Trees:** `/root/burp-re/out/clean/renamed_final`, `/root/burp-re/out/burp/`, `SCAN_ENGINE.md`, `UI_FILES_MAP.md`, `BURP_SUITE_FULLSTACK_SPECIFICATION.md`

---

## 1. Executive Summary & Reverse Engineering Methodology

This report details the internal engineering, component breakdown, underlying algorithms, data structures, and UI bindings for all 15 core components of Burp Suite Professional v2026.7.1.

### 1.1 Deobfuscation & Analysis Pipeline
Burp Suite is obfuscated using **Zelix KlassMaster (ZKM)**, which strips debug attributes (`SourceFile`, `LocalVariableTable`, `LineNumberTable`) and renames non-public classes to short identifiers (`Za`, `Zb`, `Zc`). 

Our reverse engineering pipeline recovered architectural contracts using four primary evidence channels:
1. **Synthetic Method Lambda Names**: ZKM preserves lambda compiler-generated synthetic method names (e.g. `lambda$repeaterToolFrameProvider$1`), cleanly recovering Guice `@Provides` methods across tool modules.
2. **UI Test Addressability (`setName()`)**: Burp calls `setName("camelCaseComponentName")` on Swing controls to support automated testing. These string literals survived ZKM obfuscation and unambiguously attribute obfuscated UI components to specific tools.
3. **Preserved Enum Constants**: Constant names in Java Enums survive ZKM obfuscation (`ToolRegistry` / `Zgdx`, Issue Catalog `Zcot` with 183 constants, Audit Phases `Zefx` with 7 constants, and Audit Item Status `Zq5` with 15 constants).
4. **Public Extension Boundaries**: `burp.api.montoya.*` packages and legacy `IBurpExtenderCallbacks` (`Ze7n`) are unobfuscated, revealing external interface bridges.

---

## 2. Component-by-Component Technical Analysis

---

### Component 1: Target Subsystem (Sitemap & Scope Engine)

#### 1. Scope & Functional Overview
The Target subsystem manages the hierarchical domain sitemap, vulnerability advisory display, and target scope configuration rules.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6563.java` (provides `targetToolFrameProvider` and `targetToolTabFlasher`).
- **Sitemap Navigation**: `BurpClass6563` manages the dual split-pane containing the domain `JTree` and issue grid.
- **Scope Rule Processor**: `BurpClass9061.java` (executes URL prefix rule evaluations against target URLs).

#### 3. UI Component Addressability Map (`setName()`)
- `siteMapTree`: Left hierarchical domain tree (`JTree`).
- `siteMapContentsTable`: Top-right request/response grid (`JTable`).
- `siteMapIssueDisplayPanel`: Bottom-right vulnerability display pane.
- `siteMapIssueAdvisoryPanel`: Vulnerability advisory reader (`siteMapIssueAdvisoryAiEnhancementBar`).
- `includePrefixRulesPanel`: Table & control panel for target in-scope URL prefix rules.
- `excludePrefixRulesPanel`: Table & control panel for target out-of-scope URL prefix rules.

#### 4. Underlying Mechanics & Data Flow
When traffic passes through the proxy or crawler, URLs are evaluated against `BurpClass9061` scope rules. In-scope items populate the `JTree` domain model. Selecting a node queries the underlying SQLite metadata index to populate `siteMapContentsTable`.

---

### Component 2: Proxy Subsystem (Intercept, History & WebSockets)

#### 1. Scope & Functional Overview
The Proxy subsystem acts as a non-blocking HTTP/S and WebSocket proxy, handling dynamic TLS interception, request/response editing, traffic history logging, and match-and-replace rules.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6552.java` (provides `proxyToolFrameProvider` and `proxyToolTabFlasher`).
- **Legacy Callbacks**: `Ze7n.java` (`getProxyHistory`, `sendToProxy`).
- **Proxy Intercept Engine**: `BurpClass6552` binds intercept gates and socket listeners.

#### 3. UI Component Addressability Map (`setName()`)
- `proxyForwardRequestButton`: Forwards held request (`BurpClass6552`).
- `proxyDropRequestButton`: Drops held request (`BurpClass6552`).
- `proxyInterceptToggleButton`: Intercept Is ON/OFF toggle button.
- `proxyForwardOptionsButton`: Action dropdown menu for intercepted traffic.
- `proxyHistoryTable`: HTTP traffic history data grid (`JTable`).
- `proxyHistoryFilterBar`: History display filter popover trigger.

#### 4. Underlying Mechanics & Data Flow
1. **Netty IO Pipeline**: Non-blocking sockets accept client traffic on default port `8080`.
2. **Dynamic TLS Interceptor**: Mints host certificates signed by the `PortSwigger CA` root key.
3. **Intercept Gate**: If Intercept is ON and traffic matches rules, transaction holds in GUI queue; otherwise streams upstream.
4. **Logging**: Writes raw HTTP bytes to append-only binary project storage (`.burp.log`) and updates SQLite index.

---

### Component 3: Scanner Engine (Automated Crawl & Audit Subsystem)

#### 1. Scope & Functional Overview
The Scanner engine is an automated vulnerability detection pipeline combining headless crawling, insertion point expansion, active/passive checks, BCheck DSL execution, and issue deduplication.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6553.java` (provides `scannerToolFrameProvider` and `scannerToolTabFlasher`).
- **Insertion Point Generator**: `Zuq.java` (1,479 lines - parameter expansion & relocation).
- **Lazy Check Dispatcher**: `Zcud.java` (135 lines - 2-stage lazy check pre-filtering).
- **Issue Taxonomy Enum**: `Zcot.java` (183 pre-defined issue type constants).
- **Audit Phase Enum**: `Zefx.java` (7 audit phase constants).
- **Audit Item State Machine**: `Zq5.java` (15 status states).
- **Resilience Circuit Breaker**: `Zgff.java` (2-level error circuit breaker).
- **Issue Deduplicator**: `Zbvp.java` (Chain-of-responsibility dedup) & `Zby4.java` (CRC32 signature generator).
- **BCheck DSL Interpreter**: `Zht9.java` (embeds BCheck v2-beta grammar).

#### 3. UI Component Addressability Map (`setName()`)
- `auditItemsTable`: Active audit queue table.
- `auditItemsTableInsertionPointsViewToggle`: Toggles detailed insertion point view in queue table.
- `customScanCheckTesterTestCaseTable`: Custom scan check tester table.
- `customScanCheckTesterTestCaseTableContextMenuEnableOption`: Context menu option to enable test case.
- `customScanCheckTesterTestCaseTableContextMenuDisableOption`: Context menu option to disable test case.

#### 4. Underlying Mechanics & Data Flow
```
HTTP Request ---> [ Zuq Insertion Point Generator ] (Expands Query, Body, Headers, REST paths)
                         |
                         v
                  [ Zcud Lazy Check Dispatcher ] (Stage 1: Config match; Stage 2: Tech pre-filter)
                         |
                         v
                  [ Check Execution / BCheck ] (Sends payload mutations, evaluates response)
                         |
                         v
                  [ Zbvp Issue Consolidation ] (Calculates Zby4 CRC32, merges duplicate findings)
                         |
                         v
                  Target Sitemap & Dashboard Feed
```

---

### Component 4: Intruder Subsystem (Custom Payload Attack Engine)

#### 1. Scope & Functional Overview
Intruder performs customized automated attacks against HTTP applications, supporting multiple attack modes, payload generators, and response extraction rules.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6045.java` (provides `intruderToolFrameProvider` and `intruderToolTabFlasher`).

#### 3. UI Component Addressability Map (`setName()`)
- `intruderAttackFrameResultItemTabBar`: Tab bar for active attack result windows.
- `intruderAttackConfigSettingsStoreRequests`: Checkbox setting to store request logs per attack.
- `intruderAttackConfigSettingsStoreResponses`: Checkbox setting to store response logs per attack.
- `intruderAttackConfigSettingsMakeUnmodifiedBaselineRequest`: Toggle for sending unmodified baseline request.

#### 4. Underlying Mechanics & Data Flow
Supports 4 attack modes: **Sniper** (1 payload set, sequential positions), **Battering Ram** (1 payload set, identical positions), **Pitchfork** (N payload sets, parallel positions), **Cluster Bomb** (N payload sets, Cartesian product). Positions are marked using `§...§` syntax.

---

### Component 5: Repeater Subsystem (Manual Request Manipulation)

#### 1. Scope & Functional Overview
Repeater enables manual modification and re-issuance of individual HTTP requests with real-time response rendering and detailed inspector analysis.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `RepeaterModule.java` (provides `repeaterToolFrameProvider` and `repeaterToolTabFlasher`).
- **Tab Manager**: `BurpClass10595.java` (`secondarySuiteTabBar`).

#### 3. UI Component Addressability Map (`setName()`)
- `repeaterSendButton`: Main action button to dispatch request.
- `repeaterSendOptionsButton`: Send options menu dropdown.
- `repeaterConfigurationGlobalMenuItemEnableH1ConnectionReuse`: Toggle for HTTP/1.1 connection reuse.
- `repeaterConfigurationGlobalMenuItemEnableH2ConnectionReuse`: Toggle for HTTP/2 connection reuse.
- `repeaterConfigurationGlobalMenuItemUpdateContentLength`: Toggle for auto updating Content-Length header.

#### 4. Underlying Mechanics & Data Flow
User edits request in `RSyntaxTextArea` editor pane. Clicking `repeaterSendButton` dispatches the request over an HTTP/1.1 or HTTP/2 connection. Connection options (`EnableH1ConnectionReuse` / `EnableH2ConnectionReuse`) determine socket reuse. Response streams to the right editor pane and updates `inspectorMainPanel`.

---

### Component 6: Collaborator Subsystem (Out-of-Band Interaction Testing)

#### 1. Scope & Functional Overview
Collaborator detects asynchronous/out-of-band vulnerabilities (Blind SSRF, Blind RCE, Blind XXE) by issuing unique domain payloads and polling a remote service for DNS, HTTP, and SMTP interactions.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6040.java` (provides `collaboratorToolTabFlasher` and `collaboratorToolFrameProvider`).

#### 3. UI Component Addressability Map (`setName()`)
- `collaboratorCommunityUpsellPanel`: Information and configuration panel for Collaborator service.

#### 4. Underlying Mechanics & Data Flow
Generates subdomains targeting `*.burpcollaborator.net` (or private Collaborator instances). Polling worker periodically queries the Collaborator server via HTTPS to retrieve captured interaction records (DNS lookups, HTTP requests, SMTP connections) and maps them back to active scan items.

---

### Component 7: Sequencer Subsystem (Token Randomness Analysis)

#### 1. Scope & Functional Overview
Sequencer analyzes the randomness and entropy of session tokens, CSRF tokens, and password reset hashes generated by target applications.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6562.java` (provides `sequencerToolFrameProvider` and `sequencerToolTabFlasher`).

#### 3. UI Component Addressability Map (`setName()`)
- `sequencerToolTabFlasher`: Tab flasher token provider for Sequencer.

#### 4. Underlying Mechanics & Data Flow
Captures thousands of sample tokens from HTTP responses (via cookie headers or regex-extracted body parameters). Applies FIPS 140-2 statistical randomness tests (monobit, poker, runs, long runs) and bit-level character distribution entropy calculations.

---

### Component 8: Comparer Subsystem (Visual & Byte Diff Engine)

#### 1. Scope & Functional Overview
Comparer performs visual word-level or byte-level diffing between two HTTP requests, responses, or text blobs.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6041.java` (provides `compareToolFrameProvider` and `comparerToolTabFlasher`).

#### 3. UI Component Addressability Map (`setName()`)
- `comparerToolTabFlasher`: Tab flasher token provider for Comparer.

#### 4. Underlying Mechanics & Data Flow
Takes Item A and Item B input strings/byte arrays. Calculates edit distance using an optimized Myers diff algorithm. Highlights additions (green), modifications (yellow), and deletions (red) in a dual synchronized scroll pane.

---

### Component 9: Logger Subsystem (Unified Traffic Log & Query Engine)

#### 1. Scope & Functional Overview
Logger provides a historical record of all HTTP traffic generated across all tools (Proxy, Scanner, Repeater, Intruder, Extensions).

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6018.java` (provides `loggerToolFrameProvider` and `loggerToolTabFlasher`).

#### 3. UI Component Addressability Map (`setName()`)
- `loggerToolFrameProvider`: Frame provider method for Logger.

#### 4. Underlying Mechanics & Data Flow
Subscribes to global HTTP event bus. Aggregates transactions into a virtualized data table. Supports real-time regex filtering by tool origin, status code, and header values.

---

### Component 10: Organiser Subsystem (Request Collection & Storage)

#### 1. Scope & Functional Overview
Organiser allows security testers to store, annotate, and organize notable HTTP requests for manual review and reporting.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6038.java` (provides `organiserToolFrameProvider` and `organiserToolTabFlasher`).

#### 3. UI Component Addressability Map (`setName()`)
- `organiserCollectionNewMenuItem`: Context menu action to create a new collection.
- `organiserCollectionRenameMenuItem`: Action to rename collection.
- `organiserCollectionCopyLinkMenuItem`: Action to copy request link.
- `organiserCollectionUnlinkMenuItem`: Action to remove request from collection.

#### 4. Underlying Mechanics & Data Flow
Stores request pointers in SQLite database under named collection tags. Allows users to attach custom Markdown notes and status flags to individual request items.

---

### Component 11: Extender Subsystem & BApp Store (Extension Engine)

#### 1. Scope & Functional Overview
Extender manages third-party extensions (Java, Python via Jython, Ruby via JRuby) and provides access to the BApp Store extension catalog.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6024.java` (provides `extenderToolFrameProvider` and `extenderToolTabFlasher`).
- **Legacy Extension Bridge**: `Ze7n.java` (implements pre-Montoya `IBurpExtenderCallbacks`).

#### 3. UI Component Addressability Map (`setName()`)
- `extenderToolFrameProvider`: Frame provider method for Extender.

#### 4. Underlying Mechanics & Data Flow
Loads extension `.jar`, `.py`, or `.rb` files into isolated `URLClassLoader` sandboxes. Exposes legacy `IBurpExtenderCallbacks` (`Ze7n`) and modern `burp.api.montoya` interfaces to extensions.

---

### Component 12: Dashboard Subsystem (Task Progress & Event Feed)

#### 1. Scope & Functional Overview
Dashboard serves as the central command view showing active scan tasks, task progress metrics, vulnerability activity feeds, and system event logs.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `DashboardModule.java` (provides `dashboardToolFrameProvider` and `dashboardToolTabFlasher`).
- **Task View Adapter**: `Zrb9.java` (renders 5 scan task shapes into UI components).

#### 3. UI Component Addressability Map (`setName()`)
- `dashboardToolFrameProvider`: Frame provider method for Dashboard.

#### 4. Underlying Mechanics & Data Flow
Subscribes to Task Engine event bus. Renders task progress cards, pause/resume queue controls, system event log tables, and real-time vulnerability discovery feeds.

---

### Component 13: Burp AI & Bambda Subsystem (AI Gateway & Scripting)

#### 1. Scope & Functional Overview
Burp AI provides AI-assisted vulnerability explanation and automated login generation via PortSwigger's AI Gateway (`Hakawai`). Bambdas allow users to write custom Java expressions for HTTP table filtering.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Guice Module**: `BurpClass6039.java` (provides `burpAiToolFrameProvider`).
- **AI Endpoints Interface**: `Zeao.java` (interface for 6 AI endpoint URIs).
- **Production AI Provider**: `Zhag.java` (`UriHakawaiEndpoints` resolving `https://ai.portswigger.net`).
- **Testing AI Provider**: `Zidx.java` (`TestingHakawaiEndpoints` reading system property `burp.testing.hakawai.url`).
- **AI Endpoints Resolver**: `Zb50.java` (`HakawaiEndpointsProvider`).
- **AI HTTP Client**: `Zbsu.java` (`HakawaiHttpClient`).
- **AI Attack Runner**: `Zbp4.java` (`ExploreAttackRunner`).
- **MCP Agentic Tools**: `burp.agentic.Zba` (`RunSkillScriptTool`), `burp.agentic.Zca` (`SkillScriptExecutor`).

#### 3. UI Component Addressability Map (`setName()`)
- `aiCreditsBuyCreditsButton`: Button to purchase AI credits (`BurpClass0868`).
- `acInformationLabel`: Label showing available AI credit balance (`BurpClass0868`).
- `acErrorLabel`: Error label for AI balance sync issues (`BurpClass0868`).
- `acRetryAnchor`: Retry link for failed AI requests (`BurpClass0868`).
- `bambdaLoadButton`: Button to load Bambda filter script.
- `bambdaCollaboratorCallbackToggle`: Toggle for Bambda Collaborator interaction.
- `bambdaLibraryDialog`: Dialog for Bambda script template library.

#### 4. Hakawai AI Gateway Endpoints (`Zeao` / `Zhag`)

| Method | Inferred Role | PortSwigger AI API Path |
|---|---|---|
| `ZE()` | `burpBase()` | `burp/` |
| `Zp()` | `explainThis()` | `ai/hakawai-explain-this/api/v1/` |
| `Z_()` | `exploreService()` | `ai/hakawai-explore-service/api/v1/` |
| `ZG()` | `recordedLoginGenerator()` | `ai/hakawai-recorded-login-generator/api/v1/` |
| `Zn()` | `brokenAccessControl()` | `ai/hakawai-broken-access-control/api/v1/` |
| `ZF()` | `montoyaService()` | `/ai/hakawai-montoya-service/api/v1/` |

---

### Component 14: Project Persistence & Storage Subsystem

#### 1. Scope & Functional Overview
Manages disk storage for project files (`.burp`), combining binary append-only request/response logs with an indexed SQLite metadata store.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Project Store Engine**: Manages `.burp` container files and transaction logs.

#### 3. Underlying Mechanics & Data Flow
Raw HTTP bytes write to an append-only `.burp.log` file. SQLite metadata database indexes transactions (`id`, `url`, `method`, `status`, `log_offset`, `log_length`). UI components read 32-byte struct pointers into the log file, eliminating RAM duplicate buffer overhead.

---

### Component 15: Montoya Public API Extension Bridge Subsystem

#### 1. Scope & Functional Overview
Exposes official, unobfuscated extension interfaces (`burp.api.montoya.*`) to third-party extensions while bridging calls internally to obfuscated `BurpClass####` core types.

#### 2. Key Deobfuscated & Obfuscated Classes
- **Montoya Public API Packages**: `burp.api.montoya.proxy`, `scanner`, `repeater`, `intruder`, `ui`, `http`, `websocket`, `persistence`.

#### 3. Underlying Mechanics & Data Flow
Extensions register via `MontoyaApi` entry point. Extension calls pass through wrapper facades (`Zcps` for scanner, `Ze7n` for legacy callbacks) which translate public API parameters into internal core engine data types.

---

## 3. Comprehensive Component Synthesis Matrix

| # | Component Name | Guice UI Module / Class | Primary Backend Engine Class | UI Addressability Test IDs (`setName`) | Key Subsystem Contract |
|---|---|---|---|---|---|
| 1 | **Target** | `BurpClass6563.java` | `BurpClass9061.java` | `siteMapTree`, `siteMapContentsTable`, `includePrefixRulesPanel` | Domain Sitemap & Scope Evaluator |
| 2 | **Proxy** | `BurpClass6552.java` | `BurpClass6552.java` | `proxyForwardRequestButton`, `proxyDropRequestButton`, `proxyHistoryTable` | Netty Intercept & TLS CA Minter |
| 3 | **Scanner** | `BurpClass6553.java` | `Zuq.java`, `Zcud.java`, `Zcot.java` | `auditItemsTable`, `customScanCheckTesterTestCaseTable` | Insertion Point Expansion & 183 Issue Catalog |
| 4 | **Intruder** | `BurpClass6045.java` | `BurpClass6045.java` | `intruderAttackFrameResultItemTabBar`, `intruderAttackConfigSettings...` | 4 Attack Modes & `§...§` Payload Markers |
| 5 | **Repeater** | `RepeaterModule.java` | `RepeaterModule.java` | `repeaterSendButton`, `repeaterConfigurationGlobalMenuItem...` | Dual HTTP Editor & Connection Reuse |
| 6 | **Collaborator** | `BurpClass6040.java` | `BurpClass6040.java` | `collaboratorCommunityUpsellPanel` | Out-of-band DNS/HTTP/SMTP Polling Engine |
| 7 | **Sequencer** | `BurpClass6562.java` | `BurpClass6562.java` | `sequencerToolTabFlasher` | Token Sampling & FIPS 140-2 Randomness Tests |
| 8 | **Comparer** | `BurpClass6041.java` | `BurpClass6041.java` | `comparerToolTabFlasher` | Visual Myers Diff (Words vs. Bytes) |
| 9 | **Logger** | `BurpClass6018.java` | `BurpClass6018.java` | `loggerToolFrameProvider` | Multi-tool Unified Traffic Stream Log |
| 10 | **Organiser** | `BurpClass6038.java` | `BurpClass6038.java` | `organiserCollectionNewMenuItem`, `organiserCollectionCopyLink...` | Stored Request Collections & Notes |
| 11 | **Extender** | `BurpClass6024.java` | `Ze7n.java` | `extenderToolFrameProvider` | Extension Classloader Sandbox & BApp Store |
| 12 | **Dashboard** | `DashboardModule.java` | `Zrb9.java` | `dashboardToolFrameProvider` | Task Engine Progress Cards & Event Feed |
| 13 | **Burp AI & Bambda** | `BurpClass6039.java` | `Zb50.java`, `Zhag.java`, `Zbsu.java` | `aiCreditsBuyCreditsButton`, `acInformationLabel`, `bambdaLoadButton` | Hakawai AI Gateway & Dynamic Java Compiler |
| 14 | **Persistence** | N/A | Storage Engine Core | N/A | Append-Only Log & SQLite Metadata Index |
| 15 | **Montoya API** | N/A | `burp.api.montoya.*` | N/A | Unobfuscated Public Plugin Extension Bridge |
