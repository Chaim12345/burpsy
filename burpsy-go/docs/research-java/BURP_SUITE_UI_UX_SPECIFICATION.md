# Burp Suite Professional UI/UX Implementation Specification
**Document Version:** 1.0.0  
**Target Platform:** Cross-Platform Desktop (Java Swing / FlatLaf L&F)  
**Reference Architecture:** Burp Suite Professional v2026.7.1 (Deobfuscated & Reverse Engineered)  
**Authoritative Reference Sources:** `out/clean/renamed_final`, `out/strings/map_root.tsv`, `out/burp/theme/`, `UI_FILES_MAP.md`

---

## 1. Executive Summary & Architectural Principles

This document serves as the complete, production-grade UI/UX Implementation Specification for rebuilding the Burp Suite desktop client interface. Every layout, control, color token, interaction pattern, and tool view specified herein is grounded in the reverse-engineered source tree.

### 1.1 Core Architectural Requirements
1. **Component Addressability via `setName()`**: Every interactive UI component (buttons, text fields, tables, dialogs, menu items) **MUST** invoke `setName("camelCaseUniqueName")` during construction. This enables automated UI testing, component lookup, and accessibility mapping.
2. **Modular Tool Architecture (Guice Dependency Injection)**: Each application tool (`Proxy`, `Repeater`, `Intruder`, etc.) operates as an independent UI module bound via Guice (`com.google.inject.AbstractModule`). Tools expose a `ToolFrameProvider` (returns the root tool UI container) and a `ToolTabFlasher` (handles tab highlight/attention animations).
3. **FlatLaf-Based Theme System**: The visual skin is built on FlatLaf (Light/Dark variants), customized via JSON theme descriptors (`LightTheme.json`, `DarkTheme.json`, `BurpLaf.properties`) using a hierarchical **Swatch → Palette → UI Color** token resolution model.
4. **Decoupled Business Logic & Views**: Views observe backend state via reactive listeners (`BurpClass6815` table models, event dispatchers). No business logic resides directly in Swing event handlers.

---

## 2. Design System & Visual Foundations

### 2.1 Color Token Architecture

The design system resolves colors through 3 distinct layers:
1. **Swatches (Raw Hex Values)**: 10 base swatches (`orange`, `blue`, `red`, `purple`, `teal`, `magenta`, `green`, `yellow`, `black`, `white`), each containing a core color and up to 8 shades (`#RRGGBB` or `#RRGGBBAA`).
2. **Palettes (Functional Color Sets)**: 9 fixed functional palettes mapping swatches to semantic roles:
   - `mono`: Neutral grayscale for backgrounds, surfaces, and borders.
   - `primary`: Core brand accent color (Burp Orange `#E55B00` / `#FF6600`).
   - `secondary`: Supporting interface actions.
   - `tertiary`: Accent highlights & badges.
   - `error`: Destructive actions & critical vulnerability alerts (`#D32F2F`).
   - `warning`: Cautionary alerts & medium vulnerability indicators (`#F57C00`).
   - `info`: Informational tags & low vulnerability indicators (`#1976D2`).
   - `success`: Completed tasks & pass indicators (`#388E3C`).
   - `hint`: Subtle inline helper text (`#757575`).
3. **UI Tokens (Element-Specific Bindings)**:

| UI Token | Description | Light Theme Default | Dark Theme Default |
|---|---|---|---|
| `Panel.background` | Main container surface background | `#FFFFFF` | `#1E1E1E` |
| `Table.background` | Data grid background | `#FFFFFF` | `#252526` |
| `Table.alternateRowColor` | Zebra striping row background | `#F9F9F9` | `#2D2D2E` |
| `Table.selectionBackground` | Selected row highlight | `#007ACC` | `#094771` |
| `Table.selectionForeground` | Selected row text | `#FFFFFF` | `#FFFFFF` |
| `Editor.background` | Code/HTTP message editor surface | `#F5F5F5` | `#1E1E1E` |
| `Editor.lineNumbers` | Line number margin text | `#A0A0A0` | `#5A5A5A` |
| `Border.color` | Component & split pane border | `#E0E0E0` | `#3C3C3C` |
| `Tab.selectedBackground` | Active tab background indicator | `#FFFFFF` | `#2D2D2D` |
| `Tab.selectedForeground` | Active tab label text | `#E55B00` | `#FF6600` |

### 2.2 Typography System

Hierarchy definitions (configured in `BurpClass4018` and `BurpLaf.properties`):

| Text Style | Font Family | Size | Weight | Line Height | Purpose |
|---|---|---|---|---|---|
| `Display / Header` | System UI (Segoe UI / Roboto / San Francisco) | 16pt | SemiBold (600) | 1.3 | Modal titles, key metric counters |
| `Section Title` | System UI | 13pt | SemiBold (600) | 1.3 | Panel headers, tab labels |
| `Body / Regular` | System UI | 12pt | Regular (400) | 1.4 | General UI text, form labels |
| `Caption / Helper` | System UI | 11pt | Regular (400) | 1.3 | Subtext, status bar items |
| `Code / Monospace` | JetBrains Mono / Consolas / Menlo | 12pt | Regular (400) | 1.45 | HTTP Request/Response headers & bodies |

### 2.3 UI Primitives Library

#### 1. Container Panel (`ViewComponent` / `BurpClass9399`)
- **Inheritance**: Extends `javax.swing.JPanel`.
- **Behavior**: Auto-adjusts background to `Panel.background`, enforces `TitledBorder` title fonts to `Section Title` style, and handles dynamic padding (`BorderLayout(10, 0)`).
- **Addressability**: `viewComponent.setName("uniquePanelName")`.

#### 2. Labeled Sub-Control (`UIComponent` / `BurpClass11754`)
- **Composition**: Labeled input wrapper combining a `JLabel` (`BurpClass5083`), an input field (`JTextField` / `JComboBox` / `JCheckBox`), and an optional inline validation label.

#### 3. Data Grid / Table (`BurpClass6815` & `TableColumnModel`)
- **Behavior**: Virtualized row renderer supporting 100k+ rows without memory pressure.
- **Controls**: Column reordering, click-to-sort, right-click header column toggle popover, zebra striping, search highlight overlay.

#### 4. Dual-Pane HTTP Editor (`EditorPane` / `RSyntaxTextArea`)
- **Layout**: Split-pane layout with Left = Request (editable or read-only), Right = Response (read-only).
- **Features**: Line numbers, caret position tracking (Line/Col/Bytes), syntax highlighting for HTTP headers, JSON, XML, HTML, Raw Hex viewer mode toggle, auto-wrap toggle.

---

## 3. Global Window Shell & Navigation Architecture

```
+-----------------------------------------------------------------------------------+
|  Burp Suite Professional - [Project: Security_Assessment_2026]                     | [---][square][X]
+-----------------------------------------------------------------------------------+
|  [Menu Bar: Suite  Target  Proxy  Scanner  Intruder  Repeater  Options  Help]     |
+-----------------------------------------------------------------------------------+
|  MAIN TABS:                                                                       |
|  [ Dashboard ] [ Target ] [ Proxy ] [ Scanner ] [ Intruder ] [ Repeater ] ... [+] |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|                               ( Active Tool Workspace )                           |
|                                                                                   |
+-----------------------------------------------------------------------------------+
|  STATUS BAR: Tasks: 2 Running | Memory: 420MB/2048MB | Listener: 127.0.0.1:8080 ON | [AI Credits: 150]
+-----------------------------------------------------------------------------------+
```

### 3.1 Suite Root Frame (`suiteFrame` / `BurpClass10400`)
- **Component Name**: `setName("suiteFrame")`.
- **Structure**: `JFrame` with standard OS title bar, custom embedded menu bar, top primary tab container (`secondarySuiteTabBar`), central active tool container, and bottom status bar.

### 3.2 Global Command Palette (`commandPaletteMenuItem`)
- **Trigger**: `Ctrl + Shift + P` (or `Cmd + Shift + P` on macOS).
- **UI Spec**: Centered floating modal overlay with auto-focused search input (`setName("commandPaletteSearchInput")`) and fuzzy-matched result list (`setName("commandPaletteResultList")`). Supports navigating to tabs, executing actions, or toggling settings.

### 3.3 AI Credits & Account Status Badge (`acPopupTitle` / `BurpClass0868`)
- **Location**: Top-right header / bottom-right status bar.
- **Elements**:
  - `aiCreditsBuyCreditsButton` (`setName("aiCreditsBuyCreditsButton")`): Primary accent button opening purchase modal.
  - `acInformationLabel` (`setName("acInformationLabel")`): Displays active credit balance (e.g. "150 AI Credits Available").
  - `acErrorLabel` (`setName("acErrorLabel")`): Error alert for network sync issues with retry anchor (`setName("acRetryAnchor")`).

---

## 4. Detailed Tool-by-Tool UI/UX Specifications

### 4.1 Dashboard Tool (`DASHBOARD`)
- **Guice Module**: `DashboardModule.java` (`dashboardToolFrameProvider`, `dashboardToolTabFlasher`).
- **Layout**: 3-Column Masonry Dashboard Grid.
- **Panel 1 — Task Engine Status Panel**:
  - `setName("dashboardTasksPanel")`: Displays active Crawl & Audit tasks. Progress bar, items discovered count, status (Running/Paused), Action buttons: Pause All, Resume All, New Task button (`setName("dashboardNewTaskButton")`).
- **Panel 2 — Realtime Event Log**:
  - `setName("dashboardEventLogTable")`: Table columns: Timestamp, Severity Icon, Service, Message.
- **Panel 3 — Issue Activity Feed**:
  - `setName("dashboardIssueActivityPanel")`: Real-time feed of vulnerabilities flagged by Scanner.

### 4.2 Target Tool (`TARGET`)
- **Guice Module**: `BurpClass6563.java` (`targetToolFrameProvider`, `targetToolTabFlasher`).
- **Sub-Tabs**: `Site map`, `Scope settings`.
- **Site Map View**:
  - **Left Pane**: Hierarchical domain tree (`JTree`, `setName("siteMapTree")`).
  - **Top Right Pane**: Selected node request/response items table (`setName("siteMapContentsTable")`).
  - **Bottom Right Pane**: Selected vulnerability advisory reader (`setName("siteMapIssueAdvisoryPanel")`) with AI enhancement action bar (`setName("siteMapIssueAdvisoryAiEnhancementBar")`).
- **Scope Settings View**:
  - `setName("includePrefixRulesPanel")`: Table & controls for "Target In-Scope URL Prefixes" (Add, Edit, Remove buttons).
  - `setName("excludePrefixRulesPanel")`: Table & controls for "Target Out-of-Scope URL Prefixes".

### 4.3 Proxy Tool (`PROXY`)
- **Guice Module**: `BurpClass6552.java` (`proxyToolFrameProvider`, `proxyToolTabFlasher`).
- **Sub-Tabs**: `Intercept`, `HTTP history`, `WebSockets history`, `Proxy settings`.
- **Intercept Sub-tab**:
  - **Action Bar**: Forward Request button (`setName("proxyForwardRequestButton")`), Drop button (`setName("proxyDropRequestButton")`), Intercept Is ON/OFF Toggle Button (`setName("proxyInterceptToggleButton")`), Action Menu Dropdown (`setName("proxyForwardOptionsButton")`).
  - **Main View**: Editable HTTP Request message view.
  - **Sidebar**: Inspector Pane (`setName("inspectorOverviewView")`, `setName("inspectorSelectionSection")`).
- **HTTP History Sub-tab**:
  - **Filter Bar**: `setName("proxyHistoryFilterBar")` — Status filter popover trigger button.
  - **History Table**: `setName("proxyHistoryTable")` — Columns: `#`, `Host`, `Method`, `URL`, `Status`, `Length`, `MIME`, `Extension`, `Title`, `IP`, `Time`.
  - **Detail View**: Split-pane below history table showing Request and Response editors.

### 4.4 Scanner Tool (`SCANNER`)
- **Guice Module**: `BurpClass6553.java` (`scannerToolFrameProvider`, `scannerToolTabFlasher`).
- **Audit Items View**:
  - `setName("auditItemsTable")`: Active audit queue items with progress percentage, status, and insertion point toggle button (`setName("auditItemsTableInsertionPointsViewToggle")`).
- **Custom Scan Checks Tester**:
  - `setName("customScanCheckTesterTestCaseTable")`: Table with context menu options: Enable (`setName("customScanCheckTesterTestCaseTableContextMenuEnableOption")`), Disable (`setName("customScanCheckTesterTestCaseTableContextMenuDisableOption")`), Duplicate (`setName("customScanCheckTesterTestCaseTableContextMenuDuplicateOption")`), Remove (`setName("customScanCheckTesterTestCaseTableContextMenuRemoveOption")`).

### 4.5 Intruder Tool (`INTRUDER`)
- **Guice Module**: `BurpClass6045.java` (`intruderToolFrameProvider`, `intruderToolTabFlasher`).
- **Sub-Tabs**: `Target`, `Positions`, `Payloads`, `Options`.
- **Positions Tab**:
  - Attack Type Dropdown: `Sniper`, `Battering ram`, `Pitchfork`, `Cluster bomb`.
  - HTTP Template Editor: Highlights payload markers wrapped in `§` (e.g. `§password§`). Action buttons: Add `§`, Clear `§`, Auto `§`.
- **Payloads Tab**:
  - Payload Set selector dropdown.
  - Payload Type selector (Simple list, Numbers, Brute forcer, Null payloads, Custom iterator).
  - Payload Options list box with Add, Load from file, Remove, Clear buttons.
- **Options Tab**:
  - Request Headers settings (`setName("intruderAttackConfigSettingsMakeUnmodifiedBaselineRequest")`).
  - Grep - Match & Grep - Extract rules tables.
- **Attack Results Window**:
  - Tabbed window spawned per attack (`setName("intruderAttackFrameResultItemTabBar")`). Result table showing Payload, Status, Length, Error, Time.

### 4.6 Repeater Tool (`REPEATER`)
- **Guice Module**: `RepeaterModule.java` (`repeaterToolFrameProvider`, `repeaterToolTabFlasher`).
- **Tab Manager**: `setName("secondarySuiteTabBar")` — Tabbed workspace allowing multiple isolated request/response pairs.
- **Control Bar**:
  - Send Button (`setName("repeaterSendButton")`): Primary action button.
  - Cancel Button: Enabled during active request execution.
  - Target Host / Port / Protocol configuration popover.
  - Settings Gear Popover: Connection options (`setName("repeaterConfigurationGlobalMenuItemEnableH1ConnectionReuse")`, `setName("repeaterConfigurationGlobalMenuItemEnableH2ConnectionReuse")`, `setName("repeaterConfigurationGlobalMenuItemUpdateContentLength")`).
- **Editor Area**:
  - Split Pane: Left = Request Editor, Right = Response Editor.
  - Sidebar Inspector: Collapsible right drawer (`inspectorMainPanel`).

### 4.7 Collaborator Tool (`COLLABORATOR`)
- **Guice Module**: `BurpClass6040.java` (`collaboratorToolFrameProvider`, `collaboratorToolTabFlasher`).
- **Controls**: "Generate Payload" button, "Poll Now" button, Auto-poll checkbox.
- **Interaction Table**: Columns: `Interaction ID`, `Type` (DNS, HTTP, SMTP), `Client IP`, `Time`.
- **Info Panel**: `setName("collaboratorCommunityUpsellPanel")` — Explanatory panel for Collaborator usage.

### 4.8 Sequencer Tool (`SEQUENCER`)
- **Guice Module**: `BurpClass6562.java` (`sequencerToolFrameProvider`, `sequencerToolTabFlasher`).
- **Views**:
  - Select Request source (from History/Repeater).
  - Token Location selector (Cookie name, Form field, Custom regex match).
  - Live Capture control bar (Start capture, Stop, Progress bar, Sample count).
  - Analysis Results Panel (Overall entropy rating, FIPS 140-2 test passes, bit-level randomness visual chart).

### 4.9 Comparer Tool (`COMPARER`)
- **Guice Module**: `BurpClass6041.java` (`compareToolFrameProvider`, `comparerToolTabFlasher`).
- **Inputs**: Direct text paste area or selection from HTTP History / Repeater (Item A vs Item B).
- **Diff View**: Dual-pane text view with sync-scrolling. Mode buttons: `Words` vs `Bytes`. Color legend: Added (Green), Modified (Yellow), Deleted (Red).

### 4.10 Logger Tool (`LOGGER`)
- **Guice Module**: `BurpClass6018.java` (`loggerToolFrameProvider`, `loggerToolTabFlasher`).
- **Layout**: Top = Unified traffic log table across all tools, Bottom = Request/Response dual-editor viewer. Filter bar supporting regex, tool-source filters, status code filters.

### 4.11 Organiser Tool (`ORGANISER`)
- **Guice Module**: `BurpClass6038.java` (`organiserToolFrameProvider`, `organiserToolTabFlasher`).
- **Table**: Collection of stored requests for offline analysis.
- **Context Actions**: New Collection (`setName("organiserCollectionNewMenuItem")`), Rename (`setName("organiserCollectionRenameMenuItem")`), Copy Link (`setName("organiserCollectionCopyLinkMenuItem")`), Unlink (`setName("organiserCollectionUnlinkMenuItem")`).

### 4.12 Extender Tool / BApp Store (`EXTENDER`)
- **Guice Module**: `BurpClass6024.java` (`extenderToolFrameProvider`, `extenderToolTabFlasher`).
- **Sub-Tabs**: `Extensions`, `BApp Store`, `Options`, `APIs`.
- **Extensions View**: Installed extension list with Loaded checkbox, Name, Type (Java/Python/Ruby), Output console, Error console.

### 4.13 Burp AI & Bambda Editor (`BURP_AI`)
- **Bambda Editor Modal**:
  - Syntax-highlighted code editor for Java-based Bambda filter expressions.
  - Buttons: Load Bambda (`setName("bambdaLoadButton")`), Toggle Collaborator callback (`setName("bambdaCollaboratorCallbackToggle")`), Open Bambda Library (`setName("bambdaLibraryDialog")`).

---

## 5. Universal Context Menus & Keyboard Navigation

### 5.1 Universal Context Menu ("Send To..." Matrix)
Invoked via Right-Click on any HTTP Message editor or History table row:

```
+---------------------------------------------------+
|  Send to Repeater                       Ctrl+R    |
|  Send to Intruder                       Ctrl+I    |
|  Send to Organiser                      Ctrl+O    |
|  Do active scan                                   |
|  -----------------------------------------------  |
|  Copy URL                                         |
|  Copy as cURL command                             |
|  Copy request to file...                          |
|  -----------------------------------------------  |
|  Engagement tools                     >           |
|  Change request method                            |
|  Change body encoding                 >           |
|  -----------------------------------------------  |
|  Show response in browser                         |
|  Request in browser                   >           |
+---------------------------------------------------+
```

### 5.2 Global Keyboard Shortcuts Matrix

| Action | Windows / Linux Hotkey | macOS Hotkey | Scope |
|---|---|---|---|
| Send to Repeater | `Ctrl + R` | `Cmd + R` | HTTP Message / Table Row |
| Send to Intruder | `Ctrl + I` | `Cmd + I` | HTTP Message / Table Row |
| Send to Organiser | `Ctrl + O` | `Cmd + O` | HTTP Message / Table Row |
| Command Palette | `Ctrl + Shift + P` | `Cmd + Shift + P` | Global |
| Forward Intercepted Msg | `Ctrl + F` | `Cmd + F` | Proxy Intercept |
| Send Repeater Request | `Ctrl + Space` | `Cmd + Space` | Repeater Tab |
| Switch Next Main Tab | `Ctrl + Alt + Right` | `Cmd + Alt + Right` | Global |
| Switch Prev Main Tab | `Ctrl + Alt + Left` | `Cmd + Alt + Left` | Global |

---

## 6. Montoya Public API UI Extension Contracts

Extensions interact with Burp's UI via public API implementations located in `burp.api.montoya.ui`:

1. **`UserInterface` (`burp.api.montoya.ui.UserInterface`)**: Extension point for registering custom context menu items, tabbed tools, and HTTP message editor providers.
2. **`HttpRequestEditorProvider` / `HttpResponseEditorProvider`**: Allows extensions to inject custom tabbed views into the Request/Response viewer (e.g. Protocol Buffers, JWT decoders).
3. **`SettingsPanelBuilder` (`burp.api.montoya.ui.settings.SettingsPanelBuilder`)**: Provides standard Burp-styled form panels for extension settings integrated directly into Burp's Settings tab.
4. **`ContextMenuItemsProvider` (`burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider`)**: Injects extension custom action menu items into Burp's right-click context menu.

---

## 7. Implementation Roadmap & Verification Criteria

When implementing this specification from scratch:

1. **Phase 1: Design System & Primitive Component Library**
   - Implement `FlatLaf` theme parser supporting `THEMES.md` palette schema (`mono`, `primary`, etc.).
   - Create base container `BurpClass9399` (`JPanel` with `TitledBorder` overrides).
   - Implement virtualized `BurpClass6815` TableModel component.

2. **Phase 2: Global Shell & Guice Module Container**
   - Build `suiteFrame` (`BurpClass10400`) layout with primary tab container (`secondarySuiteTabBar`).
   - Wire `ToolRegistry` (`Zgdx`) and Guice module initialization sequence.

3. **Phase 3: Core Tools & Dual Editors**
   - Implement dual-pane `RSyntaxTextArea` HTTP message viewer.
   - Implement `Proxy`, `Repeater`, `Target`, and `Dashboard` tool frames.

4. **Phase 4: Addressability & Verification**
   - Verify every UI component invokes `setName()` with its corresponding spec string.
   - Test global keyboard shortcuts (`Ctrl+R`, `Ctrl+I`, `Ctrl+Shift+P`).
