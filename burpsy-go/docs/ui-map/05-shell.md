# Burpsy React UI Shell & Shared Components Map

## Route map

| Tool | Hotkey | Leaf route id | Leaf label | Description | Page component |
|------|--------|---------------|------------|-------------|----------------|
| Dashboard | alt+1 | `dashboard` | Dashboard | Coverage, running work, and recent activity | `DashboardPage` |
| Target | alt+2 | `sitemap` | Site map | Hosts, paths, and observed behaviour | `SiteMapPage` |
| Target | alt+2 | `scanner` | Issues | Findings, coverage, and active audits | `ScannerPage` |
| Target | alt+2 | `scope` | Scope | What the tools are allowed to touch | `ScopePage` |
| Proxy | alt+3 | `intercept` | Intercept | Hold, edit, and release traffic in flight | `InterceptPage` |
| Proxy | alt+3 | `history` | HTTP history | Every captured request and response | `HistoryPage` |
| Proxy | alt+3 | `wshistory` | WebSockets history | Upgrade connections and frame payloads | `WebSocketPage` |
| Proxy | alt+3 | `matchreplace` | Match & Replace | Reviewable traffic transformations | `MatchReplacePage` |
| Intruder | alt+4 | `intruder` | Intruder | Payload-driven attacks with bounded accounting | `IntruderPage` |
| Repeater | alt+5 | `repeater` | Repeater | Craft and resend requests | `RepeaterPage` |
| Sequencer | alt+6 | `sequencer` | Sequencer | Token randomness analysis | `SequencerPage` |
| Decoder | alt+7 | `decoder` | Decoder | Transform and hash data | `DecoderPage` |
| Comparer | alt+8 | `comparer` | Comparer | Byte-level differences | `ComparerPage` |
| Logger | alt+9 | `logger` | Logger | Requests burpsy itself sent | `LoggerPage` |
| Organizer | alt+0 | `organizer` | Organizer | Curated investigation notes | `OrganizerPage` |
| Session | — | `session` | Session | Login macros and recovery behaviour | `SessionPage` |
| Settings | — | `settings` | Settings | Protocols, appearance, certificates, and diagnostics | `SettingsPage` |

**Notes:**
- Tools without a hotkey: Session, Settings
- Tools with one leaf (entry tab navigates directly to that leaf): Dashboard, Intruder, Repeater, Sequencer, Decoder, Comparer, Logger, Organizer, Session, Settings
- Tools with multiple leaves (entry tab shows sub-tabs): Target (3 leaves), Proxy (4 leaves)

---

## URL / hash routing

**Hash Format:** `#<leaf-id>`

**How routes are read from URL:**
- On initial load: `location.hash.slice(1)` extracts the hash (line 142, `useHashRoute()`)
- Verified against `NAV_LEAVES` array; if the ID is found, `setRoute()` updates store
- If hash is empty or invalid, the first leaf in `NAV_LEAVES` is used (fallback in `findLeaf()` returns index 0)

**How routes are written to URL:**
- Whenever `route` store state changes, `history.replaceState()` writes the hash (line 153)
- Format: `#${route}` (the leaf ID becomes the hash fragment)

**Hash change event listener:**
- Registered in `useHashRoute()` (line 148)
- Listens to `hashchange` event on window
- Validates incoming hash against `NAV_LEAVES` before updating store
- Cleaned up on component unmount

**Unknown hash behavior:**
- Invalid or unrecognized hashes are silently discarded
- When an unrecognized hash is found, no navigation occurs (line 143 condition fails)
- User stays on whatever route was previously set

---

## Global keyboard shortcuts

| Keys | Registered in | enableOnFormTags | Action | Notes |
|------|---|---|---|---|
| `mod+K` | `app.tsx` line 198 | `true` | Open command palette | Burp parity |
| `shift+/` (equivalent to `?`) | `app.tsx` line 207 | `false` | Show keyboard shortcuts help | Burp parity |
| `mod+shift+L` | `app.tsx` line 208 | `true` | Toggle light/dark theme | Burp parity |
| `alt+1` | `app.tsx` line 220 | `true` | Switch to Dashboard tool | Maps to first leaf of Dashboard |
| `alt+2` | `app.tsx` line 220 | `true` | Switch to Target tool | Maps to first leaf of Target (sitemap) |
| `alt+3` | `app.tsx` line 220 | `true` | Switch to Proxy tool | Maps to first leaf of Proxy (intercept) |
| `alt+4` | `app.tsx` line 220 | `true` | Switch to Intruder tool | Maps to Intruder leaf |
| `alt+5` | `app.tsx` line 220 | `true` | Switch to Repeater tool | Maps to Repeater leaf |
| `alt+6` | `app.tsx` line 220 | `true` | Switch to Sequencer tool | Maps to Sequencer leaf |
| `alt+7` | `app.tsx` line 220 | `true` | Switch to Decoder tool | Maps to Decoder leaf |
| `alt+8` | `app.tsx` line 220 | `true` | Switch to Comparer tool | Maps to Comparer leaf |
| `alt+9` | `app.tsx` line 220 | `true` | Switch to Logger tool | Maps to Logger leaf |
| `alt+0` | `app.tsx` line 220 | `true` | Switch to Organizer tool | Maps to Organizer leaf |

**Message editor hotkeys** (in `HttpEditor` when focused on raw view):
| Keys | Action | Notes |
|------|--------|-------|
| `mod+U` | URL-encode selection | Calls `urlEncodeKeyChars()` |
| `mod+shift+U` | URL-decode selection | Calls `urlDecode()` |
| `mod+H` | HTML-encode selection | Calls `htmlEncodeKeyChars()` |
| `mod+shift+H` | HTML-decode selection | Calls `htmlDecode()` |
| `mod+B` | Base64-encode selection | Calls `base64Encode()` |
| `mod+shift+B` | Base64-decode selection | Calls `base64Decode()` |
| `mod+S` | Search in editor | Opens CodeMirror search panel |
| `mod+Enter` | Send the request in Repeater | App-specific, handled by page |

**Shortcuts help dialog** (`ShortcutHelp` component, lines 44–95):
The dialog displays groups:
1. **Send to:** mod+R (send to Repeater), mod+I (send to Intruder), Enter (send focused row to Repeater), right-click (all actions)
2. **Proxy:** mod+F (forward held message), alt+T (toggle interception, *note: Burp uses mod+T, browsers reserve it*)
3. **Message editor:** mod+U/shift+U (URL), mod+H/shift+H (HTML), mod+B/shift+B (Base64), mod+S (search), mod+Enter (send in Repeater)
4. **Navigation:** mod+K (command palette), alt+1…0 (switch tool, *note: Burp uses mod+shift+letter, browsers reserve those*), ↑↓ (table move), PgUp/PgDn (page move), Home/End (table extremes)
5. **Appearance and help:** mod+shift+L (toggle theme), ? (show this list)

**Dialog text vs actual bindings:**
- Dialog claims: "alt+T toggle interception" → Actual binding: `alt+T` (see app.tsx line 58, noted as browser limitation)
- Dialog claims: "alt+1…0 switch tool" → Actual bindings: `alt+1`, `alt+2`, `alt+3`, `alt+4`, `alt+5`, `alt+6`, `alt+7`, `alt+8`, `alt+9`, `alt+0` (all registered at line 220)
- **No mismatch:** Editor hotkeys in dialog (lines 62–72) match `PAIRS` logic in editor.tsx (lines 140–167)

---

## Menu bar

Rendered in `src/app.tsx`'s `MENUS`. Five top-level menus with dropdown interface: `burpsy`,
`File`, `Repeater`, `View`, `Help`.

**Corrected 2026-09-14 (burpsy-react-ui-lje3):** this section used to call the second menu
"Project", and listed a five-item set that included a `Tools` menu. Neither was true of the live
console: the menu is labelled **File**, and `Tools` — a burpsy invention, absent from Burp — was
deleted when the tab list moved into `View` as Burp's visibility switches. The Burp-side comparison
(what Burp's six menus contain, item by item) is in
`../ui-parity-verify-2026-09-14-shell-settings.md`.

### burpsy menu
**Actions:**
- **Settings** | Navigates to `settings` leaf | Always enabled
- **Command palette** | Shortcut: `mod+K` | Opens palette | Always enabled
- **Keyboard shortcuts** | Shortcut: `?` | Opens shortcut help modal | Always enabled

### File menu
**Actions (grouped):**
- **Export report (HTML)** | Opens `/api/report/html` in new window | Always enabled
- **Export report (JSON)** | Opens `/api/report/json` in new window | Always enabled
- **Export report (SARIF)** | Opens `/api/report/sarif` in new window | Always enabled
- **Download CA certificate** | Opens `/ca.crt` in new window | Always enabled

### Repeater menu
**Actions:**
- **New request tab** | Creates a repeater tab with template request to `example.com` and navigates to repeater | Always enabled | Icon: Plus
- **Go to Repeater** | Shortcut: `alt+5` | Navigates to `repeater` leaf | Always enabled | Icon: Repeat2

### View menu
**Actions (grouped):**
- **Top-level tabs** (group title) — one checkable entry per tool tab, checked when the tab is
  showing. Unchecking hides it from the strip; the preference is `burpsy.tooltabs.hidden` in
  localStorage, read back through `lib/tool-tabs.ts`, whose reader treats anything that is not a
  list of ids as "nothing is hidden".
- **Restore default tab layout** — clears that preference; disabled when nothing is hidden.
  (Burp's `mainViewMenuRestoreDefaultLayout`.)
- **[Light|Dark] theme** | Shortcut: `mod+shift+L` | Toggles between light and dark | Always enabled | Icon: Sun or Moon (context-aware)
- **Follow the system theme** | Navigates to `"system"` theme setting | Disabled when `theme === "system"` | No shortcut
- **[Comfortable|Compact] table rows** | Toggles density | Always enabled | Icon: Rows3

### Help menu
**Actions (grouped):**
- **Keyboard shortcuts** | Shortcut: `?` | Opens shortcut help modal | Always enabled
- **Command palette** | Shortcut: `mod+K` | Opens palette | Always enabled

---

## Command palette

**How it opens:**
- Triggered by `mod+K` keyboard shortcut (line 198–205)
- Also via menu items (burpsy > Command palette, Help > Command palette)
- Bound with `enableOnFormTags: true` so it works in form contexts

**Component:** `CommandPalette` (`ui/palette.tsx`, lines 46–154)

**What actions it lists:**
1. **Navigation actions** (lines 234–245): One action per leaf across all tools
   - Format: `${tool.label} › ${leaf.label}` if tool has multiple leaves, else just `${leaf.label}`
   - 12 tools × (1–4 leaves) = 22 navigation actions
   - Group: `"Go to"`
   - Each includes icon, description (from `leaf.description`), shortcut (if tool has hotkey and this is entry leaf)

2. **Command actions** (lines 247–289):
   - "Switch to [light|dark] theme" | Group: Appearance | Icon: Sun/Moon | Shortcut: `mod+shift+L`
   - "Use [comfortable|compact] table rows" | Group: Appearance | Keywords: "density rows spacing"
   - "Show keyboard shortcuts" | Group: Help | Icon: Keyboard | Shortcut: `?`
   - "Download the CA certificate" | Group: Help | Icon: ShieldCheck | Keywords: "certificate https tls install"
   - "Export the findings report (HTML)" | Group: Help | Keywords: "html findings issues export"
   - Total: 5 command actions

**How the list is built:**
1. Flatten all tool leaves into navigation actions (lines 234–245)
2. Append hard-coded command actions (lines 247–289)
3. Combine: `[...navigation, ...commands]` (line 291)
4. Total: 22 + 5 = 27 actions

**Keyboard behaviour:**
- Arrow Down: Move cursor forward (line 110)
- Arrow Up: Move cursor backward (line 113)
- Enter: Commit the selected action (line 114–116)
- Escape: Close the palette (radix Dialog default)

**Search / filtering:**
- Input field searches against: `${action.label} ${action.group} ${action.keywords ?? ""}`
- Scoring function (lines 22–44):
  - Direct match at position 0: score 1000
  - Direct match elsewhere: score 700 minus position
  - Initials match (e.g., "hh" matches "HTTP history"): score 600
  - Subsequence match: score 200 (if all characters found in order)
  - No match: score 0
- Results limited to top 60 by score (line 64)
- Sorted descending by score (line 63)

**Empty query behavior:**
- When term is empty (`term.trim() === ""`), all actions score 1, all pass filter, all are sorted equally
- All 27 actions appear in default order

**No matches behavior:**
- When no actions score > 0, `matches.length === 0` (line 123)
- Renders: `<div className="palette-empty">No matching command</div>`
- Action list remains empty

---

## Shared components

### layout.tsx

**PageHeader** (`lines 11–34`)
- Props: `title`, `eyebrow?`, `description?`, `actions?`
- Renders: Title (with optional eyebrow superscript), optional description paragraph, optional actions slot
- CSS class: `page-header`
- Use: Section title bar that shares a row with action buttons

**SectionHeading** (`lines 36–54`)
- Props: `title`, `detail?`, `actions?`
- Renders: h3 title (with optional subtitle), optional actions slot
- CSS class: `section-heading`
- Use: Group header within a page

**RefreshButton** (`lines 56–71`)
- Props: `onClick`, `loading?`, `label?`
- Renders: Button with RefreshCw icon, shows "Refresh" label by default
- Icon rotates (CSS class `spin`) when `loading === true`
- Disabled when `loading === true`

**SplitPane** (`lines 77–120`)
- Props: `master`, `detail`, `orientation?` ("vertical" | "horizontal"), `storageId`, `defaultMasterSize?`, `minMasterSize?`, `className?`
- Renders: Resizable two-panel split using react-resizable-panels
- Stores drag position in localStorage via `burpsy.split.${storageId}`
- Default layout: vertical (master above), 58% master, 20% min master, 15% min detail
- Resize handle: Draggable separator with visual grip indicator
- CSS classes: `split-pane`, `split-vertical` or `split-horizontal`, `resize-handle`, `resize-grip`

**LoadingPanel** (`lines 122–129`)
- Props: `label?` (default: "Loading")
- Renders: Spinner component + text label in centered panel
- CSS class: `loading-panel`

**ErrorBoundary** (`lines 139–170`)
- Class component that catches render errors in child tree
- Displays: AlertTriangle icon + "This view failed to render" + error message + "Try again" button
- Resets on `resetKey` prop change or "Try again" click
- Logs errors to console: `console.error("page crashed", error, info.componentStack)`
- CSS class: `crash-panel`

---

### menu.tsx

**MenuAction interface** (`lines 5–14`)
- `id`: Stable key and fallback label
- `label`: Visible label
- `icon?`: ComponentType receiving `{ size?: number }`
- `shortcut?`: Display text (e.g., "mod+K")
- `danger?`: Visual styling for destructive actions
- `disabled?`: Grayed out and non-interactive
- `onSelect`: Callback when clicked

**MenuGroup interface** (`lines 16–19`)
- `id`: Stable key
- `actions`: Array of MenuAction

**ContextMenu** (`lines 50–62`)
- Props: `groups: MenuGroup[]`, `children: ReactNode`
- Right-click menu wrapper
- Renders children unwrapped if all groups are empty (no-op for non-interactive rows)
- Otherwise: Radix Context Menu with rendered items/separators
- CSS class: `menu-content`

**DropdownMenu** (`lines 65–84`)
- Props: `groups: MenuGroup[]`, `trigger: ReactNode`, `align?` ("start" | "center" | "end", default "end")
- Click-to-open dropdown menu
- Uses Radix Dropdown Menu
- CSS class: `menu-content`
- Used for: toolbar overflow menus, menu bar top-level dropdowns

**Rendering function** (`lines 21–47`, shared)
- Filters groups to visible ones (non-empty `actions` arrays)
- Renders separator between groups (except before first)
- Each action renders as Item with: icon (left), label (center), shortcut hint (right)
- Icon size: 14px
- Action items CSS class: `menu-item` or `menu-item-danger`
- Disabled actions are non-clickable

---

### palette.tsx

**PaletteAction interface** (`lines 7–16`)
- `id`: Stable unique key
- `label`: Visible action title
- `group`: Category for grouping (e.g., "Go to", "Appearance", "Help")
- `hint?`: Subtitle/description
- `shortcut?`: Display text (e.g., "mod+K")
- `keywords?`: Additional search terms (joined with label/group for scoring)
- `icon?`: ComponentType receiving `{ size?: number }`
- `run`: Callback when action is invoked

**CommandPalette** (`lines 46–154`)
- Props: `open`, `onOpenChange`, `actions: PaletteAction[]`
- Dialog-based (Radix Dialog)
- Search input with Search icon + Esc hint (Kbd display)
- Results scroll area with virtual scroll
- Group headings rendered inline (no separate grouping level)
- Item render: icon (14px) + label + hint + shortcut
- Active item: highlighted class + keyboard focus
- Selection mode: keyboard (arrow up/down, enter) or mouse hover/click
- Scoring algorithm (lines 22–44):
  - Case-insensitive search on `${label} ${group} ${keywords}`
  - Biased toward word starts (e.g., "hh" → "HTTP history")
  - Top 60 results by score
- Empty state: "No matching command" message
- On commit (Enter/click): Closes palette, runs `action.run()`

---

### primitives.tsx

**Button** (`lines 19–29`)
- Props: Standard `<button>` attrs + `variant?` + `size?`
- Variants: "primary" | "outline" | "danger" | "quiet" | "ghost" (default: "primary")
- Sizes: "medium" | "small" (default: "medium")
- CSS classes: `button`, `button-${variant}`, `button-sm` (if small)

**LinkButton** (`lines 31–37`)
- Props: Standard `<a>` attrs + `variant?`
- Variants: "primary" | "outline" | "quiet" (default: "outline")
- CSS classes: `button`, `button-${variant}`

**IconButton** (`lines 39–57`)
- Props: Standard button attrs except no `aria-label`, plus `label` (required) + `children` + `size?`
- Wrapped in Tooltip with `label` content
- Size: "medium" | "small" (default: "medium")
- CSS classes: `icon-button`, `icon-button-sm` (if small)

**Input, Textarea, Select** (`lines 59–69`)
- Standard HTML elements with CSS class wrapper (`input`, `textarea`, `select`)
- Textarea has `spellCheck={false}`

**Card** (`lines 71–73`)
- CSS class: `card`

**Badge** (`lines 75–81`)
- Props: Span attributes + `tone?`
- Tone: "neutral" | "good" | "warn" | "bad" | "info" | "accent" (default: "neutral")
- CSS classes: `badge`, `badge-${tone}`

**Field** (`lines 83–116`)
- Props: `label`, `hint?`, `children`, `className?`, `htmlFor?`
- Renders label + control + hint
- If `htmlFor` provided: explicit label → control structure (for Radix widgets)
- Otherwise: label wraps control implicitly
- CSS class: `field`

**Toolbar** (`lines 118–120`)
- CSS class: `toolbar`

**Empty** (`lines 122–130`)
- Props: `title`, `detail`, `action?`
- Renders: bold title + paragraph detail + optional action slot
- CSS class: `empty`

**ErrorNotice** (`lines 132–147`)
- Props: `error`, `onRetry?`
- Renders: "Request failed" + error message + optional Retry button
- CSS class: `error-notice`

**Metric** (`lines 149–169`)
- Props: `label`, `value`, `detail?`, `accent?`, `tone?`
- Renders: Card with label + bold value + optional detail
- Tone: CSS class `metric-${tone}`
- Accent: CSS class `metric-accent` (for highlighting)
- CSS classes: `card`, `metric`

**Kbd** (`lines 171–173`)
- Props: `children`
- CSS class: `kbd`

**Spinner** (`lines 175–177`)
- Props: `label?` (default: "Loading")
- Renders: `<span>` with `role="status"` + aria-label
- CSS class: `spinner`

**Tooltip** (`lines 179–192`)
- Props: `content`, `children`
- No-op if content is falsy
- Radix Tooltip with Portal
- CSS classes: `tooltip`, `tooltip-arrow`
- Delay: 420ms, skip on hover in 200ms

**Switch** (`lines 194–210`)
- Props: `checked`, `onCheckedChange`, `id?`, `label` (required)
- Radix Switch with thumb
- CSS class: `switch`, `switch-thumb`

**Checkbox** (`lines 212–229`)
- Props: `checked`, `onCheckedChange`, `label`, `className?`
- Native `<input type="checkbox">` in label
- CSS class: `check-row`

**Tabs** (`lines 231–243`)
- Re-exports Radix Tabs components with CSS class wrapping
- `Tabs` = `TabsPrimitive.Root`
- `TabsList`: CSS class `tabs-list`
- `TabsTrigger`: CSS class `tabs-trigger`
- `TabsContent`: CSS class `tabs-content`

**Modal** (`lines 245–281`)
- Props: `open`, `onOpenChange`, `title`, `description?`, `children`, `wide?`
- Radix Dialog with Portal + Overlay
- Header: title + description + close button (X icon)
- CSS classes: `dialog-overlay`, `dialog-content`, `dialog-wide` (if wide), `dialog-head`, `dialog-title`, `dialog-description`

---

### table.tsx

**Column<T>** (line 20)
- Type alias for `ColumnDef<T, any>` (TanStack Table)

**VirtualTable<T>** (`lines 75–276`)
- Props:
  - `data: T[]` — Row data
  - `columns: Column<T>[]` — Column definitions
  - `getRowId: (row: T) => string` — Row key function
  - `ariaLabel: string` — For scroll container
  - `selectedId?: string | null` — Currently selected row ID
  - `onSelect?: (row: T) => void` — Single-click handler
  - `onActivate?: (row: T) => void` — Double-click/Enter handler (falls back to onSelect)
  - `menuGroups?: (row: T) => MenuGroup[]` — Right-click context menu builder
  - `rowClassName?: (row: T) => string | undefined` — Row-specific CSS
  - `loading?: boolean` — Show spinner overlay
  - `empty?: ReactNode` — Empty state message
  - `density?: "comfortable" | "compact"` — Row height mode
  - `height?: string` — CSS height for scroll viewport
  - `initialSort?: SortingState` — Initial sort state

- Features:
  - TanStack Table core + sort model
  - TanStack Virtual (virtualization)
  - Keyboard navigation: ↑↓ (move), PgUp/PgDn (jump), Home/End (extremes), Enter (activate)
  - Row selection: click, right-click selects first
  - Column sorting: Click header, toggles asc/desc, shows arrow icons
  - Column resizing: Drag separator, double-click resets, touch-support
  - Row height probe: Measures CSS token `--row-h-compact` or `--row-h` at runtime
  - Virtualization: Renders only visible rows + 14-row overscan

- CSS classes:
  - `table-frame`, `density-compact` or `density-comfortable`
  - `table-scroll` (scroll container)
  - `data-row`, `selected-row`, `clickable`
  - `th-sort` (header button), `col-resize`, `col-resizing`

- Child component: TableRow (lines 278–314)
  - Wraps row with optional ContextMenu
  - Context menu triggered on right-click and context menu key
  - Supports double-click activation

**SimpleTable** (`lines 317–334`)
- Non-virtualized static table for short lists
- Props: `headers: string[]`, `children: ReactNode`, `className?`
- Renders: thead with headers, tbody with children as rows
- CSS class: `table-frame`

---

### editor.tsx

**HttpEditor** (`lines 184–315`)
- Props:
  - `value: string` — Raw HTTP message
  - `onChange?: (value: string) => void` — Edit callback (if editable)
  - `readOnly?: boolean` — Prevent edits (default: false)
  - `label: string` — Display label
  - `actions?: ReactNode` — Custom toolbar buttons
  - `height?: string` — CSS height (default: "100%")
  - `filename?: string` — Download filename (default: "message.txt")
  - `placeholder?: string` — CodeMirror placeholder
  - `className?: string` — CSS class on wrapper
  - `views?: boolean` — Enable view tabs (default: true)

- Views (tabs):
  - **raw**: Editable raw bytes (the only editable view)
  - **pretty**: Formatted body only (read-only, only shown if different from raw)
  - **hex**: Byte-level hexdump (read-only)
  - **render**: Response body rendered in sandboxed iframe (read-only, responses only)
  - Selection: Tabs appear only if `views === true`

- Editor bar (top):
  - Label
  - View tabs (if any)
  - Byte count (formatBytes)
  - Wrap toggle (WrapText icon, only for non-render views)
  - Copy message button
  - Save to file button

- Editor content:
  - CodeMirror for raw/pretty/hex views
  - Iframe for render view

- Keyboard shortcuts (handled by `burpEditorKeys` extension):
  - `mod+S`: Open CodeMirror search panel
  - `mod+U`, `mod+shift+U`: URL encode/decode on selection
  - `mod+H`, `mod+shift+H`: HTML encode/decode on selection
  - `mod+B`, `mod+shift+B`: Base64 encode/decode on selection
  - Only active when there is a selection

- CodeMirror theme:
  - Custom theme with CSS variables for light/dark
  - Line numbers, active line highlight (in edit mode)
  - HTTP-aware syntax highlighting (start line, headers, body)
  - Colors from `--editor-*` CSS tokens

- CSS classes: `editor-shell`, `editor-bar`, `editor-label-inline`, `editor-views`, `editor-meta`, `editor-bar-actions`, `editor-body`, `render-frame`, `editor-note`

---

### inspector.tsx

**Inspector** (`lines 60–114`)
- Props: `raw: string`, `label?: string` (default: "Inspector")
- Renders message as structured sections (request/response, query params, cookies, body params, headers)

- Sections:
  1. **Request / Response overview**: Method/Target/Version/Host/Body (request) or Status/Version/Content-type/Body (response)
  2. **Query parameters**: From request target (if request, not response)
  3. **Cookies**: Cookie header (request) or Set-Cookie (response)
  4. **Body parameters**: Form-encoded or multipart params (if request, not response)
  5. **Headers**: All headers as key-value pairs

- Section rendering: Collapsible with ChevronDown/Right
  - Title + row count (badge)
  - Click to toggle open/close
  - Sections with content default open; empty sections stay closed
  - Rows as definition list: dt (name) + dd (value, click-to-copy button)

- Row interactions:
  - Click value button: Copy to clipboard
  - Empty values show "(empty)" label with dim styling

- Inspector bar:
  - Label

- CSS classes: `inspector`, `inspector-bar`, `inspector-section`, `inspector-head`, `inspector-rows`, `inspector-value`, `inspector-empty`, `cell-dim`

---

### json.tsx

**JsonView** (`lines 74–96`)
- Props: `value: Json`, `defaultOpen?: number` (default: 2), `label?: string` (default: "response")
- Renders recursive collapsible tree of JSON value
- Root level shows as list (for array: indexed entries, for object: key/value pairs)

- Node rendering:
  - Leaf values (scalars): Colored by type (null, bool, number, string)
  - Branch values (array/object): Collapsible toggle + summary (e.g., "5 items", "3 fields")
  - Depth-based indentation: `depth * 14px`
  - Opened by default if `depth < defaultOpen`

- Leaf node colors (CSS classes):
  - `json-null`: null values
  - `json-bool`: true/false
  - `json-number`: Numbers (locale-formatted)
  - `json-string`: Quoted strings
  - `json-empty`: Empty strings (shows "(empty)")

- Branch node rendering:
  - Chevron toggle (Down if open, Right if closed)
  - Key name
  - Summary (e.g., "4 items")
  - Children expanded inline if open

- Head bar:
  - Label
  - Copy JSON button (copies `JSON.stringify(value, null, 2)`)

- CSS classes: `json-view`, `json-view-head`, `json-view-body`, `json-row`, `json-branch`, `json-toggle`, `json-key`, `json-summary`, `json-null`, `json-bool`, `json-number`, `json-string`, `json-empty`

**DetailList** (`lines 99–110`)
- Props: `rows: { label: string; value: ReactNode }[]`
- Renders compact label/value grid as definition list
- CSS class: `detail-list`
- Use: Known-shape detail panes (alternative to generic JsonView)

---

## Toolbar and status bar

### Top toolbar (lines 438–480)

**Structure:**
```
[brand] [tool-tabs ...] [toolbar-right items]
```

**Brand section (lines 439–441):**
- "b/" symbol + "burpsy" text logo
- CSS class: `brand`
- Non-interactive

**Tool tabs (lines 443–460):**
- One button per tool in TOOLS array
- Button text: tool icon + label
- Title attribute: Shows hotkey hint (e.g., "Dashboard (alt+1)")
- Active state: `tool-tab-active` class + `aria-current="page"`
- Click: Navigates to entry leaf of tool
- Right-click: a context menu with **Detach tab** (opens the route in a new browser window) and
  **Hide tab** (writes the same `burpsy.tooltabs.hidden` preference the View menu's checkboxes do)
- Hidden tabs are not rendered — the operator's View-menu choice wins over the strip, and the tab
  is still reachable by hotkey, by the command palette and by any link into one of its routes
- CSS classes: `toolbar-row`, `tool-tabs`, `tool-tab`, `tool-tab-active`

**The fifteen tabs, in strip order** (read off the live console on 2026-09-14, and matching
`src/nav.ts`): Dashboard `alt+1` · Target `alt+2` · Proxy
`alt+3` · Intruder `alt+4` · Repeater `alt+5` · Collaborator · Sequencer `alt+6` · Decoder `alt+7`
· Comparer `alt+8` · Logger `alt+9` · Organizer `alt+0` · Session · Extensions · Discover ·
Settings. A tab with no hotkey is reachable by click and from the command palette. This section
previously listed none of them, so the three tabs added after it was written — Extensions, Discover
and Collaborator — appeared nowhere in this map.

**Toolbar right section (lines 462–479):**
- **Connection badge**: Tone "good" (green, "live") or "warn" (orange, "offline")
  - Icon: Activity (live) or Unplug (offline)
  - Text: "live" or "offline"
  - CSS class: `toolbar-right`
- **Command palette button**: Icon Command, label "Command palette (mod+K)", triggers `setPaletteOpen(true)`
- **Shortcuts button**: Icon Keyboard, label "Keyboard shortcuts (?)", triggers `setShortcutsOpen(true)`
- **Theme toggle button**: Icon Sun/Moon (context-aware), label "Use [light|dark] theme", triggers `toggleTheme()`

**CSS classes:** `toolbar-row`, `tool-tabs`, `tool-tab`, `tool-tab-active`, `toolbar-right`

---

### Sub-tabs row (lines 483–500)

**Rendered only if:** Tool has more than one leaf (`hasSubTabs = tool.leaves.length > 1`)

**Structure:**
```
[sub-tab] [sub-tab] ...
```

**Each sub-tab:**
- One button per leaf in tool.leaves
- Button text: leaf label
- Title: leaf description
- Active state: `sub-tab-active` class + `aria-current="page"`
- Click: Navigates to leaf
- CSS classes: `sub-tabs`, `sub-tab`, `sub-tab-active`

---

### Bottom status bar (lines 509–531)

**Structure:**
```
[live indicator] [data stored] [exchanges] [messages] [scope] [CA cert link] [last event / spacer]
```

**Elements (left to right):**

1. **Event stream status** (lines 510–512):
   - Dot indicator: CSS class `status-dot live` (green, animated) or `status-dot stale` (gray)
   - Text: "event stream connected" (if live) or "event stream offline"

2. **Data storage** (lines 514–516):
   - Icon: Database
   - Text: Formatted byte count (e.g., "1.2 MB stored") or "—" if stats unavailable
   - Never interactive

3. **Exchange count** (lines 518–520):
   - Icon: Network
   - Text: Formatted count (e.g., "42 exchanges") or "—"
   - Never interactive

4. **Message count** (lines 522):
   - Text: Formatted count (e.g., "18 messages") or "—"
   - Never interactive

5. **Scope status** (line 523):
   - Text: "scope: everything" (if allow_all) or "scope: N rules"
   - Never interactive

6. **CA certificate download link** (lines 524–527):
   - Icon: ShieldCheck
   - Text: "CA certificate"
   - HTML `<a href="/ca.crt" download>` — triggers browser download
   - CSS class: `status-link`

7. **Last event timestamp** (lines 528–530):
   - CSS class: `status-push` (pushed to right edge)
   - Text: Relative time (e.g., "last event 30s ago") if eventCount > 0 and lastEventAt is set
   - Text: "no events yet" otherwise
   - Never interactive

**CSS classes:** `statusbar`, `status-dot`, `status-link`, `status-push`

---

## App shell structure

```
<SkipLink href="#main-content">
<div class="app-shell [has-subtabs]">
  <div class="menu-bar">
    [DropdownMenu] (burpsy)
    [DropdownMenu] (File)
    [DropdownMenu] (Repeater)
    [DropdownMenu] (View)
    [DropdownMenu] (Help)
  </div>
  
  <header class="toolbar-row">
    [brand] [tool-tabs] [toolbar-right]
  </header>
  
  {hasSubTabs && (
    <nav class="sub-tabs" aria-label="...">
      [sub-tab] ...
    </nav>
  )}
  
  <main id="main-content" tabIndex={-1}>
    <ErrorBoundary>
      [ActivePage component]
    </ErrorBoundary>
  </main>
  
  <div class="statusbar">
    [status elements...]
  </div>
</div>

<CommandPalette />
<ShortcutHelp />
<Toaster />
```

---

## Notable behaviors and patterns

1. **Route state is dual-source:** Store + URL hash stay synchronized bidirectionally via `useHashRoute()`

2. **Tool entry navigation:** Clicking a tool tab navigates to its first leaf (via `entryLeaf()` function)

3. **Split pane persistence:** Drag position stored in localStorage, survives navigation and page reload

4. **Row height measurement:** Uses a CSS-based probe element to measure font/padding-driven row height dynamically

5. **Virtualization overscan:** Table virtualizer renders 14 extra rows above/below viewport to reduce perceived jank

6. **Context menu on right-click:** Right-clicking a table row both selects it AND opens its context menu

7. **Cascade on theme toggle:** Theme change flows through `useThemeEffect()` to set `data-theme` attribute on `<html>`, CSS reads it

8. **Density toggle via store:** Changes flow through store to `VirtualTable`, which re-measures row height probe

9. **Message editor views are read-only except Raw:** Pretty/Hex/Render views can't be edited; Raw is the "source of truth"

10. **Column resize double-click:** Double-clicking the resize handle resets column to its default width

11. **Palette scoring:** Biases toward word starts so "hh" matches "HTTP history" without requiring "httph"

12. **Menu separator logic:** Separators are only rendered between non-empty groups (filters out empty groups first)

13. **Error boundary per-page:** Each page is wrapped in its own error boundary so one page crash doesn't blank the console

14. **Skip link:** Invisible anchor at top of shell for keyboard-only navigation to main content

15. **Tooltip delay:** 420ms appears; 200ms to skip delay if already hovering (rapid menu traversal)

