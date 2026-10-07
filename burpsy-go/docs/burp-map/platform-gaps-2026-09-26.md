# Burp PLATFORM / EXTENSION / UI-KIT / AI surfaces -> burpsy gap map (2026-09-26)

**Oracle:** `/root/burp-re`, Burp Suite 2026.7.1 (build 51467), four-layer protocol per
`SOURCE-OF-TRUTH.md`. Produced by a read-only scout.

## Per-area verdicts

| area | verdict | gap | burp evidence | burpsy evidence |
|---|---|---|---|---|
| extender / extension model | PARTIAL (by design for the substrate) | local JSON-RPC executables only; no BApp store, no JVM/Jython/JRuby, no auto-reload; 4 of 13 registration points live | `out/burp/api/montoya/ui/UserInterface.java:51-132`; `extension/Extension.java:41`; `map_root.tsv:678-691` | `internal/extension/AGENTS.md:9-13`; `protocol.go:85-116`; `api_extensions.go:16-22`; `host.go:339-343` |
| UI kit an extension may register | PARTIAL | hotkey, settings-panel, suite-tab, WS-editor providers have no protocol kind | `ui/hotkey/HotKeyContext.java:12-18`; `ui/settings/SettingsPanel.java:23`; `SettingsPanelPersistence.java:9-22` | `protocol.go:88-109`; `lib/palette-commands.ts:111-125` |
| AI surface | PARTIAL | Burp AI second look landed; no chat-prompt extension API, no agentic 54-tool registry, no MCP server | `FINDINGS.md:174-238,240-300`; `ai/chat/Prompt.java:24-56` | bead `ei0v` CLOSED; `internal/scanner/triage.go`; `docs/MCP.md:3-10` |
| persistence / project | PARTIAL | write-through SQLite + VACUUM INTO backup; no `.burp` project file, no user-vs-project settings split | `project/Project.java:13-20`; `persistence/Persistence.java:23-32`; `map_root.tsv:1927,8703,15418` | `internal/persist/persist.go:107-120`; `api_config.go:60-101` |
| scope | LANDED (editor+library) / PARTIAL (notification) | `registerScopeChangeHandler` has no analogue | `scope/Scope.java:28-55`; `ScopeChange.java` | `internal/core/scope.go:46-52,294-320,396,664,728`; bead `e365` CLOSED |
| sitemap | LANDED (views+filters+compare) / PARTIAL (node->issues) | a node's findings cannot be opened from the map | `sitemap/SiteMapNode.java:26-40` | `pages/sitemap.tsx:1042-1070`; node->issues is bead `zzz` OPEN |
| suite / shell settings | PARTIAL | 20 settings sections landed; no Suite-level section (Performance, Startup, Shutdown, Temp files, Updates, Early adopter, REST API) | `map_root.tsv:8846,5445-5447,6939-6940,14375-14405` | `settings-sections.ts:52-167`; `proxy/proxy.go:42-47` |
| utilities an extension uses | PARTIAL | no plugin-reachable shell exec, JSON node API, ranking or byte helpers | `utilities/shell/ShellUtils.java:18-50`; `utilities/json/JsonNode.java:76-187`; `utilities/rank/RankingUtils.java:20-29` | `internal/session/jsonpath.go:5-9,50-53`; `internal/extscan/`; `internal/domexec/` |
| themes / L&F | PARTIAL | token system is Penpot-canonical; cannot express Burp's group/status/issue colour families | `BurpLaf.properties:917-965,1068-1076`; `DarkTheme.json:141-240,359-371` | `tokens/semantic.css:55-57,82-84`; `primitives.css:38-45` |

## Ready-to-file beads

### 1. ui: Settings has no Suite page - Performance, Startup, Shutdown, Temp files, Updates and Early adopter are all absent
- **Claim:** six of Burp's seven Suite settings have no section; burpsy has 20 sections and none
  is Suite-level, so the absence is invisible rather than stated.
- **Evidence:** `map_root.tsv:8846` (`user_options.misc.temporary_files_location`); `:5445`
  (`user_options.auto_update.enabled`); `:6939` (`suppress_confirm_on_close`); `:6946`
  (`enable_proxy_interception_at_startup` — this one IS built); burpsy
  `settings-sections.ts:52-167` (no suite id), `proxy/proxy.go:42-47` (CA path hard-coded to
  `~/.burpsy/ca`).
- **Fix direction:** add a `suite` section; make the two buildable items real (temp-files
  location read by `proxy.go:38-47`, close confirmation) and state the other four as declined
  with reasons rather than leaving them silently missing.
- **Why it matters:** the configuration surface is the migration path, and a missing section
  reads as "burpsy cannot do this" — which is only true for some of it.

### 2. extender: no plugin can register a hotkey, so a plugin's only triggers are three menus and a tab
- **Claim:** `registerHotKeyHandler` (3 overloads, 5 `HotKeyContext`s) has no protocol kind;
  u7h closed the *UI* half but the protocol half is still absent.
- **Evidence:** `ui/hotkey/HotKeyContext.java:12-18`; `UserInterface.java:100-123`; burpsy
  `protocol.go:114-116` (4 kinds, no hotkey), `views.go:156-168`; `u7h` CLOSED.
- **Fix direction:** add `KindHotKey` + a `hotkey.invoke` entry to `MethodSpecs` (the file's own
  test reads it), then have `shortcuts.ts` install it.
- **Why it matters:** every serious Burp extension binds a key; without the kind, a plugin can
  only be reached by clicking.

### 3. suite: no REST-API settings page - burpsy IS a JSON API with nothing describing or gating it
- **Claim:** Burp's REST API is a 12-key settings page; burpsy serves ~200 routes with no
  surface describing them.
- **Evidence:** `map_root.tsv:14375-14405` (`user_options.misc.api.*`); burpsy
  `route_manifest_test.go:46-65` already classifies every route's risk;
  `docs/MCP.md:1-10` says MCP is not shipped but says nothing about the HTTP API.
- **Fix direction:** one Settings section rendering the existing route list with its risk class,
  plus the `-web` bind. Read-only; no new backend.
- **Why it matters:** an operator cannot see what their console exposes, and the classification
  that would answer it already exists in a test file.

### 4. theme: burpsy cannot express Burp's group/status/issue colour families
- **Claim:** Burp's 15 group colours, 9 highlight colours, 5 task statuses and 5 issue severities
  are each a named, themeable family; burpsy has 3 semantic status roles.
- **Evidence:** `BurpLaf.properties:917-965,1068-1076`; `DarkTheme.json:141-240,359-371`;
  burpsy `tokens/semantic.css:55-57,82-84`.
- **Fix direction:** a `severity-*` set in `semantic.css` composed from the existing red/orange/
  yellow/blue primitives, consumed by the Issues table (which currently maps severity->tone in
  TSX). Plus the one genuinely additive gap the inventory found: cookie-name/cookie-value editor
  tokens, which Burp has (`DarkTheme.json:280-281`) and burpsy does not.
- **Why it matters:** severity and status are read at a glance in a triage table; hard-coded
  per-component colours cannot be themed and drift from the rest of the console.

### 5. scope: no scope-change notification - a plugin can never be told the scope moved
- **Claim:** Burp pushes a `ScopeChangeHandler` callback; burpsy re-reads the scope per request,
  which is correct but unobservable.
- **Evidence:** `scope/ScopeChangeHandler.java:20-26`; `ScopeChange.java` (empty marker);
  burpsy `server.go:797-811` (closure reads live state per request, with the reason in-file).
- **Fix direction:** one `OnChange(func())` on `core.Scope`, called by
  `Add`/`RemoveScoped`/`ReplaceScoped`/`Clear`, so an extension and the event stream can
  subscribe. Self-contained in `core/scope.go`.
- **Why it matters:** an extension that caches scope decisions has no way to invalidate them, so
  it either re-reads forever or goes stale.

## Theme inventory (the concrete deliverable)

- The 779 keys in `BurpLaf.properties` split three ways. **~215 are colour-slot declarations**
  (`Colors.*`), and every one is `=null` in the shipped file — the real values live in
  `DarkTheme.json` / `LightTheme.json`. The properties file is a *slot manifest*, not a palette.
  - 9 palettes x 9 = **81** `Colors.palette.*`. burpsy has the ramps (`--grey-*`, `--*-dark`)
    but no palette indirection: `semantic.css:49-84` maps roles straight to primitives.
  - `Colors.ui.text.*` 11, `Colors.ui.icon.*` 11, `Colors.ui.background.1..10` 10. burpsy covers
    text and background; **icon roles have no token at all** — icons reuse text roles.
  - `Colors.ui.editor.message.*` = **44**, the family burpsy most closely matches:
    `styles.css:77-100` (light) and `:124-151` (dark) carry headerName/headerValue/body/start/
    json-key/string/number/html-tag/attr-name/attr-value/js-keyword/string/comment/css-property/
    value/url-param-name/value/match. **~17 of 44 map 1:1**; the rest are Diff/Match chrome,
    gutter, lozenges and search highlights burpsy does not have.
  - `Colors.ui.groups.0..14.*` = **30** (issue/annotation group colours; none in burpsy).
  - `Colors.ui.highlight.0..8.*` = **18** (Burp's 9 annotation highlights; burpsy has one
    `--editor-match*` triple and per-item exchange highlights, no palette).
  - `Colors.ui.target.method.*` = **10** — burpsy colours nothing by HTTP method; cheap win.
  - `Colors.ui.status.{new,inProgress,postponed,ignored,done}` = **5** — exactly the Organizer
    statuses bead `4t8` shipped; burpsy has `--good/--warn/--bad` only.
  - `Colors.ui.issue.{high,medium,low,info}` = **4** — burpsy maps severity->tone in TSX.
- **~60 are Swing/FlatLaf component keys** (`Button.*`, `Component.arc=8`,
  `TabbedPane.tabInsets=9,15,9,15`, `TableHeader.cellMargins=4,3,4,3`, `Separator.height=1`,
  20 UI-delegate class names). Burp-internal chrome, **not adoptable** — but the geometry numbers
  are what a "look like Burp" pass wants.
- **3 are edition brand colours:** `Colors.brand.burp=#FF6633`, `.pro=#5B4FFF`,
  `.community=#00A2B9`. burpsy's `--orange-bright: #ff6633` is an **exact match**, provenance
  documented at `styles.css:20-25`.
- **Do NOT adopt Burp's editor syntax hexes.** `DarkTheme.json:288-290,310-311` vs burpsy's
  `styles.css:129-131`: burpsy's are Darcula values deliberately lifted past WCAG AA and the file
  records the measurement ("Darcula's own purple #9876aa and green #6a8759 measure 3.71 and
  3.52 … below AA"). Adopting Burp's would regress contrast on the bytes an operator reads.
- **Do NOT adopt Burp's indirection layer** (10 swatches x 7-8 shades -> 9 palettes -> 240 slots,
  `THEMES.md:99-127`): burpsy's 2-tier Penpot pipeline is declared canonical by
  `scripts/gen-tokens.mjs:6-8`. That is a design decision, not a gap.
- **Deliberate contradictions to keep:** `styles.css:75` `--editor-active-line: rgb(255 102 51 / 2%)`
  vs Burp's `#35383A` band — the 2% tint exists because 7%/10% pushed `.cm-placeholder` below
  4.5:1, recorded in-file.
- **UNKNOWN:** whether the installed 2026.7.3 build changed any `Colors.*` slot versus this
  2026.7.1 tree. To settle: re-run SOURCE-OF-TRUTH.md §9's extraction against
  `/opt/BurpSuite/burpsuite.jar` and diff the key sets.
