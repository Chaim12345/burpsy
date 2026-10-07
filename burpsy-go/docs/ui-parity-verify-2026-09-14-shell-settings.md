# burpsy shell + Session / Discover / Extensions / Extender options / Extender APIs / Settings / Collaborator
Live parity sweep, 2026-09-14. Read-only. No repo file edited, no git, no bd.

**Evidence basis.** Live DOM on http://127.0.0.1:18281/ (seeded: event stream connected, 10 exchanges, 66 messages, no CA, 0 scope rules) driven with pointerdown→mousedown→pointerup→mouseup→click; Burp's own menu structure from `/root/burp-re/out/strings/map_root.tsv` (file is ASCII; positive control `grep -a -c -F Repeater` = 67) and the bundled docs under `.../documentation/desktop/`. Where a control is only reachable from a state this server cannot enter (no plugin allowlisted, no collaborator server), I read `internal/web/ui/src/pages/*.tsx` and say so.

**The audit doc is stale in both directions.** `ui-parity-audit-complete.md` claims "context menus: Burp ~12, burpsy 0" — burpsy's history-row menu has 28 items; it claims Extender Add/Edit/Remove = No/HIGH — `/api/extensions/load` and `/unload` are served and the page renders a Load/Unload toggle; it claims Discover "Content discovery (ffuf) = No/HIGH" — it exists as `Target › Content discovery`. `ui-map/05-shell.md` is also stale: it documents a "Project" menu where the live bar says **File**, and its route table has no Extender, Discover or Collaborator at all.

---

## 1. The shell

### 1.1 Menu bar — shape

| | burpsy (live) | Burp (`map_root.tsv` menu classes) |
|---|---|---|
| Menus | burpsy · File · Repeater · **Tools** · View · Help | Burp · **Project** · **Intruder** · Repeater · View · Help |

Six each. `burpsy`↔`Burp` and `File`↔`Project` line up; **Intruder is absent** and **Tools is a burpsy invention** carrying what Burp puts in View.

*Derivation of Burp's six:* five `main*Menu` telemetry keys in `map_root.tsv` (`mainSuiteMenu`, `mainIntruderMenu`, `mainRepeaterMenu`, `mainViewMenu`, `mainHelpMenu`) plus `Project`, documented in `projects/manage-project-files.html` ("From the top menu bar, select **Project > Save copy**"). Positive control against a menu with no telemetry key: stripping tags across every `.html` under `documentation/desktop/` and grepping every `X > Y` path and every "top-level/top menu" phrase yields only `Burp >`, `Project >`, `Help > Diagnostics`, "top-level Intruder menu", "top-level View menu" — **no Window, Tools or File menu path anywhere**. (`Extensions > …` and `Settings > …` paths appear, but `managing-extensions.html` places those on the Extensions **tab** and the Settings **dialog**, not the menu bar.)

### 1.2 `burpsy` menu vs Burp's `Burp` menu
Burp source: `burp.Zc6t` (`mainSuiteMenu`, `mainSuiteMenuExitMenuItem`).

| burpsy | Burp | Delta |
|---|---|---|
| Settings | Settings | ✓ |
| Command palette (mod+K) | *(palette is Ctrl+K only, no menu entry)* | burpsy-only, harmless |
| Search across tools… | Search | ✓ |
| Keyboard shortcuts (?) | — | burpsy-only |
| *(sep)* Dashboard | — | burpsy-only |
| — | **Configuration library** | **HIGH** — Burp's named scan-config presets; burpsy has presets on Settings › Scanner but no library surface |
| — | **Burp Collaborator client** | MEDIUM — burpsy has a Collaborator *tab*, so the menu entry is naming only |
| — | Burp Clickbandit | LOW — not a burpsy feature |
| — | Burp Infiltrator | LOW — not a burpsy feature |
| — | Upgrade to Burp Suite Professional | n/a |
| — | Exit | LOW — a web console has no process to exit |

### 1.3 `File` menu vs Burp's `Project` menu
Burp source: `projects/manage-project-files.html` ("From the top menu bar, select **Project > Save copy**", "**Project > Import project file**"); strings `New project`, `Save copy of project`, `Save project settings`, `Rename project`, `Restore`.

| burpsy (live) | enabled | Burp | Delta |
|---|---|---|---|
| Export report (HTML) | yes | *(Report issues via context menu)* | burpsy-only placement |
| Export report (JSON) | yes | — | burpsy-only |
| Export report (SARIF) | yes | — | burpsy-only |
| Export configuration | yes | Save project settings / Save settings | ✓ (`/api/config/export`) |
| Import configuration… | yes | Load settings / Import project file | ✓ (`/api/config/import`) |
| CA certificate unavailable | **disabled** | — | correct disabled state (no CA on this server); becomes "Download CA certificate" when one exists |
| — | | **New project / Open project / Save copy of project** | **HIGH** — burpsy has no project-file concept at all. Nearest Go surface is `/api/backup` (Settings › Project backup). This is the single largest structural difference between the two products' File/Project menus. |
| — | | Rename project | MEDIUM |
| — | | Restore (project recovery tool) | LOW |

### 1.4 `Repeater` menu
Burp source: `burp.Zcu0` (`mainRepeaterMenu`).

| burpsy (live) | Burp | Delta |
|---|---|---|
| New request tab | *(the `+` on the tab strip)* | ✓ |
| Paste host / URL as request | Paste host / URL as request | ✓ (Burp documents this on the context menu) |
| Go to Repeater (alt+5) | — | burpsy-only |
| — | Follow redirections (Never / On-site only / In-scope only / Always) | **LOW** — present, but as a per-tab **Config** panel (`repeater.tsx:1052`), not a global menu |
| — | Process cookies in redirections | MEDIUM — burpsy's Config has "Process cookies in this request", which is not redirect-scoped |
| — | Update Content-Length | ✓ in Config panel (`repeater.tsx:1095`) |
| — | Normalize HTTP/1 line endings | ✓ in Config panel (`repeater.tsx:1090`) |
| — | Strip Connection header over HTTP/2 | ✓ in Config panel (`repeater.tsx:1087`) |
| — | **Unpack compressed responses** | MEDIUM — no counterpart found |
| — | **Enable HTTP/1 connection reuse** / **HTTP/2 connection reuse** | MEDIUM — no counterpart |
| — | **Enforce protocol choice on cross-domain redirections** | MEDIUM |
| — | **Allow HTTP/2 ALPN override** | MEDIUM |
| — | **Streaming response timeout** | MEDIUM — Settings › Network has an open-ended-response timeout, which is adjacent but not the same control |

Net: burpsy's Repeater *menu* is navigation only; Burp's is the tool's global configuration. burpsy puts ~4 of Burp's 11 config items in a per-tab panel and has no global default for any of them.

### 1.5 `Tools` menu — burpsy-only
15 items, all enabled, one per tool tab with its alt hotkey: Dashboard alt+1, Target alt+2, Proxy alt+3, Intruder alt+4, Repeater alt+5, Collaborator, Sequencer alt+6, Decoder alt+7, Comparer alt+8, Logger alt+9, Organizer alt+0, Session, Extensions, Discover, Settings.
Burp has no Tools menu. **Burp's View menu is where this list lives**, and there each entry is a *show/hide toggle* for the tab (`mainViewMenuOption:%s`), not a navigate action.

### 1.6 `View` menu
Burp source: `burp.Zupi` (`mainViewMenu`, `mainViewMenuRestoreDefaultLayout`, `mainViewMenuOption:%s`) + `burps-layout/customize-top-level-tabs.html`.

| burpsy (live) | Burp | Delta |
|---|---|---|
| Light theme (mod+shift+L) | *(Settings › User interface › Display)* | burpsy-only placement |
| Follow the system theme | — | burpsy-only |
| Comfortable table rows | — | burpsy-only |
| Reset panel layout | — | burpsy-only (splitters, not tabs) |
| — | **Restore default tab layout** | **HIGH** — named string confirmed; burpsy's "Reset panel layout" resets splitters, not tab visibility/placement |
| — | **One entry per top-level tab, checked when visible** ("Hidden tabs are identified by an icon beside the tab name… click the tab's name to redisplay it") | **HIGH** — whole Burp menu section absent; burpsy's Tools menu is the same list but with no hide state |

### 1.7 `Help` menu
Burp source: `burp.Zup4` (`mainHelpMenu`).

| burpsy (live) | Burp | Delta |
|---|---|---|
| Keyboard shortcuts (?) | *(Hotkeys live in Settings)* | burpsy-only |
| Command palette (mod+K) | — | burpsy-only |
| — | **Burp Suite documentation / Getting started / Using Burp Suite** | **MEDIUM** — burpsy ships docs on the **Discover** page but never links them from Help |
| — | Support Center | LOW |
| — | Report bug | LOW |
| — | **Diagnostics** | MEDIUM — burpsy has Settings › Diagnostics, unlinked from Help |
| — | Health check for Burp's browser | MEDIUM — burpsy has Settings › Browser engine, unlinked |
| — | Check for updates / Release notes / Download other installers | LOW |
| — | License / Clean Burp from computer | LOW |

### 1.8 Missing whole menu: `Intruder`
Burp source: `burp.Zcur` (`mainIntruderMenu`). burpsy has **no Intruder menu** (the live bar is burpsy/File/Repeater/Tools/View/Help — enumerated by `.menu-bar .menu-trigger`, positive control: all six opened and returned items).

Burp's items: **Start attack**, **Open saved attack**, **Save attack config**, **Load attack config**, Copy attack config, Copy configuration from first tab, Copy configuration from last tab, Use default attack configuration, Configure predefined payload lists, New tab behavior (With payload positions / Without payload positions / Automatic payload positions), Close attack results preferences, Scan defined insertion points, Do active scan, Do passive scan, Send to Repeater, Append to base parameter value, Replace base parameter value.

**HIGH** — a whole Burp top-level menu absent, and its first four items are the core attack-config workflow.

### 1.9 Tool-tab strip

burpsy (live, `nav[aria-label="Tools"]`), left to right:
`Dashboard · Target · Proxy · Intruder · Repeater · Collaborator · Sequencer · Decoder · Comparer · Logger · Organizer · Session · Extensions · Discover · Settings` — 15 tabs, each with a `title` carrying its hotkey. Right-hand icon buttons: **Command palette (mod+K)**, **Search across tools**, **Keyboard shortcuts (?)**, **Settings**, **Use light theme**. Burp puts Settings and Search on the tab bar too (`search.html`: "click **Search** on the tab bar") — ✓.

| Capability | burpsy | Burp | Delta |
|---|---|---|---|
| Drag to reorder tabs | **no** — `tool-tab` has `draggable === null` | yes (`customize-top-level-tabs.html`) | **MEDIUM** |
| Right-click a tab → menu | **no** — right-click on the Proxy tab returned **0** `[role=menu] [role=menuitem]`. **Positive control:** the identical pointerdown/mousedown/contextmenu sequence on a history row in the same evaluate returned **28** menuitems. | **Detach tab / Reattach tab / Hide tab** (strings `suiteTabBarMenuDetach`, `suiteTabBarMenuReattach`, `suiteTabBarMenuHide`) | **HIGH** — a whole Burp affordance absent |
| Detach a tab into its own window | no | yes | MEDIUM (a browser tab is a partial substitute) |
| Hide a tab | no | yes | MEDIUM |
| Tab order matches Burp | Dashboard→Organizer identical; then burpsy adds Session, Extensions, Discover, Settings | Burp's trailing tab is **Extensions** (`managing-extensions.html`: "Extensions > Installed tab"); whether anything follows it was not verified | LOW |

### 1.10 Status bar
burpsy (live, `.statusbar`), 8 read-only segments, **zero interactive elements** (`sb.querySelectorAll('button,a,[role=button]')` → `[]`): `event stream connected` · `10.9 KB stored` · `127.0.0.1:18280` · `10 exchanges` · `66 messages` · `scope: 0 rules` · `no CA` · `last event 30s ago`.

**Burp has no status bar.** `grep -ril "status bar"` over the whole bundled desktop documentation tree returns nothing. Classify as **burpsy-only**, not a delta. The one parity note: every segment is dead text — the proxy bind, scope count and CA state are all things Burp makes clickable from elsewhere, so making them navigate (bind→Proxy settings, scope→Scope, CA→Settings › Certificate) is **LOW** polish, not a gap.

### 1.11 Command palette
burpsy (live, `mod+K` button): header "Command palette / esc", then groups **GO TO** (27 navigation actions, every leaf, with `Tool › Leaf` labels and alt hotkeys on entry leaves), **APPEARANCE** (Switch to light theme mod+shift+L; Use comfortable table rows), **SEARCH** (Search across tools…), **HELP** (Show keyboard shortcuts ?; CA certificate unavailable — TLS interception is off; Export the findings report (HTML)).

Burp (`tools/command-palette.html`): Core commands (switch tabs, open tools, **encoding data**, exporting content), Search (appears at the bottom as you type), Settings ("Find and open Burp's settings"), Extensions ("find and open extensions in the BApp Store"), Extension-created commands, **recently used commands at the top**, per-command **hotkey shown beside the description**, and a **Label** column naming the category.

| Delta | Class |
|---|---|
| No **recently used at top** | MEDIUM — documented Burp behaviour, purely client-side to add |
| No **individual settings** in the palette — one "Settings" nav action, not one action per setting page/section | **HIGH** — Burp's palette is the primary way to reach a specific setting; burpsy's 20-section single-scroll Settings page makes this worse, not better |
| No **encode/decode commands** ("encoding data" is called out as a core command) | MEDIUM — the editor already has 18 encode actions on its context menu; surfacing them costs a palette entry each |
| No **extension-registered commands** | MEDIUM — `/api/extensions` returns registrations; nothing feeds the palette |
| Group label rendered as a section header rather than per-row Label | LOW |

### 1.12 Keyboard-shortcuts dialog
burpsy (live, `?` button) — 5 groups, 22 rows:
- **SEND TO**: mod+r Repeater · mod+i Intruder · mod+o Organizer · Enter (focused row → Repeater) · right-click (all row actions)
- **PROXY**: mod+f forward held · alt+t toggle interception (annotated "Burp uses mod+T; browsers reserve it")
- **MESSAGE EDITOR**: mod+U/mod+shift+U · mod+H/mod+shift+H · mod+B/mod+shift+B · mod+S · mod+enter
- **NAVIGATION**: mod+k palette · mod+alt+right / mod+alt+left (next/prev tool tab) · alt+1…0 · ↑↓ · PgUp/PgDn · Home/End
- **APPEARANCE AND HELP**: mod+shift+l theme · ? this list

The dialog annotates each divergence from Burp in-line, which is better than Burp does. Burp's own dialog equivalent is `Settings › User interface › Hotkeys` (`ui/hotkeys.html`): a **table you double-click to rebind**. burpsy has that too — Settings › Hotkeys, with a search box and per-row **Edit** (`settings.tsx` `HotkeysSection`, "N reassignable, N fixed"). **✓ parity, and burpsy states which rows are fixed and why, which Burp does not.** LOW delta only: Burp requires every hotkey to include Cmd/Ctrl; burpsy allows `alt+N` and `?`.

### 1.13 Context menu — history row
burpsy (live, right-click on a `tbody tr.data-row` in `#history`) — 28 items, 6 separator-delimited groups, none disabled:

Send to Repeater (R) · Send to Intruder (I) · Send to Sequencer (Q) · Send to Comparer (A) · Send to Comparer (B) · Send to Decoder — Change request method (GET/POST) · Change body encoding ▸ · Toggle chunked transfer framing — Copy URL · Copy as curl · Copy exchange id (#6) · Copy request to file · Copy links · Save request and response — Highlight ▸ · Add comment — Add to Organizer · Filter history by 127.0.0.1 · Open URL in browser · Show response in browser — Add 127.0.0.1 to scope · Audit exchange #6 · Actively scan this branch (crawl) · Actively scan this host (crawl) — Record an issue · Generate CSRF PoC — Copy response bytes

Against Burp's documented common context menu (`tools/context-menu.html`, 40 options):

| Burp option | burpsy | Class |
|---|---|---|
| Send to… / Add comment / Add to scope / Change request method / Change body encoding / Copy / Copy as curl command / Copy links / Copy to file / Copy URL / Do active scan / Highlight / Paste host / URL as request / Record an issue / Save items / Scan / Show response in browser / Request in browser | ✓ | — |
| **Engagement tools** (`tools/engagement-tools/index.html` names six: Find references · Discover content · Schedule task · Target analyzer · Generate CSRF PoC · Manual simulator. `tools/search.html` puts **Find comments** and **Find scripts** in the same submenu on the site map.) | only **Generate CSRF PoC**, flat | **HIGH** — a whole Burp submenu with 8 entries; burpsy has the *pages* for several (`Target › Content discovery`, Settings › Scheduled tasks, `/api/search`) but no context-menu route into them from a row |
| **Add notes** | ✗ (has Add comment) | MEDIUM |
| **Add to site map** | ✗ | MEDIUM |
| **Audit again** | ✗ (has Audit exchange #N) | LOW |
| **Compare site maps** | ✗ | MEDIUM |
| **Delete items / Delete issue** | ✗ | MEDIUM |
| **Do passive scan** | ✗ (only active) | MEDIUM |
| **Export as CSV** | ✗ | MEDIUM |
| **Documentation** ("opens the relevant documentation") | ✗ | MEDIUM — burpsy has Discover, unlinked |
| **Show details in new window** | ✗ | MEDIUM |
| **Show insertion points / Scan defined insertion points** | ✗ | MEDIUM |
| **Set severity / Set confidence / Go to issue / Report issue** | ✗ on a history row | LOW (issue-table context, out of my page scope) |
| **Save entire history** | ✗ | LOW |
| **Insert Collaborator payload** | ✗ on a row (✓ in the editor) | LOW |
| Column header right-click → **Copy column / Hide column / Sort** (`customize-tables.html`) | **not checked in this sweep** | — |

### 1.14 Context menu — Repeater request / response pane
burpsy (live, right-click on `.cm-content`). Positive control: both panes returned menus; the disabled/enabled split is meaningful (encode actions correctly disabled with no selection).

**Request pane, 26 items:** Change body encoding: Form URL-encoded · Multipart form · JSON *(disabled — body is form-encoded)* · Toggle body encoding *(disabled)* — **Insert Collaborator payload** — URL-encode (Ctrl+U) · URL-encode all characters · URL-encode all characters (Unicode %uXXXX) · URL-decode · HTML-encode · HTML-encode all (numeric) · HTML-encode all (hex) · HTML-decode · Base64-encode · Base64-decode · Base64-URL-encode · Base64-URL-decode *(all disabled, no selection)* — JavaScript (double-quoted) · JavaScript (single-quoted) · SQL for Microsoft SQL Server · SQL for Oracle · SQL for MySQL *(disabled)* — Find in this message (Ctrl+S)

**Response pane, 20 items:** the same encode/convert block + Find in this message. The "Actions for Request" toolbar button opens the identical menu.

| Burp option on a message editor | burpsy | Class |
|---|---|---|
| Change body encoding / Toggle body encoding | ✓ | — |
| Convert selection (URL, HTML, Base64) | ✓, and richer (Unicode %u, hex, JS, 3 SQL dialects) | burpsy wins |
| Insert Collaborator payload | ✓ (request pane only — correct) | — |
| **Send to…** | **✗** — not in either pane's menu; only a "To Intruder" toolbar button | **HIGH** — Burp's editor context menu is how you move a crafted request to Intruder/Comparer/Sequencer; burpsy exposes exactly one of those, as a button |
| **Copy / Cut / Paste / Paste from file / Copy to file** | ✗ in the menu; "Paste from file", "Copy message", "Save to file" are toolbar buttons | MEDIUM |
| **Copy as curl command / Copy URL / Copy links** | ✗ in the editor (✓ on a history row) | MEDIUM |
| **Request in browser / Show response in browser** | ✗ in the editor (✓ on a history row) | MEDIUM |
| **Add comment / Add notes / Highlight** | ✗ in the editor | MEDIUM |
| **Show insertion points / Scan defined insertion points / Do active scan** | ✗ | MEDIUM |
| **URL-encode as you type** | ✗ | MEDIUM |
| **Engagement tools** | ✗ | HIGH (same item as §1.13) |
| **View** (change editor view settings) | ✓ as PRETTY/RAW/HEX/PARAMS tabs + "Disable wrapping" / "Show non-printing characters" toolbar toggles | ✓ |

### 1.15 Search dialog (bonus — reached from the shell)
burpsy (live): SEARCH FOR (text/pattern) · Case sensitive · Regular expression · Negative matches · In scope only · LOCATION (Request and response / Request only / Response only) · WITHIN (Headers and body / Headers only / Body only) · TOOLS TO SEARCH (Proxy history, Crawler, Repeater, Intruder, Scanner, Organizer) · Search button · result list · preview pane.

Burp (`tools/search.html`) asks for exactly: expression, case sensitive, literal-vs-regex, negative matches, in-scope only, **dynamic update**, locations, tools (Target, Repeater, Proxy, Organizer).

| Delta | Class |
|---|---|
| No **Dynamic update** ("results update as new HTTP messages are processed") | MEDIUM — `/api/search` is a one-shot POST; the event stream already exists to drive it |
| Result table columns not verified (no results in this state) | — |
| burpsy searches 6 tools to Burp's 4 | burpsy wins |

---

## 2. Pages

### 2.1 Session (`#session`)

| Claim | Status | Evidence |
|---|---|---|
| Session/login rules list | ✓ | live: `H2: Login rules`, "Rules are matched by host; the first that applies owns the recovery", `0 CONFIGURED`, empty state + New rule |
| Rule editor — Details tab equivalent | ✓ | live: NAME, ENABLED toggle, MAX ATTEMPTS, `H2: Rule actions` |
| Rule editor — Scope tab equivalent | ✓ | live: 9 tool checkboxes (repeater, intruder, scanner, sequencer, comparer, session, decoder, crawler, proxy); URL scope radios **Include all URLs / Use suite scope [defined in Target tab] / Use custom scope**; "New scope parameter" + Add parameter |
| Rule **actions** vocabulary | ✓ **8 of Burp's 9** | live `<select>`: Run a macro · Run a post-request macro · Check whether the current session is valid, and perform sub-actions conditionally · Add cookies from the session handling cookie jar · Set a specific cookie value · Set a specific parameter value · Set a specific header value · Replace matching part of the request · Invoke an extension. Burp's list (`settings/sessions/session-handling-rules.html`) adds **Prompt the user for in-browser session recovery** → **MEDIUM**, and merges cookie/parameter into one action (burpsy splits it — clearer). |
| Action ordering + terminal flag | ✓ | live: Move action N up/down, Remove action N, "No further actions apply to this request" checkbox — matches Burp's "unless one of the actions specifies that no further actions should be applied" |
| Session-validity inspection | ✓ | live: STATUS IS · BODY CONTAINS · BODY DOES NOT CONTAIN · HEADER PRESENT · HEADER ABSENT · REDIRECT TARGET URL CONTAINS · Regular expression · Case sensitive — covers Burp's "headers / body / URL of any redirection target, literal or regex, case sensitive" exactly |
| Macro editor | ✓ | live: `H2: Macro steps`, **Record from history** (= Burp's Macro Recorder), Add step, per-step method/URL/headers/body, Move/Remove step, **Add extraction**, **Test macro** — matches Burp's Record / Configure item / Test macro |
| Parameter derivation from a prior response | ✓ (as "extraction") | live: Add extraction; textarea placeholder `user=admin&password={{password}}` shows templating |
| **Re-analyze macro** | ✗ | Burp auto-derives relationships and offers "Re-analyze macro"; burpsy's extraction is manual → **MEDIUM** |
| **Custom parameter locations in response** | ✗ | Burp's response-extraction-rules dialog → **LOW** (burpsy's extraction covers the common case) |
| Cookie jar | ✓ | live: AUTHORITY/NAME/VALUE table, Refresh jar, Empty jar, Edit cookie, Remove cookie. Burp's per-macro-item "add received cookies to the jar / add jar cookies to the request" toggles → **MEDIUM**, not seen |
| Probe / "Log in again" | ✓ burpsy-only framing | live: PROBE METHOD/URL/HEADERS/BODY + **Run login now** |
| Rule state is wired | ✓ | live badge `WIRED`; Go: `/api/session/rules`, `/api/session/rules/`, `/api/session/login`, `/api/session/macro-steps`, `/api/session/cookies` |

Verdict: **Session is the closest page to Burp in this whole sweep.** The audit's table for it was right; two real MEDIUMs remain (in-browser recovery prompt; re-analyze macro).

### 2.2 Discover (`#discover`)
Live: search box "Search the reference" + 10 sections — What burpsy does not do · Query language · BCheck syntax · Keyboard — Send to · Keyboard — Proxy · Keyboard — Message editor · Keyboard — Navigation · Keyboard — Appearance and help · Shipped documentation.

**Burp has no Discover tab.** This is burpsy-only, and the audit's "Content discovery (ffuf) = No / HIGH" is **wrong on both counts**: content discovery is a different page (`Target › Content discovery`, palette description "Sweep a path space with ffuf, and what the scope check dropped", Go route `/api/discovery`), and Discover is a documentation hub.

| Delta | Class |
|---|---|
| Not linked from Help, and not from any context menu ("Documentation" — "opens the relevant documentation" — is a documented Burp context-menu option) | **MEDIUM** — reachable only by its tab, the Tools menu or the palette; nothing that is *about* documentation points at it |
| Named "Discover", which in Burp vocabulary means *content discovery* | **MEDIUM (naming)** — an operator reading the tab strip will expect ffuf here and find a docs index |

### 2.3 Extensions › Installed (`#extensions`)
**Sub-tab count:** burpsy has 3 (Installed · Options · APIs, from `nav.ts` leaf ids `extensions`/`extenderoptions`/`extenderapis`). Burp has **5** — `Extensions > Installed`, `> BApp Store`, `> APIs`, `> Bambda library`, `> Custom scan checks` (all five paths appear verbatim in the bundled docs).
Live state: no plugin allowlisted, so the table is replaced by an empty state. Metrics rendered: ALLOWLISTED 0 · LOADED 0 · NOT LOADED 0 · FAILED TO LOAD 0 ("Never completed the handshake") · EXITED ON THEIR OWN 0.

Populated shape read from `pages/extensions.tsx` (**source, not live** — this server has no plugin):
- `SimpleTable headers={["Loaded","Name","Type","Version","State","Registrations","Console",""]}` (line 354)
- per-row Load/Unload toggle (lines 368, 402) → `/api/extensions/load`, `/api/extensions/unload`
- per-plugin **Registrations** list (line 258), **Output console** (266) and **Error console** (277) → `/api/extensions/console`

| Burp (`extend-burp/extensions/managing-extensions.html`) | burpsy | Class |
|---|---|---|
| Installed tab lists extensions in processing order | ✓ | — |
| **Loaded checkbox** to disable without removing | ✓ (Load/Unload) | — |
| **Details / Output / Errors** tabs per extension | Registrations + Output console + Error console | ✓ (Details≈Registrations) |
| **Up / Down** to reorder (order = request processing order) | **✗** | **HIGH** — in Burp the list order *is* the pipeline order; without it an operator cannot control which plugin sees a request first |
| **Add** (manual install) | **✗ by design** | Page says so explicitly: "start burpsy with `-plugins name=/path/to/plugin`… Loading a plugin runs operator-supplied code in this process, so nothing can be admitted from the browser." **This is a stated design decision, not a gap.** The audit's "Add extension = No / HIGH" should be re-classed. |
| **Remove** (uninstall) | ✗ | **MEDIUM** — consistent with the allowlist model, but Unload-then-forget is not offered either |
| **Auto-reload** on file change, Ctrl+click to reload | ✗ | MEDIUM — a real developer-loop item; `/api/extensions/load` already exists to build on |
| **Extensions settings** button | ✓ as the sibling **Options** tab | ✓ |
| Use AI / AI credits used | ✗ | n/a |
| Column reorder / resize / right-click Copy column | ✗ | LOW |
| **Bambda library** tab (`Extensions > Bambda library`, with Import) | ✗ | **MEDIUM** — Burp's filter/expression library; burpsy's nearest is the Discover page's query-language reference, which is documentation, not a stored library |
| **Custom scan checks** tab (`Extensions > Custom scan checks`, with Import) | ✗ as a tab | **MEDIUM** — burpsy interprets BChecks (Discover documents the syntax) but has no Extensions sub-tab to import or manage them |
| **BApp Store** tab | ✗ **by design** | Extender options states it: "There is no plugin registry, store or install path… the server reports `registry: null` on this surface rather than leaving the absence to be inferred." **Correctly classified as deliberate, not a gap.** |

### 2.4 Extender options (`#extenderoptions`)
Live: **Admission** table (SETTING/VALUE/WHY, 5 rows) — Allowlist flag `-plugins name=/path/to/plugin` · Plugins allowlisted 0 · Shell **NEVER USED** · Environment passed to a plugin `PATH HOME LANG TMPDIR` · Protocol version 1. **Bounds**: LOAD TIMEOUT 10.0 s · CALL TIMEOUT 30.0 s · SHUTDOWN GRACE 2.0 s · CONSOLE LINES 500 · CONSOLE LINE BYTES 8,192 · MESSAGE BYTES 1,048,576 · REGISTRATIONS 64. **There is no store** (explanatory).

Burp's equivalent (`settings/extensions.html`) is *Core extension settings*: Startup behavior (auto-reload extensions on startup, auto-update installed BApps), Load behavior (hide dialog when reloading), Java environment (library folder), Python environment (Jython JAR, module folder), Ruby environment (JRuby JAR) — plus extension-generated settings panels.

| Delta | Class |
|---|---|
| **Every value is read-only.** Burp's whole extensions settings page is editable; burpsy's is a report of what the process was started with. | **MEDIUM** — defensible (the allowlist is a startup act), but the *bounds* (timeouts, console limits, registration cap) have no reason to be restart-only and no route to change them. |
| **Automatically reload extensions on startup** | MEDIUM — no counterpart |
| Java / Python / Ruby environment | **n/a by design** — plugins are local executables speaking JSON-RPC, not JVM classes. The audit's "Ruby/Python/Java config = MEDIUM" is a category error for this architecture. |
| **Extension-generated settings panels** ("if an extension includes settings, you'll see a panel labeled with the extension's name") | **MEDIUM** — `/api/extensions` returns registrations; no registration kind produces a settings panel |
| Every bound carries a WHY column | burpsy wins — Burp documents none of this in-product |

### 2.5 Extender APIs (`#extenderapis`)
Live: **Transport** (3 rows) · **Registration points** (KIND / INVOKED BY / WHAT IT IS / **BURP'S EQUIVALENT**, 4 rows) · **Methods** (METHOD / DIRECTION / CALL / PARAMS / RESULT / WHY, 7 rows) · **What a plugin cannot do** (NOT OFFERED / WHY, 4 rows). Protocol version 1. Go: `/api/extensions/apis`.

Burp's third Extender tab is the **Java API javadoc viewer** (`burp.api.montoya`). burpsy's is a rendered contract for its own JSON-RPC protocol.

| Delta | Class |
|---|---|
| Not Burp's API (Montoya) and cannot be | **n/a** — different extension model; the page's own "BURP'S EQUIVALENT" column makes the mapping explicit, which is the right answer |
| No **JMenu items** / **hot key handlers** registration kind (audit called both MEDIUM) | **MEDIUM, confirmed still open** — only 4 registration kinds exist; nothing a plugin registers can appear in a context menu, the menubar or the command palette. This is the same root as §1.11's "no extension-registered palette commands". |
| Read-only reference page with no "try it" | LOW |

### 2.6 Settings (`#settings`)
Live, in render order — 20 sections on **one continuous scroll**:
Proxy (3 radios + Refresh) · Resource pools (New pool) · What each tool honours (TOOL/ROUTE/MAX CONCURRENT/DELAY/THROTTLING/WHY NOT, 3 rows) · Scheduled tasks (New schedule) · Protocols (DOWNGRADE REASON/COUNT, 19 rows) · Negotiation probe (host, port, Use TLS, Probe negotiation) · **Network** (Hostname resolution + Add override; DNS lookup System resolver / A resolver I name; Timeouts ×3; Redirections Never / On-site only / In-scope only / Always (still scope-checked) + max; 100-continue ×2 + timeout; Open-ended responses; Revert / Save) · Scanner (Server default; Presets NAME/KEYS SET, 6 rows) · Browser engine · Upstream proxy and SOCKS (default + per-host rules, Clear all) · Platform authentication (host / Basic|Digest / user / password / realm, Add rule) · Client TLS certificates (host / p12 path / password, Bind certificate) · Appearance (theme / density / zoom 100–150% / font 12–18px) · **Hotkeys** (search + per-row Edit, "N reassignable, N fixed") · Certificate (Re-check) · Use your own CA (PEM cert + PEM key, Import CA) · Uninteresting headers (request + response lists, Restore response defaults) · Project backup (directory, snapshots to keep, Back up now) · Diagnostics.

Burp's Settings dialog tree (`settings/index.html`): **Tools** (Burp's browser, Comparer, Intruder, Proxy, Repeater, Sequencer) · **Project** (Automatic backup, Collaborator, Logging, Scope, Tasks) · **Sessions** (Session handling rules, Macros) · **Network** (Connections, DNS, HTTP, TLS) · **User interface** (Display, Hotkeys, Message editor, Side panel) · **Suite** (Early adopter, Performance, REST API, Shutdown behavior, Startup behavior, Temp files location, Updates) · **AI** · **Extensions** · **Configuration library**.

| Claim | Status | Evidence / delta |
|---|---|---|
| Network settings (Connections/DNS/HTTP/TLS) | ✓ | live Network + Protocols + Upstream proxy + Platform auth + Client TLS sections cover all four Burp pages |
| Automatic backup | ✓ | live Project backup; Go `/api/backup` |
| Hotkeys | ✓ | live, editable, with a search box — matches `ui/hotkeys.html` |
| Display (theme/density/zoom/font) | ✓ | live Appearance |
| Resource pools / tool limits | ✓ | live; audit already had this ✓ |
| **No navigation tree** | ✗ | **HIGH** — Burp's Settings is a dialog with a left-hand tree, a **Search bar**, and **All / User / Project** filter buttons. burpsy is a single 20-section scroll with no tree, no search and no filter. This is the most visible "doesn't look like Burp" difference on any page in my scope. |
| **No Restore defaults / Save settings / Load settings** in the page | ✗ | **HIGH** — Burp puts "Manage global settings → Restore default settings / Save settings / Load settings" here, and per-setting actions on a per-row icon. burpsy has Export/Import configuration **on the File menu only** (`/api/config/export`, `/api/config/import`) and a section-local "Revert"/"Restore response defaults". |
| **No user-vs-project split** | ✗ | **MEDIUM** — Burp's "Override options for this project only" toggle has no counterpart because burpsy has no project files (same root as §1.3) |
| **Message editor settings** | ✗ | **MEDIUM** — Burp's `ui/message-editor.html` page; burpsy's editor toggles live only on the per-pane toolbar |
| **Side panel settings** | ✗ | LOW |
| **Suite: REST API** | ✗ | **MEDIUM** — burpsy *is* a JSON API; there is no page describing or gating it |
| **Suite: Performance / Startup / Shutdown / Temp files / Updates / Early adopter** | ✗ | LOW each |
| **Configuration library** | ✗ | **HIGH** (same item as §1.2) — Burp's named scan configs; burpsy has Scanner Presets (6 rows, read-only "KEYS SET") which is the seed of it but no library CRUD |
| **AI settings** | ✗ | n/a |
| Sessions / Scope / Collaborator / Extensions settings live on their own tabs, not in Settings | — | **LOW (placement)** — defensible for a tab-per-tool console, but it means Burp's "Settings" mental model doesn't transfer |
| Scanner presets are read-only | ✗ editable | MEDIUM — Burp's scan configs are fully editable |

### 2.7 Collaborator (`#collaborator`)
Live state: `NOT CONFIGURED` (no `-collaborator-server`, no `-blindxss`). Rendered: **Interaction server** (Server URL, Client binary path, **Set server**) · **Interaction channel** (payload count `number` input, **Copy payload**, **Poll now**, empty state) · **Blind XSS callbacks** (**Copy script tag**, empty state).
Populated shape from `pages/collaborator.tsx` (**source**): Interactions table `["#","Type","Client IP","Payload","Time","Read","Note",""]` (line 405); blind-XSS table `["Token","Script URL","State","Hits","Last hit"]` (line 270). Go: `/api/collaborator/server`, `/payload`, `/poll`, `/interactions`, `/interaction/`, `/status`, `/api/blindxss`, `/api/blindxss/payload`.

| Burp (`tools/collaborator/index.html`) | burpsy | Class |
|---|---|---|
| **Payloads to generate** field | ✓ (number input) | — |
| **Copy to clipboard** | ✓ (Copy payload) | — |
| **Poll now** (Burp auto-polls every 60 s) | ✓ button | — |
| **Auto-poll every 60 s** | **not evidenced** — only a manual button is rendered | MEDIUM |
| **Include Collaborator server location** checkbox | **✗** | MEDIUM — Burp lets you emit a bare ID rather than a full address |
| Interactions list with per-interaction detail | ✓ (table + `/api/collaborator/interaction/`) | — |
| **Insert Collaborator payload** in Repeater | ✓ | confirmed live in §1.14 |
| **Collaborator payloads as an Intruder payload type** | not checked (Intruder out of scope) | — |
| Configure the server *from the UI* rather than a restart | ✓ **Set server** | **burpsy wins** — Burp needs Settings › Project › Collaborator |
| **Blind-XSS callback channel** | ✓ | **burpsy wins** — Burp has no equivalent |
| Private-server deployment | ✗ by design, stated on the page | n/a |

---

## 3. Ranked still-open items

Every item below was verified absent live (or read from source where the live state could not reach it). "Go side" says whether the backend already serves it.

**1 — The Settings page has no tree, no search and no filter (HIGH).**
Live: 20 `<h2>` sections on one scroll, no navigation affordance of any kind. Burp's Settings is a dialog with a left tree, a **Search** bar and **All / User / Project** buttons — and `tools/command-palette.html` says the palette's job is to "find and open Burp's settings", which burpsy's palette also cannot do (one "Settings" nav action, §1.11). *Sketch:* `pages/settings.tsx` — the sections are already discrete `<Card>`s with `SectionHeading title=`; lift those titles into a `SETTINGS_SECTIONS` array, render a sticky left rail (`position: sticky` two-column grid, the same shape `discover.tsx` already uses for its 10-section index), add a filter input that hides non-matching cards, and emit one palette action per section (`Settings › Network`, `Settings › Hotkeys`, …) from `ui/palette.tsx`. *Go side:* **not needed** — presentation only. Cheapest large win in the list.

**2 — Burp's `Intruder` menu is absent (HIGH).**
The only whole Burp top-level menu with no burpsy counterpart, and its first four items — **Start attack, Open saved attack, Save attack config, Load attack config** — are the attack-configuration workflow an Intruder user reaches for constantly. *Sketch:* `ui/src/app.tsx`, beside the existing `Repeater` `DropdownMenu` in the `.menu-bar` (the trigger list is built in the same JSX block that yields `burpsy/File/Repeater/Tools/View/Help`). Items: `Start attack` / `Stop attack` (dispatch to the Intruder page's existing run action), `Save attack config` and `Load attack config` (JSON download/upload of the positions+payloads state), `Go to Intruder (alt+4)`. *Go side:* **partly.** `/api/intruder/run`, `/api/intruder/attacks`, `/api/intruder/attacks/`, `/api/intruder/points`, `/api/intruder/payload-files` all exist, so Start/Stop need no new route; **save/load of an attack *config* has no route** and would need one (or a pure client-side serialise of the Intruder store, which is the cheaper first cut).

**3 — Burp's `View` menu is a tab-visibility list; burpsy's is a theme menu (HIGH).**
Burp's View menu holds one checkable entry per top-level tab (`mainViewMenuOption:%s`) plus **Restore default tab layout** (`mainViewMenuRestoreDefaultLayout`); hiding a tab is how a Burp user focuses. burpsy's View menu is Light theme / Follow system / Comfortable rows / Reset panel layout, and the tab list sits in a non-Burp **Tools** menu as *navigate* actions. *Sketch:* `app.tsx` — move the `TOOLS.map(...)` block out of the Tools menu into View as `DropdownMenuCheckboxItem`s bound to a new `hiddenTools: Set<string>` in the UI store (`lib/store.ts`, persisted alongside `theme`/`density`), have `nav[aria-label="Tools"]` filter on it, and add `Restore default tab layout` to clear the set. Keep the alt+N hotkeys working on hidden tabs (Burp: "if you send a request to a hidden tab, that tab reappears"). *Go side:* **not needed** — pure client state, same as theme.

**4 — No tool-tab context menu (HIGH).**
Right-clicking a tab does nothing (0 menuitems; positive control on a history row in the same call returned 28). Burp has exactly three items there: `suiteTabBarMenuDetach` / `suiteTabBarMenuReattach` / `suiteTabBarMenuHide`. *Sketch:* `app.tsx`, wrap each `.tool-tab` `<button>` in the same `ContextMenu` primitive the history table already uses (`ui/menu.tsx`). **Hide tab** writes the `hiddenTools` set from item 3 — do them together. **Detach tab** maps naturally to `window.open('#'+leafId)` on a route-only shell; **Reattach** is then "close that window". Also set `draggable` on the tab and implement drop-reorder into a persisted `toolOrder` array. *Go side:* **not needed.**

**5 — No `Send to…` on the Repeater editor context menu (HIGH).**
Both panes' menus are encode/convert/find only; the sole send action anywhere on the page is a `To Intruder` toolbar button. In Burp, `Send to…` is on every message editor. *Sketch:* `pages/repeater.tsx` — the editor's context menu is built where the "Actions for Request" `DropdownMenu` groups are assembled; add a leading group reusing the exact action list the history row already builds (`pages/history.tsx` row menu): Repeater (new tab), Intruder, Sequencer, Comparer (A)/(B), Decoder, plus Copy URL / Copy as curl / Copy links / Show response in browser. *Go side:* **already served** — `/api/repeater/send`, `/api/intruder/points`, `/api/sequencer/capture`, `/api/tools/compare`, `/api/tools/decode`, `/api/exchange/in-browser/` are all live; this is wiring, not new backend.

**6 — No `Engagement tools` submenu (HIGH).**
Burp's context menu has an 8-entry Engagement tools submenu; burpsy has one of its members (Generate CSRF PoC) flat on the row menu. *Sketch:* `pages/history.tsx` row menu — add a `sub` group "Engagement tools" holding **Find references** (`/api/search` scoped to responses linking the row's URL as a prefix), **Find comments / Find scripts** (`/api/search` with a canned regex, per `search.html`), **Discover content** (navigate to `#contentdiscovery` pre-seeded with the row's host+path), **Schedule task** (navigate to Settings › Scheduled tasks), **Generate CSRF PoC** (move the existing item in). Burp's remaining two — **Target analyzer** and **Manual simulator** — have no burpsy counterpart at all and are separate items, not part of this wiring. *Go side:* **mostly served** — `/api/search`, `/api/discovery`, `/api/schedules` all exist; only the canned search presets are new UI.

**7 — No `Configuration library` (HIGH).**
Burp's `Burp` menu entry and Settings tree node; burpsy has Settings › Scanner › Presets rendered read-only (NAME / KEYS SET, 6 rows). *Sketch:* `pages/settings.tsx` ScannerSection — make the presets table editable (name, clone, delete, set-as-default) and let a scan launch pick one by name. *Go side:* **partly** — `/api/scanner/configs` and `/api/scanner/config` exist; whether they accept a write was not verified in this sweep.

**8 — No project-file concept (`File` vs `Project`) (HIGH, but arguably a product decision).**
Burp's Project menu is New project / Open / Save copy / Rename / Restore; burpsy's File menu is report exports + config import/export. *Sketch:* if this is ever taken on, the honest version is not "project files" but naming the capture: `/api/backup` already snapshots to a directory with a keep-count (Settings › Project backup). A `File → Save a copy…` that calls `/api/backup` and a `File → Restore…` that picks a snapshot would close most of the practical gap without inventing a file format. *Go side:* `/api/backup` exists; restore-from-snapshot does not appear in the route table.

**9 — Extensions list has no Up/Down reorder (HIGH within the page).**
Burp: "Requests and responses pass through the extensions in the order that they are listed" — order is semantics, not cosmetics. *Sketch:* `pages/extensions.tsx` line 354 table, add a leading column with the same Move-up/Move-down `IconButton` pair `session.tsx` already uses for rule actions. *Go side:* **no** — needs an order field on the plugin host (`internal/extension/host.go`) and a route to set it; nothing in the route table carries ordering today.

**10 — Nothing a plugin registers can reach the UI chrome (MEDIUM).**
Extender APIs shows 4 registration kinds; Burp extensions add **context-menu items**, **hotkeys** and **palette commands**, and the command palette doc names "Extension-created commands" as a first-class category. *Sketch:* add a `menu` registration kind to the protocol (`internal/extension/protocol.go`, which is already in flight in the working tree), surface it in `ui/palette.tsx`'s action list and in the history row menu. *Go side:* **no** — new protocol kind plus a dispatch route (`/api/extensions/invoke` exists and is the natural target).

**11 — Command palette: no recently-used, no per-setting entries, no encode commands (MEDIUM).**
All three are documented Burp palette behaviours. *Sketch:* `ui/palette.tsx` — an MRU array in the UI store re-sorted to the top on empty query; the `SETTINGS_SECTIONS` array from item 1; one action per entry in the editor's existing `PAIRS` encode table. *Go side:* **not needed.**

**12 — Search dialog has no Dynamic update (MEDIUM).** `/api/search` is one-shot; the event stream (`/api/events`) already exists to re-fire it. *Sketch:* `ui/search.tsx`, a checkbox that subscribes the last query to the event stream.

**13 — Help menu links to nothing burpsy ships (MEDIUM).** Burp's Help has Documentation / Getting started / Diagnostics / Browser health check. burpsy *has* all four (Discover page, Settings › Diagnostics, Settings › Browser engine) and links to none of them. *Sketch:* four `DropdownMenuItem`s in `app.tsx` that set `location.hash`. Cheapest item in this list; also fixes Discover's unreachability (§2.2). *Go side:* not needed.

**14 — Session: no "Prompt the user for in-browser session recovery" action, no "Re-analyze macro" (MEDIUM ×2).** The action `<select>` in `pages/session.tsx` is one entry short of Burp's nine; the macro editor's extraction is entirely manual where Burp auto-derives. *Go side:* `/api/session/rules` would need a new action type; re-analyze is a server-side diff of macro responses (`/api/session/macro-steps`).

**15 — Extender options is entirely read-only (MEDIUM).** The admission policy being restart-only is right; the *bounds* (load/call timeout, console limits, registration cap) being restart-only is not argued for anywhere on the page. *Go side:* no write route on `/api/extensions`.

**16 — Collaborator: no "Include Collaborator server location" toggle, no auto-poll (MEDIUM ×2).** *Sketch:* `pages/collaborator.tsx`, a checkbox beside the payload-count input feeding `/api/collaborator/payload`, and a 60 s interval on `/api/collaborator/poll` matching Burp's documented cadence.

**17 — Repeater menu carries none of Burp's 11 global config items (MEDIUM).** burpsy has 4 of them per-tab in the Config panel and no global default for any. *Sketch:* `app.tsx` Repeater menu — a "Default send options" group writing the same shape `SendOptionsPanel` reads, used as the seed for new tabs. *Go side:* not needed if the defaults live client-side.

**18 — Row context menu: Add notes, Add to site map, Do passive scan, Export as CSV, Delete items, Show details in new window, Documentation (MEDIUM, 7 items).** Each is one `DropdownMenuItem` in `pages/history.tsx`. *Go side:* `/api/sitemap`, `/api/scanner/passive-branch` and `/api/history` exist; CSV export and delete do not appear in the route table.

**19 — Status bar segments are dead text (LOW).** 8 segments, 0 interactive elements. Burp has no status bar at all, so this is polish, not parity: make the proxy bind, scope count and CA state navigate to their pages.

**20 — Discover's name collides with Burp's "content discovery" (LOW).** Renaming it to something like "Reference" would stop an operator expecting ffuf there.

---

## 4. Highest-impact item

**#1 — give the Settings page a navigation tree, a search box, and one command-palette entry per section.**

It is first for three reasons the sweep produced directly. It is the largest *visible* divergence on any page in my scope: Burp's Settings is a dialog with a left tree, a search bar and All/User/Project filters, and burpsy's is twenty `<h2>` sections on one uninterrupted scroll with no way to jump, filter or find. It is the only item that compounds with another confirmed gap — `tools/command-palette.html` states that finding settings is one of the palette's core jobs, and burpsy's palette offers a single "Settings" navigate action for all twenty sections, so the two defects reinforce each other and one change fixes both. And it is the cheapest of the nine HIGHs to build: the sections are already discrete `<Card>`s with `SectionHeading title=` props, `discover.tsx` already implements exactly this index-plus-filter shape ten sections wide, and the Go side needs **no change at all** — every route the page calls already exists.

On strict Burp-parity grounds the absent **Intruder** menu (#2) has the stronger claim, because a whole Burp top-level menu is missing and the brief classes that as HIGH. It is ranked second anyway: it needs a new backend route for save/load attack config and touches the Intruder page's run state, where #1 is presentation-only, self-contained in `settings.tsx` plus `palette.tsx`, and is what an operator opening burpsy notices in the first thirty seconds.
