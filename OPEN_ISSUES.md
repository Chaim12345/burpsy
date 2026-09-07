# Open Beads Issues

## [burpsy-react-ui-i4fa] Intruder: attack engine, positions, payloads and results parity

**Beads ID:** `burpsy-react-ui-i4fa`
**Priority:** P1
**Labels:** burp-parity, epic, intruder

### Description

Umbrella for Intruder gaps: manual payload markers, JSON/XML/base64-aware insertion points, recursive grep payloads, results payload/sort/export/handoff, grep-match expression list, retry, baseline request, resource-pool-driven attack quality, cross-tool Collaborator insertion.

---

## [burpsy-react-ui-mun] intruder: Positions has no manual payload markers — Burp's Add §/Clear §/Auto § do not exist, positions are auto-discovered only

**Beads ID:** `burpsy-react-ui-mun`
**Priority:** P1
**Labels:** burp-parity, capability-gap, intruder, positions

### Description

Intruder's Positions tab offers no way to mark a payload position by hand. Positions are whatever
the discoverer found, and nothing else.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/configure-attack/positions.html`
(Burp's own shipped documentation, 2026.7.1). The Positions tab is a request editor with three
buttons — **Add §**, **Clear §**, **Auto §**. The operator selects any bytes in the template request
and marks them. `Auto §` is the automatic guess; it is the *fallback*, not the only mode. The spec at
`/root/burp-re/BURP_SUITE_UI_UX_SPECIFICATION.md:167-168` records the same three buttons.

## burpsy-side evidence

- `internal/intruder/points.go:23-33` — nine fixed `PointKind` families. There is no "manual" or
  "marker" kind, and `InsertionPoint` is only ever constructed by `FindPoints`.
- `internal/web/ui/src/pages/intruder.tsx:706-708` — the base-request editor is `readOnly`, so the
  operator cannot even type a marker.
- `internal/web/ui/src/pages/intruder.tsx:660-691` — the entire position UI is a checkbox per
  discovered point.
- `internal/web/api_tools.go:344-357` (`selectPoints`) and `intruderRunReq.Points` — the wire
  contract carries *indices into the discovered list*, so a hand-marked span cannot be expressed
  even by an API caller.

Absence grep over both the engine and the page:

    $ grep -rni "marker|§" internal/intruder/points.go internal/web/ui/src/pages/intruder.tsx
    internal/web/ui/src/pages/intruder.tsx:1047: ... "Count responses containing a marker ..."
    internal/web/ui/src/pages/intruder.tsx:1060: ... hint="Captures the text after this marker."

Both hits are the *grep-extract* help text, unrelated to positions. Positive control on the same two
files: `grep -n "PointKind" internal/intruder/points.go` → 4 hits;
`grep -c "payload" internal/web/ui/src/pages/intruder.tsx` → 66.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Attack any position the discoverer does not model: a substring of a value (`id=12§34§`), one segment
of a JWT, a field inside a base64 blob, one member of a JSON body, or a slice of a custom binary
parameter. This is the first action in every Burp Intruder workflow.

## Note on scope

The splice path already accepts arbitrary spans — `InsertionPoint{Kind, Span, Label}` plus
`fixContentLength` after every splice (`internal/intruder/points.go:303, 318-327`) will splice a
hand-marked region unchanged. The work is a marker-aware request editor plus a wire shape that can
carry explicit spans alongside discovered indices. Fixing this also subsumes the JSON-body gap filed
separately, because a `§`-capable editor lets an operator target a JSON field by hand.


### Acceptance Criteria

The Positions tab lets an operator mark an arbitrary byte range in the base request as a payload position, and an attack runs against hand-marked positions as well as discovered ones.

---

## [burpsy-react-ui-oco4] Scanner & scope: config parity and re-triage

**Beads ID:** `burpsy-react-ui-oco4`
**Priority:** P1
**Labels:** burp-parity, epic, scanner, scope

### Description

Umbrella for Scanner/Scope gaps: only 4/78 scan-config keys exist, findings cannot be re-triaged (severity/confidence/delete/false-positive), no drop-all-out-of-scope switch, scope rules cannot be edited in place.

---

## [burpsy-react-ui-p0na] Repeater: redirect chains, connection reuse and history snapshots

**Beads ID:** `burpsy-react-ui-p0na`
**Priority:** P1
**Labels:** burp-parity, epic, repeater

### Description

Umbrella for Repeater gaps: final redirect-chain response never returned, no Send-group / connection reuse for race-condition workflows, history entries carry no request snapshot.

---

## [burpsy-react-ui-t2s] scanner: only 4 of Burp's 78 scan-config keys exist; insertion points and check selection are unrepresentable

**Beads ID:** `burpsy-react-ui-t2s`
**Priority:** P1
**Labels:** config, parity, scanner

### Description

burpsy's `scanner.BuiltInConfig` has **4 knobs**. Burp's 29 shipped configurations set **78
functional leaf keys across 15 sections**. That is **4/78 (5%)**, spanning **2/15 sections**.

## Re-derived, not inherited

`docs/parity/W0-burp-denominators.md` states it was reconstructed and not re-derived. I re-derived it
from `/root/burp-re/in/extract/resources/BuiltInConfigs` (29 files, confirmed):

| Figure | W0 said | Re-derived | Verdict |
|---|---|---|---|
| BuiltInConfigs files | 29 | 29 | confirmed |
| total leaf keys | 83 | 84 | off by one |
| `description.*` metadata | 6 | 6 | confirmed |
| functional keys | 77 | **78** | corrected |
| sections | 20 | **15** | W0 overstated by 5 |

Use 78 and 15. The conclusion is unchanged and the correction is small, but the numbers get quoted.

## The two sections that are entirely unrepresentable

**`scanner/insertion_point_types` — 8 keys.** Controls WHERE the scanner injects:

    insert_url_params, insert_body_params, insert_cookies, insert_http_headers,
    insert_param_name, insert_url_path_filename, insert_url_path_folders, insert_entire_body

**`scanner/issues_reported` — 9 keys.** Controls WHICH checks run:

    scan_type_passive, scan_type_light_active, scan_type_medium_active,
    scan_type_intrusive_active, scan_type_javascript_analysis,
    scan_only_selected_issues, select_individual_issues, selected_issues,
    store_issues_within_queue_items

A scanner whose insertion points and check selection cannot be expressed is not a configurable
scanner. This is the single largest capability gap on the Burp side of the comparison, and it is not
a UI gap — there is no field to bind a control to.

## What burpsy's 4 keys cover

`ConsecutiveCheckFailuresToAbandonUnit`, `ConsecutiveUnitFailuresToFailItem`,
`PauseSessionAfterFailedItems` land in `scanner/error_handling` (5 keys); `MaximumAuditTimeMinutes` is
`scanner/audit_optimization/maximum_crawl_and_audit_time` (7 keys). Every one was verified present in
Burp's JSON — the transcription is honest, it is just tiny.

Note what `error_handling` is missing even within a section burpsy touches:
`number_of_follow_up_passes` and `pause_task_failed_audit_item_percentage`.

## Why this is P1 and should be split

Do NOT take this as one task. `issues_reported` is the higher value half: `settings.tsx` already has
~21 audit-check-family switches wired to `ScanConfig`, so burpsy has *a* check-selection mechanism —
it is simply not Burp's shipped vocabulary and cannot load a Burp configuration. Reconciling those two
is a smaller, well-defined job than building insertion-point control from nothing.

`insertion_point_types` is the deeper one: it needs the audit engine to be told which insertion point
classes to enumerate, which touches `internal/scanner`'s point generation rather than a config struct.

## Constraint inherited from the existing code

`builtInConfigKeys` is deliberately the single description of what a shipped configuration can change,
read by both `Apply` and `BuiltInConfig.Keys` so a chooser can tell an operator what each config does.
Any new key must go through that table, not around it.


### Acceptance Criteria

scanner/issues_reported and scanner/insertion_point_types are representable, a Burp-shipped configuration can be loaded without silently dropping keys, and builtInConfigKeys remains the single description of what a config changes.

---

## [burpsy-react-ui-016] intruder: payload files can only be loaded from a path on the burpsy server, so an operator cannot use a wordlist from their own machine

**Beads ID:** `burpsy-react-ui-016`
**Priority:** P2
**Labels:** capability-gap, intruder, payloads

### Description

Intruder's file payload type takes a path that is resolved on the burpsy **server**. There is no way
to load a wordlist from the machine the operator is sitting at, and no upload route exists.

This is a separate concern from *which* wordlists ship (that is the licensing decision already filed):
even with a perfect corpus available locally, an operator cannot get their own list into an attack
against a remote burpsy.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/configure-attack/payload-lists.html`
and `.../payload-types.html` — the payload options box has **Add**, **Load ...**, **Remove**, **Clear**
buttons; `Load ...` opens a file chooser on the operator's own filesystem. Burp is a desktop app, so
local and server are the same machine there — but Burp's *user* settings page is explicit that
uploading lists is a first-class action:
`.../configure-attack/settings.html` — "To configure Burp Intruder user settings for startup and
closing behavior, and **to upload payload lists**, go to the Intruder page in the Settings dialog."
The spec records the buttons at `/root/burp-re/BURP_SUITE_UI_UX_SPECIFICATION.md:170`.

## burpsy-side evidence

- `internal/web/ui/src/pages/intruder.tsx:816-828` — the only file control is a text input for a
  server-side path, and the hint says so:

      <Field label="Server file path" hint="File must exist on server; blank lines skipped">
        ... placeholder="/tmp/payloads.txt or ./wordlists/sqli.txt"

- `internal/web/ui/src/pages/intruder.tsx:508-510` — the wire form is
  `{ type: "file", filename: ... }`.
- `internal/intruder/payload.go:208` — "FileSource is the filename for `{"type":"file"}` — payloads
  from server file, one per line"; resolved at `internal/intruder/payload.go:259` and `:363-366`.
- No upload route exists. `grep -rni "upload|multipart" internal/web/server.go` returns a single hit —
  `internal/web/server.go:175`, a comment about the 16 MiB body cap ("runaway upload cannot exhaust
  memory"). Positive control on the same file: `grep -n "intruder" internal/web/server.go` → `:263`,
  `:742`, `:743`.
- Nor is there a file input in the UI: `grep -rn "type=\"file\"" internal/web/ui/src/pages/intruder.tsx`
  → no output; positive control on the same file, `grep -c "Input" internal/web/ui/src/pages/intruder.tsx`
  → non-zero (the page is full of them).

## Classification

CAPABILITY GAP.

## What an operator cannot do

Use their own wordlist. burpsy runs as a server; when that server is a container, a VM or a jump host
— which is the normal deployment — the operator's `~/wordlists/usernames.txt` is not on it, and the
only workaround is an out-of-band copy (scp, a volume mount) before every attack. Combined with the
zero bundled corpora, Intruder ships with no reachable payload source other than typing lines into a
textarea.

## Note on the decision boundary

Do not fold this into the wordlist-licensing issue. That one asks *what content burpsy ships*; this one
asks *how an operator supplies content at all*, and it stands even if the answer there is "ship
nothing". The wordlist issue's second proposed outcome — a shared wordlist manager, since
`/api/discovery` already takes a wordlist path — would resolve both if it includes an upload or
browse-the-server path picker. Whoever takes that one should read this.


### Acceptance Criteria

An operator can supply a payload list from their own machine — by upload or an equivalent — without shell access to the burpsy host.

---

## [burpsy-react-ui-03z] repeater: tab groups are organizational only — no Send group (single connection / separate connections / parallel), so the race-condition workflow is absent

**Beads ID:** `burpsy-react-ui-03z`
**Priority:** P2
**Labels:** race-conditions

### Description

Repeater has tab groups, but a group cannot be *sent*. Burp's whole reason for grouping tabs —
beyond tidying the strip — is the **Send group** dropdown next to the Send button, which fires
every tab in the group together. burpsy's groups are organizational only, and the store makes that
explicit ("grouping must never gate sending or scope", `store.ts:39`). There is no group-send
control, so the primary race-condition / single-packet workflow does not exist.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/repeater/send-group.html`:

> Burp Repeater's Group send options feature enables you to send grouped HTTP requests with a single
> click. You can send requests either in parallel (all at once), or in sequence (one after the other).
> ... Click the drop-down arrow by the side of the Send button and select one of the available options:
> **Send group in sequence (single connection)** / **Send group in sequence (separate connections)** /
> **Send group in parallel** ... Click **Send group**.

Same page names the point: "if you're testing for race condition vulnerabilities ... send parallel
requests with a single click." `groups.html` confirms grouping "enables you to send requests from
multiple tabs in sequence."

## burpsy-side evidence

- `internal/web/ui/src/pages/repeater.tsx` — groups render (create/rename/delete/collapse/move,
  colored border, member count) but the group header carries only Collapse / Delete. The Send button
  (`submit(active)`) sends the single active tab; there is no dropdown and no group entry point.
- `internal/web/ui/src/lib/store.ts:39` — "grouping must never gate sending or scope" — grouping is
  deliberately inert with respect to sending.
- `/api/repeater/send` takes one request; there is no batch/group send endpoint.

## Scope note

"Send group in parallel" and "separate connections" are reachable with the current one-request-per-
call sender by fanning out N sends. "Single connection" (the true single-packet / last-byte-sync
path) depends on connection reuse (`burpsy-react-ui-6i4`) and HTTP/2 (`burpsy-react-ui-745`); those
are the mechanics, this issue is the missing affordance and the parallel/separate-connection modes.
Burp's Pro "Trigger race conditions" custom action is a related convenience layered on top of this.


---

## [burpsy-react-ui-10e] site map: nothing can be deleted from the map — /api/sitemap is read-only

**Beads ID:** `burpsy-react-ui-10e`
**Priority:** P2
**Labels:** api, sitemap, ui

### Description

## Claim

Nothing can be removed from the site map. `/api/sitemap` is registered as a read-only handler, so a map
polluted by a mistargeted crawl stays polluted for the life of the process.

## burpsy side

`internal/web/server.go:818`

    s.mux.HandleFunc("/api/sitemap", s.handleSitemap)

and the handler, `internal/web/api_toolkit.go:82-90`, documents itself as
`GET /api/sitemap?host=&path=&depth=`. It is the only sitemap route.

Absence grep: `grep -rniE "delete host|delete branch|remove.*from.*site ?map"` over
`internal/web/ui/src`, `internal/sitemap/` and `internal/web/*.go` returns nothing but unrelated
backup-pruning hits in `api_backup.go` and `settings.tsx`. Positive control on the same file set:
`grep -n "sitemap" internal/web/server.go` -> `:25`, `:58`, `:189`, `:210-212`, `:647-648`, `:818`.

`pages/sitemap.tsx` has no delete control on the tree, the contents table, or the header.

## Burp side

`map_root.tsv` class `burp.Zxut` — `Delete host`, `Delete branch`, `Delete item`,
`Delete selected items`. Burp also ships a bulk variant, `burp.Zraa`:
`Remove out-of-scope items (based on current suite scope)`.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Clean up. A crawl that wandered onto a CDN or a staging host leaves those hosts in the tree
permanently, inflating every node count and every subsequent "scan this branch" target.

## Note before coding

The site map is a projection: `internal/web/server.go:212` wires `s.sitemap.Follow(store)`, so the tree
is derived from the exchange store. Deleting a branch therefore needs a decision — does it delete the
underlying exchanges (which HTTP history and findings both reference), or does the site map grow a
suppression set that `Follow` respects? The second is almost certainly right and is the smaller change,
but it should be chosen explicitly rather than discovered mid-implementation.


### Acceptance Criteria

A host, branch or item can be removed from the site map; the decision on whether removal suppresses or deletes underlying exchanges is recorded, and node counts reflect the removal.

---

## [burpsy-react-ui-1yd] scanner: no consolidated Scanner surface — launch is split across three pages and named after its output

**Beads ID:** `burpsy-react-ui-1yd`
**Priority:** P2
**Labels:** nav, scanner, ux

### Description

Burp has a SCANNER tool: one place to configure and launch a scan. burpsy has the capability and no
consolidated surface — scanning is reachable but fragmented across three pages.

Verified at HEAD:

- **Launch** is split three ways: `dashboard.tsx`'s "New scan" / "New live task" modals, the Site
  map's Crawl button (`ui/crawl.tsx`), and a "Targeted audit" button plus a "Live active audit"
  toggle buried inside an *Audit settings modal* on `scanner.tsx`.
- **Configure** lives somewhere else again: ~21 audit-check-family switches on `settings.tsx`, wired
  to `ScanConfig`.
- **Read results** is `scanner.tsx`, which `nav.ts` labels "Issues" as a leaf under Target, and whose
  own `PageHeader` says "Issues".

So the page an operator would look for a scanner on is named after its output, and the two controls
that actually start a scan are behind a modal on it.

## Not a capability gap — a findability gap

Every piece is wired and works. `POST /api/scanner/audit` and the live-audit toggle were both traced
end to end and consume what they are sent. This issue is only that a new operator cannot find them,
and an experienced Burp user will look for a Scanner tab and conclude scanning is absent.

## Shape

Cheapest honest fix is a nav leaf under Target labelled "Scanner" that gathers the launch controls
and links to the config, leaving `scanner.tsx` as the results view it already is. That is a
composition of existing surfaces, not new backend work.

Worth deciding alongside: whether the ~21 check switches belong on Settings at all, or on the scanner
surface next to the thing they configure. Burp puts scan configuration in the scan-launch dialogue,
not in global settings, and burpsy's placement is why the config is hard to associate with a run.


### Acceptance Criteria

An operator can find and launch a scan from one surface; the check-family switches sit where their effect is visible; scanner.tsx keeps being the results view.

---

## [burpsy-react-ui-36d] site map: no filter bar — substring match on path is the only filter

**Beads ID:** `burpsy-react-ui-36d`
**Priority:** P2
**Labels:** filter, sitemap, ui

### Description

## Claim

The site map's only filter is a case-insensitive substring match on a node's path or segment. Burp's
site map has a filter bar with seven filter groups; none of the other six exists here in any form
reachable from the site map.

## burpsy side

`burpsy-go/internal/web/ui/src/pages/sitemap.tsx:369-381` — the whole tree toolbar is one `Input`
with `placeholder="Filter by segment or path"`.

The matcher, `subtreeMatches()` at `sitemap.tsx:41-45`:

    if (node.path.toLowerCase().includes(term) || node.segment.toLowerCase().includes(term)) return true;

Server side, `internal/web/api_toolkit.go:82-90` — `handleSitemap` serves
`GET /api/sitemap?host=&path=&depth=` and reads nothing else off the query.

Positive control on the same file: `grep "Filter by segment" pages/sitemap.tsx` -> hit at `:374`.

## Burp side

`map_root.tsv` class `burp.Zh5v` carries all seven group labels and the 24 backing preference keys:

- **Filter by request type** — `Show only in-scope items`, `Show only requested items`,
  `Show only parameterized requests`, `Hide not-found items`
- **Filter by MIME type** — `HTML`, `Script`, `XML`, `CSS`, `Images`, `Flash`, `Other text`, `Other binary`
- **Filter by status code** — `2xx [success]`, `3xx [redirection]`, `4xx [request error]`, `5xx [server error]`
- **Filter by folders** — `Hide empty folders`
- **Filter by search term** — `Case sensitive`, `Regex`, `Negative search`
- **Filter by file extension** — `Show only:` / `Hide:` specific extensions
- **Filter by annotation** — `Show only highlighted items`, `Show only items with notes`

Keys: `target.filter.by_mime_type.show_html`, `target.filter.by_status_code.show_2xx`,
`target.filter.by_request_type.hide_not_found_items`, `target.filter.by_search.regex`, etc.
`burp.Zid_` = `siteMapFilterBar`.

## Classification

CAPABILITY GAP for MIME / status / extension / folders / regex / negative search.

UX DIVERGENCE for in-scope-only and highlighted/commented: those filters are implemented, but on
**HTTP history** (`pages/history.tsx:906` "In scope only"; `:532`/`:574` `onlyHighlighted`) over data
that exists on the exchange (`internal/core/store.go:384-389` `Highlight`, plus the comment field).
The site map cannot reach them.

## What an operator cannot do

Reduce a large map to a target list — "in-scope HTML pages that returned 200 and take parameters" is
the first move on any real engagement, and here the map can only be searched by name.

## Note before coding

Two of these are already answerable server-side by the query DSL that HTTP history uses. Worth
deciding whether the site map grows a filter popover of its own or gains a DSL box, because the
answer changes whether the filtering is client-side over the loaded tree or a new server parameter.


### Acceptance Criteria

The site map offers filtering by MIME type, status-code class, in-scope, requested-only, parameterized-only and not-found, at minimum; the existing search gains regex and case-sensitive options.

---

## [burpsy-react-ui-3f3] sequencer: FIPS tests run over the flattened bit stream, not per bit position, and the page does not say so

**Beads ID:** `burpsy-react-ui-3f3`
**Priority:** P2
**Labels:** analysis, burp-parity, decision, decision-needed, disclosure, parity, sequencer, ux-divergence

### Description

## Claim
The FIPS tests run over the concatenated bit stream in 20,000-bit blocks rather than at each bit position across tokens, so the report cannot name which bit positions failed — and unlike the page's other statistical caveats, this one is not disclosed.

## Burp-side evidence
`tools/sequencer/results/tests.html`, "Bit-level analysis":
> "each token is converted into a set of bits. This enables Burp to perform powerful bit-level tests **at each bit position**."

Per test, the same framing, repeatedly: monobit — "analyzes the distribution of ones and zeroes at each bit position"; poker — "At each position, the test calculates the probability…"; runs — "divides the bit sequence at each position into runs"; long runs — "measures the longest run of bits with the same value at each bit position".

And the reported output is per-position: "FIPS result - For FIPS tests, a FIPS pass or fail result. **Any bits that failed the test are identified.**" (`tools/sequencer/results/index.html`, "Individual tests").

## burpsy-side evidence
`internal/sequencer/fips.go:11-20`, the package's own description of the shape:
> "Because every interval is a function of the 20,000-bit sample size, the stream is cut into whole 20,000-bit blocks, each is tested exactly as specified, and the leftover bits are reported as untested rather than folded in."

Implementation: `BitsOf(tokens, encoding)` (`internal/sequencer/fips.go:183`) flattens every token into one `[]byte` bit stream; `AnalyseFipsBits(bits)` (`fips.go:465`) walks it in `BlockBits`-sized slices; `testBlock(block)` (`fips.go:453`) treats its slice as an undifferentiated sequence. Nothing carries a bit *index within a token*.

The reported unit is consequently a block, not a position — `FipsTest.BlocksPassed` / `BlocksFailed` (`fips.go:313-314`), rendered as a "Blocks" column at `internal/web/ui/src/pages/sequencer.tsx:96-98`.

## Why this is filed as its own claim
The statistics are correct for what they measure, and the FIPS thresholds genuinely are defined on a 20,000-bit sample — the block-cutting is a defensible reading. The gap is that a Burp user reads the bit-level tab to learn *which bits* are weak (a fixed prefix, a low-entropy counter field), and that answer is unavailable here in principle, not by sample size.

The undisclosed part is what makes it actionable rather than a preference. The page is scrupulous about its other statistical limits:
- positional independence: `pages/sequencer.tsx:216-222` ("an upper estimate, not a measurement")
- FIPS not run below one block: `pages/sequencer.tsx:82-85`
- bit view vs. encoding: `internal/sequencer/fips.go:62-70`, surfaced as a warning at `report.go:207-212`

Nothing anywhere says the FIPS verdict is a whole-stream verdict rather than a per-position one. An operator who knows Burp will read the "FIPS 140-2 bit-level tests" heading (`pages/sequencer.tsx:80`) as the per-position battery they know.

## Decision needed before code
1. Re-shape the FIPS battery to run per bit position, as Burp does. Requires deciding what to do about thresholds: Burp "adjusts the FIPS pass criteria to work with random sample sizes" (`tests.html`) and notes that formal compliance needs 20,000 tokens. That adjustment is exactly the confidently-wrong-number risk `fips.go:11-20` was written to avoid, so it needs a stated method, not a fudge.
2. Keep the block model and disclose it — one sentence under the FIPS heading saying the verdict describes the stream, not individual bit positions.

(2) is small and should happen regardless of whether (1) is scheduled.

## Classification
UX DIVERGENCE in the statistics, plus a missing disclosure.

## What an operator cannot do
Say which bit positions of a token are non-random — so they cannot distinguish a token with a fixed prefix from one that is uniformly weak, which is the finding Burp's bit-level tab exists to produce.


### Acceptance Criteria

The FIPS section either reports per-bit-position results naming the failing bits, or states in the UI that its verdict describes the whole bit stream rather than individual bit positions. The disclosure half lands even if the per-position work is deferred.

---

## [burpsy-react-ui-3fr] ui: Issues, Organizer, Content discovery and Dashboard tables have no right-click menu (Sequencer: not a gap)

**Beads ID:** `burpsy-react-ui-3fr`
**Priority:** P2
**Labels:** contextmenu, organizer, p2, scanner, ui

### Description

## Claim
Five data tables offer no right-click menu at all, because they are built on `SimpleTable`, which has no menu support. The worst affected is Target -> Issues, where Burp's entire issue-triage menu (Set severity, Set confidence, Report issue, Go to issue, Delete issue) lives.

## Burp-side evidence
- `tools/context-menu.html` (Burp bundled docs): *"The context menu provides quick access to a variety of tools and functions throughout Burp Suite. To view the context menu, right-click an item or group of items. **Most Burp Suite tools support this functionality.**"*
- Issue-specific entries in that same list: **Set severity** *"Sets or changes the severity level of an issue"*; **Set confidence**; **Report issue** *"Creates a report from the selected items"*; **Go to issue** *"Opens the relevant issue in the Issues tab"*; **Delete issue**.
- Spec section 4.11 documents the Organiser context actions (New Collection / Rename / Copy Link / Unlink).

## burpsy-side evidence
Surfaces that DO have a row menu (all pass `VirtualTable`'s `menuGroups`): `pages/history.tsx:1012`, `pages/sitemap.tsx:548`, `pages/logger.tsx:354`, `pages/intercept.tsx:728`, `pages/wshistory.tsx:213`. Plus `pages/repeater.tsx:296` on tab headers.

Surfaces that do NOT — all use `SimpleTable`, which takes no `menuGroups` prop (`ui/table.tsx:448-478`, signature is `{headers, children, className, density}` only, and it renders a bare `<tbody>{children}</tbody>` with no `ContextMenu` wrapper; contrast `ui/table.tsx:446-447` in `TableRow`, where `VirtualTable` does wrap):
- Target -> Issues: `pages/scanner.tsx:190` (`grep -c ContextMenu pages/scanner.tsx` -> 0; positive control `grep -c import` -> 16)
- Organizer: `pages/organizer.tsx:358` (ContextMenu -> 0, import -> 9)
- Sequencer: `pages/sequencer.tsx` (ContextMenu -> 0, import -> 10)
- Content discovery: `pages/contentdiscovery.tsx` (ContextMenu -> 0, import -> 8)
- Dashboard: `pages/dashboard.tsx` (ContextMenu -> 0, import -> 14)

## Classification
CAPABILITY GAP.

## What an operator cannot do
On Target -> Issues, right-click a finding to set its severity or confidence, report it, or jump to it in the site map — the whole Scanner triage loop. On Organizer, right-click a stored item to rename or act on it. The `ContextMenu` component already exists and `VirtualTable` already wires it; the gap is that these five tables are on the non-menu table primitive.

## Decision needed
Whether to add a `menuGroups` prop to `SimpleTable` (small, keeps both primitives) or migrate these tables to `VirtualTable` (fewer primitives, but Issues/Organizer are short lists where a scroll viewport is wrong — the reason `SimpleTable` exists per its own doc comment at `ui/table.tsx:447`).


### Acceptance Criteria

DONE in 63e101b: Organizer, Content discovery and both Dashboard tables have row menus; Target -> Issues has a menu on its finding leaf carrying go-to-issue, report exports, copies and the full cross-tool matrix on the finding's exchange. REMAINS: the Issues menu cannot carry Set severity, Set confidence or Delete issue — /api/issues is registered GET-only (internal/web/server.go:727), so this needs PATCH and DELETE endpoints first (a .go change). Sequencer is REMOVED from scope: its three tables are analysis output (FIPS bit-test results, per-position entropy, capture-miss reasons), not item rows, and Burp puts no row menu on its own Sequencer analysis panels either. Also corrected: pages/scanner.tsx:190 is the Passive check coverage counter table, not the Issues list; Issues is the role=tree around scanner.tsx:500-560.

---

## [burpsy-react-ui-4rd] intruder: results tables use the non-sortable SimpleTable, so results cannot be sorted or filtered

**Beads ID:** `burpsy-react-ui-4rd`
**Priority:** P2
**Labels:** burp-parity, capability-gap, intruder, results

### Description

Intruder's results tables are rendered with `SimpleTable`, a static `<table>` with no sorting, no
filtering and no column controls — while the same module exports a sortable, filterable table that
other pages use.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/results/filtering-results.html`
is an entire page about filtering the results table, and
`.../configure-attack/settings.html` repeatedly relies on sorting as the way to find findings:

> During the attack, Burp adds a results column for each expression in the list. This records the
> number of times the expression is found in the response. **To identify results with the expression,
> click on the column header to sort the results.**

Sorting is not a convenience in Burp Intruder; it is the documented mechanism for reading the output.

## burpsy-side evidence

- `internal/web/ui/src/ui/table.tsx:451-476` — `SimpleTable` takes `headers: string[]` and renders
  `<th key={header}>{header}</th>`. No sort state, no click handler, no filter input.
- The same file has the capable table: `:4` `getSortedRowModel`, `:8` `SortingState`, `:137`
  `useState<SortingState>`, `:161-168` wired into the tanstack instance, `:345-346`
  `header.column.getIsSorted()` / `getCanSort()`.
- Intruder uses only `SimpleTable`: `internal/web/ui/src/pages/intruder.tsx:43` imports it, and it is
  used for all four result tables — buckets (`:210`), errors (`:243`), payload-set accounting (`:262`)
  and attempts (`:307`).

## Classification

CAPABILITY GAP (results triage).

## What an operator cannot do

Order or narrow the output. A 5,000-request attack returns buckets and up to `detail_limit` attempt
rows in plan order; the operator cannot sort by length to find the outlier, sort by time to find the
slow one, or filter to errors only. The bucketing (`internal/intruder/engine.go` → grouped by status,
length and reflection) does a lot of this work up front and is genuinely better than an unsorted flat
table — but once a bucket list is more than a screenful, there is no way to reorder it.

## Note

This is small: the sortable table already exists in the same module and is already used elsewhere in
the app, so the change is largely swapping the component and defining columns. Worth sequencing after
the missing Payload column, since sorting is most useful once rows can be identified.


### Acceptance Criteria

Intruder result tables are sortable by column and filterable, using the sortable table already exported from ui/table.tsx.

---

## [burpsy-react-ui-5j4i] scope: no 'Drop all out-of-scope requests' — burpsy will still issue requests to out-of-scope hosts

**Beads ID:** `burpsy-react-ui-5j4i`
**Priority:** P2
**Labels:** burp-parity, capability-gap, scope

### Description

## Burp-side evidence
`settings/project/scope.html` — "Out-of-scope request handling: Select **Drop all out-of-scope
requests** to prevent Burp from issuing any out-of-scope requests. With this setting enabled,
out-of-scope outgoing requests are dropped by Burp even if the browser explicitly requests them. You
can select how Burp defines an out-of-scope request: Use suite scope / Use custom scope." This is a
safety control that stops burp from ever touching hosts you have no permission to test.

## burpsy-side evidence
burpsy has no such control. The Scope page (`burpsy-go/internal/web/ui/src/pages/scope.tsx`, whole
file, 220 lines) offers only include/exclude rule add/remove/clear — no out-of-scope request handling
section. A backend search finds no drop-out-of-scope setting: `grep -rin "out.of.scope|DropOutOfScope"
internal/**/*.go` returns only scanner/passive gating counters and organizer scope resolution, none of
which prevent an out-of-scope request from being issued. (Distinct from am6, which is about not
*logging* out-of-scope traffic; this is about not *sending* it.) So an operator cannot make burpsy
refuse to issue requests to out-of-scope hosts — the accidental-attack guardrail Burp provides.


---

## [burpsy-react-ui-6i4] repeater: no connection reuse or keep-alive, so a smuggling or desync finding cannot be reproduced by hand

**Beads ID:** `burpsy-react-ui-6i4`
**Priority:** P2
**Labels:** burp-parity, capability-gap, decision-needed, repeater, transport

### Description

Every Repeater send dials a fresh connection and closes it. There is no connection-reuse or keep-alive
option, so no test that depends on two requests sharing one socket can be performed from Repeater.

## Burp-side evidence

`/root/burp-re/BURP_SUITE_UI_UX_SPECIFICATION.md:185` records the Repeater settings-gear items by name:
`repeaterConfigurationGlobalMenuItemEnableH1ConnectionReuse` and
`...EnableH2ConnectionReuse`. The Intruder equivalent is documented in prose at
`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/configure-attack/settings.html`:

> **HTTP/1 connection reuse** - Use this setting to control whether Burp Intruder reuses connections to
> issue multiple HTTP/1 requests. This can greatly increase the speed of your attacks.
>
> If you deselect HTTP/1 connection reuse, Burp opens a new connection for each request and closes it
> after receiving a response.

## burpsy-side evidence

- `internal/web/ui/src/pages/repeater.tsx:606-654` — the config-override panel's full control set:
  redirect mode, protocol preference, process cookies, strip Connection, normalize line endings,
  update Content-Length. No reuse toggle.
- `internal/web/repeater_options.go:23-44` — `repeaterSendOptions` has six fields, none about
  connection lifetime.
- `internal/web/api_tools.go:139` — one `s.sender.SendRawOutcome(...)` per request.
- The behaviour is documented in the sender: `internal/sender/pipeline.go:3-9` —

  > writeHTTP1 (sender.go:597) dials fresh and reads exactly one response per send, which is exactly
  > right for every check that sends independent probes — but it cannot represent a front-end/back-end
  > framing disagreement, because that disagreement only exists *across* two requests sharing one
  > reused socket. checks_cache.go declines "HTTP request smuggling" and "Client-side desync" for
  > precisely this reason: "sender has no keep-alive/pipelining primitive".

Absence grep:

    $ grep -rni "reuse" internal/sender/*.go internal/web/ui/src/pages/repeater.tsx
    internal/sender/redirect.go:136:  ... reuses that decision ...
    internal/sender/pipeline.go:7:    ... reused socket ...
    internal/sender/cancel.go:43:     ... before the connection is reused or closed.

Three hits, all prose in comments, zero settings. Positive control on the same file set:
`grep -c "func" internal/sender/pipeline.go` → non-zero.

## What already exists and is not reachable from Repeater

`internal/sender/pipeline.go` provides `SendPipelined`, `SendKeepAlive` and `TimedRead` — the exact
primitive this needs. They are not called from the Repeater path. The file is explicit that a caller
must run every raw request through `ScopeChecker.AuthoriseRaw` first ("one call per raw ... a smuggled
prefix can address a different target than the socket it rides in on"), which is the design constraint
any Repeater wiring has to honour.

## Classification

CAPABILITY GAP. The absence is honestly disclosed in the sender's own comments, and the corresponding
scanner checks are explicitly *declined* rather than faked — but it is a user-facing capability Burp
offers on this screen, not an internals difference, so it is filed rather than treated as deliberate.

## What an operator cannot do

Manually verify a request-smuggling or client-side-desync finding from Repeater. In Burp this is the
standard workflow: disable/enable connection reuse, send two crafted requests down one socket, and
watch the second get the first's framing. Here it cannot be attempted at all, and the two
corresponding automated checks are declined for the same reason — so neither the automated nor the
manual path exists.

## Decision needed

Whether Repeater grows a per-tab "reuse connection for the next send" mode (needs a per-tab connection
handle held across sends, which is state the current stateless handler does not have), or a narrower
"send these two requests on one socket" action. The second is smaller and covers the smuggling
workflow; the first is Burp parity. Either way `AuthoriseRaw` must run per raw request, not per socket.


### Acceptance Criteria

Repeater can put two or more crafted requests down one socket via the existing sender.SendKeepAlive/SendPipelined primitives, with AuthoriseRaw run per raw request, or the gap is closed as deliberate with the reasoning recorded.

---

## [burpsy-react-ui-79u] intruder: a result cannot be sent to Repeater or Comparer — the Results tab has no context menu or handoff at all

**Beads ID:** `burpsy-react-ui-79u`
**Priority:** P2
**Labels:** burp-parity, handoff, intruder, results, ux-divergence

### Description

An Intruder result is a dead end. There is no context menu and no button anywhere on the Results tab
to send a result to Repeater, Comparer or anywhere else.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/results/workflow.html`
and `.../viewing-results.html` — a results row has the suite context menu, and
`.../configure-attack/settings.html` lists "Send requests or responses to other Burp tools" as one of
the three stated reasons the `Store requests / responses` setting exists. The suite-wide menu is
recorded at `/root/burp-re/BURP_SUITE_UI_UX_SPECIFICATION.md:237-238` (`Send to Repeater Ctrl+R`,
`Send to Intruder Ctrl+I`).

## burpsy-side evidence

Nothing on the page offers a handoff:

    $ grep -rni "ContextMenu|sendTo|lib/actions" internal/web/ui/src/pages/intruder.tsx
    (no output)

Positive control on the same file: `grep -c "SimpleTable" internal/web/ui/src/pages/intruder.tsx` →
non-zero (imported `:43`, used `:210, 243, 262, 307`).

- `internal/web/ui/src/pages/intruder.tsx:308-326` — attempt rows are plain `<tr>` with no menu
  wrapper. Compare `internal/web/ui/src/pages/repeater.tsx:296` where `ContextMenu` does wrap a
  trigger, so the primitive exists and is used elsewhere.
- `internal/web/ui/src/lib/actions.ts` — the shared send-to menu (`sendToRepeater`, `sendToComparer`
  at `:193`, menu entries at `:368-369`) is imported by `pages/history.tsx`, `pages/sitemap.tsx` and
  `pages/wshistory.tsx` only.

## Correction to the existing comparison doc

`/root/burp-re/BURP_UI_UX_COMPARISON.md:314` lists "Send to Repeater" under burpsy Intruder's
**Actions (from TSX)**. That is wrong at HEAD — `pages/intruder.tsx` contains no handoff of any kind.
The handoff is one-way: Repeater → Intruder (`pages/repeater.tsx:162-193, 524-527`). Worth fixing in
the doc so this gap is not assumed closed.

## Classification

UX DIVERGENCE — the send-to actions exist on other screens and not this one.

## What an operator cannot do

Follow up a finding. The attack surfaces a bucket that returned 302 where everything else returned
200; the operator now wants that exact request in Repeater to poke at it by hand. There is no path —
and because the per-result response id is also unrendered (filed separately), there is not even a
message id on screen to type in somewhere else.

## Note on dependency

This needs the result rows to be addressable first: `Attempt.ResponseID` and
`ResultBucket`'s example response id are returned but unread
(`internal/web/ui/src/lib/types.tools.ts:85, 102`), and no request-side message id is returned for an
attempt at all — `record` in `internal/web/api_tools.go:640-643` stores only the response. Sending an
attack *request* to Repeater therefore needs either the spliced request stored per attempt, or the
request reconstructed client-side from the base message plus the payload combination.


### Acceptance Criteria

A result row offers the shared send-to actions (Repeater, Comparer), addressing the stored request and response for that attempt; BURP_UI_UX_COMPARISON.md:314 is corrected to stop claiming this already exists.

---

## [burpsy-react-ui-a09g] Session handling & Match/Replace parity

**Beads ID:** `burpsy-react-ui-a09g`
**Priority:** P2
**Labels:** burp-parity, epic, matchreplace, session

### Description

Umbrella for session-handling gaps: macro recording from history, editable/removable cookie jar, rule tool-scoping, the 8 unrepresented rule actions, and the 5 missing Match & Replace parameter-targeted rule types.

---

## [burpsy-react-ui-akv] intercept: the target host/port/TLS of a held request cannot be edited before forwarding

**Beads ID:** `burpsy-react-ui-akv`
**Priority:** P2
**Labels:** burp-parity, capability-gap, intercept, parity, ui

### Description

VERIFIED against HEAD by AuditProxy (Proxy-screen parity audit, 2026-08-27).

A held request's destination is display-only in burpsy. Burp lets the operator
click the target and change it before forwarding.

## Burp-side evidence

BurpClass9694.java -- the intercept header bar:
  :197  setName("proxyInterceptTargetLabel")
  :206  setName("proxyInterceptEditTargetButton")
  :66   the pencil action, labelled "Edit target"
  :109  setToolTipText(var2 ? "Click to modify" : null)
  :195  setText("https://ginandjuice.shop")   -- the label shows the authority

## burpsy-side evidence

The authority is rendered twice, read-only both times:
  pages/intercept.tsx:485-490   the "Host" column, accessorFn returning
                                `${row.host}:${row.port}${row.tls ? " (tls)" : ""}`
  pages/intercept.tsx:512-516   the detail head, static text

The wire carries no destination field. The forward request body is exactly three
keys:
  internal/web/api_intercept.go:333
    struct { Raw *string; FixContentLength bool `json:"fix_content_length"` }
    keyed by id
and the engine signature matches:
  internal/intercept/intercept.go:670
    func (e *Engine) Forward(id uint64, edited *string, fixContentLength bool) error

There is no host, port or TLS parameter on either, so the capability is absent
end to end and not merely unrendered.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Redirect a held request to a different host, port or scheme before releasing it
-- Burp's standard move for replaying a production request against a staging
origin, or for steering a request at an internal host reached through the proxy.
Today the only route is Drop, then hand-edit in Repeater, which loses the
client's waiting connection.

## Note on scope

Editing the target changes where bytes go, so the held message's recorded
authority and the history row it produces must reflect the destination actually
used, not the one the client asked for -- internal/proxy/ws.go:166 already sets
the precedent for annotating a request that was altered before forwarding.


### Acceptance Criteria

A held request's destination host, port and TLS flag can be changed from the Intercept detail pane before forwarding; the relay dials the edited destination; the recorded history row states the destination actually used.

---

## [burpsy-react-ui-ayi] session: a rule can only replay a macro on invalid session — 8 of Burp's 9 rule actions are unrepresentable

**Beads ID:** `burpsy-react-ui-ayi`
**Priority:** P2
**Labels:** burp-parity, capability-gap, decision, decision-needed, parity, session

### Description

## Claim
A session-handling rule can express exactly one action — replay the macro when the session is invalid — so eight of Burp's nine rule actions are unrepresentable.

## Burp-side evidence
`settings/sessions/session-handling-rules.html`, "Rule actions":
> "Click Add to add the following actions to your rules:
> - Add cookies from the session handling cookie jar.
> - Set a specific cookie or parameter value.
> - Check whether the current session is valid, and perform sub-actions conditionally on the result.
> - Prompt the user for in-browser session recovery.
> - Run a macro.
> - Run a post-request macro — this issues the current request, and then executes a further macro.
> - Invoke a Burp extension.
> - Set a specific header value.
> - Replace matching part of the request"

And the composition model: "Each rule includes one or more actions that should be carried out when the rule is applied. Burp performs these actions in sequence, unless one of the actions specifies that no further actions should be applied to the request."

## burpsy-side evidence
The rule struct has no action list — `internal/session/session.go:693-703`:
```go
type SessionRule struct {
    ...
    ScopeHosts  []string
    Steps       []MacroStep
    MaxAttempts int
    Validity    ...
}
```
The behaviour is hardcoded: check validity, and if invalid replay `Steps` up to `MaxAttempts` times (`internal/session/recovery.go`). That is Burp's actions 3 and 5 fused into the only thing a rule can be.

The editor matches — `internal/web/ui/src/pages/session.tsx` offers Name, Enabled, Max attempts (`:740-772`), scope hosts (`:774-823`), the validity check (`:825-879`), and macro steps (`:881-918`). No action list, no action ordering, no "stop processing further rules".

## Partial coverage elsewhere in the tree (checked, not assumed)
Two of the nine exist as standalone tools rather than rule actions:
- "Replace matching part of the request" and "Set a specific header value" are approximately `internal/matchreplace/` with the `pages/matchreplace.tsx` surface.

That coverage is real but not equivalent: match-and-replace rules are global, not scoped per session rule, not ordered against the other actions, and not conditional on a validity check. So the gap stands, and the estimate should account for the overlap rather than duplicating the engine.

"Add cookies from the cookie jar" is currently implicit and per-call-site rather than a rule action — filed separately (see the Repeater-only `cookieHeaderFor` issue).

## Decision needed before code
This is a data-model change, not an increment. Options:
1. Full action list on the rule — `Actions []Action` with a sum type, executed in order, honouring a stop flag. Matches Burp, and makes the existing validity+macro behaviour one composite action rather than the rule's identity. Largest change; everything else composes afterwards.
2. Add the two or three actions with the clearest standalone value (set cookie/param value, set header value, add cookies from jar) as optional fields on the existing rule shape. Cheaper, but locks in a shape that cannot express ordering, and each further action makes it worse.
3. Decline the extension actions permanently (there is no Burp-extension host to invoke) and the in-browser recovery prompt (no browser to drive), and scope the issue to the remaining six.

(3) should be settled first regardless of which of (1)/(2) is chosen, because it changes the count this issue is measured against.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Handle a CSRF-token application. The canonical Burp recipe — run a macro to fetch a token, then set that token as a named parameter on the outgoing request — needs "run a macro" *and* "set a specific parameter value" in one rule, and the second half does not exist.


### Acceptance Criteria

A rule holds an ordered list of actions; at minimum "add cookies from the jar", "set a specific cookie or parameter value", "set a specific header value" and the existing validity-check-plus-macro are all expressible in one rule and execute in the stated order. Actions declined as out of scope (extension invocation, in-browser recovery prompt) are recorded as declined with the reason.

---

## [burpsy-react-ui-d2g] sequencer: character transition, spectral, correlation and compression tests are all absent from the randomness battery

**Beads ID:** `burpsy-react-ui-d2g`
**Priority:** P2
**Labels:** analysis, burp-parity, capability-gap, parity, sequencer

### Description

## Claim
Four of the eight randomness tests Burp Sequencer runs are absent: character transition analysis, the spectral test, the correlation test, and the compression test.

## Burp-side evidence
`tools/sequencer/results/tests.html` enumerates the battery in full. Character-level ("Two different character-level tests are performed at each character position"):
1. **Character count analysis** — distribution of characters at each position.
2. **Character transition analysis** — "analyzes the transitions between successive tokens in the sample. If the sample is randomly generated, a character appearing at a given position is equally likely to be followed in the next token by any one of the characters that is used at that position."

Bit-level:
3. FIPS monobit test
4. FIPS poker test
5. FIPS runs test
6. FIPS long runs test
7. **Spectral tests** — "treats each series of consecutive numbers as coordinates in a multi-dimensional space […] repeated for multiple sizes of number (between 1 and 8 bits) and for multiple numbers of dimensions (between 2 and 6). This test can identify evidence of non-randomness in some samples that pass the other statistical tests."
8. **Correlation test** — "tests for any statistically significant relationships between the values at different bit positions within the tokens. […] This test enables you to assess the amount of randomness in the token as a whole. This is important as each of the bit-level tests operates only on individual bit positions."
9. **Compression test** — "attempts to compress the bit sequence at each position using standard ZLIB compression. The results indicate the proportional reduction in the size of the bit sequence when it is compressed."

(Nine named tests; four FIPS members are one family, hence "eight" as an operator counts them.)

`BURP_SUITE_UI_UX_SPECIFICATION.md` §4.8 lists "FIPS poker" and "Spectral" among the recovered Sequencer config strings, confirming both are per-test toggles in the shipped product.

## burpsy-side evidence
The whole implemented set is in `internal/sequencer/`:
- Character count: `internal/sequencer/report.go:290` `AnalyseChars` — per-position counts and entropy.
- FIPS monobit: `internal/sequencer/fips.go:420`
- FIPS poker: `internal/sequencer/fips.go:440`
- FIPS runs: `internal/sequencer/fips.go:387` with `runIntervals` at `fips.go:53-60`
- FIPS long runs: `internal/sequencer/fips.go:391`

`testBlock` (`internal/sequencer/fips.go:453`) computes exactly the four FIPS statistics and nothing else; `blockResult` (`fips.go:371-377`) has exactly four fields. `FipsTest.ID` is documented as `"monobit" | "poker" | "runs" | "long_runs"` (`fips.go:301`).

Absent: no transition, spectral, correlation, or compression computation anywhere in the package. The rendered report is the FIPS four plus per-position character stats — `internal/web/ui/src/pages/sequencer.tsx:87-101` (the FIPS table) and `:152-180` (the positions table).

Separately implemented but **not reachable from the web report**: `ChiSquare` (`internal/sequencer/sequencer.go:137`), `SerialCorrelation` (`:156`), `MonteCarloPi` (`:180`), `DetectPatterns` (`:209`). Their only non-test caller is the CLI, `cmd/burpsy/cli_tools.go:361-370`. `SerialCorrelation` is not Burp's correlation test (it correlates successive character codes, not values at different bit positions), so it is not a substitute — but it does mean the web Sequencer reports less than burpsy's own CLI.

## Classification
CAPABILITY GAP — one capability (the randomness battery), four named members missing.

## What an operator cannot do
Reach the verdict Burp's docs single out the spectral test for: catching non-randomness in a sample that passes every other test. The correlation test's absence is the one with a stated consequence in Burp's own documentation — without it, a token whose bit positions are individually random but mutually dependent scores as high-entropy.


### Acceptance Criteria

The analysis report names and reports a result for character transition analysis, the spectral test, the correlation test and the compression test alongside the existing FIPS four, each with the observed statistic rather than a bare pass/fail. Any test that cannot run on the supplied sample reports "not tested" with the reason, matching the existing FIPS-below-one-block behaviour.

---

## [burpsy-react-ui-dkb] session: the cookie jar is read-only — no way to edit, remove or empty cookies

**Beads ID:** `burpsy-react-ui-dkb`
**Priority:** P2
**Labels:** burp-parity, capability-gap, cookiejar, parity, session

### Description

## Claim
The cookie jar is read-only: there is no way to edit a cookie, remove one, or empty the jar.

## Burp-side evidence
`settings/sessions/index.html`, "Managing the cookie jar":
> "To manage the contents of the cookie jar, click Open cookie jar. You can **edit cookies manually, remove cookies from the jar, or empty the jar altogether**."

## burpsy-side evidence
The endpoint is GET-only — `internal/web/api_session.go:958-962`:
```go
func (s *Server) handleSessionCookies(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
```
and it is the only cookie route — `internal/web/server.go:780` registers `/api/session/cookies` and nothing else under it (the neighbouring session routes are `/api/session/rules`, `/api/session/rules/`, `/api/session/login` at `server.go:778-781`).

The store exposes no mutator: `CookieJarManager` has `CookieHeader` (`internal/session/session.go:664`), `AbsorbSetCookie` (`:675`) and `Jars` (`:570`). No delete, no clear, no set.

The page renders a plain read-only table — `internal/web/ui/src/pages/session.tsx:1025-1040`, three cells (Authority, Name, Value) with no controls and no per-row actions.

## Why this matters more here than it would in Burp
`internal/session/session.go:626-638` records that cookie attributes are dropped and cookies therefore "persist for the life of the process". That is a stated, deliberate simplification — but it means a stale or wrong cookie in the jar cannot expire out and cannot be removed either, so the only remedy available to the operator is restarting the process, which costs them their captured traffic.

The two together are worse than either alone, which is why the read-only jar is filed even though the attribute-dropping is deliberate and disclosed.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Clear a poisoned session. A jar holding a logged-out or wrong-user cookie will keep attaching it to every Repeater send, and the only way out is a restart.


### Acceptance Criteria

The cookie jar table supports editing a cookie's value, deleting a single cookie, and emptying the jar, each reaching the coordinator's jar and reflected in the next request that would carry the cookie. Emptying the jar is confirmed, matching the existing destructive-action pattern on this page.

---

## [burpsy-react-ui-dpk] site map: tree rows have no context menu, so no action can be aimed at a subtree

**Beads ID:** `burpsy-react-ui-dpk`
**Priority:** P2
**Labels:** contextmenu, sitemap, ui

### Description

## Claim

Site map tree rows have no context menu. Every action Burp reaches by right-clicking a host or folder
is either elsewhere in burpsy or absent, and none of them can be aimed at a subtree.

## burpsy side

`pages/sitemap.tsx:103-186` — `TreeRow` binds `onClick={onSelect}` on the row and `onClick` on the
expand toggle. There is no `onContextMenu` and no menu prop; compare the contents table two panes
over, which does have one: `sitemap.tsx:548` `menuGroups={(row) => actions.menu(row)}`.

Where the equivalents actually live:

- **Add to scope** — `lib/actions.ts:402`, on an *exchange* row, not a node.
- **Actively scan this branch / this host** — `lib/actions.ts:404-405`, also keyed to one exchange
  (`crawlFrom(exchange, "branch"|"host")`).
- **Passively scan this branch** — a page-header toolbar button, `sitemap.tsx:600-634`.
- **Discover content** — a separate Target sub-tab, `nav.ts:100-108`.
- **Expand / collapse branch** — only the per-row chevron; no recursive branch expand.

So the consequence is not "these features are missing" but "these features cannot be aimed at a
subtree": each one needs a captured exchange under the node first.

## Burp side

`map_root.tsv` class `burp.Zeem` — `siteMapTreeExpandBranchMenuItem`,
`siteMapTreeCollapseBranchMenuItem`, `siteMapContentDiscoveryMenuItem`,
`siteMapEngagementToolsMenuItem`, `Actively scan this branch`, `Actively scan this host`,
`Actively scan selected branches`, `Passively scan this branch`, `Passively scan this host`.
Scope entries are in `burp.Zg5v`/`burp.Zh5w` (`Add URL to scope`, `Remove URL from scope`).

## Classification

UX DIVERGENCE.

## What an operator cannot do

Right-click a host and scope it or scan it. "Scan this host" currently requires finding a request
under that host first and acting on the request instead — the reverse of how the tree is meant to be
driven.


### Acceptance Criteria

Right-clicking a site-map host or folder offers, at minimum, add-to-scope, actively/passively scan this branch and this host, and expand/collapse branch — each acting on the node rather than requiring a selected exchange.

---

## [burpsy-react-ui-e2j6] dashboard: 'Crawl and audit' and 'API-only scan' scan types are disabled ('not built yet') — only a bare Crawl can be launched, so Burp's primary crawl+audit workflow is unavailable

**Beads ID:** `burpsy-react-ui-e2j6`
**Priority:** P2
**Labels:** burp-parity, capability-gap, dashboard

### Description

## Burp-side evidence
dashboard/ (New scan) — Burp's New scan dialog offers "Crawl and audit" (the default, maps the surface then audits it) and "Crawl" and API scans. Crawl-and-audit is Burp's primary scanning workflow: point it at a seed and it both maps and audits in one bounded task.

## burpsy-side evidence
internal/web/ui/src/pages/dashboard.tsx:341-345 defines SCAN_TYPES with crawl-audit ready:false and api ready:false; only "crawl" is ready:true. The cards for Crawl-and-audit and API-only scan render disabled with "not built yet" (dashboard.tsx:387), and NewScanModal only submits a crawl via useStartCrawl (dashboard.tsx:356-368). A bounded crawl-and-audit against a seed cannot be launched at all — auditing is only available as the always-on live sweep over proxied traffic. Relate to burpsy-react-ui-1yd and burpsy-react-ui-f3k.


---

## [burpsy-react-ui-escl] session: cannot record a macro from Proxy history — macro steps are hand-typed only

**Beads ID:** `burpsy-react-ui-escl`
**Priority:** P2
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/macros.html — "Macros are made up of requests taken from the Proxy history ... Click Add to open the Macro Recorder dialog. Select the items you need from the Proxy history list."

## burpsy-side evidence
pages/session.tsx builds macro steps only by hand: each StepCard (333-407) is a typed method/URL/headers/body form, added via "Add step" (884-899). There is no macro recorder and no way to select requests from HTTP history to seed a macro. ("Update macro from this run", 933-946, promotes steps observed during a login probe — not an arbitrary history selection.)


---

## [burpsy-react-ui-f3k] dashboard: New scan takes one seed URL though the engine and the site-map launcher take many

**Beads ID:** `burpsy-react-ui-f3k`
**Priority:** P2
**Labels:** crawler, dashboard, ui

### Description

## Claim

The Dashboard's "New scan" dialog accepts a single seed URL, while the crawl engine and a second
launcher in the same codebase both accept many.

## burpsy side

`pages/dashboard.tsx:259-261` — one `Input`:

    <Field label="Seed URL">
      {(id) => <Input id={id} value={seed} ... placeholder="https://demo.local/" />}

and the submit at `:222-236` sends `seeds: [seed.trim()]` — a one-element array.

The multi-seed form already exists: `ui/crawl.tsx:56-70`, `label="Seed URLs"`, hint "One per line, or
comma separated", splitting on `/[\s,]+/` at `:28-31`. It is rendered from the **Site map** header
(`pages/sitemap.tsx:636` `<CrawlLauncher />`), not from the Dashboard.

So the engine, the wire and a working UI all support N seeds; only the dialog a Burp user reaches for
does not.

Positive control on the same file: `grep -n "Seed URL" pages/dashboard.tsx` -> `:259`.

## Burp side

Burp's Scan details page is a multi-line "URLs to scan" box, described in `map_root.tsv` class
`burp.Zhwl`: *"Define the URLs to scan. Burp will begin crawling from these URLs, and by default will
include everything beneath the specified URLs' folders."*

## Classification

UX DIVERGENCE — the capability exists, the Dashboard dialog just cannot express it.

## What an operator cannot do

Start one scan across the three hosts of an application from the Dashboard. They must either run three
scans or go find the other launcher on a different tab.

## Note

Smallest honest fix is to have the New scan dialog reuse `CrawlLauncher`'s seed field rather than grow
a second parser — two split-and-trim implementations of the same input is how they come to disagree.


### Acceptance Criteria

The Dashboard's New scan dialog accepts multiple seed URLs, parsed by the same code path as ui/crawl.tsx, and starts one task covering all of them.

---

## [burpsy-react-ui-fgv8] scanner: findings cannot be re-triaged — no set-severity, set-confidence, delete-issue or mark-false-positive; /api/issues is GET-only

**Beads ID:** `burpsy-react-ui-fgv8`
**Priority:** P2
**Labels:** burp-parity, capability-gap, scanner

### Description

## Burp-side evidence
tools/intruder/results/analyzing-results.html and the scanner issue view describe the issue context menu: "Set severity", "Set confidence", "Report issue", "Delete issue", and marking a false positive / "Highlight a result". An analyst routinely down-grades a tentative finding, marks a false positive, or deletes noise.

## burpsy-side evidence
internal/web/ui/src/pages/scanner.tsx:359-365 documents that Set severity, Set confidence and Delete issue are deliberately absent because "/api/issues is registered GET-only (internal/web/server.go:727) — there is no PATCH to move a severity or a confidence onto a finding, and no DELETE to remove one." The issue leaf context menu (menuForLeaf, scanner.tsx:376-454) therefore offers only go-to, copy, and whole-scan report exports. There is no false-positive flag either.

## Note
scanner.tsx says this is "Tracked on burpsy-react-ui-3fr", but 3fr's title is about tables lacking a right-click menu at all — and the Issues tree now HAS a context menu (scanner.tsx:529). This bead captures the real remaining gap: the issue-mutation endpoints (PATCH severity/confidence, DELETE, false-positive) do not exist. Relate to 3fr.


---

## [burpsy-react-ui-fhp] sequencer: no "Send to Sequencer" action exists, so every capture starts by hand-copying a request

**Beads ID:** `burpsy-react-ui-fhp`
**Priority:** P2
**Labels:** burp-parity, capability-gap, contextmenu, parity, sequencer, ui

### Description

## Claim
There is no "Send to Sequencer" action anywhere in the UI, so a live capture requires the operator to transcribe a request that is already in history.

## Burp-side evidence
`tools/sequencer/sample/index.html` ("Configuring a live capture of tokens"):
> "Locate a request that returns a token that you want to analyze. Right-click the request and choose **Send to Sequencer** from the context menu. You can send a request from anywhere in Burp. Select the token in the Token location within response panel. Click Start live capture."

`tools/sequencer/getting-started.html` makes it step 3 of 8 of the canonical workflow, and step 4 notes the sent entry "is automatically selected in the Select live capture request panel."

`BURP_SUITE_UI_UX_SPECIFICATION.md` §4.8 lists "Select Request source (from History/Repeater)" as a Sequencer view.

## burpsy-side evidence
Absence-grep across the whole UI tree, excluding the Sequencer's own three files:
```
$ cd internal/web/ui/src && grep -rn "equencer" --include=*.ts --include=*.tsx . \
    | grep -v "^./pages/sequencer.tsx\|^./lib/data.workbench.ts\|^./lib/types.workbench.ts"
nav.ts:38:import { SequencerPage } from "./pages/sequencer";
nav.ts:157:    id: "sequencer",
nav.ts:158:    label: "Sequencer",
nav.ts:162:      { id: "sequencer", label: "Sequencer", description: "Token randomness analysis", page: SequencerPage },
ui/hex-editor.tsx:63:  /** Absent means read-only — a captured response, a sequencer token. */
```
Routing and one comment. No action, no menu entry, no store hand-off.

Positive control on the same files the action would live in — `grep -rn "Send to\|sendTo"` over the same tree returns the full existing matrix, so those files are readable:
`internal/web/ui/src/lib/actions.ts:366-371` is the complete context menu send group — Repeater, Intruder, Comparer (A), Comparer (B), Decoder. `lib/actions.ts:142-151` declares the matching action types. Sequencer is in neither.

What the operator does instead, on `internal/web/ui/src/pages/sequencer.tsx`:
- pastes raw request bytes into the "Request to repeat" editor (`:428-436`)
- types the target URL (`:438-447`)
- types a cookie name, header name, or RE2 body pattern (`:448-479`)

## Classification
CAPABILITY GAP.

## What an operator cannot do
Start a Sequencer capture from a request they already have. Every capture begins by hand-copying a request out of HTTP history and retyping the authority.

## Note
The related gap — that the token location is typed rather than picked from a dropdown of cookies actually present in the response, and that Burp's **Form field** location has no counterpart — is filed separately. The declared-not-guessed design is deliberate and disclosed at `pages/sequencer.tsx:422-425`; the missing hand-off is not.


### Acceptance Criteria

The row context menu and the detail-pane action bar in HTTP history and Site map offer "Send to Sequencer", and it lands the exchange's request bytes and authority in the Sequencer's live-capture tab without the operator typing either.

---

## [burpsy-react-ui-hi8] collaborator: no "Insert Collaborator payload" action in Repeater or Intruder

**Beads ID:** `burpsy-react-ui-hi8`
**Priority:** P2
**Labels:** burp-parity, capability-gap, collaborator, intruder, parity, repeater

### Description

## Claim
There is no "Insert Collaborator payload" action in Repeater or Intruder, so an out-of-band payload can only reach a request by the operator pasting it in by hand.

## Burp-side evidence
`tools/collaborator/index.html`, "Generating payloads" — this is the primary insertion route, listed before the bulk-copy one:
> "You can directly insert Collaborator payloads into any request that is open in Burp Repeater. Right-click on the request and select **Insert Collaborator payload**.
> You can automatically insert Collaborator payloads into a Burp Intruder attack. For more information, see Payload types - Collaborator payloads."

`tools/collaborator/getting-started.html` makes it step 4 of the canonical manual OOB workflow:
> "Go to the Repeater tab. Highlight the URL in the Referer header, right-click, and select Insert Collaborator payload. This replaces the Referer URL with a URL that points to the Collaborator server."

## burpsy-side evidence
Absence-grep on the three files the action would live in, with same-file positive control:
```
$ grep -rn "collab\|Collab" internal/web/ui/src/pages/repeater.tsx \
      internal/web/ui/src/pages/intruder.tsx internal/web/ui/src/lib/actions.ts
(no output)

$ grep -c "Repeater" internal/web/ui/src/pages/repeater.tsx
67
```
All three files are readable; the zero is real.

The context-menu send group (`internal/web/ui/src/lib/actions.ts:366-371`) is Repeater / Intruder / Comparer A / Comparer B / Decoder — no Collaborator entry, and no in-editor insertion action anywhere.

Minting works and is reachable, but only as clipboard: `internal/web/ui/src/pages/collaborator.tsx:144-158` mints one address and copies it (`copyToClipboard(payload.address)` at `:150`). The operator then switches tab and pastes.

Intruder payload types: no Collaborator payload type — `internal/web/ui/src/lib/types.tools.ts` carries `PAYLOAD_LAYERS` for payload *processing*, and the generator set has no OOB member.

## Classification
CAPABILITY GAP.

## What works today, for scoping
The rest of the manual OOB loop is functional and should not be re-implemented: mint (`api_collaborator.go` mint handler), auto-refreshing interactions every 5s (`internal/web/ui/src/lib/data.collab.ts:56,68,173` — tighter than Burp's 60s auto-poll), the interaction table with Burp's own columns (`pages/collaborator.tsx:284`), and a detail pane carrying the correlation id, the client-IP interpretation and the raw request (`pages/collaborator.tsx:321-333`). The divergence in what "Poll now" means is disclosed on the wire itself (`internal/web/api_collaborator.go:83-85`).

So this issue is only the insertion half.

## What an operator cannot do
Put a payload into a request without leaving the request. Every blind-SSRF or OOB test is: open Collaborator, mint, switch to Repeater, paste, switch back — and for Intruder, there is no route at all, so an OOB payload cannot be swept across a parameter list.


### Acceptance Criteria

Repeater offers an action that mints a payload and inserts it at the cursor or over the selection in the request editor, and Intruder offers a Collaborator payload generator that mints a fresh address per request. Both refuse with a stated reason when no interaction server is configured, rather than inserting a placeholder.

---

## [burpsy-react-ui-i18] dashboard: no Issue activity feed — findings appear only as aggregate counts

**Beads ID:** `burpsy-react-ui-i18`
**Priority:** P2
**Labels:** dashboard, scanner, ui

### Description

## Claim

The Dashboard has no Issue activity feed. Findings are shown only as aggregate severity counts, so
nothing tells an operator *which* issue was just raised.

## burpsy side

`pages/dashboard.tsx` renders five cards — Coverage (`:415`), Requests sent by burpsy (`:431`), Tool
events (`:436`), Tasks (`:456`), Traffic sources (`:476`) — plus the severity tile row at `:382-412`.

The tiles are counts pulled from `useIssues()`: `issues.data!.counts?.[severity]` (`:390`). They tell
you five went from 4 to 5; they do not tell you what the fifth was, and there is no link through.

"Tool events" is not this feed — it is `data.events` (`:440`), documented in its own subtitle as
"State changes that are not requests."

Absence grep: `grep -rniE "issue activity" internal/web/ui/src internal/dash` -> no match.
Positive control on the same tree: `grep -rn "Tool events" internal/web/ui/src` ->
`pages/dashboard.tsx:437`.

## Burp side

Issue activity is one of Burp's three Dashboard panels and one of the three tabs in every task's
detail window. `map_root.tsv` classes `burp.Zi96`, `burp.Zr_d`, `burp.Zr_f` and `burp.Zr_y` each carry
the same triple of labels: `Audit items`, `Issue activity`, `Event log`. The backing tree is
`siteMapIssueActivityTree` (`burp.Zhlv`), which is also what Burp hangs the per-issue context menu off.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Watch findings arrive during a scan. The only signal today is a tile number changing between
refreshes, which gives no name, no host and no way in.

## Note

Cheap version first: the feed is a reverse-chronological list of findings with severity, name and host,
linking to the advisory. The finding store already has everything it needs — this is a view, not new
collection.


### Acceptance Criteria

The Dashboard carries a reverse-chronological feed of findings as they are raised, each naming severity, issue and host, and each opening its advisory.

---

## [burpsy-react-ui-irt] intruder: Grep - match takes one expression and reports a boolean, not Burp's expression list with a per-expression occurrence-count column

**Beads ID:** `burpsy-react-ui-irt`
**Priority:** P2
**Labels:** burp-parity, capability-gap, intruder, settings

### Description

Burp's Grep - match takes a **list** of expressions and adds one results column per expression,
counting occurrences per response. burpsy takes a single expression and reports one boolean per
attempt.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/configure-attack/settings.html`,
under **Grep - match**:

> **Flag responses matching these expressions** - Specify a list of expressions to flag. By default,
> the expressions list shows some common error strings that are useful when fuzzing.
>
> During the attack, Burp adds a results column for each expression in the list. This records the
> number of times the expression is found in the response. To identify results with the expression,
> click on the column header to sort the results.

Also in the same section, and equally absent on the burpsy side: **Match type** (simple string /
regex), **Case sensitive match**, and **Exclude HTTP headers**.

## burpsy-side evidence

Single expression, boolean answer, all the way down:

- `internal/web/api_tools.go:355-356` — `GrepMatch *string` and `GrepExtract *string`. Scalars, not
  lists.
- `internal/web/api_tools.go:736-752` (`buildGrep`) — compiles exactly one pattern for each.
- `internal/intruder/engine.go:76-83` — `Grep{MatchRe, ExtractRe *regexp.Regexp}`; one each.
- `internal/intruder/engine.go:89-101` (`run`) — `MatchRe.Match(raw)` returns a bool. No occurrence
  count anywhere.
- `internal/intruder/engine.go:227` — `Attempt.GrepMatched *bool`.
- `internal/web/ui/src/pages/intruder.tsx:1049-1062` — one input per grep field.
- `internal/web/ui/src/pages/intruder.tsx:323` — the results column renders a badge reading "match",
  not a number.

There is no case-sensitivity or exclude-headers option: `Grep.run` is handed the whole raw response
including the header block (`engine.go:89`), and case behaviour is whatever the operator encodes in
the pattern (`(?i)`).

## Classification

CAPABILITY GAP.

## What an operator cannot do

Fuzz with more than one indicator at a time. Burp's default fuzzing workflow is to flag a dozen error
strings at once and sort by whichever column lights up; here the operator must either union them into
one regex — losing the ability to tell *which* one matched, since the answer is a single bool — or run
the attack once per indicator. Counting occurrences is also unavailable, so "this response mentions
`root:` eleven times" and "once" look identical.

## Related, filed separately

The labelling defect on these same two fields (they are regexes described as literal strings) is a
distinct issue. This issue is about arity and the missing per-expression options, and it should be
designed together with that one since both touch the same wire fields.

Burp's **Grep - payloads** options (case sensitivity, exclude headers, match against pre-URL-encoded
payloads) are also absent — burpsy detects reflection as a bare boolean at
`internal/intruder/engine.go:224` (`Attempt.Reflected`) with no options — and are filed separately.


### Acceptance Criteria

Grep - match accepts a list of expressions with match-type, case-sensitivity and exclude-headers options, and results carry one occurrence-count column per expression.

---

## [burpsy-react-ui-k5l] scope: an existing rule cannot be edited — only removed and retyped

**Beads ID:** `burpsy-react-ui-k5l`
**Priority:** P2
**Labels:** scope, ui

### Description

## Claim

An existing scope rule cannot be edited. The only way to change one is to remove it and retype the
whole tuple.

This is distinct from burpsy-react-ui-c09 (advanced scope control / save-to-library): that issue is
about rule *expressiveness*, this one is about editing a rule that already exists at all.

## burpsy side

`pages/scope.tsx` has exactly three mutating controls:

- `addRule()` (`:43-68`), driven by the form at `:163-194`
- `removeSelected()` (`:70-84`), the "Remove rule" button at `:202-206`
- Clear scope (`:141-152`)

Row selection sets `selected` (`:213-214`) and is used only by `removeSelected`. There is no edit
affordance and no `PUT`-shaped action — `useUpdateScope` takes `action: "include" | "exclude" |
"remove" | "clear"` only (`lib/data.policy.ts`, per the call sites at `:56`, `:75`, `:147`).

Absence grep on the file: `grep -riE "edit|paste|load from|import" pages/scope.tsx` returns only the
`import` statements at `:1-7`. Positive control on the same file: `grep -n "Add rule" pages/scope.tsx`
-> `:192`.

## Burp side

`map_root.tsv` class `burp.Zry2` (`configPanelTargetScope`) — `Add a new item`,
**`Edit the selected item`**, `Remove the selected item`. Edit is a first-class button next to Add and
Remove in both the include and exclude tables.

## Classification

CAPABILITY GAP (small, high-frequency).

## What an operator cannot do

Fix a typo, or narrow `*.example.com` to `api.example.com`, without deleting the rule and re-entering
host, port, path and protocol from scratch. On a five-arm rule that is five fields retyped to change
one.


### Acceptance Criteria

Selecting a scope rule allows editing its arms in place and saving, with the edit replacing exactly that tuple.

---

## [burpsy-react-ui-kal] intruder: no payload wordlists at all — 0 of Burp's 48, and the fix is a licensing decision first

**Beads ID:** `burpsy-react-ui-kal`
**Priority:** P2
**Labels:** content, decision, intruder

### Description

Burp ships **48 `.pay` payload wordlists**. burpsy bundles **zero** (`find -name '*.pay'` = 0).
Re-derived from `/root/burp-re/in/extract/resources`: 48 confirmed.

burpsy has 6 payload *generators* instead (numbers, dates, brute force, custom iterator, null,
character substitution — completed in 7f5b3b1 / 0def353). Generators and corpora are not substitutes
for each other: a generator produces a space you describe, a wordlist carries knowledge someone else
gathered. Burp's `.pay` files are the second kind — fuzzing strings, known usernames, SQL and XSS
payloads, directory names.

## Why this matters more than it looks

An operator who opens Intruder in burpsy has an empty payload set and must supply their own list from
somewhere. That is not a missing control — the Simple-list and Runtime-file types work — it is a
missing corpus, so the tool is functional and unarmed.

## The decision to make first

This is NOT obviously "copy Burp's 48 files". Two problems:

1. **Licensing.** Burp's shipped resources are PortSwigger's. Bundling them is a legal question, not
   an engineering one, and it should be answered before anyone writes a loader.
2. **Provenance.** A payload corpus is security content; shipping it means owning what is in it.
   SecLists and fuzzdb are permissively licensed and larger, and pointing at them may be the better
   answer than vendoring anything.

Three defensible outcomes, and this issue is closed by any of them being chosen and written down:

- Bundle a small permissively-licensed starter corpus, with its source and licence recorded.
- Ship no corpus and add a wordlist *manager* — a path list, validated, so an operator points at
  their own once rather than per attack. `/api/discovery` already takes a wordlist path, so a shared
  manager would serve both.
- Declare it deliberately out of scope, as the BApp store was, and say so in the Intruder UI so an
  operator is not left hunting for a payload list burpsy never intended to have.

My recommendation is the second: it is the smallest, it has an existing consumer in content
discovery, and it avoids owning security content.


### Acceptance Criteria

One of the three outcomes is chosen and recorded: a licensed starter corpus, a shared wordlist manager serving Intruder and content discovery, or a documented out-of-scope decision surfaced in the Intruder UI.

---

## [burpsy-react-ui-n39] intruder: a network failure is never retried — no retry count and no pause-before-retry exist

**Beads ID:** `burpsy-react-ui-n39`
**Priority:** P2
**Labels:** burp-parity, capability-gap, intruder, settings

### Description

A network failure on one Intruder request is permanent. There is no retry count and no pause-before-
retry, so a transient error turns into a counted `failed` attempt and a hole in the results.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/configure-attack/settings.html`,
under **Error handling**:

> **Number of retries on network failure** - Specify the number of times Burp retries a request when a
> failure occurs. Intermittent network failures are common when testing, so it is best to retry the
> request several times.
>
> **Pause before retry** - Specify the time (in milliseconds) that Burp waits before retrying a failed
> request.

Burp's own guidance is that this is the common case ("intermittent network failures are common when
testing"), which is why both knobs are defaults-on rather than expert options.

## burpsy-side evidence

- `internal/web/api_tools.go:614-628` — the `send` closure is one `auth.Send` per request with a
  per-send timeout and no retry loop:

      send := func(raw []byte) (intruder.Sent, error) {
          ... sctx, cancel = context.WithTimeout(ctx, timeout) ...
          res, err := auth.Send(sctx, raw)
          if err != nil { return intruder.Sent{}, err }
          ...
      }

- `internal/intruder/engine.go` — `Run` records the error against the attempt and moves on; the error
  is grouped into `ErrorBucket` (`engine.go:245`) and counted in `report.Failed` (`:240`).
- `internal/web/api_tools.go:348-364` — `intruderRunReq` has no retry or retry-delay field.
- `internal/web/ui/src/pages/intruder.tsx:1043-1065` — the Settings tab has no such control.

Absence grep:

    $ grep -rli "retries" internal/intruder internal/web/api_tools.go internal/web/ui/src/pages/intruder.tsx
    (no output)

Positive control from the same invocation over the same paths: `grep -rli "baseline" ...` →
`internal/intruder/engine_test.go`.

Note what *does* exist and is not a substitute: `intruder.RateLimit.WithAutoThrottle`
(`internal/web/api_tools.go:420-428`, `internal/intruder/limit.go`) slows the attack down in response
to configured *statuses*. That is Burp's throttling behaviour, not its retry behaviour — it never
re-sends the failed request.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Get a complete result set over a flaky link or against a target with connection limits. A 2,000-
request attack across a VPN drops an arbitrary handful of attempts, and because the payload behind a
failed ordinal is not displayed either, the operator cannot even tell which payloads were never
actually tested. The report is honest that they failed — `report.failed` and the grouped `errors`
table (`pages/intruder.tsx:240-257`) — but the only remedy is re-running the whole attack.

## Note

Retry interacts with the rate limiter: a retry must consume a token from the same
`intruder.RateLimiter` rather than bypass it, or the retry path becomes a way to exceed the pool's
rps. Worth stating in the implementation.


### Acceptance Criteria

Retry count and pause-before-retry are configurable per attack, retries consume the same rate limiter as first sends, and the report distinguishes an attempt that succeeded after retry from one that never succeeded.

---

## [burpsy-react-ui-n7n] ui: the Render view does not render image responses, only HTML

**Beads ID:** `burpsy-react-ui-n7n`
**Priority:** P2
**Labels:** editor, p2, ui

### Description

## Claim
The Render view is offered only for HTML responses. Burp's Render tab also renders image responses, so a captured image in burpsy can only be read as raw bytes or a hex dump.

## Burp-side evidence
- `tools/message-editor/index.html` (bundled docs), Render tab: *"This tab applies to HTTP responses containing HTML **or image** content. It attempts to render the contents of the message body in the form it would appear when displayed in a browser."*

## burpsy-side evidence
- `burpsy-go/internal/web/ui/src/ui/editor.tsx:250` — `const renderable = useMemo(() => response && /html/i.test(contentTypeOf(value)), [response, value]);`
- `:269` gates the tab on that flag; `:347-355` renders through `<iframe sandbox="" srcDoc={bodyOf(value)} />`, which is an HTML-only mechanism.
- An `image/png` or `image/jpeg` response therefore has `available = ["raw","hex"]` and no Render tab.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Look at a captured image — a CAPTCHA, a QR code, an IDOR'd avatar, an exposed document scan or a chart that leaks data. These are ordinary findings and the evidence is in the response body burpsy already stored.


### Acceptance Criteria

Selecting a response whose Content-Type is an image type offers a Render view that displays the decoded image; the existing HTML path is unchanged.

---

## [burpsy-react-ui-pf4] intruder: an attack report cannot be exported — no CSV or download exists on the Results tab

**Beads ID:** `burpsy-react-ui-pf4`
**Priority:** P2
**Labels:** burp-parity, capability-gap, intruder, results

### Description

There is no way to get an Intruder attack's results out of burpsy. No CSV or other export exists on
the Results tab, even though HTTP history has one.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/results/saving-attacks.html`
covers saving an attack and exporting its results; `/root/burp-re/BURP_UI_UX_COMPARISON.md:288` records
"Export results (CSV)" among Burp Intruder's actions.

## burpsy-side evidence

Absence grep:

    $ grep -rni "csv" internal/web/ui/src/pages/intruder.tsx internal/web/api_tools.go
    (no output)

Positive control across the same page directory, confirming the pattern does match in this tree:

    $ grep -rli "csv" internal/web/ui/src/pages/
    internal/web/ui/src/pages/history.tsx

- `internal/web/ui/src/pages/intruder.tsx:1067-1091` — the Results tab renders `AttackResult`, the
  legacy JSON view, or an empty state. No export control.
- `internal/web/ui/src/pages/intruder.tsx:148-332` (`AttackResult`) — four tables and a metric grid,
  no download affordance.
- Nothing server-side either: the only Intruder routes are `/api/intruder/points` and
  `/api/intruder/run` (`internal/web/server.go:742-743`).

The one export-adjacent thing Intruder has is `HttpEditor`'s `filename` prop for the *base request*
(`internal/web/ui/src/pages/intruder.tsx:717`), which saves the template, not the results.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Take the results anywhere. The report cannot be handed to a colleague, diffed against a later run,
pasted into a finding, or post-processed. Combined with the fact that navigating away destroys the
report (filed separately), an attack's output currently exists only in one browser tab until that tab
changes page.

## Note on what to export

The `RunView` shape (`internal/web/api_tools.go:453-457` — report, examples, payload sets) is already a
complete, self-describing JSON document, so a "download this report" button costs almost nothing and
preserves the bounds accounting that makes the report honest. A flat CSV of attempt rows is what a Burp
user will ask for by name; it should carry the payload column, which means it depends on resolving the
missing-payload issue first, and it should carry the caveat fields (`truncated`, `unbucketed`,
`detail_limit`) somewhere, or a CSV of a capped attack will read as a complete result set.


### Acceptance Criteria

An attack report can be downloaded from the Results tab, and any flat row export carries the payload column and the truncated/unbucketed/detail_limit caveats so a capped attack cannot read as complete.

---

## [burpsy-react-ui-pwd] issues: a finding cannot be triaged — no severity override, false-positive mark, comment or delete

**Beads ID:** `burpsy-react-ui-pwd`
**Priority:** P2
**Labels:** scanner, triage, ui

### Description

## Claim

A finding cannot be changed or removed. `/api/issues` exposes no mutation, and the Issues tree has no
context menu, so none of Burp's issue-triage actions has an equivalent.

## burpsy side

`internal/web/server.go:727-728`

    s.mux.HandleFunc("/api/issues", s.handleIssues)
    s.mux.HandleFunc("/api/findings", s.handleFindings) // legacy alias for /api/issues

Those are the only finding routes registered, and both are read paths.

`pages/scanner.tsx:423-459` — the tree leaf is a bare
`<div role="treeitem" onClick={() => setSelectedKey(leaf.key)}>`. No `menuGroups`, no `onContextMenu`.
The advisory pane's action bar (`:489-507`) offers exactly one button, "In history".

Absence grep: `grep -ri "false positive" internal/web/ui/src` returns only `lib/reference.ts:294,300`,
both prose about scanner absence rules, never a control. Positive control on the same tree:
`grep -rn "Tool events" internal/web/ui/src` -> `pages/dashboard.tsx:437`.

## Burp side

`map_root.tsv` class `burp.Zuv8` — `Set severity`, `Set confidence`, `Add comment`, `Delete issue`,
`False positive`, and the severity vocabulary `High severity` / `Medium severity` / `Low severity` /
`Informational`. Class `burp.Zhlv` (`siteMapIssueActivityTree`) — `Delete issue`,
`Are you sure you want to delete all issues for the selected item?`. Class `burp.Zeem` —
`Report issues`, `Delete issues`.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Mark a finding a false positive, correct a severity they disagree with, leave a note for a colleague,
or delete noise — so the Issues tree can never be worked down to a deliverable set. On a scan that
produces 200 findings this is the difference between a report and a raw dump.

## Note before coding

Persistence is the open question, not the UI. An override has to survive a re-audit that re-raises the
same finding, which means it keys on something stabler than the in-memory finding id. Decide the key
(check name + host + path + param?) before building the control, because the wrong key makes the
feature actively misleading — a suppressed false positive that comes back, or a real new finding
silently inheriting an old suppression.


### Acceptance Criteria

A finding can be given an operator-set severity and/or marked a false positive, the override persists across a re-audit that re-raises the same finding, and the Issues tree exposes it from the row.

---

## [burpsy-react-ui-r6q] dashboard: a task can only be cancelled — no rename, delete, scan-again or details

**Beads ID:** `burpsy-react-ui-r6q`
**Priority:** P2
**Labels:** dashboard, tasks, ui

### Description

## Claim

A task on the Dashboard can only be cancelled. There is no per-task menu, so a task cannot be renamed,
deleted from the list, re-run, or opened for detail.

Scope note: this issue is deliberately **not** about pause/resume, which is already tracked as
burpsy-react-ui-8gw. This is the rest of Burp's `taskListEntryOptionsMenu`.

## burpsy side

`internal/web/server.go:819`

    s.mux.HandleFunc("/api/tasks/", s.handleTaskCancel)

That is the only task-mutation route in the server, and `internal/web/api_tasks_cancel.go:25` parses
only the `/cancel` suffix:

    idStr := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/tasks/"), "/cancel")

`pages/dashboard.tsx:142-170` — the last table cell renders one `IconButton` (a `Square`) per running
task, wired to `useCancelTask()` (`:66-76`). Nothing else.

Positive control on the same route family: `grep -rn "api/tasks" internal/web/ internal/` ->
`server.go:819`, `api_tasks_cancel.go:11,25`, `dashboard.tsx:69`, plus tests. No other verb.

## Burp side

`map_merged.tsv` — `taskListEntryOptionsMenu` with `taskListEntryRenameMenuEntry`,
`taskListEntryDeleteMenuEntry`, `taskListEntryScanAgainMenuEntry`,
`taskListEntrySettingsMenuEntry`, and `taskListEntryShowDetailsButton`. `map_root.tsv` class
`burp.Zreg` carries the `Delete task` label. `burp.Zr_o` also carries `dashboardTasksFilterLine` —
Burp's task list is filterable; burpsy's is not.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Re-run a finished scan against the same target, clear completed tasks out of a list that only grows,
or name two crawls of the same host apart.


### Acceptance Criteria

A Dashboard task row offers an options menu with, at minimum, scan again and delete-from-list, backed by routes beyond /cancel.

---

## [burpsy-react-ui-so3] session: rules have no tools scope, so a rule cannot be restricted to specific tools

**Beads ID:** `burpsy-react-ui-so3`
**Priority:** P2
**Labels:** burp-parity, capability-gap, parity, session

### Description

## Claim
Session rules are scoped by host only — there is no tools scope, so a rule cannot be restricted to some tools and not others.

## Burp-side evidence
`settings/sessions/session-handling-rules.html` — the rule editor's Scope tab has three axes:
> "**Tools scope** — The Tools scope settings are on the Scope tab of the session handling rule editor. These settings enable you to specify the Burp tools that each rule should apply to. Burp only processes rules for requests made by in-scope tools."
> "**URL scope** …"
> (and a **Parameter scope**, referenced by the note on "Replace matching part of the request": "it doesn't take into account the Parameter scope setting in the Scope tab")

`settings/sessions/index.html` shows why it is load-bearing rather than cosmetic:
> "There is a default session handling rule that updates requests made by the Scanner with cookies from Burp's cookie jar. This rule does not apply when the Scanner is managing its own sessions during crawling and crawl-driven auditing. You can disable this rule if required."

i.e. Burp's own shipped default rule is defined by its tools scope.

## burpsy-side evidence
The rule's only scope field is a host list — `internal/session/session.go:697`:
```go
ScopeHosts  []string  `json:"scope_hosts"`
```
consumed by `MatchHost` (`internal/session/session.go:717`), which is the whole matching predicate; `Coordinator.MatchingRule(host)` (`session.go:942`) takes a host and nothing else.

The editor is explicit that host is all that is read — `internal/web/ui/src/pages/session.tsx:49`:
> `/** Only host patterns are read server-side; an empty list means "applies everywhere". */`

and the flattening confirms it, `pages/session.tsx:113`:
```ts
hosts: (rule.scope?.rules ?? []).map((entry) => entry.host ?? "").filter(Boolean),
```
The wire scope document has an `allow_all` flag and `{kind, host}` rules (`pages/session.tsx:145`) — richer than the host list, but still only hosts.

## Classification
CAPABILITY GAP.

## Related but separate
URL scope and parameter scope are the other two axes of the same tab. They are not claimed here because host scope is a partial substitute for URL scope (coarser, but the same axis), whereas tools scope has no substitute at all — there is no way to express it. Parameter scope only becomes meaningful once rules have parameter-setting actions, which is the separate rule-actions issue.

## What an operator cannot do
Keep a re-login rule away from a tool it would corrupt. Concretely: a rule that re-logs-in on a 302 will fire during an Intruder attack that is deliberately fuzzing the session cookie, and there is no way to say "this rule applies to Repeater and Scanner but not Intruder".


### Acceptance Criteria

A rule carries a set of tools it applies to, defaulting to all; the coordinator's rule-matching consults the requesting tool alongside the host, and a request from an out-of-scope tool does not trigger the rule. Covered by a test that fires the same request as two different tools and gets different behaviour.

---

## [burpsy-react-ui-srzn] Cross-tool UI shell: search, extender hooks, context menus and attention signaling

**Beads ID:** `burpsy-react-ui-srzn`
**Priority:** P2
**Labels:** epic, ui

### Description

Umbrella for suite-wide UI gaps: no cross-tool Search dialog, disabled dashboard scan types, intercept-to-Repeater/Intruder handoff, tool tabs never signal attention, extender context-menu/editor-tab hooks never surface, missing context menus on Issues/Organizer/Content-discovery/Dashboard, dashboard New-scan single-seed limitation, intercept target host/port/TLS not editable.

---

## [burpsy-react-ui-v34] intruder: no Make unmodified baseline request, so no attack has a base response to compare against

**Beads ID:** `burpsy-react-ui-v34`
**Priority:** P2
**Labels:** burp-parity, capability-gap, intruder, settings

### Description

Burp's `Make unmodified baseline request` issues the template request with every payload position at
its original value, as item 0 of the results, so every attack response has something to be compared
against. burpsy has no equivalent.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/configure-attack/settings.html`,
under **Attack results**:

> **Make unmodified baseline request** - Set the attack to issue the template request with all payload
> positions set to their base values, in addition to the configured attack requests. The request shows
> as item 0 in the results table. This is useful to provide a base response against which to compare
> the attack responses.

The spec records the control's own id: `/root/burp-re/BURP_SUITE_UI_UX_SPECIFICATION.md:173` —
`setName("intruderAttackConfigSettingsMakeUnmodifiedBaselineRequest")`.

## burpsy-side evidence

Absent from the engine, the wire contract and the UI:

- `internal/web/api_tools.go:348-364` — `intruderRunReq` has no baseline field. The full field list is
  `msg_id, target, all, point_index, payloads, mode, points, payload_sets, payload_sources,
  payload_rules, max_payloads, grep_match, grep_extract, pool, auto_throttle, rps, max_in_flight,
  max_requests, timeout_ms`.
- `internal/intruder/engine.go:232-249` — `AttackReport` has no baseline field; `Attempts` are plan
  ordinals only, and ordinals start at the plan's first combination.
- `internal/web/ui/src/pages/intruder.tsx:1043-1065` — the Settings tab contains only the two grep
  fields.

Absence grep:

    $ grep -rli "baseline" internal/intruder internal/web/api_tools.go internal/web/ui/src/pages/intruder.tsx
    internal/intruder/engine_test.go

The single hit is a test, not an implementation, and it is the positive control for this grep: the
pattern does match in this path set, so the empty result for the non-test files is real.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Tell an interesting response from the application's normal one. burpsy's result buckets group by
status, length and reflection (`internal/web/ui/src/pages/intruder.tsx:209-234`), which is a good
substitute for eyeballing a table — but with no baseline row, the operator cannot tell whether the
largest bucket *is* the normal response or whether every single response differs from the unattacked
request. For a single-position sniper over a login form, "all 500 responses were 200/4.1 kB" means
nothing without knowing what the untouched request returns.

## Note on shape

This composes with the honest-accounting style already in the report: a baseline attempt would be one
extra send with `ApplyAll` given no payloads, recorded as ordinal 0 and excluded from the bucket
counts (or shown as its own row) so it cannot inflate `sent`. It needs `Attempt`/`ResultBucket` to
distinguish "baseline" from "attempt 0", which today are the same integer.


### Acceptance Criteria

An opt-in baseline setting issues the template request with all positions at their base values, reported as its own result distinguishable from attempt 0 and excluded from bucket counts.

---

## [burpsy-react-ui-vh0p] Sequencer: randomness battery completeness

**Beads ID:** `burpsy-react-ui-vh0p`
**Priority:** P2
**Labels:** burp-parity, epic, sequencer

### Description

Umbrella for Sequencer gaps: FIPS tests run over the flattened bit stream without disclosure, missing character-transition/spectral/correlation/compression tests, no Send-to-Sequencer action.

---

## [burpsy-react-ui-vs9k] ui: no suite-wide Search dialog — search is per-tool only, no cross-tool search over Proxy/Repeater/Target/Organizer

**Beads ID:** `burpsy-react-ui-vs9k`
**Priority:** P2
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/search.html — "You can perform suite-wide searches in the search dialog. To access the search dialog, click Search on the tab bar." Options: case sensitive, literal/regex, negative matches, in-scope only, dynamic update, request-vs-response / headers-vs-body location, and which tools (Target, Repeater, Proxy, Organizer). Results table with Source/Host/URL/Status/Length/Time and a match-highlighting preview pane.

## burpsy-side evidence
No suite-wide search exists (grep for project-wide/global search / /api/search / SearchPanel is empty). Search is per-tool only — HTTP history's DSL box (pages/history.tsx) filters one tool's rows; there is no dialog that searches across Proxy/Repeater/Organizer/Target at once.


---

## [burpsy-react-ui-ww5] extender: plugin-registered context-menu items and editor tabs never appear in the context menu or the editor tab strip

**Beads ID:** `burpsy-react-ui-ww5`
**Priority:** P2
**Labels:** contextmenu, editor, extender, p2

### Description

## Claim
A plugin's registered context-menu item never appears in any context menu, and a registered editor tab never appears in the message editor's view strip. Both can only be triggered from a Run button on the Extender -> Extensions page, with no selected exchange as context.

## Burp-side evidence
- Spec section 6.4: `ContextMenuItemsProvider` — *"Injects extension custom action menu items into Burp's right-click context menu."*
- Spec section 6.2: `HttpRequestEditorProvider` / `HttpResponseEditorProvider` — *"Allows extensions to inject custom tabbed views into the Request/Response viewer (e.g. Protocol Buffers, JWT decoders)."*
- `tools/message-editor/index.html` (bundled docs) confirms the editor tab strip is the extension surface: *"you can remove or reorder the tabs, and add some extra ones from the settings menu."*

## burpsy-side evidence
This is NOT the documented Swing exclusion. burpsy's own disclosure puts these three points explicitly IN scope — `lib/reference.ts:341`: *"Of userInterface()'s registration points, the ten Swing ones are out of scope for lack of an honest web analogue. The three declarative ones — context-menu items, message-editor tabs, menu actions — are in scope."*

The server side is real: `internal/extension/protocol.go:89-91` defines `KindContextMenu` as *"the analogue of registerContextMenuItemsProvider: an action against a selected [request]"*; `internal/extension/host.go:529-530` dispatches `contextMenu.invoke`; `internal/extension/views.go:157,163` label it.

The UI never surfaces it. The only consumer of the registration list in the entire UI tree is the Extender page's own table:
- `grep -rn 'registration' --include=*.ts --include=*.tsx lib/ ui/ pages/` (excluding reference.ts) -> hits only in `lib/types.extensions.ts`, `lib/data.extensions.ts`, `pages/extensions.tsx`.
- `pages/extensions.tsx:139-180` renders a Registrations table with a per-row Run button (`run(registration)` -> `POST` via `lib/data.extensions.ts:75-90`).
- `lib/actions.ts:782-834` `menu()` never reads the registration list.
- `ui/editor.tsx:264-274` builds `available` from a closed literal union (`MessageView` at `:177`) with no extension point.
- `app.tsx:414-571` `MENUS` is a static array, so `KindMenu` is unsurfaced too.

## Classification
CAPABILITY GAP, contradicting the project's own stated scope.

## What an operator cannot do
Right-click a request and run a plugin action on it. The plugin's action is invocable only by navigating to Extender -> Extensions -> select the plugin -> Run, which does not carry the exchange the operator wanted to act on — so a context-menu plugin cannot do the one thing its kind name means.


### Acceptance Criteria

A loaded plugin's context-menu registrations appear as menu entries in the exchange row and editor context menus and are invoked with the selected exchange; its editor-tab registrations appear as views in the message editor tab strip.

---

## [burpsy-react-ui-xvo] ui: tool tabs never signal attention — a held intercepted request is invisible from every other tool

**Beads ID:** `burpsy-react-ui-xvo`
**Priority:** P2
**Labels:** intercept, p2, shell, ui

### Description

## Claim
Tool tabs never signal that a tool needs attention. With Intercept on and a request held, nothing outside the Proxy page says so — in Burp the Proxy tab highlights, which is how an operator notices their browser has stalled.

## Burp-side evidence
- Spec section 1.1, point 2: every tool module *"expose[s] a `ToolFrameProvider` (returns the root tool UI container) and a **`ToolTabFlasher` (handles tab highlight/attention animations)**."*
- Spec sections 4.1-4.12 name a per-tool flasher for each tool: `dashboardToolTabFlasher`, `proxyToolTabFlasher`, `scannerToolTabFlasher`, `repeaterToolTabFlasher`, and so on — it is a shell-wide contract, not a Proxy special case.

## burpsy-side evidence
- `app.tsx:602-620` renders each tool tab as icon + label only. The only conditional is the active class (`:610`) and `aria-current` (`:611`). No count, badge, dot or animation class.
- No such styling exists: `grep -n 'tool-tab' burpsy-go/internal/web/ui/src/styles.css` returns layout, hover, active and two responsive rules only (lines 277, 290, 298, 319, 324, 2559, 2562, 2579, 2582, 3484) — nothing attention-shaped.
- The data is already in the shell: `app.tsx:146` `useEventStream()`, and `app.tsx:156-158` already reads `live`, `lastEventAt`, `eventCount` off the connection store.

## Classification
UX DIVERGENCE.

## What an operator cannot do
Notice that interception is holding traffic while they are on any other tool. Their browser hangs, and the only way to find out why is to navigate to Proxy -> Intercept and look. Same for a finished audit or a new finding.


### Acceptance Criteria

A tool tab carries a visible attention indicator when its tool needs the operator — at minimum a held-message count on Proxy — driven off the existing event stream and visible from every other tool.

---

## [burpsy-react-ui-ztuu] intruder: no Recursive grep payload type — a payload cannot be derived from the previous response, so token-following and recursive enumeration are impossible

**Beads ID:** `burpsy-react-ui-ztuu`
**Priority:** P2
**Labels:** burp-parity, capability-gap, intruder

### Description

## Burp-side evidence
tools/intruder/configure-attack/payload-types.html — "Recursive grep: This enables you to extract text from the response to the previous request, and use it as the payload for the current request." Settings: Initial payload for first request, Extract grep item, Stop if duplicate payload found; must use a resource pool with max concurrent 1. Core mechanism for following dependent values (CSRF tokens, sequential DB enumeration).

## burpsy-side evidence
Payload types offered in internal/web/ui/src/pages/intruder.tsx:1060-1066 are exactly: list, numbers, file, brute_force, dates, custom_iterator, null. Recursive grep is not among them, and the backend payload_sources union (intruder.tsx:780-804) has no "recursive_grep" case. There is no way to derive a payload from the previous response.


---

## [burpsy-react-ui-1s07] ui: no Engagement tools 'Find comments' / 'Find scripts' / 'Find references' over the site map

**Beads ID:** `burpsy-react-ui-1s07`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/search.html — Engagement tools: "Find comments" and "Find scripts" search part or all of the Target site map for HTML comments / scripts, with a sortable results table, preview highlighting, dynamic update and Export (consolidating duplicates). "Find references (links) to a particular URL" also listed.

## burpsy-side evidence
lib/actions.ts engagement group (498-500) contains only "Generate CSRF PoC"; there is no Find comments, Find scripts, or Find references action, and no site-map engagement-tools submenu.


---

## [burpsy-react-ui-1xb] scope: a rule cannot be disabled without deleting it

**Beads ID:** `burpsy-react-ui-1xb`
**Priority:** P3
**Labels:** scope, ui

### Description

## Claim

A scope rule cannot be disabled. The only way to stop a rule applying is to delete it.

## burpsy side

`internal/core/scope.go` — `ScopeRule` has `Kind`, `Regex`, `Port`, `PathPrefix`, `Protocol` (per the
constructors at `:67-80` and the matcher at `:83-105`) and no enabled/disabled field.
`MatchesRequest` (`:91`) consults no such flag.

`pages/scope.tsx:98-130` — the table's five columns are `Kind`, `Host`, `Port`, `Protocol`,
`Path prefix`. No checkbox column, and `ScopeRow` (`:10-16`) carries no enabled field.

Positive control that `enabled` exists elsewhere on the wire (so this is a scope-specific gap, not a
missing convention): `grep -n "enabled" internal/web/ui/src/lib/types.policy.ts` -> `:57`, `:119`,
`:230`, all on match/replace and session rules.

## Burp side

Burp's scope tables have a per-row Enabled checkbox — `map_root.tsv` `burp.Zb4l` and `burp.Zbwj` carry
the `Enabled` column label, alongside `configPanelTargetScope`'s Add / Edit / Remove controls
(`burp.Zry2`).

## Classification

CAPABILITY GAP (polish).

## What an operator cannot do

Temporarily widen scope — lift an exclusion for one test and put it back — without retyping the rule.
Combined with the absence of rule editing (burpsy-react-ui-k5l), every scope change is destructive.


### Acceptance Criteria

A scope rule can be toggled inactive and back, the state persists, and an inactive rule is ignored by ScopeRule matching.

---

## [burpsy-react-ui-2g13] intruder: 9 payload generator types absent — character substitution, case modification, illegal Unicode, character blocks/frobber, bit flipper, username generator, ECB shuffler, copy other payload

**Beads ID:** `burpsy-react-ui-2g13`
**Priority:** P3
**Labels:** burp-parity, capability-gap, intruder

### Description

## Burp-side evidence
tools/intruder/configure-attack/payload-types.html enumerates Burp's payload types. Beyond the 7 burpsy has, Burp also offers: Character substitution, Case modification, Illegal Unicode, Character blocks, Character frobber, Bit flipper, Username generator, ECB block shuffler, Copy other payload. Each is a documented generator (e.g. "Case modification ... generates case variations on dictionary words"; "Bit flipper ... flips individual bits"; "Username generator ... derives usernames from a list of names").

## burpsy-side evidence
internal/web/ui/src/pages/intruder.tsx:1060-1066 offers only: Simple list, Numbers, File, Brute force, Dates, Custom iterator, Null payloads. The 9 generators above are absent from both the Select and the payload_sources builder (intruder.tsx:780-804). Recursive grep is tracked separately.


---

## [burpsy-react-ui-3sq] sequencer: chi-square, serial-correlation, Monte-Carlo-pi and duplicate detection are CLI-only, absent from the web report

**Beads ID:** `burpsy-react-ui-3sq`
**Priority:** P3
**Labels:** analysis, burp-parity, reachability, sequencer, ux-divergence

### Description

## Claim
The web Sequencer report omits the chi-square, serial-correlation and Monte-Carlo-pi statistics that burpsy's own CLI reports from the same package.

## Burp-side evidence
Not a Burp-parity claim in itself — Burp's battery is covered by the separate missing-tests issue. This is an internal inconsistency: two front-ends over one engine disagree about what the engine can say, and the web one is the surface an operator uses.

For context on why these are worth surfacing at all: `tools/sequencer/results/tests.html` describes the FIPS poker test as performing "a chi-square calculation to evaluate this distribution", and the correlation test as assessing "the amount of randomness in the token as a whole" — so the statistics burpsy already computes are in the same family as tests Burp reports.

## burpsy-side evidence
Implemented in the package:
- `ChiSquare(cs CharStats)` — `internal/sequencer/sequencer.go:137`, documented at `:135` as "the chi-square statistic for character uniformity"
- `SerialCorrelation(values []int)` — `internal/sequencer/sequencer.go:156`
- `MonteCarloPi(values []float64)` — `internal/sequencer/sequencer.go:180`
- `DetectPatterns(tokens)` — `internal/sequencer/sequencer.go:209`, "finds exact duplicates"

All four are aggregated by `Analyse(tl *TokenList)` into `Analysis` (`internal/sequencer/sequencer.go:227-266`).

Their only non-test caller is the CLI:
```
$ grep -rn "ChiSquare\|SerialCorrelation\|MonteCarloPi\|DetectPatterns\|sequencer.Analyse(" --include=*.go . | grep -v _test.go
cmd/burpsy/cli_tools.go:361:  analysis := sequencer.Analyse(tl)
cmd/burpsy/cli_tools.go:368:    "chi_square":      analysis.ChiSquare,
cmd/burpsy/cli_tools.go:370:    "monte_carlo_pi":  analysis.MonteCarloPi,
internal/sequencer/sequencer.go:...  (definitions and internal use only)
```
The web path is a different entry point entirely — `handleSequencerAnalyse` (`internal/web/api_tools.go:888`) calls `sequencer.AnalyseAs` (`internal/sequencer/report.go:167`), which composes `AnalyseChars` + `BitsOf` + `AnalyseFipsBits` and never touches `Analyse`.

`DetectPatterns` is the one with the sharpest operator value: an exact duplicate in a session-token sample is a finding on its own, and the web report has no duplicate count.

## Classification
CAPABILITY GAP — reachability. Nothing needs implementing; the report shape needs extending.

## Caveat against over-claiming
`SerialCorrelation` is **not** Burp's correlation test. It correlates successive character codes within the stream; Burp's correlation test looks for relationships between values at *different bit positions* across tokens. Adding it does not close the missing-tests issue, and the two should not be conflated when either is worked.

## What an operator cannot do
See that their token sample contains repeated tokens, or read the character-uniformity statistic — both available from the same build via the CLI, neither on the page.


### Acceptance Criteria

The web analysis report includes the duplicate-token count and the character-uniformity statistic already computed in internal/sequencer/sequencer.go, each labelled for what it measures. Serial correlation is not presented as Burp's correlation test.

---

## [burpsy-react-ui-446] ui: no request/response layout switcher — split orientation is hardcoded per page and there is no combined view

**Beads ID:** `burpsy-react-ui-446`
**Priority:** P3
**Labels:** editor, layout, p3, ui

### Description

## Claim
There is no way to switch how a request and response are arranged. Burp offers three layouts (side-by-side, stacked, and a combined single-pane view with tabs) from icons in the editor's top-right corner; in burpsy the orientation is fixed per page in source.

## Burp-side evidence
- `tools/message-editor/index.html` (bundled docs): *"In the upper-right corner of the message editor, there are three icons that adjust the screen layout. You can choose from the following options: **Horizontal layout** - The request and response are arranged side-by-side. **Vertical layout** - The request and response are stacked one on top of the other. **Combined view** - Either the request or response fills the message editor pane. You can use the tabs to alternate between the two."*

## burpsy-side evidence
- Orientation is a hardcoded prop per page: `pages/history.tsx:1001` `orientation="vertical"`, `pages/intercept.tsx:717` `"vertical"`, `pages/sitemap.tsx:526` `"vertical"`, `pages/logger.tsx:341` `"vertical"`, `pages/sitemap.tsx:646` `"horizontal"`, `pages/scanner.tsx:674` `"horizontal"`, `pages/advisories.tsx:258` `"horizontal"`.
- `ui/layout.tsx:77-120` `SplitPane` accepts `orientation` as a prop and persists only the divider position (`useDefaultLayout` keyed `burpsy.split.${storageId}`, `:96-100`). There is no control anywhere that changes `orientation` at runtime, and no combined/tabbed mode exists in the component at all.

## Classification
UX DIVERGENCE.

## What an operator cannot do
Give a long response the full pane and switch back to the request with a tab — the standard laptop workflow in Burp. The only lever here is dragging the splitter to the edge and dragging it back.


### Acceptance Criteria

Each request/response pane offers horizontal, vertical and combined (single pane with request/response tabs) layouts from a control in the editor area, persisted per surface.

---

## [burpsy-react-ui-4d5c] scanner: Issues filter is single-select — severity and confidence are one-value dropdowns, so High+Medium cannot be shown together, and there is no hide-duplicate/false-positive filter

**Beads ID:** `burpsy-react-ui-4d5c`
**Priority:** P3
**Labels:** burp-parity, capability-gap, scanner

### Description

## Burp-side evidence
Burp's Issues view filter bar (tools/target issues filtering) is a set of checkboxes — "Show only" High / Medium / Low / Information and Certain / Firm / Tentative — that can be combined, plus hide-duplicate and hide-false-positive. An analyst can show High+Medium while hiding Low+Info in one view.

## burpsy-side evidence
internal/web/ui/src/pages/scanner.tsx:760-775 uses two single-value Select dropdowns: severity is "all" or exactly one of Critical/High/Medium/Low/Informational (state at :281), confidence likewise. There is no way to show two severities at once (e.g. High and Medium but not Low), and no hide-duplicate / hide-false-positive control.


---

## [burpsy-react-ui-4qqz] ui: no 'Record an issue' — a request/response pair cannot be manually recorded as an issue

**Beads ID:** `burpsy-react-ui-4qqz`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/context-menu.html — "Record an issue — Creates an issue for the selected request / response pair or adds to a previously created issue." tools/message-editor/index.html: Create an issue / Add to manually created issue.

## burpsy-side evidence
lib/actions.ts menu (416-500) has no "Record an issue" / manual-issue action; issues can only arise from scans. A request/response pair cannot be manually recorded as an issue from the editor or a table row.


---

## [burpsy-react-ui-5da] logger: entries cannot be annotated with a comment or highlight, and Entry.Note is unused

**Beads ID:** `burpsy-react-ui-5da`
**Priority:** P3
**Labels:** burp-parity, capability-gap, logger, parity, ui

### Description

## Claim
Logger entries cannot be annotated with a comment or a highlight, although `toollog.Entry` already carries an unused `Note` field.

## Burp-side evidence
`tools/logger/entries.html`, "Annotating log entries":
> "You can annotate log entries for later attention:
> To highlight an entry, click in the # column and choose a color from the drop-down menu.
> To leave a comment on an entry, double-click on the Comment column."

`tools/logger/filter/view.html` pairs it with a filter, which is what makes annotation useful rather than decorative:
> "**Filter by annotation** - Choose whether to show only items that have been annotated, either by a comment or highlight."

## burpsy-side evidence
The field exists on the record and is dead. `internal/toollog/toollog.go:102`:
```go
Note        string
```
It appears twice in the whole file (the struct field and nothing that writes it):
```
$ grep -c "Note" internal/toollog/toollog.go
2
```
It is absent from the wire projection — `toolLogEntry`, `internal/web/api_toolkit.go:835-854`, carries `id, tool, host, port, method, path, status, response_len, started_ms, duration_ms, error` and no note.

Consequently there is no annotation UI: the Logger columns are Age / Tool / Authority / Request / Status / Length / Time / Error (`internal/web/ui/src/pages/logger.tsx:130-196`), and the row context menu is copy-URL, copy-curl and two show-in-history actions (`pages/logger.tsx:354-395`). No highlight, no comment.

For contrast, the pattern exists elsewhere in the build: the Organizer has a highlight swatch row and a note textarea (`internal/web/ui/src/pages/organizer.tsx:498-527`), with `HIGHLIGHTS` / `HIGHLIGHT_TONE` already shared from `internal/web/ui/src/lib/types.ts`.

## Classification
CAPABILITY GAP. Partly a wiring job — the storage field is already there, unused.

## What an operator cannot do
Mark a logged request to come back to. On a log of a few thousand tool requests there is no way to flag the three that looked wrong, and no way to filter to them afterwards.


### Acceptance Criteria

A logged entry can be given a highlight colour and a comment, both projected on the wire and persisted for the life of the log, reusing the Organizer's existing highlight vocabulary. The table can filter to annotated entries.

---

## [burpsy-react-ui-5k4] wshistory: no filter surface at all — not just Bambda

**Beads ID:** `burpsy-react-ui-5k4`
**Priority:** P3
**Labels:** p3, ui, wshistory

### Description

RE-TITLED, because the original framing named the one thing that was already decided against and understated the actual gap.

The Bambda half is NOT a gap: burpsy has its own typed query DSL and 8sa closed the Bambda question in burpsy's favour on the grounds that a second filter language would give two ways to say the same thing and stop the query box being the single statement of what is filtered. Filing 'no Bambda filter' invites someone to build the thing that decision refused.

THE REAL GAP, verified: wshistory.tsx contains ZERO matches for 'filter'. Not a DSL box, not a toolbar select, not a search field — nothing. History gained per-column filters composing into the DSL in 5ffe51b and the WS page got none of it, so an operator with a busy WebSocket connection has no way to narrow the frame list at all. That is worse than missing Bambda and is the thing to fix.

## Shape of the work

The DSL is the wrong tool as it stands: internal/query's fields are host/method/path/mime/status/body/length/duration/header/extension/params/highlight/comment — all HTTP-shaped. A frame has a direction, an opcode, a payload and a connection, and none of those are expressible. So this is either:

1. a plain toolbar filter over the frame list (direction, opcode, payload substring), which is small and honest; or
2. new DSL fields for frames, which means deciding what a Queryable is for a frame — the crawler's frontierRow precedent says an adapter that cannot answer a field must report absent rather than guess, and a frame cannot answer  or  at all.

Prefer (1) first. It is the operator-facing gap, and (2) is a grammar decision that should not be made to serve one page.

### Acceptance Criteria

The WebSocket history frame list can be narrowed by direction, opcode and payload substring; an empty result is distinguishable from an empty connection; the Bambda framing is not reintroduced.

---

## [burpsy-react-ui-5kx] sequencer: a live capture cannot be paused, and captured tokens cannot be copied or saved

**Beads ID:** `burpsy-react-ui-5kx`
**Priority:** P3
**Labels:** burp-parity, capability-gap, capture, parity, sequencer

### Description

## Claim
A live capture cannot be paused, and the captured tokens cannot be copied or saved — Stop is the only exit.

## Burp-side evidence
`tools/sequencer/sample/live-capture.html`, "The buttons in the results window enable you to control aspects of the capture":
> "**Pause or Resume** - Temporarily pause and resume the capture.
> **Stop** - Permanently stop the capture.
> **Copy tokens** - Copy the captured tokens to the clipboard.
> **Save tokens** - Save the captured tokens as a file.
> Analyze now - Analyze the current sample of tokens. You need a minimum of 100 captured tokens to perform the analysis.
> **Auto-analyze** - Perform automatic analysis periodically during the live capture."

And why the export matters: "You can use the copied or saved tokens as payloads for Burp Intruder or Burp Scanner. You can also manually load them in a future Sequencer analysis."

`getting-started.html` uses Pause as a normal step: "When Burp has captured a few hundred tokens, click **Pause**. To run randomness tests on the tokens, click Analyze now."

## burpsy-side evidence
The only capture controls are Start and Stop — `internal/web/ui/src/pages/sequencer.tsx:503-524` (`Start capture`, then a danger-variant `Stop capture`). No pause; the stop endpoint is `POST /api/sequencer/capture/stop` (`internal/web/ui/src/lib/data.workbench.ts:112`) and there is no pause/resume route in `internal/web/server.go:756-761`.

The captured tokens are never rendered or exported. `captured` is read at `internal/web/ui/src/pages/sequencer.tsx:311`:
```ts
const captured = capture.data?.tokens ?? [];
```
and used only for a count badge (`:379`), a disabled check (`:396`) and the analyse call (`runCaptured`, `:364-371`). There is no token list in `CaptureProgress` (`pages/sequencer.tsx:238-282`) — that card renders metrics and miss reasons only — and no copy or download action anywhere on the page.

Analyse-now is covered (the header Analyse button operates on the captured set). Auto-analyze is not.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Keep a sample. A capture that produced 400 good tokens can be analysed once in this session and then only stopped; the tokens cannot be pulled out for an Intruder payload list, saved for a later comparison, or held while the capture is paused mid-run.


### Acceptance Criteria

A running capture can be paused and resumed without losing the tokens collected so far, and the captured token list can be copied to the clipboard and downloaded as a newline-delimited file.

---

## [burpsy-react-ui-5q8u] intercept: held messages cannot be annotated or highlighted — no Comment column, no Highlight action, nothing carried into HTTP history

**Beads ID:** `burpsy-react-ui-5q8u`
**Priority:** P3
**Labels:** burp-parity, capability-gap, intercept

### Description

## Burp-side evidence
tools/proxy/intercept-messages.html — "You can add notes and highlights to intercepted messages ... To highlight an intercepted message, right-click the message in the table and select Highlight. Then select a color ... Any annotations that you make also appear against the item in the HTTP history."

## burpsy-side evidence
internal/web/ui/src/pages/intercept.tsx: the held-queue columns (648-679) are #, Dir, Method, Host, Path, Status, Held, Len — no Comment column and no highlight. heldMenu (473-607) has no Highlight or Add-comment action. A held message cannot be annotated, and nothing carries an annotation forward into HTTP history.


---

## [burpsy-react-ui-656] organizer and logger: neither can export as CSV, though HTTP history can

**Beads ID:** `burpsy-react-ui-656`
**Priority:** P3
**Labels:** burp-parity, capability-gap, export, logger, organizer, parity

### Description

## Claim
Neither the Organizer nor the Logger can export as CSV, though HTTP history can.

## Burp-side evidence
`tools/organizer/index.html`, "Exporting results":
> "You can export Organizer items as a CSV file to easily share with others or include in your reports. […] To export all items: Right-click the table then select **Export as CSV**. […] To export specific items: Select the items that you want to export. Right-click and select Export as CSV."

`tools/logger/entries.html`, "Export log entries as CSV":
> "To export log entries as a CSV file, select the relevant entries in the table, right-click and select **Export as CSV**. The whole table is exported if you select zero entries or one entry."

Both docs specify escaping in detail — comma wrapping, doubled quotes, and an Excel guard: "Any data starting with -, +, = or @ is escaped for Excel by prefixing a single quote (')".

## burpsy-side evidence
Exactly one CSV path exists in the UI, and it is History's:
```
$ grep -rn "csv\|CSV" internal/web/ui/src --include=*.tsx --include=*.ts
internal/web/ui/src/lib/api.ts:121,123,157,164,173,180,197,209,210   (historyToCSV and helpers)
internal/web/ui/src/pages/history.tsx:6,594-605,877-879             (exportCSV + the button)
internal/web/ui/src/app.tsx:26,179                                  (desktop shell File > Export History)
```
`lib/api.ts:157` documents it as "The one CSV shape in the app: the History…". No hit under `pages/organizer.tsx` or `pages/logger.tsx`.

Confirmed against the pages themselves: the Organizer's header actions are a count badge and Refresh (`internal/web/ui/src/pages/organizer.tsx:253-258`); the Logger's are counters, Clear log and Refresh (`internal/web/ui/src/pages/logger.tsx:248-272`). Neither row context menu offers an export (`pages/organizer.tsx:420-443`, `pages/logger.tsx:354-395`).

## Classification
CAPABILITY GAP.

## Sizing note
`historyToCSV` (`internal/web/ui/src/lib/api.ts:180`) plus `downloadText` are the working precedent, including a deliberate decision about empty values (`lib/api.ts:121-123`). Note that precedent does *not* currently implement the Excel formula guard Burp's docs specify; if these exports are added, that guard is worth applying to all three rather than only the new two, since a note field is far more likely to start with `=` or `-` than a URL is.

## What an operator cannot do
Get saved exchanges or logged requests out of the tool. The Organizer's whole purpose is collecting evidence for a report, and its contents can only leave by hand.


### Acceptance Criteria

Both tables export the selection (or the whole table when nothing is selected) as CSV, reusing History's export path. The Excel formula guard Burp specifies for values starting with -, +, = or @ is applied, including retroactively to the History export.

---

## [burpsy-react-ui-6a2l] organizer: filter lacks search-term (regex/case/negative), file-extension and annotation axes

**Beads ID:** `burpsy-react-ui-6a2l`
**Priority:** P3
**Labels:** burp-parity, capability-gap, organizer

### Description

## Burp-side evidence
tools/organizer/filter.html: "Filter by search term - You can: Filter responses that contain a specified search term. Use a literal string or a regular expression. Make your search case-sensitive. Select Negative search ... Filter by file extension - Show or hide items based on their file extension. Filter by annotation - Show items with notes or highlights."

## burpsy-side evidence
burpsy-go/internal/web/ui/src/pages/organizer.tsx only implements three filter axes — `inScopeOnly`, `statusClass`, `mimeFilter` (state declared ~line 116; applied in the `visible` useMemo). There is no free-text search box over the rows (the only `<Input>` on the page is the add-by-exchange-id field), no regex/case-sensitive/negative-search option, no file-extension filter, and no filter-by-annotation (notes/highlight) toggle.


---

## [burpsy-react-ui-6ex] repeater: no WebSocket messages in Repeater — a frame cannot be sent, edited (to server or client) and resent; Repeater is HTTP-only

**Beads ID:** `burpsy-react-ui-6ex`
**Priority:** P3
**Labels:** decision-needed

### Description

Burp Repeater is not HTTP-only: a WebSocket message can be sent to Repeater, edited, and resent
against the live connection, with a choice of sending to server or client. burpsy's Repeater is
HTTP-only. WebSocket traffic is visible in Proxy > WebSockets history but is read-only there
(`burpsy-react-ui-nmv`: the frame table has no context menu, so a frame cannot even be sent
anywhere), and Repeater has no WebSocket tab type.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/repeater/websocket-messages.html`:

> You can use Burp Repeater to manipulate and resend individual WebSocket messages... Right-click on
> a WebSocket message, and click **Send to Repeater**... Modify the message. Select whether the
> message should be sent to the server or client. Click **Send**... To resend the message,
> right-click on it and click **Edit and resend**.

> For WebSocket messages, each Repeater tab contains ... A message editor ... The WebSocket
> connection via which the message is sent. This is set automatically when you send a message [from
> WebSockets history].

`managing-tabs.html` confirms the tab type is first-class: "Burp Repeater opens each new HTTP or
WebSocket message in a new tab ... click the button. Select either **HTTP** or **WebSocket**."

## burpsy-side evidence

- `internal/web/ui/src/pages/repeater.tsx` — `RepeaterTab` carries `target`/`request`/`protocol`
  (http/https) only; the editor and send path assume an HTTP request/response. There is no WebSocket
  tab, no direction (to-server / to-client) control, and no held-connection concept.
- `internal/web/ui/src/pages/wshistory.tsx` is read-only (see `burpsy-react-ui-nmv`), so there is no
  "Send to Repeater" origin for a frame either.

## Decision

This is a subsystem, not a control: it needs a persistent client-side WebSocket the operator can
frame against (server *and* client direction), a new Repeater tab type, and a "Send to Repeater"
path out of WebSockets history. Sizing and whether to build it is a product decision, hence the
[DECISION] marker. Blocks nothing else; blocked by the wshistory frame menu (`nmv`) for the
natural entry point.


---

## [burpsy-react-ui-6fq] ui: message-editor syntax colouring stops at the headers — bodies are one flat colour, with no hover-decode popups

**Beads ID:** `burpsy-react-ui-6fq`
**Priority:** P3
**Labels:** editor, p3, ui

### Description

## Claim
Syntax colouring stops at the end of the headers. The whole body renders in one flat colour, and there are no hover popups showing decoded values. Burp colourises parameters, HTML elements, JavaScript, JSON and CSS, and decodes syntax items on mouse-over.

## Burp-side evidence
- `tools/message-editor/text-editor.html` (bundled docs), Syntax analysis: *"Syntax in HTTP requests and responses is automatically colorized to highlight interesting items, such as **parameters in requests and HTML elements in responses**. **JavaScript, JSON, and CSS content is also fully colorized.**"*
- Same section: *"When syntax colorizing is enabled, the editor also displays **mouse-over popups that show the decoded values of syntax items** where appropriate. For HTTP requests, the popups perform URL-decoding, and for responses they perform HTML-decoding."*
- Pretty printing coverage in the same file: *"JSON. XML (including image/svg+xml content). HTML. CSS. JavaScript."*

## burpsy-side evidence
- Four decorations total, and the body is one of them: `ui/editor.tsx:23-26` — `START_LINE`, `HEADER_NAME`, `HEADER_VALUE`, and `BODY_LINE = Decoration.line({ class: "cm-http-body" })`. `buildDecorations` (`:41-66`) applies `BODY_LINE` to every line past the header boundary with no tokenisation inside it.
- No language mode is loaded: the extension list is `ui/editor.tsx:243` — `[httpHighlight, burpEditorKeys, EditorView.contentAttributes.of(...)]` plus optional `lineWrapping`. No `@codemirror/lang-*` import anywhere in the file (`grep -c 'lang-' ui/editor.tsx` -> 0; positive control `grep -c '@codemirror' ui/editor.tsx` -> 3).
- No hover decode: `grep -rn 'hoverTooltip' --include=*.tsx src/` -> no hits.
- Pretty printing covers JSON and XML/HTML only, not CSS or JavaScript: `lib/message.ts:278-302` `prettyMessage` branches on `type.includes("json") || looksLikeJson(body)` (`:284`) and `type.includes("xml") || type.includes("html") || /^\s*<[a-z!?]/i` (`:290`), with no CSS or JS branch.

## Classification
UX DIVERGENCE.

## What an operator cannot do
Scan a response body structurally — pick out a script block, spot a parameter, see where a JSON value ends. And a URL-encoded parameter value in a request cannot be read without selecting it and pressing the decode chord, where Burp just shows it on hover.


### Acceptance Criteria

Response and request bodies are colourised by content type (JSON, HTML/XML, JavaScript, CSS), request parameters are distinguished, and hovering a URL- or HTML-encoded syntax item shows its decoded value.

---

## [burpsy-react-ui-6s2] ui: Proxy settings miscellaneous and web-interface sections absent

**Beads ID:** `burpsy-react-ui-6s2`
**Priority:** P3
**Labels:** p3, proxysettings, ui

### Description

Audit gap #46/#47 (PlumOtter parity audit 2026-08-27). proxysettings.tsx covers bind/intercept/certificate/redirect/timeout but not Burp's 'Miscellaneous' settings (e.g. strip comments, remove unsupported encodings) or 'Web interface' (accessible via browser) section. Verified absent: grep miscellaneous|web interface|webInterface in proxysettings.tsx returns no matches. NOTE: TLS passthrough (#10) and resource pools (#11) were already filed as burpsy-react-ui-wyp and closed FALSE (they exist).

---

## [burpsy-react-ui-6t8] sequencer: token location is free-text only, with no picker over the response and no form-field option

**Beads ID:** `burpsy-react-ui-6t8`
**Priority:** P3
**Labels:** burp-parity, capability-gap, capture, parity, sequencer, ui

### Description

## Claim
The Sequencer's token location is typed as free text with no dropdown of what the response actually contains, and Burp's "Form field" location has no counterpart.

## Burp-side evidence
`tools/sequencer/sample/index.html`, "Selecting a token location" — all three are pickers over the response, not free text:
> "You can specify the token you want to analyze in the Token location within response panel. The following options are available:
> **Cookie** - Select a cookie from the drop-down list. This is the most common method to pass session tokens to clients.
> **Form field** - Select an HTML form field value from the drop-down list. You can use this method to transmit anti-CSRF tokens and other per-page tokens to clients.
> **Custom location** - Specify a custom location within the response that contains the token you want to analyze. This uses the response extraction rule dialog."

`getting-started.html` step 5: "Select a cookie in the Token location within response panel."

`BURP_SUITE_UI_UX_SPECIFICATION.md` §4.8: "Token Location selector (Cookie name, Form field, Custom regex match)."

## burpsy-side evidence
Three kinds, all typed by hand — `internal/web/ui/src/pages/sequencer.tsx:448-479`:
```tsx
<option value="cookie">Set-Cookie value</option>
<option value="header">Response header value</option>
<option value="body_regex">Body, by pattern</option>
```
followed by a free-text `Input` for the cookie name / header name (`:469-478`) or the RE2 pattern (`:458-467`). No option is populated from a response.

Server side, `tokenLocation` (`internal/web/api_sequencer_capture.go:56-58`) matches those three kinds and compiles the pattern (`:87`). There is no form-field extractor:
- `cookie` reads a Set-Cookie value
- `header` reads a response header value
- `body_regex` applies an RE2 pattern

A form field is reachable *only* by the operator hand-writing a regex for it, which is a different task from picking a name off a list — and the regex has to be right about the surrounding HTML.

## The deliberate part, and where it stops
Declared-not-guessed is an explicit design choice and is disclosed — `internal/web/ui/src/pages/sequencer.tsx:422-425`:
> "The token location is declared, not guessed: a heuristic that picked the wrong cookie would produce a confident verdict about the wrong string."

That reasoning defends refusing to *auto-select* a location. It does not defend refusing to *offer* the list: presenting the cookies and form fields actually present in a captured response, for the operator to choose from, is still a declaration — the operator picks. So the disclosure covers auto-detection, not the absence of a picker, and this issue is scoped to the picker.

This depends on the send-to-Sequencer issue: a picker needs a response to populate from, which the paste-a-raw-request flow does not have.

## Classification
CAPABILITY GAP (form-field location; picker) — not covered by the existing disclosure.

## What an operator cannot do
Pick the token. They must already know the exact cookie or header name before opening the page, and for an anti-CSRF form token they must write a working regex against HTML they cannot see on this page.


### Acceptance Criteria

When a request arrives with a response (via send-to-Sequencer), the token location offers the cookies, headers and HTML form fields actually present in that response as selectable options, plus a form-field extractor server-side. The operator still chooses — nothing is auto-selected — so the declared-not-guessed disclosure stays true.

---

## [burpsy-react-ui-72k9] logger: capture filter is tool-only — no capture-by-scope/MIME/status/search-term and no memory or size limit

**Beads ID:** `burpsy-react-ui-72k9`
**Priority:** P3
**Labels:** burp-parity, capability-gap, logger

### Description

## Burp-side evidence
`tools/logger/filter/capture.html` — the Logger capture filter (Settings mode) has these dimensions:
"Capture limit [memory]... Capture by request type: Capture only in-scope items / Discard items
without responses / Capture only parameterized requests. Capture by MIME type... Capture by status
code... Capture by tool... Capture by search term (Regex / Case sensitive / Negative search)...
Session handling... Limit request/response size." The capture filter is destructive and separate from
the view filter: "Items that are not captured will be discarded from Logger."

## burpsy-side evidence
burpsy's capture axis is TOOL-ONLY. The UI renders one checkbox per tool and nothing else:
`burpsy-go/internal/web/ui/src/pages/logger.tsx:320-335` (the `capture-axis` toolbar maps `tools` to
per-tool `<Checkbox>` only). The endpoint takes only `{tool, on}`:
`burpsy-go/internal/web/api_toolkit.go:903` `toolLogSetCaptureReq{ Tool string; On bool }` and
`:922` `s.toolLog.SetCapturing(tool, req.On)`. There is no capture-by-scope, capture-by-MIME,
capture-by-status, capture-by-search-term, no session-handling toggle, and no configurable memory or
per-item size limit (eviction is a fixed cap surfaced only as the read-only `dropped` count at
logger.tsx:255). So an operator cannot restrict what Logger records except by whole tool.
(Method/status/search filters at logger.tsx:84-102 are client-side DISPLAY filters over already-kept
rows — they do not stop capture.)


---

## [burpsy-react-ui-745] repeater: the Protocol override cannot force HTTP/2 — only auto or force HTTP/1.1

**Beads ID:** `burpsy-react-ui-745`
**Priority:** P3
**Labels:** burp-parity, capability-gap, repeater, transport

### Description

Repeater's Protocol override offers "Auto (negotiate)" and "Force HTTP/1.1". There is no "force
HTTP/2". The sender can speak h2 and will do so when a target negotiates it, but the operator cannot
require it — so a target that advertises only HTTP/1.1 in ALPN, or negotiates h2 inconsistently,
cannot be tested over h2 from Repeater.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/configure-attack/settings.html`,
under **HTTP version** (Repeater carries the same override):

> Use this setting to control whether Burp Intruder uses HTTP/2 or HTTP/1 for the current attack.
>
> If you enable Override the project-level HTTP/2 setting, then Burp ignores the current project-level
> HTTP/2 setting configuration.
>
> You can then choose whether to use HTTP/2 or HTTP/1 for the current attack. **Select Default to
> HTTP/2 if the server supports it** to use HTTP/2 with all servers that advertise support for it
> during the TLS handshake. Deselect this option to use HTTP/1 even if the server supports HTTP/2.

## burpsy-side evidence

- `internal/web/ui/src/pages/repeater.tsx:624-635` — the select has exactly two options:
  `""` → "Auto (negotiate)" and `"http1"` → "Force HTTP/1.1".
- `internal/web/repeater_options.go:55-59` — the server-side allowlist matches:

      switch o.ProtocolPreference {
      case "", "auto", "http1":
      default:
          return fmt.Errorf("protocol_preference: unknown preference %q (want auto, http1, or empty for auto)", ...)
      }

- `internal/web/repeater_options.go:64-69` — `protocolPreference()` maps `"http1"` to
  `sender.ProtocolPreferenceHTTP1` and *everything else* to `sender.ProtocolPreferenceAuto`. There is
  no h2 value to map to.
- h2 does work when negotiated: `internal/web/api_tools.go:133-136` records the actual protocol
  (`outcome.Protocol`) precisely because "an HTTP/1.1 request to a target that negotiates h2 goes out
  as h2".

## Related but distinct: h2 crafting lives on another screen

burpsy does have raw HTTP/2 frame crafting — `POST /api/http2/program`, registered at
`internal/web/server.go:741`, hook at `internal/web/ui/src/lib/data.policy.ts:202`, typed at
`internal/web/ui/src/lib/types.policy.ts:242`. Its only UI is in **Settings**
(`internal/web/ui/src/pages/settings.tsx:201, 205`). Burp puts HTTP/2 message editing in Repeater,
where the request being tested is. That placement divergence is worth noting here but the actionable
claim in this issue is the missing force-h2 preference.

Absence grep for an h2 preference value:

    $ grep -rn "http2\|/api/h2" internal/web/ui/src/pages/repeater.tsx
    (no output)

Positive control, same file: `grep -c "protocol" internal/web/ui/src/pages/repeater.tsx` → non-zero
(`:107`, `:117`, `:506`, `:624-634`).

## Classification

CAPABILITY GAP.

## What an operator cannot do

Pin a send to HTTP/2. There is no way to say "use h2 for this request" — only "do not use it". A
target whose h2 behaviour differs from its h1 behaviour (h2-specific header handling, h2 downgrade
issues, `:authority` versus `Host` disagreements) cannot be exercised deliberately from Repeater; the
operator is at the mercy of whatever ALPN returns, and `internal/web/repeater_options.go:18-21`
records that the protocol choice is per-authority cached, so it may not even be stable across sends.

## Note

The deliberate omission recorded at `internal/web/repeater_options.go:18-21` is an **ALPN** override
specifically ("h2 carries no ALPN knob a raw-byte send could honour — offering it would be a switch
that does nothing"). That is a different control from a protocol *preference* of h2, which the sender's
`ProtocolPreference` enum is already shaped to express — so this is not covered by that disclosure.
Whoever picks this up should confirm `sender.ProtocolPreference` has, or can gain, an h2 variant
without reintroducing the switch-that-does-nothing problem; if it cannot, this issue should be closed
as deliberate with that reasoning written down.


### Acceptance Criteria

An operator can pin a send to HTTP/2, or the omission is recorded as deliberate in repeater_options.go with the reason, the way the ALPN override already is.

---

## [burpsy-react-ui-7bd] settings: no font-size or UI-scaling control — editor text is hardcoded at 12px

**Beads ID:** `burpsy-react-ui-7bd`
**Priority:** P3
**Labels:** editor, p3, settings, ui

### Description

## Claim
There is no font-size or UI-scaling control. Burp offers separate font adjustment for the UI and for the message editor; burpsy's only appearance controls are Theme and Table density, and the editor font size is a hardcoded 12px.

## Burp-side evidence
- `tools/message-editor/text-editor.html` (bundled docs), Syntax analysis: *"You can configure this behavior, and **adjust the font**, in the message display settings."*
- Spec section 2.2 defines two independent scales: a System UI hierarchy (16/13/12/11pt) and a separate `Code / Monospace` scale (12pt, JetBrains Mono / Consolas / Menlo) for *"HTTP Request/Response headers & bodies"* — two knobs, deliberately separate.

## burpsy-side evidence
- Appearance section offers Theme and Table density only: `pages/settings.tsx:1301-1335` (`THEMES` at `:40`, `DENSITIES` at `:46`). `grep -in 'font|scal|zoom' pages/settings.tsx` -> one hit, `:1421`, an inline `fontSize: "var(--fs-sm)"` style on unrelated helper text.
- UI sizes are viewport-fluid clamps with no user input: `tokens/primitives.css:46-48` e.g. `--fs-sm: clamp(12px, 0.68vw, 14px)`.
- Editor font size is hardcoded: `ui/editor.tsx:86` `"&": { ..., fontSize: "12px" }` and `:93-94` gutters at `11px`.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Enlarge the HTTP message text without enlarging the tables. Browser zoom is the only lever and it scales everything together — which is precisely why Burp ships the two knobs separately. On a 4K display this is a per-session irritation.


### Acceptance Criteria

Settings -> Appearance offers a UI text-size control and a separate message-editor font-size control, both persisted, with the editor size driving ui/editor.tsx's theme instead of a literal.

---

## [burpsy-react-ui-7nh2] session: rules have no URL scope (suite scope / custom URL path-port-protocol match) — host patterns only

**Beads ID:** `burpsy-react-ui-7nh2`
**Priority:** P3
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/session-handling-rules.html — "URL scope ... You can select from the following options: All URLs. The suite scope ... A specific custom scope" and links to URL-matching rules (protocol/host/port/path).

## burpsy-side evidence
pages/session.tsx:774-823 offers only a list of host patterns ("Hosts this rule covers"); ruleOut (128-149) emits scope.rules as Include{host} only. There is no "use the suite (Target) scope" binding and no path/port/protocol URL-matching — a rule cannot be scoped to a single URL or path.


---

## [burpsy-react-ui-7vy] proxy settings: the interception state at startup cannot be configured — it always begins off

**Beads ID:** `burpsy-react-ui-7vy`
**Priority:** P3
**Labels:** burp-parity, capability-gap, intercept, parity, proxysettings, ui

### Description

VERIFIED against HEAD by AuditProxy (Proxy-screen parity audit, 2026-08-27).

Interception state is per-process and resets on restart. Burp lets the operator
choose what the state should be at startup.

## Burp-side evidence

BurpClass9641.java -- configPanelProxyInterception (:36):
  :42  title "Default Proxy interception state"
  :47  "...whether Burp Proxy interception is enabled when you start Burp."
  :87  "Enable interception"
  :96  "Disable interception"
  :79  "Restore the settings that was selected in the Proxy > Intercept tab when
        Burp closed"
  :53  preference key user_options.misc.enable_proxy_interception_at_startup

## burpsy-side evidence

The toggle reads and writes live server state only:
  pages/intercept.tsx:399-405   toggle() -> controls.setEnabled.mutate(!data.enabled)
  pages/intercept.tsx:669-673   the Switch, checked={data?.enabled ?? false}

No startup preference exists. pages/proxysettings.tsx is 140 lines end to end
(read in full) and contains only the six response-modification switches and the
outcome counters. The section inventory of pages/settings.tsx (Scope, Protocols,
Proxy, TLS passthrough, Browser engine, Audit checks, Scanner, Network, Hotkeys,
Appearance, Project backup, Uninteresting headers, Use your own CA, Certificate,
Diagnostics, Upstream proxy and SOCKS, Resource pools, Scheduled tasks) has no
interception entry.

## Classification

CAPABILITY GAP (minor).

## What an operator cannot do

Start a session with interception already on. A session that begins with a login
flow the operator needs to hold has to be raced: start the server, reach the
console, flip the switch, and only then point the client -- anything the client
sent in between passed through unheld.

## Note

burpsy has a natural place for this that Burp does not: settings.tsx already
persists project-scoped state (ProjectBackupSection :1367), so "restore what was
selected last time" is available as an option and is arguably the better default
of Burp's three.


### Acceptance Criteria

An operator can choose whether interception is on, off, or restored-from-last-session at server start; the choice survives a restart and the Intercept page reflects it on first load.

---

## [burpsy-react-ui-7zdm] session: no Test macro dry-run showing each step's request/response, cookies and derived values

**Beads ID:** `burpsy-react-ui-7zdm`
**Priority:** P3
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/macros.html — "Test macro ... Burp issues the macro requests in sequence ... displays: All requests and responses. The values of any cookies received. The details of any parameters that Burp attempted to derive values for."

## burpsy-side evidence
pages/session.tsx has "Run login now" (986-990) which runs the full recovery and shows an outcome + the probe response body only (loginRows / 991-1000). There is no standalone Test-macro that dry-runs a rule's steps and shows each step's request, response, received cookies and derived values.


---

## [burpsy-react-ui-8cbc] intruder: no 'URL-encode these characters' payload encoding — the default final-pass character encoding of the Payloads panel is absent, only a whole-payload encode processing rule exists

**Beads ID:** `burpsy-react-ui-8cbc`
**Priority:** P3
**Labels:** burp-parity, capability-gap, intruder

### Description

## Burp-side evidence
tools/intruder/configure-attack/payload-types.html (Payload encoding) — the Payloads side panel ends with "URL-encode these characters", a box naming the characters Intruder URL-encodes in every generated payload as the final step before sending, independent of the payload type. Burp defaults this to characters like `=&?+;/%` etc.

## burpsy-side evidence
internal/web/ui/src/pages/intruder.tsx has no payload-encoding control. Encoding is reachable only as an ordered processing rule (PAYLOAD_RULES "encode" with a layer, types.tools.ts:30, intruder.tsx:1274-1304), which URL-encodes the entire payload rather than a chosen character set and does not run as an automatic final pass. The default "URL-encode these characters" safety net is absent.


---

## [burpsy-react-ui-8f2] intruder: no Auto-pause — an attack cannot stop itself when an expression appears in or disappears from a response

**Beads ID:** `burpsy-react-ui-8f2`
**Priority:** P3
**Labels:** blocked, burp-parity, capability-gap, intruder, settings

### Description

Burp's Auto-pause pauses an attack when a chosen expression appears in — or goes missing from — a
response. burpsy has no equivalent.

Filed separately from the general "cannot stop an attack" issue because it is a distinct control with
its own configuration, but it is **blocked on that one**: there is nothing to pause until a running
attack has a pause mechanism.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/intruder/configure-attack/settings.html`,
under **Auto-pause attack**:

> These settings automatically pause the attack when a specified expression appears in or is missing
> from a response.
>
> - Select **Enable auto-pause**.
> - Choose one of: **Pause if an expression in the list appears in a response** / **Pause if an
>   expression in the list is missing from a response**.
> - Add expressions to the list ...
> - Select the **Match type**: Simple string / Regex.
> - If required, enable **Case-sensitive match**.
>
> During the attack, Burp automatically pauses the attack if a response contains (or doesn't contain)
> the expressions. You can resume the attack at any time ... Once resumed, Burp will pause the attack
> each time a response meets the auto-pause condition.

## burpsy-side evidence

Absence grep:

    $ grep -rli "auto_pause|autopause" internal/intruder internal/web/api_tools.go internal/web/ui/src/pages/intruder.tsx
    (no output)

Positive control from the same invocation over the same paths: `grep -rli "baseline" ...` →
`internal/intruder/engine_test.go`.

- `internal/web/api_tools.go:348-364` — `intruderRunReq` has no auto-pause field.
- `internal/web/ui/src/pages/intruder.tsx:1043-1065` — the Settings tab has only the two grep fields.
- `internal/intruder/engine.go:89-101` — the per-response hook that would host this check
  (`Grep.run`) computes a match boolean and an extraction and returns; nothing can act on the result
  to halt the loop.

What exists and is *not* this: `intruder.RateLimit.WithAutoThrottle`
(`internal/web/api_tools.go:420-428`) slows the attack in response to configured HTTP statuses. That is
Burp's throttling, keyed on status, and it slows rather than pauses — it cannot key on response
content and it does not stop.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Stop an attack automatically when it starts doing damage or when it has found what it was looking for.
The two cases Burp's docs are built around: a lockout page appearing mid-spray (the operator wants to
stop before locking every account), and a success indicator appearing (the operator wants to stop
rather than send the remaining 4,000 requests). Today the attack runs to its bound either way, and
because there is no manual stop either, both outcomes are unavoidable once launched.

## Sequencing

Do the manual pause/stop work first — a mechanism that can halt a running attack, and a report shape
that can say it was halted. Auto-pause is then a predicate evaluated in the same place `Grep.run`
already runs, plus its expression list and options. The expression-list plumbing overlaps with the
Grep - match arity issue; the two should share one list type rather than growing two.


### Acceptance Criteria

Auto-pause is configurable with an expression list, appears/missing mode, match type and case sensitivity, and a triggered condition actually pauses the attack with the report saying so.

---

## [burpsy-react-ui-8gw] ui: Dashboard pause/resume and listener-status controls absent

**Beads ID:** `burpsy-react-ui-8gw`
**Priority:** P3
**Labels:** dashboard, p3, ui

### Description

Audit gap #32/#33 (PlumOtter parity audit 2026-08-27). Dashboard.tsx has a live task-progress bar (line 117) but no pause/resume control for a running task and no listener up/down status indicator. Burp's dashboard exposes both. Verified absent: grep for pause|resume|listener status|telemetry in dashboard.tsx returns no matches.

---

## [burpsy-react-ui-8o6] collaborator: interaction table has no protocol filter, search, annotation or mark-as-read

**Beads ID:** `burpsy-react-ui-8o6`
**Priority:** P3
**Labels:** burp-parity, capability-gap, collaborator, parity, ui

### Description

## Claim
The Collaborator interaction table cannot be filtered by protocol, searched, or annotated, and interactions cannot be marked read.

## Burp-side evidence
`tools/collaborator/index.html`, "Viewing results":
> "Results are displayed in the table. You can perform the following actions to analyze the results:
> **Filter the table** - To filter the table by network protocol, click the HTTP, DNS, and SMTP buttons.
> **Search the table** - Click Search and enter an expression.
> **Annotate interactions** - Right-click any interaction and select Comment or Highlight.
> **Mark interactions as read** - Select the desired interactions then right-click and select Mark as read."

And the unread count is surfaced globally: "The number of unread interactions is displayed on the Collaborator tab label, making it easy for you to see interaction counts at a glance."

## burpsy-side evidence
The table is a bare `SimpleTable` with no controls — `internal/web/ui/src/pages/collaborator.tsx:284`:
```tsx
<SimpleTable headers={["#", "Type", "Client IP", "Payload", "Time", ""]}>
```
Rows render a type badge, IP, payload and time, plus an Open button (`pages/collaborator.tsx:285-301`). The only state the component holds is which row is expanded — `const [selected, setSelected] = useState<number | null>(null)` (`pages/collaborator.tsx:44`). No filter state, no search box, no context menu, no read/unread.

The columns themselves match `BURP_SUITE_UI_UX_SPECIFICATION.md` §4.7 ("Columns: Interaction ID, Type (DNS, HTTP, SMTP), Client IP, Time") — the data is there; the triage controls are not.

Protocol filtering has real values to filter on: the OOB client models four — `internal/oob/client.go:67`:
```go
// Protocol is "dns", "http", "smtp" or "ldap".
```
So a filter is not blocked on data. Note burpsy has one protocol more than Burp's three buttons (ldap), which the filter design should account for rather than hardcoding Burp's set.

## Classification
CAPABILITY GAP.

## Scoping note — what already works, do not redo
Minting, the 5-second auto-refresh (`internal/web/ui/src/lib/data.collab.ts:56,68,173`, tighter than Burp's 60s auto-poll), the detail pane with correlation id, client-IP interpretation and raw request (`pages/collaborator.tsx:307-335`), and the honest poll-semantics disclosure (`internal/web/api_collaborator.go:83-85`) are all in place. This issue is the table's triage controls only.

## What an operator cannot do
Work a channel that has collected volume. With a few hundred DNS interactions from a scan plus the handful of HTTP hits that actually prove a finding, there is no way to show only HTTP, search for the payload subdomain in question, or mark what has been reviewed.


### Acceptance Criteria

The interaction table can be filtered by protocol (covering all protocols the OOB client models, not just Burp's three), searched by expression, and annotated with a comment or highlight; interactions can be marked read and an unread count is visible without opening the page.

---

## [burpsy-react-ui-8r6] issues: report export cannot be filtered — always the whole finding store

**Beads ID:** `burpsy-react-ui-8r6`
**Priority:** P3
**Labels:** report, scanner, ui

### Description

## Claim

Report export is always the entire finding store. There is no way to export a subset — by severity, by
host, or by selection.

## burpsy side

`internal/web/api_report.go:18-35` — `handleReport` reads nothing off the request but the path suffix:

    format := strings.TrimPrefix(r.URL.Path, "/api/report/")

then dispatches to `reportJSON` / `reportSARIF` / `reportHTML`. No `r.URL.Query()` call anywhere in the
file. `reportRows()` (`:40-67`) begins `findings := s.findings.All()` and iterates all of them.

`pages/scanner.tsx:641-646` renders three unconditional download links built from `REPORT_FORMATS`
(`:47-51`) — `/api/report/html`, `/api/report/json`, `/api/report/sarif`. They ignore the page's own
severity and confidence filters, which are applied only to `rows` for display (`:292-303`).

Positive control on the same file: `grep -n "api/report" internal/web/api_report.go` -> `:12`, `:23`.

## Burp side

`map_root.tsv` class `burp.Zeem` — `Report issues`; class `burp.Zuv8` — `Report `, `selected issues`,
`the "%s" issues`. Burp reports from a selection.

## Classification

CAPABILITY GAP (polish).

## What an operator cannot do

Hand over "the High and Critical findings on this host" — the export is everything or nothing, so the
filtering has to happen in whatever tool receives the file.

## Note

Worth noting the mismatch is visible on screen: the operator filters the Issues tree to 3 findings,
clicks HTML, and gets 200. Making the export honour the active filters would be the least surprising
behaviour and needs no new controls.


### Acceptance Criteria

Report export honours a severity/host filter or the active Issues-tree filter, and the UI states which findings the file will contain.

---

## [burpsy-react-ui-9hip] session: rules have no parameter scope — cannot restrict a rule to requests carrying a named parameter

**Beads ID:** `burpsy-react-ui-9hip`
**Priority:** P3
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/session-handling-rules.html — "Parameter scope. You can specify that rules should only apply to requests containing specific named parameters. This enables you to create a rule that updates a certain parameter across all requests, such as a CSRF token."

## burpsy-side evidence
pages/session.tsx rule editor has Name, Enabled, Max attempts, Hosts, Validity, Steps — no parameter-scope field. SessionRuleFull (lib/types.policy.ts) has no parameter-scope member, so a rule cannot be restricted to requests carrying a named parameter.


---

## [burpsy-react-ui-9prk] session: validity check has no regex/case-sensitive matching and no redirection-target-URL condition

**Beads ID:** `burpsy-react-ui-9prk`
**Priority:** P3
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/session-handling-rules.html — validity search "You can search for a literal string or a regular expression. You can make the search case sensitive" and can inspect "The URL of any redirection target" in addition to headers/body.

## burpsy-side evidence
burpsy-go/internal/session/session.go ValidityRule struct: StatusIs, BodyContains, BodyNotContains, HeaderPresent, HeaderAbsent, All/Any/Not. All string matches are literal substrings (validate.go) — no regex flag, no case-sensitivity option, and no redirection-target-URL condition. pages/session.tsx:57-62 VALIDITY_FIELDS mirror exactly these literal fields.


---

## [burpsy-react-ui-9t1] sequencer: live capture has no thread/concurrency control — only a per-request delay

**Beads ID:** `burpsy-react-ui-9t1`
**Priority:** P3
**Labels:** burp-parity, capability-gap, sequencer

### Description

## Burp-side evidence
settings/tools/sequencer.html — Live capture settings: "Number of threads - Specify the maximum number of concurrent requests that the live capture can make." Burp captures tokens with a configurable concurrency pool.

## burpsy-side evidence
burpsy-go/internal/web/api_sequencer_capture.go:354-358 — the capture request struct exposes only `Count` and `DelayMs`; the capture loop is single-threaded and paced only by delay. There is no thread/concurrency control, so a 5000-token capture over a slow app cannot be parallelised. pages/sequencer.tsx:480-502 exposes only "Requests" and "Delay (ms)" fields.


---

## [burpsy-react-ui-a13] scan launch: no pre-scan filter step to drop duplicates, static assets or unparameterized items

**Beads ID:** `burpsy-react-ui-a13`
**Priority:** P3
**Labels:** crawler, scanner, ui

### Description

## Claim

There is no pre-scan filter step. A scan launched from the site map goes straight to the engine, so
static assets and duplicate items consume the request budget.

## burpsy side

`lib/actions.ts:404-405` — "Actively scan this branch (crawl)" / "this host (crawl)" call
`crawlFrom(exchange, "branch"|"host")` directly; there is no intermediate dialog.
`pages/dashboard.tsx:222-236` — `submit()` calls `startCrawl.mutate` and `close()` immediately.

Absence grep: `grep -rniE "remove duplicate|no parameters|remove items with" internal/web/ui/src` -> no
match. Positive control on the same tree: `grep -rn "Actively scan this branch" internal/web/ui/src` ->
`lib/actions.ts:404`.

Note what *does* exist and is not this: the crawl form's bounds — max requests, max depth, rps
(`ui/crawl.tsx:72-83`) — cap the total cost but cannot express "spend it on the parameterized pages,
not the sprite sheets".

## Burp side

`map_root.tsv` class `burp.Zraa` is the wizard step, with the prompt *"You have selected N items to
scan. Before continuing, you can use the filters below to remove certain categories of items, to make
your scanning more targeted and efficient."* and four filters:

- `Remove duplicate items (same URL and parameters)`
- `Remove items with no parameters`
- `Remove out-of-scope items (based on current suite scope)`
- `Remove items with the following extensions` — shipped default
  `js,gif,jpg,png,ico,css,woff,woff2,ttf,svg`

Each renders a live count (the `[calculating...]` variants are in the same class).

## Classification

CAPABILITY GAP.

## What an operator cannot do

Aim a bounded scan. With a 200-request budget on a site whose map is 60% static assets, most of the
budget goes to files that cannot carry a finding — and nothing on screen says so.

## Note

The extension filter is the one worth building first; it is a client-side predicate over the same tree
the site map already holds, and Burp's default list is a reasonable starting value to copy.


### Acceptance Criteria

Launching a scan from a site-map selection offers filters to exclude items by extension, items with no parameters, and duplicates, each showing how many items it removes.

---

## [burpsy-react-ui-b2nt] ui: convert-selection offers only key-char URL/HTML/Base64 — no all-chars/%u/entity variants, no Base64-URL, no Construct string

**Beads ID:** `burpsy-react-ui-b2nt`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/message-editor/index.html — Convert selection: URL ("just key HTTP metacharacters, or all characters, or all characters using 2-byte Unicode-encoding (e.g. %u0041)"), HTML ("key metacharacters, or all characters, numeric entities &#65;, or hex entities &#x41;"), Base64, Base64 URL, and "Construct string" (JavaScript, SQL for Microsoft/Oracle/MySQL).

## burpsy-side evidence
ui/editor.tsx:353-364 selectionGroups offers exactly six entries: URL-encode/decode (key chars only, urlEncodeKeyChars), HTML-encode/decode (key chars), Base64-encode/decode. No all-chars or %u-Unicode URL variant, no numeric/hex HTML entity variant, no Base64-URL in the selection menu, and no Construct string (JS/SQL) generator.


---

## [burpsy-react-ui-boq] sequencer: no significance level and no effective-entropy chart — entropy is one number plus a grade

**Beads ID:** `burpsy-react-ui-boq`
**Priority:** P3
**Labels:** analysis, burp-parity, parity, sequencer, ux-divergence

### Description

## Claim
The Sequencer report has no significance level and no effective-entropy chart, so entropy is reported as a single number with a pass/fail rather than as bits-at-a-confidence-level.

## Burp-side evidence
`tools/sequencer/results/tests.html`, "How the tests work" — significance is the operator's input to the whole analysis:
> "Compares the probability to a range of significance levels. You can reject the hypothesis that the sample is randomly generated if the probability falls below the significance level you choose for your analysis.
> You can choose the probability you use to interpret the randomness of your findings - this is the significance level. Scientific experiments often use levels between 1% and 5%. FIPS tests often use levels between 0.002% and 0.03%. A lower significance level means that stronger evidence is required to reject the hypothesis…"

`tools/sequencer/results/index.html` — and the headline output is a curve over it, not a scalar:
> "**Effective entropy** — The Effective entropy chart shows the number of bits that pass the randomness tests at various significance levels, ranging from > 0.001% to 10%.
> In most cases, the Effective entropy chart shows that the choice of significance level is not important. This occurs when the tokens possess either a clearly satisfactory or clearly unsatisfactory amount of randomness for any of the significance levels."

Both the character-level and bit-level tabs repeat the pair: "Significance levels chart" and "Effective entropy chart".

## burpsy-side evidence
No significance parameter exists on any path. The analyse request accepts `text` / `tokens` / `encoding` only — `sequencerAnalyseReq` consumed at `internal/web/api_tools.go:893-920`; the frontend sends exactly those (`internal/web/ui/src/lib/data.workbench.ts:58-72`).

The report is scalars plus a grade — `SequencerReport` at `internal/sequencer/report.go:138-155`: `Tokens, Encoding, EncodingDetected, Characters, Bits, Fips, Grade, Verdict, Warnings`. `Grade` is one of pass / fail / insufficient (`pages/sequencer.tsx:40`).

FIPS pass criteria are fixed constants, not functions of a chosen significance — `internal/sequencer/fips.go:36-60` (`monobitLow/High`, `pokerLow/High`, `longRunBits`, `runIntervals`), documented at `fips.go:6-13` as the literal FIPS 140-2 numbers.

No chart of any kind on the page. Verified across the tree with positive control:
```
$ grep -rn "chart\|Chart\|svg\|Recharts" internal/web/ui/src/pages/sequencer.tsx
(no output)
$ grep -c "Metric\|SimpleTable" internal/web/ui/src/pages/sequencer.tsx
16
```
The rendered output is `Metric` tiles (`pages/sequencer.tsx:197-215`), the FIPS table (`:87-101`) and the positions table (`:152-180`).

## Classification
CAPABILITY GAP (significance level) + UX DIVERGENCE (a scalar and a grade where Burp gives a curve).

## Note on an existing docs error
`BURP_UI_UX_COMPARISON.md` §9 records "Charts / visualization | ✅ GUI charts | ⚠️ Web charts" for burpsy. There are no charts on this page; that row is wrong and should not be used to size this work.

## What an operator cannot do
State a finding the way a report expects it — "N bits of effective entropy at a 1% significance level" — or see whether the verdict is robust to the choice of level, which is the question Burp's chart is designed to answer at a glance.


### Acceptance Criteria

The analysis accepts a significance level and reports effective entropy as bits-per-significance-level across Burp's range, rendered so the operator can see whether the verdict is robust to the choice. The stale "Web charts" row in BURP_UI_UX_COMPARISON.md section 9 is corrected.

---

## [burpsy-react-ui-c09] ui: Scope advanced scope control and save-to-library absent

**Beads ID:** `burpsy-react-ui-c09`
**Priority:** P3
**Labels:** p3, scope, ui

### Description

Audit gap #37/#38 (PlumOtter parity audit 2026-08-27). scope.tsx has no advanced scope-rule builder (protocol/host/port/file/param include-exclude expressions) and no 'save to scope library' action. Verified absent: grep advanced|library|save to in scope.tsx returns no matches.

---

## [burpsy-react-ui-c6y] proxy settings: TLS pass-through is built but lives on the Settings page, where a Burp user does not look for it

**Beads ID:** `burpsy-react-ui-c6y`
**Priority:** P3
**Labels:** burp-parity, decision, decision-needed, nav, proxysettings, ux, ux-divergence

### Description

VERIFIED against HEAD by AuditProxy (Proxy-screen parity audit, 2026-08-27).

TLS pass-through is fully built and works. It lives on the Settings page. In Burp
2026.7.1 it is a PROXY settings panel, so a migrating operator looks for it under
Proxy settings, finds six response-modification switches, and concludes the
feature is missing.

This has already produced one false finding in this repo, and it produced a
second, smaller one in the close reason that closed the first.

## Burp-side evidence -- the panel is Proxy-scoped

BurpClass9055.java:
  :46  setName("configPanelProxyTlsPassThrough")
  :60  title "TLS pass through"
  :65  "Use these settings to specify destination webservers for which Burp will
        directly pass through TLS connections. No details about requests or
        responses made via these connections will be available in the Proxy
        intercept view or history."
  :71  help anchor DESKTOP_TOOLS_PROXY_OPTIONS_TLS_PASS_THROUGH
  :71  preference key "proxy.ssl_pass_through"

Both the control name and the help anchor are TOOLS_PROXY_OPTIONS, i.e. this is
one of the Proxy tool's own option panels, filed beside
configPanelProxyModificationRules (whose anchor is
DESKTOP_TOOLS_PROXY_OPTIONS_RESPONSE_MODIFICATION -- BurpClass9083.java:74) and
configPanelProxyListeners.

## Correction to burpsy-react-ui-wyp's close reason

wyp was correctly closed FALSE -- the feature exists. But its close reason also
states: "Both live on the SETTINGS page rather than Proxy settings -- which is
also where Burp puts TLS pass-through (Settings -> TLS), so it is not even a
placement divergence."

That parenthetical is wrong for 2026.7.1, per the evidence above. Burp does have
a Settings -> TLS area, but TLS pass-through is not in it; it is a Proxy options
panel. So the placement divergence wyp ruled out is real. wyp's verdict on the
capability stands and should not be reopened -- this issue is only the placement
question wyp deferred in its final line ("Reopen only if someone wants these
surfaced on the Proxy settings page as well, which is a placement question and
not a capability gap").

Resource pools, the other half of wyp, are correctly placed: Burp files those
outside the Proxy tool too, so nothing to change there. Upstream proxy and SOCKS
(settings.tsx:1733) are likewise correctly under Settings, matching Burp's
configPanelUpstreamProxyServers / configPanelSocksProxy.

## burpsy-side evidence

Built and working: pages/settings.tsx:395-484 (TlsPassthroughSection), hooks
usePassthrough / useAddPassthrough / useRemovePassthrough
(lib/data.policy.ts, imported at settings.tsx:27), route
/api/proxy/passthrough (internal/web/server.go:790).

Note the route is already namespaced /api/proxy/ -- the backend considers this a
proxy concern; only the UI does not.

Reached from nav "settings" (nav.ts:262-268), not from "proxysettings"
(nav.ts:128).

## Classification

UX DIVERGENCE. No capability is missing.

## What an operator cannot do

Find it. A Burp user opens Proxy -> Proxy settings, sees only response
modification, and reports TLS pass-through as absent -- which is exactly what
happened in this tracker.

## Shape of the work -- a placement decision, not a feature

Options:
1. Move TlsPassthroughSection to pages/proxysettings.tsx. Matches Burp and the
   route's own namespace; costs Settings a panel.
2. Render it in both places from one component. Avoids the move but gives two
   doors to one setting.
3. Leave it and add a pointer on Proxy settings naming where it lives.

(1) or (3). (3) is nearly free and would have prevented both false findings; (1)
is the better end state. Recommend (3) now, (1) when proxysettings.tsx is next
touched -- burpsy-react-ui-77m (listener config) will touch it.


### Acceptance Criteria

Proxy settings either hosts the TLS pass-through panel or names where it lives; a reader of burpsy-react-ui-wyp's close reason is not left believing Burp files this panel under Settings.

---

## [burpsy-react-ui-c7w6] intruder: results table lacks Time-of-day, Cookies, Comment and a Timeout column distinct from Error — a result cannot be annotated and a timeout looks like any error

**Beads ID:** `burpsy-react-ui-c7w6`
**Priority:** P3
**Labels:** burp-parity, capability-gap, intruder

### Description

## Burp-side evidence
tools/intruder/results/viewing-results.html lists the results-table columns: Request, Position, Payload, Status code, Time of day, Response received, Response completed, Error, Timeout, Length, Cookies, Comment. "Time of day - The time of day the request was made"; "Timeout - Whether a timeout occurred"; "Cookies - Any cookies received in the response"; "Comment - Any user-applied comment".

## burpsy-side evidence
internal/web/ui/src/pages/intruder.tsx:468 fixes the Attempts columns to: #, Payload, Status, Length, Time, Reflected, Grep, Error, Response. There is no Time-of-day column, no Cookies column, no per-row Comment column, and no Timeout column distinct from Error (intruder.tsx:468-497). A finding cannot be annotated in the results, and a timeout is indistinguishable from any other network error.


---

## [burpsy-react-ui-ce8] ui: no 'paste URL as request' — a new Repeater tab always starts from a fixed example.com template

**Beads ID:** `burpsy-react-ui-ce8`
**Priority:** P3
**Labels:** p3, repeater, ui

### Description

## Claim
There is no way to turn a host or URL into a request. Burp's "Paste host / URL as request" builds a request from a copied URL; in burpsy a new Repeater tab always starts from a fixed example.com template that must be hand-edited.

## Burp-side evidence
- `tools/context-menu.html` (bundled docs), universal menu options: **Paste host / URL as request** — *"Creates an HTTP request from a copied host or URL. For example, ginandjuice.shop or https://ginandjuice.shop"*.

## burpsy-side evidence
- Absence grep over the whole UI tree: `grep -rli 'Paste host' --include=*.tsx --include=*.ts burpsy-go/internal/web/ui/src/` -> **no files**; `grep -rli 'as request'` -> **no files**. Same-tree positive control: `grep -rli 'Copy URL' --include=*.tsx --include=*.ts .` -> `pages/logger.tsx lib/actions.ts`.
- The only new-tab path is a fixed template: `app.tsx:472-485` Repeater -> "New request tab" calls `openRepeaterTab({ name: ..., target: "https://example.com:443", protocol: "https", request: templateRequest("example.com") })`.
- `lib/actions.ts:561-577`'s action surface has no URL-to-request entry.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Paste a URL from a ticket, a report or a browser bar and get a working request. They open a template pointed at example.com and hand-edit the target field, the request line and the Host header — four edits for what is one paste in Burp.


### Acceptance Criteria

Pasting or entering a host or URL creates a Repeater tab whose target, request line and Host header are derived from it, reachable from the Repeater menu and the new-tab affordance.

---

## [burpsy-react-ui-d18r] session: cookie jar shows only host/name/value — no path, domain, expiry or Secure/HttpOnly

**Beads ID:** `burpsy-react-ui-d18r`
**Priority:** P3
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/index.html — "The cookie jar honors the domain and path scope of cookies." Burp's cookie jar viewer shows domain/path and lets you edit each cookie's attributes.

## burpsy-side evidence
pages/session.tsx:1025-1040 renders the jar as three columns only: Authority (host+scheme), Name, Value. There is no Path, Domain, Expiry, or Secure/HttpOnly column, so two cookies differing only by path are indistinguishable and scope attributes are invisible.


---

## [burpsy-react-ui-dao] scope: no Paste URL and no load-from-file for bulk scope entry

**Beads ID:** `burpsy-react-ui-dao`
**Priority:** P3
**Labels:** scope, ui

### Description

## Claim

Scope rules can only be entered one at a time through the form. There is no paste-a-URL shortcut and no
load-from-file, so scoping a 40-host engagement is 40 manual entries.

## burpsy side

`pages/scope.tsx:163-194` — one `Toolbar` of five `Field`s (kind, host pattern, port, path prefix,
protocol) and an "Add rule" button. `addRule()` (`:43-68`) reads those five pieces of state and clears
them; it parses nothing URL-shaped.

Absence grep on the file: `grep -riE "edit|paste|load from|import" pages/scope.tsx` returns only the
`import` statements at `:1-7`. Positive control on the same file: `grep -n "Add rule" pages/scope.tsx`
-> `:192`.

## Burp side

`map_root.tsv` class `burp.Zry2` (`configPanelTargetScope`) — `Add a new item by pasting a URL`,
`Paste URL`, and `Load ...`. The same pair appears on the other scope-entry surfaces: `burp.Zh5w`,
`burp.Zrda`, `burp.Zhw_` all carry `Paste URL` + `Load ...`.

## Classification

CAPABILITY GAP (polish).

## What an operator cannot do

Turn a scope list they were handed — a text file of URLs, or a URL on the clipboard — into scope rules
without decomposing each one into host / port / path / protocol by hand.

## Note

Paste URL is the higher-value half and is nearly free: it is a URL parse feeding the five fields the
form already has. Load-from-file needs a decision on format (one URL per line? the JSON the API
speaks?) and can wait.


### Acceptance Criteria

A URL can be pasted and decomposed into a scope rule's arms; bulk entry from a file or multi-line paste is available or explicitly declined with a reason.

---

## [burpsy-react-ui-e23c] session: no automatic macro parameter analysis / Re-analyze — every cross-step value wired by hand

**Beads ID:** `burpsy-react-ui-e23c`
**Priority:** P3
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/macros.html — "When you define a new macro, Burp automatically tries to find any relationships ... identifying parameters whose values can be determined from the preceding response ... form field values, redirection targets, or query strings in links." plus a "Re-analyze macro" button and "Derive from prior response" parameter handling.

## burpsy-side evidence
pages/session.tsx requires every cross-step value to be declared by hand as an extraction (ExtractionRows, 228-331) and referenced as {{name}}. There is no automatic parameter-relationship analysis and no Re-analyze action; a CSRF token flow must be wired manually step by step.


---

## [burpsy-react-ui-f6a] settings: no search across settings and no category tree — 20 sections and ~87 fields in one flat scroll

**Beads ID:** `burpsy-react-ui-f6a`
**Priority:** P3
**Labels:** p3, settings, ui

### Description

## Claim
Settings is one flat 20-section scrolling page with no search and no category tree. Burp's Settings is a searchable tree, and the search box is how a Burp user finds any setting they do not already know the location of.

## Burp-side evidence
- `settings/ui/hotkeys.html` (bundled docs) navigates by path — *"Go to **Settings > User interface > Hotkeys**"* — and the whole docs tree under `desktop/settings/` mirrors Burp's category hierarchy (`settings/ui/`, `settings/network/`, `settings/tools/`, ...), i.e. a two-level tree is the addressing scheme.
- Same page also records the project/user split, which burpsy has no analogue for: *"The Hotkeys settings are **user settings**. They apply to all installations of Burp on your machine."*
- Spec section 4.12 and the tool sections consistently reference a Settings *dialog* reached from each tool's own gear.

## burpsy-side evidence
- `pages/settings.tsx:1967-1994` `SettingsPage` renders 20 sections in sequence with nothing but a `PageHeader` above them; the file is 2,627 lines with 87 `Field`s (`grep -c Field pages/settings.tsx` -> 87).
- The only search in the whole file is hotkeys-local: `grep -in search pages/settings.tsx` -> 2 hits, `:1271` *"Search hotkeys"* and `:1284` *"No matching hotkey"*. Nothing searches across sections.
- No anchor nav, no tree, no section index component is rendered by `SettingsPage`.
- No project/user distinction: config export/import is a single undifferentiated bundle (`app.tsx:279-323`, `internal/web/api_config.go`).

## Classification
UX DIVERGENCE.

## What an operator cannot do
Type "redirect" or "response modification" and land on the setting. They scroll 20 sections instead, past ~87 fields.

## Decision needed
Scope call before code: (a) add a filter box that hides non-matching sections/fields (cheap, gets 80% of the value); (b) add a left category tree plus deep-linkable section routes; (c) also introduce a project-vs-user settings distinction, which is a data-model decision about what travels with a capture and touches `api_config.go`. (a) and (b) are independent of (c).


### Acceptance Criteria

Settings offers a search that filters to matching sections and fields across the whole page, and sections are reachable by name (tree or deep-linkable anchors) rather than only by scrolling.

---

## [burpsy-react-ui-he81] history: no Listener port column — multiple listeners are indistinguishable in history

**Beads ID:** `burpsy-react-ui-he81`
**Priority:** P3
**Labels:** burp-parity, capability-gap, history

### Description

## Burp-side evidence
tools/proxy/http-history/index.html — "Listener port - The listener port on which the request was received."

## burpsy-side evidence
pages/history.tsx:635-751 has no Listener port column; Exchange (lib/types.ts:81+) does not record which proxy listener captured the exchange. With multiple listeners there is no way to tell them apart in history.


---

## [burpsy-react-ui-hmp1] history: no custom columns (Bambda/Montoya script-defined column)

**Beads ID:** `burpsy-react-ui-hmp1`
**Priority:** P3
**Labels:** burp-parity, capability-gap, decision-needed, history

### Description

## Burp-side evidence
tools/proxy/http-history/custom-columns.html — "Add custom columns ... use Java-based scripts to add powerful custom columns to the HTTP history table" via the Montoya API (ProxyHttpRequestResponse), loadable from a Bambda library.

## burpsy-side evidence
pages/history.tsx has a fixed column set (635-751); there is no "Add custom column" action and no Bambda/script surface anywhere in the UI. [DECISION] requires an extension/scripting runtime (ties to extender gap ww5) — a scripting-architecture call.


---

## [burpsy-react-ui-i3l] organizer: cannot show a saved exchange's request and response — only a jump to HTTP history

**Beads ID:** `burpsy-react-ui-i3l`
**Priority:** P3
**Labels:** burp-parity, capability-gap, decision, decision-needed, organizer, parity, ui

### Description

## Claim
The Organizer cannot show a saved exchange's request and response — selecting a row offers only a jump to HTTP history.

## Burp-side evidence
`tools/organizer/index.html`, "Inspecting a message in Organizer":
> "Select a message to inspect its request and response in the lower pane. Both are shown as read-only snapshots.
> To search within the request or response, use the search bar below the message.
> Use the tabs beside the message to switch between the Inspector and Notes panels."

And the snapshot semantics, stated earlier on the same page: "Messages appear in the Organizer inbox as **read-only copies** of the original request and response, including any notes and highlights."

## burpsy-side evidence
The detail card renders the note editor only — `internal/web/ui/src/pages/organizer.tsx:450-533`: Title, Highlight swatches, and an "Investigation note" textarea. No message editor.

Viewing the bytes means leaving the page — `internal/web/ui/src/pages/organizer.tsx:233-237`:
```ts
/** Reveal the underlying exchange in HTTP history rather than copying its bytes here. */
const openInHistory = (exchange: number) => {
  focusExchange(exchange);
  setRoute("history");
};
```
reached from a per-row icon button (`:422-431`) and a "Show in history" action (`:459-462`).

## The design tension worth deciding
burpsy stores a *reference*, not a copy: `organizer.Item` holds `Exchange int` (`internal/organizer/organizer.go:10`), and the page states the intent — `pages/organizer.tsx:455`: "The note stays attached to the exchange, not to a copy of its bytes."

That choice is defensible and has a visible consequence the page handles well: when the exchange is evicted, the row shows "exchange no longer retained" (`pages/organizer.tsx:402-408`) and is exempted from filters with a stated reason (`pages/organizer.tsx:20-37`).

But it is also the reason the bytes cannot be shown reliably, and it diverges from Burp, where the copy is the point — the item survives independently of history. So:

1. Add a read-only request/response pane resolving from the traffic store on demand. Cheapest; inherits the unresolved state that already exists. An evicted exchange still cannot be inspected.
2. Store a byte snapshot at save time, matching Burp. Removes the unresolved-row state entirely, at a memory cost, and makes the Organizer usable as evidence after eviction — which is what an operator saving something for a report actually wants.

(2) is the larger change and the better match to what the tool is for; (1) is a real improvement available now. Worth an explicit decision rather than defaulting to (1) because it is easier.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Read what they saved, in the place they saved it. Every look at a shortlisted exchange is a round trip to HTTP history and back, and once the exchange is evicted the note survives with no way to see what it was about.


### Acceptance Criteria

Selecting an Organizer item shows its request and response read-only on the Organizer page. Whether bytes are snapshotted at save time or resolved from the traffic store is decided and recorded; if resolved, an evicted exchange keeps the existing explicit unresolved state.

---

## [burpsy-react-ui-i4u] sequencer: no token-handling settings — short tokens cannot be padded and there is no base64-decode-before-analysis

**Beads ID:** `burpsy-react-ui-i4u`
**Priority:** P3
**Labels:** analysis, burp-parity, capability-gap, parity, sequencer

### Description

## Claim
The Sequencer has no token-handling settings: short tokens cannot be padded, and there is no "Base64-decode before analyzing".

## Burp-side evidence
`settings/tools/sequencer.html`, "Token handling":
> "**Pad short tokens at start / end** - The Sequencer statistical tests can only be performed on tokens of identical length. If the application produces tokens with a variable length, then the tokens are padded. You can choose whether padding is applied at the start or end of each token. In most cases, pad tokens at the start.
> **Pad** - Specify the character that is used for padding. For numeric or ASCII hex-encoded tokens, the 0 character is usually most appropriate.
> **Base64-decode before analyzing** - Enable this setting to decode any Base-64-encoded tokens before analysis. This generally improves the accuracy of the analysis."

`BURP_SUITE_UI_UX_SPECIFICATION.md` §4.8 confirms `configPanelSequencerTokenHandling` as a recovered config panel, and the comparison doc records the strings "Base64-decode before analyzing", "Pad short tokens at:", "Start" / "End".

`tools/sequencer/results/index.html` shows padding is reported as sample metadata: the Summary tab contains "The number of tokens that were padded."

## burpsy-side evidence
No padding anywhere. `AnalyseChars` (`internal/sequencer/report.go:290`) walks each token to its own length; variable length is reported as a warning rather than normalised — `internal/sequencer/report.go:189-194`:
> "token lengths vary (%d to %d): positions past %d have fewer samples than the rest, and a variable-length token is itself worth explaining"

and surfaced per-position as a `samples` column (`internal/web/ui/src/pages/sequencer.tsx:163`). That is a defensible alternative to padding and is honest, but it is not the same operation, and the operator has no way to choose Burp's.

No decode-before-analysis. The one related control is the "Read token bits as" select — `internal/web/ui/src/pages/sequencer.tsx:380-393`, values `SEQUENCER_ENCODINGS = ["hex", "base64", "raw"]` (`lib/data.workbench.ts:54`) — which reaches `AnalyseAs(tokens, encoding)` (`internal/sequencer/report.go:167`) and selects the **bit view** for the FIPS tests via `BitsOf` (`fips.go:183`). The character-level analysis still runs over the raw token characters (`report.go:175`, `AnalyseChars(tokens)`, unconditioned on encoding).

So the encoding select is genuinely wired — it is not a decorative control — but it does something different from Burp's setting: it changes how bits are read, not what the character analysis sees. A base64 session token analysed here has its character positions measured over base64 characters, where Burp would measure the decoded bytes.

## Classification
CAPABILITY GAP (padding, decode-before-analysis) plus a semantic divergence in the one adjacent control.

## What an operator cannot do
Analyse a variable-length or base64-wrapped token on the same basis Burp would, and cannot tell from the page that the basis differs — the encoding select's label suggests it covers the base64 case.


### Acceptance Criteria

Token handling offers padding at start or end with a configurable pad character, reporting how many tokens were padded, and a decode-before-analysis option whose effect on the character-level analysis is distinguished in the UI from the existing bit-view encoding select.

---

## [burpsy-react-ui-j7t] certificate: the CA cannot be regenerated from the console — only imported or downloaded

**Beads ID:** `burpsy-react-ui-j7t`
**Priority:** P3
**Labels:** burp-parity, capability-gap, certificate, parity, proxysettings, ui

### Description

VERIFIED against HEAD by AuditProxy (Proxy-screen parity audit, 2026-08-27).

burpsy can import a CA and export the current one, but cannot generate a fresh
one. There is no rotation path from the console.

## Burp-side evidence

BurpClass9617.java, in the Proxy listeners panel:
  :149  setText("Regenerate CA certificate")
  :198  confirm text: "Are you sure you want to regenerate Burp's CA
        certificate?\nTo take effect, you will need to restart Burp, and then
        install the new certificate in your browser."
  :141  the sibling "Import / export CA certificate" button
  :132  the panel's explanation of why both exist

## burpsy-side evidence

Import EXISTS:
  internal/web/api_ca.go:89        handleCAImport
  internal/web/server.go:722       /api/proxy/ca/import
  lib/data.policy.ts:110-113       useImportCaCert
  pages/settings.tsx:1533-1619     CaImportSection ("Use your own CA")
Export EXISTS:
  /ca.crt, with pages/settings.tsx:1621-1663 CertificateSection and the sidebar
  download at app.tsx:453-457.

Regenerate does NOT:
`grep -rniE "regenerat" --include=*.go --include=*.tsx internal/` returns 6 hits,
none of them a CA action -- internal/crawler/destructive.go:128 (a word list),
internal/intruder/engine.go:17,217 and payload.go:148 (payload replay),
internal/scanner/catalog.go:9 (codegen), and internal/proxy/proxy.go:288, which
is a doc comment reading "A regenerated CA would invalidate any trust-store..."
with no caller. Per the count rule: that is one comment and zero implementations.

Positive control, same grep style and same directories: the import path above is
found by `grep -rn "ImportCaCert\|ca/import"` across the same trees.

## Classification

CAPABILITY GAP.

## What an operator cannot do

Rotate the CA. A CA whose private key may have been exposed, or one that was
installed into a client's trust store during an engagement that has now ended,
cannot be replaced from the console. The nearest workaround is to generate a CA
pair out-of-band with openssl and import it -- which works (CaImportSection
validates the pair and discards previously issued per-host certificates,
settings.tsx:1611-1615) but requires leaving the tool.

## Note

The import path already does everything the hard part of this needs -- validate,
swap, invalidate the per-host cache, keep /ca.crt serving whichever CA is in
force (server.go:125). Regenerate is that same swap with a self-generated pair
instead of a pasted one, so it is small. It must reuse the import path's
invalidation rather than adding a second one.


### Acceptance Criteria

A new CA can be generated from the console; it reuses the import path's validation and per-host certificate invalidation; /ca.crt then serves the new CA and the UI states that clients must re-trust it.

---

## [burpsy-react-ui-js1] ui: no 'URL-encode as you type' mode in the message editor

**Beads ID:** `burpsy-react-ui-js1`
**Priority:** P3
**Labels:** editor, p3, ui

### Description

## Claim
There is no "URL-encode as you type" mode in the message editor. Burp offers it as a toggle so that special characters typed into a request are encoded automatically.

## Burp-side evidence
- `tools/context-menu.html` (bundled docs), universal menu options: **URL-encode as you type** — *"Automatically URL-encodes special characters as you type"*.

## burpsy-side evidence
- The editor's keydown handler encodes only an existing selection on an explicit chord: `ui/editor.tsx:149-170` `burpEditorKeys` requires `ctrlKey || metaKey` (`:152`) and returns false unless a non-empty selection exists (`:165`). Nothing acts on ordinary typing.
- No such mode anywhere: `grep -rn -i 'as you type' --include=*.tsx --include=*.ts burpsy-go/internal/web/ui/src/` -> no hits. Positive control on the same file: `grep -c urlEncodeKeyChars ui/editor.tsx` -> 2 (`:15` import, `:144` in `PAIRS`), so the helper this mode would reuse is present.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Type a payload containing `&`, `=`, `#` or a space into a URL-encoded parameter and have it encoded as they go. They type it raw and then remember to select it and press the encode chord — and a forgotten encode silently changes the request's parameter structure rather than testing the value.


### Acceptance Criteria

The message editor offers a persisted per-editor toggle that URL-encodes special characters as they are typed, reusing the existing urlEncodeKeyChars helper.

---

## [burpsy-react-ui-js5y] ui: no 'Show response in browser' and no 'Request in browser (original/current session)' for access-control testing

**Beads ID:** `burpsy-react-ui-js5y`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/message-editor/index.html — "Show response in browser" (Burp serves a unique URL with the exact selected response, so relative links resolve) and "Request in browser" with sub-options "In original session" (exact original Cookie header) and "In current browser session" (browser's cookies) — the standard access-control test.

## burpsy-side evidence
lib/actions.ts:485,290-296 has only "Open URL in browser" which navigates the operator's browser to the URL (captured only if that browser proxies through burpsy) — it does not serve the captured response, and offers no original-session vs current-session re-issue. The access-control-testing workflow is absent.


---

## [burpsy-react-ui-k3a7] ui: no 'Compare site maps' action — Comparer works only on two message/text items

**Beads ID:** `burpsy-react-ui-k3a7`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/context-menu.html — "Compare site maps — Compares site maps, helping you to find access control vulnerabilities and identify areas to inspect manually."

## burpsy-side evidence
The Comparer works only on two message/text items (pages/comparer.tsx); there is no "Compare site maps" action anywhere (no site-map diff over two crawls/sessions). The access-control site-map comparison workflow is absent.


---

## [burpsy-react-ui-ku62] decoder: no Octal or Binary encode/decode function — 2 of Burp's 8 codecs are absent

**Beads ID:** `burpsy-react-ui-ku62`
**Priority:** P3
**Labels:** burp-parity, capability-gap, decoder

### Description

## Burp-side evidence
tools/decoder.html: "The following decode and encode functions are available: URL. HTML. Base64. ASCII hex. Hex. Octal. Binary. GZIP." Burp Decoder offers Octal and Binary as first-class encode/decode functions.

## burpsy-side evidence
burpsy-go/internal/web/ui/src/lib/data.workbench.ts:52 `DECODE_LAYERS = ["url","html","base64","base64url","hex","gzip","deflate","jwt","ascii"]` and :66 `ENCODE_ENCODINGS = ["url","html","base64","base64url","hex","gzip","deflate","ascii","rot13"]`. Neither list contains octal or binary; the server has "no passthrough branch, so ... encoding ... is a 400" for anything else (comment at :55-58). So Octal and Binary transforms cannot be performed at all.


---

## [burpsy-react-ui-l7xj] ui: convert-selection on a read-only message shows no result dialog (Burp shows the conversion in a dialog)

**Beads ID:** `burpsy-react-ui-l7xj`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/message-editor/index.html — Convert selection: "If the message is editable, then the conversion is performed in-place ... If the message is not editable, then the result of the conversion is shown in a dialog."

## burpsy-side evidence
ui/editor.tsx:339-342 runTransform always calls transformSelection, which dispatches a doc change into the CodeMirror view. On a read-only message (history detail, ui/editor.tsx readOnly) there is no result dialog — the Convert-selection submenu is still shown (selectionGroups is gated only on active==="raw", 344-345) but produces no viewable conversion result.


---

## [burpsy-react-ui-ldfk] organizer: no originating-Tool column and no filter-by-tool

**Beads ID:** `burpsy-react-ui-ldfk`
**Priority:** P3
**Labels:** burp-parity, capability-gap, organizer

### Description

## Burp-side evidence
tools/organizer/index.html: columns include "Tool - The Burp tool that originally generated the request. This always reflects the request's origin, even if the message is later sent from Burp Logger or from within Organizer." tools/organizer/filter.html: "Filter by tool - Show or hide items that were sent to Organizer from different tools."

## burpsy-side evidence
burpsy-go/internal/web/ui/src/lib/types.ts:430-450 `OrganizerItem` carries exchange/host/port/method/path/status/mime/in_scope but has NO `tool`/origin field. The table headers at pages/organizer.tsx:482 are `["#","Exchange","Request","Status","Type","Title","Highlight","Note",""]` — no Tool column — and the filter controls (organizer.tsx: inScopeOnly/statusClass/mimeFilter) have no filter-by-tool axis.


---

## [burpsy-react-ui-luu3] ui: Inspector selection has no code-point (decimal/hex) view — cannot edit a char's code point to insert a non-printing byte

**Beads ID:** `burpsy-react-ui-luu3`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/message-editor/index.html — "To view the code point for a character, select a character ... An entry will appear in the Inspector that indicates the decimal and hex code points for the character. In editable contexts ... you can edit this value to overwrite the selected character. Insert a non-printing character ... by editing the code point of an existing byte using the Inspector."

## burpsy-side evidence
ui/inspector.tsx Selection section applies codecs (CODECS: url/html/base64, 87-93) and writes the transformed text back, but never shows the decimal/hex code point of a selected character, and offers no way to edit a code point to insert a non-printing byte (grep: no code-point/decimal display in inspector.tsx).


---

## [burpsy-react-ui-mem3] ui: table columns cannot be reordered by drag (no columnOrder in VirtualTable)

**Beads ID:** `burpsy-react-ui-mem3`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
burps-layout/customize-tables.html — "Move columns - Drag and drop the column header to a new location." Applies across Burp's tables.

## burpsy-side evidence
ui/table.tsx VirtualTable supports sorting and visibility but has no columnOrder state and no drag-and-drop reorder handler (no `columnOrder` anywhere in ui/table.tsx). No burpsy table lets the operator reorder columns.


---

## [burpsy-react-ui-mr4p] history: no IP column (destination server IP address)

**Beads ID:** `burpsy-react-ui-mr4p`
**Priority:** P3
**Labels:** burp-parity, capability-gap, history

### Description

## Burp-side evidence
tools/proxy/http-history/index.html — "IP - The IP address of the destination server."

## burpsy-side evidence
pages/history.tsx:635-751 has no IP column; lib/types.ts Exchange (81+) carries no resolved-IP field. The destination IP is never captured or surfaced.


---

## [burpsy-react-ui-mwq] ui: Comparer has no word-level diff mode

**Beads ID:** `burpsy-react-ui-mwq`
**Priority:** P3
**Labels:** comparer, p3, ui

### Description

Audit gap #50 (PlumOtter parity audit 2026-08-27). comparer.tsx is byte-level aligned only (lines 268-277: 'There is no word-level mode, and none is offered rather than a control that silently did the same thing'). Burp's Comparer offers word-level. Verified: handler reads two flat strings, no granularity param.

---

## [burpsy-react-ui-n29] session: no session-handling tracer — nothing shows which rules and actions ran on a request

**Beads ID:** `burpsy-react-ui-n29`
**Priority:** P3
**Labels:** burp-parity, capability-gap, observability, parity, session

### Description

## Claim
There is no session-handling tracer: nothing shows which rules and actions were applied to a request, or how the request changed at each step.

## Burp-side evidence
`settings/sessions/index.html`, "Session handling tracer":
> "The session handling tracer can help you when troubleshooting your session handling configuration. To view the tracer, click Open sessions tracer.
> The tracer shows a listing of every request that has been handled by the session handling functionality (that is, those requests where at least one session rule has been applied). For each request handled, the tracer shows **the sequence of rules and actions that were carried out. It also shows the changes made to the current request at each step in the sequence.** This information can help you to see whether your current rule configuration is achieving the required results."

Burp also states its cost, which is a design input here: "The session handling tracer imposes a processing and storage overhead on all affected HTTP requests. We recommend that you only use the tracer when troubleshooting issues with session handling rules." — i.e. it is opt-in, not always-on.

## burpsy-side evidence
Nothing records per-request rule application. `Coordinator.MatchingRule(host)` (`internal/session/session.go:942`) returns a rule and keeps no trace; `RunMacro` (`internal/session/session.go:1029`) returns the steps sent, the per-step results and a validity state to its caller but stores no history.

Extraction outcomes *are* logged, to the zap logger rather than to a readable surface — `Coordinator.logExtraction` (`internal/session/session.go:977`). That is diagnostics for whoever has the process log, not a tracer for the operator.

The only per-run feedback on the page is the single most recent "Run login now" result — `internal/web/ui/src/pages/session.tsx:566-587` builds `loginRows` from `loginResult`, and `:424` holds exactly one:
```ts
const [loginResult, setLoginResult] = useState<SessionLoginResponse | null>(null);
```
It covers one deliberately-triggered probe, reports outcome / rule / failed-step / validity (`pages/session.tsx:570-585`), and is replaced by the next run. It says nothing about the requests that flowed through the coordinator on their own.

Absence-grep with same-file positive control:
```
$ grep -rn "tracer\|Tracer" --include=*.go internal/session/ internal/web/
(no output)
$ grep -c "func " internal/session/session.go
43
$ grep -c "func " internal/web/api_session.go
24
```

## Classification
CAPABILITY GAP.

## Dependency
Most valuable after rules gain an action list (see the rule-actions issue) — tracing one hardcoded behaviour is worth much less than tracing an ordered sequence of actions, which is what makes a misconfiguration hard to see. Worth filing now because it is also the missing evidence trail for the cookie-jar and tools-scope issues: when a request unexpectedly carries or lacks a session, there is currently nothing to consult.

## What an operator cannot do
Debug a session rule that is not firing. There is no way to tell "the rule matched but the extraction found nothing" from "no rule matched this host" from "the rule fired and the target still rejected us", except by reading the process log.


### Acceptance Criteria

An opt-in tracer records, per request the coordinator handled, which rule matched and the sequence of steps taken with the change made to the request at each step, readable from the Session page. Off by default, with its overhead stated where it is enabled.

---

## [burpsy-react-ui-p5w2] ui: Match & Replace target dropdown lacks request_param_name / request_param_value (backend+API already accept them)

**Beads ID:** `burpsy-react-ui-p5w2`
**Priority:** P3

### Description

Follow-up from the closed backend bead burpsy-react-ui-l4h. The Go engine declares TargetRequestParamName/Value (internal/matchreplace/matchreplace.go:22-23) and the API round-trips them as request_param_name / request_param_value (internal/web/api_toolkit.go matchReplaceTargetName, with an api_toolkit_test.go round-trip assertion over every declared target). The React UI cannot select them: internal/web/ui/src/pages/matchreplace.tsx:19-27 (TARGETS) and internal/web/ui/src/lib/types.policy.ts:17-24 (MatchReplaceTarget union) omit both values. Fix is a two-line-per-value dropdown + union edit adding 'Request parameter name' and 'Request parameter value', then one manual check that a param rule survives the settings round trip.

---

## [burpsy-react-ui-p836] ui: no character-set control for message body display (auto / platform default / raw bytes / specific charset)

**Beads ID:** `burpsy-react-ui-p836`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
settings/ui/message-editor.html — Character sets: "Recognize automatically based on message headers", "Use the platform default" (UTF-8), "Display as raw bytes (ASCII)", "Use a specific character set". "The charset encoding options only apply to the message body."

## burpsy-side evidence
ui/editor.tsx renders the server-provided text as-is (TextEncoder for the byte count, 273) with no charset control; there is no way to reinterpret a body in a different character set or as raw bytes. A response in a non-UTF-8 charset cannot be viewed correctly.


---

## [burpsy-react-ui-qpl] sequencer: no Auto-analyze — the battery is never re-run periodically during a live capture

**Beads ID:** `burpsy-react-ui-qpl`
**Priority:** P3
**Labels:** burp-parity, capability-gap, sequencer

### Description

## Burp-side evidence
tools/sequencer/sample/live-capture.html — "Auto-analyze - Perform automatic analysis periodically during the live capture." Burp re-runs the randomness battery at intervals while capturing so the verdict converges live.

## burpsy-side evidence
pages/sequencer.tsx:311-371 — capture and analysis are strictly separate steps: the operator must click Analyse after (or attach and then click) — nothing re-analyses periodically during a running capture. No auto-analyze toggle exists in the capture panel (pages/sequencer.tsx:480-525).


---

## [burpsy-react-ui-r6li] history: no Delete items or Clear — capture rows cannot be removed from the UI (history is GET-only)

**Beads ID:** `burpsy-react-ui-r6li`
**Priority:** P3
**Labels:** burp-parity, capability-gap, history

### Description

## Burp-side evidence
tools/context-menu.html: "Delete items - Deletes the selected items from Burp" and "Clear (tool) - Removes all items from the open tool." Standard across Burp tables including HTTP history.

## burpsy-side evidence
history.tsx has no delete/clear action anywhere (the only "DELETE" token is in the METHODS filter list, line 40). server.go:714 registers "/api/history" -> handleHistory as the only history route and it is GET-only (history_source_filter_test.go:31 issues MethodGet); there is no delete-exchange endpoint. An operator cannot remove noise rows or clear the capture from the UI. (Distinct from site-map read-only burpsy-react-ui-10e.)


---

## [burpsy-react-ui-rcs] sequencer: no 'ignore tokens whose length deviates by X characters' capture filter

**Beads ID:** `burpsy-react-ui-rcs`
**Priority:** P3
**Labels:** burp-parity, capability-gap, sequencer

### Description

## Burp-side evidence
settings/tools/sequencer.html — Live capture: "Ignore token whose length deviates by X characters - Enable this setting to ignore tokens that deviate by a specified number of characters from the average token length. This setting is useful if the application occasionally returns a different item in the location where a token normally appears."

## burpsy-side evidence
No length-deviation filter exists. burpsy-go/internal/web/api_sequencer_capture.go keeps every extracted string as a token (missCount only records extraction failures, not length outliers); pages/sequencer.tsx has no such setting. A stray wrong-length item in the token location silently pollutes the sample instead of being dropped.


---

## [burpsy-react-ui-rfgs] match & replace: no 'Only apply to in-scope items' toggle, and per-rule scope is dropped on save

**Beads ID:** `burpsy-react-ui-rfgs`
**Priority:** P3
**Labels:** burp-parity, capability-gap, match-replace

### Description

## Burp-side evidence
tools/proxy/match-and-replace/index.html — "To only apply match and replace rules to items that are in the project scope, select Only apply to in-scope items." Per-rule scope is also supported.

## burpsy-side evidence
pages/matchreplace.tsx has no "Only apply to in-scope items" control anywhere; rules run on every proxied message (header, 215). Worse, the page's own notice (389-396) states the rule endpoint does not persist a rule's scope or query, so any per-rule scope is dropped on save. Match/replace cannot be limited to in-scope traffic.


---

## [burpsy-react-ui-ruw] ui: Match & Replace original/auto-modified message preview absent

**Beads ID:** `burpsy-react-ui-ruw`
**Priority:** P3
**Labels:** matchreplace, p3, ui

### Description

Audit gap #44/#45 (PlumOtter parity audit 2026-08-27). matchreplace.tsx has inline edit of match/replace/comment and move/duplicate/delete, but no side-by-side 'original message' vs 'auto-modified' preview per rule. Verified absent: grep preview|original message|auto-modified in matchreplace.tsx returns no matches.

---

## [burpsy-react-ui-sel6] settings.network: platform authentication supports only Basic and Digest — NTLMv1, NTLMv2 and Negotiate are absent, so NTLM/Kerberos-protected targets cannot be authenticated to

**Beads ID:** `burpsy-react-ui-sel6`
**Priority:** P3
**Labels:** burp-parity, capability-gap, decision-needed, settings

### Description

## Burp-side evidence
Burp Settings → Network → Connections → Platform authentication supports schemes Basic, NTLMv1, NTLMv2, Negotiate and Digest (settings/network — "Platform authentication ... Type: Basic / NTLMv1 / NTLMv2 / Negotiate / Digest"). NTLM/Negotiate are needed for Windows-integrated and Kerberos-protected targets, a common enterprise case.

## burpsy-side evidence
internal/web/ui/src/pages/settings.network.tsx:106-107,119-129 offers only Basic and Digest and states outright that "NTLM needs the per-connection affinity the sender does not offer, and Negotiate needs a Kerberos credential rather than a password", so both are unavailable. A target behind NTLM/Negotiate cannot be authenticated to, and requests go out unauthenticated.

[DECISION] Adding NTLM/NTLMv2/Negotiate needs a sender/architecture change (per-connection auth affinity, Kerberos credential handling) — a product/architecture call.


---

## [burpsy-react-ui-sn3j] session: cookie-jar monitored-tool set is hardcoded to Proxy — cannot monitor Repeater/Intruder/Scanner/etc

**Beads ID:** `burpsy-react-ui-sn3j`
**Priority:** P3
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/index.html — "By default, the cookie jar is updated based on traffic from the Proxy. However, you can configure the cookie jar to monitor any of the following tools to update cookies: Proxy, Intruder, Scanner, Sequencer, Repeater, Extensions."

## burpsy-side evidence
burpsy-go/internal/session/absorb.go:127 — "makes the monitored-tool set configurable with Proxy on by default; this build has one absorbing" tool. The monitored-tool set is hardcoded (Proxy only) and pages/session.tsx exposes no control to add Repeater/Intruder/Scanner/etc.


---

## [burpsy-react-ui-t94i] ui: message-editor tabs cannot be shown/hidden/reordered and Headers/Cookies/Attributes/Body-params tabs cannot be added

**Beads ID:** `burpsy-react-ui-t94i`
**Priority:** P3
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/message-editor/index.html — "By default, the Pretty, Raw, Hex, and Render tabs are displayed, but you can remove or reorder the tabs, and add some extra ones from the settings menu." Extra tabs: Headers, Query params, Body params, Cookies, Attributes. settings/ui/message-editor.html: Show + Wrap text per view, reorder with Up/Down.

## burpsy-side evidence
ui/editor.tsx:289-299 computes `available` tabs from fixed logic (Pretty/Raw/Hex/Render/GraphQL/JWT/Params); order is hardcoded and there is no settings menu to show/hide/reorder tabs or to add Headers/Cookies/Attributes/Body-params tabs.


---

## [burpsy-react-ui-tirx] intruder: no redirection handling — the attack never follows a 3xx and there is no Follow-redirections setting, so a result only visible after a redirect is missed

**Beads ID:** `burpsy-react-ui-tirx`
**Priority:** P3
**Labels:** burp-parity, capability-gap, decision-needed, intruder

### Description

## Burp-side evidence
tools/intruder/configure-attack/settings.html (Redirections) — Intruder attack settings include "Follow redirections" (Never / On-site only / In-scope only / Always) and "Process cookies in redirections", so an attack can chase a 3xx to the page that actually carries the result.

## burpsy-side evidence
internal/intruder/intruder.go:27-31 states the engine "does not follow redirects at all" and that the redirect config field was deliberately removed. internal/web/ui/src/pages/intruder.tsx exposes no redirect setting. A login/brute-force attack whose success is only observable after a 302 sees only the 302.

[DECISION] burpsy removed redirect-following on purpose for scope-safety (per-hop re-authorisation through the scope chokepoint). Reaching Burp parity needs a product/architecture call on whether to reintroduce scoped redirect-following.


---

## [burpsy-react-ui-ts3v] sequencer: Manual load has no load-from-file — a token sample can only be pasted, not read from disk

**Beads ID:** `burpsy-react-ui-ts3v`
**Priority:** P3
**Labels:** burp-parity, capability-gap, sequencer

### Description

## Burp-side evidence
tools/sequencer/sample/index.html: "Manually loading tokens ... To paste tokens from the clipboard, click Paste. To load tokens from a file, click Load." Burp's Manual load offers both Paste and Load-from-file.

## burpsy-side evidence
sequencer.tsx:410-420 the "Paste a list" tab is a single HttpEditor bound to a textarea (tokens state); there is no file-load control. An operator with a token sample already on disk (from an earlier capture or an Intruder run) must open and copy-paste the file by hand — Burp's Load button reads it directly. Mirrors the file-source gap noted for Intruder payloads (burpsy-react-ui-016).


---

## [burpsy-react-ui-ufn] comparer: no hex view of the compared items

**Beads ID:** `burpsy-react-ui-ufn`
**Priority:** P3
**Labels:** burp-parity, capability-gap, comparer, parity, ui

### Description

## Claim
The Comparer has no hex view of the compared items, though the Decoder on the same build has one.

## Burp-side evidence
`tools/comparer.html`, "Results" — the controls in the results window:
> "There are various controls in the results window that help you to analyze the results:
> Sync views - Select this setting to scroll the two panels simultaneously.
> **Text** - View both items in text form.
> **Hex** - View both items in hex form."

## burpsy-side evidence
No view toggle on the page. The panes render text spans directly — `internal/web/ui/src/pages/comparer.tsx:95-108` (`Pane`, emitting `<span>` per segment), and the header actions are Swap and Compare only (`pages/comparer.tsx:253-265`).

The page's own badge asserts the granularity but not a view mode — `pages/comparer.tsx:255`: `<Badge>byte-level</Badge>`.

For contrast, the machinery exists one page over: the Decoder has a Text/Hex toggle (`internal/web/ui/src/pages/decoder.tsx:276-293`) backed by a local `hexDump` (`pages/decoder.tsx:39-55`) with a `MAX_HEX_BYTES` cap (`:37`) and a documented reason for the cap (`:33-36`).

## Why it matters on this page specifically
The diff is byte-level and its ops carry byte offsets — `byteSlice` at `pages/comparer.tsx:13-16` slices through a `TextEncoder` view precisely because "Ops carry byte offsets, so slicing has to go through the same byte view the server used". A byte-level diff whose only rendering is text is hard to read exactly where it matters: a difference in whitespace, a stray CR, a NUL, or a non-UTF-8 byte shows as nothing or as a replacement character. The padding glyph the panes use for alignment (`GAP_CHAR = "·"`, `:34`) is itself indistinguishable from a real middot in the data.

## Classification
CAPABILITY GAP.

## What an operator cannot do
Identify a whitespace-only or non-printable-byte difference between two responses — which on a byte-level comparer is the class of difference the tool is best placed to find.


### Acceptance Criteria

The Comparer offers a Text/Hex toggle that renders both panes as aligned hex with the diff highlighting preserved, so a whitespace-only or non-printable-byte difference is visible. Reuses the Decoder's dump approach including its size cap.

---

## [burpsy-react-ui-uxi] ui: Dashboard telemetry (task throughput / bytes / requests) absent

**Beads ID:** `burpsy-react-ui-uxi`
**Priority:** P3
**Labels:** dashboard, p3, ui

### Description

Audit gap #34 (PlumOtter parity audit 2026-08-27). dashboard.tsx has a live task-progress bar and task table but no telemetry view (requests/sec, bytes transferred, task throughput over time) that Burp's dashboard shows. Verified absent: grep telemetry|listener in dashboard.tsx returns no matches.

---

## [burpsy-react-ui-v8q] collaborator: mints one payload per click, with no batch generation and no id-only form

**Beads ID:** `burpsy-react-ui-v8q`
**Priority:** P3
**Labels:** burp-parity, capability-gap, collaborator, parity, ui

### Description

## Claim
The Collaborator mints one payload per click with no way to generate several at once and no control over whether the server location is included.

## Burp-side evidence
`tools/collaborator/index.html`, "Generating payloads":
> "You can also generate multiple payloads at once in the Collaborator tab:
> Enter the number of Collaborator payloads that you want to generate in the **Payloads to generate** field.
> To include the full Collaborator server address in your payloads, select **Include Collaborator server location**. If this is not selected, only the Collaborator ID is included in your payloads.
> Click **Copy to clipboard** to copy the specified number of payloads.
> To access the payloads, paste them into a document."

`BURP_SUITE_UI_UX_SPECIFICATION.md` §4.7 lists a "Generate Payload" button as a Collaborator control.

## burpsy-side evidence
One mint per click, straight to the clipboard — `internal/web/ui/src/pages/collaborator.tsx:144-158`:
```tsx
<Button size="small" disabled={!s.configured || mint.isPending}
  onClick={() => mint.mutate(undefined, {
    onSuccess: (payload) => {
      void copyToClipboard(payload.address);
      toast.success(`Payload ${payload.address} copied`);
    },
```
The mutation takes no argument (`mint.mutate(undefined, …)`), so there is no count parameter on the wire, and the button is labelled "Copy payload" (`:157`) — singular by construction.

There is no bare-id form. The response field consumed is `payload.address` (`:150`), the full address; nothing renders or copies an id-only variant.

Minted payloads are counted but not listed for the interaction channel — the status card shows `s.payloads.length` as a metric (`pages/collaborator.tsx:180`) with no table. (The blind-XSS section below it *does* list its payloads with per-row copy, `pages/collaborator.tsx:228-251` — so the pattern to follow already exists on the same page.)

## Classification
CAPABILITY GAP.

## Sizing note
Smaller than it looks: the blind-XSS payload table on the same page (`pages/collaborator.tsx:228-251`) is the shape needed, and the mint endpoint would take a count. "Include server location" needs a decision on whether an id-only payload is meaningful for an interactsh-backed channel — with interactsh the correlation id is embedded in the subdomain, so an id without the domain may not be a usable payload here. If it is not, decline that half explicitly rather than shipping a toggle that changes nothing.

## What an operator cannot do
Prepare a batch of addresses before a test run — one per injection point across a form — without clicking mint and pasting once per payload, and without a list of what was minted to correlate against later.


### Acceptance Criteria

The operator can mint N payloads in one action and copy them all, and minted payloads for the interaction channel are listed with per-row copy as the blind-XSS section already does. Whether an id-only payload is meaningful for an interactsh channel is decided and, if not, declined in writing rather than shipped as a toggle.

---

## [burpsy-react-ui-vhs0] sequencer: live capture capped at 5000 tokens, below Burp's 20,000 FIPS-compliance maximum

**Beads ID:** `burpsy-react-ui-vhs0`
**Priority:** P3
**Labels:** burp-parity, capability-gap, sequencer

### Description

## Burp-side evidence
tools/sequencer/sample/index.html — "Sequencer supports a maximum sample size of 20,000 tokens, for compliance with the FIPS standards."

## burpsy-side evidence
burpsy-go/internal/web/api_sequencer_capture.go:361-364 — `const maxCaptureCount = 5000` hard-caps a live capture at 5000 tokens, well below the 20,000 the FIPS standard requires for a compliant result. The page presents FIPS 140-2 results (pages/sequencer.tsx:72-118) but can never gather a formally FIPS-compliant sample via live capture.


---

## [burpsy-react-ui-voc] dashboard: event feed has no clear action and is capped at 12 rows

**Beads ID:** `burpsy-react-ui-voc`
**Priority:** P3
**Labels:** dashboard, ui

### Description

## Claim

The Dashboard's event feed has no clear action and is hard-capped at 12 rows with no way to see more.

## burpsy side

`pages/dashboard.tsx:436-454` — the "Tool events" card renders
`data.events.slice(0, 12)` (`:440`). The 12 is a literal; there is no paging, no "show all", and no
link to a fuller view.

Absence grep: `grep -rniE "clear.*event log|events/clear" internal/web/*.go internal/dash/*.go
internal/web/ui/src/` -> no match. Positive control on the same tree:
`grep -rn "Tool events" internal/web/ui/src/` -> `pages/dashboard.tsx:437`.

## Burp side

`map_root.tsv` class `burp.Zbuz` — `Clear event log`, and `burp.Zr_h` — `No event log items to show`,
`dashboardEventLogEmptyState`, plus the empty-state copy *"The event log shows key task events, such as
start times, alerts, and progress updates."* Burp's is a scrollable table with a clear action, not a
fixed-height digest.

## Classification

CAPABILITY GAP (polish).

## What an operator cannot do

Read the 13th event, or reset the feed after resolving a burst of errors so that the next one is
visible.


### Acceptance Criteria

The Dashboard event feed is scrollable or paged past 12 entries and offers a clear action.

---

## [burpsy-react-ui-whr] ui: no hide-headers toggle in the message editor (and Settings' 'Uninteresting headers' is a different feature that hides nothing)

**Beads ID:** `burpsy-react-ui-whr`
**Priority:** P3
**Labels:** editor, p3, settings, ui

### Description

## Claim
There is no way to hide uninteresting HTTP headers while reading a message. Burp has an eye button above each message driven by editable Hide request headers / Hide response headers lists. burpsy's similarly-named "Uninteresting headers" setting is a Comparer diffing weight and hides nothing — its own copy says so.

## Burp-side evidence
- `tools/message-editor/text-editor.html` (bundled docs), Hide headers: *"In the Pretty tab, you have the option to hide HTTP headers that typically don't offer much insight into the target application's behavior... Toggle whether these HTTP headers are visible using the eye button above each message. Burp hides the headers specified in the Hide request headers or Hide response headers list. You can edit these lists in the Settings dialog, under **User interface > Message editor**."*

## burpsy-side evidence
- No such control in the editor: the full toolbar is `ui/editor.tsx:323-344` (Wrap, Copy, Save). `grep -rn 'EyeOff\|<Eye' --include=*.tsx src/` -> no hits in `ui/editor.tsx`; the only "eye" string in the tree is an unrelated comment at `ui/inspector.tsx:144`. Positive control on editor.tsx: `grep -c import ui/editor.tsx` -> 14.
- The name collision is the trap: `pages/settings.tsx:1467-1530` "Uninteresting headers" is explicitly not this feature. Its section detail reads *"Differences in these headers are dimmed in: ..."* (`:1470-1472`) and its footnote states *"**Nothing is hidden.** A difference inside one of these headers is still reported and still rendered — dimmed, and counted separately"* (`:1524-1530`). It feeds Comparer, not the editor.

## Classification
CAPABILITY GAP. Flagging the naming separately: a migrating user reading the Settings tree will conclude the feature is present.

## What an operator cannot do
Reduce a 30-header response to the five that matter while reading it. Also worth a rename or a cross-reference note so "Uninteresting headers" is not mistaken for Burp's hide-headers lists.


### Acceptance Criteria

A toggle above each message hides the headers named in an editable request/response hide-list, and the existing Comparer 'Uninteresting headers' section is named or cross-referenced so the two are not confused.

---

## [burpsy-react-ui-wkkz] extender: no BApp Store and no Java/Python/Ruby (Montoya) extension model — plugins are local JSON-RPC executables only

**Beads ID:** `burpsy-react-ui-wkkz`
**Priority:** P3
**Labels:** burp-parity, capability-gap, decision-needed, extender

### Description

## Burp-side evidence
extend-burp/index.html + settings/extensions.html — Burp's extension model: BApp Store one-click install, Montoya API extensions in Java/Python (Jython)/Ruby (JRuby) with configurable environments, "Automatically reload extensions on startup", "Automatically update installed BApps on startup", and extension-generated settings panels.

## burpsy-side evidence
pages/extensions.tsx:23-31 documents the deliberate model: plugins are local executables the operator names on the command line, speaking JSON-RPC over stdin/stdout — there is explicitly no BApp Store, no Montoya/Java/Python/Ruby runtime, and no auto-reload / auto-update settings. A Burp user's entire BApp ecosystem and Montoya extensions cannot be loaded. [DECISION] architecture/licensing call.


---

## [burpsy-react-ui-wv5] ui: 'Change body encoding' only toggles chunked framing — no form-urlencoded / multipart / JSON conversion

**Beads ID:** `burpsy-react-ui-wv5`
**Priority:** P3
**Labels:** contextmenu, p3, ui

### Description

## Claim
The row menu's "Change body encoding" only toggles chunked transfer framing. Burp's item of that name converts a request body between form URL-encoding, multipart encoding and JSON — a different operation under the same label.

## Burp-side evidence
- `tools/context-menu.html` (bundled docs): **Change body encoding** — *"Change the encoding of any request body between **form URL-encoding, multipart encoding, and JSON**. You can also select Toggle body encoding to switch between the two most recently used encodings in the current Repeater tab."*

## burpsy-side evidence
- Menu entry: `lib/actions.ts:799` — `{ id: "body-encoding", label: "Change body encoding (chunked)", onSelect: () => void changeBodyEncoding(exchange) }`.
- Implementation is chunked framing only: `lib/actions.ts:729-749` `changeBodyEncoding` calls `isChunked(raw) ? dechunkBody(raw) : chunkBody(raw)`; `chunkBody` (`:539-549`) swaps `Content-Length` for `Transfer-Encoding: chunked`, `dechunkBody` (`:520-536`) reverses it.
- No form/multipart/JSON conversion exists: `grep -rn 'multipart' --include=*.ts lib/` -> no conversion helper (positive control: `grep -rn 'x-www-form-urlencoded' lib/message.ts` -> `:260`, which is a parameter-form *detector* used by the Inspector, not a body converter).

## Classification
CAPABILITY GAP for the conversion; the label is separately misleading since it already carries the Burp name for a different operation. The parenthetical `(chunked)` mitigates but does not remove the collision.

## What an operator cannot do
Re-encode a JSON body as form-urlencoded (or as multipart) to test whether the server accepts both — a routine content-type confusion / parser-differential probe. Chunked framing is a useful capability and should stay, under its own name.


### Acceptance Criteria

The row menu converts a request body between form URL-encoding, multipart and JSON (adjusting Content-Type and Content-Length), and the existing chunked-framing toggle is offered under its own distinct label.

---

## [burpsy-react-ui-yy2] comparer: only two overwritable slots — no item tables, so each send-to destroys a side

**Beads ID:** `burpsy-react-ui-yy2`
**Priority:** P3
**Labels:** burp-parity, capability-gap, comparer, parity, ui

### Description

## Claim
The Comparer holds only two overwritable slots — there are no item tables, so a new "Send to Comparer" destroys a side rather than adding to a list.

## Burp-side evidence
`tools/comparer.html`, "Carrying out comparisons":
> "Right-click each message and select Send to Comparer. You can send a message from anywhere in Burp. Go to the Comparer tab. **The messages are listed in the two item tables.** Select the two messages you want to compare."
> "Note: The two item tables each display a list of all the messages that you have sent to Comparer. You need to select an item from each table. To sort the contents of the table, click on any table header."

And the controls that manage those lists:
> "**Paste** - Add an item from the clipboard. **Load** - Add an item from a file. **Remove** - Delete the highlighted item. **Clear** - Delete all items in the list."

## burpsy-side evidence
Two scalar slots in component state — `internal/web/ui/src/pages/comparer.tsx:119-122`:
```ts
const [a, setA] = useState("");
const [b, setB] = useState("");
```
A hand-off overwrites — `pages/comparer.tsx:139-149`:
```ts
useEffect(() => {
  if (!slots.a) return;
  setA(slots.a);
  setComparerSlot("a", "");
}, [slots.a, setComparerSlot]);
```
The store carries one string per side (`sendToComparer(exchange, slot)` at `internal/web/ui/src/lib/actions.ts:193`, menu entries at `:368-369`), so the third send-to a slot replaces the first with no record that it existed.

The rendered surface per side is one editor plus a message-id Load — `pages/comparer.tsx:214-247`. There is no list, and no Remove or Clear.

`Load` exists in a different sense than Burp's: it fetches stored message bytes by numeric id (`loadSlot`, `pages/comparer.tsx:170-187`) rather than adding a file to a list.

## Classification
CAPABILITY GAP.

## Not the word-level issue
Distinct from `burpsy-react-ui-mwq` (Comparer has no word-level diff mode), which is the declined-and-disclosed granularity claim. This is about how many items the tool can hold.

## What an operator cannot do
Compare pairs out of a set. The Intruder use case Burp's own docs lead with — "compare large responses with different lengths that you have identified in an Intruder attack" — means sending five or six candidates over and trying pairs; here each send-to costs the operator whichever side they aimed at.


### Acceptance Criteria

Each side holds a list of items that send-to appends to, with per-item remove and a clear-all, and the comparison runs on the selected item from each list. Sending an exchange to a side no longer discards what was there.

---

## [burpsy-react-ui-adrh] decoder: transforms apply to the whole input only — no per-selection transform and no colour-coding of the applied encoding

**Beads ID:** `burpsy-react-ui-adrh`
**Priority:** P4
**Labels:** burp-parity, capability-gap, decoder

### Description

## Burp-side evidence
tools/decoder.html: "The transformation applies to the whole data set. To apply the transformation to only a portion of the data, select the relevant section before you choose an operation." and "The data is color-coded to indicate the type of encoding or decoding that is applied."

## burpsy-side evidence
burpsy-go/internal/web/ui/src/pages/decoder.tsx:646-659 the pipeline mutates `{ input, steps }` — the entire input string is transformed by each step; there is no way to select a substring and transform only that portion. Output is rendered as plain text/hex (decoder.tsx:600 `<div className="prose tool-output">`) with no per-byte colour-coding of which encoding was applied; only a "detected" layer-chain badge row (decoder.tsx:566-574) is shown.


---

## [burpsy-react-ui-amu] ui: no 'Add to site map' action — the site map is populated only by observed traffic

**Beads ID:** `burpsy-react-ui-amu`
**Priority:** P4
**Labels:** contextmenu, p4, sitemap, ui

### Description

## Claim
There is no "Add to site map" action. Burp lets you push a selected item onto the site map; in burpsy the site map is populated only by observed proxy traffic and crawls.

## Burp-side evidence
- `tools/context-menu.html` (bundled docs), universal menu options: **Add to site map** — *"Adds the selected items to the project scope"* [sic — the table's description column; the option name and its effect are the site map].

## burpsy-side evidence
- Absence grep over the whole UI tree: `grep -rli 'Add to site map' --include=*.tsx --include=*.ts burpsy-go/internal/web/ui/src/` -> **no files**. Same-tree positive control: `grep -rli 'Copy URL'` -> `pages/logger.tsx lib/actions.ts`.
- The shared row menu's organise and scope groups (`lib/actions.ts:811-827`) offer Add to Organizer, Filter history by host, Open URL in browser, Add host to scope, Audit exchange, and two crawl scopes — no site-map insert.

## Classification
CAPABILITY GAP, low frequency.

## What an operator cannot do
Put a URL they know about onto the site map without sending traffic to it. Note this interacts with the documented append-only store property (`lib/reference.ts:349-351`: *"the site map adds and never removes. A host on the map was observed at some point — that is not evidence it is reachable now."*) — an operator-inserted node would break that invariant's current meaning.

## Decision needed
Whether an operator-added node is acceptable at all given the disclosure above. If yes, it needs to be distinguishable from an observed node on the map, or the disclosure needs rewording. Worth answering before implementing.


### Acceptance Criteria

A decision is recorded on whether operator-inserted site-map nodes are allowed; if allowed, the row menu offers 'Add to site map' and inserted nodes are visually distinguishable from observed ones.

---

## [burpsy-react-ui-fkj] repeater: tab strip has no scrolling/wrapped view toggle, no drag-reorder, and individual (ungrouped) tabs cannot be colored

**Beads ID:** `burpsy-react-ui-fkj`
**Priority:** P4
**Labels:** ui

### Description

Three small tab-strip affordances Burp's Repeater has and burpsy's does not. Grouped here because
each alone is cosmetic; together they are the difference between a strip that scales to the dozens
of tabs a real engagement accumulates and one that does not.

## Burp-side evidence

`/root/burp-re/in/extract/resources/Documentation/burp/documentation/desktop/tools/repeater/managing-tabs.html`:

> **Switch tab view** - Use the tab view toggle in the top-right corner to choose from two different
> views: **Scrolling view** - a single, scrollable row ... [or a] drop-down list of open tabs ...
> **Wrapped view** - wrap tabs onto multiple rows.

`groups.html`: "Select a group color. The group's tabs are highlighted with this color on the tab
bar." Burp also lets tabs be dragged to reorder and dragged between groups.

## burpsy-side evidence (`internal/web/ui/src/pages/repeater.tsx`)

1. **No scrolling/wrapped view toggle.** `ungrouped.map(renderTabTrigger)` renders one flat
   `tabs-list` row; with many tabs it overflows with no scroll affordance and no overflow dropdown.
2. **No drag to reorder / drag into a group.** Order is fixed to `state.repeaterTabs`; moving a tab
   into a group is menu-only (`setRepeaterTabGroup`). There is no `draggable`/`onDrag*` anywhere in
   the page or a `moveRepeaterTab` reorder action in `store.ts`.
3. **Individual tabs cannot be colored.** Color lives on the *group* (`group.color`, the colored
   border); an ungrouped tab has no color. Burp colors per group too, but exposes it as a tab-bar
   highlight; a single ungrouped tab still cannot be marked.

## Not in scope of this issue

Per-tab *settings* (Burp's blue settings icon + "Restore global default") are already at parity:
the Config trigger shows an override count `Config (N)` and offers "Reset overrides"
(`SendOptionsPanel`). Rename (double-click) and duplicate are also present.


---

## [burpsy-react-ui-fmxv] intruder: attack settings absent — Set Connection: close header, denial-of-service mode, and store-full-payloads toggle are unavailable

**Beads ID:** `burpsy-react-ui-fmxv`
**Priority:** P4
**Labels:** burp-parity, capability-gap, intruder

### Description

## Burp-side evidence
tools/intruder/configure-attack/settings.html — attack settings include "Set Connection header" (add/update Connection: close), "Use denial-of-service mode" (issue request then close the TCP connection without processing the response), and "Store full payloads" (retain full payload values to allow modifying grep or resending at runtime).

## burpsy-side evidence
internal/web/ui/src/pages/intruder.tsx has only Grep match/extract on its Settings tab (intruder.tsx:1431-1485) and Max requests / concurrency / rps on the pool tab. None of Set Connection header, denial-of-service mode, or a store-full-payloads toggle exist in the UI or the /api/intruder/run body (intruder.tsx:759-807).


---

## [burpsy-react-ui-jcdm] history: Time is one total duration — no start/end response-timer (TTFB vs complete) split

**Beads ID:** `burpsy-react-ui-jcdm`
**Priority:** P4
**Labels:** burp-parity, capability-gap, history

### Description

## Burp-side evidence
tools/proxy/http-history/index.html — two distinct timing columns: "Start response timer - the time in ms from when the request was sent until the first byte of the response is received" and "End response timer - the time ... until the complete response was received."

## burpsy-side evidence
pages/history.tsx:737-742 renders a single "Time" column from duration_ms; Exchange (lib/types.ts) has only duration_ms. There is no time-to-first-byte vs time-to-complete distinction, so a slow-body response reads the same as a slow-to-respond one.


---

## [burpsy-react-ui-sf8o] wshistory: frame table has no Edited / TLS / Notes / Listener-port / WebSocket-ID columns

**Beads ID:** `burpsy-react-ui-sf8o`
**Priority:** P4
**Labels:** burp-parity, capability-gap, wshistory

### Description

## Burp-side evidence
tools/proxy/websockets-history/index.html — WebSockets history columns: #, URL, Direction, "Edited - Flag whether the message was modified by the user", Length, Notes, "TLS - Flag whether TLS is used", Time, "Listener port", "WebSocket ID - Burp's internal ID for the WebSocket".

## burpsy-side evidence
pages/wshistory.tsx:145-176 frame table columns are only #, Dir, Opcode, Length, Age. There is no Edited flag, no TLS column, no Notes column, no Listener-port column and no WebSocket-ID column; WsRow (lib/types.ts) carries none of these.


---

## [burpsy-react-ui-us12] session: cannot validate only after a set number of requests (no validation interval)

**Beads ID:** `burpsy-react-ui-us12`
**Priority:** P4
**Labels:** burp-parity, capability-gap, session

### Description

## Burp-side evidence
settings/sessions/session-handling-rules.html — Check session is valid: "Optionally, you can configure Burp to validate the session after a set number of requests. This helps you to avoid making unnecessary requests in cases where the application rarely invalidates your session."

## burpsy-side evidence
The session rule (pages/session.tsx, SessionRuleFull) has no "validate every N requests" throttle; validity is checked per the recovery flow with no interval control. There is no field for it in the rule editor.


---

## [burpsy-react-ui-wvcl] ui: no 'Show details in new window' — items are only shown in the page's own detail pane, no pop-up/detached windows

**Beads ID:** `burpsy-react-ui-wvcl`
**Priority:** P4
**Labels:** burp-parity, capability-gap, ui

### Description

## Burp-side evidence
tools/context-menu.html — "Show details in new window — Opens detailed information about the selected item in a new window." tools/proxy/http-history/index.html — "Double-click an item to open it in a pop-up window" and "Show new history window".

## burpsy-side evidence
burpsy has no detachable/pop-up detail windows; a selected item is only ever shown in the page's own detail pane (e.g. pages/history.tsx SplitPane detail). There is no "open in new window" action on any tool.


---
