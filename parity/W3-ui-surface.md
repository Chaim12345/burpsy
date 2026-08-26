# W3 — UI Surface Parity: Decorative Controls, Scanner Anomaly, Per-Tool Depth

**Analyst HEAD at read time:** `9194df6` (`fix(matchreplace): an unimplemented target must change nothing, not rewrite the body`) — one commit ahead of the task's stated baseline `a619c9a`. All source reads below are against `9194df6`.

**Worktree contention note:** during this run, other concurrent agents in the same shared `tsk_BGwVMYR` worktree added two docs-only commits (`ccd6d45`, `749ddbd`), moving HEAD to `749ddbd` by the time this report was written. Both sub-sweeps independently re-checked `git status`/`git log` mid-task and confirmed neither commit touches any file examined in this report (`internal/web/ui/src/**`, `internal/**/*.go`). Findings below are unaffected — this matches the "worktree contention" pattern already logged for this repo (multiple concurrent checkouts can share a worktree).

Method: three parallel read-only sweeps, each given a disjoint subset of `internal/web/ui/src/pages/*.tsx`, tracing every stateful control from its `useState`/form value → the request body built in `lib/api.ts`/`lib/actions.ts`/`lib/data*.ts` → the Go HTTP handler → whether the handler's logic actually consults that field. Classified WORKING / DECORATIVE / DISCLOSED LIMITATION per the calibration in the task brief (a disclosed limitation is copy the UI itself uses to admit a gap; a decorative control is an *undisclosed* promise the backend does not keep).

---

## 1. Decorative controls (ranked by damage)

### 1.1 CONFIRMED — Decoder "guess base64 / hex alphabets" checkbox is a no-op

- **Frontend:** `internal/web/ui/src/pages/decoder.tsx:104-109` renders a `Checkbox` labeled `"guess base64 / hex alphabets"`, bound to `step.guess`, shown only when a step is `kind === "decode"` and `value === "auto"` (i.e. "smart detect" mode). `internal/web/ui/src/lib/data.workbench.ts:120-134` serializes `step.guess` into the POST body as `guess_alphabets`.
- **Backend:** `internal/web/api_toolkit.go:938` unmarshals it into `req.Guess bool`; `:947` calls `smartDecode(dec, req.Input, req.Guess)`. **Verified independently** (I re-read the function myself, not just trusting the sub-agent): `smartDecode` at `internal/web/api_toolkit.go:1000-1024` takes `guess bool` as a parameter but **never references it in the function body** — the four fixed steps (base64, url, hex, html) run in the same fixed order regardless of the flag's value. `grep -rn "guess" internal/tools/*.go internal/web/api_toolkit.go` confirms no other consumer.
- **Verdict: DECORATIVE.** The checkbox makes an undisclosed promise (narrow smart-detection to base64/hex) the backend silently ignores. Nothing in `decoder.tsx` discloses this — contrast with e.g. `matchreplace.tsx`'s explicit "this build's rule endpoint does not persist either" notice. This is the **worst decorative control found**: it's a security/analysis-workflow toggle, in the same functional family (encode/decode step control) the task explicitly flagged as high-risk, and it fails silently with a 200 response and plausible-looking output.
- **Fix shape (not applied — read-only task):** either wire `guess` to actually gate which of the four decode layers `smartDecode` tries, or remove the checkbox and disclose that smart-detect always tries all four.

No other decorative controls were found across the full sweep (24 pages: intercept, proxysettings, settings.network, session, scope, history, wshistory, matchreplace, intruder, repeater, sequencer, comparer, collaborator, decoder, scanner, discover, sitemap, auditqueue, advisories, organizer, extensions, logger, dashboard, settings). Every other writable control traced to a Go handler that reads and acts on that exact field, or the UI explicitly labels the gap in its own copy.

### 1.2 Honestly-disclosed limitations (NOT decorative — reported separately per the task's calibration rule)

These are UI surfaces where the frontend itself tells the operator the control doesn't do what it might imply, matching the matchreplace.tsx precedent from the task brief:

| Page | Disclosure | Citation |
|---|---|---|
| matchreplace.tsx | "this build's rule endpoint does not persist either" for scope/query condition fields | `pages/matchreplace.tsx:365-372` |
| matchreplace.tsx | `TARGETS` dropdown only offers the 5 implemented targets; `request_param_name`/`request_param_value` (the ones with the now-fixed-but-still-unimplemented handling) are not even selectable | `pages/matchreplace.tsx:18-24` |
| settings.network.tsx | `presented_on_egress` badge live-computed from `sender.CarriesPlatformAuth()`/`CarriesClientCerts()`; warns when a stored rule won't actually be sent | `pages/settings.network.tsx` ↔ `internal/web/api_netauth.go:128,245` |
| dashboard.tsx | "Crawl and audit" / "API-only scan" cards are disabled with "not built yet" | `pages/dashboard.tsx:207-211,244-256` |
| extensions.tsx | Options/APIs tabs state there is no BApp Store; `registry: null` shown explicitly | `pages/extensions.tsx:524-534` |
| extensions.tsx | Registration table shows "needs a message" instead of a broken Run button for `editor-tab`/`context-menu` kinds | `pages/extensions.tsx:183-190` |
| settings.tsx | Resource pools "What each tool honours" table names per-tool bounds with *no effect* (e.g. crawl's sequential loop can't honor concurrency > 1) rather than pretending uniform enforcement | `pages/settings.tsx:1929-1962` |
| settings.tsx | Upstream proxy `wired`/`attached`/`persisted` badges tell the operator when a saved rule reaches nothing or won't survive restart | `pages/settings.tsx:1524-1553` |
| settings.tsx | DOM engine section is read-only by design, states why (race risk) | `pages/settings.tsx:485-508` |
| comparer.tsx | Explicit notice that the server only does byte-level diffing, no word/line granularity selector "rather than one that silently does the same thing" | `pages/comparer.tsx:254-259` |
| nav.ts / extensions.tsx | Extender has 3 of Burp's 4 sub-tabs; BApp Store omitted with inline comment explaining why (hosted catalogue, no counterpart) | `nav.ts:207-210` |
| repeater.tsx | "Process cookies in redirections" and an ALPN override are simply not offered as controls, by design, per comment | `pages/repeater.tsx:554-563` ↔ `internal/web/repeater_options.go:17-22` |

**Count: 1 decorative control proven, 12 honestly-disclosed limitations catalogued.** This codebase is unusually disciplined about disclosure — nearly every non-trivial control that doesn't fully work carries inline UI copy admitting it, which is why the sweep surfaced so few undisclosed violations despite covering ~24 pages and ~80+ distinct controls.

---

## 2. Scanner anomaly resolution

**Question:** Burp's `ToolRegistry` enum has `SCANNER`, but the W0/overlap analysis calls it Burp-only even though burpsy has `internal/scanner` and `pages/scanner.tsx`. What does that mean, and can a user actually reach scanning?

**Resolved, with correction to a prior analyst's framing:**

- `nav.ts:89` puts `scanner.tsx` as a **leaf inside the `target` tool**, labeled `"Issues"` — not as its own top-level nav tab. `pages/scanner.tsx:626` sets `PageHeader title="Issues"`, confirming the page identifies itself as an issues/findings viewer, not "Scanner."
- **Prior analyst's claim — "Scanner is folded into Target's Issues/Audit-queue leaves" — is CONFIRMED, with one refinement.** `scanner.tsx` is primarily a findings tree + advisory reader (`groupFindings`, tree pane, advisory pane at `scanner.tsx:213-621`), i.e. what Burp would call the Scanner tool's *output*. But it is not purely passive: it also contains a real scan-trigger control inside an "Audit settings" modal (`scanner.tsx:676-736`) — a **"Targeted audit"** button (runs configured checks against one exchange, wired to `POST /api/scanner/audit` → `handleScannerAudit`, `internal/web/api_scanner_audit.go:61`) and a **"Live active audit" toggle** (wired to `useSetScannerLive` → `handleScannerLive`, `internal/web/api_tools.go:810`). Both are genuinely functional (WORKING, verified both sides), not decorative.
- **What "no dedicated Scanner nav entry" actually means for a user:** there is no single place labeled "Scanner" where you configure and launch a broad scan the way Burp's SCANNER tool does. Instead, scan-*launching* is split across:
  - `dashboard.tsx`'s "New scan"/"New live task" modals (crawl+audit orchestration entry point),
  - Site map's Crawl button (`ui/crawl.tsx:33-45` → `internal/web/api_crawl.go:123-150,222-260`, a genuinely consumed limits struct),
  - and the narrower single-exchange "Targeted audit" / live-audit toggle buried in scanner.tsx's own settings modal.
  
  Scan *configuration* (which checks run, concurrency, timeouts) lives on `settings.tsx:556-671` (~20 audit-check-family switches, each traced to `internal/web/api_scanner_config.go` → `internal/scanner.ScanConfig` fields consulted by individual check files, e.g. `CheckHostDiscovery` at `checks_discovery.go:17`).
- **Reachability verdict:** Yes, a user can reach and drive scanning functionality — it is not absent — but it is **fragmented across three pages (Dashboard, Site map, Target→Issues) with no unifying "Scanner" surface**, which is a real UX/parity gap relative to Burp's single consolidated tool, distinct from the enum-naming technicality. The `SCANNER` "Burp-only" classification in the ToolRegistry overlap table is correct at the nav-tab level and should not be read as "scanning is unreachable" — it isn't.

### 2.1 Related: `/api/discovery` (ffuf sweep) reachability — confirmed unreachable, prior phrasing corrected

A previous analyst (see shared context `gap_engine_capabilities_report`) found `/api/discovery` routed with a real backend (`internal/web/api_discovery.go`) but zero frontend references — STATE 3 (UNREACHABLE). Re-verified directly: `grep -n -i "discovery"` across `pages/discover.tsx` and `lib/api.ts` returns **zero matches** in both files.

Correction to framing: `pages/discover.tsx` was never a candidate for calling `/api/discovery` — it is burpsy's replacement for Burp's "Learn" tab (in-app reference: query grammar, BCheck syntax, hotkeys, deliberate-gaps list), per its own doc comment (`discover.tsx:9-31`) and the `nav.ts:242-248` comment block. The name collision between `discover.tsx`/`DISCOVER` (Burp's renamed Learn tool) and `/api/discovery` (the ffuf-style endpoint) is coincidental. The underlying finding stands — no page anywhere references `/api/discovery` — but "discover.tsx doesn't call it" is the wrong way to state it, since discover.tsx isn't the content-discovery UI.

---

## 3. Per-tool sub-feature depth, 12 overlapping tools

Per W0's rule and the taxonomy's ban on a single aggregate percentage, these are reported per-tool, not averaged. burpsy-side counts are leaves in `nav.ts` (recounted directly from `TOOLS[]`, HEAD `9194df6`). Burp-side sub-tab/sub-panel counts are sourced from `/root/burp-re/BURP_SUITE_UI_UX_SPECIFICATION.md` §4 (a **prior analyst document — treated as a hypothesis, not ground truth**, per the taxonomy's rule that prior docs must be falsified, not cited); I spot-verified a subset of its claims directly against `/root/burp-re/out/strings/map_root.tsv` (raw extracted UI strings) where feasible — confirmed literal strings `"Site map"`, `"Scope settings"`-adjacent, `"BApp Store"`, `"Grep - Payloads"`, `"0 positions"` are genuinely present in Burp's shipped strings, supporting the spec doc's Target/Extender/Intruder sub-structure claims. I did **not** independently re-derive every count from raw class files given time constraints — flagged per-row below as VERIFIED (spot-checked against map_root.tsv) or UNVERIFIED (spec-doc only, not independently confirmed).

| Tool | Burp sub-tabs/panels (source: spec doc §4, provenance noted) | burpsy `nav.ts` leaves | Ratio | Note |
|---|---|---|---|---|
| Dashboard | 3 panels (Task Engine, Event Log, Issue Activity) — UNVERIFIED | 1 leaf | 1/3 by panel count | burpsy's single dashboard.tsx page internally renders multiple cards/panels (not counted here — leaf-count understates it; not independently re-verified) |
| Target | 2 sub-tabs (Site map, Scope settings) — VERIFIED strings present | 5 leaves (sitemap, scanner/"Issues", auditqueue, advisories, scope) | 5/2 | burpsy's Target is *structurally larger* than Burp's because it absorbed Scanner's audit-facing surfaces (Issues, Audit queue, Issue definitions) — see §2 above. Not an apples-to-apples ratio; the extra 3 leaves are Scanner-adjacent, not Target depth |
| Proxy | 4 sub-tabs (Intercept, HTTP history, WebSockets history, Proxy settings) — UNVERIFIED | 5 leaves (+ matchreplace) | 5/4 | Real Burp nests Match & Replace *inside* the Proxy settings tab as a rules table, not a peer tab; burpsy promotes it to a peer nav leaf. Depth is comparable, organization differs |
| Intruder | 4 sub-tabs (Target, Positions, Payloads, Options) — VERIFIED strings present ("Grep - Payloads", "0 positions") | 1 leaf | 1/4 by tab count | Misleading if read as "burpsy is 1/4 as deep": all four Burp sub-tab's *functions* (position selection, payload sets, payload processing rules, grep-match/extract, concurrency/rate limits) are confirmed WORKING within the single burpsy page (sweep-attacktools verified both sides for each). The gap is layout (tabs vs. single scrollable page), not missing function, with one exception: no attack-type-specific payload-encoding toggle equivalent was found beyond payload processing rules |
| Repeater | No formal sub-tabs; tab-manager for multiple concurrent request/response pairs (`secondarySuiteTabBar`) — UNVERIFIED | 1 leaf | Not comparable by leaf count | Not confirmed whether burpsy's single Repeater page supports multiple concurrent isolated tabs the way Burp's tab manager does — **NOT DETERMINED**, would need dedicated UI trace beyond this task's scope |
| Sequencer | No formal sub-tabs (single view: source selector, token location, capture bar, analysis panel) — UNVERIFIED | 1 leaf | 1/1 | Functional coverage confirmed WORKING (encoding, token location kind, count/delay, real cancellation) |
| Comparer | No formal sub-tabs; Words/Bytes diff-mode toggle | 1 leaf | 1/1 leaves, but Burp has 2 diff modes vs burpsy's 1 (byte-only) | Gap disclosed in-UI (§1.2) |
| Collaborator | No formal sub-tabs | 1 leaf | 1/1 | Confirmed WORKING controls (payload gen, poll, blind-XSS mint) with disclosed state-machine semantics |
| Logger | No formal sub-tabs (single unified table + filter bar) | 1 leaf | 1/1 | — |
| Organiser | No formal sub-tabs | 1 leaf | 1/1 | Confirmed WORKING (title/note/highlight, add-by-id, delete) |
| Extender | 4 sub-tabs (Extensions, BApp Store, Options, APIs) — VERIFIED "BApp Store" string present | 3 leaves (extensions, extenderoptions, extenderapis) | 3/4 | Missing sub-tab is BApp Store, explicitly disclosed as out of scope (hosted catalogue) — this is the cleanest, most honest ratio in the table |
| Discover | Not enumerated in spec doc §4 (no `4.x Discover/Learn` section; Burp's tool is likely "Learn," possibly renamed to Discover only in the `ToolRegistry` enum, not documented in this spec's tool-by-tool section) | 1 leaf | NOT DETERMINED | Burp-side depth for this tool could not be sourced from the documents available in this task; do not guess a ratio |

**No aggregate percentage is offered**, consistent with W0's explicit rejection of a single headline number (this repo has 5 prior false denominators).

---

## 4. Ungated manual observations (tsc, e2e)

Per shared context `verified_ci_gates`: CI gates only `gofmt`/`go build`/`go vet`/`go test`. Neither `bun run check` (tsc) nor `behaviour.spec.ts` (Playwright, 32 blocks) run in CI. Results below are **UNGATED MANUAL OBSERVATIONS**, not evidence of a CI-enforced guarantee.

- **`tsc --noEmit`** (via `bunx tsc --noEmit` after `bun install`, since `node_modules` was not present in this worktree — 130 packages, 4.86s install): **clean, zero errors**, at HEAD `9194df6`+docs-only commits. This is a positive finding, not a defect: the frontend typechecks cleanly even though nothing gates it.
- **Playwright `behaviour.spec.ts`**: **not run** in this task — it requires a live server + browser session and was out of scope for a read-only static-trace audit given the time budget. Its non-gated status per `verified_ci_gates` stands as previously verified; no new observation to add.

---

## Summary for `orch context`

1 decorative control PROVEN (Decoder "guess base64/hex alphabets" checkbox, `decoder.tsx:104` → `api_toolkit.go:1000-1024`, parameter never read), 12 honestly-disclosed limitations catalogued (not decorative), Scanner reachable-but-fragmented across Dashboard/Sitemap/Target confirmed (not absent). tsc clean (ungated). No aggregate depth percentage offered — see per-tool table.
