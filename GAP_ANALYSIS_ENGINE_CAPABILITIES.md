# Gap analysis: engine capabilities that exist but are not reachable

Scope: burpsy-go/internal/**, measured against committed HEAD in this worktree
(`ede8f1f`, branch `orchestry/tsk_cv1rqyw/gap-analysis-engine-capabilities-that-ex`,
working tree clean — `git status --short` returns nothing, so file:line citations
below are committed state, not working-tree state).

Method: for every candidate, (a) grep every non-test Go file for the package import,
(b) if imported by `internal/web/*`, read the handler to see whether it actually calls
the capability or reimplements it, (c) grep `internal/web/server.go` `setupRoutes` for
a registered route, (d) grep `internal/web/route_manifest_test.go` for a manifest entry,
(e) grep the React source (`internal/web/ui/src/**`) for a fetch call / hook / nav entry
that reaches the route. State-2/3 requires (e) to come back empty, or (a)/(b) to show
the engine code has zero non-test callers.

## Finding 1 — STATE 2 (IMPLEMENTED BUT NOT WIRED): word/byte Myers-diff engine in internal/tools/comparer.go

- `internal/tools/comparer.go:52` defines `GranularityWord` (and byte granularity), `comparer.go:99`
  `Diff(a, b, granularity)`, `comparer.go:109` `DiffWithBudget(...)` — a real Myers-diff
  implementation (`comparer.go:325` `myers`, `:362` `backtrack`) with word-vs-byte tokenization
  (`comparer.go:214` `newTokens`, `:268` `wordSpans`) and a budget that bounds cost on large bodies
  (`comparer.go:120` `budgetFor`).
- Repo-wide grep for the only ways to reach it — `Diff(`, `DiffWithBudget(`, `GranularityWord`,
  `GranularityByte` — outside `internal/tools/comparer.go` itself matches **only** its own test files:
  `internal/tools/comparer_test.go` and `internal/tools/comparer_budget_test.go`. Zero production
  callers anywhere in the tree.
- The web handler that should be the caller, `handleToolsCompare` at
  `internal/web/api_toolkit.go:1224`, does **not** import or call `comparer.Diff`/`DiffWithBudget`.
  Its own comment admits it: "The engine produces a byte-level comparison; this folds consecutive
  differences into equal/replace/insert/delete ops" (`api_toolkit.go:1224-1226`). It reimplements a
  separate, much weaker positional diff in `compareOps` (`api_toolkit.go:1259-1297`): a single
  forward scan that walks `a[i]`/`b[i]` in lockstep and calls everything from the first mismatch to
  `min(len(a), len(b))` one "replace" run — it does not realign after an insertion/deletion the way
  the Myers algorithm in comparer.go does, so a single inserted byte turns the entire remainder of a
  response into a "replace". This is a second, inferior implementation living beside the real one,
  not a case where the real one was deleted.
- `internal/web/server.go:795` registers `/api/tools/compare` → `handleToolsCompare`, and it is in
  the manifest at `internal/web/route_manifest_test.go:492`, so the *route* is reachable end to end.
  What is unreachable is the specific engine capability the task is asking about: word granularity
  and the budget-bounded Myers diff.
- Independent confirmation from the frontend side, which already noticed the gap and worked around
  it rather than exposing it: `internal/web/ui/src/pages/comparer.tsx:254-257` — "The handler reads
  two flat strings and has no granularity parameter, so ... This build compares bytes. The server
  exposes no word-level mode, so no granularity control is offered rather [than shown broken]" — and
  the same statement in `internal/web/ui/src/lib/data.workbench.ts:183`.
- Numerator/denominator: of the 2 granularities comparer.go implements (byte, word), 0 are exposed by
  `handleToolsCompare`; of comparer.go's 2 public entry points (`Diff`, `DiffWithBudget`), 0 have a
  non-test caller.
- Not determined: whether comparer.go was ever wired and regressed, or was written and never
  connected — no `git log -p` history search was done for this (out of scope for a HEAD-state
  measurement); stating "regression" vs "never wired" would be a guess.

## Finding 2 — STATE 3 (WIRED BUT UNREACHABLE FROM THE UI): content-discovery sweep (`/api/discovery`, internal/extscan)

- `internal/extscan` wraps `ffuf` for content/parameter discovery (`internal/extscan/nuclei.go:62`
  comment: "burpsy has its own out-of-band channel in internal/oob" — package doc frames extscan as
  the discovery/fuzzing wrapper).
- It has three importers: `cmd/burpsy/cli_extscan.go:10` (CLI), `internal/web/api_discovery.go:16`
  (the web handler), and it is referenced from `internal/dash/tasks.go:57`. So, contrary to the task
  prompt's framing of extscan as "CLI only," the web layer already imports and drives it — this is a
  case where the prior/tracker framing is stale, matching the warning that tracker claims cannot be
  trusted at face value.
- `internal/web/server.go:772` registers `/api/discovery` → `handleDiscovery`, with a comment
  (`server.go:769-771`) explicitly contrasting it with `/api/crawl` as "Burp's 'Discover content'
  engagement tool, delegated to ffuf." It is in the manifest at
  `internal/web/route_manifest_test.go:207-213` with a full descriptor ("GET: the ffuf allowlist
  state and the retained discovery runs. POST: sweep a host's ...").
- The gap: `internal/web/ui/src/**` has **zero** references to `/api/discovery`, `useDiscovery`, or
  any ffuf/sweep concept. Verified three ways:
  - `grep -rln "/api/discovery" internal/web/ui/src` → no results.
  - `grep -rln "useDiscovery\|DiscoverySweep\|ContentDiscovery" internal/web/ui/src` → no results.
  - `grep -rin "discovery\|ffuf" internal/web/ui/src` → only 4 unrelated hits, all in
    `pages/settings.tsx` and `lib/types.policy.ts` about a `discovery_handshakes` TLS metric,
    nothing about content discovery.
  - `internal/web/ui/src/nav.ts` imports 20 page components for its nav tree (dashboard, comparer,
    collaborator, crawl is reached via `ui/crawl.tsx`/`lib/data.observe.ts`/`lib/actions.ts`, etc.)
    and none of them is a discovery/sweep page.
  - `internal/web/ui/src/pages/discover.tsx` is a false-positive by name only: its own doc comment
    (`discover.tsx:9-14`) states it is "Burp's DISCOVER tab, the one that used to be called Learn" —
    a static reference/help page (query grammar, hotkeys), unrelated to content discovery. It does
    not call `/api/discovery` and was excluded from the finding after reading it.
  - Contrast case, to rule out a search-methodology error: the sibling route `/api/crawl`, registered
    two lines above discovery at `server.go:768`, *does* have full frontend wiring —
    `internal/web/ui/src/ui/crawl.tsx`, `lib/data.observe.ts`, `lib/actions.ts` all reference
    `/api/crawl`/`useCrawl`. So the absence of any hit for discovery is not an artifact of the grep
    approach; a comparable route in the same file segment is reachable and this one is not.
- Numerator/denominator: of the 2 sibling engagement-tool routes registered adjacent to each other in
  `server.go:766-772` (crawl, discovery), 1 of 2 has frontend wiring (crawl); 0 of 2 is discovery.

## Checked and ruled out (class matches from the task prompt that are already fixed — do not carry these into the consolidated report as gaps)

- **internal/oob**: not directly routed, but consumed by `internal/web/api_collaborator.go:52`
  (imports oob) behind `/api/collaborator/*`, registered at `server.go:721-725` and present in the
  manifest (`route_manifest_test.go:156-181`), with full frontend wiring in
  `internal/web/ui/src/pages/collaborator.tsx`. Also consumed by scanner OOB checks
  (`internal/scanner/oob_channel.go:28`, `checks_remaining.go:32`). State 4 as far as reachability
  goes — not independently verified for correctness of OOB detection logic itself.
- **internal/blindxss**: routed at `server.go:777-778` (`/api/blindxss`, `/api/blindxss/payload`),
  in the manifest (`route_manifest_test.go:138-148`, and the risk-class list at line 845), **and**
  has full frontend wiring: `internal/web/ui/src/pages/collaborator.tsx:19-153` calls `useBlindXSS()`
  and `useMintBlindXSSPayload()`, renders configured/unconfigured/empty states and the payload list;
  `internal/web/ui/src/lib/data.collab.ts:139-154` defines those hooks against the two routes.
  `cmd/blindxss-demo` is an additional standalone CLI demo binary, not evidence the web integration
  is missing — it coexists with, not replaces, the wired path. State 4 for reachability.
- **internal/extscan**: see Finding 2 above — the package itself is reachable from the web layer
  (`api_discovery.go`), so "extscan is CLI-only" is stale; the actual live gap is narrower — the
  *route* has no UI, not that the *package* has no web caller.
- **internal/intruder §marker§ parsing**: `internal/intruder/intruder.go:217-224` (`injectPayload`)
  parses `§...§` position markers and is exercised through `/api/intruder/run`
  (`server.go:696`, manifest-covered). Grepped `internal/intruder/*.go` for "section" and found no
  hits — could not locate a distinct "section-marker" feature under that name separate from the
  `§marker§` payload-position parsing already covered by the wired attack-run path. **Not
  determined**: whether the task's phrase "section-marker parsing" refers to something specific this
  grep missed (e.g. a different term for the same concept, or a feature elsewhere in
  `internal/sequencer`/`internal/matchreplace` not surveyed under that name) — flagging as unresolved
  rather than asserting either a gap or a non-gap.

## Swept for other orphaned packages, found none

Counted non-test, non-self external importers for every remaining `internal/**` package not already
covered above (advisory, alpn, bcheck, domexec, extension, http2, httputil, matchreplace, netauth,
organizer, persist, pool, query, schedule, sender, sequencer, session, sitemap, tlsprobe, vulnapp,
upstream, toollog): every one has at least 1 importer outside its own package/tests
(`tlsprobe` has exactly 1: `internal/scanner/checks_remaining.go`; `sitemap` has 2:
`internal/web/api_toolkit.go`, `internal/web/server.go`). None showed the "only cmd/ or only tests"
pattern that flags a state-2 candidate. This sweep only counted import edges, not
call-into-vs-reimplement (the same pattern that hid Finding 1) — a package can be imported and still
have its specific entry points bypassed the way comparer.go's were. Given the effort budget, only
the comparer.go case was checked at that depth; a full call-graph audit of the other 22 packages'
individual exported functions was not performed and is the main thing this analysis could not rule
out.

## Summary

| Capability | State | Evidence |
|---|---|---|
| comparer.go Myers diff (word/byte granularity) | 2 — implemented, not wired | api_toolkit.go:1224 reimplements instead of calling comparer.Diff/DiffWithBudget; 0 non-test callers repo-wide |
| /api/discovery content-discovery sweep (extscan/ffuf) | 3 — wired, no UI | route+manifest present; 0 frontend references anywhere in internal/web/ui/src |
| internal/oob | 4 — working (reachable via /api/collaborator, frontend wired) | corrects task prompt's example |
| internal/blindxss | 4 — working (route + manifest + frontend page) | corrects task prompt's example |
| internal/extscan as a package | 4 — reachable from web (api_discovery.go) | the real gap is the UI (Finding 2), not the package |
| intruder §marker§ parsing | 4 — working via /api/intruder/run | "section-marker" phrasing not matched to distinct code; unresolved |
