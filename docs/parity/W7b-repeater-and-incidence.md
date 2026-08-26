# W7b — Repeater concurrent isolated tabs; match/replace param-target incidence

Closes two explicitly-open items in `BURP_PARITY_GAP_ANALYSIS.md` §8 (item 8 and item 3).

## Provenance

```
$ cd /root/burpsy-react-ui/.orchestry/workspaces/tsk_0QDKrTZ
$ git rev-parse --short HEAD
51dea16
$ git status --short --branch
## orchestry/tsk_0QDKrTZ/auto-cto-burp-parity-gap-analysis-measur
   (no modified/untracked entries — clean)
```

Measured at **`51dea16`**, a clean committed tree. Where a claim rests on a file's contents I
verified the worktree copy is byte-identical to the committed blob:

```
$ git show HEAD:burpsy-go/internal/web/ui/src/lib/store.ts | sha256sum
e6750f2c334b608cc445c5e072226b8721c1fb69614966b52951a719924cea3f  -
$ sha256sum burpsy-go/internal/web/ui/src/lib/store.ts
e6750f2c334b608cc445c5e072226b8721c1fb69614966b52951a719924cea3f  ...store.ts
```

No production file was modified. The behavioural probes in Item A run against copies extracted
with `git show HEAD:` into `/tmp/w7b/`, per TAXONOMY rule 8.

### CI gating (TAXONOMY rule 4)

```
$ ls .github/workflows/
go.yml  release.yml
$ grep -n 'run:' .github/workflows/go.yml
94:        run: go build ./...
97:        run: go vet ./...
103:        run: go test ./... -count=1 -timeout 1700s
   (+ gofmt at :85)
```

There is **no `tsc`, no `bun run check`, and no Playwright step in CI.** Every TypeScript-side
statement below is therefore about code that is *not gated* — which is not the same as *not
working*, and I distinguish the two throughout. The Go-side statements in Item B **are** gated.

---

# ITEM A — Repeater concurrent isolated tabs

§8 item 8 asked whether burpsy's Repeater supports multiple concurrent *isolated* tabs the way
Burp's tab manager does, and warned that leaf-counting cannot answer it. It cannot; the answer
below comes from driving the actual state container.

There are **two** Repeater implementations in this repo. Both have a tab model. The React one is
the subject of the parity report; I note the other for completeness.

| Implementation | Path | Shipped via |
|---|---|---|
| React (primary) | `burpsy-go/internal/web/ui/src/pages/repeater.tsx` (681 lines) | Go server, `internal/web` |
| Vanilla TS (Rust CLI) | `crates/web/ui/src/repeater.ts` (182 lines) | `include_str!` into the Rust binary, `crates/web/src/ui.rs:12-14` |

## A.1 — Multiple concurrent tabs — STATE 4

**Claim under test:** the Repeater holds many independent request tabs, not one current request.

**Evidence — there is a genuine tab collection, not a single current-request model:**

- `burpsy-go/internal/web/ui/src/lib/store.ts:68-72` — the store holds
  `repeaterTabs: RepeaterTab[]`, `activeRepeaterTab: string | null`,
  `closedRepeaterTabs: RepeaterTab[]`, `repeaterGroups: RepeaterGroup[]`.
- `store.ts:20-35` — `RepeaterTab` carries its **own** `id`, `name`, `target`, `protocol`,
  `request`, `fromExchange`, `groupId`, `options`. The request buffer is a per-tab field, not a
  shared one.
- `store.ts:91-106` — fifteen tab/group actions: open, update, close, close-others,
  close-left-of, close-right-of, duplicate, reopen-closed, set-active, plus five group actions
  and per-tab options.
- `burpsy-go/internal/web/ui/src/pages/repeater.tsx:23-27` — the page's own docstring:
  *"Repeater keeps one tab per request under test."*

**Four distinct call sites open tabs**, so multi-tab is the normal operating mode rather than a
theoretical capability:

```
$ grep -rn 'openRepeaterTab' burpsy-go/internal/web/ui/src/ | grep -v 'lib/store.ts'
burpsy-go/internal/web/ui/src/app.tsx:139           (selector)
burpsy-go/internal/web/ui/src/app.tsx:477           (menu bar → new Repeater tab)
burpsy-go/internal/web/ui/src/pages/repeater.tsx:31 (selector)
burpsy-go/internal/web/ui/src/pages/repeater.tsx:104 ("New request" button, :193 and :416)
burpsy-go/internal/web/ui/src/lib/actions.ts:159    (selector)
burpsy-go/internal/web/ui/src/lib/actions.ts:169    (send-to-Repeater action)
burpsy-go/internal/web/ui/src/lib/actions.ts:294
burpsy-go/internal/web/ui/src/lib/actions.ts:317
```

**Answer to question 1: yes.** There is a real tab model in state, not a single current-request
model.

## A.2 — THE CRUX: is each tab's state ISOLATED? — STATE 4

**Claim under test:** *"a tab strip over shared state looks like parity and is not."* So: does
editing one tab's request clobber another's?

**Evidence (structural):** every mutator is keyed by tab id — it maps over the array and patches
only the matching element, leaving siblings referentially untouched:

- `store.ts:151-154` — `updateRepeaterTab: (id, patch) => set((state) => ({ repeaterTabs:
  state.repeaterTabs.map((tab) => (tab.id === id ? { ...tab, ...patch } : tab)) }))`
- `store.ts:262-265` — `setRepeaterTabGroup` — same by-id map.
- `store.ts:266-269` — `setRepeaterTabOptions` — same by-id map.

And the editor is bound to the **active tab's own** buffer, writing back under that tab's id:

- `repeater.tsx:515-519` — `<HttpEditor value={active.request} onChange={(value) =>
  updateRepeaterTab(active.id, { request: value })} />`
- `repeater.tsx:484` — target edits: `updateRepeaterTab(active.id, { target: next, protocol: ... })`
- `repeater.tsx:500` — tab name; `repeater.tsx:535` — the Inspector's request editor, same binding.

**Proof (behavioural).** Structure is not behaviour, so I drove the committed store directly. The
store is a pure zustand module, so it can be exercised headlessly. Setup — committed blobs only,
plus a `localStorage` shim (zustand's `persist` needs one) and the UI's own `node_modules`:

```
$ rm -rf /tmp/w7b && mkdir -p /tmp/w7b/lib
$ git show HEAD:burpsy-go/internal/web/ui/src/lib/store.ts > /tmp/w7b/lib/store.ts
$ git show HEAD:burpsy-go/internal/web/ui/src/lib/types.ts > /tmp/w7b/lib/types.ts
$ ln -s /root/burpsy-react-ui/burpsy-go/internal/web/ui/node_modules /tmp/w7b/node_modules
$ bun --preload ./preload.ts drive.ts
```

Real output:

```
preload: typeof localStorage = object
PASS  three concurrent tabs coexist  :: len=3
PASS  tab ids are distinct  :: tmtafcdh31,tmtafcdh42,tmtafcdh53
PASS  edit landed on tab A
PASS  CRUX: tab B request buffer untouched by A's edit  :: "GET /b HTTP/1.1\r\nHost: b.test\r\n\r\n"
PASS  CRUX: tab C request buffer untouched by A's edit  :: "GET /c HTTP/1.1\r\nHost: c.test\r\n\r\n"
PASS  per-tab target isolated
PASS  active tab switch does not mutate buffers
PASS  options set on A only  :: A={"follow_redirects":true} B=undefined
PASS  localStorage key written
PASS  persisted payload carries all 3 tabs with distinct requests  :: n=3
PASS  persisted payload carries activeRepeaterTab  :: tmtafcdh31
PASS  closedRepeaterTabs deliberately NOT persisted
PASS  group assigned to tab B
PASS  group persisted
PASS  group collapse toggles
PASS  deleting a group keeps its tabs
PASS  close removes the tab
PASS  reopen restores the closed tab with its buffer
INFO  opened 3 + 10 = 13 tabs; store now holds 12
INFO  oldest tab A (holding the hand-edited draft "EDITED-A") still present? false
INFO  is the evicted tab recoverable from the reopen stack? false
PASS  cap is 12  :: len=12

=== 0 failure(s) ===
```

**Answer to question 2: the tabs are genuinely ISOLATED.** This is a positive finding and it
should be recorded as one. Editing tab A's request buffer, target, or per-send options leaves
tabs B and C byte-identical; switching the active tab mutates nothing. There is no shared
buffer, and switching tabs does not clobber edits. This is not a tab strip over shared state.

**Scope of the proof — stated precisely.** This probe exercises the **state container**, which is
where the isolation invariant actually lives, and it is the layer the React page reads and writes
through the bindings cited above. It does **not** render React, so it does not prove the DOM wires
those bindings up as written. Per the brief's rule, a passing probe proves the layer it tests.
The remaining risk is confined to the JSX bindings at `repeater.tsx:484/500/515-519/535`, all four
of which pass `active.id` explicitly and are quoted verbatim above.

## A.3 — Per-tab response history (back/forward) — STATE 4 within a page visit

**Claim under test:** Burp keeps a back/forward history per Repeater tab.

**Evidence — history is a per-tab map, and the navigation chrome exists:**

- `repeater.tsx:63` — `const [history, setHistory] = useState<Record<string, RepeaterResult[]>>({})`
  — keyed by tab id, holding **every** response a tab has received, oldest first.
- `repeater.tsx:65` — `const [viewing, setViewing] = useState<Record<string, number | null>>({})`
  — which entry of *that tab's* history is on screen; `null` follows the newest.
- `repeater.tsx:126` — a send appends to `[tab.id]` only:
  `setHistory((current) => ({ ...current, [tab.id]: [...(current[tab.id] ?? []), result] }))`.
- `repeater.tsx:204-206` — `activeHistory = history[active.id] ?? []`, `viewIndex =
  viewing[active.id] ?? activeHistory.length - 1`.
- `repeater.tsx:358-382` — the rendered back/forward group: `role="group"
  aria-label="Response history"`, a "Previous response" `IconButton` (`:360`), an
  `aria-live="polite"` `N/M` position counter, and a "Next response" `IconButton` (`:372`).
  Both are disabled at the ends. Landing back on the newest resets to `null` so the tab resumes
  following new sends rather than pinning to a stale index.
- `repeater.tsx:83-88` — a pruning effect keeps `history`/`viewing` free of keys for tabs that no
  longer exist, so bulk closes cannot leak.

**Answer to question 3: yes, there is real per-tab history with back/forward navigation** — and
the code comment at `repeater.tsx:55-62` shows this was a deliberate fix to an earlier version
that "kept exactly one response per tab and dropped the rest on every send."

**The divergence:** this history is component `useState`, not store state, and it is deliberately
not persisted (`store.ts:285-295` — `partialize` omits it; the comment at `:56-58` says the store
"persists the request draft across reloads, deliberately not the responses"). Burp keeps per-tab
history for the session. See NOT DETERMINED #1 for the page-navigation consequence, which I did
not behaviourally prove.

## A.4 — Is the persisted tab/group state genuinely consumed, or write-only? — STATE 4 (and the sibling is STATE 2)

This is question 4, and the answer differs for the two halves.

**`repeaterTabs` / `activeRepeaterTab` / `repeaterGroups` are genuinely consumed — both directions.**

*Written:* `store.ts:285-295`, `partialize` under localStorage key `burpsy.workspace`.

*Read back — proven behaviourally.* Writing to localStorage proves nothing; I pre-seeded the key
as a prior session would have left it and booted a fresh store:

```
$ bun --preload ./preload.ts rehydrate.ts
preload: typeof localStorage = object
PASS  REHYDRATE: both prior tabs came back  :: len=2
PASS  REHYDRATE: each tab kept its OWN request buffer  :: ["POST /SURVIVED-A HTTP/1.1\r\n\r\n","POST /SURVIVED-B HTTP/1.1\r\n\r\n"]
PASS  REHYDRATE: activeRepeaterTab restored  :: t2
PASS  REHYDRATE: repeaterGroups restored (incl. collapsed + colour)  :: [{"id":"g1","name":"prior group","color":"#3b82f6","collapsed":true}]
PASS  REHYDRATE: tab->group membership restored
PASS  CONTRAST: inspectorDock also rehydrates into the store  :: left

=== 0 failure(s) ===
```

*Rendered:* `repeaterGroups` is not merely rehydrated, it drives real UI —
`repeater.tsx:420-470` renders each group as a coloured bordered container with a
collapse/expand chevron bound to `toggleRepeaterGroup(group.id)` (`:428`), a colour dot, inline
rename (`:433-457`), a delete button labelled "keeps its tabs" (`:463`), and its member tabs
(`:467`). `repeater.tsx:246-249` adds a "Move to <group>" entry per group to the tab context
menu. `repeater.tsx:336` computes the ungrouped remainder.

**The sibling persisted state is a different story, and the prior wave's finding survives.**

```
$ grep -rn 'inspectorDock\|inspectorPanelState\|setInspectorDock\|setInspectorPanelState' \
    burpsy-go/internal/web/ui/src/
burpsy-go/internal/web/ui/src/lib/store.ts:65    inspectorDock: InspectorDock;
burpsy-go/internal/web/ui/src/lib/store.ts:66    inspectorPanelState: InspectorPanelState;
burpsy-go/internal/web/ui/src/lib/store.ts:88    setInspectorDock: (dock: InspectorDock) => void;
burpsy-go/internal/web/ui/src/lib/store.ts:89    setInspectorPanelState: (state: InspectorPanelState) => void;
burpsy-go/internal/web/ui/src/lib/store.ts:123      inspectorDock: "right",
burpsy-go/internal/web/ui/src/lib/store.ts:124      inspectorPanelState: "auto",
burpsy-go/internal/web/ui/src/lib/store.ts:140      setInspectorDock: (inspectorDock) => set({ inspectorDock }),
burpsy-go/internal/web/ui/src/lib/store.ts:141      setInspectorPanelState: (inspectorPanelState) => set({ inspectorPanelState }),
burpsy-go/internal/web/ui/src/lib/store.ts:287        inspectorDock: state.inspectorDock,
burpsy-go/internal/web/ui/src/lib/store.ts:288        inspectorPanelState: state.inspectorPanelState,
```

**Ten hits, all in `store.ts`. Zero consumers, and zero callers of either setter, anywhere —
including tests.** Declared, defaulted, made settable, persisted to localStorage, rehydrated into
the store (proven by the CONTRAST line above), and read by nothing.

*Positive control for this negative (TAXONOMY rule 3):* the same grep, same corpus, same method
finds `repeaterGroups` consumed outside `store.ts` — `repeater.tsx:42, 246-251, 336, 420-467`.
So the corpus is right and the method finds real consumers; the zero for `inspectorDock` is a
property of the code, not of my grep.

`inspectorDock` / `inspectorPanelState`: **STATE 2 (UNWIRED)** — real implementation, zero
non-test callers. Note the Repeater's Inspector visibility is separate local state
(`repeater.tsx:79`, `const [inspector, setInspector] = useState(true)`), so the persisted dock
preference cannot even be reached through the one page that shows an Inspector.

**Answer to question 4: the Repeater tab/group state is genuinely consumed** — persisted, proven
to rehydrate, and rendered. It is *not* another write-only persistence. The write-only pathology
is real but confined to `inspectorDock`/`inspectorPanelState`.

## A.5 — NEW FINDING: an undocumented 12-tab cap silently destroys the oldest tab's draft — STATE 5

Not in the brief; found while measuring. It is a behavioural defect, so it is reported.

**Evidence:**

```
store.ts:143-149  openRepeaterTab: ({ name, target, protocol = "https", request, fromExchange }) => {
                    const id = nextId();
                    set((state) => ({
                      repeaterTabs: [...state.repeaterTabs, { id, name, ... }].slice(-12),
                      activeRepeaterTab: id,
                    }));
store.ts:211      duplicateRepeaterTab: ... return { repeaterTabs: next.slice(-12), ... };
```

**Proof (behavioural, from the `drive.ts` run above):**

```
INFO  opened 3 + 10 = 13 tabs; store now holds 12
INFO  oldest tab A (holding the hand-edited draft "EDITED-A") still present? false
INFO  is the evicted tab recoverable from the reopen stack? false
PASS  cap is 12  :: len=12
```

**Why this is STATE 5 and not a documented capability limit (TAXONOMY rule 7):**

1. **It is undocumented.** `.slice(-12)` at `store.ts:146` and `:211` is a bare magic number with
   no comment, in a file that comments nearly every other decision — including the adjacent
   choice *not* to persist `closedRepeaterTabs` (`store.ts:293-294`), justified on the grounds
   that resurrecting a closed draft "reads as a bug, not a feature". No `docs/` file mentions a
   tab cap: `grep -rn 'slice(-12)\|12 tab\|twelve' store.ts repeater.tsx docs/` returns only the
   six `.slice(-12)` sites and one unrelated hit in `docs/parity/W4-test-honesty.md:783`.
2. **The eviction is silent.** `grep -n 'newTab\|toast\|limit\|max' repeater.tsx` shows the only
   toasts are send-success (`:130`), send-error (`:132`), and the Intruder handoff (`:171`,
   `:177`). `newTab` (`:103-110`) and both "New request" controls (`:193`, `:416`) warn nothing.
3. **It is unrecoverable.** `closeRepeaterTab` deliberately pushes onto `closedRepeaterTabs`
   (`store.ts:166`) precisely so a closed draft can be reopened — but the cap eviction in
   `openRepeaterTab` bypasses that stack entirely. The reopen affordance that exists to protect
   drafts does not cover the one path that destroys them without being asked to.
4. **Burp has no such cap.** Its tab manager holds arbitrarily many tabs.

**Impact:** an operator holding 12 tabs who opens a 13th — including via "send to Repeater" from
Proxy/history, which is a reflex action (`actions.ts:169`, `:294`, `:317`) — silently loses the
oldest tab and its hand-crafted request, with no toast, no confirmation, and no undo. That is
exactly the failure mode `repeater.tsx:24-26` says the persistence exists to prevent
("losing a hand-crafted request to an accidental refresh is the failure mode operators complain
about most").

## A.6 — Honest parity statement for Item A

**Overall: STATE 4 for the concurrent-isolated-tabs capability, with one STATE 5 defect
(the silent 12-tab eviction) and one adjacent STATE 2 (`inspectorDock`/`inspectorPanelState`).**

burpsy's Repeater is a genuine multi-tab tool, not a tab strip over a shared buffer. Measured
against Burp's `secondarySuiteTabBar` behaviours:

| Burp behaviour | burpsy | Evidence |
|---|---|---|
| Many concurrent tabs | **yes** | `store.ts:68`, `:143-149` |
| Per-tab request buffer, edited independently | **yes, proven isolated** | `store.ts:151-154`; `drive.ts` CRUX lines |
| Per-tab response | **yes** | `repeater.tsx:63`, `:126`, `:204-206` |
| Per-tab back/forward response history | **yes** | `repeater.tsx:63-65`, `:358-382` |
| Per-tab send-option overrides | **yes** | `store.ts:266-269`, `repeater.tsx` Config panel |
| Tab groups (colour, collapse, rename, delete) | **yes, rendered** | `store.ts:225-265`, `repeater.tsx:420-470` |
| Rename tab | **yes** | `repeater.tsx:332`, `:500` |
| Duplicate tab | **yes** | `store.ts:203-212` |
| Close others / left / right | **yes** | `store.ts:171-201` |
| Reopen closed tab | **yes** (session only, deliberately not persisted) | `store.ts:213-222`, `:293-294` |
| Drafts survive reload | **yes, proven to rehydrate** | `store.ts:289`; `rehydrate.ts` output |
| Unbounded tab count | **NO — silent 12-tab cap** | `store.ts:146`; A.5 |
| Response history survives leaving the tool | **NO** (structural; see NOT DETERMINED #1) | `repeater.tsx:63`, `app.tsx:162`, `:663-665` |
| Drag-to-reorder tabs | **not determined** | see NOT DETERMINED #2 |

The prior wave was right to refuse to guess a ratio here, and right that leaf-counting could not
answer it: the Repeater is *one* nav leaf (`nav.ts:144`) and holds twelve of these behaviours.

---

# ITEM B — match/replace param-target field incidence

§8 item 3 stated the match/replace param-target issue "is reachable via the public API" while the
UI dropdown offers only 5 targets, and asked whether **any** extension, script, config file, test
fixture, e2e script or CI job actually sends `request_param_name` / `request_param_value` to
`/api/proxy/matchreplace`.

Two corrections to the question itself, then the answer.

## B.1 — CORRECTION: `/api/proxy/matchreplace` is not a route in this codebase

The endpoint named in §8 item 3 (and in `BURP_PARITY_GAP_ANALYSIS.md:353`, `parity/W1-broken-behaviour.md:117`
and `:224`, `parity/W5-unwired-sweep.md:421`) **does not exist at `51dea16`.**

```
$ grep -rn 'proxy/matchreplace' burpsy-go/ crates/ --include=*.go --include=*.rs --include=*.ts --include=*.tsx
$ echo $?
1
```

*Positive control (TAXONOMY rule 3)* — the same method, same corpus, finds the real routes:

```
$ grep -rn 'tools/rules' burpsy-go/internal/web/server.go
burpsy-go/internal/web/server.go:789:	s.mux.HandleFunc("/api/tools/rules", s.handleMatchReplaceRules)
burpsy-go/internal/web/server.go:790:	s.mux.HandleFunc("/api/tools/rules/test", s.handleMatchReplaceTest)
```

So the grep works; the zero is real. The match/replace routes are **`/api/tools/rules`** and
**`/api/tools/rules/test`**. `/api/proxy/matchreplace` appears **only** in prose inside
`.md` files. Confirmed from the UI side too — `lib/data.ts:249` (`useMatchReplace` → GET
`/api/tools/rules`), `lib/data.ts:299-302` (`useSaveMatchReplace` → PUT `/api/tools/rules`),
`lib/data.policy.ts:94-97` (`useTestMatchReplace` → POST `/api/tools/rules/test`).

**The route name in the master report is wrong and should be corrected.** I searched for both
spellings below so the incidence answer does not depend on which one is right.

## B.2 — CORRECTION: the param targets are no longer accepted — the STATE 5 is FIXED — STATE 4

The premise "reachable via the public API" is **stale at `51dea16`**. Two independent layers now
refuse or neutralise a param rule.

**Layer 1 — the API refuses with 400, by name.** `burpsy-go/internal/web/api_toolkit.go:563-569`
holds the accepted vocabulary (exactly the 5 the UI offers). `:570-579` declares
`matchReplaceUnappliedTargets` mapping `request_param_name` → `TargetRequestParamName` and
`request_param_value` → `TargetRequestParamValue`. `targetToCategory` (`:612-637`) has no `case`
for either, and its `default` (`:627-635`) returns:

```go
if engineName, unapplied := matchReplaceUnappliedTargets[ruleType]; unapplied {
    return 0, fmt.Errorf(
        "rule_type %q is declared by the engine as %s but has no applier yet, so a rule "+
            "using it would be applied as a whole-body rewrite and could change unrelated "+
            "parameters; refused until it is implemented. Accepted values are %s",
        ruleType, engineName, strings.Join(matchReplaceTargetNames, ", "))
}
```

The comment at `api_toolkit.go:596-611` records that a prior commit (`4469cf1`) *added* these two
as accepted and that this was the reintroduction of the original defect, since reverted.

**Layer 2 — the engine no-ops rather than body-rewrites.**
`burpsy-go/internal/matchreplace/matchreplace.go:242-273`, `applyOne`, now ends:

```go
default:
    // An unimplemented target did not fire. `nil` is this function's contract for that —
    // see Apply, which only sets `changed` when applyOne returns non-nil.
    //
    // This used to be `return applyBody(r, raw)`. [...] A param-name rule
    // replacing "secret" with "harmless" against
    // `user=admin&secret=hunter2&nonsecret=keep` produced
    // `user=admin&harmless=hunter2&nonharmless=keep` — it renamed `nonsecret`, an
    // unrelated parameter [...]
    return nil
```

`nil`, not `raw` — so the rule is not counted as fired and `fixContentLength` does not run over
an untouched body. This closes the bypass that would otherwise exist via a hand-edited persisted
config: the restore path builds a `matchreplace.RuleSet` from engine `Target` values and does not
pass through `targetToCategory` (`server.go:470-474` `persistMatchReplace` /
`persist.SaveMatchRules`), so Layer 1 alone would not cover it. Layer 2 does.

**Proof — commands run and real output** (this is CI-gated Go, per B.5):

```
$ cd burpsy-go && go test ./internal/web/ -run 'TestAParamRulePutIsRefusedAndInstallsNothing|TestTheParamTargetsAreRefused' -v
=== RUN   TestTheParamTargetsAreRefusedAsUnimplementedNotUnknown
--- PASS: TestTheParamTargetsAreRefusedAsUnimplementedNotUnknown (0.00s)
=== RUN   TestAParamRulePutIsRefusedAndInstallsNothing
--- PASS: TestAParamRulePutIsRefusedAndInstallsNothing (0.01s)
PASS
ok  	github.com/burpsy-go/burpsy/internal/web	0.044s
```

The second test is the end-to-end one and it is worth naming what layer it proves. It drives the
**real mux** — `httptest.NewRequest(http.MethodPut, "/api/tools/rules", ...)` then
`ts.mux.ServeHTTP(rec, req)` (`matchreplace_target_test.go:198-213`) — and asserts both a 400 and
`len(ts.matchReplace.Rules()) == 0`, i.e. that the refusal installs nothing into the live set.
That is the HTTP layer a browser or a script actually hits. It is *not* a browser, so it does not
prove the React page's rendering; it does prove the API contract, which is what §8 item 3 asked about.

The broader run:

```
$ go test ./internal/web/ -run 'MatchReplace|Target' -v   (tail)
--- PASS: TestWebLayerAndProxyObserveOneSharedMatchReplaceRuleset (0.01s)
--- PASS: TestEveryEngineTargetHasANameAndOnlyAppliableOnesRoundTrip (0.00s)
--- PASS: TestTheParamTargetsAreRefusedAsUnimplementedNotUnknown (0.00s)
--- PASS: TestAnUnmappedTargetSaysSoRatherThanClaimingRequestBody (0.00s)
PASS
ok  	github.com/burpsy-go/burpsy/internal/web	0.724s
```

**The gap is now a documented capability gap (TAXONOMY rule 7), not a defect.** Burp can
match/replace on parameter names and values; burpsy cannot, refuses to pretend it can, and says
why in the 400. Per rule 7 that grades separately from the STATE 5 it used to be.

## B.3 — INCIDENCE: the answer is ZERO non-test senders

**Literal-string sweep, whole repo, all file types:**

```
$ grep -rn 'request_param_name' . --exclude-dir=node_modules --exclude-dir=.git
$ grep -rn 'request_param_value' . --exclude-dir=node_modules --exclude-dir=.git
```

Every hit falls into exactly three buckets. Full classification of the union:

| Bucket | Sites | Sender? |
|---|---|---|
| **Go implementation** (the refusal machinery itself) | `burpsy-go/internal/web/api_toolkit.go:577, 578, 596, 732, 734` | no — these *define* and *refuse* the names |
| **Go tests** | `burpsy-go/internal/web/matchreplace_target_test.go:178, 202, 269` | no — tests, excluded by the brief |
| **Markdown prose** (parity docs, ADR, gap analysis, a `.patch` file) | `BURP_PARITY_GAP_ANALYSIS.md:353,362`; `docs/parity/W1-broken-behaviour.md:25,33`; `docs/parity/W4-test-honesty.md:366,394,506,507,859`; `docs/parity/W3-ui-surface.md:29`; `docs/parity/W5-unwired-sweep.md:421,422`; `docs/adr/0001-burp-parity-measurement.md:136`; `parity/W1-broken-behaviour.md:117,124,329`; `parity/W3-ui-surface.md:29`; `parity/W5-unwired-sweep.md:421,422`; `parity/W1-suggested-fix-matchreplace-applyOne.patch:17` | no — documentation about the gap |

**Disambiguation (TAXONOMY rule 4 on positive greps).** The 5 Go implementation hits are the same
symbol, not lookalikes: `:577-578` are the two keys of `matchReplaceUnappliedTargets`, `:596` is a
doc comment, and `:732`/`:734` are the two `return` arms of `matchReplaceTargetName` — the
inverse function, which must stay total over the engine enum (`api_toolkit.go:709-722` explains
why). All five are in one file, in the `internal/web` match/replace machinery. There is no
same-named symbol elsewhere: the Rust second implementation has no param concept at all —
`grep -n 'ParamName\|ParamValue\|param' crates/tools/src/matchreplace.rs` returns **nothing**.

**Every `rule_type` sender in the repo, non-test:**

```
$ grep -rn 'rule_type' . --exclude-dir=node_modules --exclude-dir=.git --exclude=*.md | grep -v '_test.go'
burpsy-go/internal/web/ui/src/lib/types.ts:409:          rule_type: string;
burpsy-go/internal/web/ui/src/pages/matchreplace.tsx:74:   rule_type: asTarget(rule.rule_type),
burpsy-go/internal/web/ui/src/pages/matchreplace.tsx:116:  rule_type: direction === "response" ? "response_header" : "request_header",
burpsy-go/internal/web/ui/src/pages/matchreplace.tsx:163:  if (directionOf(rule.rule_type) === "response") response = true;
burpsy-go/internal/web/ui/src/pages/matchreplace.tsx:275:  value={rule.rule_type}
burpsy-go/internal/web/ui/src/pages/matchreplace.tsx:276:  onChange={(event) => patch(index, { rule_type: asTarget(event.target.value) })}
burpsy-go/internal/web/api_toolkit.go:536:                RuleType string `json:"rule_type"`
   (+ api_toolkit.go doc/error strings at :559, 571, 574, 581, 587, 626, 630, 635)
```

The **only** client that sends a `rule_type` is `pages/matchreplace.tsx`, and it is doubly
constrained:

- `matchreplace.tsx:18-24` — `TARGETS` lists exactly the five implemented targets.
- `lib/types.policy.ts:10-15` — `MatchReplaceTarget` is a 5-member string-literal union; a param
  value would not typecheck. (Ungated — no `tsc` in CI. See B.5.)
- `matchreplace.tsx:38-40` — `asTarget()` coerces anything outside the five to `"request_header"`,
  so even a param value arriving *from* the server could not be echoed back on save.

**Shell / config / e2e sweep:**

```
$ grep -rn 'matchreplace\|match_replace\|match-replace\|tools/rules' \
    --include=*.sh --include=*.yml --include=*.yaml --include=*.json --include=*.toml . \
    --exclude-dir=node_modules --exclude-dir=.git | grep -v 'package.json\|bun.lock'
   (no output)
```

*Positive control for that negative* — my first attempt used `api/proxy` and found nothing, which
would have been a false N/A exactly as TAXONOMY rule 3 warns. The shell corpus is real and does
make API calls:

```
$ grep -rn 'curl' --include=*.sh . --exclude-dir=node_modules | wc -l
89
$ grep -rhno '/api/[a-z0-9/_-]*' --include=*.sh . --exclude-dir=node_modules | sort -u -t: -k2
/api/audit/ ... /api/history ... /api/intercept ... /api/intruder/points ... /api/intruder/run
/api/issues ... /api/message/ ... /api/repeater/send ... /api/scanner/audit
/api/sequencer/analyse ... /api/sequencer/capture ... /api/session/cookies ... /api/stats
```

89 curl invocations across 10 shell scripts, hitting ~14 distinct `/api/` paths — and
`/api/tools/rules` is **not among them**. So the method finds endpoints; the zero is a property
of the scripts. **No e2e or verification script exercises match/replace at all** — a coverage gap
worth recording separately from the incidence answer.

**Extension surface:** the only `examples/` directory in the repo is `crates/proxy/examples`; there
is no extension example, sample script, or fixture anywhere that constructs a match/replace rule.

## B.4 — Item B answer

**There are ZERO non-test senders of `request_param_name` or `request_param_value`, to either
`/api/tools/rules` (the real route) or `/api/proxy/matchreplace` (the route named in the report,
which does not exist).** No extension, no script, no config file, no YAML/JSON/TOML, no e2e
script, no CI job. The only non-doc, non-test occurrences are the five sites in `api_toolkit.go`
that exist to *refuse* and *name* these values.

**State:** the surface §8 item 3 describes is **STATE 4** at `51dea16` — the API behaves per its
stated contract (refuse by name with a 400, install nothing), proven by a mux-level test. The
*capability* — parameter-scoped match/replace — is **STATE 0 (ABSENT)** and is a documented
capability gap under TAXONOMY rule 7, not a defect. **Incidence: zero.**

## B.5 — Gated vs ungated (TAXONOMY rule 4)

| Claim | Rests on | Gated in CI? |
|---|---|---|
| API refuses param targets with 400, installs nothing | `go test ./internal/web/` | **YES** — `go.yml:103` |
| Engine no-ops unimplemented targets | `matchreplace.go:250-271` + `go test` | **YES** |
| `MatchReplaceTarget` union blocks param values at compile time | `tsc --noEmit` via `bun run check` | **NO** — no `tsc` in CI |
| UI dropdown offers only 5 targets | source read + ungated Playwright | **NO** |
| Repeater tab isolation (Item A.2) | my `/tmp/w7b` probe | **NO** — my own manual run |
| Repeater multi-tab behaviour | no e2e covers it (see NOT DETERMINED #3) | **NO** |

---

# NOT DETERMINED

1. **Whether leaving the Repeater page destroys per-tab response history.** `app.tsx:162`
   (`const ActivePage = leaf.page`) and `:663-665` (`<ErrorBoundary resetKey={route}><ActivePage /></ErrorBoundary>`)
   render only the active page, and `history`/`viewing` are `useState` inside `RepeaterPage`
   (`repeater.tsx:63` and `:65`). React's component-identity rule means a different component type at
   that position unmounts the old one and discards its state, so navigating Repeater → Proxy →
   Repeater should leave every tab's request draft intact (store-backed) but its response history
   empty. I did **not** observe this: no DOM harness is installed
   (`happy-dom`, `jsdom`, `@testing-library/react` all absent from the UI's `node_modules`), and
   TAXONOMY requires behavioural proof for STATE 5. **Reported as a structural inference, not a
   measured defect.** To settle it: add a DOM test harness, or drive `#repeater` → `#proxy-intercept`
   → `#repeater` in a browser and check whether the `N/M` counter at `repeater.tsx:369` returns.
2. **Whether tabs can be reordered by drag.** Burp's tab bar supports it. I found the tab strip
   (`repeater.tsx:416-470`) and no drag handler, but I did not enumerate the Radix
   `@radix-ui/react-tabs` primitives to confirm none is inherited, so I am not asserting a zero.
3. **Multi-tab behaviour in a real browser.** No e2e spec opens a second Repeater tab:
   `grep -rn -i 'repeater' e2e/specs/*.ts` returns 23 hits, all single-tab (menu-bar navigation
   at `behaviour.spec.ts:326-336`, Inspector edits at `:499`, response read-only note at `:602`,
   route smoke at `routes.spec.ts:93-99`). So **the isolation invariant is untested in CI and
   untested in the ungated e2e suite**; my `/tmp/w7b` probe is currently the only evidence, and
   it covers the store, not the DOM.
4. **Whether the 12-tab cap was ever a deliberate decision.** I established it is undocumented in
   code and `docs/`; I did not search commit history for a rationale. `git log -S 'slice(-12)'`
   would settle intent, which changes whether A.5 is graded a defect (STATE 5) or a documented
   divergence (rule 7). I graded it STATE 5 on the strength of the silent, unrecoverable
   data loss, which is a defect on either reading of intent.
5. **The Rust CLI's Repeater (`crates/web/ui/src/repeater.ts`).** I confirmed it has a tab model
   (`tabs: RepeaterTab[]` at `:34`, add/close/select at `:66-78`) and that its own header comment
   claims per-tab history, and that it is shipped via `include_str!` (`crates/web/src/ui.rs:12-14`).
   I did **not** test its isolation. Item A's verdict covers the React UI only.
6. **`/api/repeater/send` server-side statelessness.** Only one repeater route exists
   (`server.go:689`), which is consistent with tabs being purely client-side, but I did not read
   `handleRepeaterSend` to confirm it holds no per-tab state.

---

# DENOMINATORS I RECOUNTED

| Count | Value | Exact command / method | Corpus, and what it counts |
|---|---|---|---|
| Repeater API routes | **1** | `grep -rn '"/api/repeater' burpsy-go/internal/web/server.go` | registered mux routes; counts `HandleFunc` calls. Only `/api/repeater/send` |
| match/replace API routes | **2** | `grep -rn 'tools/rules' burpsy-go/internal/web/server.go` | `/api/tools/rules`, `/api/tools/rules/test` |
| `/api/proxy/matchreplace` route registrations | **0** | `grep -rn 'proxy/matchreplace' burpsy-go/ crates/ --include=*.go --include=*.rs --include=*.ts --include=*.tsx` → exit 1 | code only, .md excluded. Positive control: same method finds `tools/rules` |
| UI match/replace targets offered | **5** | `matchreplace.tsx:18-24`, read line by line | dropdown `TARGETS` entries |
| TS `MatchReplaceTarget` union members | **5** | `types.policy.ts:10-15`, read line by line | string-literal union arms |
| Go accepted `rule_type` values | **5** | `api_toolkit.go:563-569`, `matchReplaceTargetNames` elements | the accepted vocabulary |
| Go engine `Target` enum values | **7** | `matchReplaceTargetName` arms, `api_toolkit.go:723-742` | named enum values; 5 appliable + 2 refused |
| `applyOne` implemented cases | **3 arms / 5 targets** | `matchreplace.go:243-249` | 3 `case` arms covering 5 enum values (body×2, header×2, first-line×1) |
| **Non-test senders of the param targets** | **0** | `grep -rn 'request_param_name\|request_param_value' . --exclude-dir=node_modules --exclude-dir=.git`, then classified every hit into impl / test / .md | whole repo, all file types |
| Non-test `rule_type` senders | **1 file** | `grep -rn 'rule_type' . --exclude-dir=node_modules --exclude-dir=.git --exclude=*.md \| grep -v '_test.go'` | `pages/matchreplace.tsx` only |
| Shell scripts in repo | **10** | `find . -name '*.sh' -not -path './node_modules/*' -not -path './.git/*'` | 7 e2e + `integrate.sh`, `serve.sh`, `verify.sh` |
| curl invocations in shell corpus | **89** | `grep -rn 'curl' --include=*.sh . --exclude-dir=node_modules \| wc -l` | positive control establishing the corpus is live |
| Shell/config references to match/replace | **0** | `grep -rn 'matchreplace\|match_replace\|match-replace\|tools/rules' --include=*.sh --include=*.yml --include=*.yaml --include=*.json --include=*.toml .` | positive control: the 89 curls above |
| `openRepeaterTab` call sites (non-store) | **4** | `grep -rn 'openRepeaterTab' src/ \| grep -v 'lib/store.ts'` → 8 hits = 4 selectors + 4 invocations | proves multi-tab is the normal mode |
| Repeater tab/group actions in store | **15** | `store.ts:91-106`, counted line by line | 9 tab + 5 group + 1 per-tab options |
| `inspectorDock`/`inspectorPanelState` hits | **10, all in store.ts; 0 consumers** | `grep -rn 'inspectorDock\|inspectorPanelState\|setInspectorDock\|setInspectorPanelState' src/` | positive control: same grep finds `repeaterGroups` consumed in `repeater.tsx` |
| `.slice(-12)` sites | **6** | `grep -rn 'slice(-12)' store.ts` | 2 cap `repeaterTabs` (`:146`, `:211`), 4 cap `closedRepeaterTabs` |
| Repeater mentions in e2e specs | **23, all single-tab** | `grep -rn -i 'repeater' e2e/specs/*.ts`, each hit read | none opens a second tab |
| CI gate steps | **4** | `grep -n 'run:' .github/workflows/go.yml` | gofmt, `go build`, `go vet`, `go test`. No tsc, no bun, no Playwright |
