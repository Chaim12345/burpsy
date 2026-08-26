# Burp-Parity Gap Analysis: burpsy vs Burp Suite 2026.7.1

**Status:** consolidating — W2/W3/W4/W5 in flight, sections marked PENDING below.
**Author:** CTO, from six analyst workstreams.
**Reference:** `/root/burp-re`, a teardown of Burp Suite 2026.7.1 including its shipped jar resources.
**burpsy baselines:** wave 1 at `ede8f1f`, wave 2 at `a619c9a`, this consolidation authored at `9194df6`.
Baseline drift across waves is real and is flagged per finding rather than smoothed over.
**Measurement contract:** `/root/burpsy-parity/TAXONOMY.md`.

---

## 1. The headline, stated honestly

burpsy is **not close to Burp Suite 2026.7.1**, and the distance is not a single number.

There is **no defensible aggregate percentage** and this report refuses to invent one. The
measurable surfaces do not share a unit: scanner config keys, Intruder wordlists, Montoya
class counts, tool tabs and advisory definitions cannot be summed into one ratio. Anyone
who quotes a single "% of Burp" figure for this project is quoting something nobody
measured. What follows is a **vector**, reported per surface.

Second, and more important than any count: **this codebase's own trackers cannot be used
as evidence.** Across two waves, analysts falsified **four published denominators** and
**one categorical feature claim**, and found defects that trackers recorded as working.
The failure mode is consistent — a tracker tick asserts that a control **exists**; it never
measured that the control **behaves**. Section 6 documents this, because it is the finding
most likely to cause the next wrong decision.

---

## 2. Distance from parity, per surface

Each row is a ratio whose denominator was recounted by an analyst, with the recount
command recorded. Rows are **not** commensurable.

| Surface | burpsy | Burp 2026.7.1 | Ratio | Confidence |
|---|---|---|---|---|
| **Scanner config depth** | 4 knobs (`BuiltInConfig`) | 77 functional leaf keys / 20 sections | **4/77 (5.2%)**, 2/20 sections | High — recounted from Burp's 29 shipped configs |
| **Tool tabs** | 15 in `nav.ts` | 15 in `ToolRegistry` | **12/15 overlap**, not 15/15 | High — enum-vs-route, both enumerated |
| **Advisory definitions** | 183 bundled, 181 index-reachable | 183 | **183/183 bundled, 181/183 reachable** | High — the 2-file shadowing is in *Burp's* own data |
| **Intruder wordlists** | 0 bundled (6 generators) | 48 `.pay` files | **0/48** | High — `find -name '*.pay'` = 0 |
| **Intruder attack types** | 4 | 4 | **4/4 parity** | High |
| **Extender / Montoya UI hooks** | 3 registration points | 13 `userInterface()` points | **3/13**, self-documented | High — `internal/extension/protocol.go:19-33` |
| **Burp AI** | absent | 881 first-party classes + 306 bundled MCP classes | **0/881** | High — and the tracker's "N/A" is false, §6 |
| **Config panels** | not enumerated | ~90 top-level (from 134 identifiers, 108 candidates) | **NOT DETERMINED** | Low — largest open denominator |

### The sharpest single gap

**burpsy side re-verified by me at `749ddbd`.** `BuiltInConfig`
(`internal/scanner/audit.go:558-565`) carries exactly **4 overlayable knobs** —
`ConsecutiveCheckFailuresToAbandonUnit`, `ConsecutiveUnitFailuresToFailItem`,
`PauseSessionAfterFailedItems`, `MaximumAuditTimeMinutes` (`Name` is a label, not a knob).
Their 4 `burpKey` mappings (`audit.go:594,601,608,615`) land in exactly **two** Burp
sections: `scanner/error_handling` (3) and `scanner/audit_optimization` (1). The 4/77 and
2/20 figures hold.

Burp's scanner exposes `scanner.insertion_point_types` (8 keys — **WHERE** it injects) and
`scanner.issues_reported` (12 keys — **WHICH** checks run). Neither is **representable at
all** in burpsy's config model.

Two independent workstreams reached this from opposite directions: W0 counted Burp's
shipped config JSON and found 4/77; R1-B walked burpsy's `nav.ts` and found the
scan-configuration editor is STATE 1 with Scanner having no top-level tab. Method
triangulation on the same conclusion — this is the most reliable finding in the report.

A scanner whose insertion points and check selection cannot be expressed is not a
configurable scanner. **This, not the missing tabs, is the deepest structural gap.**

---

## 3. Broken, not merely missing (STATE 5)

The most damaging category: reachable code that does something other than what its
contract promises. Confirmed count in the surfaces swept so far: **1**.

### 3.1 match/replace param targets silently rewrite the whole body — LIVE

Detail and proof: `W1-broken-behaviour.md`. Summary:

`/api/proxy/matchreplace` accepts `rule_type` values `request_param_name` and
`request_param_value`. The API lists them (`api_toolkit.go:566-567`), parses them into a
valid Target with a **nil error** (`api_toolkit.go:595-598`), installs them into the
**live proxy ruleset**, and answers `200 {"compiled":N}`. The engine's `applyOne` has **no
case for either** (`matchreplace.go:242-253`); both fall to `default: return applyBody(raw)`.

Proven behaviourally at `a619c9a` on a scratch copy:

```
rule:   {request_param_name, literal, "secret" -> "harmless"}
body:   user=admin&secret=hunter2&nonsecret=keep
result: user=admin&harmless=hunter2&nonharmless=keep
                                    ^^^^^^^^^^^^^ unrelated parameter corrupted
```

`request_param_value` yields **byte-identical** output, proving neither is implemented.

Three things make this worth reading twice:

1. **A prior fix created the false confidence.** R1-B reported this class fixed at
   `api_toolkit.go:587-607`, and it genuinely was — for *unknown* `rule_type` values. The
   guard was added for garbage and missed the two **known-but-unimplemented** values in
   the project's own published vocabulary. Both analysts were right; only the reconciliation
   is correct.
2. **The tests pass.** `internal/matchreplace` is green at HEAD. Nothing covers
   accepted-but-unhandled targets.
3. **The code comment is false.** `matchreplace.tsx:17` claims unknown targets "silently
   become a no-op rule." Wrong twice: these two are *accepted*, and `default` is a
   **body-wide rewrite**, not a no-op.

### 3.2 The bug class, generalised

> An API-layer vocabulary — a string→enum parser, a switch on a `type` field, an accepted
> config key — that **admits more values than the engine-layer switch implements**,
> terminating in a **silent non-error `default`**.

This is the highest-yield pattern in the codebase and the sweep method is mechanical:
tabulate the ACCEPTED set against the HANDLED set with `file:line` for both; anything in
`accepted − handled` reaching a non-error default is a candidate; prove each in `/tmp`.

**Surfaces swept clean at `a619c9a`:** intercept, netauth, session, upstream, proxy
options, toolkit codec/hash, session recovery outcomes — several with explicit
refuse-by-default code documented as prior fixes of this same class. The pattern is known
here; the coverage is incomplete.

---

## 4. Built but unreachable (STATE 2 / STATE 3)

Work already paid for that no user can reach. Full detail in
`GAP_ANALYSIS_ENGINE_CAPABILITIES.md`, committed at `a518385`.

- **STATE 2 — Myers diff engine, zero non-test callers.**
  `internal/tools/comparer.go` (`:52,99,109,325`) implements word/byte Myers diff.
  `handleToolsCompare` (`api_toolkit.go:1224`) **reimplements a weaker positional diff**
  (`:1259-1297`) rather than calling it. The frontend documents its own gap
  (`comparer.tsx:254-257`, `data.workbench.ts:183`): it **deliberately hides a granularity
  control** because it believes the backend cannot support one. The backend can. This is
  the cheapest real win in the report — wire the existing engine and un-hide the control.
- **STATE 3 — ffuf content discovery, no UI.** `/api/discovery` (`internal/extscan`) is
  registered (`server.go:772`) and manifest-covered
  (`route_manifest_test.go:207-213`), with **zero references** in `internal/web/ui/src`.
  Positive control applied per TAXONOMY rule 3: sibling `/api/crawl` *is* fully wired,
  ruling out a search miss. Compounding this, burpsy's "Discover" leaf is a
  **deliberately-substituted documentation page** — so the tab exists, the backend works,
  and they are not connected.
- **Swept clean:** the other 22 `internal/**` packages have no zero-importer orphans.

---

## 5. Deliberate divergence — capability gaps, not defects

Graded separately per TAXONOMY rule 7. These are **decisions**, and honest ones:

- **Extender:** 3 of Montoya's 13 `userInterface()` registration points, stated in the
  code at `internal/extension/protocol.go:19-33`.
- **Logger:** narrower than Burp's by design — own-tool traffic only, no MIME/regex/
  scope-only filters.
- **SOCKS + upstream proxy:** Burp's two Network panels merged into one list, stated at
  `settings.tsx:1443-1450`.
- **burpsy-only tabs:** decoder, session, settings. **Decoder is not one of Burp's 15
  tabs** — shipping one is a *divergence*, not parity progress, and should never be
  counted toward a parity number.

Two divergences are **undocumented** and should be recorded as decisions or reversed:
- **Burp AI** — absent, comprehensive, no decision recorded anywhere.
- **Replayer** — absent. Burp's own string table offers little to compare against, so the
  cost of matching it is itself undetermined.

### Honesty is inconsistent, and that is a real defect

`UpstreamProxySection` self-reports `wired`, `attached` and `persisted`, and warns the
user when persistence requires `-db` (`settings.tsx:1610-1624`). That is exemplary.
`PlatformAuthSection` (`settings.network.tsx:44`) works but **discloses no persistence
state at all**. Same product, same release, opposite candour. The good pattern exists —
it just is not enforced anywhere.

---

## 6. Why the trackers are unusable as evidence

The most consequential section. Every item was falsified by an analyst against Burp's own
artefacts.

### 6.1 Four false denominators

| Published claim | Truth | How it broke |
|---|---|---|
| "137 `configPanel*`" | **134** distinct | `grep -c` counted 135 (one duplicate row, `configPanelClosingBehavior`); nobody ran `sort -u`. Also: 26 of the 134 are leaf widgets, so 134 is not a *panel* count either — 108 candidates, ~90 top-level. |
| "960+ `setName()` per `map_root.tsv`" | `map_root.tsv` contains `setName` **exactly once** (line 6678) | **Fabricated provenance.** The real named-widget surface is 1069 unique `setName("literal")` in `out/clean/renamed_final/`, 1059 in `out/readable_strict/`. Right ballpark, wrong corpus, invented citation. |
| "15/15 tool tabs" | **12/15 overlap** | Both sides have 15; they are not the same 15. Burp-only: SCANNER, BURP_AI, REPLAYER. burpsy-only: decoder, session, settings. Counting cardinality instead of intersection. |
| "183 advisories reachable" | 183 bundled, **181 index-reachable** | Two files declare a neighbour's `typeIndex` — in **Burp's own data** (React2Shell→Perl 1052160, Bambda→BCheck 150994944). Honest form: 183/183 bundled, 181/183 index-reachable, 2 shadowed-by-design, reachable by name. |

### 6.2 A false categorical claim, and the trap that ratified it

`BURP_FEATURE_INVENTORY_VS_BURPSY.md` states *"MCP server: Not present in 2026.7.1 = N/A"*.

**False.** Burp 2026.7.1 bundles **306 `io/modelcontextprotocol` classes**, ships
`burp/agentic/tool/McpBurpTool`, and carries its own `burpai.mcp.url`, `BURPAI_MCP_URL`,
`Portswigger-Burp-Ai-Mcp-Nonce`, `setMcpConnectionState` (`map_root.tsv` lines 1575, 1579,
5465, 11575, 11665).

**The trap, and it is the most transferable lesson here:** `grep -rl
modelcontextprotocol out/clean/renamed_final/` returns **0** — and would *confirm* the
tracker. That corpus **excludes bundled `io/**` libraries**. A negative grep in the wrong
corpus is precisely how a false "N/A" became a ratified project fact. Hence TAXONOMY rule
3: **every negative grep requires a positive control.**

### 6.3 The green build does not test the frontend at all

**Re-verified by me directly at `749ddbd`, not taken from an analyst** — this claim is
load-bearing, and the version I inherited understated it.

CI has exactly two workflows (`go.yml`, `release.yml`). `go.yml` gates four things:
`gofmt`, `go build ./...`, `go vet ./...`, `go test ./... -count=1 -timeout 1700s`
(`.github/workflows/go.yml:84-103`). The Go side is gated *well* — CI even provisions
Chrome and installs `ffuf` and `nuclei` with a nuclei template corpus so the live extscan
tests actually run (`go.yml:47,71,76`).

The frontend has **no gate whatsoever.** `burpsy-go/internal/web/ui/package.json` defines:

```
"check": "tsc --noEmit && node scripts/gen-tokens.mjs --check && bun run check:tokens
          && bun run test:scripts && bun run test:lib"
```

Nothing in `.github/**` invokes it. Verified by a repo-wide grep at HEAD for
`bun run check|tsc --noEmit|playwright|behaviour.spec` scoped to `.github/` — **zero
hits**, with the positive control that the same grep finds the Go steps it should.

So the following is written, committed, and **never executed by CI**:

| Ungated check | Scale |
|---|---|
| `tsc --noEmit` | the entire TypeScript frontend |
| `bun test src/lib` | **4 files, 72 test blocks** (`history-derive`, `hotkeys`, `message`, `mime-label`) |
| Playwright e2e | **6 spec files, 46 test blocks** — behaviour 32, routes 5, a11y 3, menubar 2, scope 2, screenshots 2 |
| e2e `tsc --noEmit -p .` | the e2e suite's own typecheck |
| `gen-tokens --check` | design-token drift |
| `check:tokens` | closed-token check |

**118 frontend test assertions exist and none of them gate anything.** Two token-drift
checks and two typechecks likewise.

Two consequences worth separating carefully:

1. Per TAXONOMY rule 4, **not gated is not the same as not working.** These tests may well
   pass right now. Nobody would find out if they stopped.
2. But the honesty consequence is direct: any "verified working" claim in a tracker that
   rests on `tsc` or on `behaviour.spec.ts` rests on **a manual run somebody did once, on
   an unknown commit.** Given §6.4 — one of the seven working-while-broken items *was* a
   typecheck step that had never once executed — that is exactly the evidence class this
   project has already been burned by.

The asymmetry is the actionable part. This is not a project without testing discipline;
the Go half has real gates including live-network tests. The frontend half has 118
assertions sitting outside the wall. Gating `bun run check` is one line of YAML.

### 6.4 The pattern

Seven items were recorded as working while broken, and **each was internally
self-consistent** — which is why review did not catch them: a MIME filter with six
consumers bound to a field nothing populated; a typecheck step that had never once
executed; a racy test committed green; issue counts summing to 15 of 21; an advisory
catalogue serving the wrong advisory for two entries; match/replace silently rewriting
bodies on accepted input; and a measurement taken against the working tree and reported as
committed state.

**A tick means a control exists. It has never meant the control behaves.** Treat every
tracker row as a hypothesis to falsify.

### 6.5 The antidote already exists in-tree

The most useful thing found in this audit is not a gap. It is that **this team already
solved the accepted-but-unhandled problem, correctly, and did not propagate the solution.**

`internal/scanner/audit.go:567-580` documents a single-source-of-truth table
(`builtInConfigKeys`) from which both the engine overlay and the operator-facing key
listing are derived, precisely so the two cannot drift — with the reasoning stated: a
hand-maintained second copy "drifts silently, because a listing that is missing a key
still renders." `Test_every_built_in_config_field_has_a_key_row` (`audit_test.go:513`)
reflects over the struct and fails when a field has no row, because "a field with no row is
neither applied nor listed."

That is a structural fix for exactly the defect class of §3. The match/replace vocabulary
two packages away has an API list, a separate engine switch, and no test binding them —
and carries a live traffic-corrupting bug as a direct result.

The implication for planning: the constraint here is **not** engineering judgement, which
is demonstrably good. It is that good local decisions are not being propagated into
conventions. That is a cheaper problem to fix than a skill gap, and §9.1 is the first
instance.

---

## 7. PENDING — wave 2 in flight

Four workstreams were running when this consolidation was written. Their absence is
recorded rather than papered over:

- **W2 — scanner reality check.** Can the 183-row issue catalogue actually *fire*? Bundled
  and index-reachable are established; **firing is not.**
- **W3 — UI surface parity.** Which burpsy controls are decorative? Directly tests the
  gap between existence and behaviour that §6 says the trackers cannot see.
- **W4 — test-suite honesty audit.** What does the green build actually prove? Extends §6.3
  from gates to test content.
- **W5 — STATE 2/3 sweep** across all 37 internal packages. R1-C swept 22 for
  zero-importer orphans; this completes it.

Until these land, this report **understates** the gap. Every wave so far has found defects
in surfaces the previous wave called clean.

---

## 8. NOT DETERMINED

Named explicitly per TAXONOMY rule 6, rather than guessed:

1. **~87 of ~90 Burp top-level config panels** were never individually behaviour-verified.
   **The largest open denominator in this analysis.** Only 3 were checked.
2. **Whether the 183 advisories can fire.** Bundled ≠ reachable ≠ firing. W2 pending.
3. **Field incidence of the match/replace STATE 5 defect.** It is reachable via the public
   API but not from the UI dropdown (only 5 targets, `matchreplace.tsx:18-23`). Whether any
   extension, script or CI job actually sends those values is unknown.
4. **Intruder "section-marker parsing"** — no such distinct feature found in
   `internal/intruder`; only the existing `§marker§` payload-position parsing, already
   wired via `/api/intruder/run`. Flagged rather than guessed.
5. **Cost of Replayer parity** — Burp's string table gives too little to size it.
6. **Two wave-1 workstreams produced no recoverable output** ("verify claimed-working
   features actually behave", "audit the other four reports for unsupported claims"). Their
   findings are lost, not absent. W3 and W4 re-cover that ground.
7. **The Collaborator mint-payload fix** is recorded as verified in a surviving summary,
   but the summary was truncated before its evidence. The claim stands unproven here.

---

## 9. What I would do next, in order

1. **Fix the match/replace STATE 5 defect by propagating a pattern this codebase already
   invented.** Do not design a new guard — copy `internal/scanner/audit.go`. That file
   solves precisely this problem: `builtInConfigKeys` is the single table both the engine
   overlay and the operator-facing listing read from, its comment
   (`audit.go:567-580`) explains that a hand-maintained second copy "drifts silently,
   because a listing that is missing a key still renders," and
   `Test_every_built_in_config_field_has_a_key_row` (`audit_test.go:513`) reflects over the
   struct and **fails** if a field has no row — "a field with no row is neither applied nor
   listed." It even distinguishes *this preset leaves the budget alone* from *this engine
   has no budget*.

   That is the exact antidote to the accepted-but-unhandled bug class, written by this
   team, sitting two packages away from the defect it would have prevented. Apply it to the
   `rule_type` vocabulary: one table, engine switch and API vocabulary both derived from
   it, one reflective test asserting `accepted == handled`. This makes the bug class
   **structurally unrepresentable** rather than fixed case by case — and it is the single
   highest-leverage change in this report.
2. **Gate `bun run check` and the Playwright e2e suite in CI.** 118 frontend test
   assertions, two typechecks and two token-drift checks are committed and never executed.
   The Go half of this project has real gates including live `ffuf`/`nuclei` tests; the
   frontend half has none. This is the highest value-per-line change available — the tests
   are already written.
3. **Wire the Myers diff engine** into `handleToolsCompare` and un-hide the granularity
   control. Deleting a weaker reimplementation is a negative-diff improvement.
4. **Decide about `/api/discovery`** — give it a UI or delete it. A working ffuf backend
   sitting behind a documentation page is the worst of both: maintenance cost, zero user
   value.
5. **Record the Burp AI and Replayer omissions as explicit decisions.** They are almost
   certainly correct calls; being undocumented is what makes them debt.
6. **Delete or re-derive every ratio in the existing trackers.** Four of four checked
   denominators were wrong. The prior is now that an unverified number in this repo is
   wrong, and a wrong number is worse than none.
7. **Enumerate the ~90 config panels** and close item 8.1. Until then, the config-surface
   gap is genuinely unmeasured.
