# Burp-Parity Gap Analysis: burpsy vs Burp Suite 2026.7.1

**Status:** COMPLETE. All six workstreams landed and folded in (W0-W6b).
**Baseline for this final pass:** `638c480`. Findings proven at earlier SHAs are labelled
with the SHA they were proven at, and re-checked at `638c480` where status could have moved
— one had (§3.1).
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

Second, and more important than any count: **published claims about this codebase cannot be
used as evidence — including this report's own.** Across four waves, analysts falsified
**five denominators**, **one categorical feature claim**, and **one API route that never
existed**, and found defects the trackers recorded as working. The failure mode is consistent
— a tick asserts that a control **exists**; nothing measured that the control **behaves**.

**Three of those falsifications are ours.** The fifth denominator (§6.1a), the phantom route
`/api/proxy/matchreplace` that four documents cited as observed (§3.1), and a false "never
used" claim that under-priced a §9 fix by a whole tier (§6.8). We then audited our own
citations and found **1 false claim in 13 sampled** (§6.8). This is the strongest evidence
available that the failure mode is **structural** rather than a previous team's carelessness:
a team explicitly hunting this exact error, with a written rulebook, still committed it three
times. §6 documents the mechanism, because it is the finding most likely to cause the next
wrong decision.

Third, the counterweight, which is real and which a hostile reading would miss: **where
burpsy has not built something, it overwhelmingly renders nothing rather than something
fake.** Zero stubs across 85 config panels (§2.1); one decorative control across ~80 tool
controls, against twelve limitations the UI discloses in its own copy (§5.1). And **the
scanner genuinely works** — 58 checks, 64 real HTTP probes, real High-severity findings,
proven by running it (§3.0). The defects found are **few and structural, not many and
sloppy** — which is why §9 recommends making a bug class unrepresentable rather than
auditing harder.

Fourth, the sentence that ties the STATE 5 defects together and is the real thesis of
this report: **burpsy's characteristic failure is reporting success for work it did not
do.** An audit that never sent a header probe says `Audited`. A discovery sweep that POSTed
to `/robots.txt` and got a 405 says `state=audited, skipped=0, note: None`. A session
validity rule that never evaluated its second condition says `Valid`, and the authenticated
scan that depends on it quietly runs logged out (§3.1a). A thirteenth Repeater tab opens
successfully and destroys the first (§6.7b). None of these throw, none log, none show a
warning. That is a far more dangerous property in a security tool than any missing feature,
because **a missing feature is visible and a false clean is not.**

And the same sentence describes this report's own three errors, which is why §6.8 and §10 are
in it. A phantom route, a "never used" symbol that was used, and a reconstruction that inverted
a finding are all **reporting success for work we did not do** — we did not open the endpoint,
did not walk to the producer, did not re-read the evidence. The pathology under audit turned
out to be a property of *measuring under deadline*, not of this codebase.

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
| **Config panels** | 41 wired (29 plain + 12 caveated) | **85 top-level** (derived from 134 identifiers by a 4-step documented collapse) | **41/85 wired (48%)**, 36 absent, 3 unwired, 5 unreachable, **0 stubs** | High — both sides recounted independently by two analysts |
| **Internal packages reachable** | 29 / 37 routed; 1 wholly unreachable | n/a — burpsy-internal measure | **1 STATE 2 package, 4 STATE 2 sub-capabilities, 2 STATE 3 routes** | High — `go list` import census, not grep |
| **Scanner: does it fire** | 58 active checks, 64 real probes, High findings emitted | n/a | **STATE 4, all 3 launch paths** | High — **behaviourally proven**, real targets, pasted output |
| **Scanner: check breadth** | 183 descriptors registered, **58 admitted at defaults** (3 active injection / 5 active discovery / 50 network-free) | **no honest denominator exists** in Burp's shipped resources | **58/183 admitted; no N/M vs Burp is offered** | High on burpsy side; Burp side deliberately refused |
| **Scanner: insertion points** | **3 of 8** at defaults, 5 of 8 all-on, **0 of 6** relocation types | 8 types + 6 relocation | **3/8**, though `bcheck` implements all 15 kinds | High — greps positive-controlled |
| **Repeater: concurrent isolated tabs** | isolated tabs + per-tab history, **capped at 12 silently** | `secondarySuiteTabBar`, uncapped | **parity on isolation**; STATE 5 on the cap (§6.7b) | High — **behaviourally proven**, store driven directly |

The config-panel row moved from "NOT DETERMINED" to a **fully mapped 41/85** this wave — it
was the largest open item in the entire analysis and is now closed. §2.1 reads the
distribution; the row-by-row table is in `W6-config-panels.md`.

The denominator was derived as follows and then **independently re-derived, name for name, by
a second analyst** — the only figure in this report to get that treatment, and it earned it by
being the one four prior trackers got wrong.
W6 collapsed Burp's 134 distinct `configPanel*` identifiers in four reproducible steps:
25 leaf widgets removed by suffix (→109), mechanical prefix collapse of documented
sub-controls (→95), manual semantic collapse of two Intruder payload/grep-extract clusters
(→87), and exclusion of `configPanelTitle`/`configPanelDescription` as per-panel template
chrome (→85). **If you reject step 4 the denominator is 87; if you reject step 3 as well it
is 95.** All three are reproducible from the commands in `W6-config-panels.md`. This report
uses 85 and says so at every total — which is the standard the four falsified denominators
in §6.1 failed to meet.

### 2.1 The config surface, fully mapped — and what its shape says

85 panels, every one classified, with positive controls for every negative grep and pasted
output for four behavioural test runs.

| State | Count | Share |
|---|---|---|
| 0 ABSENT | **36** | 42% |
| 1 STUB | **0** | 0% |
| 2 UNWIRED | **3** | 4% |
| 3 UNREACHABLE from UI | **5** | 6% |
| 4 WIRED | **41** | 48% (29 plain + 12 with a recorded caveat) |
| 5 BROKEN | **0** *(none proven — not a correctness claim)* | 0% |

The **36 absences are stable under all three candidate denominators** (85, 87, 95); only the
wired/unwired split moves. That robustness is worth more than the precision of any single
percentage.

**Zero stubs is the healthiest number in this report.** Where burpsy has not built a config
panel it renders **nothing** — not a screen that looks live. The high absence count is
therefore absence taken honestly rather than laundered into a stub, and it is the same
discipline §5.1 finds in the tool pages. A 42% absence rate with 0% stubs is a substantially
better position than a lower absence rate padded with placeholders.

**The absences are mostly structural, and they describe what burpsy chose to be:**
Burp-the-desktop-app panels with no browser meaning (closing behaviour, temp-file location,
project backup — 5 rows); the JVM extension estate (Java/Python/Ruby environments — 4 rows,
already covered by the self-documented 3-of-13 Montoya gap); message-editor and Inspector
*display* panels where the capability exists and only its *configurability* is missing (8
rows). Those are not parity debt in any meaningful sense.

**Two absences are genuine capability holes, and one is undisclosed:**
- **WebSocket interception** (rows 53–55). `grep 'WebSocket' internal/intercept/` → 0 hits,
  positive control applied. WS traffic is proxied, recorded and viewable but **can never be
  held**, and no WS match/replace target exists.
- **TLS negotiation control** (row 80). The sender's only `tls.Config` sets neither
  `MinVersion` nor `CipherSuites` — burpsy cannot be pointed at a legacy-TLS target, and
  cannot be constrained away from one. That is a real testing limitation and **nothing in
  the UI says so.**

> **RETRACTION 2026-08-27 — the "3 unwired rows" are 2.** Row #12 (`inspectorPanelState`/`inspectorDock`) is fully wired: read at `ui/ui/inspector.tsx:475,550,551`, written at `:476,477`, applied at `:769,784`. The greps that reported zero readers were blind to that single file, which held a literal NUL byte — ugrep classified the 826-line source as binary and reported no matches while exiting 0, with no warning. #27/#28 were real and are now wired. The paragraph below is left as written; treat every #12 claim in it as withdrawn.

**The 3 unwired rows are the TAXONOMY failure mode in its purest form** — code that reads as
finished, is commented as finished, is *named after the Burp panel it implements*, and has no
caller. `inspectorPanelState`/`inspectorDock` are declared, defaulted, given setters, and
persisted to localStorage **under a comment explaining why they deserve persistence** — and
nothing in 13,354 lines of React reads them. The whole `PayloadGenerator`
(`internal/intruder/intruder.go:346-387` — numbers, file lists, custom lists, plus a committed
regression fix for an inverted-range panic) has zero non-test callers; **Intruder takes pasted
text only.** Note what makes these diagnosable: `repeaterGroups` sits in the same store file
with identical persistence treatment and *is* read. The difference is invisible from the
store and only visible from a caller grep — which is exactly why §6.1a happened.

### 2.2 The finding an operator would actually be burned by

**`Export configuration` is silently partial.** It downloads a file named
`burpsy-config.json` containing scope rules, intercept lists and session rules — and nothing
else (`internal/web/api_config.go:48-67`). Network settings, proxy options, match/replace
rules, resource pools, schedules, scanner config, platform authentication and client
certificates are **all dropped without a word**. The menu item does not say "partial," the
file does not record what it omitted, and the import result counts only the three sections it
knows about.

This is not STATE 5 — nothing behaves incorrectly, and it is not claimed as a correctness
defect. It is worse in practice than most STATE 5s: carrying that file to a new machine and
believing your engagement configuration travelled with it is a mistake the product actively
does nothing to prevent, and the failure is discovered later, during work, when the missing
settings matter. **Highest-value single fix in the config surface**, and it is a
one-line-per-subsystem change plus an honest manifest.

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
contract promises. **Confirmed live count: 5** — three in the scanner (§3.0.3), one in
session handling (§3.1a), and one in the Repeater UI (§6.7b, the silent 12-tab eviction),
every one proven by running it and pasting real output. A sixth (§3.1) was live when wave 1
proved it and has since been fixed; it is retained because it is this report's best worked
example of the failure mode and because the fix is exemplary.

**The count went up in the final wave, and that is the number to pay attention to.** §6.7b was
found by an agent sent to answer a *positive* question — "do Repeater tabs isolate properly?"
— which they do. The defect was adjacent to the answer. Every wave of this analysis found
STATE 5 defects in surfaces the previous wave had cleared, including the wave that went looking
for good news. **5 is a floor.**

**Start with §3.1a.** It is the most damaging finding in this report, it was nearly lost
between two contradictory records of the same workstream, and it is live at HEAD.

**Read §3.0 first.** The scanner's headline is *positive*, and the STATE 5 findings below
are defects in a working engine, not evidence of a hollow one.

### 3.0 The scanner fires — this is the report's biggest positive finding

W2 stood up real targets and ran real scans. `POST /api/audit/0` on a proxied exchange
returned `{"active_checks": 58, "summary": "10 found, and nothing was skipped, errored or
gated"}`, and **the target's own request log showed 64 genuine HTTP probes** — `?q='`,
`?id='`, `q="><svg id=zxss… onload=alert(1)>`, `q=../../../etc/passwd`, traversal payloads
spliced into cookies. Two **High** findings (SQL injection on query `id` and body `user`;
reflected XSS on query `q`) reached `/api/issues`. The live-audit toggle works end to end
(issues 26 → 38 from one proxied URL, no further user action). **All three launch paths are
STATE 4.**

That matters because §2's 4/77 config finding could easily be misread as "the scanner is a
shell." It is not. It is a working scanner that cannot be configured and cannot be aimed.

**But the check count is 58, not 183.** All 183 registry descriptors are runnable and none
are declined (`check_registry_declined.go:26-28` returns empty) — and shipped defaults turn
on only 8 of 21 family switches (`scanner.go:230-246`), admitting **58**. The server says so
itself: `"active_checks": 58`. Of those 58: **3 genuine active injection checks, 5 active
discovery, 50 network-free response analysers.**

W2 **refused to state a Burp-side check-count denominator**, because Burp's shipped
resources do not contain an honest one (`selected_issues` enumerates only 15 distinct
`type_index` across all presets). That refusal is correct and is the behaviour §6 asks for.
So there is **no "N of M checks" ratio in this report** — anyone who publishes one has
invented the M.

**And "183 runnable descriptors" must never be restated as "183 checks work."** W2 drove
roughly **11** distinct checks to a real finding; the other ~170 evaluators were never
individually exercised. That is the sixth-false-denominator trap, and it was avoided by an
inch.

### 3.0.1 The insertion-point gap is worse than the config gap

§2 shows burpsy cannot be *told* where to inject. W2 shows where it actually injects:
**3 of Burp's 8 insertion-point types at defaults, 5 of 8 with everything on, and 0 of the 6
relocation types ever.**

The damning part is that the capability exists. `bcheck/insertion.go` implements **all 15
kinds** correctly — the scanner simply never asks for them.
`DefaultProbeInsertionKinds` (`probe_harness.go:40`) is 4 kinds, and the only default-on
checks walk `coreInjectionKinds` = **3** (`checks_core_injection.go:52`). Greps for the
other 11 kind strings return 0 in production code, positive-controlled against `bcheck` and
`internal/intruder/points.go`.

**burpsy's Intruder covers Burp's insertion-point surface; its Scanner does not.** The same
repo contains both. This is STATE 2 for 11 of 15 kinds, and it is the single largest
capability gap in the scanner.

### 3.0.2 burpsy's "passive scanning" is not passive

The largest behavioural divergence from Burp that W2 found. **50 of the 58 default checks
are network-free analysis that only runs when a user explicitly launches an audit on a
specific exchange.** Merely proxying a URL yields 5 findings, from a legacy hardcoded
`PassiveScanner` (`scanner.go:669`, `capture.go:298`). The *same exchange* after an audit
yields 15.

In Burp, passive analysis of proxied traffic is continuous and automatic. In burpsy, most of
what looks like passive scanning is audit-gated. An operator who browses a site and reads
the Issues view is seeing a third of what the engine could already tell them, with nothing
indicating the rest is one click away.

### 3.0.3 The three scanner STATE 5 defects

**(a) Host-discovery probes reuse the base exchange's HTTP method — default-ON, silent.**
`sendTestRequestFull` (`scanner.go:507-539`) builds probes with `Method: exchange.Method`
(`:515`) — the method of whatever request happened to be the audit's base. Proven: two
identical origins serving `GET /robots.txt → 200` and `POST /robots.txt → 405`. From a GET
base exchange burpsy sent `GET /robots.txt` and reported **`Robots.txt file`**; from a POST
base it sent `POST /robots.txt` and reported nothing — while the item's own outcome read
`state=audited, ran=58, skipped=0, send_failures=0, note: None`.

**A silent miss reported as a clean, complete audit, in a default-ON family.** Six more call
sites share the primitive, including — with real irony — the HTTP-PUT check's *verification
GET* (`checks_discovery.go:185`), whose own finding text says "a subsequent GET of the same
path."

The practical consequence: **anyone testing an API through the proxy browses mostly POSTs**,
so burpsy POSTs to `/robots.txt`, `/openapi.json`, `/swagger.json` and ~20 other static
paths and reports clean on every one.

And the correct primitive already exists **as the immediately next function**: `sendTestRequestBody`
(`scanner.go:546`) takes an explicit method, and its comment (`:541-545`) says it exists
"for probes that need a specific method … rather than the exchange's own method." This is
the §6.5 pattern again — *the antidote is in-tree and unpropagated.*

This also violates a rule the package wrote for itself. `checks_injection.go:6-11`:
***"'we could not look' is not 'we looked and found nothing'."*** Here it is, silently, at
defaults.

**(b) The same advisory reported twice, at two severities.** Grouping `/api/issues` by
`(url, advisory.type_index)`: `005009a0` appears as both `Low | Missing X-Frame-Options
Header` and `Informational | Frameable response (potential Clickjacking)` on the same URL,
across three URLs. Issue counts are inflated and one condition lands in two severity
buckets — which corrupts any triage that sorts by severity or counts by total.

**(c) Header insertion points labelled "Audited" while nothing probes them.** The ledger
enumerates with 4 kinds (`audit_engine.go:849`) but admitted checks walk 3, so
`User-Agent`, `Accept` and `Proxy-Connection` display **`Audited`** when zero of 36–64
probes touched a header. The documenting comment's own sentence, "the four kinds the native
injection evaluators walk," is false at defaults.

> **Correction (verified at `210f73f`).** This subsection originally added: *"the status
> vocabulary already contains the right answer — `AuditItemPointNoChecks`
> (`audit_items.go:188-190`) — and it is never used."* **Both halves of that are wrong**, and
> the corrected version is a sharper finding with a much larger fix estimate.
>
> **It is used, on a live path.** `AuditItemLedger.Resolve` (`audit_items.go:525`, a public
> method) → `resolvePoints` (`:574`) → `pointStatusFor` (`:601`) returns
> `AuditItemPointNoChecks` at `:602-603` whenever `row.UnitsPlanned == 0`. The original claim
> came from grepping the identifier and reading the declaration and the `switch` arms as the
> only hits — **trap #1 again**: the producer was two frames up the call chain from where we
> looked.
>
> **And "just use it" cannot fix (c).** `UnitsPlanned` is an **item-level** field
> (`:343`). `AuditItemPoint` (`:252-262`) carries only `Kind`, `Name`, `Status`, `Detail` —
> **no per-point probe accounting at all**. So `pointStatusFor` decides one status per *item*
> from item-level evidence, and `resolvePoints` then stamps that single status onto **every**
> point in the row (`:576-582`). The structure is therefore *incapable* of distinguishing
> "this point was probed" from "a sibling point was probed": when 36-64 probes ran, every
> enumerated point gets `AuditItemPointCovered` → **`Audited`**, including the three header
> kinds nothing touched.
>
> **Consequence for §9 item 3.** The right value existing is not the fix. Reporting (c)
> honestly requires **adding per-point probe accounting to `AuditItemPoint`** and keying the
> status off it — a data-model and plumbing change, not a status swap. The defect is exactly
> as real as described; the repair is a tier more expensive than we first priced it, and a
> fixer who trusted the original sentence would have gone looking for a missing `case` that
> was never the problem.
>
> Note what this near-miss demonstrates: the item ranked **#3 by harm** and was described as
> nearly free. Under-pricing a fix is its own kind of false claim — it is how real defects
> get deferred, because the estimate stops matching the work and nobody re-checks.

All three share one shape, and it is the shape of this entire report: **the product reports
success for work it did not do.**

### 3.0.4 Two scanner STATE 2 items

- **`CheckPhase` is a six-value taxonomy with one value ever assigned** (`PhaseActive`).
  Burp's 5 scan types cannot be represented at all while this stays unpopulated.
- **`NativeCheckCoverage()` — the per-check operator report — has zero non-test callers.**
  Consequence: a default burpsy tells the operator **"no passive checks loaded"** while 58
  checks are running. The one surface that would have exposed everything in §3.0.1–3.0.3 to
  a user is the surface nobody wired.

### 3.1 match/replace param targets silently rewrote the whole body — **FIXED at `638c480`**

**Status correction, and it is a correction to *this report*.** W1 proved this defect live at
`a619c9a`. It was fixed at **`638c480`** while this analysis was running, and §3.1 continued
to say "LIVE" for two waves after that stopped being true. W4 caught it. **I verified both
halves myself before accepting the correction** — this report has now been wrong about a
defect's status in both directions, and neither error was caught by re-reading; both were
caught by someone going and looking.

The fix is better than the one I reverted, and the difference is instructive:

- `applyOne`'s `default:` now returns **`nil`**, not `raw`
  (`internal/matchreplace/matchreplace.go:242-272`). The comment explains why `raw` was
  wrong: it is non-nil and therefore reads as "the rule fired," which "would have marked the
  message changed, counted a modification that never happened, and run `fixContentLength`
  over an untouched body — **trading a wrong rewrite for a wrong count.**" That is precisely
  why commit `9194df6` was reverted at `8700e2e`, and the revert was correct.
- The API now **refuses the two targets by name**, not as unknown
  (`internal/web/api_toolkit.go:576-579, 613-637`), because "unknown rule_type would be a
  lie: the Target exists, `targetsDir` routes it, and `matchReplaceTargetName` can name it.
  What is missing is the applier."
- Three tests guard it, including `internal/web/matchreplace_target_test.go:139`.

**So this is now a CAPABILITY GAP — 5 of 7 rule_types implemented — not a defect.** Removing
it took the STATE 5 count to **3, all in the scanner**.

> *(That was the count when this subsection was written, and it did not stay true: §3.1a's
> session defect was recovered afterwards and §6.7b's Repeater eviction was found in the final
> wave, so **the live count is 5** — see §3. Left visible rather than silently overwritten,
> because a count that only ever moved **upward**, in a report specifically hunting for this
> category, is itself the finding.)*

The author's own commit comment is the most valuable artefact this analysis produced, because
it diagnoses the reasoning error rather than just the bug: *"I added those two here in
`4469cf1` and it was wrong. My justification was that 'the engine already matches on them
(matchreplace.go:129)' — but that line is `targetsDir`, which says which direction a target
belongs to. The applier is `applyOne` … **I reintroduced the very defect the rest of this
comment describes, by verifying against one function and asserting about another.**"*

That is the same error as §6.1a — verifying at the wrong layer — committed independently by
a developer and by this analysis's own wave 1, in the same codebase, within days. It is
strong evidence the failure is structural, not personal.

**The original finding is preserved below**, because a fixed defect is still evidence about
how this system fails, and because the fix's quality is only legible against it.

Detail and proof: `W1-broken-behaviour.md`. Summary:

> **Route-name correction (W7b, verified independently at `415564e`).** Every prior telling of
> this finding — this report and three evidence files — called the endpoint
> **`/api/proxy/matchreplace`**. **That route does not exist and never did.** The real routes
> are `/api/tools/rules` and `/api/tools/rules/test` (`web/server.go:789-790`). The phantom
> path appears in **zero** non-markdown files in the repo: it existed only in our own prose,
> where it propagated by copying.
>
> Control, because a negative grep needs one: `/api/proxy/*` is a real prefix — `passthrough`
> and `options` live there (`server.go:740-741`) — so the search would have found the route
> had it existed. This is a **sixth false artefact, and the third of ours** (§6.1a, §6.8,
> here). It is also the most embarrassing kind: a plausible-sounding API path, invented by
> nobody in particular, that four documents then cited as though observed. Note what saved it
> from being caught earlier — nothing did. It was found only because someone was asked to go
> *use* the endpoint rather than describe it.

The endpoint (`/api/tools/rules`) accepts `rule_type` values `request_param_name` and
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

`request_param_value` yielded **byte-identical** output, proving neither was implemented.

Three things make this worth reading twice:

1. **A prior fix created the false confidence.** R1-B reported this class fixed at
   `api_toolkit.go:587-607`, and it genuinely was — for *unknown* `rule_type` values. The
   guard was added for garbage and missed the two **known-but-unimplemented** values in
   the project's own published vocabulary. Both analysts were right; only the reconciliation
   is correct.
2. **The tests passed.** `internal/matchreplace` was green throughout. Nothing covered
   accepted-but-unhandled targets — which is exactly what the three new tests now do.
3. **The code comment is false.** `matchreplace.tsx:17` claims unknown targets "silently
   become a no-op rule." Wrong twice: these two are *accepted*, and `default` is a
   **body-wide rewrite**, not a no-op.

### 3.1a Session validity rules evaluate only their first stated field — **LIVE, and the worst defect in this report**

**Provenance matters here.** Shared context `parity_w1` recorded this as W1's *worst*
finding. `W1-broken-behaviour.md` — reconstructed by the same analyst after the workspace
reap — says the opposite: *"1 confirmed STATE 5 in scope. All other accepted-vs-handled
tables across `intercept`, `netauth`, `session` … came back clean."* Two records of one
workstream, in direct contradiction, and **the finding appeared in neither the master report
nor any surviving evidence file.** It was very nearly lost outright.

**I resolved it by running it myself at `638c480`.** Production tree untouched; scratch copy
of the module at `/tmp/bgproof`.

`ValidityRule.Evaluate` (`internal/session/session.go:38-118`) is a **first-stated-field-wins
if-chain**, not a conjunction. `StatusIs` is checked first and **returns unconditionally** —
every later field is dead code for that rule.

The web API unmarshals free-form operator JSON straight into the struct
(`internal/web/api_session.go:337-341`), so a rule stating both conditions is accepted:

```
$ go test ./internal/session/ -run TestCTO -v

=== RUN   TestCTO_FirstFieldWins_LoggedOutPageReportsValid
    rule wire form : {"status_is":200,"body_not_contains":"Please log in"}
    response       : status=200 body="<html><body>Please log in to continue</body></html>"
    Evaluate()     : 0                        <-- Valid (session.go:22, Valid = iota)
--- FAIL: DEFECT CONFIRMED: body_not_contains never evaluated

=== RUN   TestCTO_Control_AllComposesCorrectly
    All{} composition on the same input: 1    <-- Invalid, the correct answer
--- PASS
```

**The operator writes "the response must be 200 **and** must not say 'Please log in'." The
engine reads only the first half and reports the logged-out login page as a valid session.**

Why this outranks everything else here:

1. **The blast radius is every authenticated finding.** `recovery.go:198,325,375,381` gate
   re-login on `Evaluate(...) == Valid`. A rule that always says Valid means the scanner
   never re-authenticates — so **an authenticated scan silently degrades into an
   unauthenticated one**, and every check in §3.0 runs against logged-out responses. The
   audit still reports `state=audited, skipped=0`. This is §1's thesis at its most dangerous:
   a clean bill of health over work that never happened.
2. **The correct construct exists and works.** `All{}` composes properly — the control proves
   it. A flat two-field rule is the intuitive way to write it and the one that silently fails.
   Nothing refuses it, and `dtoToRule`'s own comment says a malformed validity block is
   refused "because a broken validity rule silently re-logging in on every request would be
   worse than an error." **The refusal it describes is exactly the one that is missing.**
3. **It survived a workstream, a reap, a reconstruction and two consolidation passes** — and
   was recovered only because §1 cited it from memory and the citation didn't match any
   evidence. That is luck, not process.

**Fix shape:** either evaluate all stated fields conjunctively, or refuse a flat rule with
more than one field set and tell the operator to use `All{}`. The second is smaller, is a
400 rather than a behaviour change, and matches the refusal pattern `targetToCategory`
already uses (§3.1).

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
### 4.1 The sweep is now complete — all 37 internal packages (W5)

Wave 1 swept 22 packages by grep. W5 completed it across **all 37**, using `go list` — the
compiler's own import graph — rather than grep, which is the right instrument for this
question and caught a case grep would have missed.

| Category | Count | Which |
|---|---|---|
| STATE 2, whole package | **1** | `internal/jsexec` |
| STATE 2, sub-capability | **3 new + 1 inherited** | tlsprobe cipher/protocol analysis; `advisory.Catalogue.ByName`; http2 `Malformation` vocabulary (residue); `tools/comparer.go` (inherited) |
| STATE 3 | **1 new + 1 inherited** | `/api/intercept/drop-all` (new); `/api/discovery` (re-confirmed independently) |
| STATE 5 found by W5 | **0** | true when W5 ran; the live count has since risen to **5** (§3) |
| Packages reached by ≥1 route | 29 / 37 | |
| Packages with no route, by design | 8 / 37 | alpn, domexec, httputil, jsexec, tlsprobe, upstreamtest, vulnapp, web |
| Routes with zero production-UI reference | **4 / 81** | 2 documented legacy aliases + the 2 STATE 3 rows |

**The coherence check is what makes this table trustworthy.** Every per-package UI shortfall
is fully accounted for by those same 4 unreferenced routes — no package has an unexplained
gap. That is a property the data either has or does not have, and it has it.

**`internal/jsexec` — STATE 2, whole package, and honestly labelled.** 14 exported symbols,
316 lines, a working goja-backed prototype-pollution sandbox. Zero importers of *any* kind
— the only package in the repo with neither a production nor a test importer outside itself.
Its single external mention is a **string literal in a coverage table**
(`internal/scanner/infra_coverage.go:274`), not an import. Critically, that file's own header
(`:1-17`) says a row appearing there means *"we now have the machinery"* and explicitly **not**
*"we now detect this,"* calling the conflation "exactly the dishonest counting this project
forbids." So jsexec is a **self-declared** built-but-unwired primitive. Report it as STATE 2
capability debt; **do not report it as a false claim.** The distinction matters and §6 would
be wrong to absorb it.

**`/api/intercept/drop-all` — STATE 3, new.** Backend complete: routed at `server.go:758`,
in the manifest at `route_manifest_test.go:281`, handler
(`api_intercept.go:130-145`) calls `intercept.DropAll` and returns a real count. The UI never
calls it. The positive control here is unusually strong — all three sibling
`/api/intercept/*` routes match on the identical grep in the identical directory, and
`drop-all` alone is absent. That is a UI path never built, not a search miss.

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

### 5.1 The UI is unusually honest — 1 decorative control in ~80 (W3)

This is the report's main **counter-finding**, and it is load-bearing, because a gap
analysis that only finds bad news has stopped measuring and started arguing.

W3 swept **24 pages and ~80+ distinct controls** looking for *decorative controls* — a
control that renders, accepts input, returns 200, and whose value the backend never reads.
That is the UI-layer form of the §3 bug class and the most user-hostile defect a tool like
this can have.

**It found exactly one.** Every other writable control traced to a Go handler that reads and
acts on that exact field, or the UI **says so in its own copy**.

**The one:** Decoder's *"guess base64 / hex alphabets"* checkbox
(`decoder.tsx:104-109`) serializes to `guess_alphabets` (`data.workbench.ts:120-134`),
unmarshals into `req.Guess` (`api_toolkit.go:938`), and is passed to `smartDecode`
(`:947`) — which **takes the parameter and never references it in the body**
(`:1000-1024`). The four decode layers run in the same fixed order either way. It fails
silently, with a 200 and plausible-looking output, on a security-analysis toggle. Fix or
delete it; both are small.

**The other 12** are limitations the UI **discloses to the operator itself**, and they are
not defects — they are the opposite:

- `comparer.tsx:254-259` states the server only does byte-level diffing and **deliberately
  omits a granularity selector "rather than one that silently does the same thing."**
- `matchreplace.tsx:18-24` restricts the dropdown to the 5 implemented targets.
- `settings.tsx:1929-1962` names per-tool resource bounds that have **no effect** (crawl's
  sequential loop cannot honour concurrency > 1) rather than implying uniform enforcement.
- `dashboard.tsx:207-211` disables the unbuilt scan cards with "not built yet."
- `extensions.tsx:183-190` shows "needs a message" instead of a broken Run button.
- `settings.tsx:485-508` marks the DOM engine read-only **and says why** (race risk).

That is a team that has internalised the difference between *exists* and *behaves* **at the
UI layer** — the exact discipline §6 finds missing at the tracker layer. The disclosure
habit is real and should be protected; it is the cheapest quality asset this project has.

**But it is a convention, not a mechanism, and conventions decay.** `UpstreamProxySection`
self-reports `wired`/`attached`/`persisted` and warns when persistence requires `-db`
(`settings.tsx:1610-1624`) — exemplary. `PlatformAuthSection` (`settings.network.tsx:44`)
works but **discloses no persistence state at all**. Same product, same release, opposite
candour. Nothing enforces the good pattern, so the gap between the best and worst surfaces
will widen, not close.

**The honest reading of §3 + §5.1 together:** the defects found are *few and structural*,
not *many and sloppy*. That is a much better position to be in — and it is why the
recommendation in §9.1 is to make the bug class unrepresentable rather than to audit
harder.

---

## 6. Why the trackers are unusable as evidence

The most consequential section. Every item was falsified by an analyst against Burp's own
artefacts.

### 6.1 Five false denominators — the fifth is ours

| Published claim | Truth | How it broke |
|---|---|---|
| "137 `configPanel*`" | **134** distinct | `grep -c` counted 135 (one duplicate row, `configPanelClosingBehavior`); nobody ran `sort -u`. Also: 26 of the 134 are leaf widgets, so 134 is not a *panel* count either — 108 candidates, ~90 top-level. |
| "960+ `setName()` per `map_root.tsv`" | `map_root.tsv` contains `setName` **exactly once** (line 6678) | **Fabricated provenance.** The real named-widget surface is 1069 unique `setName("literal")` in `out/clean/renamed_final/`, 1059 in `out/readable_strict/`. Right ballpark, wrong corpus, invented citation. |
| "15/15 tool tabs" | **12/15 overlap** | Both sides have 15; they are not the same 15. Burp-only: SCANNER, BURP_AI, REPLAYER. burpsy-only: decoder, session, settings. Counting cardinality instead of intersection. |
| "183 advisories reachable" | 183 bundled, **181 index-reachable** | Two files declare a neighbour's `typeIndex` — in **Burp's own data** (React2Shell→Perl 1052160, Bambda→BCheck 150994944). Honest form: 183/183 bundled, 181/181 addressable by index, 2 shadowed-by-design. |
| **"…and the 2 shadowed are reachable BY NAME"** — *this analysis, wave 1* | **Not at the product surface** | See §6.1a. Our own correction, found by W5 in wave 2. |

#### 6.1a The fifth one is ours, and that is the most important sentence in this report

Wave 1 of *this analysis* published, as verified shared context, that the 2 shadowed
advisories are "reachable BY NAME." W5 falsified it in wave 2.

`(*Catalogue).ByName` (`internal/advisory/advisory.go:216`) has **zero non-test callers**.
Its only references are two test files — one of which,
`TestShadowedDefinitionsRemainReachableByName` (`index_collision_test.go:92,98`), proves
the *Go API* can reach them, which is exactly what made the claim feel verified. But the
live path resolves by index only: `handleAdvisoryDetail`
(`api_advisories.go:198-210`) parses the URL segment as hex and calls `ByIndex`; there is no
name branch, and the UI agrees (`data.advisory.ts:51` requests
`` `/api/advisories/${typeIndex ?? ""}` ``). So for a shared index, the reader gets the
winner's definition.

**Honest restatement:** 183 bundled, 181 addressable by index, and the 2 shadowed
definitions are reachable **only through a Go API that nothing but a test calls.**

Two things make this the load-bearing item in §6:

1. **A green test was mistaken for a reachable feature.** The test was correct; it tested
   the Go API, not the product. This is the §6.4 pattern — *exists* measured instead of
   *behaves* — committed by analysts who had explicitly written that rule down. The pattern
   is not a competence failure by the previous team. It is the default outcome of measuring
   the wrong layer, and it will happen again to whoever reads this next.
2. **A naive `grep ByName` returns ~50 hits and looks alive.** Nearly all are
   `scanner.ByName` and `scanner.BuiltInConfigByName` — *different functions in a different
   package*, both genuinely live. Only a method-vs-function distinction separates the dead
   one from the live ones. Per TAXONOMY rule 3 a negative grep needs a positive control;
   this case shows the mirror hazard — **a positive grep needs disambiguation.**

This report therefore holds its own wave-1 output to the same standard as the trackers it
criticises, and the reader should extend that suspicion to everything here that was not
proven behaviourally.

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

That is a structural fix for exactly the defect class of §3.

### 6.5a Correction: the antidote **did** propagate — the *mechanism* didn't (W4)

W4 measured this properly instead of assuming, and the earlier framing above was too harsh.
There are **12 structurally exhaustive tests across 7 packages** — the convention spread
widely. But **5 of the newer ones assert against a hand-typed list** rather than reflecting
over the source of truth, including `matchreplace_target_test.go:139`, whose own comment
claims it "walks every declared Target" while it walks a **hand-typed slice of 7**.

That is a meaningfully different diagnosis with a different fix. A hand-typed exhaustive
test is not a weaker version of a reflective one — **it is the same silent-drift bug the
pattern was invented to kill, wearing the pattern's clothes.** It passes forever; adding an
eighth Target changes nothing; and it reads, to a reviewer, exactly like the real thing.

The tools to do it properly are already in-tree: `reflect`, `go/ast`, and the
`fieldCount = iota` sentinel (`query.go:147`). **The convention propagated and the rigour did
not**, and the comment on the weakest instance is what makes it dangerous rather than merely
incomplete.

### 6.6 What the green build actually proves (W4)

- **2,213 tests / 243 files / 46 packages, all green, ~8 min.** Coverage **69.0%
  per-package, 77.7% whole-tree**. This is a genuinely well-tested Go codebase and the
  report should say so plainly.
- **One real hole: `cmd/burpsy` at 15.8%** — and it holds **18 of the 59** string-vocabulary
  `switch`-with-`default` sites in the tree, the densest concentration of the exact
  construct that produced §3.1. Lowest coverage sitting on highest-risk shape.
- **W4 avoided authoring a sixth false denominator.** `internal/httputil` reads **0%**
  per-package and **82%** cross-package — reporting the 0% would have been another
  wrong-corpus artefact. It is a maintainability observation, not a coverage gap.
- **No `-race` anywhere in CI**, while two of the only two genuinely assertion-free tests in
  the suite (`scanner_test.go:131`, `sitemap/concurrent_test.go:19`) are documented as
  failing *under* `-race`. The suite contains its own unread warning.
- **Shape vs behaviour, from burpsy's own `riskClass` manifest (82 routes, 20
  config-mutating): 14 of the 20 have no `internal/web` test observing an effect**, and 61%
  of API tests assert only against the API's own reply. That is the §6.4 pattern rendered as
  a coverage statistic — a shape test **cannot** catch "accepted, 200, did the wrong thing"
  by construction, which is why 2,213 green tests coexisted with §3.1 and §3.1a.

### 6.7 Three more instances of the bug class, found systematically (W4)

Two AST passes over 316 switches (→ 59 string-vocabulary-with-default; 61 partial enum
switches, all survivors hand-read). **No second live instance of the §3.1 defect** — all 8
parser/consumer pairs verified matched. But three near-misses of the same family:

- **`internal/proxy/options.go:372-386`** — appliers are `if enabled[K]` with no
  exhaustiveness binding. **3 tests bind the option *listing* to `OptionKeys`; 0 bind the
  *applier*.** `responseRules` appears in **no test at all**. A newly added option would
  list, set, return 200 — and do nothing. This is §3.1 with the safety catch left off.
- **`category` — 3 unvalidated two-value coercions** (`api_toolkit.go:692,782`,
  `api_intercept.go:167`) defaulting in **opposite directions** (matchreplace → literal,
  intercept → regex), untested, sitting **five lines** from the `rule_type` code that
  validates properly. Same file, same author, same day, opposite rigour.
- **`internal/bcheck/parser.go:388-411`** — tolerant metadata default, while **the same
  file** refuses properly at `:668-689`.

The implication for planning: the constraint is **not** engineering judgement, which is
demonstrably good — the antidote, the refusal pattern, and the reflective test were all
invented here. It is that **rigour is applied per-site rather than per-class**, so the same
developer writes the careful version and the careless version within a few lines of each
other. That is a cheaper problem to fix than a skill gap, and it is what §9.1 addresses.

### 6.7a A coverage table that credits the wrong primitive (W7a)

Two records disagreed: `scanner/infra_coverage.go:281` lists `Client-side prototype pollution`
under `WiredIssues` for the **`js-execution-tier`** row (`File: internal/jsexec/jsexec.go`),
while §4.1 measured `internal/jsexec` as the tree's **only STATE 2 package**. Per ADR rule 11,
this was re-run rather than resolved by preference — and **both records were right about
different things.**

- `internal/jsexec` **is** STATE 2. Proven better than grep can: **delete the package and
  `go build ./...` and `go vet ./...` both stay at exit 0** (46 packages → 45).
- `Client-side prototype pollution` **is** STATE 4 — it fires, proven behaviourally against
  the bundled vulnapp's `/dm/proto`, with the safe counterpart staying quiet as a control.
- **And the row still detects with `internal/jsexec` deleted from the tree.** The detection
  belongs to `domexec` (`checks_dom_extra.go:25-44` → `checks_dom.go:186-201`); the coverage
  table credits `jsexec` for work `domexec` does. Verified here independently: the only
  producer of that finding string is `checks_dom_extra.go:39`.

**Two guard-test holes let this sit green,** and they are the interesting part: `File:` is only
checked **non-empty** (`infra_coverage_test.go:14`), and `TestEveryWiredIssueIsActuallyRunnable`
verifies the *issue* is runnable — never that the *named primitive* is why. Demonstrated by
experiment: pointing `File:` at a nonexistent path keeps every guard green; deleting the row
and reassigning its issue to `dom-execution-harness` keeps the pinned
`InfraWiredIssueCount() == 139` green; deleting it *without* reassigning yields 138, which is
the arithmetic control proving the count is otherwise sound. **139 is correct. `jsexec`
contributes zero to it.**

**Severity, deliberately not inflated.** The tempting read is "a security tool tells operators
a check ran when it cannot run" — a STATE 5 reporting layer. **It is not that.** `WiredIssues`
has **no operator-facing consumer**: verified here that the only references to
`InfraPrimitives` / `InfraWiredIssueCount` are *inside `infra_coverage.go` itself* — zero
elsewhere in Go, zero `/api` route, zero in `ui/src`, and `docs/` is not embedded. Positive
control: 78 live `scanner.X` references exist in `internal/web`, so the corpus does carry real
cross-package use. **This is documentation drift with a repo-internal audience.** It matters
because the table is the thing a future planner would trust to decide what is already built —
not because a user sees it today.

A second false statement rides along: `checks_dom_extra.go:6-8` claims "two tiers (goja and a
real browser)"; **only one runs.** Disambiguation, since this is exactly where §10 trap #2
strikes: `internal/scanner` *does* import `goja/parser` for static AST work
(`xss_jscontext.go:28`), but the goja **runtime** appears only in `jsexec.go:48`. The import is
real; the tier is not.

**The original open question — "is wiring it blocked by anything beyond scheduling?" — was the
wrong question.** The row already works. The residual work is re-attribution, two comment
fixes, and closing the guard-test hole. `jsexec`'s genuinely unbuilt purpose is its
**Chrome-less fallback**, which is a real capability gap and should be recorded as one.

### 6.7b A silent 12-tab ceiling in Repeater (W7b) — new STATE 5

Found while confirming that Repeater tabs are genuinely isolated (they are — §8 item 8).
`store.ts:146`: `openRepeaterTab` appends the new tab and then applies **`.slice(-12)`**.

Opening a 13th tab **silently discards the oldest**, with no toast, no confirmation, and no
entry in the reopen stack that exists precisely to protect drafts. Proven behaviourally by
driving the committed store: *oldest tab A still present? `false`. Recoverable from reopen
stack? `false`.* An operator with twelve tabs of hand-built requests loses the first one by
opening a thirteenth, and finds out later.

This is the same shape as everything else in §3: **the product reports success for work it did
not do** — here, "tab opened" while a different tab was destroyed. It is also cheap to fix
honestly: refuse, or evict into the reopen stack, or say so.

### 6.8 We turned the audit on ourselves, and it found things

Having spent six sections establishing that this repo's claims do not survive checking, the
obvious question is whether *this document's* claims do. Two passes at `210f73f`:

**Pass 1 — structural, exhaustive.** Extracted all distinct `file:line` citations in
this report and resolved every one against the tree: does the file exist, and does it have
that many lines? **70 / 70 passed** when first run, and **102 / 102** on re-run after this
wave's additions — the citation count grew as findings landed, and the pass was re-run rather
than quoted from memory. No dangling citations, no line numbers off the end of a file, no paths
that moved. Cheap to run and worth keeping — it is `grep -oE` plus a loop, and re-running it is
the only reason this paragraph does not still say 70.

**Pass 2 — semantic, sampled.** Structural resolution is the weaker check: the W1 failure
(§10 trap #4) was a file that existed, at the right path, saying the *opposite* of what cited
it. So we re-read the cited code behind the load-bearing claims — everything backing §9's top
fixes, plus every STATE 2 verdict §9 asks someone to act on — and asked whether it says what
we said it says. **13 claims checked:**

| Claim | Citation | Verdict |
|---|---|---|
| §3.1a session validity is first-stated-field-wins | `session/session.go:38-118` | **Holds exactly.** `StatusIs` returns unconditionally at `:42-52`; every later field unreachable for that rule. |
| §3.0.3a `sendTestRequestFull` reuses the exchange's method | `scanner/scanner.go:507-539` | **Holds exactly.** `Method: exchange.Method` at `:515`. Confirmed concretely by `checks_reflection3.go:227` probing a fixed `/trace.axd`. |
| §3.0.3a the correct primitive exists nearby | `scanner/scanner.go:546` | **Holds** — understated, in fact: `sendTestRequestBody` is the *immediately next* function, not "two functions away", and its comment `:541-545` states its rationale. |
| §6.5 the antidote is a single-source-of-truth table | `scanner/audit.go:567-580` | **Holds.** The comment even states the anti-drift rationale itself. |
| §6.5 the reflective guard test exists | `scanner/audit_test.go:513` | **Holds.** Genuinely reflects over `BuiltInConfig`. |
| §6.7 `options.go` binds listing, not applier | `proxy/options.go:372-386` | **Holds.** |
| §4 Myers diff engine has zero non-test callers | `tools/comparer.go:99,109` | **Holds.** Only its own declarations. Positive control: `tools.NewDecoder()` *is* found live at `api_toolkit.go:1026`, so the method can see live use of that package. |
| §2.1 Intruder `PayloadGenerator` has zero non-test callers | `intruder/intruder.go:346-387` | **Holds.** Only its own declarations and methods. |
| §6.1a `advisory.Catalogue.ByName` has zero non-test callers | `advisory/advisory.go:216` | **Holds, including the trap it warns about** — the competing hits really are `scanner.BuiltInConfigByName` (`api_scanner_configs.go:124`), a different symbol in a different package. |
| ~~§2.1 `inspectorPanelState`/`inspectorDock` are written and never read~~ **RETRACTED 2026-08-27** |
| §2.2 `Export configuration` ships only scope + intercept + session | `web/api_config.go:48-67` | **Holds exactly.** The `configBundle` is populated with `Scope`, `Intercept` and `SessionRules` and nothing else, then encoded. |
| §2.1 row 80 — the sender's `tls.Config` pins neither version nor ciphers | `sender/sender.go:242-244` | **Holds, and understates itself.** Only `InsecureSkipVerify` is set. The report cited one path; there are **two**, and `alpn.Dialer` (`alpn/alpn.go:182-188`) sets only `ServerName`, `InsecureSkipVerify` and `NextProtos`. **Neither** path constrains TLS version or cipher suite. |
| §3.0.3c `AuditItemPointNoChecks` "is never used" | `scanner/audit_items.go:188-190` | **FALSE — corrected in place.** Produced live via `Resolve`→`resolvePoints`→`pointStatusFor:602`. |
| §9 item 3 is a cheap status swap | (derived) | **FALSE — re-priced.** Point status is per-*item* and stamped onto every point; the fix needs new per-point accounting. |

**1 of 13 sampled claims was wrong, and it took a §9 priority estimate down with it.** The
error was **trap #1 for the third time**: we grepped an identifier, found the declaration and
the `switch` arms, and concluded "never used" without walking two frames up to the producer.

Notably, **every STATE 2 verdict sampled held** — including the one §6.1a had already caught
itself getting wrong. The unwired findings are the sturdiest part of this report, which makes
sense: "zero non-test callers" is a claim an import census can settle mechanically, and the
method was applied with a positive control each time.

Four things follow, and they are the honest reading:

1. **The structural pass is necessary and nearly worthless on its own.** It scored 100% on a
   document containing a false claim. A citation audit that only checks that files exist
   measures tidiness, not truth.
2. **A 1-in-13 semantic error rate is this report's own floor, not its ceiling** — 89
   citations went unsampled, and the sample was deliberately drawn from the *most*
   scrutinised claims, so it is biased optimistic. §7's "read this as a floor, not a
   measurement" applies to the document as much as to the product. Anyone acting on a claim
   here should re-read its citation first; that is now cheap, because all 102 resolve.
3. **The error was in a fix estimate, which is the most dangerous place to be wrong.** A
   wrong severity gets argued about; a wrong *cost* silently changes what gets scheduled. An
   under-priced defect is deferred by ordinary good planning, and nothing ever re-checks the
   estimate. Worth stating plainly: **this report's cost estimates are the least-verified
   numbers in it**, and unlike its denominators, not one was independently re-derived.
4. **The auditor fell into the trap mid-audit, which is the most useful datum here.** While
   checking the `sendTestRequestFull` claim, `grep 'func sendTestRequestFull'` returned
   **nothing** — because it is a method, so the real declaration reads
   `func (s *ActiveScanner) sendTestRequestFull`. For about a minute the priority-#2 fix
   looked like it cited a function that did not exist. Only the standing rule — *a negative
   grep needs a positive control* — caught it. That rule is in §10 because earlier waves
   needed it; it earned its place again here, against the person auditing for exactly this
   class of error. **Treat the rules in §10 as operational, not commemorative.**

---

## 7. Landed this wave, and what is still open

**Landed (folded into §2, §4.1, §5.1, §6.1a above):**

- **W3 — UI surface parity.** 24 pages, ~80+ controls. 1 decorative control, 12
  honestly-disclosed limitations, Scanner anomaly resolved (§5.1, §7.1).
- **W5 — STATE 2/3 sweep.** All 37 internal packages by `go list` import census. Completed
  wave 1's partial 22-package grep sweep and **corrected one of our own claims** (§6.1a).
- **W6 + W6b — the config surface, end to end.** Denominator settled at **85** (alternatives
  87 and 95 preserved), then independently re-derived name-for-name by a second analyst, then
  every row mapped: **41 wired / 36 absent / 3 unwired / 5 unreachable / 0 stubs** (§2.1).
  This closes what was the largest open item in the analysis.

- **W2 — scanner reality check.** The only workstream that stood up live targets and ran
  real scans. Answered the question affirmatively (§3.0) and found **three of the report's
  five live STATE 5 defects** in the process. It also declined to state a Burp-side
  check-count denominator because none honestly exists — the single best methodological
  decision made in this analysis. It avoided a false denominator authored by us; three others
  got through anyway (§1).

- **W4 — test-suite honesty audit.** 2,213 tests measured, two AST passes over 316
  switches, and **two corrections to this report**: §6.5's "the antidote never propagated"
  was wrong (it propagated as a convention but not as a mechanism, §6.5a), and §3.1's
  exemplar defect had been **fixed** while we still called it live (§3.1). Full results in
  §6.6-6.7.

- **W7a + W7b — the last four open questions, and a self-audit.** Sent to *close* §8 items
  rather than open new ground; between them they closed items **3, 8, 10** and corrected the
  premise of item **7** (§8), while turning up **a new STATE 5** (§6.7b), **a misattributed
  coverage row** (§6.7a), and **a route name that never existed** (§3.1). In parallel, this
  report's own citations were audited: 102/102 resolve structurally, **1 of 13 false**
  semantically (§6.8).

**Nothing remains open from the original plan.** What the report still does not know is
listed in §8, and the largest item there is no longer a workstream that can be run — it is
the ~170 scanner evaluators that would each need a live target to exercise.

**The final wave is the strongest evidence for reading this as a floor.** Both W7 agents were
sent to *close* questions, and both found new defects on the way — one of them while
confirming that a feature works correctly. The two questions that closed cleanly
(Repeater isolation, prototype-pollution detection) both closed **in burpsy's favour**, and
both had a defect sitting immediately beside the good news.

**A closing note on completeness.** Every wave found defects in surfaces the previous wave
called clean, *including surfaces this analysis called clean*. Wave 3 found a live STATE 5
(§3.1a) that two earlier passes had recorded as clean, and found it only because a citation
in §1 didn't match any evidence file. **This report should be read as a floor, not a
measurement.**

### 7.1 Scanner is reachable — but it has no front door

W3 resolved the §2 Scanner anomaly, and the resolution is more interesting than "missing."

Scanning is **not** unreachable. `nav.ts:89` places `scanner.tsx` as a leaf **inside Target**,
titled *"Issues"* — a findings viewer. But it also carries genuinely working launch controls
in an Audit-settings modal (`scanner.tsx:676-736`): a **Targeted audit** button
(→ `POST /api/scanner/audit`) and a **Live active audit** toggle (→ `handleScannerLive`),
both verified on both sides.

The real gap is **fragmentation**. Scan launching is split across three pages — Dashboard's
New-scan modals, Site map's Crawl button, and a narrow single-exchange control buried in
Target→Issues' settings modal — while scan *configuration* lives somewhere else again
(`settings.tsx:556-671`). Burp has one consolidated tool; burpsy has the same capability
with no front door.

So `SCANNER` being "Burp-only" in the §2 tool-tab overlap row is correct **at the nav-tab
level** and must not be read as "scanning is unreachable." It isn't. Combined with §2's
4/77 config-key finding, the accurate statement is: **burpsy can scan, cannot be told much
about how to scan, and offers no single place to do it.**

---

## 8. NOT DETERMINED

Named explicitly per TAXONOMY rule 6, rather than guessed:

1. ~~**~87 of ~90 Burp top-level config panels** never verified.~~ **CLOSED this wave.**
   All 85 mapped — §2.1. Residual: no panel was proven STATE 5, because proving a config
   panel *wrong* (as opposed to absent or unwired) needs behavioural runs this pass did not
   have budget for on all 41 wired rows. **0 BROKEN is therefore "none proven," not "none
   exist"** — the distinction §6.4 exists to protect.
2. ~~**Whether the advisory catalogue can fire.**~~ **CLOSED** — it fires (§3.0). Residual,
   and important: **roughly 11 of ~183 evaluators were actually driven to a finding.** The
   other ~170 are *runnable descriptors*, which is a claim about registration, not about
   correctness. **"183 runnable" must never be restated as "183 checks work."**
2a. ~~**Whether burpsy's scanner injects at Burp's 8 insertion-point types.**~~ **CLOSED** —
   3 of 8 at defaults, 5 of 8 all-on, 0 of 6 relocation types (§3.0.1).
2b. **Whether Burp has an honest check-count denominator at all.** W2 looked and concluded
   the shipped resources do not contain one (`selected_issues` enumerates 15 distinct
   `type_index` across all presets). This is recorded as *deliberately not determined*
   rather than estimated. **Do not let anyone fill this in without new evidence.**
3. ~~**Field incidence of the match/replace STATE 5 defect.**~~ **CLOSED (W7b) — incidence is
   zero, and the defect is no longer a defect.** Every occurrence of `request_param_name` /
   `request_param_value` in the repo is implementation, Go test, or docs prose; the only
   sender of a `rule_type` is `matchreplace.tsx`, which offers 5 triple-constrained targets.
   The API now **refuses both by name with a 400** (`api_toolkit.go:628-635`, verified here)
   and the engine no-ops instead of body-rewriting, closing even the hand-edited-config
   bypass. **Reclassify: STATE 4 plus a documented STATE 0 capability gap** (5 of 7 Burp
   `rule_type`s implemented) — *not* a live defect. See also the route-name correction in §3.1.
   Residual, and it is a real gap: **no e2e script touches match/replace at all.** Positive
   control — 89 `curl`s across 10 shell scripts hit ~14 distinct `/api/` paths, and
   `/api/tools/rules` is not among them.
4. **Intruder "section-marker parsing"** — no such distinct feature found in
   `internal/intruder`; only the existing `§marker§` payload-position parsing, already
   wired via `/api/intruder/run`. Flagged rather than guessed.
5. **Cost of Replayer parity** — Burp's string table gives too little to size it.
6. **Two wave-1 workstreams produced no recoverable output** ("verify claimed-working
   features actually behave", "audit the other four reports for unsupported claims"). Their
   findings are lost, not absent. W3 has since re-covered the first; **W4 has since landed
   and re-covers the second** (§6.6-6.7). This item is closed as a workstream; what remains
   is that the two original waves' *specific* findings were never recovered, so anything they
   found and neither W3 nor W4 re-found is still unknown.
7. ~~**The Collaborator mint-payload fix** is recorded as verified in a surviving summary,
   but the summary was truncated before its evidence.~~ **PREMISE CORRECTED (W7a).** The
   summary is commit `361deb0` and it is **not truncated** — the message is complete and
   simply carries **no evidence and no test** (`git show --name-only`: three UI files). The
   finding narrows from "unproven capability" to something more specific and worse: minting
   **works** (`web/api_collaborator.go:502`, correlation id a `crypto/rand` DNS label at
   `:278`, wired via 5 routes at `server.go:721-725`, present in the embedded `dist/app.js`
   with positive and negative controls), and driving it in a scratch copy gave correct
   distinct addresses, 409 unconfigured, 503 broken, and no mint on status read. But **there
   are zero committed behavioural tests on that route** — no `api_collaborator_test.go` — for
   a `riskEgress` endpoint that spawns a subprocess and triggers a public DNS registration.
   **Still NOT DETERMINED:** real public-DNS resolution and interaction attribution, which is
   precisely what `361deb0` claimed.
8. ~~**Whether burpsy's Repeater supports multiple concurrent isolated tabs.**~~ **CLOSED
   (W7b) — parity achieved, and this is a genuine positive finding.** Proven behaviourally,
   not by reading: the committed store was extracted and driven, and editing tab A's request
   buffer left B and C byte-identical; per-tab target and per-send options are independent;
   switching tabs mutates nothing. Every mutator is keyed by tab id (`store.ts:151-154`) and
   the editor writes back under `active.id` (`repeater.tsx:515-519`). **This is not a tab
   strip over shared state** — which was the specific failure mode worth checking, because it
   would have looked identical from the outside. Per-tab back/forward history is real
   (`repeater.tsx:63-65`, with an `N/M` counter at `:358-382`), and `repeaterTabs` /
   `repeaterGroups` genuinely rehydrate and drive chrome (`:420-470`) — so the write-only
   pathology really is confined to `inspectorDock` / `inspectorPanelState` — **RETRACTED 2026-08-27: those two are read; there is no write-only pathology here at all.** **But see §6.7b:
   the same code path silently evicts the 13th tab.**
9. **Burp-side depth for the Discover/Learn tool.** Not enumerated in any available Burp-side
   document, so no ratio is offered for that row.
10. ~~**Whether wiring `jsexec`'s prototype-pollution check is blocked by anything beyond
   scheduling.**~~ **CLOSED (W7a) — the question was wrong.** Nothing blocks it because
   **the check already works, and `jsexec` is not what makes it work.** Full treatment in
   §6.7a, including the two guard-test holes that kept the misattribution green and the
   reason this is documentation drift rather than a STATE 5 reporting layer. `jsexec`'s
   genuinely unbuilt capability is its **Chrome-less fallback**.
11. **Whether the Collaborator route resolves against real public DNS**, and whether
   interactions attribute correctly to the minting client. Split out of item 7 because it is
   the part that remains open, and it needs live external infrastructure to answer.
12. **Whether Repeater's isolation holds at the DOM layer.** W7b's proof drove the **store**,
   which is where isolation would break — but no e2e test opens a second tab, so the
   rendered-component path is unmeasured. Named rather than assumed from the store result.

---

## 9. What I would do next, in order

*(Numbering: §9.1 is the item §5.1 refers to.)*

**Ordered by expected harm, not by effort.** The first three are correctness defects in a
security tool; everything after is parity work.

1. **Fix session validity evaluation (§3.1a).** Live at HEAD, and the only defect here whose
   blast radius is *every finding of an authenticated scan*. An operator's two-condition rule
   is read as a one-condition rule, the logged-out page reports `Valid`, the scanner never
   re-authenticates, and the audit still says `skipped=0`. Smallest correct fix: **refuse a
   flat rule with more than one field set** and point the operator at `All{}`, which already
   composes correctly. That is a 400, not a behaviour change, and it matches the refusal
   pattern `targetToCategory` already uses. Evaluating all stated fields conjunctively is the
   larger, better fix; either beats today.

2. **Fix `sendTestRequestFull`'s method reuse (§3.0.3a).** Also live, also silent, also in a
   default-ON family. Discovery probes inherit the base exchange's HTTP method, so anyone
   testing an API through the proxy gets `POST /robots.txt` → 405 → "clean." The correct
   primitive, `sendTestRequestBody`, sits **immediately below it** and its comment says exactly
   why it exists. Seven call sites, including the HTTP-PUT check's own verification GET.

3. **Fix the duplicate-advisory and false-`Audited` reporting (§3.0.3b, §3.0.3c).** Both
   corrupt triage rather than testing: one inflates counts and splits a single condition
   across two severities; the other tells the operator a header insertion point was audited
   when nothing probed it.

   **Re-priced — see the correction in §3.0.3c.** (b) is cheap. (c) is **not**: the status
   value `AuditItemPointNoChecks` is already produced on a live path, and the reason it
   cannot answer (c) is that point status is decided *per item* and stamped onto *every*
   point, because `AuditItemPoint` carries no per-point probe accounting. Fixing (c) means
   adding that accounting — plumbing, not a `case`. Do (b) first; scope (c) properly before
   committing to it.

4. **Make the bug class unrepresentable, by propagating the *mechanism* and not just the
   convention (§6.5, §6.5a).** Do not design a new guard — this team already invented it.
   `builtInConfigKeys` (`internal/scanner/audit.go:567-580`) is a single table from which
   both the engine overlay and the operator-facing listing derive, precisely so they cannot
   drift; `Test_every_built_in_config_field_has_a_key_row` (`audit_test.go:513`) reflects
   over the struct and **fails** when a field has no row.

   The nuance W4 added is the important part: the *convention* propagated to 12 tests across
   7 packages, but **5 of the newer ones assert against hand-typed lists** — including one
   whose comment claims it "walks every declared Target" while walking a slice of 7. A
   hand-typed exhaustive test is not a weaker version of a reflective one; it is the same
   silent-drift bug wearing the pattern's clothes. Convert those 5 to reflect over the source
   of truth (`reflect`, `go/ast` and the `fieldCount = iota` sentinel are all already
   in-tree), and apply the same binding to `internal/proxy/options.go:372-386`, where 3 tests
   bind the option *listing* and **0** bind the *applier*.

5. **Gate `bun run check` and the Playwright e2e suite in CI.** *(W7b adds a specific hole: no e2e script touches match/replace at all — 89 curls across 10 scripts hit ~14 `/api/` paths, and `/api/tools/rules` is not one. And no e2e opens a second Repeater tab, which is why §8 item 12 stays open.)* 118 frontend test
   assertions, two typechecks and two token-drift checks are committed and never executed.
   The Go half of this project has real gates including live `ffuf`/`nuclei` tests; the
   frontend half has none. This is the highest value-per-line change available — the tests
   are already written.
6. **Wire the Myers diff engine** into `handleToolsCompare` and un-hide the granularity
   control. Deleting a weaker reimplementation is a negative-diff improvement.
7. **Decide about `/api/discovery`** — give it a UI or delete it. A working ffuf backend
   sitting behind a documentation page is the worst of both: maintenance cost, zero user
   value.
8. **Record the Burp AI and Replayer omissions as explicit decisions.** They are almost
   certainly correct calls; being undocumented is what makes them debt.
9. **Delete or re-derive every ratio in the existing trackers.** Five of five checked
   denominators were wrong, including one this analysis published itself (§6.1a). The prior is now that an unverified number in this repo is
   wrong, and a wrong number is worse than none.
10. **Make `Export configuration` honest** (§2.2). It ships 3 of ~11 subsystems under a name
   that implies all of them. Either export everything or write a manifest into the file and
   say "partial" in the UI. Cheapest fix with the worst untreated failure mode in the report.
10a. **Fix the silent 12-tab Repeater eviction** (§6.7b). Promoted into the top group by
   harm, not by size: it is a live STATE 5 that **destroys operator work** with no warning and
   no undo, and the reopen stack it bypasses already exists. Refuse the 13th tab, or evict into
   the reopen stack, or say so in the UI — any of the three beats today. `store.ts:146`.

10b. **Re-attribute the `js-execution-tier` coverage row and close the guard-test hole**
   (§6.7a). The row credits `internal/jsexec` for a detection that `domexec` performs, and the
   check still fires with `jsexec` deleted from the tree. Low urgency — there is **no
   operator-facing consumer**, so nothing lies to a user today — but do it before anyone plans
   from that table, because a planner reading it would conclude a STATE 2 package is load-bearing
   and leave it alone. Fix the two guard holes at the same time: assert `File:` **resolves** (not
   merely non-empty), and assert the **named primitive** is why the issue is runnable, not just
   that it is. Also correct `checks_dom_extra.go:6-8`, which claims two tiers where one runs.

10c. **Add a behavioural test to the Collaborator mint route** (§8 item 7). No
   `api_collaborator_test.go` exists for a `riskEgress` endpoint that spawns a subprocess and
   triggers a public DNS registration. The scratch-copy run gave correct behaviour, so this is
   about *keeping* it, cheaply, at the layer that has none.

11. **Fix or delete the Decoder `guess_alphabets` checkbox** (§5.1). It is the only proven
   decorative control in ~80. Small, and it takes the count to zero.
12. **Give scanning a front door** (§7.1). The capability exists and is fragmented across
   three pages. This is an information-architecture change, not an engine change, and it is
   likely the largest perceived-parity gain per unit of work in this report.
13. **Turn the UI's disclosure convention into a mechanism** (§5.1). Twelve surfaces
    voluntarily admit their own limits and one does not (`PlatformAuthSection`). A convention
    that good deserves enforcement — a lint, a required prop, anything — before it decays.
14. **Decide about `/api/intercept/drop-all`** (§4.1): build the UI affordance or drop the
    route. Same argument as `/api/discovery`, smaller.
15. **Wire the Intruder `PayloadGenerator`** (§2.1). Numbers, file lists and custom lists are
    written, tested, bug-fixed — and unreachable. Intruder currently accepts pasted text
    only, which is a conspicuous gap against a tool whose entire purpose is payload
    generation. Burp ships 48 `.pay` wordlists to burpsy's 0 (§2); this is the code path
    that would consume them.
16. **Disclose the TLS negotiation limitation** (§2.1, row 80), and decide whether to fix it.
    Not being able to point the sender at a legacy-TLS target is a real constraint on what
    engagements this tool can run, and today an operator discovers it by failing.

---

## 10. Standing methodological warnings for whoever reads this next

The four traps this analysis actually fell into, as opposed to the ones it anticipated. All
four are the same shape — **an artefact was trusted for a claim it does not actually support**
— and the fourth is the one we caught ourselves committing:

1. **A passing test proves the layer it tests, not the layer users touch.**
   `TestShadowedDefinitionsRemainReachableByName` is green, correct, and was cited as
   evidence for a product claim that is false (§6.1a).
2. **A positive grep needs disambiguation as much as a negative grep needs a control.**
   `grep ByName` returns ~50 live-looking hits for a function with zero non-test callers,
   because a different package exports a similarly-named symbol (§6.1a).
3. **A bundled artefact is not a reachable feature is not an implemented capability.** This
   chain broke twice already — 183 advisories (bundled ≠ addressable) and the MCP "N/A"
   (§6.2) — and W2 is where it can break a third time if "183 definitions" is ever reported
   as "183 checks."
4. **A reconstruction is not evidence — and it can silently invert a finding.** Found last,
   and the worst of the four, because it happened inside our own citation trail. When W1's
   original report was destroyed with a reaped workspace, the same analyst rewrote a 72-line
   summary from memory. That summary asserted `session` "came back **clean**" — and it was
   the **git-canonical evidence file** for this analysis while it said so, through three
   commits and a merge. The full original, which proves the session-validity STATE 5 (§3.1a,
   the worst defect in this report), survived only in a stale duplicate directory. A reader
   who did the right thing — followed §3.1a's citation to its evidence file — would have been
   told the defect did not exist.

   Two rules follow, and they are cheap:
   - **Label a lost artefact unrecoverable. Do not re-derive it from memory** and give the
     re-derivation the original's filename. If a summary must be written, it goes in a file
     named as a summary, and it says what it could not recover.
   - **After citing an evidence file, re-read it and check it says what you just said it
     says.** This contradiction was one `grep session` away for three commits. Note the
     shape: this is trap #1 (a green artefact proving a different layer than claimed) applied
     to our own prose instead of to the code — which is why §6.1a's lesson generalises
     further than we first wrote it. The analysis kept auditing the repo's claims and stopped
     auditing its own.

   *(Fixed: `docs/parity/W1-broken-behaviour.md` now holds the full 375-line original behind
   a provenance header; the duplicate root `parity/` directory that held the only good copy
   is consolidated away. The reconstruction remains in git history at `6e83ced`.)*

And the one that destroyed two waves of work: **deliverables written inside
`.orchestry/workspaces/**` are reaped.** Everything durable in this analysis lives in
`/root/burpsy-parity/` or in git. Nowhere else.
