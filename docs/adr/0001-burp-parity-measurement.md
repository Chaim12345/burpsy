# ADR 0001 — How we measure Burp parity, and why trackers are not evidence

- **Status:** Accepted
- **Date:** 2026-08-26
- **Author:** CTO
- **Context artefacts:** `BURP_PARITY_GAP_ANALYSIS.md`, `/root/burpsy-parity/TAXONOMY.md`

## Context

burpsy has tracked its progress toward Burp Suite parity in hand-maintained markdown
documents (`ui-gaps.md`, `BURP_FEATURE_INVENTORY_VS_BURPSY.md`, the webui-parity working
memory). A six-workstream audit against a teardown of Burp Suite 2026.7.1 found those
trackers to be **actively misleading**, not merely stale.

Falsified during the audit:

- **Four of four checked denominators were wrong.** "137 `configPanel*`" (really 134, and
  not a panel count at all). "960+ `setName()` per `map_root.tsv`" (that file contains
  `setName` exactly once — fabricated provenance). "15/15 tool tabs" (both sides have 15;
  only 12 intersect). "183 advisories reachable" (183 bundled, 181 index-reachable).
- **One categorical claim was false.** "MCP server: not present in 2026.7.1 = N/A" — Burp
  bundles 306 `io/modelcontextprotocol` classes and ships `McpBurpTool`.
- **Seven items were recorded working while broken**, each internally self-consistent,
  which is why ordinary review never caught them.

The root cause is a **category error baked into the format**: a tracker tick asserts that a
control *exists*. It has never asserted that the control *behaves*. Both facts were
recorded in the same column, so they became indistinguishable.

A second, compounding cause: the false MCP claim was *ratified* by a grep that returned
zero — run against a corpus (`out/clean/renamed_final/`) that excludes bundled `io/**`
libraries. A negative result in the wrong corpus is indistinguishable from absence.

## Decision

**1. Parity claims are made in six states, never in binary.**

```
0 ABSENT / 1 STUB / 2 UNWIRED / 3 UNREACHABLE / 4 WIRED / 5 BROKEN
```

`UNWIRED` (real implementation, zero non-test callers) and `UNREACHABLE` (routed, no UI
path) are the states the old binary format collapsed, and they are where the work already
paid for sits. `BROKEN` outranks everything: reachable-but-wrong is worse than absent,
because absent does not silently corrupt a user's traffic.

**2. State 4 and State 5 require observed behaviour. Reading code is not proof.**
To claim WIRED or BROKEN you run it and paste the output. Production code is never
modified to do so — copy the package to a scratch directory.

**3. Every ratio carries a denominator the author recounted, plus the command.**
Given a 4-for-4 falsification rate, the prior is that an unverified number in this repo is
wrong. A wrong number is worse than no number, because it terminates inquiry.

**4. Every negative grep carries a positive control.**
Demonstrate the search *would* have found the thing had it been present, in that corpus.

**5. "Not gated" and "not working" are recorded as different statements.**
CI gates only gofmt, build, vet, test. There is no `tsc` and no e2e. A claim resting on
either rests on an ungated manual run.

**6. Documented deliberate divergence is graded separately from defects.**
`internal/extension/protocol.go:19-33` states its own 3-of-13 Montoya gap. That is a
capability decision. An *undocumented* omission is debt, and the fix is usually to write
the decision down, not to build the feature.

**7. No aggregate percentage. Ever.**
Config keys, wordlists, class counts and tool tabs do not share a unit. Parity is reported
as a vector per surface. A single "% of Burp" number is not a summary of these
measurements; it is a different, unmeasured claim.

**8. Analysis artefacts are durable only once committed to git.**

This attempt failed twice before establishing it. Shared deliverables were written to a
path inside an agent workspace; the orchestrator reaps and recreates those directories, so
the measurement contract and two completed reports were destroyed. Of eleven analyst
reports across three attempts, **the only one that survived intact was the one committed
to git** — the others survive as 2000-character truncations, and two are lost entirely.
Working notes therefore live outside the orchestrator's tree
(`/root/burpsy-parity/`), and any artefact that matters is committed.

## Consequences

**Accepted costs.** Behavioural proof is materially more expensive than reading code —
roughly the reason two prior attempts produced no report. Reports will contain visible
`NOT DETERMINED` sections; ~87 of ~90 Burp config panels are currently unmeasured. This is
intended: a named gap is auditable, a guess is not.

**What this buys.** The audit found a live traffic-corrupting defect
(`request_param_name` / `request_param_value` accepted by the API, unhandled by the
engine, silently rewriting the whole request body) that had green tests, a tracker tick,
and a code comment describing the wrong behaviour. Under the old format that defect was
invisible by construction. Under this one it is a State 5 and outranks every missing
feature.

**Obligations this creates.**
- Any published vocabulary (string→enum parser, `type` field, accepted config key) needs a
  table-driven test asserting the engine handles every value it admits. This makes the
  accepted-but-unhandled bug class structurally unrepresentable rather than merely fixed
  case by case.
- `bun run check` must be gated in CI. It exists and is not run; until it is, the
  frontend's correctness is not measured by the build.
- Existing tracker ratios should be deleted or re-derived, not trusted.

## Alternatives rejected

**Keep the binary tracker, improve review discipline.** Rejected: all seven
working-while-broken items were internally self-consistent and passed review. The format
gave reviewers nowhere to record "exists but does not behave," so the failure recurs by
construction rather than by inattention.

**Emit a single parity percentage for reporting.** Rejected: it requires summing
incommensurable units and would have concealed the finding that matters most — a scanner
whose insertion points and check selection are entirely unrepresentable (4 of 77 functional
config keys) scores well on any tab-based count.

**Automate parity measurement against the Burp teardown.** Attractive and premature. The
denominators themselves are still contested and three of six surfaces are unmeasured;
automating now would encode current errors as ground truth. Revisit once ADR item 7 is
closed and the panel enumeration exists.
