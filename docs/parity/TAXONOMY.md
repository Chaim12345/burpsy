# Burp-Parity Measurement Contract (TAXONOMY)

Baseline: burpsy HEAD `a619c9a`. Reference: `/root/burp-re` teardown of Burp Suite 2026.7.1.
Durable location: `/root/burpsy-parity/` — OUTSIDE `.orchestry/`, which is reaped.

## THE SIX STATES

Assign exactly one. State 5 outranks all others.

```
0 ABSENT      no code at all
1 STUB        symbol/route/screen exists, body is placeholder or returns fixed data
2 UNWIRED     real implementation, ZERO non-test callers
3 UNREACHABLE routed/registered, but no UI path reaches it
4 WIRED       end-to-end path exists AND observed to behave per contract
5 BROKEN      reachable but WRONG — requires BEHAVIOURAL proof
```

**State 4 requires observed behaviour, not presence.** A control that renders is not a
control that works. **State 5 requires you to RUN it and paste real output.** Reading the
code is not proof.

## RULES

1. **Cite `file:line` at a clean committed SHA.** Report `git rev-parse --short HEAD` and
   `git status --short` before measuring. Shared checkout — the working tree may hold
   someone else's half-finished work. Prefer `git show HEAD:<path>`.
2. **Every ratio needs a denominator you recounted yourself.** Four denominators already
   in this repo's docs were false (137 configPanel* -> really 134; "960+ setName()" ->
   provenance fabricated; 15/15 tool tabs -> only 12 overlap; 183 advisories -> 181
   index-reachable). Show numerator AND denominator AND say what each counts.
3. **Negative greps need a positive control.** A grep returning 0 in the wrong corpus is
   how a false "N/A" got ratified (`modelcontextprotocol` absent from
   `out/clean/renamed_final/` because that corpus excludes bundled `io/**`).
4. **Distinguish NOT GATED from NOT WORKING.** CI gates only gofmt/build/vet/test. There
   is no `tsc` and no e2e in CI. A claim resting on `bun run check` or `behaviour.spec.ts`
   rests on an UNGATED manual run.
5. **Prior docs are hypotheses to falsify, not sources.** Includes
   `BURP_FEATURE_INVENTORY_VS_BURPSY.md`, `ui-gaps.md`, and the webui-parity working
   memory. A tracker tick claims a control EXISTS; it never measured that it BEHAVES.
6. **Say "not determined" rather than guess.** An honest gap in the report is worth more
   than a confident wrong cell.
7. **Deliberate documented divergence is a CAPABILITY GAP, not a DEFECT.** Grade them
   separately (e.g. `internal/extension/protocol.go:19-33` documents its own 3-of-13 gap).
8. **READ-ONLY.** Change no production code. To prove behaviour, copy the package to a
   scratch dir under `/tmp` and drive it there.

## OUTPUT FORMAT

Write to `/root/burpsy-parity/W<n>-<name>.md`. Per finding:

```
### <surface> — STATE <n>
Claim under test: <what a tracker or the UI promises>
Evidence:        <file:line at SHA>
Proof:           <for STATE 4/5: the command run and its real output>
Impact:          <what a user sees / silently does not get>
```

End every report with two mandatory sections:
- **NOT DETERMINED** — what you could not settle and why.
- **DENOMINATORS I RECOUNTED** — each count, the exact command, the corpus.

## WHY THE PARANOIA IS CALIBRATED

Seven things here were recorded as working while broken, each internally self-consistent:
a MIME filter with six consumers bound to a field nothing populated; a typecheck step
that had never once executed; a racy test committed green; issue counts summing to 15 of
21; an advisory catalogue serving the WRONG advisory for two entries; match/replace
silently rewriting request bodies on accepted-but-unimplemented input; and a measurement
taken against the working tree and reported as committed state.

## NO AGGREGATE PERCENTAGE

Do not compute one. The ratios do not share a unit — config keys, wordlists, class
counts and tool tabs are not addable. Report the vector, not a scalar.
