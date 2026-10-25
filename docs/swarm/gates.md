# Wave gate

Integrator gate per merge wave, as of 2026-10-25 (backlog-b9 @ 5cf285ee):

1. Area review of the branch diff vs merge-base BEFORE merging (allowed areas + granted
   expansions only; go.mod deltas explained dep by dep).
2. `go build ./...`, `go vet` on touched packages, `gofmt -l internal/` FULL TREE (2026-10-25:
   a per-file check missed an unformatted routes_register.go for a whole wave).
3. Area suites -count=1 on the merged tree: web (~95s, needs ffuf on PATH), proxy, sender,
   httputil, and whatever the wave touched.
4. UI waves: `bun install` if needed, then the full `check` script's parts (tsc, tokens,
   gated-routes, lint, lib + component tests) plus `bunx biome format` on the whole ui/src tree
   (2026-10-25: format is not in the check script; W2's wave needed three cleanup commits).
   Rebuild ui/dist and commit it integrator-side; workers never commit dist.
5. Scanner: full -short suite detached via setsid (see sandbox.md).

## Exclusions, and who owns them
- The full-matrix tests (TestAnAuditSendsProbes..., TestTheScannerDetects...,
  TestTheScannerStaysQuiet..., TestEveryDetectionClaim...) exceed every sandbox: W1 runs them
  sharded across its wakes as a rolling per-push-batch gate (ruling 2026-10-25), nightly CI is
  the backstop of record once W5's ctdl/8pki jobs verify on their first Actions run.
- UI matrix equivalents: none known; component+lib suites are seconds.

## Generated artifacts are not independent evidence
A test that greps a corpus must exclude files GENERATED from the same source of truth it checks
against: their agreement is construction, not verification. Concrete instance (f790cb03,
2026-10-25): the route-reachability corpus included gated-routes.ts/route-risk.ts, which
gen:gated-routes derives FROM the route manifest - so a manifest-registered route looked
"console-referenced" without any caller, and the known-gap trip fired the moment a missing-surface
route regenerated in. Same class as the fxxm batch-1 miss (route keys renamed, tables not
regenerated): when a route changes, the manifest, the generated tables, and the corpus exclusion
list move together; the regen is an integrator merge step (ruling 3 of 47id).
