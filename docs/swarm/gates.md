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
