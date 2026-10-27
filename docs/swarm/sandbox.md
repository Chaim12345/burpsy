# Sandbox environment

## Long-running tests (2026-10-25)
- Foreground commands die at ~120s. `setsid cmd > log 2>&1 < /dev/null &` SURVIVES between
  commands within a run (discovered by W1, confirmed by integrator: TestTheScannerStaysQuiet
  SQLi safe/dialect/slow?id=7 completed green in 181s with a 580s budget; full scanner-short
  runs detached). Plain `nohup ... & disown` was observed killed; setsid is the known-good form.
- Background processes do NOT survive across runs (sandbox restart); restart-detached work
  each run and poll.

## Rebuilds wipe tooling (2026-10-25)
A sandbox rebuild removed: bun (reinstall: `curl -fsSL https://bun.sh/install | bash`, lands in
~/.bun/bin), node_modules in burpsy-go/internal/web/ui (`bun install`), ffuf (the web suite's
TestDiscoveryCapabilityWasExercised fails without it: `GOBIN=/tmp/gobin go install
github.com/ffuf/ffuf/v2@latest`). Go 1.27.3 toolchain lives at /tmp/gotc127/go/bin with
GOPATH=/tmp/gopath GOMODCACHE=/tmp/gopath/pkg/mod GOCACHE=/tmp/gocache. All of /tmp survived
the observed rebuilds, but treat that as luck, not contract: the repo is the only durable state.

## go test defaults (2026-10-25)
The 10-minute default timeout kills long packages mid-run; always pass an explicit -timeout.

## A paused runner is not a wedge (2026-10-25, retracted quiet-AC report)
A detached runner pauses with the sandbox. The signature: a "deterministic stall at the same point"
with ZERO PASS lines and a goroutine dump whose client is blocked on a fixture that legitimately
sleeps (e.g. /auth/slow/login) - the dump was the go-test -timeout firing mid-audit, not a mutual
wait. Before attributing a desync: (1) confirm the runner had a continuous awake window; (2) a real
wedge needs the server side to have NO in-flight handler AND the fixture to not be sleeping on
purpose; (3) re-run with -parallel N and babysitting before filing cross-lane. The 4/4
"deterministic" pattern was deterministic because the pause fired at the same wall-clock offset.
