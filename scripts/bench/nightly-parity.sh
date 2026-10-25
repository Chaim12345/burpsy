#!/usr/bin/env bash
# nightly-parity.sh — the reference-parity harness's nightly entry point (j1mk.1).
#
# Local/agent runs go through scripts/capped-run.sh so a parity night cannot starve a machine it
# shares (the bead's "run nightly under capped-run.sh"). CI calls parity_run.py directly: each
# Actions job already has a runner to itself, which is capped-run's own reason for skipping it.
#
#   scripts/bench/nightly-parity.sh [parity_run.py args...]
#
# Defaults: --all classes, results under /tmp/burpsy-parity/<date>. burpsy and the demo target
# must already be running (pass --burpsy-web/--burpsy-proxy); starting them is the caller's,
# because their lifetime is the caller's too.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${BURPSY_PARITY_OUT:-/tmp/burpsy-parity/$(date +%F)}
exec scripts/capped-run.sh -- python3 scripts/bench/parity_run.py --out "$out" "$@"
