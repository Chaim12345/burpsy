#!/usr/bin/env bash
# capped-run_test.sh — behaviour tests for scripts/capped-run.sh (bead burpsy-react-ui-9ubm).
# Run: scripts/capped-run_test.sh   (no root, cgroups or Go needed; takes ~15s)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cr="$here/capped-run.sh"
tmp=$(mktemp -d)
trap 'pkill -f "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
export BURPSY_RUN_LOCKDIR="$tmp" BURPSY_RUN_SLOTS=1 BURPSY_RUN_CPUS=1 BURPSY_KILL_GRACE=1
fail=0
check() { # name, expected, got
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want $2, got $3"; fail=1; fi
}
# wait_for FILE: wait up to 5s for FILE to exist.
wait_for() { for _ in $(seq 50); do [ -e "$1" ] && return 0; sleep 0.1; done; return 1; }
# reap PID: wait up to 8s for the wrapper; its exit status lands in $status ("hung" if still alive).
reap() {
  local pid=$1
  for _ in $(seq 80); do
    if ! kill -0 "$pid" 2>/dev/null; then wait "$pid"; status=$?; return; fi
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; status=hung
}

# 1. The run's exit status passes through.
"$cr" -- bash -c 'exit 7' 2>/dev/null
check "exit status passes through" 7 $?

# 2. A run that ignores TERM is killed after the grace period, and the wrapper exits 143.
"$cr" -- bash -c "trap '' TERM; touch $tmp/up2; while :; do sleep 0.2; done" 2>/dev/null &
w=$!
wait_for "$tmp/up2"; kill -TERM "$w"; reap "$w"
check "TERM-ignoring run is escalated to KILL, wrapper exits 143" 143 "$status"

# 3. A well-behaved run: signalled wrapper exits 143, not the run's own status.
"$cr" -- bash -c "touch $tmp/up3; exec sleep 30" 2>/dev/null &
w=$!
wait_for "$tmp/up3"; kill -TERM "$w"; reap "$w"
check "signalled wrapper exits 143" 143 "$status"

# 3b. The run is sent TERM (whatever arrived; INT would be ignored by a background job) and gets to clean up with it:
# a run that handles TERM leaves its marker, so this fails if the wrapper forwards anything else or
# goes straight to KILL.
"$cr" -- bash -c "trap 'touch $tmp/got-term; exit 0' TERM; touch $tmp/up3b; while :; do sleep 0.1; done" 2>/dev/null &
w=$!
wait_for "$tmp/up3b"; kill -HUP "$w"; reap "$w"
check "the run is forwarded TERM, whatever signal the wrapper got (HUP here)" present "$([ -e "$tmp/got-term" ] && echo present || echo absent)"

# 4. A signal while the wrapper waits for a slot: the run never starts.
flock "$tmp/burpsy-heavy.0.lock" sleep 6.123 &
holder=$!
sleep 0.5
"$cr" -- bash -c "touch $tmp/started4" 2>/dev/null &
w=$!
sleep 0.5; kill -TERM "$w"; reap "$w"
check "early signal exits 143" 143 "$status"
sleep 0.3
check "early signal: the run did not start" absent "$([ -e "$tmp/started4" ] && echo started || echo absent)"
pkill -f "sleep 6.123"; wait "$holder" 2>/dev/null

# 4b. A signal after the trap is installed but before the run starts (the window the pre-start hook
# widens): the run never starts, and the wrapper exits 143.
BURPSY_RUN_TEST_PRESTART_SLEEP=2 "$cr" -- bash -c "touch $tmp/started4b" 2>/dev/null &
w=$!
sleep 0.7; kill -TERM "$w"; reap "$w"
check "signal before the run starts exits 143" 143 "$status"
sleep 0.3
check "signal before the run starts: the run did not start" absent "$([ -e "$tmp/started4b" ] && echo started || echo absent)"

# 5. Without cgroups the whole process group is signalled, not only the direct child.
"$cr" -- bash -c "sleep 60 & echo \$! > $tmp/gc5; touch $tmp/up5; wait" 2>/dev/null &
w=$!
wait_for "$tmp/up5"; sleep 0.2
gc=$(cat "$tmp/gc5"); kill -TERM "$w"; reap "$w"
sleep 0.3
st=$(awk '/^State:/ {print $2}' "/proc/$gc/status" 2>/dev/null); # a zombie is dead, only unreaped
check "grandchild is gone after the wrapper is signalled" gone "$([ -n "$st" ] && [ "$st" != Z ] && echo alive || echo gone)"
kill -KILL "$gc" 2>/dev/null

exit $fail
