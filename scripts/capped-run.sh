#!/usr/bin/env bash
# capped-run.sh — run one heavy local command (a whole-package go test, a race run, a Chrome drive)
# inside a hard CPU and memory budget, so two agents' runs on one machine cannot starve each other.
#
#   scripts/capped-run.sh [--cpus N] [--mem SIZE] [--slots N] -- COMMAND [ARGS...]
#
# Defaults: half the machine's CPUs, half its RAM, and that many concurrent slots (2 on a 4-CPU,
# 15 GB box: each run gets 2 CPUs and ~7.5 GB). Environment overrides: BURPSY_RUN_CPUS,
# BURPSY_RUN_MEM, BURPSY_RUN_SLOTS.
#
# What it does:
#   - Waits for a free slot (flock on /tmp/burpsy-heavy.<i>.lock), replacing the single
#     /tmp/burpsy-heavy.lock: with each run capped, two can share the machine.
#   - Puts the command in its own cgroup (v1 or v2) with a hard memory limit and a CPU quota of
#     N CPUs. Everything the command starts — test binaries, Chrome — counts against it.
#   - Tells Go about the budget: GOMAXPROCS=N and go's -p=N (via GOFLAGS) so the scheduler and the
#     package-level parallelism match the quota instead of thrashing against it, and GOMEMLIMIT at
#     80% of the cap so the GC works harder before the kernel kills anything.
#   - Says so plainly when the cap killed the run, rather than leaving a bare "signal: killed".
#
# A signal to the wrapper is passed on to the whole run (its cgroup, or else its process group). A
# run that ignores TERM is sent KILL after BURPSY_KILL_GRACE seconds (default 10); a signalled
# wrapper exits 143, and a signal that arrives before the run has started stops it from starting.
#
# Where cgroups cannot be created (no permission, read-only cgroupfs) it still applies the Go
# settings and the slot, and says the hard limits are off. CI does not use it: each Actions job
# already has a runner to itself.
set -euo pipefail

usage() { sed -n '2,10p' "$0" >&2; exit 2; }

ncpu=$(nproc)
mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
cpus=${BURPSY_RUN_CPUS:-$(( ncpu / 2 > 0 ? ncpu / 2 : 1 ))}
mem=${BURPSY_RUN_MEM:-$(( mem_kb / 2 ))K}
slots=${BURPSY_RUN_SLOTS:-}
lockdir=${BURPSY_RUN_LOCKDIR:-/tmp}
grace=${BURPSY_KILL_GRACE:-10}

while [ $# -gt 0 ]; do
  case "$1" in
    --cpus) cpus=$2; shift 2 ;;
    --mem) mem=$2; shift 2 ;;
    --slots) slots=$2; shift 2 ;;
    --) shift; break ;;
    -h|--help) usage ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || usage
[[ $cpus =~ ^[1-9][0-9]*$ ]] || { echo "capped-run: --cpus must be a positive integer" >&2; exit 2; }
slots=${slots:-$(( ncpu / cpus > 0 ? ncpu / cpus : 1 ))}

# SIZE (K/M/G suffix, or bytes) to bytes.
to_bytes() {
  local v=${1%[KkMmGg]} u=${1: -1}
  [[ $v =~ ^[0-9]+$ ]] || { echo "capped-run: bad size $1" >&2; exit 2; }
  case "$u" in K|k) echo $(( v * 1024 )) ;; M|m) echo $(( v * 1024 * 1024 )) ;;
    G|g) echo $(( v * 1024 * 1024 * 1024 )) ;; *) echo "$v" ;; esac
}
mem_bytes=$(to_bytes "$mem")

# Take the first free slot; when every slot is busy, wait on one of them.
exec {lockfd}>/dev/null
for i in $(seq 0 $(( slots - 1 ))); do
  exec {lockfd}>"$lockdir/burpsy-heavy.$i.lock"
  if flock -n "$lockfd"; then slot=$i; break; fi
done
if [ -z "${slot:-}" ]; then
  slot=$(( $$ % slots ))
  exec {lockfd}>"$lockdir/burpsy-heavy.$slot.lock"
  echo "capped-run: all $slots slots busy; waiting for slot $slot" >&2
  flock "$lockfd"
fi

name="burpsy-run-$$"
mem_cg="" cpu_cg="" v2_cg=""
child=""

# run_pids: every process of the run — the members of its cgroup, or just the child without one.
# shellcheck disable=SC2329 # used by the traps
run_pids() {
  local d
  for d in "$v2_cg" "$mem_cg"; do
    if [ -n "$d" ] && [ -f "$d/cgroup.procs" ]; then cat "$d/cgroup.procs"; return; fi
  done
  if [ -n "$child" ] && kill -0 "$child" 2>/dev/null; then echo "$child"; fi
}
# shellcheck disable=SC2329 # used by the traps
signal_run() {
  local p
  for p in $(run_pids); do kill -"$1" "$p" 2>/dev/null || true; done
  # Without a cgroup only the child is known; it leads its own process group (see the launch), so
  # its descendants are reached through the group.
  if [ -z "$v2_cg$mem_cg" ] && [ -n "$child" ]; then kill -"$1" -- "-$child" 2>/dev/null || true; fi
}

# A signal to this wrapper (a harness killing its PID on a timeout, say) is passed on to the whole
# run, and the wrapper then waits for the run to end before it lets go of the slot: otherwise the
# run kept going with no supervisor and its slot free for the next one. TERM is what is passed on,
# whatever arrived — a non-interactive shell starts background jobs with INT ignored, so a forwarded
# INT would do nothing. A run that ignores TERM is killed after $grace seconds. A signal before the
# run has started means it never starts. Either way the wrapper exits 143.
got_signal=""
killer=""
# shellcheck disable=SC2329 # invoked by the traps
on_signal() {
  got_signal=1
  if [ -z "$child" ]; then exit 143; fi
  signal_run TERM
  if [ -z "$killer" ]; then
    ( sleep "$grace"; signal_run KILL ) >/dev/null 2>&1 </dev/null &
    killer=$!
  fi
}
trap on_signal INT TERM HUP

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  # Whatever outlived the command (a stray Chrome) is still in the cgroup, and a cgroup with members
  # cannot be removed: end it first.
  local i
  if [ -n "$killer" ]; then kill "$killer" 2>/dev/null || true; fi
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -z "$(run_pids)" ] && break
    signal_run KILL
    sleep 0.2
  done
  [ "$i" = 10 ] && [ -n "$(run_pids)" ] && echo "capped-run: processes outlived the run and could not be ended" >&2
  for d in "$mem_cg" "$cpu_cg" "$v2_cg"; do
    [ -n "$d" ] && [ -d "$d" ] && rmdir "$d" 2>/dev/null || true
  done
}
trap cleanup EXIT

hard="off"
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  v2_cg=/sys/fs/cgroup/$name
  if mkdir "$v2_cg" 2>/dev/null \
    && echo "$mem_bytes" > "$v2_cg/memory.max" 2>/dev/null \
    && echo "$(( cpus * 100000 )) 100000" > "$v2_cg/cpu.max" 2>/dev/null; then
    hard="cgroup v2"
  else
    rmdir "$v2_cg" 2>/dev/null || true; v2_cg=""
  fi
elif [ -d /sys/fs/cgroup/memory ] && [ -d /sys/fs/cgroup/cpu ]; then
  mem_cg=/sys/fs/cgroup/memory/$name cpu_cg=/sys/fs/cgroup/cpu/$name
  if mkdir "$mem_cg" "$cpu_cg" 2>/dev/null \
    && echo "$mem_bytes" > "$mem_cg/memory.limit_in_bytes" \
    && echo "$(( cpus * $(cat "$cpu_cg/cpu.cfs_period_us") ))" > "$cpu_cg/cpu.cfs_quota_us"; then
    # No swap past the cap where the kernel accounts it; absent when swap accounting is off.
    [ -f "$mem_cg/memory.memsw.limit_in_bytes" ] \
      && echo "$mem_bytes" > "$mem_cg/memory.memsw.limit_in_bytes" 2>/dev/null || true
    hard="cgroup v1"
  else
    rmdir "$mem_cg" "$cpu_cg" 2>/dev/null || true; mem_cg="" cpu_cg=""
  fi
fi

echo "capped-run: slot $slot/$slots, $cpus CPU, $(( mem_bytes / 1024 / 1024 )) MiB, hard limits: $hard" >&2
# Test hook (capped-run_test.sh): widen the window between installing the signal trap and starting the
# run, so a test can signal inside it. Unset in normal use.
if [ -n "${BURPSY_RUN_TEST_PRESTART_SLEEP:-}" ]; then sleep "$BURPSY_RUN_TEST_PRESTART_SLEEP"; fi

export GOMAXPROCS=$cpus
export GOMEMLIMIT=$(( mem_bytes * 8 / 10 ))
export GOFLAGS="${GOFLAGS:+$GOFLAGS }-p=$cpus"

# The child joins the cgroups before exec, so everything it starts is inside them; this shell stays
# outside to report, pass signals on and clean up. A join that fails is said out loud: the run then
# goes ahead uncapped, and the line above would otherwise claim it was capped.
set +e
(
  for d in "$mem_cg" "$cpu_cg" "$v2_cg"; do
    if [ -n "$d" ] && ! echo "$BASHPID" > "$d/cgroup.procs"; then
      echo "capped-run: could not join $d; this run is NOT hard-capped" >&2
    fi
  done
  # Its own process group, so a signal reaches what the run starts even without a cgroup.
  if command -v setsid >/dev/null 2>&1; then exec setsid "$@"; fi
  exec "$@"
) {lockfd}>&- &
child=$!
# A signal that landed between the fork and the line above is passed on now.
if [ -n "$got_signal" ]; then signal_run TERM; fi
# wait returns early when a trapped signal arrives; keep waiting until the run itself has ended.
while :; do
  wait "$child"
  rc=$?
  kill -0 "$child" 2>/dev/null || break
done
set -e
if [ -n "$got_signal" ]; then rc=143; fi

oom=0
if [ -n "$v2_cg" ] && [ -f "$v2_cg/memory.events" ]; then
  oom=$(awk '$1 == "oom_kill" {print $2}' "$v2_cg/memory.events")
elif [ -n "$mem_cg" ] && [ -f "$mem_cg/memory.oom_control" ]; then
  oom=$(awk '$1 == "oom_kill" {print $2}' "$mem_cg/memory.oom_control")
fi
if [ "${oom:-0}" -gt 0 ] && [ "$rc" -ne 0 ]; then
  echo "capped-run: the memory cap ($(( mem_bytes / 1024 / 1024 )) MiB) killed part of this run; rerun with a larger --mem, or this is a real leak" >&2
fi
exit "$rc"
