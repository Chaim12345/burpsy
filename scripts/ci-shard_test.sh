#!/usr/bin/env bash
# ci-shard_test.sh — checks that scripts/ci-shard.sh wires the race-core shard (bead
# burpsy-react-ui-8pki: internal/proxy, internal/dash and internal/pool under -race on every run). Needs Go and
# the module's dependencies; compiles and runs no test.  Run from anywhere.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
shard="$root/scripts/ci-shard.sh"
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want [$2], got [$3]"; fail=1; fi; }

check "race-core is a listed shard" 1 "$("$shard" all | grep -cx race-core)"
plan=$("$shard" plan race-core 2>&1)
check "race-core runs internal/proxy" 1 "$(grep -c 'internal/proxy' <<<"$plan")"
check "race-core runs internal/dash" 1 "$(grep -c 'internal/dash' <<<"$plan")"
rest=$("$shard" plan rest 2>&1)
check "rest no longer runs internal/proxy (race-core owns it)" 0 "$(grep -cw 'internal/proxy' <<<"$rest")"
check "rest no longer runs internal/dash" 0 "$(grep -cw 'internal/dash' <<<"$rest")"
check "race-core runs internal/pool" 1 "$(grep -c "internal/pool" <<<"$plan")"
check "rest no longer runs internal/pool" 0 "$(grep -cw "internal/pool" <<<"$rest")"
check "rest still runs internal/persist" 1 "$(grep -cw 'internal/persist' <<<"$rest")"
exit $fail
