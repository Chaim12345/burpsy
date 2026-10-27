#!/usr/bin/env bash
# ci-fuzz_test.sh — checks ci-fuzz.sh's list, its verify guard and its CI_FUZZ_ONLY selection.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
f="$root/scripts/ci-fuzz.sh"; fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want [$2], got [$3]"; fail=1; fi; }
check "lists 10 targets" 10 "$("$f" list | wc -l | tr -d ' ')"
check "one process per target (no duplicates)" 10 "$("$f" list | sort -u | wc -l | tr -d ' ')"
out=$("$f" verify 2>&1); rc=$?
if grep -rqE '^func FuzzDechunk\(' --include='*_test.go' "$root/burpsy-go/internal/httputil"; then
  check "verify passes when targets exist" 0 "$rc"
else
  check "verify fails and names a missing target" "1 1" "$rc $(grep -c 'FuzzDechunk is not defined' <<<"$out")"
fi
check "unknown CI_FUZZ_ONLY selects nothing and fails" 1 "$(CI_FUZZ_ONLY=NoSuchTarget "$f" run >/dev/null 2>&1; echo $?)"
check "bad verb is usage error" 2 "$("$f" bogus >/dev/null 2>&1; echo $?)"
exit $fail
