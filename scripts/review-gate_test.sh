#!/usr/bin/env bash
# review-gate_test.sh — checks review-gate.sh's verdicts in throwaway git repositories: which paths
# are risk-class (including a test that pins a risk-class file), and how a review sha is honoured.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
gate="$root/scripts/review-gate.sh"; fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want [$2], got [$3]"; fail=1; fi; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git -C "$tmp" init -q -b main && git -C "$tmp" config user.email t@t && git -C "$tmp" config user.name t
git -C "$tmp" commit -q --allow-empty -m base
base=$(git -C "$tmp" rev-parse HEAD)

# verdict PATH — exit status of the gate for one commit on top of base that changes PATH.
verdict() {
  git -C "$tmp" checkout -q -B "t$RANDOM" "$base"
  mkdir -p "$tmp/$(dirname "$1")" && echo x >"$tmp/$1"
  git -C "$tmp" add -A && git -C "$tmp" commit -q -m change
  (cd "$tmp" && "$gate" "$base" HEAD >/dev/null 2>&1); echo $?
}

for p in burpsy-go/internal/web/agent_tools.go burpsy-go/internal/web/confirm_binding.go \
  burpsy-go/internal/web/confirm_gate_test.go burpsy-go/internal/web/route_manifest_test.go \
  burpsy-go/internal/web/agent_tools_test.go burpsy-go/internal/web/ui/src/lib/route-manifest.ts \
  burpsy-go/internal/web/ui/src/lib/gated-routes.test.ts burpsy-go/internal/web/ui/src/lib/gated-routes.contract.test.ts \
  scripts/ci/govulncheck-baseline.txt scripts/ci-lint.sh scripts/ci-fuzz.sh burpsy-go/internal/sender/x.go; do
  check "risk path: $p" 1 "$(verdict "$p")"
done
for p in burpsy-go/internal/web/api_history.go burpsy-go/internal/web/api_history_test.go docs/x.md \
  burpsy-go/internal/web/ui/src/lib/format.test.ts; do
  check "not a risk path: $p" 0 "$(verdict "$p")"
done
check "crates/ is refused" 1 "$(verdict crates/x.rs)"

# A review at the head passes; a later risk-path commit invalidates it; a later harmless one keeps it.
verdict burpsy-go/internal/web/agent_tools.go >/dev/null
rev=$(git -C "$tmp" rev-parse HEAD)
check "approved at head passes" 0 "$(cd "$tmp" && "$gate" "$base" HEAD --reviewed-sha "$rev" >/dev/null 2>&1; echo $?)"
echo y >"$tmp/README" && git -C "$tmp" add -A && git -C "$tmp" commit -q -m docs
check "harmless push keeps the review" 0 "$(cd "$tmp" && "$gate" "$base" HEAD --reviewed-sha "$rev" >/dev/null 2>&1; echo $?)"
echo z >"$tmp/burpsy-go/internal/web/agent_tools_test.go" && git -C "$tmp" add -A && git -C "$tmp" commit -q -m pin
check "risk-path test pushed after review invalidates it" 1 "$(cd "$tmp" && "$gate" "$base" HEAD --reviewed-sha "$rev" >/dev/null 2>&1; echo $?)"
check "malformed sha is refused" 1 "$(cd "$tmp" && "$gate" "$base" HEAD --reviewed-sha abc >/dev/null 2>&1; echo $?)"
check "unresolvable base is a usage error" 2 "$(cd "$tmp" && "$gate" nope HEAD >/dev/null 2>&1; echo $?)"
exit $fail
