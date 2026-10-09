#!/usr/bin/env bash
# ci-shard.sh SHARD — run one shard of the T3 Go test gate. Run from the repo root.
#
# The full `go test ./...` is split so the shards run in parallel CI jobs (GitHub Actions and
# Buildkite both call this script, so the two pipelines cannot drift apart). The split exists
# because one package, internal/scanner, was the whole critical path: 441s of an ~9-minute
# `go test ./...` on CI, dominated by two tests (the request-budget test and the detection test,
# ~128s and ~84s locally), with every other package done in under two minutes alongside it.
#
# Shards (the union is every test in the module, by construction — see `all` below):
#   scanner-budget   internal/scanner: TestAnAuditSendsProbesAndStaysWithinARequestBudget
#   scanner-detect   internal/scanner: TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo
#   scanner-rest     internal/scanner: every other test (-skip the two above)
#   web              internal/web
#   rest             every other package
#   race-web-0/1     internal/web under -race, its tests split in two by index
#
# Completeness rules, so a split never silently drops a test:
#   - the two pinned scanner tests are checked to exist before running; a rename fails this
#     script instead of leaving a shard that runs nothing and passes;
#   - scanner-rest uses -skip with exactly those two names, so a new scanner test lands there;
#   - rest is "every package except the two above", computed from `go list` at run time;
#   - race shards are computed from `go test -list` at run time and must be non-empty.
set -euo pipefail

shard=${1:?usage: ci-shard.sh SHARD   (scanner-budget scanner-detect scanner-rest web rest race-web-0 race-web-1)}
cd "$(dirname "$0")/../burpsy-go"

mod=$(go list -m)
scanner="$mod/internal/scanner"
web="$mod/internal/web"
budget=TestAnAuditSendsProbesAndStaysWithinARequestBudget
detect=TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo
timeout=(-timeout 1700s)

# list_tests PKG: the package's top-level tests, one per line (go test -list prints them plus an
# "ok" line). Fails if listing fails — a package that does not compile is not "no tests".
list_tests() {
  local out
  out=$(go test -list '.*' "$1")
  printf '%s\n' "$out" | grep -E '^(Test|Fuzz|Example)' || true
}

require_test() {
  # The list is captured first: `grep -q` stops reading at its match, and under pipefail the
  # writer's SIGPIPE would read as "the test is gone".
  local names
  names=$(list_tests "$scanner")
  if ! grep -qx "$1" <<<"$names"; then
    echo "ci-shard: $1 no longer exists in $scanner; update scripts/ci-shard.sh so no shard runs nothing" >&2
    exit 1
  fi
}

case "$shard" in
  scanner-budget)
    require_test "$budget"
    exec go test -count=1 "${timeout[@]}" -run "^${budget}\$" "$scanner"
    ;;
  scanner-detect)
    require_test "$detect"
    exec go test -count=1 "${timeout[@]}" -run "^${detect}\$" "$scanner"
    ;;
  scanner-rest)
    require_test "$budget"
    require_test "$detect"
    exec go test -count=1 "${timeout[@]}" -skip "^(${budget}|${detect})\$" "$scanner"
    ;;
  web)
    exec go test -count=1 "${timeout[@]}" "$web"
    ;;
  rest)
    pkgs=$(go list ./... | grep -vxF -e "$scanner" -e "$web")
    [ -n "$pkgs" ] || { echo "ci-shard: no packages left for the rest shard" >&2; exit 1; }
    # shellcheck disable=SC2086 # one package path per word, by design
    exec go test -count=1 "${timeout[@]}" $pkgs
    ;;
  race-web-0|race-web-1)
    want=${shard##*-}
    names=$(list_tests "$web" | awk -v w="$want" '(NR - 1) % 2 == w')
    [ -n "$names" ] || { echo "ci-shard: $shard selected no tests" >&2; exit 1; }
    count=$(printf '%s\n' "$names" | wc -l)
    regex="^($(printf '%s\n' "$names" | paste -sd'|' -))\$"
    echo "ci-shard: $shard runs $count of internal/web's tests under -race"
    exec go test -race -count=1 -timeout 900s -run "$regex" "$web"
    ;;
  all)
    # Print the shard list, for CI matrices and for checking the split by hand.
    printf '%s\n' scanner-budget scanner-detect scanner-rest web rest race-web-0 race-web-1
    ;;
  *)
    echo "ci-shard: unknown shard '$shard'; run 'ci-shard.sh all' for the list" >&2
    exit 2
    ;;
esac
