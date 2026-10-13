#!/usr/bin/env bash
# ci-shard.sh SHARD       run one shard of the Go test gate. Run from the repo root.
# ci-shard.sh plan SHARD  say whether SHARD has anything to run (see CI_AFFECTED_BASE below).
# ci-shard.sh all         list the shards.
# ci-shard.sh verify      prove their union is every test in the module, each selected once.
#
# The full `go test ./...` is split so the shards run in parallel CI jobs (GitHub Actions and
# Buildkite both call this script, so the two pipelines cannot drift apart). The split exists
# because one package, internal/scanner, was the whole critical path: 441s of an ~9-minute
# `go test ./...` on CI, dominated by two tests (the request-budget test and the detection test,
# 271s and 223s of test time on the 2026-10-09 green run 37984373730).
#
# Shards (the union is every test in the module, by construction — `verify` checks it):
#   scanner-budget    internal/scanner: TestAnAuditSendsProbesAndStaysWithinARequestBudget
#   scanner-detect    internal/scanner: TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo
#   scanner-rest-0/1  internal/scanner: every other test, split in two by index
#   rest              every package except internal/scanner and internal/web
#   race-web-0/1      internal/web under -race, its tests split in two by index
#
# There is no plain (non-race) internal/web shard. Until 2026-10-13 a `web` shard ran exactly the
# tests race-web-0/1 run, only without -race. The race run executes the same tests (internal/web has
# no `race` build tag and no race.Enabled check, so no test exists in one build and not the other),
# which made `web` ~3 runner-minutes of pure duplication per run. scanner-rest was split in two at
# the same time: at 649s of test time on 2026-10-13 (run 38360049157) it was the critical path of
# the whole gate, ahead of scanner-budget's single test at 414s.
#
# Completeness rules, so a split never silently drops a test:
#   - the two pinned scanner tests are checked to exist before running; a rename fails this
#     script instead of leaving a shard that runs nothing and passes;
#   - scanner-rest-0/1 are computed from `go test -list` at run time, minus exactly those two
#     names, so a new scanner test lands in one of them;
#   - rest is "every package except the two above", computed from `go list` at run time;
#   - an index shard that selects no test fails.
#
# Environment:
#   CI_AFFECTED_BASE  Affected mode (pull requests into master): run only what
#                     scripts/affected-go-tests.sh selects for BASE...HEAD — the changed packages plus
#                     every package whose tests import one, transitively. A shard whose package is
#                     not selected runs nothing and says so; rest runs only the selected packages it
#                     owns. Unset: everything (pushes to master, nightly, Buildkite, local repro).
#   CI_SHARD_RACE=1   Run every shard under -race (the nightly race matrix). race-web-* always is.
#   CI_SHARD_GO_TEST_FLAGS  Extra `go test` flags, word-split. go.yml passes -vet=off: its lint job
#                     runs the full `go vet ./...`, a superset of the vet subset go test re-runs.
set -euo pipefail

shards=(scanner-budget scanner-detect scanner-rest-0 scanner-rest-1 rest race-web-0 race-web-1)
usage="usage: ci-shard.sh SHARD | plan SHARD | all | verify   (shards: ${shards[*]})"

verb=run
case "${1:-}" in
  plan) verb=plan; shift ;;
  all) printf '%s\n' "${shards[@]}"; exit 0 ;;
  verify) verb=verify ;;
esac
shard=${1:?$usage}

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo/burpsy-go"

mod=$(go list -m)
scanner="$mod/internal/scanner"
web="$mod/internal/web"
budget=TestAnAuditSendsProbesAndStaysWithinARequestBudget
detect=TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo

race=()
timeout=(-timeout 1700s)
if [ "${CI_SHARD_RACE:-}" = 1 ]; then
  race=(-race)
  # Race-instrumented code runs several times slower; the nightly job's timeout-minutes is the
  # real bound.
  timeout=(-timeout 6600s)
fi
extra=()
read -r -a extra <<<"${CI_SHARD_GO_TEST_FLAGS:-}" || true

# list_tests PKG: the package's top-level tests, one per line (go test -list prints them plus an
# "ok" line). Fails if listing fails — a package that does not compile is not "no tests". The
# explicit `|| return` matters: errexit is off inside the command substitutions that call this,
# so without it a build failure came back as an empty list and was reported as a missing test.
list_tests() {
  local out
  out=$(go test -list '.*' "$1") || { echo "ci-shard: could not list the tests in $1 (see the build error above)" >&2; return 1; }
  printf '%s\n' "$out" | grep -E '^(Test|Fuzz|Example)' || true
}

require_test() {
  # The list is captured first: `grep -q` stops reading at its match, and under pipefail the
  # writer's SIGPIPE would read as "the test is gone".
  local names
  names=$(list_tests "$scanner") || exit 1
  if ! grep -qxF "$1" <<<"$names"; then
    echo "ci-shard: $1 no longer exists in $scanner; update scripts/ci-shard.sh so no shard runs nothing" >&2
    exit 1
  fi
}

# index_names PKG N I [EXCLUDE...]: the package's tests minus EXCLUDE, every Nth starting at the Ith.
index_names() {
  local pkg=$1 n=$2 i=$3 names ex
  shift 3
  names=$(list_tests "$pkg") || return 1
  for ex in "$@"; do names=$(grep -vxF "$ex" <<<"$names" || true); done
  awk -v n="$n" -v i="$i" 'NF { if (k % n == i) print; k++ }' <<<"$names"
}

rest_pkgs() { go list ./... | grep -vxF -e "$scanner" -e "$web" || true; }

if [ "$verb" = verify ]; then
  # Recompute every shard's selection and compare the union with the module's tests. Compiles the
  # test binaries of internal/scanner and internal/web to list them; runs no test.
  # compare WHAT ALL GOT: GOT (the shards' union, sorted, duplicates kept) must equal ALL.
  rc=0
  compare() {
    if [ "$2" != "$3" ]; then
      echo "ci-shard verify: the $1 shards do not select exactly its tests (< missing, > extra or duplicated):" >&2
      diff <(echo "$2") <(echo "$3") >&2 || true
      rc=1
    else
      echo "ci-shard verify: $1: $(wc -l <<<"$2") tests, each selected by exactly one shard"
    fi
  }
  all=$(list_tests "$scanner" | sort)
  got=$({
    echo "$budget"; echo "$detect"
    index_names "$scanner" 2 0 "$budget" "$detect"
    index_names "$scanner" 2 1 "$budget" "$detect"
  } | sort)
  compare internal/scanner "$all" "$got"
  all=$(list_tests "$web" | sort)
  got=$({ index_names "$web" 2 0; index_names "$web" 2 1; } | sort)
  compare internal/web "$all" "$got"
  every=$(go list ./... | sort)
  covered=$({ echo "$scanner"; echo "$web"; rest_pkgs; } | sort)
  if [ "$every" != "$covered" ]; then
    echo "ci-shard verify: package coverage differs from go list ./...:" >&2
    diff <(echo "$every") <(echo "$covered") >&2 || true
    rc=1
  else
    echo "ci-shard verify: $(wc -l <<<"$every") packages: internal/scanner, internal/web and $(rest_pkgs | wc -l) in rest, each in exactly one shard"
  fi
  exit $rc
fi

case " ${shards[*]} " in
  *" $shard "*) ;;
  *) echo "ci-shard: unknown shard '$shard'; run 'ci-shard.sh all' for the list" >&2; exit 2 ;;
esac

case "$shard" in
  scanner-*) own=$scanner ;;
  race-web-*) own=$web ;;
  rest) own="" ;;
esac

# selected: the packages this shard runs. reason: why it is empty, in affected mode.
reason=""
if [ -n "${CI_AFFECTED_BASE:-}" ]; then
  affected=$("$repo/scripts/affected-go-tests.sh" "$CI_AFFECTED_BASE") || { echo "ci-shard: affected-go-tests.sh failed" >&2; exit 1; }
  if [ -z "$own" ]; then
    selected=$(grep -vxF -e "$scanner" -e "$web" <<<"$affected" || true)
    reason="no package outside internal/scanner and internal/web is affected by $CI_AFFECTED_BASE...HEAD"
  else
    selected=$(grep -xF "$own" <<<"$affected" || true)
    reason="${own#"$mod"/} is not affected by $CI_AFFECTED_BASE...HEAD (neither changed nor importing a changed package)"
  fi
else
  if [ -z "$own" ]; then selected=$(rest_pkgs); else selected=$own; fi
  [ -n "$selected" ] || { echo "ci-shard: no packages left for the $shard shard" >&2; exit 1; }
fi

if [ "$verb" = plan ]; then
  if [ -n "$selected" ]; then
    echo "ci-shard: $shard will run: $(tr '\n' ' ' <<<"${selected//"$mod"\//}")"
    run=true
  else
    echo "ci-shard: $shard has nothing to run: $reason"
    run=false
  fi
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "run=$run" >>"$GITHUB_OUTPUT"; fi
  if [ "$run" = false ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '**%s: NOT RUN.** %s. The full suite runs on the push to master.\n' "$shard" "$reason" >>"$GITHUB_STEP_SUMMARY"
  fi
  exit 0
fi

if [ -z "$selected" ]; then
  # Reachable only in affected mode; said loudly so a green job is never read as "tests passed".
  echo "ci-shard: $shard runs NOTHING: $reason"
  exit 0
fi

gotest() { exec go test -count=1 "${race[@]}" "${extra[@]}" "$@"; }

case "$shard" in
  scanner-budget)
    require_test "$budget"
    gotest "${timeout[@]}" -run "^${budget}\$" "$scanner"
    ;;
  scanner-detect)
    require_test "$detect"
    gotest "${timeout[@]}" -run "^${detect}\$" "$scanner"
    ;;
  scanner-rest-0|scanner-rest-1)
    require_test "$budget"
    require_test "$detect"
    names=$(index_names "$scanner" 2 "${shard##*-}" "$budget" "$detect") || exit 1
    [ -n "$names" ] || { echo "ci-shard: $shard selected no tests" >&2; exit 1; }
    echo "ci-shard: $shard runs $(wc -l <<<"$names") of internal/scanner's tests${race[*]:+ under -race}"
    gotest "${timeout[@]}" -run "^($(paste -sd'|' - <<<"$names"))\$" "$scanner"
    ;;
  rest)
    # shellcheck disable=SC2086 # one package path per word, by design
    gotest "${timeout[@]}" $selected
    ;;
  race-web-0|race-web-1)
    names=$(index_names "$web" 2 "${shard##*-}") || exit 1
    [ -n "$names" ] || { echo "ci-shard: $shard selected no tests" >&2; exit 1; }
    echo "ci-shard: $shard runs $(wc -l <<<"$names") of internal/web's tests under -race"
    race=(-race)
    if [ "${CI_SHARD_RACE:-}" != 1 ]; then timeout=(-timeout 900s); fi
    gotest "${timeout[@]}" -run "^($(paste -sd'|' - <<<"$names"))\$" "$web"
    ;;
esac
