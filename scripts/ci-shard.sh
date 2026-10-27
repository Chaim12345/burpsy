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
#   scanner-budget    internal/scanner: TestAnAuditSendsProbesAndStaysWithinARequestBudget, alone
#   scanner-detect    internal/scanner: TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo,
#                     plus its share of the other scanner tests (see "Scanner balance")
#   scanner-rest-0/1  internal/scanner: the other scanner tests, split by measured time
#   rest              every package except internal/scanner, internal/web and race-core's
#   race-web-0/1      internal/web under -race, its tests split in two by index
#   race-core         internal/proxy, internal/dash, internal/pool, internal/sender and
#                     internal/intruder under -race, always (bead burpsy-react-ui-8pki: the race gate
#                     widens one package at a time; add a package here only after it has been run
#                     clean under -race, and watch this shard's time). sender and intruder joined for
#                     bead burpsy-react-ui-racepr: the 2026-10-27 review found a data race in one and
#                     a deadlock in the other, which until then only the nightly race run could see.
#                     In affected mode the shard runs only those of its packages the PR affects, so
#                     a PR touching internal/sender gets sender, and those of these packages that
#                     import it, under -race; one touching none of them runs nothing here.
#
# There is no plain (non-race) internal/web shard. Until 2026-10-13 a `web` shard ran exactly the
# tests race-web-0/1 run, only without -race. The race run executes the same tests (internal/web has
# no `race` build tag and no race.Enabled check, so no test exists in one build and not the other),
# which made `web` ~3 runner-minutes of pure duplication per run. scanner-rest was split in two at
# the same time: at 649s of test time on 2026-10-13 (run 38360049157) it was the critical path of
# the whole gate, ahead of scanner-budget's single test at 414s.
#
# Scanner balance. The budget test is one test (~414-434s on CI) and sets the floor. Every other
# scanner test is dealt to scanner-detect, scanner-rest-0 and scanner-rest-1 by a greedy
# longest-first partition on the per-test seconds in scripts/ci-shard-weights.txt (measured; the
# file's header says how to regenerate it), with the detect test pinned to scanner-detect. A test
# not in the file weighs the file's `default`, so a new test still lands in exactly one shard; a
# stale file only costs balance, never coverage. The split was by index until 2026-10-13, when the
# first run (38362486870) put 562s of test time in scanner-rest-0 and ~90s in scanner-rest-1: a
# handful of heavy tests happened to share a parity.
#
# Completeness rules, so a split never silently drops a test:
#   - the two pinned scanner tests are checked to exist before running; a rename fails this
#     script instead of leaving a shard that runs nothing and passes;
#   - the scanner partition is computed from `go test -list` at run time, minus exactly the budget
#     test, so a new scanner test lands in one of the three partitioned shards;
#   - rest is "every package except the two above", computed from `go list` at run time;
#   - an index shard that selects no test fails.
#
# Environment:
#   CI_AFFECTED_BASE  Affected mode (pull requests into master): run only what
#                     scripts/affected-go-tests.sh selects for BASE...HEAD — the changed packages plus
#                     every package whose tests import one, transitively. A shard whose package is
#                     not selected runs nothing and says so; rest runs only the selected packages it
#                     owns. Unset: everything (pushes to master, nightly, Buildkite, local repro).
#   CI_SHARD_RACE=1   Run every shard under -race (the nightly race matrix). race-web-* and race-core always are.
#   CI_SHARD_GO_TEST_FLAGS  Extra `go test` flags, word-split. go.yml passes -vet=off: its lint job
#                     runs the full `go vet ./...`, a superset of the vet subset go test re-runs.
set -euo pipefail

shards=(scanner-budget scanner-detect scanner-rest-0 scanner-rest-1 rest race-web-0 race-web-1 race-core)
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
# The packages the race-core shard owns, one per line; every other shard leaves them alone. rest,
# in both modes, excludes exactly notrest, so adding a package here moves it out of rest in one edit.
core="$mod/internal/proxy
$mod/internal/dash
$mod/internal/pool
$mod/internal/sender
$mod/internal/intruder"
notrest="$scanner
$web
$core"
budget=TestAnAuditSendsProbesAndStaysWithinARequestBudget
detect=TestTheScannerDetectsWhatTheTargetDeclaresItIsVulnerableTo

race=()
timeout=(-timeout 1700s)
# The scanner suite is wait-bound, not CPU-bound (W11 measurement on backlog-b9: three probe
# tests at 77-91% idle wall time; the same 10 DOM audits ran in 15.6s at -parallel 8 vs 40.9s at
# -parallel 1 with unchanged CPU). -parallel defaults to GOMAXPROCS (4 on CI), which throttles a
# suite that is mostly waiting. 12, not 16: one conservative step, measured, then climb on
# evidence. Subtests that must stay serial (the stored non-DOM rows of the budget test) never
# call t.Parallel, so their ordering is unchanged at any -parallel. Flake-watch: timing-sensitive
# checks (timing SQLi, rate-limit) - a contention flake reverts this.
parallel=(-parallel 12)
if [ "${CI_SHARD_RACE:-}" = 1 ]; then
  # Scanner under -race at raised parallelism is unmeasured (the race evidence covered
  # internal/web and race-core's packages only), so race-mode shards
  # keep the default -parallel. Integrator guard for evmi; robust to future workflow edits.
  parallel=()
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
# Memoized per package in a temp directory: every scanner shard lists the package three or four
# times (require_test, the partition), and each listing ran the test binary — ~50s of the shard's
# step on run 38362486870 before any test started.
list_cache=$(mktemp -d)
trap 'rm -rf "$list_cache"' EXIT
list_tests() {
  local out f="$list_cache/${1//\//_}"
  if [ -f "$f" ]; then cat "$f"; return 0; fi
  out=$(go test -list '.*' "$1") || { echo "ci-shard: could not list the tests in $1 (see the build error above)" >&2; return 1; }
  printf '%s\n' "$out" | grep -E '^(Test|Fuzz|Example)' >"$f" || true
  cat "$f"
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

# scanner_bin I: the scanner tests dealt to bin I (0 scanner-detect, 1 scanner-rest-0,
# 2 scanner-rest-1). Longest first, each to the currently lightest bin (ties to the lowest index),
# after the detect test is placed in bin 0. Deterministic for a given test list and weights file.
weights="$repo/scripts/ci-shard-weights.txt"
scanner_bin() {
  local bin=$1 names
  names=$(list_tests "$scanner") || return 1
  grep -vxF "$budget" <<<"$names" | awk -v wf="$weights" '
    BEGIN {
      def = 1
      while ((getline line < wf) > 0) {
        n = split(line, f, " ")
        if (n < 2 || f[1] ~ /^#/) continue
        if (f[1] == "default") def = f[2] + 0; else wt[f[2]] = f[1] + 0
      }
    }
    NF { printf "%.3f %s\n", ($1 in wt) ? wt[$1] : def, $1 }' |
    sort -k1,1gr -k2,2 |
    awk -v d="$detect" -v want="$bin" '
      { w[NR] = $1; t[NR] = $2; if ($2 == d) load[0] += $1 }
      END {
        for (k = 1; k <= NR; k++) {
          if (t[k] == d) { b = 0 } else {
            b = 0
            for (i = 1; i < 3; i++) if (load[i] + 0 < load[b] + 0) b = i
            load[b] += w[k]
          }
          if (b == want) print t[k]
        }
      }'
}

rest_pkgs() { go list ./... | grep -vxF "$notrest" || true; }

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
  got=$({ echo "$budget"; scanner_bin 0; scanner_bin 1; scanner_bin 2; } | sort)
  compare internal/scanner "$all" "$got"
  all=$(list_tests "$web" | sort)
  got=$({ index_names "$web" 2 0; index_names "$web" 2 1; } | sort)
  compare internal/web "$all" "$got"
  every=$(go list ./... | sort)
  covered=$({ echo "$scanner"; echo "$web"; echo "$core"; rest_pkgs; } | sort)
  if [ "$every" != "$covered" ]; then
    echo "ci-shard verify: package coverage differs from go list ./...:" >&2
    diff <(echo "$every") <(echo "$covered") >&2 || true
    rc=1
  else
    echo "ci-shard verify: $(wc -l <<<"$every") packages: internal/scanner, internal/web, race-core and $(rest_pkgs | wc -l) in rest, each in exactly one shard"
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
  race-core) own=$core ;;
  rest) own="" ;;
esac

# selected: the packages this shard runs. reason: why it is empty, in affected mode.
reason=""
if [ -n "${CI_AFFECTED_BASE:-}" ]; then
  affected=$("$repo/scripts/affected-go-tests.sh" "$CI_AFFECTED_BASE") || { echo "ci-shard: affected-go-tests.sh failed" >&2; exit 1; }
  if [ -z "$own" ]; then
    selected=$(grep -vxF "$notrest" <<<"$affected" || true)
    reason="no package outside internal/scanner, internal/web and race-core's $(tr '\n' ' ' <<<"${core//"$mod"\//}")is affected by $CI_AFFECTED_BASE...HEAD"
  else
    selected=$(grep -xF "$own" <<<"$affected" || true)
    reason="$(tr '\n' ' ' <<<"${own//"$mod"\//}")is not affected by $CI_AFFECTED_BASE...HEAD (neither changed nor importing a changed package)"
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

gotest() { go test -count=1 "${race[@]}" "${extra[@]}" "$@"; }  # not exec: the EXIT trap cleans the list cache

case "$shard" in
  scanner-budget)
    require_test "$budget"
    gotest "${timeout[@]}" "${parallel[@]}" -run "^${budget}\$" "$scanner"
    ;;
  scanner-detect|scanner-rest-0|scanner-rest-1)
    require_test "$budget"
    require_test "$detect"
    case "$shard" in scanner-detect) bin=0 ;; scanner-rest-0) bin=1 ;; scanner-rest-1) bin=2 ;; esac
    names=$(scanner_bin "$bin") || exit 1
    [ -n "$names" ] || { echo "ci-shard: $shard selected no tests" >&2; exit 1; }
    echo "ci-shard: $shard runs $(wc -l <<<"$names") of internal/scanner's tests${race[*]:+ under -race}"
    gotest "${timeout[@]}" "${parallel[@]}" -run "^($(paste -sd'|' - <<<"$names"))\$" "$scanner"
    ;;
  rest)
    # shellcheck disable=SC2086 # one package path per word, by design
    gotest "${timeout[@]}" $selected
    ;;
  race-core)
    race=(-race)
    if [ "${CI_SHARD_RACE:-}" != 1 ]; then timeout=(-timeout 900s); fi
    echo "ci-shard: race-core runs ${selected//"$mod"\//} under -race" | tr '\n' ' '; echo
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
