#!/usr/bin/env bash
# ci-shard_test.sh — checks that scripts/ci-shard.sh wires the race-core shard (bead
# burpsy-react-ui-8pki: internal/proxy, internal/dash and internal/pool under -race on every run;
# bead burpsy-react-ui-racepr: internal/sender and internal/intruder joined it), in full mode and in
# affected mode (pull requests). Needs Go, git and the module's dependencies; compiles and runs no
# test. Run from anywhere; ~1 minute.
#
# Affected mode is exercised for real rather than mocked: the repository is cloned (--shared, so no
# object copy) into a temp directory, the WORKING-TREE copies of ci-shard.sh and
# affected-go-tests.sh are dropped into it (so an uncommitted edit is what gets tested), and one
# throwaway commit per case adds a file to one package. `ci-shard.sh plan` then runs with
# CI_AFFECTED_BASE set to the commit before it, exactly as go.yml's test job runs it on a PR.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
shard="$root/scripts/ci-shard.sh"
fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: want [$2], got [$3]"; fail=1; fi; }

# ---- full mode (pushes to master, nightly, Buildkite) ----
check "race-core is a listed shard" 1 "$("$shard" all | grep -cx race-core)"
plan=$("$shard" plan race-core 2>&1)
rest=$("$shard" plan rest 2>&1)
for p in proxy dash pool sender intruder; do
  check "race-core runs internal/$p" 1 "$(grep -cw "internal/$p" <<<"$plan")"
  check "rest no longer runs internal/$p (race-core owns it)" 0 "$(grep -cw "internal/$p" <<<"$rest")"
done
check "rest still runs internal/persist" 1 "$(grep -cw 'internal/persist' <<<"$rest")"

# ---- affected mode (pull requests) ----
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git clone -q --shared --no-checkout "$root" "$tmp/repo" && git -C "$tmp/repo" checkout -q "$(git -C "$root" rev-parse HEAD)" \
  || { echo "FAIL could not clone $root for the affected-mode cases"; exit 1; }
cp "$root/scripts/ci-shard.sh" "$root/scripts/affected-go-tests.sh" "$tmp/repo/scripts/"
git -C "$tmp/repo" add scripts/ci-shard.sh scripts/affected-go-tests.sh
gitc() { git -C "$tmp/repo" -c core.hooksPath=/dev/null -c user.name=ci-shard-test -c user.email=ci-shard-test@invalid "$@"; }
gitc commit -q --allow-empty -m "ci-shard_test: working-tree scripts" || { echo "FAIL could not commit in the clone"; exit 1; }

# affected_plan DIR PKGNAME SHARD: commit a new file to package DIR (relative to burpsy-go/) and
# print `ci-shard.sh plan SHARD` in affected mode against the commit before it.
affected_plan() {
  local base
  base=$(git -C "$tmp/repo" rev-parse HEAD)
  printf 'package %s\n' "$2" >"$tmp/repo/burpsy-go/$1/zz_ci_shard_test.go"
  gitc add "burpsy-go/$1/zz_ci_shard_test.go" && gitc commit -q -m "touch $1" || return 1
  CI_AFFECTED_BASE=$base "$tmp/repo/scripts/ci-shard.sh" plan "$3" 2>&1
  gitc reset -q --hard "$base"
}

# A change to internal/sender: sender under -race, plus internal/proxy (it imports sender); not
# intruder, dash or pool, which do not.
plan=$(affected_plan internal/sender sender race-core)
check "PR touching sender: race-core will run" 1 "$(grep -c 'race-core will run' <<<"$plan")"
check "PR touching sender: race-core runs internal/sender" 1 "$(grep -cw 'internal/sender' <<<"$plan")"
check "PR touching sender: race-core runs internal/proxy (imports sender)" 1 "$(grep -cw 'internal/proxy' <<<"$plan")"
check "PR touching sender: race-core skips internal/intruder" 0 "$(grep -cw 'internal/intruder' <<<"$plan")"
check "PR touching sender: race-core skips internal/dash" 0 "$(grep -cw 'internal/dash' <<<"$plan")"
plan=$(affected_plan internal/sender sender rest)
check "PR touching sender: rest leaves sender to race-core" 0 "$(grep -cw 'internal/sender' <<<"$plan")"

# A change to internal/intruder: intruder under -race; not sender, which does not import it.
plan=$(affected_plan internal/intruder intruder race-core)
check "PR touching intruder: race-core runs internal/intruder" 1 "$(grep -cw 'internal/intruder' <<<"$plan")"
check "PR touching intruder: race-core skips internal/sender" 0 "$(grep -cw 'internal/sender' <<<"$plan")"

# A change no race-core package can see (a main package nothing imports): race-core runs nothing,
# and says why, naming its packages.
plan=$(affected_plan cmd/demo-target main race-core)
check "PR touching cmd/demo-target: race-core has nothing to run" 1 "$(grep -c 'race-core has nothing to run' <<<"$plan")"
check "PR touching cmd/demo-target: the reason names sender and intruder" 1 "$(grep -c 'internal/sender internal/intruder' <<<"$plan")"
plan=$(affected_plan cmd/demo-target main rest)
check "PR touching cmd/demo-target: rest runs it" 1 "$(grep -cw 'cmd/demo-target' <<<"$plan")"

exit $fail
