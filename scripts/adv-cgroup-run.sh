#!/usr/bin/env bash
# adv-cgroup-run.sh - run the adversarial pre-request-script cases (burpsy-go/internal/jsexec/adv_harness_test.go)
# one per process, each inside scripts/capped-run.sh with a HARD cgroup memory cap. TEST ONLY. Linux only
# (WSL2 counts). Fails closed. Nothing here touches the network, git history or any repo file.
#
#   MEM_MIB=<cgroup memory.max, MiB>   REQUIRED, no default. Physical memory, not virtual.
#   OUT_DIR=<path>                      REQUIRED. Must NOT exist: the script creates it mode 0700.
#   CASES="recurse"                     default: ONLY recurse (the first host run proves the controls).
#                                       Other cases (dbl repeat arr join) must be named explicitly, and run
#                                       only after the recurse run's logs were reviewed.
#   Run from burpsy-go/ of a TEMPORARY CLEAN checkout of the commit named in the request.
set -uo pipefail
BASE_SHA=abe595c74e38e7fd613a83e94374b7b1beb4d9d0     # the 1944 tip this harness extends
TEST_FILE=internal/jsexec/adv_harness_test.go
TEST_SHA256=cf9501ec6407516e65f83fcfeec160454c49f6b6ca79a0159faa208e49835db6                           # sha256 of the test file, checked below
MIN_GO=1.27.3
die() { echo "REFUSING: $*" >&2; exit 2; }

[ "$(uname -s)" = Linux ] || die "Linux only"
: "${MEM_MIB:?set MEM_MIB explicitly (cgroup memory.max, MiB)}"
: "${OUT_DIR:?set OUT_DIR to a path that does not exist yet}"
[[ $MEM_MIB =~ ^[1-9][0-9]*$ ]] || die "MEM_MIB must be a positive integer"
CASES=${CASES:-recurse}
for c in $CASES; do case $c in recurse|dbl|repeat|arr|join) ;; *) die "unknown case '$c'";; esac; done
for c in timeout go git flock setsid sha256sum awk pgrep; do command -v "$c" >/dev/null || die "missing command $c"; done
[ "$(basename "$PWD")" = burpsy-go ] || die "run from burpsy-go/"
CR=../scripts/capped-run.sh; [ -x "$CR" ] || die "../scripts/capped-run.sh missing or not executable"
[ -f "$TEST_FILE" ] || die "$TEST_FILE missing"

# Source pins: the commit descends from the base tip, the tree is clean, the test file is the pinned blob.
git merge-base --is-ancestor "$BASE_SHA" HEAD || die "HEAD does not descend from $BASE_SHA"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean"
[ "$(sha256sum "$TEST_FILE" | awk '{print $1}')" = "$TEST_SHA256" ] || die "test file hash differs from the pinned one"
# Production code must equal the base tip: only test-only files and this script may differ.
unexpected=$(git diff --name-only "$BASE_SHA" HEAD | grep -v -E '^(burpsy-go/internal/jsexec/adv_harness_test\.go|scripts/adv-cgroup-run\.sh)$' || true)
[ -z "$unexpected" ] || die "files differ from the base tip beyond the harness: $unexpected"
# Go toolchain at least go.mod's directive.
have=$(go env GOVERSION | sed 's/^go//'); [ "$(printf '%s\n%s\n' "$MIN_GO" "$have" | sort -V | head -1)" = "$MIN_GO" ] || die "go $have is older than $MIN_GO"

# Fresh private output dir: refuse an existing path or a symlink; create it 0700.
[ ! -e "$OUT_DIR" ] && [ ! -L "$OUT_DIR" ] || die "OUT_DIR already exists (use a fresh path)"
mkdir -m 0700 -- "$OUT_DIR" || die "cannot create OUT_DIR"
BIN_DIR=$(mktemp -d) || exit 1; trap 'rm -rf "$BIN_DIR"' EXIT   # removes only the compiled test binary

# Preflight + compile INSIDE a hard cap: the compile runs under capped-run.sh too (COMPILE_MIB, default 3072,
# one CPU), and the script refuses to go further unless that run reports "hard limits: cgroup v2". So a host
# without a working cgroup is detected here, before any adversarial case, and compile memory is bounded.
COMPILE_MIB=${COMPILE_MIB:-3072}
[[ $COMPILE_MIB =~ ^[1-9][0-9]*$ ]] || die "COMPILE_MIB must be a positive integer"
BURPSY_KILL_GRACE=5 timeout -k 30 300 "$CR" --cpus 1 --mem "${COMPILE_MIB}M" --slots 1 -- \
  go test -c -o "$BIN_DIR/jsadv.test" ./internal/jsexec >"$OUT_DIR/compile.log" 2>&1
crc=$?; echo "$crc" >"$OUT_DIR/compile.rc"
grep -q 'hard limits: cgroup v2' "$OUT_DIR/compile.log" || die "compile ran without a cgroup v2 hard cap (see $OUT_DIR/compile.log); nothing was run"
[ "$crc" = 0 ] && [ -x "$BIN_DIR/jsadv.test" ] || die "compile failed or timed out, exit $crc (see $OUT_DIR/compile.log)"
# Snapshot the burpsy-run-* cgroups that exist now: only NEW ones after a case count as ours.
before=$(ls /sys/fs/cgroup 2>/dev/null | grep '^burpsy-run-' | sort || true)
{ echo "host: $(uname -srm)"; echo "go: $(go version)"; echo "git HEAD: $(git rev-parse HEAD)"; echo "base: $BASE_SHA"
  echo "test sha256: $TEST_SHA256"; echo "capped-run sha256: $(sha256sum "$CR" | awk '{print $1}')"
  echo "MemAvailable_KB: $(awk '/MemAvailable/{print $2}' /proc/meminfo) cpus: $(nproc) cap_MiB: $MEM_MIB cases: $CASES"
} | tee "$OUT_DIR/host.txt"

valid=1
for k in $CASES; do
  out="$OUT_DIR/$k.log"
  # In the same capped process, read back memory.max FIRST; any other value or a read failure aborts with 97.
  inner='cg=/sys/fs/cgroup/$(cut -d: -f3 /proc/self/cgroup); m=$(cat "$cg/memory.max" 2>&1)
         echo "memory.max in effect: $m"
         [ "$m" = "$(( MEM_MIB * 1024 * 1024 ))" ] || { echo "CAP NOT IN EFFECT"; exit 97; }
         exec env BURPSY_ADV_HARNESS=1 ADV='"$k"' "$BIN" -test.run TestAdversarialResourceHarness -test.v'
  # Outer timeout must exceed capped-run's own TERM->KILL grace (BURPSY_KILL_GRACE=5): -k 30 leaves it room.
  BURPSY_KILL_GRACE=5 MEM_MIB=$MEM_MIB BIN="$BIN_DIR/jsadv.test" \
    timeout -k 30 90 "$CR" --cpus 1 --mem "${MEM_MIB}M" --slots 1 -- bash -c "$inner" >"$out" 2>&1
  rc=$?; echo "$rc" >"$OUT_DIR/$k.rc"
  hard=$(grep -o 'hard limits: .*' "$out" | head -1)
  readback=$(grep -c "memory.max in effect: $(( MEM_MIB * 1024 * 1024 ))\$" "$out")
  echo "== $k exit=$rc | ${hard:-no capped-run line} | readback-matches=$readback"
  grep -E "memory.max in effect|CAP NOT|err=|fatal|out of memory|memory cap|FAIL|PASS|SKIP" "$out" | head -8 | cut -c1-200
  # Valid only with a v2 hard cap AND the in-process readback matching.
  case "$hard" in *"cgroup v2"*) ;; *) valid=0;; esac
  [ "$readback" = 1 ] || valid=0
  # Nothing of this case may be left running, and its cgroup must be gone, before the next case or the end.
  sleep 1
  # Leftovers are scoped to THIS run: processes whose command line contains this run's private binary dir, and
  # burpsy-run-* cgroups that were not there before (another job's cgroups are not ours and are ignored).
  after=$(ls /sys/fs/cgroup 2>/dev/null | grep '^burpsy-run-' | sort || true)
  new_cg=$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | tr '\n' ' ')
  if pgrep -f -- "$BIN_DIR" >/dev/null || [ -n "${new_cg// /}" ]; then
    echo "   -> LEFTOVER after $k (process matching $BIN_DIR, or new cgroup: ${new_cg:-none}): stopping, not removing anything"
    valid=0; echo "leftover after $k: $new_cg" >>"$OUT_DIR/host.txt"; break
  fi
  [ "$valid" = 1 ] || { echo "   -> cap not proven for $k: this case is not valid evidence; stopping"; break; }
done
( cd "$OUT_DIR" && sha256sum ./*.log ./*.rc host.txt > SHA256SUMS ) && echo "raw logs and SHA256SUMS kept in $OUT_DIR (valid=$valid)"
[ "$valid" = 1 ]
