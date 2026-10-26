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
BIN_DIR="$OUT_DIR/bin"; mkdir -m 0700 -- "$BIN_DIR" || die "cannot create $BIN_DIR"   # inside OUT_DIR; NEVER auto-removed

# Preflight evidence is written BEFORE anything is compiled or run.
COMPILE_MIB=${COMPILE_MIB:-3072}
[[ $COMPILE_MIB =~ ^[1-9][0-9]*$ ]] || die "COMPILE_MIB must be a positive integer"
{ echo "host: $(uname -srm)"; echo "go: $(go version)"; echo "git HEAD: $(git rev-parse HEAD)"; echo "base: $BASE_SHA"
  echo "test sha256: $TEST_SHA256"; echo "capped-run sha256: $(sha256sum "$CR" | awk '{print $1}')"
  echo "MemAvailable_KB: $(awk '/MemAvailable/{print $2}' /proc/meminfo) cpus: $(nproc) cap_MiB: $MEM_MIB compile_MiB: $COMPILE_MIB cases: $CASES"
  echo "cgroup mounts: $(grep cgroup /proc/mounts | awk '{print $3}' | sort | uniq -c | tr '\n' ' ')"
} | tee "$OUT_DIR/host.txt"

# run_capped NAME MIB TIMEOUT CMD...   Runs CMD inside capped-run.sh. Inside the cap, BEFORE exec'ing CMD, the
# shell persists ITS OWN cgroup path and reads memory.max; CMD starts only if memory.max == MIB*1048576 (else exit 97).
# So no compile or case work starts unless the cap is proven in effect from inside.
run_capped() {
  local name=$1 mib=$2 tmo=$3; shift 3
  local inner='cg=$(cut -d: -f3 /proc/self/cgroup); echo "$cg" >"$OUT_DIR/$NAME.cgroup"
         m=$(cat "/sys/fs/cgroup$cg/memory.max" 2>&1); echo "memory.max in effect: $m"
         [ "$m" = "$(( MIB * 1024 * 1024 ))" ] || { echo "CAP NOT IN EFFECT"; exit 97; }
         exec "$@"'
  BURPSY_KILL_GRACE=5 NAME=$name MIB=$mib OUT_DIR=$OUT_DIR \
    timeout -k 30 "$tmo" "$CR" --cpus 1 --mem "${mib}M" --slots 1 -- bash -c "$inner" _ "$@" >"$OUT_DIR/$name.log" 2>&1
  local rc=$?; echo "$rc" >"$OUT_DIR/$name.rc"
  hard=$(grep -o 'hard limits: .*' "$OUT_DIR/$name.log" | head -1)
  readback=$(grep -c "memory.max in effect: $(( mib * 1024 * 1024 ))\$" "$OUT_DIR/$name.log")
  echo "== $name exit=$rc | ${hard:-no capped-run line} | readback-matches=$readback"
  grep -E "memory.max in effect|CAP NOT|err=|fatal|out of memory|memory cap|FAIL|PASS|SKIP" "$OUT_DIR/$name.log" | head -8 | cut -c1-200
  CAPPED_OK=1
  case "$hard" in *"cgroup v2"*) ;; *) CAPPED_OK=0;; esac
  [ "$readback" = 1 ] || CAPPED_OK=0
  # Cleanup proof from THIS run's own recorded cgroup path: it must be gone, or have an empty cgroup.procs.
  sleep 1
  local cgp; cgp=$(cat "$OUT_DIR/$name.cgroup" 2>/dev/null)
  if [ -z "$cgp" ]; then echo "   -> no own-cgroup path recorded for $name"; CAPPED_OK=0
  elif [ "$cgp" = / ]; then echo "   -> own cgroup is the root: cap not in effect"; CAPPED_OK=0
  elif [ -d "/sys/fs/cgroup$cgp" ]; then
    if [ -n "$(cat "/sys/fs/cgroup$cgp/cgroup.procs" 2>/dev/null)" ] || grep -q '^populated 1' "/sys/fs/cgroup$cgp/cgroup.events" 2>/dev/null; then
      echo "   -> LEFTOVER: own cgroup $cgp still has processes after $name"; CLEAN=0; CAPPED_OK=0
    fi
  fi
  pgrep -f -- "$BIN_DIR" >/dev/null && { echo "   -> LEFTOVER process matching $BIN_DIR after $name"; CLEAN=0; CAPPED_OK=0; }
  { echo "$name: exit=$rc capped_ok=$CAPPED_OK clean=$CLEAN own_cgroup=${cgp:-none}"; } >>"$OUT_DIR/host.txt"
}
CLEAN=1; valid=1

# Compile runs INSIDE the proven cap too; on a failed readback the compile never starts.
run_capped compile "$COMPILE_MIB" 300 go test -c -o "$BIN_DIR/jsadv.test" ./internal/jsexec
if [ "$CAPPED_OK" != 1 ] || [ "$(cat "$OUT_DIR/compile.rc")" != 0 ] || [ ! -x "$BIN_DIR/jsadv.test" ]; then
  valid=0; echo "   -> compile not capped/clean/successful: nothing adversarial was run (see $OUT_DIR/compile.log)"
else
  for k in $CASES; do
    run_capped "$k" "$MEM_MIB" 90 env BURPSY_ADV_HARNESS=1 ADV="$k" "$BIN_DIR/jsadv.test" -test.run TestAdversarialResourceHarness -test.v
    [ "$CAPPED_OK" = 1 ] || { valid=0; echo "   -> cap/cleanup not proven for $k: not valid evidence; stopping"; break; }
  done
fi
( cd "$OUT_DIR" && sha256sum ./*.log ./*.rc ./*.cgroup host.txt > SHA256SUMS ) && echo "raw logs and SHA256SUMS kept in $OUT_DIR (valid=$valid clean=$CLEAN)"
# The binary is deleted ONLY when everything was proven clean; otherwise it and all evidence are left in place.
[ "$valid" = 1 ] && [ "$CLEAN" = 1 ] && rm -rf -- "$BIN_DIR"
[ "$valid" = 1 ]
