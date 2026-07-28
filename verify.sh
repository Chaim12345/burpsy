#!/usr/bin/env bash
# The single definition of "this tree is good".
#
# Used both directly and by integrate.sh after every branch merge. Having one script means a merge
# cannot be declared fine against a weaker bar than the one the branch itself was held to.
#
# Exit code is the verdict; the summary block at the end is for humans.
set -uo pipefail
cd "$(dirname "$0")"

QUICK=${QUICK:-0}   # QUICK=1 skips the e2e suites (they need free ports and ~1 min)
FAIL=0
SKIP=0
SKIPPED=()
step(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok(){   printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
no(){   printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
# A check that did not run is NOT a check that passed.
#
# All three of these used to call `ok`, so an absent BCheck corpus, a missing rustup, or QUICK=1
# printed green and the summary said VERIFIED. That is the failure HARD-02 names: "a skipped check
# reports as skipped rather than as a pass". It matters more than it looks — verify.sh is the single
# definition of "this tree is good" and integrate.sh runs it after every merge, so a skip that reads
# as a pass silently lowers the bar a branch was held to.
skip(){ printf '  \033[33mSKIP\033[0m  %s\n' "$1"; SKIP=$((SKIP+1)); SKIPPED+=("$1"); }

step "build (warnings count as failure)"
BUILD=$(cargo build --workspace 2>&1)
if grep -qE '^error' <<<"$BUILD"; then
  no "build errors"
  grep -E '^error' -A6 <<<"$BUILD" | head -40
else
  WARN=$(grep -cE '^warning' <<<"$BUILD")
  if [ "$WARN" -gt 0 ]; then
    no "$WARN build warning(s)"
    grep -E '^warning' -A4 <<<"$BUILD" | head -30
  else
    ok "clean build, zero warnings"
  fi
fi

step "clippy"
# Three traps here, each of which cost real time to rediscover.
#
# 1. cargo and clippy can come from DIFFERENT toolchains. On this machine /usr/bin/cargo is a
#    distro build of 1.92.0 and shadows rustup's shims in PATH, while clippy-driver exists only
#    under rustup at 1.95.0. Running plain `cargo clippy` mixes them and every workspace crate
#    fails with E0514, "found crate X compiled by an incompatible version of rustc". So clippy is
#    invoked through rustup's own cargo, which is guaranteed to match its clippy-driver.
#    A rust-toolchain.toml would NOT fix this: it is a rustup feature, and /usr/bin/cargo ignores
#    it entirely.
#
# 2. Pinning `cargo` is NOT enough — cargo (even rustup's own binary) resolves the `rustc` it
#    shells out to via a bare PATH lookup unless told otherwise, and /usr/bin/rustc (1.92) sits
#    ahead of the rustup shim in PATH here too. So rustup's cargo would happily go compile every
#    dependency with the WRONG rustc, and clippy-driver (1.95) would then reject its own build's
#    output with the identical E0514. `RUSTC` must be pinned explicitly, to rustup's rustc, not
#    just `cargo`.
#
# 3. Even on a fully consistent toolchain, clippy sets RUSTC_WORKSPACE_WRAPPER, which changes the
#    fingerprint of every workspace crate. Sharing target/ therefore makes clippy and a plain build
#    invalidate each other, rebuilding the world on every alternation. Its own target dir costs disk
#    and buys back all of that time.
if command -v rustup >/dev/null 2>&1 \
   && RUSTUP_CARGO=$(rustup which cargo 2>/dev/null) \
   && RUSTUP_RUSTC=$(rustup which rustc 2>/dev/null); then
  CLIPPY=$(RUSTC="$RUSTUP_RUSTC" CARGO_TARGET_DIR=target/clippy "$RUSTUP_CARGO" clippy --workspace --all-targets 2>&1)
  if grep -qE '^error' <<<"$CLIPPY"; then
    no "clippy failed to run"
    grep -E '^error' -A8 <<<"$CLIPPY" | head -30
  else
    CW=$(grep -cE '^warning: .*$' <<<"$CLIPPY" | head -1)
    # Ignore the per-crate roll-up lines ("generated N warnings"), count only real lints.
    CW=$(grep -E '^warning:' <<<"$CLIPPY" | grep -vcE 'generated [0-9]+ warning')
    if [ "$CW" -gt 0 ]; then
      no "$CW clippy warning(s)"
      grep -E '^warning:' <<<"$CLIPPY" | grep -vE 'generated [0-9]+ warning' | head -15
    else
      ok "clippy clean"
    fi
  fi
else
  skip "clippy did not run: rustup not available (its clippy-driver must match the rustc that built the deps)"
fi

step "unit tests"
TESTS=$(cargo test --workspace 2>&1)
NFAIL=$(grep -cE '^test .* FAILED' <<<"$TESTS")
NPASS=$(grep -E 'test result: ok\.' <<<"$TESTS" | sed 's/test result: ok\. //' | awk '{s+=$1} END{print s+0}')
if [ "$NFAIL" -gt 0 ]; then
  no "$NFAIL test(s) failing"
  grep -E '^test .* FAILED|panicked at' <<<"$TESTS" | head -20
else
  ok "$NPASS tests passing"
fi

step "BCheck corpus conformance"
if [ -d /tmp/BChecks ]; then
  CONF=$(cargo run -q --bin conform 2>&1)
  PARSED=$(grep -oE 'parsed OK      : [0-9]+' <<<"$CONF" | grep -oE '[0-9]+$')
  CFAIL=$(grep -oE '^failed         : [0-9]+' <<<"$CONF" | grep -oE '[0-9]+$')
  MODS=$(grep -oE 'TOTAL +[0-9]+' <<<"$CONF" | grep -oE '[0-9]+$')
  [ "${CFAIL:-1}" = "0" ] && ok "${PARSED} corpus checks parsed, 0 failed" || no "corpus: $CFAIL failed to parse"
  # 381 modifier clauses, cross-checked against an independent grep of the corpus. A drop here means
  # the parser silently started discarding request mutations again.
  [ "${MODS:-0}" -ge 381 ] && ok "$MODS modifier clauses captured (>=381)" \
    || no "only ${MODS:-0} modifier clauses captured, expected >=381"
else
  skip "BCheck corpus conformance did not run: /tmp/BChecks absent — the partition invariant is UNVERIFIED on this machine"
fi

if [ "$QUICK" = "1" ]; then
  step "e2e suites"; skip "e2e suites did not run (QUICK=1)"
else
  step "e2e suites"
  # Sequential: each script does `pkill -x burpsy` on cleanup and would kill its siblings.
  for s in e2e*.sh; do
    [ -x "$s" ] || continue
    R=$(./"$s" 2>&1 | tail -3 | grep -oE '[0-9]+ passed, [0-9]+ failed')
    case "$R" in
      *" 0 failed") ok "$s — $R" ;;
      "")           no "$s — no result line (did it start?)" ;;
      *)            no "$s — $R" ;;
    esac
  done
fi

# The verdict distinguishes three states, not two. "Everything that ran, passed" and "everything
# passed" are different claims, and only the second one earns an unqualified VERIFIED.
if [ "$SKIP" -gt 0 ]; then
  printf '\n\033[1m%s check(s) did not run:\033[0m\n' "$SKIP"
  for s in "${SKIPPED[@]}"; do printf '  \033[33m-\033[0m %s\n' "$s"; done
fi

printf '\n\033[1m######## '
if [ "$FAIL" -ne 0 ]; then
  printf "\033[31m$FAIL CHECK(S) FAILED\033[0m"
elif [ "$SKIP" -gt 0 ]; then
  printf "\033[33mVERIFIED WITH GAPS ($SKIP skipped)\033[0m"
else
  printf '\033[32mVERIFIED\033[0m'
fi
printf '\033[1m ########\033[0m\n'

# Exit code stays the failure count: a skip is not a failure, and making it one would mean nobody
# could run QUICK=1. The distinction is carried in the summary, which is what a human reads, and in
# STRICT=1 for a caller that wants skips to be fatal.
if [ "${STRICT:-0}" = "1" ] && [ "$SKIP" -gt 0 ] && [ "$FAIL" -eq 0 ]; then
  printf '\033[31mSTRICT=1: %s skipped check(s) treated as failure\033[0m\n' "$SKIP"
  exit "$SKIP"
fi
exit "$FAIL"
