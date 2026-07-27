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
step(){ printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok(){   printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
no(){   printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }

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
  ok "rustup not available, clippy skipped"
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
  ok "corpus not present, conformance skipped"
fi

if [ "$QUICK" = "1" ]; then
  step "e2e suites"; ok "skipped (QUICK=1)"
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

printf '\n\033[1m######## '
[ "$FAIL" -eq 0 ] && printf '\033[32mVERIFIED\033[0m' || printf "\033[31m$FAIL CHECK(S) FAILED\033[0m"
printf '\033[1m ########\033[0m\n'
exit "$FAIL"
