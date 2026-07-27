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
