#!/usr/bin/env bash
# ci-fuzz.sh — the nightly fuzz run: one `go test -fuzz` process per target, because go test accepts
# a single fuzz target per invocation. Crashers land in testdata/fuzz/<Target>/ of the owning package.
#
#   ci-fuzz.sh run     fuzz every target for CI_FUZZ_TIME (default 60s) each; exit 1 if any failed
#   ci-fuzz.sh list    print "pkg Target" lines
#   ci-fuzz.sh verify  check that every listed target exists in its package, and that every target
#                      defined under internal/ is listed (compiles nothing, runs nothing)
#
# A listed target that does not exist is a failure, not a skip: a silently shrinking fuzz set is the
# failure this guard exists to stop. CI_FUZZ_ONLY=<Target> restricts a run to one target.
set -uo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
# package-dir target — the committed list. Add a line when a fuzz target is added: verify fails on a
# target defined under internal/ that is not listed (an unlisted target is never fuzzed, only seeded).
targets='httputil FuzzRequestURL
httputil FuzzDechunk
httputil FuzzParseChunkSize
httputil FuzzSplitHeadBody
httputil FuzzHeaderValue
httputil FuzzHeaderValueExact
proxy FuzzParseClientHelloALPN
proxy FuzzAltSvcLearn
proxy FuzzProxyDechunk
proxy FuzzReadFullRequest
proxy FuzzParseRequestLine
http2 FuzzDecodeFrameHeader
http2 FuzzReadFrames
http2 FuzzHpackDecode
core FuzzParse
core FuzzParseWsFrameHeader
grpcproto FuzzDecode
grpcproto FuzzParseProto
apidoc FuzzParse
bcheck FuzzParse
query FuzzParse
session FuzzJSONPath'
verb=${1:-run}
fuzztime=${CI_FUZZ_TIME:-60s}
cd "$repo/burpsy-go" || exit 1
case "$verb" in
  list) echo "$targets" ;;
  verify)
    rc=0
    while read -r pkg name; do
      if ! grep -rqE "^func $name\(" --include='*_test.go' "internal/$pkg" 2>/dev/null; then
        echo "ci-fuzz: $name is not defined in internal/$pkg" >&2; rc=1
      fi
    done <<<"$targets"
    # The reverse direction: a Fuzz function nobody listed is a parser that is never fuzzed.
    while IFS=: read -r file name; do
      pkg=$(dirname "${file#internal/}")
      if ! grep -qxF "$pkg $name" <<<"$targets"; then
        echo "ci-fuzz: $name in internal/$pkg is not listed in ci-fuzz.sh" >&2; rc=1
      fi
    done < <(grep -rHoE '^func Fuzz[A-Za-z0-9_]+' --include='*_test.go' internal | sed 's/:func /:/')
    [ $rc = 0 ] && echo "ci-fuzz verify: every listed target exists and every target is listed"
    exit $rc ;;
  run)
    rc=0; ran=0
    while read -r pkg name; do
      [ -n "${CI_FUZZ_ONLY:-}" ] && [ "$name" != "$CI_FUZZ_ONLY" ] && continue
      ran=$((ran + 1))
      echo "::group::fuzz $pkg $name ($fuzztime)"
      if ! go test -run '^$' -fuzz "^${name}\$" -fuzztime "$fuzztime" "./internal/$pkg/"; then
        echo "ci-fuzz: $name FAILED (a crasher, if any, is in internal/$pkg/testdata/fuzz/$name/)" >&2; rc=1
      fi
      echo "::endgroup::"
    done <<<"$targets"
    [ "$ran" -gt 0 ] || { echo "ci-fuzz: no target selected" >&2; exit 1; }
    exit $rc ;;
  *) echo "usage: ci-fuzz.sh run|list|verify" >&2; exit 2 ;;
esac
