#!/usr/bin/env bash
# test-local.sh [COMMAND...] — run the Go test suite on a machine that lacks the external tools CI
# installs.
#
# Why this exists: the test packages deliberately refuse to pass when a capability was silently
# skipped. Without a startable Chrome, a package's TestMain fails (internal/domexec/domexectest);
# without ffuf/nuclei the extscan live tests fail (internal/extscan/live_test.go); and a scanner run
# that cannot demonstrate the pinned coverage fails (internal/scanner/runtime_coverage_test.go). That
# is "we did not look" refusing to read as "we looked and found nothing". CI has those tools; a
# laptop usually does not.
#
# The BURPSY_ALLOW_* variables are the documented escape hatch for a deliberately reduced
# environment. This script exports only the ones whose tool is actually missing, prints exactly what
# it will not exercise, and then execs the command it is given (default: `go test ./...` from
# burpsy-go/). It never sets a flag for a tool that is present, so a full local run is still a full
# run.
#
# Examples:
#   scripts/test-local.sh
#   scripts/test-local.sh go test ./internal/web/ -run TestThing
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
skipped=()

have() { command -v "$1" >/dev/null 2>&1; }

chrome=0
for c in chromium google-chrome google-chrome-stable; do
  if have "$c"; then chrome=1; break; fi
done
if [ "$chrome" -eq 0 ]; then
  export BURPSY_ALLOW_NO_CHROME=1
  export BURPSY_ALLOW_UNVERIFIED_COVERAGE=1
  skipped+=("Chrome/Chromium on PATH (BURPSY_ALLOW_NO_CHROME, BURPSY_ALLOW_UNVERIFIED_COVERAGE)")
fi

extscan_missing=""
have ffuf || extscan_missing="ffuf"
if have nuclei; then
  if [ ! -d "$HOME/.local/nuclei-templates/http" ]; then
    extscan_missing="${extscan_missing:+$extscan_missing, }nuclei templates"
  fi
else
  extscan_missing="${extscan_missing:+$extscan_missing, }nuclei"
fi
if [ -n "$extscan_missing" ]; then
  export BURPSY_ALLOW_UNVERIFIED_EXTSCAN=1
  skipped+=("$extscan_missing (BURPSY_ALLOW_UNVERIFIED_EXTSCAN)")
fi

if [ "${#skipped[@]}" -gt 0 ]; then
  echo "test-local: reduced environment, not exercised in this run:" >&2
  printf '  - %s\n' "${skipped[@]}" >&2
fi

cd "$root/burpsy-go"
if [ "$#" -eq 0 ]; then
  exec go test ./...
fi
exec "$@"