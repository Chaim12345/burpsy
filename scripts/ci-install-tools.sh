#!/usr/bin/env bash
# ci-install-tools.sh — provision the external tools the Go test gate exercises. Shared by the
# GitHub Actions gate (.github/actions/burpsy-test-env) and the Buildkite pipeline (.buildkite/),
# so both run the suite against the same pinned binaries. Moved here verbatim in intent from
# go.yml; the reasons for each pin and each refusal are recorded below with the step.
#
# Environment:
#   BURPSY_TOOLS_BIN        where binaries go (default ~/.local/bin); added to GITHUB_PATH when set
#   BURPSY_DOWNLOAD_CACHE   archive cache directory (default ~/.cache/burpsy-ci-downloads); a CI
#                           cache may restore it, but every archive is re-checked against its pin
#
# Each install leaves a stamp holding the SHA-256 of the archive it came from. A tool whose stamp
# matches its pin (and whose files are present) is not fetched again: that is what makes the tools
# baked into the Buildkite agent image (.buildkite/Dockerfile) a no-op here, while an image built
# before a pin changed still gets the newly pinned release.
set -euo pipefail

bin=${BURPSY_TOOLS_BIN:-$HOME/.local/bin}
dl=${BURPSY_DOWNLOAD_CACHE:-$HOME/.cache/burpsy-ci-downloads}
mkdir -p "$bin" "$dl"

FFUF_VERSION=2.1.0
FFUF_SHA256=fc2c82736c14dcbea4daf3d3cf3878c1c4773008ba45c2bc0fceba7d17b40bb5
NUCLEI_VERSION=3.8.0
NUCLEI_SHA256=cd4ea43c88b50af8ab96eb6ad3fb4debd8e9d51efaff4d4c2d99106041578943
INTERACTSH_VERSION=1.3.1
INTERACTSH_SHA256=d553fb3dd4c2684c953aedeb555f13f0d1ca94bd75112c949a5fd975d385a903
TEMPLATES_VERSION=10.4.8
TEMPLATES_SHA256=53ae80d9bcfff638fbff62c4b730c436564b6bf5e05cf4f86a7eefe37c7ecc47

# Chrome is a real dependency of the DOM catalog rows, not an optional extra. The suite has a
# BURPSY_ALLOW_NO_CHROME escape hatch for a deliberately reduced environment, and CI deliberately
# does NOT set it: a run that quietly demonstrated 35 fewer rows than the pin claims is precisely
# the "we did not look" reported as "we looked and found nothing" that this project forbids. Fail
# here, loudly, rather than silently reducing coverage minutes later.
chrome=""
for name in chromium google-chrome google-chrome-stable chrome; do
  if command -v "$name" >/dev/null 2>&1; then chrome=$name; break; fi
done
if [ -z "$chrome" ]; then
  echo "ci-install-tools: no Chrome/Chromium on PATH; the DOM catalog rows cannot be exercised" >&2
  exit 1
fi
echo "found $chrome: $("$chrome" --version 2>&1 | head -1)"

# Start it once, here, the way internal/domexec starts it (headless, no sandbox: the tests run it
# as root in containers and as the runner user here), so a shard's first test does not pay for a
# cold start, and so a Chrome that cannot start at all is visible here with its own error output
# instead of only as "websocket url timeout reached" deep in a test (bead burpsy-react-ui-2o0c).
# The time is printed; a failed warm-up FAILS this script and shows the tail of what Chrome said. It
# used to only warn and leave it to the tests, but a browser test that cannot launch Chrome skips,
# and before the skip ledger (internal/domexec/domexectest, bead burpsy-react-ui-chrome-skip-green)
# that skip was green: ~35 domexec tests reported "ok" having run nothing. The ledger now fails the
# package too, but failing here names the real cause once, with Chrome's own output, instead of as a
# list of skipped tests in every shard.
#
# It runs in the BACKGROUND while xmllint and the pinned tools install, and is reported (time, exit
# status, stderr tail) by warm_report at the end of this script. On GitHub runners the warm-up took
# 13-15s and the apt/download work after it ~10s, serially, in every test job (run 38360049157,
# 2026-10-13); overlapping them takes the shorter of the two off every job. The diagnostics are
# unchanged; the measured time now includes contention with the installs, which only makes a slow
# start look slower, never a failed one look healthy.
warm_log=$(mktemp)
warm_rc=$(mktemp)
warm_start=$(date +%s)
( rc=0; timeout -k 10 120 "$chrome" --headless --no-sandbox --disable-gpu --no-first-run --dump-dom about:blank >/dev/null 2>"$warm_log" || rc=$?
  echo "$rc $(( $(date +%s) - warm_start ))" >"$warm_rc" ) &
warm_pid=$!
warm_report() {
  [ -f "$warm_rc" ] || return 0  # already reported
  wait "$warm_pid" || true
  local rc secs
  read -r rc secs <"$warm_rc" || { rc=unknown; secs="?"; }
  if [ "$rc" = 0 ]; then
    echo "$chrome warm-up: ${secs}s (in parallel with the installs)"
    rm -f "$warm_log" "$warm_rc"
    return 0
  fi
  echo "ci-install-tools: $chrome warm-up failed (exit $rc) after ${secs}s, so the browser tests cannot run; its last output:" >&2
  tail -n 25 "$warm_log" >&2
  rm -f "$warm_log" "$warm_rc"
  return 1
}
# A failing install below must not swallow the warm-up's diagnostics. (As the EXIT trap its return
# status is ignored: the script is already failing for the install's reason.)
trap warm_report EXIT

# xmllint validates the Burp-XML export against the DTD in internal/report/burpxml.go. Without it
# those tests skip with a reason; installing it keeps CI from reporting "the export validates" over
# a test that never ran (burpsy-react-ui-m7dk).
if ! command -v xmllint >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    # NEEDRESTART_SUSPEND: the runner image's needrestart apt hook otherwise restarts services
    # (packagekit, php-fpm) after the install — ~4s of every job, for nothing a test uses. sudo
    # resets the environment, so it is passed through env.
    sudo env NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive apt-get update -qq
    sudo env NEEDRESTART_SUSPEND=1 DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends libxml2-utils
  else
    echo "ci-install-tools: xmllint missing and no apt-get to install it" >&2
    exit 1
  fi
fi
# Bare, not piped into head: head exits after one line, xmllint takes SIGPIPE on the rest, and
# under pipefail that aborted this step about one run in ten.
xmllint --version

stamps="$bin/.burpsy-ci-stamps"
mkdir -p "$stamps"
# A stamp's first line is the pinned archive's SHA-256; each further line is a sha256sum line for a
# binary installed from it, so a binary replaced in place after the stamp was written is caught.
# current NAME SHA256 PATH...: true when NAME was installed from the archive pinned as SHA256, every
# PATH still exists, and every stamped binary still has the hash it was installed with.
current() {
  local name=$1 sha=$2 f; shift 2
  [ "$(head -n1 "$stamps/$name" 2>/dev/null)" = "$sha" ] || return 1
  for f in "$@"; do [ -e "$f" ] || return 1; done
  # A stamp with no binary hashes is stale whenever binaries are named: it predates those hashes,
  # so nothing says the binary is still the one that was installed.
  if [ "$(wc -l < "$stamps/$name")" -gt 1 ]; then
    tail -n +2 "$stamps/$name" | sha256sum -c --status - || return 1
  else
    for f in "$@"; do [ -f "$f" ] && return 1; done
  fi
  echo "$name already at its pin"
}
# stamp NAME SHA256 [BINARY...]
stamp() {
  local name=$1 sha=$2; shift 2
  { echo "$sha"; if [ $# -gt 0 ]; then sha256sum "$@"; fi; } > "$stamps/$name"
}

# fetch FILE SHA256 URL: reuse a cached archive only if it already matches its pin, and check the
# pin on whatever was used. A hash pinned here proves the release is the reviewed one, which the
# release's own checksums file cannot.
fetch() {
  if [ -f "$dl/$1" ] && echo "$2  $dl/$1" | sha256sum -c --status -; then
    echo "using the cached $1"
  else
    curl -fsSL -o "$dl/$1" "$3"
  fi
  echo "$2  $dl/$1" | sha256sum -c -
}

# ffuf and nuclei are installed because internal/extscan's capability gate fails the package when
# a binary is missing. Published release binaries, not `go install`: compiling nuclei with this
# module's toolchain broke on a go:linkname into encoding/json under Go 1.26.
if ! current ffuf "$FFUF_SHA256" "$bin/ffuf"; then
  fetch ffuf.tar.gz "$FFUF_SHA256" \
    "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz"
  tar -xzf "$dl/ffuf.tar.gz" -C "$bin" ffuf
  stamp ffuf "$FFUF_SHA256" "$bin/ffuf"
fi
if ! current nuclei "$NUCLEI_SHA256" "$bin/nuclei"; then
  fetch nuclei.zip "$NUCLEI_SHA256" \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
  unzip -o -q "$dl/nuclei.zip" nuclei -d "$bin"
  stamp nuclei "$NUCLEI_SHA256" "$bin/nuclei"
fi
# interactsh-client: internal/web's batch-mint test registers against the real public pool.
if ! current interactsh "$INTERACTSH_SHA256" "$bin/interactsh-client"; then
  fetch interactsh.zip "$INTERACTSH_SHA256" \
    "https://github.com/projectdiscovery/interactsh/releases/download/v${INTERACTSH_VERSION}/interactsh-client_${INTERACTSH_VERSION}_linux_amd64.zip"
  unzip -o -q "$dl/interactsh.zip" interactsh-client -d "$bin"
  stamp interactsh "$INTERACTSH_SHA256" "$bin/interactsh-client"
fi

# The nuclei template corpus, as a pinned archive rather than `nuclei -update-templates` (which
# installed nothing on a fresh runner and said nothing). The test checks the http dir directly.
templates="$HOME/.local/nuclei-templates"
if ! current templates "$TEMPLATES_SHA256" "$templates/http"; then
  # Replace, not overlay: a corpus left over from an older pin must not mix into the new one.
  rm -rf "$templates"
  mkdir -p "$templates"
  fetch templates.tar.gz "$TEMPLATES_SHA256" \
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${TEMPLATES_VERSION}.tar.gz"
  tar -xzf "$dl/templates.tar.gz" -C "$templates" --strip-components=1
  stamp templates "$TEMPLATES_SHA256"
fi
test -d "$templates/http" || { echo "ci-install-tools: nuclei template corpus did not land in $templates" >&2; exit 1; }

warm_report || exit 1

if [ -n "${GITHUB_PATH:-}" ]; then echo "$bin" >> "$GITHUB_PATH"; fi
export PATH="$bin:$PATH"
# Run, not just present: a binary that cannot start fails here, as the old inline step did.
"$bin/ffuf" -V
"$bin/nuclei" -version
"$bin/interactsh-client" -version
