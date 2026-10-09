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

# xmllint validates the Burp-XML export against the DTD in internal/report/burpxml.go. Without it
# those tests skip with a reason; installing it keeps CI from reporting "the export validates" over
# a test that never ran (burpsy-react-ui-m7dk).
if ! command -v xmllint >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y -qq libxml2-utils
  else
    echo "ci-install-tools: xmllint missing and no apt-get to install it" >&2
    exit 1
  fi
fi
xmllint --version 2>&1 | head -1

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
fetch ffuf.tar.gz "$FFUF_SHA256" \
  "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz"
tar -xzf "$dl/ffuf.tar.gz" -C "$bin" ffuf
fetch nuclei.zip "$NUCLEI_SHA256" \
  "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
unzip -o -q "$dl/nuclei.zip" nuclei -d "$bin"
# interactsh-client: internal/web's batch-mint test registers against the real public pool.
fetch interactsh.zip "$INTERACTSH_SHA256" \
  "https://github.com/projectdiscovery/interactsh/releases/download/v${INTERACTSH_VERSION}/interactsh-client_${INTERACTSH_VERSION}_linux_amd64.zip"
unzip -o -q "$dl/interactsh.zip" interactsh-client -d "$bin"

# The nuclei template corpus, as a pinned archive rather than `nuclei -update-templates` (which
# installed nothing on a fresh runner and said nothing). The test checks the http dir directly.
templates="$HOME/.local/nuclei-templates"
mkdir -p "$templates"
fetch templates.tar.gz "$TEMPLATES_SHA256" \
  "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${TEMPLATES_VERSION}.tar.gz"
tar -xzf "$dl/templates.tar.gz" -C "$templates" --strip-components=1
test -d "$templates/http" || { echo "ci-install-tools: nuclei template corpus did not land in $templates" >&2; exit 1; }

if [ -n "${GITHUB_PATH:-}" ]; then echo "$bin" >> "$GITHUB_PATH"; fi
export PATH="$bin:$PATH"
"$bin/ffuf" -V
"$bin/nuclei" -version 2>&1 | grep -m1 -i 'engine version' || true
"$bin/interactsh-client" -version 2>&1 | grep -m1 -i version || true
