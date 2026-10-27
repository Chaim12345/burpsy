#!/usr/bin/env bash
# ci-lint.sh — golangci-lint (v2) and govulncheck for the CI gate (bead burpsy-react-ui-ctdl).
#
#   scripts/ci-lint.sh lint [BASE_REV]   golangci-lint, NEW issues only: findings on lines changed
#                                        since BASE_REV (default HEAD^1). The tree's existing findings
#                                        do not fail the gate; every line a change touches must be clean.
#   scripts/ci-lint.sh vuln              govulncheck over burpsy-go; fails on a reachable vulnerability
#                                        that is not in scripts/ci/govulncheck-baseline.txt.
#   scripts/ci-lint.sh install           install the pinned tools only.
#
# Run from anywhere. Both tools are installed at their pinned versions with `go install` into
# $BURPSY_TOOLS_BIN (default ~/.local/bin) unless that version is already there; the Go module proxy's
# checksum database verifies what is built. Config: scripts/ci/golangci.yml.
set -euo pipefail

GOLANGCI_LINT_VERSION=v2.15.0
GOVULNCHECK_VERSION=v1.9.0

root=$(cd "$(dirname "$0")/.." && pwd)
bin=${BURPSY_TOOLS_BIN:-$HOME/.local/bin}
mkdir -p "$bin"
export PATH="$bin:$PATH"
[ -z "${GITHUB_PATH:-}" ] || echo "$bin" >>"$GITHUB_PATH"

install_tools() {
  # Captured, not piped into grep -q: grep exits at its first match, the tool takes SIGPIPE, and
  # under pipefail that made an installed tool look missing.
  local have
  have=$(golangci-lint version 2>/dev/null || true)
  if ! grep -q "version ${GOLANGCI_LINT_VERSION#v}" <<<"$have"; then
    echo "installing golangci-lint $GOLANGCI_LINT_VERSION"
    GOBIN="$bin" go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$GOLANGCI_LINT_VERSION"
  fi
  have=$(govulncheck -version 2>/dev/null || true)
  if ! grep -q "govulncheck@${GOVULNCHECK_VERSION}" <<<"$have"; then
    echo "installing govulncheck $GOVULNCHECK_VERSION"
    GOBIN="$bin" go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
  fi
}

cmd=${1:-}
case "$cmd" in
  install) install_tools ;;
  lint)
    install_tools
    base=${2:-HEAD^1}
    if ! git -C "$root" rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
      echo "ci-lint: cannot resolve base '$base'; falling back to HEAD^1" >&2
      base=HEAD^1
    fi
    if ! git -C "$root" rev-parse --verify --quiet "$base^{commit}" >/dev/null; then
      echo "ci-lint: no base revision to compare with (is the checkout shallow at depth 1?); refusing to pass" >&2
      exit 1
    fi
    echo "golangci-lint $GOLANGCI_LINT_VERSION: new issues since $(git -C "$root" rev-parse --short "$base")"
    cd "$root/burpsy-go"
    golangci-lint run --config "$root/scripts/ci/golangci.yml" --new-from-rev="$base" ./...
    ;;
  vuln)
    install_tools
    cd "$root/burpsy-go"
    # The scan's output goes to a file first: a govulncheck that dies (killed, no network) must
    # fail the step, not feed the gate an empty stream. -scan symbol (the default) is what makes
    # "reachable" mean reachable.
    out=$(mktemp)
    trap 'rm -f "$out"' EXIT
    govulncheck -format json ./... >"$out"
    python3 -I "$root/scripts/ci-vulncheck-gate.py" "$root/scripts/ci/govulncheck-baseline.txt" <"$out"
    ;;
  *) sed -n '2,10p' "$0" >&2; exit 2 ;;
esac
