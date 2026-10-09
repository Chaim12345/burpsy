#!/usr/bin/env bash
# review-gate.sh BASE HEAD [--labeled] [--pushed BEFORE AFTER | --reopened] — the `review-gate` check.
#
# Lists the files BASE...HEAD (from their merge base) changes that fall in a risk class
# (docs/DEVELOPMENT-PROCESS.md section 7). Those need an independent reviewer — a fresh agent with
# the diff and that list, not the author — whose sign-off is the PR label `agent-reviewed`.
#
# The label means "reviewed since the last change to a risk path", and this script is what keeps it
# meaning that. The workflow (.github/workflows/review-gate.yml) passes --pushed with a push's
# before/after shas; when that push touches a risk path the PR changes, the script exits 3 and the
# workflow REMOVES the label and fails. A later harmless push, a label event or a reopen therefore
# cannot pass on a sign-off that predates the risk-path change: the sign-off is gone. The reviewer
# re-reviews and re-applies the label, which re-runs this check.
#
#   --pushed BEFORE AFTER  a push moved the PR head from BEFORE to AFTER. If BEFORE is missing or
#                          not an ancestor of AFTER (a force-push, or history this clone cannot
#                          see), every risk path the PR touches counts as changed.
#   --reopened             the PR was reopened. Pushes to a closed PR fire no event, so what changed
#                          while it was closed is unknown: treated as every risk path changed.
#
# Exit status:
#   0  no risk path touched; or touched, --labeled, and no revocation due
#   1  risk path touched and not --labeled; or any crates/ change (refused, label or not)
#   2  usage error, or a revision that does not resolve (fails closed: no verdict without a diff)
#   3  --labeled, but the sign-off is stale (see above): the caller must remove the label; failing
#
# The lists are paths, not semantics. A risk-class change made in a file not listed here (say, a new
# authorisation check added to an unlisted handler) is invisible to this gate; when that happens,
# add the file here, in the same PR. A path git has to quote (control characters, a newline) is
# treated as a risk path rather than matched: a name built to slip past a glob fails closed.
#
# Under pull_request_target the workflow runs THIS FILE AS IT IS ON THE DEFAULT BRANCH, never the
# PR's copy: a PR cannot edit the rules it is judged by. Changes to this file take effect for the
# PRs after the one that changes it.
set -euo pipefail

usage() { echo "usage: $0 BASE HEAD [--labeled] [--pushed BEFORE AFTER | --reopened]" >&2; exit 2; }
[ $# -ge 2 ] || usage
base=$1 head=$2
shift 2
labeled=0 before="" after="" reopened=0
while [ $# -gt 0 ]; do
  case "$1" in
    --labeled) labeled=1 ;;
    --pushed) [ $# -ge 3 ] || usage; before=$2; after=$3; shift 2 ;;
    --reopened) reopened=1 ;;
    *) usage ;;
  esac
  shift
done

commit() { git rev-parse --verify --quiet "$1^{commit}" || { echo "review-gate: '$1' is not a commit here; no verdict without a diff" >&2; exit 2; }; }
base=$(commit "$base")
head=$(commit "$head")

risk=(
  # The one authorising path to a socket, and the HTTP/2 authorisation it shares.
  "burpsy-go/internal/sender/*|sender"
  "burpsy-go/internal/http2/authorise.go|sender"
  # Scope and authorisation: what may be sent where, and who may drive the API.
  "burpsy-go/internal/core/scope*.go|scope/authorisation"
  "burpsy-go/internal/crawler/prefix_scope.go|scope/authorisation"
  "burpsy-go/cmd/burpsy/cli_scope.go|scope/authorisation"
  "burpsy-go/internal/web/api_scope_check.go|scope/authorisation"
  "burpsy-go/internal/web/api_authz.go|scope/authorisation"
  "burpsy-go/internal/web/api_sameorigin.go|scope/authorisation"
  # Gated / destructive routes: the manifest that classifies them, the confirmation gate, and the
  # generator and client copy of the gated list.
  "burpsy-go/internal/web/route_manifest.go|gated routes + MCP risk-class placement"
  "burpsy-go/internal/web/confirm_gate.go|gated routes"
  "burpsy-go/internal/web/ui/scripts/gen-gated-routes.ts|gated routes"
  "burpsy-go/internal/web/ui/src/lib/gated-routes.ts|gated routes"
  "burpsy-go/internal/web/ui/src/lib/route-risk.ts|gated routes"
  # MCP risk-class placement: which tools an MCP client is offered, in which group.
  "burpsy-go/internal/mcp/groups.go|MCP risk-class placement"
  # Credential, client-certificate, CA and TLS material. proxy.go is listed whole because it mints
  # the CA and the per-host leaves (x509.CreateCertificate); a path list cannot name a function.
  "burpsy-go/internal/netauth/*|credentials/client-cert"
  "burpsy-go/internal/servercerts/*|CA/TLS"
  "burpsy-go/internal/proxy/proxy.go|CA/TLS"
  "burpsy-go/internal/proxy/listener_cert.go|CA/TLS"
  "burpsy-go/internal/proxy/tls_*.go|CA/TLS"
  "burpsy-go/internal/web/api_ca.go|CA/TLS"
  "burpsy-go/internal/web/api_ca_export.go|CA/TLS"
  "burpsy-go/internal/web/api_server_certs.go|CA/TLS"
  "burpsy-go/internal/web/api_tlspolicy.go|CA/TLS"
  "burpsy-go/internal/web/api_netauth.go|credentials/client-cert"
  # CI, its pinned versions and SHA-256s, and the code the gates run.
  ".github/*|workflows/pinned hashes"
  "scripts/review-gate.sh|CI gate code"
  "scripts/beads-lint.py|CI gate code"
  # What the `ui` job runs (package.json's `check` script) and what it installs (lockfile, bun
  # config, the TypeScript settings tsc --noEmit checks against): editing these edits the UI gate.
  "burpsy-go/internal/web/ui/package.json|CI gate code/dependencies"
  "burpsy-go/internal/web/ui/bun.lock|CI gate code/dependencies"
  "burpsy-go/internal/web/ui/bunfig.toml|CI gate code/dependencies"
  "burpsy-go/internal/web/ui/tsconfig.json|CI gate code/dependencies"
  # Code that runs on every developer machine, and the merge rules that once wiped the tracker.
  ".beads/hooks/*|git hooks"
  ".gitattributes|merge drivers"
)

# risk_of PATH — print the class PATH falls in, or nothing.
risk_of() {
  local f=$1 entry
  case "$f" in \"*) echo "unusual file name"; return ;; esac
  for entry in "${risk[@]}"; do
    # shellcheck disable=SC2053 # the right-hand side is a glob on purpose
    if [[ "$f" == ${entry%%|*} ]]; then echo "${entry#*|}"; return; fi
  done
}

# Command substitution, not a process substitution: a failing git diff fails the script (set -e)
# instead of reading as "no files changed".
files=$(git diff --name-only --no-renames "$base...$head")

hits=() hitpaths=() crates=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in crates/* | \"crates/*) crates+=("$f"); continue ;; esac
  class=$(risk_of "$f")
  if [ -n "$class" ]; then hits+=("$f  [$class]"); hitpaths+=("$f"); fi
done <<<"$files"

status=0
if [ ${#crates[@]} -gt 0 ]; then
  echo "::error::crates/ is the frozen Rust parity oracle; changes to it are refused, not reviewed:"
  printf '  %s\n' "${crates[@]}"
  status=1
fi

if [ ${#hits[@]} -eq 0 ]; then
  echo "review-gate: no risk-class path touched."
  exit "$status"
fi

echo "review-gate: risk-class paths touched:"
printf '  %s\n' "${hits[@]}"

if [ "$labeled" = 0 ]; then
  echo "::error::This PR touches the risk-class paths above. It needs an independent agent review"
  echo "::error::(docs/DEVELOPMENT-PROCESS.md section 7) and then the label 'agent-reviewed'."
  exit 1
fi

late=()
if [ "$reopened" = 1 ]; then
  echo "review-gate: reopened — pushes while closed are invisible; treating every risk path as changed"
  late=("${hitpaths[@]}")
elif [ -n "$before" ]; then
  b=$(git rev-parse --verify --quiet "$before^{commit}" || true)
  a=$(commit "$after")
  if [ -z "$b" ] || ! git merge-base --is-ancestor "$b" "$a"; then
    echo "review-gate: previous head $before is missing or not an ancestor of $after (force-push?);"
    echo "review-gate: treating every risk path as changed"
    late=("${hitpaths[@]}")
  else
    pushed=$(git diff --name-only --no-renames "$b" "$a")
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      for h in "${hitpaths[@]}"; do
        if [ "$h" = "$f" ]; then late+=("$f"); break; fi
      done
    done <<<"$pushed"
  fi
fi

if [ ${#late[@]} -gt 0 ]; then
  echo "::error::'agent-reviewed' predates changes to these risk-class paths; the label is revoked:"
  printf '  %s\n' "${late[@]}"
  echo "::error::Re-review the PR at its current head, then re-apply the label."
  exit 3
fi

echo "review-gate: labelled agent-reviewed, and no risk path changed since."
exit "$status"
