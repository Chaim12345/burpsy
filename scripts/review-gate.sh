#!/usr/bin/env bash
# review-gate.sh BASE HEAD [--reviewed-sha S] — the `review-gate` verdict for one PR head.
#
# Lists the files BASE...HEAD (from their merge base) changes that fall in a risk class
# (docs/DEVELOPMENT-PROCESS.md section 7). Those need an independent reviewer — a fresh agent with
# the diff and that list, not the author.
#
# Sign-off is bound to code, not to a label or to the order runs finish in. The reviewer posts a
# verdict naming the exact commit it reviewed (`agent-review: approve <40-hex sha>`);
# scripts/review-verdict.sh picks the latest valid verdict, and the workflow passes its sha as
# --reviewed-sha. This script then passes only if
#   - S is a commit and an ancestor of HEAD (it is in the PR's history), and
#   - `git diff S HEAD` touches no risk path: nothing that needs review changed after the review.
# So a risk-path push after the review invalidates it whatever order events arrive or runs finish
# in, a later harmless push keeps it, and a retargeted base changes nothing (the diff is from S).
# A merge of master into the PR branch that brings risk-path changes also invalidates it — those
# changes are in S..HEAD; that is deliberate (fail closed), and costs one re-review.
#
# Exit status:
#   0  no risk path touched; or touched, and --reviewed-sha passes the checks above
#   1  risk path touched without a valid review; or any crates/ change (refused, review or not)
#   2  usage error, or BASE/HEAD does not resolve (fails closed: no verdict without a diff)
# The last line printed is a one-line summary (the workflow uses it as the status description).
#
# The lists are paths, not semantics. A risk-class change made in a file not listed here (say, a new
# authorisation check added to an unlisted handler) is invisible to this gate; when that happens,
# add the file here, in the same PR. A path git has to quote (control characters, a newline) is
# treated as a risk path rather than matched: a name built to slip past a glob fails closed.
#
# The workflow runs THIS FILE AS IT IS ON THE DEFAULT BRANCH, never the PR's copy: a PR cannot edit
# the rules it is judged by. Changes to this file take effect for the PRs after the one that
# changes it.
set -euo pipefail

usage() { echo "usage: $0 BASE HEAD [--reviewed-sha SHA]" >&2; exit 2; }
[ $# -ge 2 ] || usage
base=$1 head=$2
shift 2
reviewed=""
while [ $# -gt 0 ]; do
  case "$1" in
    --reviewed-sha) [ $# -ge 2 ] || usage; reviewed=$2; shift ;;
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
  "scripts/review-verdict.sh|CI gate code"
  "scripts/beads-lint.py|CI gate code"
  "scripts/ci-shard.sh|CI gate code"
  "scripts/ci-install-tools.sh|CI gate code/pinned hashes"
  ".buildkite/*|CI pipeline/agent image"
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

hits=() crates=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in crates/* | \"crates/*) crates+=("$f"); continue ;; esac
  class=$(risk_of "$f")
  if [ -n "$class" ]; then hits+=("$f  [$class]"); fi
done <<<"$files"

if [ ${#crates[@]} -gt 0 ]; then
  echo "::error::crates/ is the frozen Rust parity oracle; changes to it are refused, not reviewed:"
  printf '  %s\n' "${crates[@]}"
  echo "refused: changes crates/ (frozen)"
  exit 1
fi

if [ ${#hits[@]} -eq 0 ]; then
  echo "no risk-class path touched"
  exit 0
fi

echo "review-gate: risk-class paths touched:"
printf '  %s\n' "${hits[@]}"

if [ -z "$reviewed" ]; then
  echo "::error::No approving agent review. Touches the risk-class paths above: needs an independent"
  echo "::error::review posted as 'agent-review: approve <head sha>' (docs/DEVELOPMENT-PROCESS.md section 7)."
  echo "needs agent review: risk paths touched, no approving verdict"
  exit 1
fi

if ! [[ "$reviewed" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::reviewed sha '$reviewed' is not a full 40-hex commit id"
  echo "review invalid: malformed sha"
  exit 1
fi
if ! git cat-file -e "$reviewed^{commit}" 2>/dev/null || ! git merge-base --is-ancestor "$reviewed" "$head"; then
  echo "::error::The approved sha $reviewed is not a commit in this PR's history (force-push or wrong sha)."
  echo "review invalid: approved ${reviewed:0:12} not in PR history"
  exit 1
fi

since=$(git diff --name-only --no-renames "$reviewed" "$head")
late=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in crates/*) late+=("$f"); continue ;; esac
  if [ -n "$(risk_of "$f")" ]; then late+=("$f"); fi
done <<<"$since"

if [ ${#late[@]} -gt 0 ]; then
  echo "::error::Reviewed at ${reviewed:0:12}, but these risk-class paths changed after it:"
  printf '  %s\n' "${late[@]}"
  echo "::error::Re-review at the current head and post a new verdict."
  echo "stale review: risk paths changed after ${reviewed:0:12}"
  exit 1
fi

echo "reviewed at ${reviewed:0:12}; no risk path changed since"
exit 0
