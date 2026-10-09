#!/usr/bin/env bash
# review-gate.sh BASE HEAD [--labeled] [--pushed BEFORE AFTER] — the `review-gate` CI check.
#
# Lists the files BASE..HEAD changes that fall in a risk class (docs/DEVELOPMENT-PROCESS.md
# section 7). Those need an independent reviewer — a fresh agent with the diff and that list, not the
# author — whose sign-off is the PR label `agent-reviewed`. Exit status:
#   0  no risk path touched; or touched and --labeled
#   1  risk path touched and not --labeled; or any crates/ change (refused, label or not); or
#      --labeled with --pushed BEFORE AFTER (a push to the PR branch) whose commits change one of the
#      risk paths again
#   2  usage error
#
# The label is a claim about a specific diff. A push after the label is applied changes the diff the
# claim was about, so with --pushed (the push's before/after shas) a labelled PR whose new commits touch a
# risk path fails until the label is removed and re-applied after re-review — each label event
# re-runs this check, and the newest run is the one branch protection reads. When BEFORE is not in
# this clone (a force-push), the whole PR is treated as changed: conservative, and loud.
#
# The lists are paths, not semantics. A risk-class change made in a file not listed here (say, a new
# authorisation check added to an unlisted handler) is invisible to this gate; when that happens,
# add the file here, in the same PR.
set -euo pipefail

usage() { echo "usage: $0 BASE HEAD [--labeled] [--pushed BEFORE AFTER]" >&2; exit 2; }
[ $# -ge 2 ] || usage
base=$1 head=$2
shift 2
labeled=0 since="" after=""
while [ $# -gt 0 ]; do
  case "$1" in
    --labeled) labeled=1 ;;
    --pushed) [ $# -ge 3 ] || usage; since=$2; after=$3; shift 2 ;;
    *) usage ;;
  esac
  shift
done

# Each entry: a bash glob (matched against repo-root paths; * crosses /) and its class.
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
  # Code that runs on every developer machine, and the merge rules that once wiped the tracker.
  ".beads/hooks/*|git hooks"
  ".gitattributes|merge drivers"
)

touched() { git diff --name-only --no-renames "$1" "$2"; }

hits=() crates=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in crates/*) crates+=("$f"); continue ;; esac
  for entry in "${risk[@]}"; do
    # shellcheck disable=SC2053 # the right-hand side is a glob on purpose
    if [[ "$f" == ${entry%%|*} ]]; then hits+=("$f  [${entry#*|}]"); break; fi
  done
done < <(touched "$base" "$head")

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

if [ -n "$since" ]; then
  if git cat-file -e "$since^{commit}" 2>/dev/null && git cat-file -e "$after^{commit}" 2>/dev/null; then
    mapfile -t late < <(touched "$since" "$after" | while IFS= read -r f; do
      for h in "${hits[@]}"; do [ "${h%%  \[*}" = "$f" ] && echo "$f"; done
    done)
  else
    echo "review-gate: the previous head $since is not in this clone (force-push?); treating every risk path as changed"
    late=("${hits[@]}")
  fi
  if [ ${#late[@]} -gt 0 ]; then
    echo "::error::'agent-reviewed' was applied before these risk-class paths changed again:"
    printf '  %s\n' "${late[@]}"
    echo "::error::Re-review the new commits, then remove and re-apply the label."
    exit 1
  fi
fi

echo "review-gate: labelled agent-reviewed."
exit "$status"
