#!/usr/bin/env bash
# The mechanical half of the UI pass in docs/UI-VERIFICATION.md, runnable.
#
# That document defines what a console change has to survive: every route renders its own h1, no
# uncaught errors, the console explains itself, and zero axe violations per route. Its steps were
# prose plus a handful of agent-browser invocations, which made the pass as expensive to redo as it
# was to do — and a gate nobody re-runs is not a gate. This runs parts (a), (b) and (d) against an
# already-running console (`./ui-live.sh` in another terminal) and exits non-zero on any failure.
#
# Part (c) — the behaviour the change is about — is deliberately NOT here: it is different for every
# change, and automating "read the rendered state" would turn it into a screenshot comparison.
#
#   ./ui-pass.sh                    # every route, the default port
#   ./ui-pass.sh --web-port 18281   # explicit port
#   ./ui-pass.sh --route scope --route sequencer    # only the routes a change touched
#
# It never boots the fixture itself: ui-live.sh already refuses to run two fixtures at once, and a
# script that silently started its own would either collide with that or leave a stray process.
set -uo pipefail
cd "$(dirname "$0")"

WEB_PORT=18281
ROUTES=()
AXE="burpsy-go/internal/web/ui/e2e/node_modules/axe-core/axe.min.js"
ROUTES_TS="burpsy-go/internal/web/ui/e2e/harness/routes.ts"

while [ $# -gt 0 ]; do
  case "$1" in
    --web-port) WEB_PORT="$2"; shift 2 ;;
    --route)    ROUTES+=("$2"); shift 2 ;;
    -h|--help)  sed -n '2,20p' "$0"; exit 0 ;;
    *)          echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/tmp/burpsy-ab-runtime}
mkdir -p "$XDG_RUNTIME_DIR"

for tool in agent-browser python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "REFUSED: $tool is not on PATH" >&2; exit 2; }
done
[ -f "$AXE" ] || { echo "REFUSED: $AXE is missing (run bun install in internal/web/ui/e2e)" >&2; exit 2; }

if ! curl -fsS -o /dev/null "http://127.0.0.1:${WEB_PORT}/"; then
  echo "REFUSED: no console answering on 127.0.0.1:${WEB_PORT} — start one with ./ui-live.sh" >&2
  exit 2
fi

# routes.ts is the contract (id + the exact h1 the page must render), so this reads it rather than
# keeping a second list that would drift the first time a page is renamed.
ROUTE_PAIRS=$(python3 - "$ROUTES_TS" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
for id_, h1 in re.findall(r'id:\s*"([^"]+)"[^}]*?h1:\s*"([^"]+)"', src):
    print(f"{id_}\t{h1}")
PY
)
if [ -z "$ROUTE_PAIRS" ]; then
  echo "REFUSED: no routes parsed out of $ROUTES_TS" >&2
  exit 2
fi

want_route() {
  [ ${#ROUTES[@]} -eq 0 ] && return 0
  local r
  for r in "${ROUTES[@]}"; do [ "$r" = "$1" ] && return 0; done
  return 1
}

PASS=0; FAIL=0
declare -a FAILED

check_route() {
  local id="$1" want="$2"
  agent-browser open "http://127.0.0.1:${WEB_PORT}/#${id}" >/dev/null 2>&1
  sleep 0.6

  local got
  got=$(agent-browser eval 'document.querySelector("h1")?.textContent?.trim() ?? ""' 2>/dev/null | tr -d '\n' | sed 's/^"//; s/"$//')
  if [ "$got" = "$want" ]; then
    PASS=$((PASS+1)); printf '  PASS  #%-14s h1 %s\n' "$id" "$got"
  else
    FAIL=$((FAIL+1)); FAILED+=("h1 #$id: got '$got', want '$want'")
    printf '  FAIL  #%-14s h1 %s (want %s)\n' "$id" "$got" "$want"
  fi

  # axe re-injection per route: the bundle lives in the document, and a route change that reloads
  # the page would otherwise fail as "axe is not defined" rather than as a violation.
  agent-browser eval --stdin < "$AXE" >/dev/null 2>&1
  local viol
  viol=$(agent-browser eval '(async () => {
    const r = await axe.run(document, { runOnly: { type: "tag", values: ["wcag2a","wcag2aa","wcag21a","wcag21aa"] } });
    return JSON.stringify(r.violations.map(v => v.id + " (" + v.nodes.length + ")"));
  })()' 2>/dev/null | tr -d '\n' | sed 's/^"//; s/"$//')
  if [ "$viol" = "[]" ]; then
    PASS=$((PASS+1)); printf '  PASS  #%-14s axe 0 violations\n' "$id"
  else
    FAIL=$((FAIL+1)); FAILED+=("axe #$id: $viol")
    printf '  FAIL  #%-14s axe %s\n' "$id" "$viol"
  fi
}

echo "== routes and accessibility against http://127.0.0.1:${WEB_PORT}/"
while IFS=$'\t' read -r id want; do
  want_route "$id" || continue
  check_route "$id" "$want"
done <<< "$ROUTE_PAIRS"

# Part (b): uncaught page errors must be empty. The console may speak (React's dev notice, the two
# explained 404s in docs/UI-VERIFICATION.md); a page error may not.
echo "== uncaught page errors"
ERRORS=$(agent-browser errors 2>&1 | tr -d '\n')
if [ -z "$ERRORS" ] || [ "$ERRORS" = "No errors" ]; then
  PASS=$((PASS+1)); echo "  PASS  errors: none"
else
  FAIL=$((FAIL+1)); FAILED+=("page errors: $ERRORS")
  echo "  FAIL  errors: $ERRORS"
fi

echo
for f in "${FAILED[@]:-}"; do [ -n "$f" ] && echo "  $f"; done
echo "############ ${PASS} passed, ${FAIL} failed ############"
agent-browser eval 'location.hash = "dashboard"' >/dev/null 2>&1
exit $(( FAIL > 0 ? 1 : 0 ))
