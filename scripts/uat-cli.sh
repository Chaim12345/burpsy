#!/usr/bin/env bash
# uat-cli.sh — UAT for the burpsy CLI (bead burpsy-react-ui-uat1): build the real binary and use it
# the way an operator does, against a fixture target, checking findings and exit codes. Not a unit
# suite. Run from anywhere; needs go, python3 and curl. Reaches loopback only.
#
#   1. exit codes: `-scan-config list` exits 0 and prints configurations; an unknown flag and a
#      `-store-verify` of a missing directory exit non-zero; an empty one exits 0.
#   2. proxy: a request sent through the proxy reaches the fixture target (internal/vulnapp, the
#      deliberately vulnerable app) verbatim and is captured in history.
#   3. scan: an audit of that exchange (through the confirmation gate) reports the reflected
#      cross-site scripting the target declares at /search, and none on its safe twin.
#
# Ports (distinct from e2e-go.sh 18180s and the browser UAT harness 18280s): proxy 18380, web 18381,
# target 18399. e2e-go.sh stays the broad API suite (nightly); this is the short operator flow a
# pull request runs.
set -uo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
PROXY_PORT=${UAT_PROXY_PORT:-18380}
WEB_PORT=${UAT_WEB_PORT:-18381}
TARGET_PORT=${UAT_TARGET_PORT:-18399}
PASS=0; FAIL=0
ok() { echo "  PASS  $1"; PASS=$((PASS+1)); }
no() { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

work=$(mktemp -d)
cleanup() {
  [ -n "${TARGET_PID:-}" ] && kill "$TARGET_PID" 2>/dev/null
  [ -n "${BURPSY_PID:-}" ] && kill "$BURPSY_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "$FAIL" -ne 0 ]; then echo "--- burpsy log"; tail -60 "$work/burpsy.log" 2>/dev/null; fi
  rm -rf "$work"
}
trap cleanup EXIT

echo "=== build ==="
if ! (cd "$repo/burpsy-go" && go build -o "$work/burpsy" ./cmd/burpsy && go build -o "$work/demo-target" ./cmd/demo-target) 2>"$work/build.log"; then
  head -20 "$work/build.log"; echo "  FAIL  go build"; exit 1
fi
ok "burpsy and demo-target build"

echo "=== 1. exit codes ==="
out=$("$work/burpsy" -scan-config list 2>&1); rc=$?
{ [ $rc -eq 0 ] && [ -n "$out" ]; } && ok "-scan-config list exits 0 and prints configurations" || no "-scan-config list: rc=$rc"
"$work/burpsy" -no-such-flag >/dev/null 2>&1; rc=$?
[ $rc -ne 0 ] && ok "an unknown flag exits non-zero ($rc)" || no "an unknown flag exited 0"
mkdir "$work/empty-dir"
"$work/burpsy" -store-verify "$work/empty-dir" >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && ok "-store-verify of a directory with no segments exits 0 (nothing to fault)" || no "-store-verify of an empty directory: rc=$rc"
"$work/burpsy" -store-verify "$work/no-such-dir" >/dev/null 2>&1; rc=$?
[ $rc -ne 0 ] && ok "-store-verify of a directory that does not exist exits non-zero ($rc)" || no "-store-verify of a missing directory exited 0"

echo "=== 2. proxy a request to the fixture target ==="
"$work/demo-target" -addr "127.0.0.1:$TARGET_PORT" >"$work/target.log" 2>&1 & TARGET_PID=$!
"$work/burpsy" -db "$work/uat.db" -proxy "127.0.0.1:$PROXY_PORT" -web "127.0.0.1:$WEB_PORT" \
  -scope-include 127.0.0.1 >"$work/burpsy.log" 2>&1 & BURPSY_PID=$!
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$WEB_PORT/api/stats" && break; sleep 0.1; done
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$TARGET_PORT/" && break; sleep 0.1; done
body=$(env -u NO_PROXY -u no_proxy curl -s -x "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$TARGET_PORT/search?q=seed")
echo "$body" | grep -q 'seed' && ok "the proxied response reached the client" || no "proxied body: ${body:0:120}"
sleep 0.5
read -r XID <<<"$(python3 - "$WEB_PORT" <<'PY'
import json,sys,urllib.request
rows=json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/history",timeout=10))
rows=rows if isinstance(rows,list) else (rows.get("exchanges") or [])
row=next((r for r in rows if r.get("path","").startswith("/search")),None)
print(row["id"] if row else "none")
PY
)"
[ "$XID" != none ] && ok "the exchange is in history (id $XID)" || { no "no /search exchange in history"; echo "############ $PASS passed, $FAIL failed ############"; exit 1; }

echo "=== 3. scan the exchange ==="
# history_id PREFIX -> the id of the first history exchange whose path starts with PREFIX, or "none".
history_id() {
  python3 - "$WEB_PORT" "$1" <<'PY'
import json,sys,urllib.request
rows=json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/history",timeout=10))
rows=rows if isinstance(rows,list) else (rows.get("exchanges") or [])
row=next((r for r in rows if r.get("path","").startswith(sys.argv[2])),None)
print(row["id"] if row else "none")
PY
}
# audit_exchange ID LABEL -> audits one exchange through the confirmation gate (refused unconfirmed
# first), returning non-zero when it could not run.
audit_exchange() {
  local id="$1" label="$2" code token res
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$WEB_PORT/api/audit/$id")
  [ "$code" = 428 ] && ok "an unconfirmed audit of $label is refused (428)" || no "unconfirmed audit of $label -> HTTP $code, want 428"
  token=$(python3 - "$WEB_PORT" "$id" <<'PY'
import json,sys,urllib.request
web,xid=sys.argv[1:3]
d={"method":"POST","url":f"/api/audit/{xid}"}
r=urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{web}/api/audit/confirm",json.dumps(d).encode(),{"content-type":"application/json"}),timeout=10)
print(json.load(r).get("token",""))
PY
)
  [ -n "$token" ] || { no "could not mint a confirmation for the audit of $label"; return 1; }
  res=$(curl -s -m 300 -X POST "http://127.0.0.1:$WEB_PORT/api/audit/$id" -H "X-Burpsy-Confirm: $token")
  echo "$res" | grep -q "\"exchange_id\":$id" && ok "the audit of $label ran" || { no "audit of $label response: ${res:0:160}"; return 1; }
  LAST_FOUND=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("outcome",{}).get("findings",-1))' "$res")
  # Coverage: an audit that ran no active checks, or errored on some, proves nothing about a clean result.
  python3 -c '
import json,sys
d=json.loads(sys.argv[1]); b=(d.get("breakdown") or {}).get("breakdown") or {}
sys.exit(0 if d.get("active_checks",0)>0 and b.get("errored",1)==0 else 1)' "$res" && ok "the audit of $label ran active checks with none errored" || no "audit of $label ran no active checks or some errored: ${res:0:200}"
}
# xss_count [PATH] -> cross-site scripting findings, optionally only those naming PATH.
xss_count() {
  curl -s "http://127.0.0.1:$WEB_PORT/api/findings" | python3 -c '
import json,sys
d=json.load(sys.stdin)
rows=d if isinstance(d,list) else (d.get("findings") or [])
want=sys.argv[1] if len(sys.argv)>1 else ""
print(sum(1 for f in rows if "cross-site scripting" in json.dumps(f).lower() and want in json.dumps(f)))' "${1:-}"
}
audit_exchange "$XID" "/search" || { echo "############ $PASS passed, $FAIL failed ############"; exit 1; }
n=$(xss_count)
FOUND_VULN=$LAST_FOUND
[ "${n:-0}" -ge 1 ] && ok "a cross-site scripting finding was reported ($n)" || no "no cross-site scripting finding after auditing /search"

echo "=== 4. the safe twin stays clean ==="
# UAT_TWIN_PATH exists for the red control: pointing it at the vulnerable /search must make this section fail.
TWIN=${UAT_TWIN_PATH:-/safe/search}
# /safe/search is the same endpoint with the reflection escaped (internal/vulnapp declares it Safe).
# Findings carry no path, so the assertion is a count: the vulnerable audit above produced n cross-site
# scripting findings (the positive control, n >= 1), and auditing the twin must add none.
body=$(env -u NO_PROXY -u no_proxy curl -s -x "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$TARGET_PORT${TWIN}?q=twin")
echo "$body" | grep -q 'twin' && ok "the safe twin's response reached the client" || no "safe twin body: ${body:0:120}"
sleep 0.5
SID=$(history_id "${TWIN}?q=twin")
if [ "$SID" = none ]; then
  no "no /safe/search exchange in history"
elif audit_exchange "$SID" "$TWIN"; then
  FOUND_TWIN=$LAST_FOUND
  total_after=$(xss_count)
  [ "${total_after:-0}" -eq "${n:-0}" ] && ok "auditing the safe twin added no cross-site scripting finding ($n -> $total_after)" || no "cross-site scripting findings changed $n -> $total_after after the safe twin audit"
fi

echo "=== 5. the per-audit finding counts have teeth ==="
# The findings list de-duplicates by name across exchanges, so its total cannot show a second vulnerable
# exchange (or a vulnerable twin) adding anything. Each audit's own outcome.findings is per exchange: a
# second vulnerable exchange must report the same count as the first (control: the count is stable), and
# the safe twin must report strictly fewer (the reflected-XSS finding is missing). Pointing UAT_TWIN_PATH
# at /search makes the twin vulnerable and this last check must then fail.
env -u NO_PROXY -u no_proxy curl -s -o /dev/null -x "http://127.0.0.1:$PROXY_PORT" "http://127.0.0.1:$TARGET_PORT/search?q=control"
sleep 0.5
CID=$(history_id "/search?q=control")
if [ "$CID" = none ]; then no "no control exchange in history"; elif audit_exchange "$CID" "/search?q=control"; then
  [ "$LAST_FOUND" -eq "$FOUND_VULN" ] && ok "a second vulnerable exchange reports the same finding count ($FOUND_VULN)" || no "vulnerable audits disagree ($FOUND_VULN vs $LAST_FOUND): the comparison below is not trustworthy"
  [ "${FOUND_TWIN:--1}" -ge 0 ] && [ "$FOUND_TWIN" -lt "$FOUND_VULN" ] && ok "the safe twin's audit found fewer than the vulnerable one ($FOUND_TWIN < $FOUND_VULN)" || no "the twin's audit found ${FOUND_TWIN:-none}, not fewer than the vulnerable audit's $FOUND_VULN"
fi
echo; echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
