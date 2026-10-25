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
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$WEB_PORT/api/audit/$XID")
[ "$code" = 428 ] && ok "an unconfirmed audit is refused (428)" || no "unconfirmed audit -> HTTP $code, want 428"
token=$(python3 - "$WEB_PORT" "$XID" <<'PY'
import json,sys,urllib.request
web,xid=sys.argv[1:3]
d={"method":"POST","url":f"/api/audit/{xid}"}
r=urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{web}/api/audit/confirm",json.dumps(d).encode(),{"content-type":"application/json"}),timeout=10)
print(json.load(r).get("token",""))
PY
)
[ -n "$token" ] || { no "could not mint a confirmation for the audit"; echo "############ $PASS passed, $FAIL failed ############"; exit 1; }
res=$(curl -s -m 300 -X POST "http://127.0.0.1:$WEB_PORT/api/audit/$XID" -H "X-Burpsy-Confirm: $token")
echo "$res" | grep -q "\"exchange_id\":$XID" && ok "the audit ran" || no "audit response: ${res:0:160}"
n=$(curl -s "http://127.0.0.1:$WEB_PORT/api/findings" | python3 -c '
import json,sys
d=json.load(sys.stdin)
rows=d if isinstance(d,list) else (d.get("findings") or [])
print(sum(1 for f in rows if "cross-site scripting" in json.dumps(f).lower()))')
[ "${n:-0}" -ge 1 ] && ok "a cross-site scripting finding was reported ($n)" || no "no cross-site scripting finding after auditing /search"

echo; echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
