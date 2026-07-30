#!/usr/bin/env bash
# End-to-end smoke test: does the thing actually work when run?
#
# Unit tests prove the pieces; this proves the wiring. Spins up a target server, runs burpsy,
# drives traffic through the proxy, then exercises History / Repeater / Intruder via the real HTTP
# API — the same endpoints the web UI calls.
set -uo pipefail
cd "$(dirname "$0")"

PROXY_PORT=18080
WEB_PORT=18081
TARGET_PORT=18099
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

cleanup(){
  [ -n "${TARGET_PID:-}" ] && kill "$TARGET_PID" 2>/dev/null
  [ -n "${BURPSY_PID:-}" ] && kill "$BURPSY_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

# ---- target server: echoes method+path+query so we can assert on it -----------------------
python3 - "$TARGET_PORT" <<'PY' &
import sys, http.server
class H(http.server.BaseHTTPRequestHandler):
    def _go(self):
        body = f"TARGET-OK {self.command} {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = _go
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
TARGET_PID=$!

./target/debug/burpsy --proxy 127.0.0.1:$PROXY_PORT --web 127.0.0.1:$WEB_PORT >/tmp/burpsy.log 2>&1 &
BURPSY_PID=$!

# Wait for BOTH the target server and burpsy's web port. Waiting only for burpsy raced the
# Python target's startup and produced a spurious "upstream connect failed".
for _ in $(seq 1 100); do
  curl -s -o /dev/null "http://127.0.0.1:$TARGET_PORT/" && break
  sleep 0.1
done
for _ in $(seq 1 100); do
  curl -s -o /dev/null "http://127.0.0.1:$WEB_PORT/api/stats" && break
  sleep 0.1
done
# And the proxy listener itself.
for _ in $(seq 1 100); do
  (exec 3<>/dev/tcp/127.0.0.1/$PROXY_PORT) 2>/dev/null && { exec 3<&-; break; }
  sleep 0.1
done

echo "=== 1. web UI serves ==="
curl -s "http://127.0.0.1:$WEB_PORT/" | grep -q 'burpsy' && ok "UI HTML served" || no "UI HTML"

echo "=== 2. proxy forwards HTTP and captures it ==="
BODY=$(curl -s -x "http://127.0.0.1:$PROXY_PORT" \
        "http://127.0.0.1:$TARGET_PORT/hello?a=1&b=2" 2>/dev/null)
[ "$BODY" = "TARGET-OK GET /hello?a=1&b=2" ] \
  && ok "response proxied verbatim: $BODY" || no "proxied body was: '$BODY'"

sleep 0.4
HIST=$(curl -s "http://127.0.0.1:$WEB_PORT/api/history")
echo "$HIST" | grep -q '"path":"/hello?a=1&b=2"' && ok "exchange in history" || no "history missing exchange"
echo "$HIST" | grep -q '"status":200' && ok "status recorded" || no "status not recorded"

echo "=== 3. stored request is retrievable and byte-exact ==="
REQ_ID=$(echo "$HIST" | grep -o '"request":[0-9]*' | head -1 | cut -d: -f2)
MSG=$(curl -s "http://127.0.0.1:$WEB_PORT/api/message/$REQ_ID")
echo "$MSG" | grep -q 'GET /hello?a=1&b=2 HTTP/1.1' && ok "request stored origin-form" || no "request text wrong"

echo "=== 4. repeater sends and records ==="
RAW=$(printf 'GET /repeated?x=9 HTTP/1.1\nHost: 127.0.0.1:%s\nConnection: close\n\n' "$TARGET_PORT")
RESP=$(curl -s -X POST "http://127.0.0.1:$WEB_PORT/api/repeater/send" \
  -H 'content-type: application/json' \
  --arg-unused 2>/dev/null || true)
RESP=$(python3 - "$WEB_PORT" "$TARGET_PORT" <<'PY'
import json,sys,urllib.request
web,tgt=sys.argv[1],sys.argv[2]
raw=f"GET /repeated?x=9 HTTP/1.1\nHost: 127.0.0.1:{tgt}\nConnection: close\n\n"
body=json.dumps({"target":f"http://127.0.0.1:{tgt}","raw":raw}).encode()
r=urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{web}/api/repeater/send",body,{"content-type":"application/json"}),timeout=20)
print(r.read().decode())
PY
)
echo "$RESP" | grep -q 'TARGET-OK GET /repeated?x=9' && ok "repeater got expected body" || no "repeater body: ${RESP:0:120}"
echo "$RESP" | grep -q '"status":200' && ok "repeater status 200" || no "repeater status"
REP_MSG=$(echo "$RESP" | grep -o '"request_msg_id":[0-9]*' | cut -d: -f2)

echo "=== 5. intruder finds insertion points ==="
PTS=$(python3 - "$WEB_PORT" "$REP_MSG" <<'PY'
import json,sys,urllib.request
web,mid=sys.argv[1],int(sys.argv[2])
body=json.dumps({"msg_id":mid,"all":False}).encode()
r=urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{web}/api/intruder/points",body,{"content-type":"application/json"}),timeout=20)
print(r.read().decode())
PY
)
echo "$PTS" | grep -q '"kind":"url_param_value"' && ok "found url param point" || no "points: ${PTS:0:160}"
echo "$PTS" | grep -q '"label":"x"' && ok "labelled param 'x'" || no "param label missing"

echo "=== 6. intruder attack runs against the point ==="
ATT=$(python3 - "$WEB_PORT" "$REP_MSG" "$TARGET_PORT" <<'PY'
import json,sys,urllib.request
web,mid,tgt=sys.argv[1],int(sys.argv[2]),sys.argv[3]
body=json.dumps({"msg_id":mid,"target":f"http://127.0.0.1:{tgt}",
                 "point_index":0,"payloads":["AAA","BBB","'"],"all":False}).encode()
r=urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{web}/api/intruder/run",body,{"content-type":"application/json"}),timeout=60)
print(r.read().decode())
PY
)
N=$(echo "$ATT" | grep -o '"payload"' | wc -l)
[ "$N" -eq 3 ] && ok "3 attempts executed" || no "attempts=$N : ${ATT:0:160}"
echo "$ATT" | grep -q '"status":200' && ok "attack got 200s" || no "attack statuses"

echo "=== 7. memory accounting is exposed ==="
ST=$(curl -s "http://127.0.0.1:$WEB_PORT/api/stats")
echo "$ST" | grep -qE '"stored_bytes":[0-9]+' && ok "stats: $ST" || no "stats missing"

echo
echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
