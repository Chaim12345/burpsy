#!/usr/bin/env bash
# Acceptance test for request interception, failed-CONNECT recording, and connection reuse.
#
# The bar for interception is behavioural. A held request must actually be held — its client still
# blocked, the origin still untouched. An edit must actually reach the origin. A drop must actually
# not. And none of it may stall an unrelated connection. Asserting on the queue's own bookkeeping
# would pass even if the proxy forwarded everything immediately, so every check below observes a
# real client socket, the origin's own request log, or the traffic store.
#
# Driven through `cargo run --example intercept_e2e`, which mounts the real
# `routes::intercept::routes()` over a real proxy. See that file for why the shipped `burpsy`
# binary cannot host these endpoints yet.
set -uo pipefail
cd "$(dirname "$0")"

PROXY=18580; WEB=18581; ORIGIN=18599
PROXY_OOS=18582; WEB_OOS=18583
BIN=./target/debug/examples/intercept_e2e
WORK=$(mktemp -d /tmp/burpsy-intercept-XXXXXX)
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

cleanup(){
  pkill -x intercept_e2e 2>/dev/null
  [ -n "${ORIGIN_PID:-}" ] && kill "$ORIGIN_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "missing $BIN — run: cargo build -j 2 --example intercept_e2e"; exit 1; }

# ---- origin: echoes method+path, and counts connections separately from requests --------------
# Connections are counted per socket that carried at least one real request, which is what makes
# the keep-alive assertions meaningful. /__count is excluded so polling it cannot skew the numbers.
python3 - "$ORIGIN" <<'PY' &
import sys, threading, http.server
STATE = {"conns": 0, "reqs": 0}
LOCK = threading.Lock()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def setup(self):
        super().setup()
        self._counted = False
    def _reply(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == "/__count":
            with LOCK:
                self._reply(f"conns={STATE['conns']} reqs={STATE['reqs']}".encode())
            return
        with LOCK:
            STATE["reqs"] += 1
            if not self._counted:
                STATE["conns"] += 1
                self._counted = True
        self._reply(f"TARGET-OK {self.command} {self.path}".encode())
    do_POST = do_GET
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
ORIGIN_PID=$!

"$BIN" --proxy "127.0.0.1:$PROXY" --web "127.0.0.1:$WEB" > "$WORK/main.log" 2>&1 &
# A second instance whose scope covers a host this test never contacts, so everything it proxies is
# out of scope even though interception is on.
"$BIN" --proxy "127.0.0.1:$PROXY_OOS" --web "127.0.0.1:$WEB_OOS" \
       --scope-include out-of-reach.test > "$WORK/oos.log" 2>&1 &

for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$ORIGIN/__count" && break; sleep 0.1; done
for _ in $(seq 1 150); do curl -s -o /dev/null "http://127.0.0.1:$WEB/api/intercept" && break; sleep 0.1; done
for _ in $(seq 1 150); do curl -s -o /dev/null "http://127.0.0.1:$WEB_OOS/api/intercept" && break; sleep 0.1; done

# Poll the queue rather than sleeping a guessed interval.
wait_pending(){ # $1 = web port, $2 = wanted count
  for _ in $(seq 1 150); do
    n=$(curl -s "http://127.0.0.1:$1/api/intercept" | grep -o '"pending":[0-9]*' | cut -d: -f2)
    [ "${n:-0}" -ge "$2" ] && return 0
    sleep 0.1
  done
  return 1
}
held_id(){ curl -s "http://127.0.0.1:$WEB/api/intercept" | python3 -c \
  'import json,sys; q=json.load(sys.stdin)["held"]; print(q[0]["id"] if q else "")'; }
origin_reqs(){ curl -s "http://127.0.0.1:$ORIGIN/__count" | sed 's/.*reqs=//'; }
origin_conns(){ curl -s "http://127.0.0.1:$ORIGIN/__count" | sed 's/conns=//;s/ .*//'; }

echo "=== 1. interception is on and the queue is empty ==="
S=$(curl -s "http://127.0.0.1:$WEB/api/intercept")
echo "$S" | grep -q '"enabled":true' && ok "interception enabled" || no "not enabled: $S"
echo "$S" | grep -q '"pending":0' && ok "queue starts empty" || no "queue not empty: $S"

echo "=== 2. a request entering the proxy is actually held ==="
REQS_BEFORE=$(origin_reqs)
curl -s -m 30 -x "http://127.0.0.1:$PROXY" "http://127.0.0.1:$ORIGIN/hold-me" > "$WORK/held.body" &
HELD_CURL=$!
if wait_pending "$WEB" 1; then ok "request reached the hold queue"; else no "request never queued"; fi
kill -0 $HELD_CURL 2>/dev/null && ok "client is still blocked (genuinely held)" \
  || no "client already finished — the request was not held"
[ "$(origin_reqs)" = "$REQS_BEFORE" ] && ok "origin has not seen it yet" \
  || no "origin received a request that was supposed to be held"

echo "=== 3. holding one request does not block another connection ==="
# "Must not block" does NOT mean the second request skips the queue — interception holds every
# in-scope request, so /free is just as subject to it as /hold-me. It means the hold queue must not
# be a single gate that serializes connection handling: while /hold-me sits parked in its own
# oneshot, /free must still be independently ACCEPTED, PARSED and QUEUED rather than stuck behind it
# at the socket level. Both requests are released before moving on, so no phantom held entry lingers
# for a later section's held_id() (which picks q[0]) to pick up by mistake.
curl -s -m 30 -x "http://127.0.0.1:$PROXY" "http://127.0.0.1:$ORIGIN/free" > "$WORK/free.body" &
FREE_CURL=$!
if wait_pending "$WEB" 2; then ok "the second request reached the queue without waiting on the first"
else no "second request never queued — pending stayed below 2"; fi
kill -0 $HELD_CURL 2>/dev/null && kill -0 $FREE_CURL 2>/dev/null \
  && ok "both requests are still parked" || no "one was released early"

# Release /free first, independently of /hold-me, to prove forwarding one does not touch the other.
FREE_ID=$(curl -s "http://127.0.0.1:$WEB/api/intercept" \
  | python3 -c 'import json,sys; q=json.load(sys.stdin)["held"]; print(next(h["id"] for h in q if h["path"]=="/free"))')
curl -s -X POST "http://127.0.0.1:$WEB/api/intercept/$FREE_ID/forward" -H 'content-type: application/json' -d '{}' >/dev/null
wait $FREE_CURL 2>/dev/null
[ "$(cat "$WORK/free.body")" = "TARGET-OK GET /free" ] \
  && ok "the second connection completed once forwarded" || no "free.body: '$(cat "$WORK/free.body")'"
kill -0 $HELD_CURL 2>/dev/null && ok "the first request is still held after the second was released" \
  || no "forwarding the second request released the first"

echo "=== 4. an edit reaches the origin, and history records the edited bytes ==="
ID=$(held_id)
python3 - "$WEB" "$ID" <<'PY'
import json, sys, urllib.request
web, hid = sys.argv[1], int(sys.argv[2])
q = json.load(urllib.request.urlopen(f"http://127.0.0.1:{web}/api/intercept", timeout=10))
raw = next(h["raw"] for h in q["held"] if h["id"] == hid)
edited = raw.replace("/hold-me", "/edited-by-operator")
body = json.dumps({"raw": edited}).encode()
r = urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{web}/api/intercept/{hid}/forward", body,
    {"content-type": "application/json"}), timeout=10)
print(r.read().decode())
PY
wait $HELD_CURL 2>/dev/null
BODY=$(cat "$WORK/held.body")
[ "$BODY" = "TARGET-OK GET /edited-by-operator" ] \
  && ok "the origin received the edited request" || no "origin echoed: '$BODY'"

H=$(curl -s "http://127.0.0.1:$WEB/e2e/history")
echo "$H" | grep -q '"path":"/edited-by-operator"' && ok "history indexes the edited path" \
  || no "history path wrong"
echo "$H" | python3 -c 'import json,sys
rows=json.load(sys.stdin)["exchanges"]
bad=[r for r in rows if "/hold-me" in r["request"]]
sys.exit(1 if bad else 0)' \
  && ok "no stored request still carries the pre-edit bytes" \
  || no "history kept the original bytes"

echo "=== 5. a dropped request is answered, not hung, and never sent ==="
REQS_BEFORE=$(origin_reqs)
curl -s -m 30 -o "$WORK/drop.body" -w '%{http_code}' \
  -x "http://127.0.0.1:$PROXY" "http://127.0.0.1:$ORIGIN/drop-me" > "$WORK/drop.code" &
DROP_CURL=$!
if wait_pending "$WEB" 1; then ok "the request to drop was held"; else no "never queued"; fi
ID=$(held_id)
D=$(curl -s -X POST -H 'content-type: application/json' \
     -d '{"reason":"e2e says no"}' "http://127.0.0.1:$WEB/api/intercept/$ID/drop")
echo "$D" | grep -q '"dropped":true' && ok "drop accepted" || no "drop rejected: $D"
if wait $DROP_CURL 2>/dev/null; then :; fi
[ "$(cat "$WORK/drop.code")" = "403" ] \
  && ok "client got a synthetic 403 instead of hanging" \
  || no "client status was '$(cat "$WORK/drop.code")'"
grep -q 'e2e says no' "$WORK/drop.body" && ok "the reason reached the client" \
  || no "drop body: $(cat "$WORK/drop.body")"
[ "$(origin_reqs)" = "$REQS_BEFORE" ] && ok "the origin never saw the dropped request" \
  || no "a dropped request still reached the origin"
curl -s "http://127.0.0.1:$WEB/e2e/history" | grep -q 'dropped by operator' \
  && ok "the drop is recorded in history" || no "no history row for the drop"

echo "=== 6. out-of-scope traffic passes through untouched while interception is on ==="
OOS=$(curl -s -m 10 -x "http://127.0.0.1:$PROXY_OOS" "http://127.0.0.1:$ORIGIN/out-of-scope")
[ "$OOS" = "TARGET-OK GET /out-of-scope" ] && ok "out-of-scope request completed without being held" \
  || no "out-of-scope request got: '$OOS'"
P=$(curl -s "http://127.0.0.1:$WEB_OOS/api/intercept" | grep -o '"pending":[0-9]*' | cut -d: -f2)
[ "$P" = "0" ] && ok "it never entered the queue" || no "pending=$P on the narrow-scope instance"

echo "=== 7. a CONNECT that cannot reach upstream is recorded ==="
# A port nothing is listening on: bind it, read the number, release it.
DEAD=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
curl -s -m 10 -o /dev/null -x "http://127.0.0.1:$PROXY" "https://127.0.0.1:$DEAD/" 2>/dev/null
sleep 0.3
H=$(curl -s "http://127.0.0.1:$WEB/e2e/history")
echo "$H" | python3 -c "import json,sys
rows=json.load(sys.stdin)['exchanges']
m=[r for r in rows if r['method']=='CONNECT' and r['port']==$DEAD]
sys.exit(0 if m and m[0]['status']==502 and 'connect failed' in (m[0]['notes'] or '') else 1)" \
  && ok "the failed CONNECT is in history with its reason" \
  || no "no recorded failed CONNECT to port $DEAD"

echo "=== 8. active-scan probes reuse one connection per target ==="
C0=$(origin_conns)
curl -s "http://127.0.0.1:$WEB/e2e/probe?host=127.0.0.1&port=$ORIGIN&n=4" > "$WORK/probe.json"
grep -q '"ok":4' "$WORK/probe.json" && ok "all 4 probes succeeded" \
  || no "probe results: $(cat "$WORK/probe.json")"
C1=$(origin_conns)
D=$((C1 - C0))
[ "$D" -eq 2 ] \
  && ok "4 probes cost 2 connections (1 to learn the framing, 1 shared)" \
  || no "4 probes opened $D connections, expected 2"

echo "=== 9. the close-per-probe escape hatch still opens one connection each ==="
C0=$(origin_conns)
curl -s "http://127.0.0.1:$WEB/e2e/probe?host=127.0.0.1&port=$ORIGIN&n=3&force_close=true" >/dev/null
C1=$(origin_conns)
D=$((C1 - C0))
[ "$D" -eq 3 ] && ok "3 close-per-probe requests cost 3 connections" \
  || no "escape hatch opened $D connections, expected 3"

echo
echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
