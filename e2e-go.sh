#!/usr/bin/env bash
# End-to-end smoke test for the Go implementation: does burpsy-go actually work when run?
#
# This exists because it did not. verify.sh ran `cargo` only, and all four sibling e2e scripts
# launch ./target/debug/burpsy — the Rust binary. AGENTS.md calls verify.sh "the definition of
# done", which made that claim vacuous for burpsy-go/, the tree that ships the web UI: a broken Go
# wiring path printed VERIFIED. Same defect class as the honesty bugs in the Go tree itself — a
# partial result looking complete.
#
# Deliberately the same shape as e2e.sh (spin up a target, drive the proxy, then exercise the real
# HTTP API the UI calls) so the two can be read side by side and a divergence between the ports
# shows up as a diff rather than as an argument. Ports are offset by 100 from e2e.sh's so the two
# suites cannot collide if anyone runs them concurrently despite verify.sh serialising them.
set -uo pipefail
cd "$(dirname "$0")"

PROXY_PORT=18180
WEB_PORT=18181
TARGET_PORT=18199
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

BIN=$(mktemp -u /tmp/burpsy-go-e2e.XXXXXX)
cleanup(){
  [ -n "${TARGET_PID:-}" ] && kill "$TARGET_PID" 2>/dev/null
  [ -n "${BURPSY_PID:-}" ] && kill "$BURPSY_PID" 2>/dev/null
  rm -f "$BIN"
  wait 2>/dev/null
}
trap cleanup EXIT

# Built to a temp path rather than into the tree: `go build -o burpsy-go/burpsy` would leave an
# untracked binary behind, and two PRs have already been rejected for committing exactly that.
if ! (cd burpsy-go && go build -o "$BIN" ./cmd/burpsy) 2>/tmp/burpsy-go-e2e-build.log; then
  echo "  FAIL  go build ./cmd/burpsy"
  head -20 /tmp/burpsy-go-e2e-build.log
  echo; echo "############ 0 passed, 1 failed ############"
  exit 1
fi

# ---- target server: echoes method+path+query so we can assert on it -----------------------
python3 - "$TARGET_PORT" <<'PY' &
import sys, http.server, itertools
counter = itertools.count(1)
class H(http.server.BaseHTTPRequestHandler):
    def _go(self):
        body = f"TARGET-OK {self.command} {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        # A Set-Cookie with attributes, for two checks at once. The session jar has to keep the pair
        # and drop the attributes — it used to store Path and SameSite as cookies and send them back.
        # And the value varies per response, so a sequencer capture that collected the same response
        # N times cannot pass for one that sent N requests.
        self.send_header("Set-Cookie", f"E2E_SESSION=tok{next(counter):04d}; Path=/; SameSite=Lax")
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_POST = _go
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
TARGET_PID=$!

"$BIN" --proxy 127.0.0.1:$PROXY_PORT --web 127.0.0.1:$WEB_PORT >/tmp/burpsy-go.log 2>&1 &
BURPSY_PID=$!

# Wait for all three listeners, for the reason e2e.sh records: waiting only on burpsy raced the
# Python target's startup and produced a spurious "upstream connect failed".
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$TARGET_PORT/" && break; sleep 0.1; done
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$WEB_PORT/api/stats" && break; sleep 0.1; done
for _ in $(seq 1 100); do
  (exec 3<>/dev/tcp/127.0.0.1/$PROXY_PORT) 2>/dev/null && { exec 3<&-; break; }
  sleep 0.1
done

echo "=== 1. web UI serves ==="
curl -s "http://127.0.0.1:$WEB_PORT/" | grep -qi 'burpsy' && ok "UI HTML served" || no "UI HTML"

echo "=== 2. proxy forwards HTTP and captures it ==="
BODY=$(curl -s -x "http://127.0.0.1:$PROXY_PORT" \
        "http://127.0.0.1:$TARGET_PORT/hello?a=1&b=2" 2>/dev/null)
[ "$BODY" = "TARGET-OK GET /hello?a=1&b=2" ] \
  && ok "response proxied verbatim: $BODY" || no "proxied body was: '$BODY'"

sleep 0.4
HIST=$(curl -s "http://127.0.0.1:$WEB_PORT/api/history")
# Decoded rather than grepped. Go's encoding/json HTML-escapes `&` to `&` by default, so the
# obvious grep for '"path":"/hello?a=1&b=2"' fails against a perfectly correct response — the same
# assertion works verbatim on Rust's serde output, which does not escape. Harmless on the wire (the
# UI's JSON.parse unescapes it), but it makes text-matching on this API misleading, so the checks
# that care about values go through a parser.
read -r HIST_PATH HIST_STATUS <<<"$(python3 - "$WEB_PORT" <<'PY'
import json,sys,urllib.request
rows=json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/history",timeout=10))
row=next((r for r in rows if r.get("path","").startswith("/hello")), None)
print((row["path"] if row else "-"), (row.get("status") if row else "-"))
PY
)"
[ "$HIST_PATH" = "/hello?a=1&b=2" ] && ok "exchange in history with the origin-form path" \
  || no "history path was '$HIST_PATH', want /hello?a=1&b=2"
[ "$HIST_STATUS" = "200" ] && ok "status recorded" || no "status recorded as '$HIST_STATUS'"

echo "=== 3. the FIRST captured exchange is id 0 and is addressable (HONEST-05) ==="
# The point of this section. Exchange ids are a dense counter from zero, and both audit routes used
# to reject id 0 — so the top row of HTTP history was the one row that could not be audited, and the
# error blamed the caller ("Invalid exchange id") for a well-formed real id.
FIRST_ID=$(python3 - "$WEB_PORT" <<'PY'
import json,sys,urllib.request
h=json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/history",timeout=10))
# /api/history is a bare JSON array in the Go port; tolerate an envelope so a future wrapping of it
# fails on the assertion below rather than on a KeyError here.
rows=h if isinstance(h,list) else (h.get("exchanges") or h.get("rows") or [])
print(min(int(r["id"]) for r in rows) if rows else "none")
PY
)
[ "$FIRST_ID" = "0" ] && ok "first captured exchange is id 0" || no "lowest exchange id is '$FIRST_ID', expected 0"

AUD=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$WEB_PORT/api/audit/0")
[ "$AUD" = "200" ] && ok "POST /api/audit/0 accepted" || no "POST /api/audit/0 -> HTTP $AUD"
AUDB=$(curl -s -X POST "http://127.0.0.1:$WEB_PORT/api/audit/0")
echo "$AUDB" | grep -q '"exchange_id":0' && ok "audit ran against exchange 0" || no "audit body: ${AUDB:0:160}"
# The legacy alias had the same bug spelled differently ("exchange_id is required" for a supplied 0).
LEG=$(curl -s -X POST "http://127.0.0.1:$WEB_PORT/api/scanner/audit" \
      -H 'content-type: application/json' -d '{"exchange_id":0}')
echo "$LEG" | grep -q '"exchange_id":0' && ok "legacy alias accepts exchange 0" || no "legacy alias: ${LEG:0:160}"

echo "=== 4. stored request is retrievable and byte-exact ==="
# The stored bytes must be the bytes upstream received — origin-form, not the absolute-form the
# client sent — because that is what history shows and what Repeater and Intruder start from. A
# request stored in one form and sent in another makes every downstream tool subtly wrong.
REQ_ID=$(echo "$HIST" | grep -o '"request":[0-9]*' | head -1 | cut -d: -f2)
FIRSTLINE=$(python3 - "$WEB_PORT" "$REQ_ID" <<'PY'
import json,sys,urllib.request
m=json.load(urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/message/{sys.argv[2]}",timeout=10))
print(m.get("text","").splitlines()[0] if m.get("text") else "-")
PY
)
[ "$FIRSTLINE" = "GET /hello?a=1&b=2 HTTP/1.1" ] && ok "request stored origin-form" \
  || no "stored request line was '$FIRSTLINE'"

echo "=== 5. repeater sends and records ==="
# The Go DTO is {target, protocol, request} — not Rust's {target, raw}. That difference is the kind
# of thing this suite exists to catch: the UI is shared, so a rename on either side breaks one port.
RESP=$(python3 - "$WEB_PORT" "$TARGET_PORT" <<'PY'
import json,sys,urllib.request
web,tgt=sys.argv[1],sys.argv[2]
raw=f"GET /repeated?x=9 HTTP/1.1\r\nHost: 127.0.0.1:{tgt}\r\nConnection: close\r\n\r\n"
body=json.dumps({"target":f"http://127.0.0.1:{tgt}","protocol":"http","request":raw}).encode()
r=urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{web}/api/repeater/send",body,{"content-type":"application/json"}),timeout=20)
print(r.read().decode())
PY
)
echo "$RESP" | grep -q 'TARGET-OK GET /repeated?x=9' && ok "repeater got expected body" || no "repeater body: ${RESP:0:160}"
echo "$RESP" | grep -q '"status":200' && ok "repeater status 200" || no "repeater status"
REP_MSG=$(echo "$RESP" | grep -o '"request_msg_id":[0-9]*' | cut -d: -f2)

echo "=== 6. intruder finds insertion points ==="
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

# A wrong verb must say "wrong verb", not complain about the body it never got (defect 0.4). Every
# other handler in the file guarded this; these two did not, so GET answered "Invalid request body".
PM=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$WEB_PORT/api/intruder/points")
[ "$PM" = "405" ] && ok "GET /api/intruder/points -> 405" || no "GET /api/intruder/points -> HTTP $PM, want 405"

echo "=== 7. intruder attack runs against the point ==="
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
[ "$N" -ge 3 ] && ok "$N attempts executed" || no "attempts=$N : ${ATT:0:160}"
echo "$ATT" | grep -q '"status":200' && ok "attack got 200s" || no "attack statuses"

echo "=== 8. sequencer capture is a real loop, and is honest when there is none (HONEST-02) ==="
# /stop used to answer {"stopped":true} for a loop that did not exist, and on any verb — so a GET
# reported a state change it could not have caused. And GET /capture/{id} answered
# {"total":0,"tokens":[]} for every id, which reads as "this application's tokens are unanalysable"
# when nothing had ever been sent.
SM=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$WEB_PORT/api/sequencer/capture/stop")
[ "$SM" = "405" ] && ok "GET .../capture/stop -> 405" || no "GET .../capture/stop -> HTTP $SM, want 405"

# Nothing is running yet, so stop must say so rather than claiming a success.
STOP=$(curl -s -X POST "http://127.0.0.1:$WEB_PORT/api/sequencer/capture/stop")
case "$STOP" in
  *'"stopped":true'*) no "stop claims it halted a capture that was never started: $STOP" ;;
  '')                 no "stop returned nothing" ;;
  *)                  ok "stop does not claim to have halted a capture that never ran" ;;
esac
# And an id that was never issued is a 404, not an empty capture.
UNK=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$WEB_PORT/api/sequencer/capture/4242")
[ "$UNK" = "404" ] && ok "an unknown capture id -> 404" || no "unknown capture id -> HTTP $UNK, want 404"

# Now a real capture. The demo target sets E2E_SESSION on every response, so 12 requests must yield
# 12 distinct tokens — the assertion a stub cannot satisfy.
CAP=$(python3 - "$WEB_PORT" "$TARGET_PORT" <<'PY'
import json,sys,time,urllib.request
web,tgt=sys.argv[1],sys.argv[2]
raw=f"GET /token HTTP/1.1\r\nHost: 127.0.0.1:{tgt}\r\nConnection: close\r\n\r\n"
body=json.dumps({"target":f"http://127.0.0.1:{tgt}","protocol":"http","request":raw,"count":12,
                 "location":{"kind":"cookie","name":"E2E_SESSION"}}).encode()
started=json.load(urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{web}/api/sequencer/capture",body,{"content-type":"application/json"}),timeout=20))
for _ in range(200):
    view=json.load(urllib.request.urlopen(f"http://127.0.0.1:{web}/api/sequencer/capture/{started['id']}",timeout=10))
    if not view["capturing"]:
        break
    time.sleep(0.05)
toks=view.get("tokens") or []
print(json.dumps({"total":view["total"],"attempts":view["attempts"],"requested":view["requested"],
                  "misses":view["misses"],"distinct":len(set(toks))}))
PY
)
echo "$CAP" | python3 -c "
import json,sys
v=json.load(sys.stdin)
assert v['total']==12, v
assert v['attempts']==12, v
assert v['requested']==12, v
assert v['misses']==0, v
# Distinct, because a loop that re-read one buffered response twelve times would satisfy every count
# above while the sample an entropy verdict is computed over would be a single token repeated.
assert v['distinct']==12, v
" 2>/dev/null && ok "capture collected 12 distinct tokens from 12 requests: $CAP" || no "capture reported: $CAP"

# Analysing the captured list closes the loop: a capture whose tokens the analyser cannot read would
# be two features that each work alone.
ANA=$(python3 - "$WEB_PORT" <<'PY'
import json,sys,urllib.request
web=sys.argv[1]
cap=json.load(urllib.request.urlopen(f"http://127.0.0.1:{web}/api/sequencer/capture/1",timeout=10))
body=json.dumps({"tokens":cap.get("tokens") or []}).encode()
r=urllib.request.urlopen(urllib.request.Request(
    f"http://127.0.0.1:{web}/api/sequencer/analyse",body,{"content-type":"application/json"}),timeout=20)
print(json.load(r)["tokens"])
PY
)
[ "$ANA" = "12" ] && ok "the analyser read the 12 captured tokens" || no "analyse over captured tokens reported '$ANA'"

echo "=== 9. the session cookie jar reports what it holds (HONEST-03) ==="
# The target sets E2E_SESSION on every response. This route used to answer {"wired":true,
# "cookies":[]} unconditionally, so the operator's table denied cookies the coordinator was holding.
# Attributes must not appear as cookies: Path and SameSite were being stored and sent back.
CJ=$(curl -s "http://127.0.0.1:$WEB_PORT/api/session/cookies")
echo "$CJ" | grep -q '"wired":' && ok "cookie route answers" || no "cookie route: ${CJ:0:160}"
echo "$CJ" | grep -qE '"name":"(Path|SameSite)"' \
  && no "cookie attributes stored as cookies: ${CJ:0:200}" \
  || ok "no cookie attributes masquerading as cookies"

echo "=== 10. memory accounting is exposed ==="
ST=$(curl -s "http://127.0.0.1:$WEB_PORT/api/stats")
echo "$ST" | grep -qE '"stored_bytes":[0-9]+' && ok "stats: $ST" || no "stats missing"

echo
echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
