#!/usr/bin/env bash
# Acceptance test for TLS interception (tasks 1-3).
#
# The bar: browse an HTTPS origin through the proxy with the burpsy CA trusted, and see the
# PLAINTEXT request and response in history. Anything less is a tunnel, not interception.
set -uo pipefail
cd "$(dirname "$0")"

# NB: keep these well apart — an earlier version used PROXY+1 for the second instance,
# which collided with WEB and made the second proxy fail to bind (silently, via select!).
PROXY=18190; WEB=18191; ORIGIN=18199
PROXY2=18290; WEB2=18291
CADIR=$(mktemp -d /tmp/burpsy-ca-e2e-XXXXXX)
WORK=$(mktemp -d /tmp/burpsy-tls-e2e-XXXXXX)
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup(){ pkill -x burpsy 2>/dev/null; kill ${ORIGIN_PID:-0} 2>/dev/null; rm -rf "$CADIR" "$WORK"; }
trap cleanup EXIT

# ---- an HTTPS origin with its own unrelated self-signed cert -----------------------------
# Deliberately self-signed and untrusted: a testing proxy must reach staging hosts whose certs
# do not validate, so this also exercises the permissive upstream verifier.
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/o.key" -out "$WORK/o.crt" -days 2 -nodes \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1

python3 - "$ORIGIN" "$WORK" <<'PY' &
import sys, ssl, http.server
port, work = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = f"SECRET-PLAINTEXT {self.command} {self.path}".encode()
        self.send_response(200); self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.send_header("X-Origin-Marker","only-visible-if-decrypted")
        self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{work}/o.crt", f"{work}/o.key")
srv = http.server.HTTPServer(("127.0.0.1", port), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
ORIGIN_PID=$!

for _ in $(seq 1 80); do
  curl -sk -o /dev/null "https://localhost:$ORIGIN/" && break; sleep 0.1
done
curl -sk -o /dev/null "https://localhost:$ORIGIN/" \
  && ok "https origin up (self-signed)" || no "origin not up"

# ---- burpsy with interception ------------------------------------------------------------
./target/debug/burpsy --proxy "127.0.0.1:$PROXY" --web "127.0.0.1:$WEB" \
  --intercept-tls --ca-dir "$CADIR" > "$WORK/burpsy.log" 2>&1 &
for _ in $(seq 1 80); do curl -s -o /dev/null "http://127.0.0.1:$WEB/api/stats" && break; sleep 0.1; done

echo "=== 1. CA is generated and downloadable ==="
[ -s "$CADIR/ca.pem" ] && ok "ca.pem written to disk" || no "ca.pem missing"
[ "$(stat -c '%a' "$CADIR/ca.key" 2>/dev/null)" = "600" ] && ok "ca.key is 0600" || no "ca.key perms"
curl -s "http://127.0.0.1:$WEB/ca.crt" -o "$WORK/ca.crt"
grep -q 'BEGIN CERTIFICATE' "$WORK/ca.crt" && ok "/ca.crt serves the CA" || no "/ca.crt bad"

echo "=== 2. CA has the extensions browsers require ==="
X=$(openssl x509 -in "$WORK/ca.crt" -noout -text 2>/dev/null)
echo "$X" | grep -q 'CA:TRUE'                        && ok "basicConstraints CA:TRUE" || no "no CA:TRUE"
echo "$X" | grep -qE 'Certificate Sign'              && ok "keyUsage keyCertSign"     || no "no keyCertSign"
echo "$X" | grep -q 'X509v3 Subject Key Identifier'  && ok "has SKI"                  || no "no SKI"
# An EKU on a root is read by Windows as a constraint — it must be absent.
echo "$X" | grep -q 'X509v3 Extended Key Usage' && no "root has an EKU (Windows treats as constraint)" \
                                                || ok "root has no EKU (correct)"

echo "=== 3. HTTPS through the proxy, trusting only the burpsy CA ==="
BODY=$(curl -s --max-time 15 --cacert "$WORK/ca.crt" \
        --proxy "http://127.0.0.1:$PROXY" "https://localhost:$ORIGIN/secret?q=1" 2>"$WORK/curl.err")
if [ "$BODY" = "SECRET-PLAINTEXT GET /secret?q=1" ]; then
  ok "TLS handshake validated against burpsy CA, body correct"
else
  no "body was '$BODY' (curl: $(tr -d '\n' < "$WORK/curl.err" | tail -c 160))"
fi

echo "=== 4. the exchange is DECRYPTED in history ==="
sleep 0.5
H=$(curl -s "http://127.0.0.1:$WEB/api/history")
echo "$H" | grep -q '"path":"/secret?q=1"' && ok "plaintext path in history" || no "path not decrypted"
echo "$H" | grep -q '"notes":"intercepted"' && ok "marked intercepted" || no "not marked intercepted"
echo "$H" | grep -q '"status":200'          && ok "status 200 recorded"  || no "status missing"

REQ=$(echo "$H" | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r.get('path')=='/secret?q=1': print(r['request']); break")
if [ -n "$REQ" ]; then
  M=$(curl -s "http://127.0.0.1:$WEB/api/message/$REQ")
  echo "$M" | grep -q 'GET /secret?q=1 HTTP/1.1' && ok "request stored as plaintext" || no "request not plaintext"
  RES=$(echo "$H" | python3 -c "
import json,sys
for r in json.load(sys.stdin):
    if r.get('path')=='/secret?q=1' and r.get('response') is not None: print(r['response']); break")
  if [ -n "$RES" ]; then
    R=$(curl -s "http://127.0.0.1:$WEB/api/message/$RES")
    echo "$R" | grep -q 'only-visible-if-decrypted' \
      && ok "response header visible => genuinely decrypted" || no "response not decrypted"
  else no "no response message id"; fi
else no "could not find the exchange"; fi

echo "=== 5. passthrough still bypasses interception ==="
./target/debug/burpsy --proxy "127.0.0.1:$PROXY2" --web "127.0.0.1:$WEB2" \
  --intercept-tls --ca-dir "$CADIR" --tls-passthrough 'localhost' > "$WORK/b2.log" 2>&1 &
for _ in $(seq 1 80); do curl -s -o /dev/null "http://127.0.0.1:$WEB2/api/stats" && break; sleep 0.1; done
curl -s --max-time 8 --cacert "$WORK/ca.crt" --proxy "http://127.0.0.1:$PROXY2" \
  "https://localhost:$ORIGIN/" -o /dev/null 2>/dev/null
sleep 0.4
H2=$(curl -s "http://127.0.0.1:$WEB2/api/history")
echo "$H2" | grep -q 'passthrough: host matches passthrough pattern' \
  && ok "passthrough host tunnelled, not intercepted" \
  || no "passthrough note missing: $(echo "$H2" | head -c 200)"

echo
echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
