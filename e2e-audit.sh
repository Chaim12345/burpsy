#!/usr/bin/env bash
# Acceptance test for active scanning (BCheck M2 — `send request`).
#
# The bar: a check that mutates the base request must produce a finding that is only reachable if the
# mutation actually reached the origin. So the origin answers 404 everywhere except the probe path,
# and it records every path it was asked for. A test that merely proved "the send did not error"
# would pass even with all 381 modifier clauses discarded, which is exactly the bug this replaces.
set -uo pipefail
cd "$(dirname "$0")"

PROXY=18490; WEB=18491; ORIGIN=18499
WORK=$(mktemp -d /tmp/burpsy-audit-XXXXXX)
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup(){ pkill -x burpsy 2>/dev/null; kill ${ORIGIN_PID:-0} 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# ---- origin: 404 everywhere except the probe path, and it logs what it was asked for -----
python3 - "$ORIGIN" "$WORK/paths.log" <<'PY' &
import sys, http.server
LOG = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(LOG, "a") as f:
            f.write(self.path + "\n")
        if self.path.startswith("/admin"):
            body = b"ADMIN CONSOLE unprotected"; code = 200
        else:
            body = b"not found"; code = 404
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
ORIGIN_PID=$!
for _ in $(seq 1 80); do curl -s -o /dev/null "http://127.0.0.1:$ORIGIN/" && break; sleep 0.1; done

# ---- the check set: one positive, one negative, one that appends a query ----------------
mkdir -p "$WORK/checks"
cat > "$WORK/checks/admin.bcheck" <<'EOF'
metadata:
    language: v2-beta
    name: "Unprotected admin console"
    description: "Probes a fixed path and reports only on a 200."
    author: "burpsy e2e"

given host then
    send request called probe:
        path: "/admin"
    if {probe.response.status_code} is "200" and "ADMIN CONSOLE" in {probe.response.body} then
        report issue:
            name: "Unprotected admin console"
            severity: high
            confidence: certain
            detail: `Probing /admin returned {probe.response.status_code}.`
    end if
EOF
cat > "$WORK/checks/absent.bcheck" <<'EOF'
metadata:
    language: v2-beta
    name: "Should never fire"
    author: "burpsy e2e"

given host then
    send request called probe:
        path: "/definitely-not-here"
    if {probe.response.status_code} is "200" then
        report issue:
            name: "False positive canary"
            severity: high
            confidence: certain
    end if
EOF
cat > "$WORK/checks/query.bcheck" <<'EOF'
metadata:
    language: v2-beta
    name: "Query appender"
    author: "burpsy e2e"

given host then
    send request:
        appending queries: `probe_marker=e2e`
    if "never matches this" in {latest.response.body} then
        report issue:
            severity: info
            confidence: tentative
    end if
EOF

./target/debug/burpsy --proxy "127.0.0.1:$PROXY" --web "127.0.0.1:$WEB" \
  --bchecks "$WORK/checks" > "$WORK/b.log" 2>&1 &
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$WEB/api/stats" && break; sleep 0.1; done

echo "=== 1. the check set loads with active checks runnable ==="
grep -q 'active runnable' "$WORK/b.log" \
  && ok "coverage: $(grep -o '[0-9]* passive runnable.*' "$WORK/b.log" | head -1)" \
  || no "no coverage line: $(tail -3 "$WORK/b.log")"
grep -qE '3 active runnable' "$WORK/b.log" && ok "3 active checks loaded" \
  || no "expected 3 active, got: $(grep -o '[0-9]* active runnable' "$WORK/b.log" | head -1)"

echo "=== 2. capture a base exchange through the proxy ==="
curl -s -o /dev/null -x "http://127.0.0.1:$PROXY" "http://127.0.0.1:$ORIGIN/harmless"
sleep 0.5
# /api/history is a bare JSON array of exchanges, and ids start at 0.
EX=$(curl -s "http://127.0.0.1:$WEB/api/history" \
     | python3 -c "import json,sys; h=json.load(sys.stdin); print(h[0]['id'] if h else '')" 2>/dev/null)
ST=$(curl -s "http://127.0.0.1:$WEB/api/history" \
     | python3 -c "import json,sys; h=json.load(sys.stdin); print(h[0]['status'] if h else '')" 2>/dev/null)
[ -n "$EX" ] && ok "captured exchange id=$EX (base status $ST)" || no "no exchange captured"
[ "$ST" = "404" ] && ok "base request 404s, so a finding cannot come from the base response" \
  || no "base status was $ST, expected 404"

echo "=== 3. auditing that exchange sends the MUTATED request ==="
: > "$WORK/paths.log"
A=$(curl -s -X POST "http://127.0.0.1:$WEB/api/audit/$EX")
echo "$A" | python3 -m json.tool 2>/dev/null | sed 's/^/        /' | head -12
RAN=$(echo "$A" | python3 -c "import json,sys; print(json.load(sys.stdin)['outcome']['ran'])" 2>/dev/null)
SF=$(echo "$A" | python3 -c "import json,sys; print(json.load(sys.stdin)['outcome']['send_failures'])" 2>/dev/null)
[ "${RAN:-0}" -eq 3 ] && ok "all 3 active checks ran" || no "ran=$RAN (send_failures=$SF)"
grep -q '^/admin' "$WORK/paths.log" \
  && ok "origin received /admin — 'path:' modifier reached the wire" \
  || no "origin never saw /admin; paths were: $(tr '\n' ' ' < "$WORK/paths.log")"
grep -q 'probe_marker=e2e' "$WORK/paths.log" \
  && ok "origin received probe_marker=e2e — 'appending queries' reached the wire" \
  || no "appended query never arrived; paths: $(tr '\n' ' ' < "$WORK/paths.log")"

echo "=== 4. the finding is recorded, and only the true one ==="
I=$(curl -s "http://127.0.0.1:$WEB/api/issues")
N=$(echo "$I" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['findings']))")
echo "$I" | python3 -c "
import json,sys
for f in json.load(sys.stdin)['findings']:
    print(f\"        {f['severity']:<7} {str(f['issue_name']):<34} {f['detail']}\")
" 2>/dev/null
[ "$N" -eq 1 ] && ok "exactly 1 finding (the real one)" || no "expected 1 finding, got $N"
echo "$I" | grep -q 'Unprotected admin console' && ok "the admin console issue was reported" \
  || no "admin finding missing"
echo "$I" | grep -q 'False positive canary' \
  && no "the canary check fired — a 404 probe was treated as a finding" \
  || ok "the 404 probe produced no finding"
echo "$I" | grep -q 'Probing /admin returned 200' \
  && ok "detail interpolated the probe's own status code" \
  || no "detail did not interpolate {probe.response.status_code}"

echo "=== 5. a failed send is reported, not turned into a finding ==="
# Kill the origin, then audit again: every probe must fail and nothing may be reported.
kill $ORIGIN_PID 2>/dev/null; wait $ORIGIN_PID 2>/dev/null
sleep 0.3
A2=$(curl -s -X POST "http://127.0.0.1:$WEB/api/audit/$EX")
SF2=$(echo "$A2" | python3 -c "import json,sys; print(json.load(sys.stdin)['outcome']['send_failures'])" 2>/dev/null)
N2=$(curl -s "http://127.0.0.1:$WEB/api/issues" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['findings']))")
[ "${SF2:-0}" -eq 3 ] && ok "all 3 sends failed and were counted as failures" || no "send_failures=$SF2"
[ "$N2" -eq "$N" ] && ok "no new findings from failed sends (still $N2)" \
  || no "findings grew $N -> $N2 on a dead origin"

echo "=== 6. auditing an unknown exchange errors cleanly ==="
curl -s -X POST "http://127.0.0.1:$WEB/api/audit/999999" | grep -q 'no such exchange' \
  && ok "unknown exchange rejected" || no "unknown exchange not handled"

echo
echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
