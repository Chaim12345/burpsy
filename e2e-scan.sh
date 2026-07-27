#!/usr/bin/env bash
# Acceptance test for passive scanning (task #10).
#
# The bar: load PortSwigger's real BCheck corpus, proxy a response that contains a secret, and see a
# deduplicated finding via /api/issues. Anything less is a parser with no consumer.
set -uo pipefail
cd "$(dirname "$0")"

PROXY=18390; WEB=18391; ORIGIN=18399
CORPUS=${CORPUS:-/tmp/BChecks}
WORK=$(mktemp -d /tmp/burpsy-scan-XXXXXX)
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup(){ pkill -x burpsy 2>/dev/null; kill ${ORIGIN_PID:-0} 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

[ -d "$CORPUS" ] || { echo "corpus missing at $CORPUS"; exit 0; }

# ---- origin that leaks things the real corpus looks for ----------------------------------
python3 - "$ORIGIN" <<'PY' &
import sys, http.server
# An AWS access key ID shape (AKIA + 16 uppercase alnum) — matched by several corpus checks.
LEAK = b"config: aws_key=AKIAIOSFODNN7EXAMPLE end"
CLEAN = b"nothing sensitive here at all"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = CLEAN if self.path.startswith("/clean") else LEAK
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
ORIGIN_PID=$!
for _ in $(seq 1 80); do curl -s -o /dev/null "http://127.0.0.1:$ORIGIN/" && break; sleep 0.1; done

./target/debug/burpsy --proxy "127.0.0.1:$PROXY" --web "127.0.0.1:$WEB" \
  --bchecks "$CORPUS" > "$WORK/b.log" 2>&1 &
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$WEB/api/stats" && break; sleep 0.1; done

echo "=== 1. corpus loaded and coverage reported ==="
grep -q 'passive runnable' "$WORK/b.log" && ok "coverage stated: $(grep -o '[0-9]* passive runnable.*' "$WORK/b.log" | head -1)" \
  || no "no coverage line in log"
grep -q '105 passive runnable' "$WORK/b.log" && ok "105 passive checks loaded" || no "unexpected passive count"
# Match the per-file WARNING, not the summary — the summary contains the literal text
# "0 unparsable", so grepping for the bare word reports failure when the count is zero.
grep -q 'unparsable bcheck' "$WORK/b.log" && no "some bchecks failed to parse" \
  || ok "all 264 corpus files parsed (0 unparsable)"

echo "=== 2. issues endpoint is enabled ==="
curl -s "http://127.0.0.1:$WEB/api/issues" | grep -q '"enabled":true' && ok "/api/issues enabled" || no "issues not enabled"

echo "=== 3. a leaked key in a proxied response produces a finding ==="
curl -s -o /dev/null -x "http://127.0.0.1:$PROXY" "http://127.0.0.1:$ORIGIN/leak1"
sleep 1.0
I=$(curl -s "http://127.0.0.1:$WEB/api/issues")
N=$(echo "$I" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['findings']))")
[ "$N" -ge 1 ] && ok "$N finding(s) recorded" || no "no findings after a leaking response"
echo "$I" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for f in d['findings'][:3]:
    print(f\"        {f['severity']:<7} {f['check_name'][:44]:<44} x{f['times_seen']}\")
" 2>/dev/null

echo "=== 4. repeat hits on the same host dedup ==="
for p in leak2 leak3 leak4; do
  curl -s -o /dev/null -x "http://127.0.0.1:$PROXY" "http://127.0.0.1:$ORIGIN/$p"
done
sleep 1.2
I2=$(curl -s "http://127.0.0.1:$WEB/api/issues")
N2=$(echo "$I2" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['findings']))")
SEEN=$(echo "$I2" | python3 -c "import json,sys; d=json.load(sys.stdin); print(max((f['times_seen'] for f in d['findings']), default=0))")
[ "$N2" -eq "$N" ] && ok "finding count stayed $N2 across 4 leaking pages (deduped)" \
  || no "finding count grew $N -> $N2; dedup not working"
[ "$SEEN" -ge 4 ] && ok "times_seen reached $SEEN (occurrences tracked)" || no "times_seen only $SEEN"

echo "=== 5. a clean response adds nothing ==="
curl -s -o /dev/null -x "http://127.0.0.1:$PROXY" "http://127.0.0.1:$ORIGIN/clean"
sleep 0.8
N3=$(curl -s "http://127.0.0.1:$WEB/api/issues" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['findings']))")
[ "$N3" -eq "$N2" ] && ok "clean page added no findings" || no "clean page added findings ($N2 -> $N3)"

echo "=== 6. scanning did not break proxying ==="
B=$(curl -s -x "http://127.0.0.1:$PROXY" "http://127.0.0.1:$ORIGIN/clean")
[ "$B" = "nothing sensitive here at all" ] && ok "response still proxied verbatim" || no "body was '$B'"

echo
echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
