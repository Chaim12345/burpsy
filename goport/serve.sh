#!/usr/bin/env bash
# Launch burpsy Go Port for interactive exploration, with a demo target and seeded traffic.
#
# Binds 0.0.0.0 so it is reachable from Windows both via localhostForwarding and via the WSL IP.
set -uo pipefail
cd "$(dirname "$0")"

PROXY_PORT=${PROXY_PORT:-8080}
WEB_PORT=${WEB_PORT:-8081}
DEMO_PORT=${DEMO_PORT:-8099}

pkill -f './burpsy' 2>/dev/null || true
pkill -f 'burpsy-demo-target-go' 2>/dev/null || true
sleep 0.3

# Ensure the binary is built
if [ ! -f ./burpsy ]; then
  echo "Building Go burpsy binary..."
  go build -o burpsy ./cmd/burpsy
fi

# ---- demo target: a tiny app with params, cookies and varied statuses --------------------
python3 - "$DEMO_PORT" burpsy-demo-target-go <<'PY' &
import sys, http.server, urllib.parse

PAGE = b"""<!doctype html><title>demo app</title>
<h1>burpsy demo target</h1>
<form method=POST action=/login>
  <input name=user value=admin><input name=pass value=hunter2><button>login</button>
</form>
<a href="/search?q=test&lang=en">search</a> | <a href="/admin">admin</a> | <a href="/missing">404</a>
"""

class H(http.server.BaseHTTPRequestHandler):
    server_version = "demo/1.0"
    def reply(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path == "/":
            self.reply(200, PAGE, extra={"Set-Cookie": "sid=abc123; Path=/"})
        elif p.path == "/search":
            q = urllib.parse.parse_qs(p.query)
            body = f"results for {q.get('q',[''])[0]!r} lang={q.get('lang',[''])[0]!r}".encode()
            self.reply(200, body, "text/plain")
        elif p.path == "/admin":
            self.reply(403, b"forbidden", "text/plain")
        elif p.path == "/slow":
            import time; time.sleep(1.2)
            self.reply(200, b"slow ok", "text/plain")
        else:
            self.reply(404, b"not found", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        f = urllib.parse.parse_qs(raw)
        user = f.get("user", [""])[0]
        if "'" in raw or '"' in raw:
            self.reply(500, b"SQL syntax error near unexpected token", "text/plain")
        elif user == "admin" and f.get("pass", [""])[0] == "hunter2":
            self.reply(302, b"", extra={"Location": "/", "Set-Cookie": "auth=yes; Path=/"})
        else:
            self.reply(401, b"bad credentials", "text/plain")

    def log_message(self, *a): pass

http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
DEMO_PID=$!

for _ in $(seq 1 60); do curl -s -o /dev/null "http://127.0.0.1:$DEMO_PORT/" && break; sleep 0.1; done

# ---- burpsy Go Port ---------------------------------------------------------------------
nohup ./burpsy --proxy "0.0.0.0:$PROXY_PORT" --web "0.0.0.0:$WEB_PORT" \
  > /tmp/burpsy-go-serve.log 2>&1 &
BURPSY_PID=$!
for _ in $(seq 1 80); do curl -s -o /dev/null "http://127.0.0.1:$WEB_PORT/api/stats" && break; sleep 0.1; done

# ---- seed varied traffic through the proxy ----------------------------------------------
X="http://127.0.0.1:$PROXY_PORT"
T="http://127.0.0.1:$DEMO_PORT"
curl -s -o /dev/null -x "$X" "$T/"                                             # 200 + Set-Cookie
curl -s -o /dev/null -x "$X" "$T/search?q=test&lang=en"                        # 200, 2 params
curl -s -o /dev/null -x "$X" "$T/search?q=admin%27&lang=de"                    # quote in param
curl -s -o /dev/null -x "$X" "$T/admin"                                        # 403
curl -s -o /dev/null -x "$X" "$T/missing"                                      # 404
curl -s -o /dev/null -x "$X" -H 'Cookie: sid=abc123; theme=dark' "$T/"         # cookies
curl -s -o /dev/null -x "$X" -d 'user=admin&pass=hunter2' "$T/login"           # 302 POST
curl -s -o /dev/null -x "$X" -d "user=admin'&pass=x" "$T/login"                # 500 SQLish
curl -s -o /dev/null -x "$X" "$T/slow" &                                       # slow one
sleep 1.6

WSL_IP=$(ip -4 addr show eth0 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)
STATS=$(curl -s "http://127.0.0.1:$WEB_PORT/api/stats")

cat <<EOF

  burpsy Go Port is running (fully functional backend and frontend!)
  ─────────────────────────────────────────────────────────
  Web UI      http://localhost:$WEB_PORT
              http://${WSL_IP:-<wsl-ip>}:$WEB_PORT     (if localhost forwarding is off)
  Proxy       127.0.0.1:$PROXY_PORT   (or ${WSL_IP:-<wsl-ip>}:$PROXY_PORT)
  Demo app    http://127.0.0.1:$DEMO_PORT   — reachable through the proxy

  Seeded      $STATS

  Try:
    History   click any row to see raw request + response
    Repeater  target http://127.0.0.1:$DEMO_PORT
              GET /search?q=test&lang=en HTTP/1.1
              Host: 127.0.0.1:$DEMO_PORT
              Connection: close
    Intruder  msg id from a /login POST row, target http://127.0.0.1:$DEMO_PORT
              Find points -> pick the 'user' body param -> Attack
              payloads:  admin,admin',",../../etc/passwd,{{7*7}}
              the demo app 500s on a quote, so you should see it stand out

  logs        tail -f /tmp/burpsy-go-serve.log
  stop        pkill -f './burpsy' ; pkill -f burpsy-demo-target-go
  ─────────────────────────────────────────────────────────
EOF
