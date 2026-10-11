#!/usr/bin/env bash
# Bootstrap the live VulnerableApp benchmark environment after a sandbox reset.
# Idempotent: safe to re-run. Writes everything under /tmp/bsywork.
set -u
ROOT=/workspace/project/7cc3fba96fa2489f89d38773fa3b3769/burpsy
W=/tmp/bsywork
mkdir -p "$W"

# 1. Go toolchain
if [ ! -x /usr/local/go/bin/go ]; then
  echo "[boot] installing Go"
  cd /tmp && curl -fsSL -o go.tgz https://go.dev/dl/go1.26.9.linux-amd64.tar.gz \
    && sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go.tgz
fi
export PATH="/usr/local/go/bin:$PATH"

# 2. Docker + target app
if ! sudo docker info >/dev/null 2>&1; then
  echo "[boot] starting dockerd"
  sudo dockerd > "$W/dockerd.log" 2>&1 &
  sleep 12
fi
if ! sudo docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^va$'; then
  echo "[boot] starting VulnerableApp"
  sudo docker rm -f va >/dev/null 2>&1
  sudo docker run -d --name va -p 9090:9090 sasanlabs/owasp-vulnerableapp:latest >/dev/null
fi

# 3. burpsy
cd "$ROOT/burpsy-go" || exit 1
if [ ! -x "$W/burpsy" ] || [ -n "$(find internal cmd -name '*.go' -newer "$W/burpsy" -print -quit 2>/dev/null)" ]; then
  echo "[boot] building burpsy"
  go build -o "$W/burpsy" ./cmd/burpsy
fi
pkill -f "$W/burpsy -db" 2>/dev/null
sleep 1
nohup "$W/burpsy" -db "$W/burpsy.db" -proxy 127.0.0.1:18080 -web 127.0.0.1:18081 \
  -scope-include 127.0.0.1 -dom chromium > "$W/server.log" 2>&1 &
disown

# 4. wait for both
for i in $(seq 1 40); do
  a=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9090/VulnerableApp/scanner 2>/dev/null)
  b=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18081/api/history 2>/dev/null)
  if [ "$a" = "200" ] && [ "$b" = "200" ]; then echo "[boot] ready app=$a burpsy=$b"; exit 0; fi
  sleep 2
done
echo "[boot] FAILED app=$a burpsy=$b"; tail -5 "$W/server.log" 2>/dev/null; exit 1
