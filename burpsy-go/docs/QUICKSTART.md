# burpsy-go — Quickstart

Get from `git clone` to a running, headless burpsy proxy + JSON API in a few
minutes. Every command below was run against the real Go binary and its output
verified before this page was written; there are no aspirational steps.

> **Authorized use only.** burpsy sends real traffic to whatever you point it at.
> Only ever run it against targets you are explicitly authorized to test, and
> keep an engagement scope declared (see step 4). Nothing in this guide is for
> use against systems you do not own or have written permission to test.

---

## 1. Prerequisites

- **Go 1.26.2 or newer** (`go.mod` declares `go 1.26.2`). Check with `go version`.
- A Unix-like shell. Everything here runs headless — no display, no browser
  required — so it works over SSH.

## 2. Clone and build

The Go port lives in the `burpsy-go/` subdirectory of the repository.

```bash
git clone https://github.com/Chaim12345/brpsy.git
cd brpsy/burpsy-go
go build -o burpsy ./cmd/burpsy
```

You now have a `./burpsy` binary. Confirm it and see every flag:

```bash
./burpsy -h
```

## 3. Run it headless

The default run starts two listeners: an intercepting HTTP proxy on
`127.0.0.1:8080` and the JSON API / web UI on `127.0.0.1:8081`.

```bash
./burpsy
```

Leave it running in one terminal (or background it / run under `tmux` for SSH).
Nothing binds a public interface by default — both listeners are loopback-only.

For a fully self-contained first run, pick your own ports and a scratch database:

```bash
./burpsy \
  -proxy 127.0.0.1:8080 \
  -web   127.0.0.1:8081 \
  -db    /tmp/burpsy.db
```

- `-proxy` — where the intercepting proxy listens (point your client here).
- `-web` — where the JSON API and single-page UI are served.
- `-db` — SQLite file for persistent history, findings, scope and rules. Omit it
  for an in-memory session that is discarded on exit.

## 4. Declare an authorized scope

Scope is what every sender inside burpsy is allowed to reach. Set it at launch
with `-scope-include` / `-scope-exclude` (host patterns), or later over the API
(`POST /api/scope`).

```bash
./burpsy -scope-include 'example.com' -scope-exclude 'logout.example.com'
```

Traffic to hosts outside scope is not scanned; scope is enforced against the
request actually sent.

## 5. Send traffic through the proxy

Point any HTTP client at the proxy and make a request. This example proxies a
plain-HTTP request through burpsy:

```bash
curl -x http://127.0.0.1:8080 http://your-authorized-target/path
```

The exchange is captured and immediately queryable over the API:

```bash
curl -s http://127.0.0.1:8081/api/history          # captured exchanges
curl -s http://127.0.0.1:8081/api/stats             # {"exchanges":N,"messages":M,"stored_bytes":B}
```

*(Verified: a proxied `GET` appears in `/api/history` with method, path, status,
protocol and timing, and `/api/stats` increments accordingly.)*

## 6. Intercept HTTPS (TLS MITM)

To intercept TLS, enable it and choose where the CA lives. burpsy generates a
CA on first run and serves the public certificate at `/ca.crt`:

```bash
./burpsy -intercept-tls -ca-dir "$HOME/.config/burpsy/ca"
```

```bash
# Fetch the CA so your client can trust burpsy's on-the-fly leaf certs:
curl -s http://127.0.0.1:8081/ca.crt -o burpsy-ca.crt
```

Install `burpsy-ca.crt` into the trust store of the client you are testing (only
on machines you control). Then proxy HTTPS the same way as step 5.

> `/ca.crt` returns **404 until TLS interception has produced a CA** — that is
> honest behavior, not a bug: with no CA there is nothing to serve. Run with
> `-intercept-tls` (and a writable `-ca-dir`) and it returns a PEM certificate.

For hosts you must not MITM (certificate-pinned apps, etc.), pass them through
untouched:

```bash
./burpsy -intercept-tls \
  -tls-passthrough 'pinned.example.com' \
  -tls-defaults          # preload a set of commonly-pinned hosts
```

## 7. Passive scanning with BCheck (optional)

burpsy runs PortSwigger's published BCheck corpus, honestly counted, against
proxied responses. The corpus is **not vendored** in this repo — you supply a
directory of `.bcheck` files with `-bchecks`:

```bash
./burpsy -bchecks /path/to/BChecks
```

At startup the log reports exactly what loaded, e.g.:

```
bchecks loaded  dir=/path/to/BChecks  report="264 files: … passive, … active, … need insertion point, … need tools, 0 parse errors"
```

Coverage — which checks actually ran, and what was skipped and why — is reported
honestly at any time:

```bash
curl -s http://127.0.0.1:8081/api/scanner/coverage
```

With nothing loaded this endpoint says `"no passive checks loaded"` rather than
implying a clean scan. See [BCHECK-COVERAGE.md](./BCHECK-COVERAGE.md) for what is
and is not supported.

## 8. Allow external tools for `run tool` checks (optional)

Some BCheck files invoke an external binary (`run tool`). Execution is **off by
default**; a check that wants a tool is counted but not dispatched unless you
explicitly allowlist the binary by name and absolute path:

```bash
./burpsy -bchecks /path/to/BChecks \
  -tools 'sqlmap=/usr/bin/sqlmap,jwt_tool=/opt/jwt_tool/jwt_tool.py'
```

The allowlist is `name=path` pairs, comma-separated. A check requesting a tool
that is not on the allowlist stays counted-but-undispatched — it is never run
silently.

## 9. Where to go next

- [JSON-API.md](./JSON-API.md) — the full route surface for driving burpsy from
  scripts and agents.
- [MCP.md](./MCP.md) — the (planned) MCP surface and what drives burpsy today.
- [BCHECK-COVERAGE.md](./BCHECK-COVERAGE.md) — honest BCheck coverage.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `bind: address already in use` | Another process (or a previous burpsy) holds that port. Pick a different `-proxy` / `-web`, or stop the other process. |
| `/ca.crt` returns 404 | TLS interception has not produced a CA yet. Run with `-intercept-tls` and a writable `-ca-dir`. |
| `/api/scanner/coverage` says "no passive checks loaded" | You did not pass `-bchecks DIR`. Point it at a directory of `.bcheck` files. |
| A `run tool` check never fires | Tool execution is opt-in. Add the binary to `-tools name=/abs/path`. |
