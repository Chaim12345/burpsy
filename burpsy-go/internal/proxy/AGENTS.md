<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# proxy

## Purpose

The intercepting HTTP/HTTPS proxy: the thing a browser is pointed at. It accepts connections, forwards
or MITM-terminates them, captures every exchange into the shared `core.TrafficStore`, hands passive
scanning off the hot path, and can hold requests/responses for operator editing via
`internal/intercept`. It mirrors `crates/proxy`, but the ALPN negotiation vocabulary that lived in the
Rust crate's `tls.rs` has been extracted to `internal/alpn` here (see that package); only the *policy*
"interception forces http/1.1" stays in this package (`alpn.go`).

## Key Files

| File | Description |
|------|-------------|
| `proxy.go` | The bulk of the package: `ProxyConfig`/`Server`, the accept loop (`ListenAndServe`/`handleConnection`), `handleConnect`/`interceptTLS`/`tunnelConnection`, plain `handleHTTP`, the CA (`TlsEngine`, `LoadOrGenerateCA`, `GetCertificate`), `TlsPolicy`/`TlsAction` passthrough rules, `toOriginForm`, and the shared capture handle (`record`/`capture`) |
| `alpn.go` | The proxy's ALPN *policy* only: `AlpnOffer` (interception ⇒ http/1.1), `NegotiatedProtocol`, `ClientALPNProtos` — all thin wrappers over `internal/alpn` |
| `tls_peek.go` | `peekClientALPN`: reads the ClientHello off the client socket, parses its ALPN list, and returns a `replayConn` that replays the peeked bytes into the real handshake |
| `tls_dial.go` | `dialUpstreamTLS`: opens the upstream TLS leg with a chosen ALPN offer |
| `h2_relay.go` | `relayH2`/`relayH2Stream`: drives HTTP/2 on both decrypted legs with `golang.org/x/net/http2`, recording each stream as its own exchange rendered in HTTP/1 shape |
| `ws.go` | WebSocket relay after a `101`: `handleWebSocketUpgrade`, `relayWebsocket`, per-direction pumps, `stripWsHandshake` and its note |
| `capture_sites_test.go` | Pins that no capture site can mint a row that stalls the live-audit cursor; drives real origins through mid-exchange death/unparseable/upgrade/drop |
| `proxy_test.go`, `cert_test.go`, `h2_relay_test.go`, `ws_test.go`, `alpn_test.go`, `origin_form_test.go`, `dom_wiring_test.go`, `parity_test.go` | Unit/integration tests for each surface |

## For AI Agents

- **Every capture site records through `scanner.Capture.Record` (the `capture()` handle), which refuses
  an exchange it cannot complete.** This is load-bearing: `internal/web`'s live-audit sweep breaks on
  the first exchange whose `Response` is `nil`, so a row that will never be completed stalls the cursor
  for the life of the process. `capture_sites_test.go` drives the sites through the failure modes that
  produce such a row. `Source` is set once in `capture()` to `core.SourceProxy` rather than per-site, so
  a new capture site inherits attribution. The **one** exception is the blind CONNECT tunnel row, which
  does not use the shared producer and is asserted as such so the exception stays visible.
- **ALPN is keyed on the interception master switch, not on rules or attachment.** `AlpnOffer` calls
  `alpn.Filter(clientOffer, !interceptionEnabled)`; interception forces http/1.1 because the hold queue
  is HTTP/1-shaped. The offer is settled from the peeked ClientHello (`peekClientALPN`) before any
  request exists to match a rule against, so an operator whose rules name one host still pays the
  downgrade on every host — inherent, not a bug.
- **Request-line rewriting happens before intercept and before the store.** `toOriginForm` rewrites
  absolute-form (`GET http://host/path`) to origin-form only when the target actually carries an
  `http://`/`https://` scheme; it replaces the target positionally within the first line (preserving odd
  whitespace) and leaves asterisk-form and origin-form untouched. The invariant is that what history
  shows, what the operator edits, and what upstream receives are the same bytes. `e2e-go.sh` caught the
  un-rewritten case as a Rust parity mismatch on the first proxied request.
- **CA material is written only when interception is requested.** `LoadOrGenerateCA` is called by the
  CLI only under `--intercept-tls`. `GetCertificate` caches per-host leaves with double-checked locking,
  clamps each leaf's validity window to the CA's own, and presents the chain leaf-then-CA. `/ca/`,
  `*.pem`, `*.key` are gitignored — never commit generated CA material.
- **WebSocket: relay before capture, always.** Every byte read is written to the far side before the
  decoder sees it; one goroutine per direction; a frame desync stops the *capture* for that direction
  (with a recorded marker) but never the connection. `stripWsHandshake` removes
  `Sec-WebSocket-Extensions` before forwarding only when configured, and only if the handshake parses —
  an unparseable one is forwarded untouched and nothing is claimed; a real strip records a verbatim note
  naming the removed offer. Interception is not wired for WebSocket.
- **HTTP/2 is relayed and recorded, not intercepted.** `relayH2Stream` renders the request into HTTP/1
  shape (`burpsyhttp2.RenderRequest`) only when in scope, and captures both halves together through the
  shared producer. The stored bytes are a re-rendering, not the wire octets (HPACK makes byte-exact
  replay impossible).
- **Match-and-replace here is response-direction only.** `matchReplace.Apply(matchreplace.DirResponse, …)`
  runs on the response path (`handleTLSResponse` and `completeResponse`); this package does not apply the
  request direction.

## Testing Requirements

```bash
go test ./internal/proxy/...     # unit + integration (capture sites, alpn, h2, websocket, cert, parity)
../e2e-go.sh                     # end-to-end against the built Go binary (intercept and TLS arms)
```

## Dependencies

### Internal

- `internal/core` — store, scope, message model, protocol/source enums
- `internal/intercept` — the request/response hold queue
- `internal/scanner` — the shared capture-and-scan pipeline (`scanner.Capture`)
- `internal/matchreplace` — response match-and-replace
- `internal/alpn` — the ALPN negotiation vocabulary (offer filtering, wire-value mapping, dialing)
- `internal/http2` — HTTP/1-shape rendering of relayed h2 streams
- `internal/httputil` — HTTP helpers

### External

- `golang.org/x/net/http2` — the h2 relay's client/server
- `go.uber.org/zap` — logging
- stdlib `crypto/tls`, `crypto/x509`, `crypto/rsa`, `encoding/pem` — CA and leaf generation

<!-- MANUAL: -->
