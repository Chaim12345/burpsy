<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# alpn

## Purpose

The one place that decides which HTTP version a TLS connection carries. This logic was
`internal/proxy`'s, and correctly so — a MITM must make both legs speak the same protocol or it
corrupts the exchange it relays — but the proxy is not the only surface that dials a target:
`internal/sender` dials one for every scanner probe, intruder payload and repeater resend, and it did so
with no ALPN offer at all, so an HTTP/2 target silently got HTTP/1.1 (the H2-04 gap). Two copies of an
offer list is how a tool ends up testing a target over one protocol and relaying it over another, so the
vocabulary moved here and both callers reach it. This package has **no Rust crate counterpart**; in the
Rust reference the equivalent lives inside `crates/proxy/src/tls.rs`.

The proxy's *policy* — interception forces http/1.1 — deliberately stays in `internal/proxy/alpn.go`,
because it is a proxy decision and belongs where a reader of the proxy will find it.

## Key Files

| File | Description |
|------|-------------|
| `alpn.go` | The whole package: `H2`/`HTTP11` identifiers, `Filter`, `EgressOffer`, `Protocol`, `Single`, and the `Dialer` struct with its `Dial` method |
| `alpn_test.go` | Unit tests for the filtering/mapping rules |

## For AI Agents

- **`Filter` preserves the caller's order and never invents an offer.** On the proxy's upstream leg the
  list is the *client's* offer and its order is the client's preference; re-sorting would make the origin
  negotiate something the client did not ask for first. An empty offer returns `nil`, not a default list —
  a peer that sent no ALPN extension has not asked for anything.
- **`EgressOffer(wantH2)` offers both protocols (h2 first), never h2 alone.** A server that does not speak
  h2 aborts the handshake with `no_application_protocol`, so offering h2 alone would fail a scan of an
  HTTP/1.1-only host at the TLS layer instead of running over HTTP/1.1 and reporting the downgrade.
- **`Protocol` is conservative on the unknown case.** `""` and `http/1.1` map to `core.ProtocolHTTP1` with
  no error; `h2` to `ProtocolHTTP2`; anything else returns `ProtocolHTTP1` *and* an error, so a caller that
  ignores the error still gets the safe answer.
- **`Dial` returns the raw wire value, not a `core.Protocol`.** The caller must distinguish "the peer chose
  http/1.1" from "the peer sent no ALPN at all" — `Protocol` collapses both to HTTP/1 — because only one of
  them is a downgrade worth reporting. An empty offer sends no ALPN extension at all.
- **This package does not decide whether a request may be sent.** That gate is
  `sender.AuthorisedSender`'s (HARD-03) and runs before any dial here; `Dialer` has no scope handle and must
  never grow one. h2c is deliberately absent — cleartext HTTP has no ALPN to negotiate.

## Testing Requirements

```bash
go test ./internal/alpn/...
```

## Dependencies

### Internal

- `internal/core` — `core.Protocol`

### External

- stdlib only (`crypto/tls`, `net`, `context`, `time`)

<!-- MANUAL: -->
