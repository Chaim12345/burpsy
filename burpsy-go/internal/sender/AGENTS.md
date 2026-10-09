<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# sender

## Purpose

The one authorising path from a constructed request to a socket. `AuthorisedSender` checks a
`ScopeChecker` against the **actual outbound bytes** — the rendered request line, not the target
string the operator typed — and only then reaches the transport it wraps. This is the sender half of
the intruder guarantee: a payload spliced into a path position can rewrite the request line, so only
the bytes about to be written can be trusted.

Ports the Rust `burpsy-sender` contract: the scope handle is bound at construction, every send is
checked individually, a refusal is counted and returned as the send's error, and the transport is
never reached on refusal.

## Key Files

| File | Description |
|------|-------------|
| `sender.go` | `Sender`, `SenderConfig`, `NewSender` — the raw transport over `net/http`. The transport never follows 30x and there is still no knob to make it; `ProxyURL` is explicit, never `$HTTP_PROXY`. `Network`/`ApplyNetwork` are the live settings surface, and `mu` guards `client`/`config`/`net` as one decision |
| `network.go` | `NetworkSettings` — the one named surface for resolution overrides, DNS lookup policy, the three timeouts, redirect policy, 100-continue and open-ended responses. `Validate` refuses; `Normalise` is what both the API and persistence read through |
| `read.go` | `readResponse` — reads one *final* response: skips interim 1xx (never 101), and for a declared streaming host returns what arrived instead of the deadline error |
| `redirect.go` | `FollowRedirects` — the opt-in redirect follower. Every hop is a fresh `AuthorisedSender` bound to the new authority |
| `authorised.go` | `AuthorisedSender`, `ScopeChecker`, `AuthorisedResult`. `Send`(raw) and `SendRequest`(*Request) both run `AuthoriseRaw` on the request line before the dial and feed the same `Sent`/`Refused` counters |
| `protocol.go` | ALPN/protocol negotiation, downgrade and rewrite reporting, and the per-`Sender` `ProtocolCache`. `planH2` decides whether raw HTTP/1 bytes can be carried as HTTP/2 |
| `pipeline.go` | `SendPipelined`, `SendKeepAlive`, `TimedRead` — HTTP/1.1-only single-socket sends for request-smuggling / desync probes. `dialOne` offers only HTTP/1.1 on TLS so h2 cannot silently turn a probe into a no-op |
| `h2.go` | `h2Request` — minimal h2 request extracted from raw bytes and rendered for a single h2 exchange |
| `sendopts.go` | `SendOptions`, `WithSendOptions` — per-send overrides carried on the context. `ResponseTimeout` replaces the network read bound for one send, clamped to an earlier context deadline; `setDeadline` reads it, so `NetworkSettings` is never mutated per send (mmca) |
| `connpool.go` | `ConnPool`, `AuthorisedSender.SendReusing` — HTTP/1 connection reuse for a stream of independent sends (Intruder's "HTTP/1 connection reuse", xhqr). Live connections bounded at the pool's max; a connection is reused only after a cleanly delimited, non-`Connection: close`, HTTP/1.1, final response; h2 is never pooled |
| `h2program.go` | `SendFrameProgram` — authorises and sends an `http2.H2FrameProgram`, gating per-request or host-only depending on what the program can be decided to address |

## For AI Agents

- **The scope check is on rendered bytes, before the dial.** `AuthoriseRaw(host, port, isTLS, raw)`
  runs on the request line actually about to be written. A redirect to another authority is not
  followed and a request naming a different authority than the sender is bound to is refused — the
  tests `TestARedirectToAnotherAuthorityIsNotFollowed` and
  `TestSendRequestRefusesARequestNamingAnotherAuthority` pin this.
- **Refusal counters describe traffic decisions, not transport failures.** `Refused` covers scope,
  readability and wrong-authority refusals; a request that cleared scope but failed at the transport
  is neither `Sent` nor `Refused` and is reported by the caller. Counters are `atomic.Int64` so one
  `AuthorisedSender` is safe to share across concurrent callers (`TestConcurrentSendsDoNotLoseCounters`).
- **Redirects: still no knob *in the transport*, and that is the load-bearing half.** `NewSender`'s
  transport does not follow 30x and there is no config field to switch it on, because a follow inside
  the transport would dial the next hop with no scope gate. What `redirect.go` adds is the opposite
  construction, not a reversal: `AuthorisedSender.FollowRedirects` builds a fresh `AuthorisedSender`
  bound to each new authority, so every hop is authorised on the same terms as a first request. There
  is no path through it that reaches a socket without `AuthoriseRaw` — which is the only reason
  following can be offered at all. It is off by default (`RedirectNever`), because a 30x *is* the
  response: an operator auditing a login flow needs the redirect and its `Set-Cookie`, following
  multiplies traffic at the client's expense, and a redirect to an error page reads as a clean 200.
  `RedirectAlways` does **not** mean "unauthorised" — it means "apply no extra on-site or scope-shaped
  filter of my own", and the scope still decides. `TestAnOutOfScopeRedirectHopIsRefusedRatherThanFollowed`
  pins that, counting arrivals on a second listener rather than trusting a struct field.
- **Network settings are live and shared.** `ApplyNetwork` validates and applies as a unit — never half
  a document — and rebuilds the typed path's `http.Client`, because `http.Transport` reads its timeouts
  when a connection is established rather than per request. `cmd/burpsy` builds **one** `Sender` for the
  scanner and the web server: two would mean a resolution override an operator typed applied to Repeater
  and not to audit probes. The hostname-resolution table changes only the **address** dialled; SNI and
  the `Host` header keep the operator's name, which is why `alpn.Dialer.Dial` takes `serverName` and
  `addr` separately. `/api/network/settings` is the endpoint, and it persists via `internal/persist`'s
  `settings` table under `network.settings`.
- **`ProxyURL` is explicit egress only.** The transport does not carry `http.ProxyFromEnvironment`;
  an ambient `$HTTP_PROXY` must not silently re-route attack traffic through an un-scoped third party.
- **Pipelining is HTTP/1.1 only, on purpose.** `dialOne` offers `alpn.EgressOffer(false)` because
  keep-alive/pipelining desync is an HTTP/1.1 property; h2 multiplexes independent streams so there is
  no framing disagreement to observe. `SendPipelined` returns one `PipelinedExchange` per input raw
  in order even on partial write/read failure — a failed request gets its own `ReadErr`, never a
  silent drop; the error return is only for a dial failure before any exchange was attempted.
- **`classifyFraming`/`readFramedResponse` name the framing rule but do not reimplement the reader.**
  Body reading goes through `httputil.ReadResponseHead`/`ReadResponseBody` (the same capped reader the
  rest of the package trusts); a body read that fails returns the head bytes, `complete=false` and an
  error — never a truncated or guessed body.
- **Frame-program authorisation is stricter than request authorisation.** `SendFrameProgram` falls
  back to host-level authorisation (`authoriseHostOnly`) when a program cannot be decided to address a
  request; an undecidable program never reaches the target
  (`TestAnUndecidableProgramNeverReachesTheTarget`).

## Testing Requirements

```bash
go test ./internal/sender/...
```

Tests use `127.0.0.1` and local listeners; avoid hostnames that cost a real resolver timeout.

## Dependencies

### Internal

- `internal/core` — `Scope`/`SharedScope` satisfy `ScopeChecker` (used by `protocol.go` directly)
- `internal/http2` — `H2FrameProgram`, `ProgramRequest`, and the frame vocabulary for `h2program.go`
- `internal/alpn` — the egress ALPN offer shared across the TLS dials
- `internal/httputil` — the capped response head/body readers

### External

- `net/http`, `crypto/tls` — the standard-library transport (`ForceAttemptHTTP2`, no proxy-from-env)
