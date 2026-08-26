<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-17 | Updated: 2026-08-17 -->

# internal

## Purpose

The engine: 32 packages under a single Go module, playing the role the 13 Rust crates play in
`../../crates/`. There are no Cargo-style manifest boundaries here — the split is enforced by Go's
package graph and by convention — but the same rule holds: `core` owns the store and knows nothing
about networks, `bcheck` is a pure interpreter with no transport, and `sender` is the only package
that opens a socket for a constructed request. A package boundary here is a statement about what a
component is *not* allowed to reach, same as on the Rust side.

## Package index

| Package | Purpose |
|---------|---------|
| [`core/`](core/AGENTS.md) | HTTP message model (span-based parsing), the append-only position-is-the-id `TrafficStore` with disk-backed segments, engagement scope, findings, request editing, WebSocket framing. The dependency-free root every other package holds |
| [`bcheck/`](bcheck/AGENTS.md) | Parser and evaluator for PortSwigger's BCheck DSL: lexer, recursive-descent parser, shared passive/active evaluators, insertion-point enumeration |
| [`scanner/`](scanner/AGENTS.md) | Passive BCheck scanning, the active audit engine, and Burp's transcribed 183-issue catalog; work is bounded at a counted admission gate, never by silently discarding it |
| [`sender/`](sender/AGENTS.md) | The one authorising path from a constructed request to a socket — `AuthorisedSender` checks scope against the actual rendered bytes before every dial |
| [`proxy/`](proxy/AGENTS.md) | The intercepting HTTP/HTTPS proxy: MITM termination, capture, HTTP/2 and WebSocket relay, held requests/responses |
| [`intercept/`](intercept/AGENTS.md) | The request/response hold queue behind interactive interception (off / unconditional / selective rule lists) |
| [`tlsprobe/`](tlsprobe/AGENTS.md) | Wraps the external `tlsx` CLI for TLS certificate/cipher/protocol defect scanning, keeping "found nothing" distinct from "could not look" |
| [`alpn/`](alpn/AGENTS.md) | The single shared vocabulary for HTTP-version negotiation over TLS (offer filtering, wire-value mapping, dialing), so the proxy and sender legs cannot drift |
| [`http2/`](http2/AGENTS.md) | Sockets-free, pure-byte HTTP/2 framing/HPACK/malformed-frame authoring for smuggling research |
| [`intruder/`](intruder/AGENTS.md) | Insertion-point discovery and payload attacks (sniper/battering ram/pitchfork/cluster bomb), bucketing responses instead of retaining bodies |
| [`sequencer/`](sequencer/AGENTS.md) | Statistical randomness analysis of session tokens: per-position Shannon entropy plus the FIPS 140-2 bit-level battery |
| [`crawler/`](crawler/AGENTS.md) | Breadth-first application discovery from seed URLs, routed through the same scope-authorised sender as proxied traffic; no Rust counterpart |
| [`sitemap/`](sitemap/AGENTS.md) | Aggregates recorded exchanges into a host → path → method/status tree for the web UI, kept current via a store observer |
| [`domexec/`](domexec/AGENTS.md) | Headless-Chrome (chromedp) DOM taint harness: plants a canary, reports every instrumented sink it reaches at runtime |
| [`jsexec/`](jsexec/AGENTS.md) | DOM-less pure-Go JavaScript tier (goja) for prototype-pollution probing when Chrome is absent — not a browser substitute |
| [`oob/`](oob/AGENTS.md) | Out-of-band interaction channel via `interactsh-client`, confirming callback-only vulnerabilities (SSRF, blind SQLi, XXE) |
| [`blindxss/`](blindxss/AGENTS.md) | Blind-XSS callback channel: owns an HTTP listener serving a bounded capture script at a token-carrying path, so a payload rendered where the scanner cannot look calls home with its page context. Sibling of `oob`, same mint-plant-poll shape |
| [`extscan/`](extscan/AGENTS.md) | Delegates a scan phase to the external `ffuf` (content discovery) and `nuclei` (template corpus) binaries, gated on the operator's allowlist and an up-front whole-subtree scope decision, and renders both into ordinary `report.Row`s |
| [`tools/`](tools/AGENTS.md) | Pure byte/string transforms — Decoder, Hasher, budgeted Comparer — reused by intruder, proxy and the UI; no I/O |
| [`matchreplace/`](matchreplace/AGENTS.md) | Ordered regex/literal rewrite rules over proxied requests/responses, Burp-compatible rule types |
| [`organizer/`](organizer/AGENTS.md) | Ephemeral in-memory shortlist of saved exchanges, shared by web and CLI, never persisted |
| [`query/`](query/AGENTS.md) | A closed, typed filter grammar over captured traffic, type-checked at parse time against the `Queryable` interface |
| [`report/`](report/AGENTS.md) | Renders scan findings to JSON, SARIF 2.1.0, and self-contained HTML |
| [`session/`](session/AGENTS.md) | Recorded-login re-authentication policy: scoped rules and login macros with bounded single-flight retry |
| [`persist/`](persist/AGENTS.md) | The SQLite write-through mirror of the authoritative in-memory stores (history, findings, scope, rules) |
| [`advisory/`](advisory/AGENTS.md) | The issue-definition catalogue: Burp's 183 knowledge-base entries turning a finding's name into remediation text |
| [`dash/`](dash/AGENTS.md) | The dashboard's shared vocabulary and runtime state — honest counts, an observe-only task registry, a bounded event log |
| [`vulnapp/`](vulnapp/AGENTS.md) | A deliberately vulnerable in-process app plus a manifest pairing each endpoint with the catalog row it should trigger |
| [`web/`](web/AGENTS.md) | The JSON API and the embedded React single-page UI |
| `httputil/` | Shared HTTP/1.x framing helpers (`ReadHTTPResponse`, chunked/Content-Length aware) used by `proxy` and `sender`. Single file — no `AGENTS.md` of its own; see below |
| `upstream/` | The one place that decides which upstream proxy (HTTP/HTTPS CONNECT, SOCKS4/4a/5) carries an egress connection, and the one place that dials it. Ordered host-pattern rules with a default; held by reference so `sender` and `proxy` share one policy and a live edit reaches both. Refuses an unparseable proxy URL rather than falling back to a direct dial. Single file plus `upstreamtest/` — no `AGENTS.md` of its own; see below |
| `toollog/` | Records every request burpsy's tools (Repeater, Intruder, Scanner, Sequencer, Comparer, Session, Decoder, Crawler) sent, kept separate from proxy history. Single file — no `AGENTS.md` of its own; see below |

`httputil`, `toollog` and `upstream` are single-file packages, covered here rather than with their own
`AGENTS.md` (`upstream`'s package comment carries its own rationale at length; `upstream/upstreamtest`
is its in-process proxy harness, used by `upstream`, `sender` and `proxy` so the three cannot diverge
in what they consider a proxied egress) — the same "one per meaningful unit, don't dilute with boilerplate" rule the Rust
`crates/` hierarchy follows for its own trivial directories.

## For AI Agents

### Working in this directory

**Adding a package** is just adding the directory under `internal/` — Go's build discovers it from
imports, there is no members list to edit (unlike the Rust workspace's `Cargo.toml`).

**Check the dependency direction before adding an edge.** `core` depends on no other `internal/`
package and must stay that way — it is the one thing every other package holds, and giving it a
network or parser dependency would make the memory model untestable in isolation. Nothing but
`web` and `cmd/burpsy` should reach into `proxy`.

**Anything that opens a socket for a constructed request belongs in `sender/`.** The Rust side
enforces this with a source-scanning test (`crates/sender/tests/no_alternate_egress.rs`); the Go
side has no equivalent scanner yet, so this is enforced by review discipline only — a gap worth
closing if a new package is tempted to dial out on its own.

### Testing Requirements

Per package during development, whole tree before claiming done:

```bash
go test ./internal/<pkg>/...
go test ./...
```

### Common Patterns

- Several packages deliberately refuse capabilities they could easily have, mirroring the Rust
  crates they port: `bcheck` has no transport, `tools` has no clock or filesystem. Those refusals
  are load-bearing — do not "fix" them.
- Honest counting shows up as a *type*, not just a convention: `dash`'s `Breakdown`/`Summary` have
  no "total" field, `crawler`'s reports exhaustively partition every skip reason, and `scanner`'s
  coverage types keep "declined" and "runnable" separate rather than collapsing to one count.

## Dependencies

### Internal

`core` is the root; `sender` is the one egress path; most other packages sit between them. See each
package's own `AGENTS.md` for its specific edges, and `../AGENTS.md` for how this mirrors the Rust
crate spine.

### External

Declared once in `../go.mod`. Notable non-stdlib dependencies and the package that owns each:
`golang.org/x/net/http2` (`http2`, `sender`), `golang.org/x/net/proxy` (`upstream`'s SOCKS5 dial), `chromedp`/`cdproto` (`domexec`), `dop251/goja`
(`jsexec`), `PuerkitoBio/goquery` (`crawler`), `projectdiscovery/wappalyzergo` (`crawler`/`advisory`),
`modernc.org/sqlite` (`persist`), `mvdan.cc/sh` (`bcheck`'s `run tool`), `go.uber.org/zap` (logging,
used broadly).

<!-- MANUAL: -->
