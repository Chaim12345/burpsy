<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# cli (`burpsy-cli`)

## Purpose

The `burpsy` binary. It owns all the wiring — one shared `TrafficStore` behind the proxy and the web UI,
so traffic captured by the proxy is immediately available to Repeater and Intruder without copying
bodies between subsystems.

This is the only crate that constructs concrete implementations and hands them to the layers that
declared traits for them. That is deliberate: it keeps `web` independent of `scanner`, and `scanner`
independent of any transport.

## Key Files

| File | Description |
|------|-------------|
| `src/main.rs` | Argument parsing, the `store verify` subcommand, store/CA/scanner/proxy/web wiring, and the `--help` text |

## For AI Agents

### Subcommands are dispatched before logging is initialised

`store verify` is a read-only offline check, and `tracing` lines on stdout would corrupt its report. The
check for `store` happens before `tracing_subscriber` is set up and before flag parsing. Any future
read-only subcommand belongs in the same place.

`store verify` exits **non-zero** when any segment reports a fault, so it is usable in a script rather
than being something a human has to read. Preserve that.

### Flags currently supported

| Flag | Effect |
|------|--------|
| `--proxy HOST:PORT`, `--web HOST:PORT` | Bind addresses (default `127.0.0.1:8080` / `:8081`) |
| `--tls-passthrough PATTERN`, `--tls-passthrough-port PORT`, `--tls-defaults` | TLS passthrough policy |
| `--intercept-tls` | Enable TLS interception; **only then** is CA material loaded or generated |
| `--bchecks DIR` | Load the BCheck corpus and passively scan responses |
| `--scope-include HOST`, `--scope-exclude HOST` | Engagement scope (repeatable) |
| `--ca-dir DIR` | Where CA material lives |
| `--capture-dir DIR`, `--segment-bytes N` | Capture to disk in sealed segments instead of RAM |

Every flag added here needs a matching entry in the `--help` text, which is the only user-facing
documentation of the tool's surface. The existing text explains *why* options exist (why passthrough is
necessary, why coverage is partial, why the segment size is a target rather than a cap) — match that
depth rather than adding a bare one-liner.

### The wiring rules that matter

- **The audit hook builds an `AuthorisedSender`, not a bare transport.** An active audit constructs
  requests, so it is exactly the traffic the chokepoint exists to authorise. If you replace it with a
  raw `NetSender`, the egress scan will not catch you — `sender` is allowed to be used here — but you
  will have removed the scope check from active scanning.
- **No `--scope-*` flag means allow everything.** Narrowing capture must be a deliberate act, not a
  default that silently drops traffic.
- **CA material is written only under `--intercept-tls`.** A plain HTTP session must not leave key
  material on disk it never needed.
- **`--capture-dir` refuses a non-empty capture directory.** There is no startup-recovery path yet, so
  reusing one would overwrite a previous capture.

### Testing Requirements

This crate has no unit tests; it is wiring, and the behaviour is covered by the e2e scripts:

```bash
cargo build -p burpsy-cli
./serve.sh                 # launch locally
./e2e.sh                   # and the other e2e-*.sh suites
cargo run -p burpsy-cli -- store verify <dir>
cargo run -p burpsy-cli -- --help
```

When changing wiring, run `--help` and at least one e2e suite. A wiring regression usually compiles.

## Dependencies

### Internal

- `burpsy-core` — the store, scope
- `burpsy-proxy` — the proxy, CA, TLS policy
- `burpsy-web` — the API and UI
- `burpsy-scanner` — the passive scanner and audit entry points
- `burpsy-sender` — `AuthorisedSender` and `NetSender` for the audit hook

### External

- `tokio` (`#[tokio::main]`), `anyhow`, `serde_json`, `tracing`, `tracing-subscriber` (with `env-filter`)

<!-- MANUAL: -->
