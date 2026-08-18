<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# tlsprobe

## Purpose

A wrapper around the external `tlsx` CLI for TLS certificate and cipher analysis. It runs `tlsx` against
a set of targets, parses its JSONL output into typed `Host` records, and exposes the discriminators the
scanner's "TLS certificate" and weak-cipher/deprecated-protocol catalog rows need. `zcrypto` was
evaluated and rejected — its current release refuses SSLv3 client-side and will not negotiate RC4 or
export-grade DH, the only capabilities it had over stdlib `crypto/tls`; `tlsx` reaches those through its
openssl backend and additionally classifies cipher strength per TLS version. There is no Rust crate
counterpart.

## Key Files

| File | Description |
|------|-------------|
| `tlsprobe.go` | The whole package: `Probe` (build argv, run `tlsx`, parse), `Available`, `Options`, `Result`, the `Outcome` enum, `Host`/`CipherSet`/`Ciphers` records, and the `Host` accessors `HasCertificateDefect`/`WeakCiphers`/`DeprecatedProtocols` |
| `tlsprobe_test.go` | Unit tests for JSONL parsing and the record accessors |
| `tlsprobe_live_test.go` | Live test that actually invokes `tlsx` (needs the binary on PATH) |

## For AI Agents

- **`Outcome` keeps "found nothing" separate from "could not look."** `OutcomeNotInvoked` (empty target
  list), `OutcomeUnavailable` (binary not on PATH), `OutcomeFailed`, and `OutcomeCompleted` are distinct so
  a missing binary or a timeout can never read as a clean TLS result. An empty target list returns
  `OutcomeNotInvoked` with an error, not a completed empty scan — this is the project's honest-counting
  value in miniature.
- **A non-zero `tlsx` exit with usable records is still a completed result.** `tlsx` exits non-zero when
  *some* targets fail; `Probe` only refuses (`OutcomeFailed`) when **nothing** parsed. So partial output is
  returned as `OutcomeCompleted` with whatever hosts parsed.
- **`Result.Command` records the exact argv executed.** It exists for the provenance line a delegated
  check must record — `Probe` sets it even on failure.
- **Timeout defaults branch on `EnumerateCiphers`.** Per-suite enumeration is slow (a single host took
  ~200s in testing), so it gets `DefaultCipherEnumTimeout` (6 min) versus `DefaultTimeout` (30s); an
  explicit `Options.Timeout` overrides both. Output is capped at `maxOutputBytes` (8 MiB).
- **Parsing is line-oriented and skips non-JSON lines.** `parseJSONL` ignores blank lines and lines not
  starting with `{` (tlsx banner/log noise), but a line that starts with `{` and fails to unmarshal is a
  hard error — refuse-by-default on unparseable input.
- **`Host` maps only the fields the scanner reads.** `WeakCiphers` flattens weak *and* insecure suites
  across every enumerated version as `version:cipher`; `DeprecatedProtocols` lists `ssl30`/`tls10`/`tls11`;
  `HasCertificateDefect` is the OR of expired/self-signed/mismatched/revoked/untrusted.

## Testing Requirements

```bash
go test ./internal/tlsprobe/...
```

The live test (`tlsprobe_live_test.go`) needs the `tlsx` binary on PATH; it is skipped otherwise.

## Dependencies

### Internal

- None.

### External

- The external `tlsx` binary (ProjectDiscovery) at run time — invoked via `os/exec`, not linked.
- stdlib only otherwise (`encoding/json`, `bufio`, `bytes`, `context`, `os/exec`, `time`)

<!-- MANUAL: -->
