<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# oob

## Purpose

An out-of-band (OOB) interaction channel for scanner checks that can only be confirmed by
observing a callback from the target — SSRF / out-of-band resource load, blind SQL injection,
XXE with an external entity, and the three external-service-interaction issues (DNS / HTTP /
SMTP). It drives ProjectDiscovery's official `interactsh-client` binary (Interactsh v1.3.1) as
a subprocess and reads its `-json` output.

There is no matching Rust crate; this is a Go-only capability.

## Key Files

| File | Description |
|------|-------------|
| `client.go` | Everything: `Client` subprocess lifecycle (`NewClient`, `Close`), the `Interaction` decode struct, registration-domain scraping, `Interactions`/`InteractionsFor` polling, and `Deduplicate` |
| `client_test.go` | Unit tests (parsing, dedup, marker filtering) |
| `live_test.go` | Live test against a real OAST server, gated so it is skipped without the binary / network |

## For AI Agents

- **It shells out deliberately rather than importing the library.** Importing
  `interactsh/pkg/client` drags in `pkg/server`/`pkg/storage` — DNS/SMTP/LDAP/FTP servers,
  certmagic/ACME, leveldb, buntdb, bbolt: ~100 modules into a go.mod of 3 direct + 12 indirect.
  Shelling out keeps the wire protocol (RSA-OAEP/AES) upstream's problem at the cost of one runtime
  prerequisite, which `NewClient` reports honestly when absent.
- **The honest-failure contract.** A missing `interactsh-client` on PATH (or `Options.BinaryPath`)
  makes `NewClient` return an error naming what it looked for. A caller MUST surface "no OOB
  channel available" and MUST NOT report a clean result — zero interactions with a working channel
  and zero with no channel are different facts.
- **`RemoteAddress` means different things per protocol.** For `http` it is the real client IP
  (usually the target itself — attributable evidence). For `dns` it is the upstream *resolver*
  (Google/Cloudflare in practice), not the target: a DNS interaction proves the payload domain was
  resolved but cannot prove which host resolved it. Findings built on DNS interactions must not
  claim attribution.
- **Never compare `FullID` exactly.** It carries DNS-0x20 randomised casing, so sibling rows from
  one lookup each differ. Correlate on `UniqueID` (lowercased); `FullID` is evidence display only.
- **`Interaction` field names mirror the binary's `-json` output exactly** (verified against a live
  oast.online capture) so a rename upstream fails loudly at unmarshal rather than silently zeroing a
  field. Do not "tidy" the JSON tags.
- **Poll semantics tolerate the subprocess writing while we read.** `Interactions` skips
  unparseable lines rather than erroring — a half-written trailing line is expected operation, not
  corruption. It raises the scanner token buffer to 1 MiB because raw DNS records exceed the 64 KiB
  default.
- **Always `Deduplicate` before counting.** One DNS lookup legitimately fans out to several
  interactions (a live single nslookup yielded six: A + AAAA from three resolvers); collapsing on
  `(protocol, q-type, remote-address)` prevents over-reporting "how many times my payload fired".
- **Prefix a per-probe marker onto `Domain()`** (e.g. `<marker>. + Domain()`) so `InteractionsFor`
  can separate concurrent checks' callbacks. `Close` is idempotent; the kill-triggered `Wait`
  error is the expected outcome, not a failure.

## Testing Requirements

```bash
go test ./internal/oob/...
```

`live_test.go` reaches a real OAST server and is skipped when the binary or network is unavailable;
the rest run offline.

## Dependencies

No other `internal/` packages are imported — `oob` is a leaf. No external Go module dependencies
either (standard library only: `os/exec`, `bufio`, `regexp`, `encoding/json`). The one real
dependency is the external `interactsh-client` binary at runtime.
