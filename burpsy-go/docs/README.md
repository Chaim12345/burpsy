# burpsy-go — documentation

User- and operator-facing docs for the Go port. Every command in these pages was
run against the real binary and its output verified before publishing; no
aspirational behavior is documented as if it exists.

> **Authorized use only.** burpsy sends real traffic to whatever you point it at.
> Only run it against targets you are explicitly authorized to test, and keep an
> engagement scope declared.

## Start here

- **[QUICKSTART.md](./QUICKSTART.md)** — clone → build → run headless / over SSH,
  including TLS interception, BCheck loading, and the `-tools` allowlist.
- **[JSON-API.md](./JSON-API.md)** — the full HTTP route surface (paths, methods,
  risk classes) for driving burpsy from scripts and agents.
- **[MCP.md](./MCP.md)** — MCP status (not yet shipped) and what drives burpsy
  today.
- **[BCHECK-COVERAGE.md](./BCHECK-COVERAGE.md)** — honest BCheck coverage: parse
  vs. runtime, and how coverage is reported.

## Background / research (deeper, not a getting-started path)

- [BCHECK-RESEARCH.md](./BCHECK-RESEARCH.md), [BCHECK-M2-SEMANTICS.md](./BCHECK-M2-SEMANTICS.md)
- [TLS-RESEARCH.md](./TLS-RESEARCH.md)
- `../gaps.md` — verified Rust-parity gaps and how the corpus was counted.
