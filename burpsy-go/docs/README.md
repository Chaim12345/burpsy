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

## Coverage — honestly counted

- **[BCHECK-COVERAGE.md](./BCHECK-COVERAGE.md)** — BCheck coverage: parse
  conformance vs. runtime coverage, and how coverage is reported.
- **[SCANNER-COVERAGE.md](./SCANNER-COVERAGE.md)** — the 183-issue Burp catalog:
  which rows are runnable, which are declined, and why.
- **[SCANNER-INFRA.md](./SCANNER-INFRA.md)** — the capability primitives behind
  the catalog checks and the wiring that sits on them.
- **[SCANNER-INFRA-ROADMAP.md](./SCANNER-INFRA-ROADMAP.md)** — a plan, not a
  claim: capability gaps and the Go libraries that would close them.

## Reference / design

- **[DATA-MODEL.md](./DATA-MODEL.md)** — the entities, how they are identified,
  and the identity hazard the type design exists to prevent.
- **[HANDOFF-2026-08-13.md](./HANDOFF-2026-08-13.md)** — the latest dated work
  handoff (scanner coverage measurement rebuilt on runtime evidence).
- `../gaps.md` — the source-verified Rust-parity ledger and how the corpus was
  counted.
- `../PORT_STATUS.md` — recent verified work and where to read live status.

## Research (deeper background, not a getting-started path)

- **[RESEARCH-BRIEF-GO-TOOLING.md](./RESEARCH-BRIEF-GO-TOOLING.md)** — a
  self-contained brief on Go libraries for a web-app security scanner.
- `research-java/` — the Burp 2026.7.1 teardown notes the specification is
  derived from (scan engine, scanner map, UI/backend maps, component reports).
- `ui-map/` — the UI surface map and UAT scripts for the React web UI.
- `plans/` — dated port plans (e.g. the ghauri SQLi port).
