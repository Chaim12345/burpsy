# External Integrations

**Analysis Date:** 2026-07-27

## Framing

burpsy is a security-testing tool (intercepting proxy, scanner, Repeater, Intruder), not a
service with a backend of its own. There is **no database, no auth provider, no webhook
receiver, and no SaaS API client** in the conventional sense — a naive scan for those finds
nothing. The integrations that actually matter here are: (1) a runtime-loaded, file-based
knowledge corpus that drives the scanner, (2) an offline reference corpus that a code
generator mechanically transcribes into source, and (3) the outbound network targets this
tool itself attacks, which are access-controlled by an in-process scope engine. Each is
documented below in place of the standard "no integrations found."

## Runtime-Loaded External Corpus: BChecks (`/tmp/BChecks`)

- **What it is:** PortSwigger's published BCheck corpus — 264 `.bcheck` definition files (plus
  a checker jar, docs, and examples) at `/tmp/BChecks`, of which `/tmp/BChecks/examples` and
  other subdirectories hold the actual check bodies.
- **How it's consumed at runtime:** the `burpsy` CLI binary accepts `--bchecks <dir>`
  (`crates/cli/src/main.rs`), which points the scanner at a directory of BCheck files to load
  and execute against captured traffic. This is a genuine runtime dependency surface — if the
  directory is malformed or a BCheck can't be parsed, the scanner's active checks are affected.
- **How it's consumed by the test suite:** `verify.sh`'s "BCheck corpus conformance" step
  (final section of the script) treats `/tmp/BChecks` as a **conformance oracle**: it runs
  `cargo run -q --bin conform` (a binary defined somewhere under `crates/`) against the corpus
  and asserts (a) 0 parse failures across all corpus files, and (b) at least 381 modifier
  clauses are captured across the corpus — a regression in that count means the parser started
  silently discarding request mutations. If `/tmp/BChecks` is absent, this step is skipped and
  marked passing rather than failing — the corpus is optional for local dev but load-bearing
  for the "verified good" bar when present.
- **Implementation surface:** `crates/bcheck/` is the crate that parses and executes `.bcheck`
  syntax; `crates/bcheck/src/funcs.rs` implements the BCheck function library (`to_lower`,
  `base64_decode`, etc.) that check bodies call into. `generate_collaborator_address` (function
  id 54 in Burp's numbering, per a comment near line 14 of `funcs.rs`) is deliberately **not**
  implemented — there is no Burp Collaborator (out-of-band interaction) integration in this
  project.

## Offline Reference Corpus: burp-re Teardown (`/root/burp-re/`)

- **What it is:** a decompiled teardown of the shipped Burp Suite 2026.7.1 jar
  (`burp-2026.7.1-teardown-20260726.tar.zst`), living outside this repo at `/root/burp-re/`.
  It includes `docs/`, `FINDINGS.md`, `SCAN_ENGINE.md`, `SCANNER_MAP.md`,
  `UI_BACKEND_MAP.md`, and — most operationally relevant — `out/scanner_spec/issues/`, which
  holds **366 issue-definition JSON files** extracted from Burp's shipped KnowledgeBase.
- **How it's consumed:** `crates/scanner/tools/gen_catalog.py` is a one-shot Python generator
  that reads `/root/burp-re/out/scanner_spec/issues/` (path hardcoded as `SRC` at line 21 of
  that script) and mechanically transcribes each issue definition into Rust source at
  `crates/scanner/src/catalog_data.rs` (currently ~3,705 lines, generated, not hand-authored).
  Regeneration command, per the script's own header comment:
  `python3 crates/scanner/tools/gen_catalog.py crates/scanner/src/catalog_data.rs`.
- **Nature of the dependency:** this is a **build-time / maintenance-time** dependency, not a
  runtime one — `catalog_data.rs` is committed, so a normal `cargo build`/`cargo test` does not
  need `/root/burp-re/` to exist. It only matters when someone needs to regenerate the scanner's
  issue catalog after a new Burp teardown, e.g. to pick up new/changed issue definitions.
- **Directional note:** issue count in the teardown (366 JSON files) and the count referenced
  in `gen_catalog.py`'s own docstring (183) differ from each other and from BCheck corpus
  counts; treat the live `out/scanner_spec/issues/` listing as authoritative if reconciling.

## Outbound Attack Targets (the real "external API" of this tool)

- **What it is:** the arbitrary HTTP(S) hosts that burpsy's proxy, Repeater, and Intruder send
  traffic to/through on behalf of the operator — i.e., the systems under test. These are the
  closest thing this project has to "external services it talks to," and access to them is
  gated, not open-ended.
- **Access control:** `crates/core/src/scope.rs` implements an explicit, ordered scope-rule
  engine (`ScopeRule` — include/exclude, matched on host/port/path-prefix/TLS-ness, last-match-
  wins, default-deny when no rules are set). Its doc comment explains the rationale: scope is
  "the machine-readable form of 'what am I allowed to attack'," enforced in **two independent
  places** — the proxy (deciding what gets captured/stored) and every outbound attack path
  (Repeater, Intruder, and eventually the scanner), each of which independently refuses a
  target not in scope. The doc comment also notes that in Burp's own agentic tool registry,
  `add_to_scope` is one of only four tools marked `ALWAYS_ESCALATE` out of 54 — widening scope
  is treated as the single privileged, auditable operation in the whole system.
- **Configuration:** scope is set via CLI flags `--scope-include <host>` / `--scope-exclude
  <host>` in `crates/cli/src/main.rs`, and exposed read-only via the web API at
  `GET /api/scope` (`crates/web/src/lib.rs`).
- **TLS interception:** to observe HTTPS traffic to these targets, the proxy dynamically
  generates a CA and per-host leaf certificates via `rcgen` and terminates/re-establishes TLS
  using `rustls`/`tokio-rustls` (`crates/proxy/`). The generated CA certificate is exposed over
  the web UI at `GET /ca.crt` for the operator to trust (`crates/web/src/lib.rs`), and
  `--tls-passthrough` / `--tls-passthrough-port` / `--tls-defaults` flags let specific
  hosts/ports bypass interception (e.g., for pinned or opaque traffic).

## Local Web/API Surface (self-hosted, not third-party)

This is the tool's own control surface, not an external integration, but is the closest thing
to a conventional "API" in the repo — served by `axum` in `crates/web/src/lib.rs`:
- `GET /ca.crt` — download the proxy's generated CA certificate.
- `GET /` — UI index.
- `GET /api/stats`, `GET /api/history`, `GET /api/message/{id}`, `GET /api/exchange/{id}` —
  captured-traffic inspection.
- `POST /api/repeater/send` — Repeater.
- `POST /api/intruder/points`, `POST /api/intruder/run` — Intruder.
- `GET /api/scope` — read current scope rules.
- `GET /api/issues`, `POST /api/audit/{id}` — scanner findings and triggering an audit run.

Default bind: `127.0.0.1:8081` (web), `127.0.0.1:8080` (proxy) — both loopback-only by
default, per `crates/cli/src/main.rs`; no auth layer is present on this local API.

## Data Storage

**Databases:** None. State (captured HTTP traffic, scan issues) lives in-process in a shared
`TrafficStore` (`burpsy_core::TrafficStore`, constructed once in `crates/cli/src/main.rs` and
passed to both the proxy and the web server) — no persistence to disk or external DB detected.

**File Storage:** Local filesystem only — the CA/cert directory (`--ca-dir`, default via
`burpsy_proxy::default_ca_dir()`) and, at runtime, the optional `--bchecks` directory described
above.

**Caching:** None detected.

## Authentication & Identity

None. There is no auth provider, no login flow, and no token-based access to the local web
API. Access control in this codebase is entirely about **scope** (which network targets the
tool is allowed to attack), described above — not about authenticating users of the tool.

## Monitoring & Observability

**Error Tracking:** None (no Sentry/Bugsnag-style integration).

**Logs:** `tracing` + `tracing-subscriber`, configured via `EnvFilter` (defaults to `"info"`)
in `crates/cli/src/main.rs`; no external log sink.

## CI/CD & Deployment

**Hosting:** None — single local binary, no cloud deployment target found (`find . -name
"*.yml" -o -name "*.yaml"` returns no CI workfiles in this repo).

**CI Pipeline:** None detected (no `.github/workflows`, no other CI config). Local
equivalent is `verify.sh`, invoked directly and by `integrate.sh` after every branch merge.

## Environment Configuration

**Required env vars:** None strictly required; `RUST_LOG` optionally controls tracing
verbosity (falls back to `"info"`).

**Secrets location:** None present — no `.env*` files exist in the repository.

## Webhooks & Callbacks

**Incoming:** None.

**Outgoing:** None (notably: Burp's own `generate_collaborator_address` BCheck function,
which would enable out-of-band/webhook-style interaction testing, is explicitly not
implemented — see `crates/bcheck/src/funcs.rs`).

---

*Integration audit: 2026-07-27*
</content>
