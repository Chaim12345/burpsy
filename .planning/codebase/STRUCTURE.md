# Codebase Structure

**Analysis Date:** 2026-07-27

## Directory Layout

```
burpsy/                             # Cargo workspace root
├── Cargo.toml                      # [workspace] member list + shared dependency versions
├── crates/
│   ├── core/                       # burpsy-core — HTTP message model, store, scope, findings
│   │   ├── src/
│   │   │   ├── lib.rs              # TrafficStore, StoredMessage, MsgId, Span, MessageShape, parse()
│   │   │   ├── edit.rs             # RequestEdit — take apart / reassemble a request for editing
│   │   │   ├── findings.rs         # FindingStore, dedup-at-insertion
│   │   │   ├── scope.rs            # Scope, ScopeRule, RuleKind — authorization rules
│   │   │   └── sitemap.rs          # SiteMap — incremental host/path tree fold
│   │   └── tests/                  # integration tests for the store/edit model
│   ├── proxy/                      # burpsy-proxy — intercepting HTTP(S) proxy
│   │   ├── src/
│   │   │   ├── lib.rs              # run_with(), ProxyConfig, connection handling
│   │   │   ├── tls.rs              # TLS MITM engine (rustls, per-host leaf signing)
│   │   │   ├── tls_policy.rs       # TlsPolicy — passthrough hosts/ports
│   │   │   ├── intercept.rs        # request hold queue for interactive interception
│   │   │   └── sender.rs           # NetSender — blocking, connection-reusing sender for active checks
│   │   ├── examples/intercept_e2e.rs   # end-to-end example driving the real web API (dev-only cycle)
│   │   └── tests/interception.rs   # integration tests for the hold queue, also drives burpsy-web
│   ├── repeater/                   # burpsy-repeater — byte-exact HTTP send engine
│   │   └── src/lib.rs              # Target, send() — raw TCP/TLS, no client-side normalization
│   ├── intruder/                   # burpsy-intruder — insertion points + payload attacks
│   │   └── src/
│   │       ├── lib.rs              # find_points(), InsertionPoint, PointConfig, splicing
│   │       ├── plan.rs             # AttackPlan — lazy, ordinal-derived attack shape
│   │       ├── limit.rs            # RateLimit, in-flight cap
│   │       └── engine.rs           # run(), Attack, AttackReport, bucketed result summary
│   ├── bcheck/                     # burpsy-bcheck — PortSwigger BCheck DSL: lexer → parser → evaluator
│   │   └── src/
│   │       ├── lib.rs              # module docs: milestone status (M1/M2/M3), grammar notes
│   │       ├── lexer.rs            # tokenizer
│   │       ├── parser.rs           # recursive-descent parser → ast
│   │       ├── ast.rs              # AST node types
│   │       ├── eval.rs             # evaluator, Sender trait, EvalError
│   │       ├── funcs.rs            # builtin DSL functions
│   │       ├── insertion.rs        # payload placement into insertion points
│   │       └── bin/conform.rs      # conformance runner vs PortSwigger's own parser jar
│   ├── scanner/                    # burpsy-scanner — passive scan + operator-triggered active audit
│   │   ├── src/
│   │   │   ├── lib.rs              # PassiveScanner: scan()/audit()/audit_session(), LoadReport
│   │   │   ├── audit.rs            # AuditConfig, AuditLedger, ItemBreaker/SessionBreaker, Disposition
│   │   │   ├── catalog.rs          # IssueDefinition lookup (Burp's 183 shipped issue types)
│   │   │   └── catalog_data.rs     # generated catalog data
│   │   └── tools/gen_catalog.py    # script that regenerates catalog_data.rs from the teardown
│   ├── tools/                      # burpsy-tools — pure, I/O-free supporting tools
│   │   └── src/
│   │       ├── lib.rs              # module docs: shared discipline (spans not copies, refuse not mangle)
│   │       ├── decoder.rs          # Decoder — smart/manual encode/decode passes
│   │       ├── comparer.rs         # Comparer — span-based diff
│   │       ├── logger.rs           # Logger — event log with parameterized timestamps
│   │       ├── organizer.rs        # Organizer — saved request/response collections
│   │       └── matchreplace.rs     # match-and-replace Rule, compiled at construction
│   ├── web/                        # burpsy-web — axum JSON API + embedded single-page UI
│   │   └── src/
│   │       ├── lib.rs              # AppState, AuditHook type, router_*() builders, core API handlers, UI HTML
│   │       └── routes/
│   │           ├── mod.rs          # all() — merges every feature router
│   │           ├── intercept.rs    # held-request endpoints (interception)
│   │           ├── sitemap.rs      # site-map tree endpoints
│   │           └── tools.rs        # Decoder/Comparer/Logger/Organizer/match-replace endpoints
│   └── cli/                        # burpsy-cli — the `burpsy` binary
│       └── src/main.rs             # arg parsing, composition root, task spawning
├── docs/                           # project documentation (teardown notes, design docs)
└── .planning/                      # GSD planning artifacts (this directory's parent)
```

## Directory Purposes

**`crates/core/`:**
- Purpose: the one crate every other crate depends on; owns the message store, span model,
  authorization scope, findings, and site-map fold.
- Contains: no I/O, no async — pure data structures and parsing logic.
- Key files: `crates/core/src/lib.rs` (`TrafficStore`, `MsgId`, `Span`), `crates/core/src/scope.rs`
  (`Scope`), `crates/core/src/edit.rs` (`RequestEdit`).

**`crates/proxy/`:**
- Purpose: the intercepting proxy process logic — TLS MITM, passthrough policy, request holding,
  and the outbound sender used by active scanner checks.
- Contains: tokio-based async networking code, rustls/rcgen for TLS.
- Key files: `crates/proxy/src/lib.rs` (`run_with`, `ProxyConfig`), `crates/proxy/src/sender.rs`
  (`NetSender`).

**`crates/bcheck/`:**
- Purpose: a real interpreter for PortSwigger's BCheck scan-check DSL — this is where new BCheck
  language features (functions, insertion-point kinds) get implemented.
- Contains: lexer, recursive-descent parser, AST, evaluator, builtin functions, a conformance binary.
- Key files: `crates/bcheck/src/lexer.rs`, `crates/bcheck/src/parser.rs`, `crates/bcheck/src/eval.rs`.

**`crates/scanner/`:**
- Purpose: load `.bcheck` files, classify them (passive / active / needs-insertion-point /
  needs-Collaborator), run passive scans automatically, and run active audits only on explicit
  operator request, under budgets and circuit breakers.
- Contains: dispatch-scope bookkeeping, audit ledger/breakers, Burp's issue catalog.
- Key files: `crates/scanner/src/lib.rs` (`PassiveScanner`), `crates/scanner/src/audit.rs`.

**`crates/intruder/`:**
- Purpose: discover insertion points in a captured request and run rate-limited, budget-capped
  multi-position attacks (sniper/battering ram/pitchfork/cluster bomb).
- Contains: insertion-point discovery/splicing, the lazy `AttackPlan`, the rate limiter, the attack
  driver/report.
- Key files: `crates/intruder/src/lib.rs`, `crates/intruder/src/plan.rs`,
  `crates/intruder/src/engine.rs`.

**`crates/repeater/`:**
- Purpose: send one HTTP request byte-for-byte as typed, over raw TCP/TLS, deliberately bypassing
  any client-side HTTP normalization.
- Contains: a single small module — `Target`, `send()`.
- Key files: `crates/repeater/src/lib.rs`.

**`crates/tools/`:**
- Purpose: reusable, I/O-free byte/message transformations shared by the proxy, the web UI, and
  tests.
- Contains: Decoder, Comparer, Logger, Organizer, match-and-replace — each independently testable.
- Key files: `crates/tools/src/decoder.rs`, `crates/tools/src/comparer.rs`,
  `crates/tools/src/matchreplace.rs`.

**`crates/web/`:**
- Purpose: expose everything above as a JSON API plus one embedded single-page UI.
- Contains: axum router construction, `AppState`, per-feature route modules.
- Key files: `crates/web/src/lib.rs` (core routes + `AppState` + `AuditHook`),
  `crates/web/src/routes/mod.rs` (feature router merge point).

**`crates/cli/`:**
- Purpose: the actual `burpsy` executable — the only place that imports every subsystem crate and
  wires them together (including the `AuditHook` closure that keeps `burpsy-web` decoupled from the
  scanner/sender).
- Contains: one file, `main.rs`.
- Key files: `crates/cli/src/main.rs`.

## Key File Locations

**Entry Points:**
- `crates/cli/src/main.rs`: process entry point (`#[tokio::main] async fn main`).
- `crates/proxy/src/lib.rs` (`run_with`): proxy listener entry point, spawned as a tokio task.
- `crates/web/src/lib.rs` (`serve_audit`): web/API listener entry point, spawned as a tokio task.

**Configuration:**
- `Cargo.toml` (workspace root): member list, shared dependency versions (`tokio`, `bytes`,
  `anyhow`, `serde`, `parking_lot`, etc.).
- Each `crates/<name>/Cargo.toml`: per-crate dependency list; `[dev-dependencies]` sections
  document deliberate dev-only cycles where present (see `crates/proxy/Cargo.toml`).

**Core Logic:**
- `crates/core/src/lib.rs`: message storage/parsing.
- `crates/scanner/src/lib.rs` + `crates/scanner/src/audit.rs`: scan/audit dispatch and bounding.
- `crates/intruder/src/plan.rs` + `crates/intruder/src/engine.rs`: attack shape and execution.
- `crates/bcheck/src/eval.rs`: BCheck DSL evaluation.

**Testing:**
- Unit tests: `#[cfg(test)] mod tests` blocks inline at the bottom of most `lib.rs`/module files
  (e.g. `crates/scanner/src/lib.rs`, `crates/web/src/lib.rs`).
- Integration tests: `crates/core/tests/`, `crates/proxy/tests/interception.rs`.
- Example-as-test: `crates/proxy/examples/intercept_e2e.rs`.
- Conformance tool: `crates/bcheck/src/bin/conform.rs` (run manually against a `.bcheck` corpus).

## Naming Conventions

**Files:**
- One file per cohesive subsystem concern, named for the concern, not the type (`plan.rs`,
  `limit.rs`, `engine.rs`, `sender.rs`) — not `types.rs`/`utils.rs` catch-alls.
- Crate names on disk are short (`core`, `proxy`, `web`), but the published/linked package name is
  prefixed `burpsy-*` (e.g. `burpsy-core`, `burpsy-scanner`) per `[package] name` in each
  `Cargo.toml`.

**Directories:**
- `crates/<name>/src/` for library code; `crates/<name>/tests/` for integration tests;
  `crates/<name>/examples/` for runnable examples; `crates/<name>/src/bin/` for auxiliary binaries
  (only `bcheck` has one: `conform.rs`).
- `crates/web/src/routes/` — one file per feature area, each exporting a `routes()` function merged
  by `crates/web/src/routes/mod.rs`.

## Where to Add New Code

**New web API endpoint / feature area:**
- Add a new file under `crates/web/src/routes/<feature>.rs` exporting `pub fn routes() -> Router<AppState>`,
  then merge it in `crates/web/src/routes/mod.rs`'s `all()`. Do NOT add routes directly to
  `crates/web/src/lib.rs`'s `router_audit()` unless the endpoint is core (history/message/exchange/
  stats) — that table is intentionally kept small so feature work doesn't collide there.

**New BCheck DSL function or construct:**
- Lexer/grammar changes: `crates/bcheck/src/lexer.rs` and `crates/bcheck/src/parser.rs`/`ast.rs`.
- New builtin function: `crates/bcheck/src/funcs.rs`.
- New evaluation behavior: `crates/bcheck/src/eval.rs`.
- Validate against the corpus with `crates/bcheck/src/bin/conform.rs`.

**New scanner issue-catalog entry or dispatch scope:**
- Catalog data: `crates/scanner/src/catalog_data.rs` (regenerate via
  `crates/scanner/tools/gen_catalog.py` rather than hand-editing).
- Dispatch/bounding logic: `crates/scanner/src/audit.rs`.

**New attack mode or insertion-point kind:**
- Insertion-point kinds/splicing: `crates/intruder/src/lib.rs`.
- Attack shape/ordinal math: `crates/intruder/src/plan.rs`.
- Execution/reporting: `crates/intruder/src/engine.rs`.

**New supporting tool (Decoder/Comparer/etc. sibling):**
- Add a new I/O-free module under `crates/tools/src/`, keep it free of clock/filesystem/socket
  access (pass timestamps as parameters, per the crate's stated discipline), then expose it via a
  new `crates/web/src/routes/tools.rs` handler or a new route file.

**Shared/cross-cutting data model changes (new message metadata, new span kind):**
- `crates/core/src/lib.rs` (`MessageShape`, `HeaderSpan`) or `crates/core/src/edit.rs`
  (`RequestEdit`) — remember every consumer (repeater, intruder, bcheck, scanner) expects spans,
  not copied bytes.

## Special Directories

**`docs/`:**
- Purpose: project documentation (teardown analysis, design notes).
- Generated: No.
- Committed: Yes.

**`.planning/`:**
- Purpose: GSD workflow state — roadmap, phase plans, and (this file's parent) codebase maps.
- Generated: Partially — codebase docs are regenerated by `/gsd-map-codebase`.
- Committed: Yes (workflow convention; verify against this repo's `.gitignore` before assuming).

**`target/`:**
- Purpose: Cargo build output.
- Generated: Yes.
- Committed: No.

**`crates/scanner/tools/`:**
- Purpose: a Python helper (`gen_catalog.py`) that regenerates `catalog_data.rs` from the Burp
  teardown data — not a Rust crate despite living under `crates/`.
- Generated output: `crates/scanner/src/catalog_data.rs` is generated; the script itself is
  hand-written and committed.

---

*Structure analysis: 2026-07-27*
