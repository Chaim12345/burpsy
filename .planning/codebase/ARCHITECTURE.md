<!-- refreshed: 2026-07-27 -->
# Architecture

**Analysis Date:** 2026-07-27

## System Overview

burpsy is a Rust reimplementation of the core of Burp Suite (built from a teardown of the shipped
Burp 2026.7.1 jar), organized as a Cargo workspace of 9 crates under `crates/`. Everything is wired
together by one binary, `crates/cli/src/main.rs`, which starts an intercepting proxy and a web UI
as two tokio tasks sharing one `TrafficStore`.

```text
┌───────────────────────────────────────────────────────────────────────────┐
│  crates/cli/src/main.rs  — composition root: parses args, builds          │
│  TrafficStore/Scope/TlsPolicy/PassiveScanner, spawns proxy + web tasks     │
└───────────────┬───────────────────────────────────┬───────────────────────┘
                │                                    │
                ▼                                    ▼
┌───────────────────────────────┐   ┌───────────────────────────────────────┐
│  burpsy-proxy                 │   │  burpsy-web                           │
│  `crates/proxy/src/`          │   │  `crates/web/src/`                    │
│  Intercepting HTTP(S) proxy,  │   │  axum JSON API + single-page UI.      │
│  TLS engine, hold queue,      │   │  Routes split per feature:            │
│  NetSender for active probes  │   │  `crates/web/src/routes/{intercept,   │
│  (`sender.rs`)                │   │   sitemap,tools}.rs`                  │
└───────────┬───────────┬───────┘   └──────┬──────┬──────┬──────┬──────────┘
            │           │                  │      │      │      │
            ▼           ▼                  ▼      ▼      ▼      ▼
   ┌────────────┐  ┌──────────┐    ┌──────────┐┌────────┐┌───────┐┌────────┐
   │burpsy-      │  │burpsy-   │    │burpsy-   ││burpsy- ││burpsy-││burpsy- │
   │scanner      │  │bcheck    │    │repeater  ││intruder││tools  ││core    │
   │(passive scan│  │(DSL:     │    │(byte-    ││(attack ││(Decoder│(store, │
   │ + active    │  │lexer/    │    │exact HTTP││engine, ││Compare │findings│
   │ audit)      │  │parser/   │    │sender)   ││plan)   ││Logger..││scope,  │
   │             │  │eval)     │    │          ││        ││)       ││sitemap)│
   └──────┬──────┘  └────┬─────┘    └────┬─────┘└───┬────┘└───┬────┘└───┬────┘
          └──────────────┴────────────────┴──────────┴─────────┴────────┘
                                    all depend on burpsy-core
```

## Component Responsibilities

| Component | Responsibility | File |
|-----------|----------------|------|
| Composition root | Parses CLI flags, builds `TrafficStore`/`Scope`/`TlsPolicy`, wires the `AuditHook` closure, spawns proxy + web tasks | `crates/cli/src/main.rs` |
| Traffic store | Append-only log of raw message bytes + span-based parse; the one place bodies are copied | `crates/core/src/lib.rs` |
| Request editing | Take apart / reassemble a captured request (Content-Length, chunked decode, absolute-form) | `crates/core/src/edit.rs` |
| Findings storage | Deduplicated finding store, merged at insertion time | `crates/core/src/findings.rs` |
| Scope | Authorization rules: what may be captured/attacked | `crates/core/src/scope.rs` |
| Site map | Host→path tree, incrementally folded from the store | `crates/core/src/sitemap.rs` |
| Proxy | Intercepting HTTP(S) proxy, TLS MITM engine, hold-queue interception, TLS passthrough policy | `crates/proxy/src/lib.rs`, `crates/proxy/src/tls.rs`, `crates/proxy/src/tls_policy.rs`, `crates/proxy/src/intercept.rs` |
| Outbound sender | Blocking connection-reuse HTTP sender used by active scanner checks | `crates/proxy/src/sender.rs` |
| BCheck engine | Lexer → parser → AST → evaluator for PortSwigger's BCheck DSL | `crates/bcheck/src/lexer.rs`, `crates/bcheck/src/parser.rs`, `crates/bcheck/src/ast.rs`, `crates/bcheck/src/eval.rs`, `crates/bcheck/src/funcs.rs`, `crates/bcheck/src/insertion.rs` |
| BCheck conformance | Validates the grammar against PortSwigger's own parser as an oracle | `crates/bcheck/src/bin/conform.rs` |
| Scanner | Passive scan (off proxy hot path) + operator-triggered active audit with budgets/circuit breakers; Burp's issue catalog | `crates/scanner/src/lib.rs`, `crates/scanner/src/audit.rs`, `crates/scanner/src/catalog.rs`, `crates/scanner/src/catalog_data.rs` |
| Repeater | Byte-exact request send over raw TCP/TLS, no HTTP client normalization | `crates/repeater/src/lib.rs` |
| Intruder | Insertion-point discovery, lazy attack plan generation, rate-limited attack engine | `crates/intruder/src/lib.rs`, `crates/intruder/src/plan.rs`, `crates/intruder/src/engine.rs`, `crates/intruder/src/limit.rs` |
| Tools | Pure, I/O-free transformations: Decoder, Comparer, Logger, Organizer, match-and-replace | `crates/tools/src/decoder.rs`, `crates/tools/src/comparer.rs`, `crates/tools/src/logger.rs`, `crates/tools/src/organizer.rs`, `crates/tools/src/matchreplace.rs` |
| Web API/UI | axum router, JSON API, embedded single-page UI, feature routers | `crates/web/src/lib.rs`, `crates/web/src/routes/mod.rs`, `crates/web/src/routes/intercept.rs`, `crates/web/src/routes/sitemap.rs`, `crates/web/src/routes/tools.rs` |

## Pattern Overview

**Overall:** Layered library crates behind one composition-root binary. Each crate is a
self-contained subsystem (proxy, scanner, bcheck, repeater, intruder, tools) built on `burpsy-core`,
and the binary and the web crate are the only places that wire subsystems together.

**Key Characteristics:**
- Zero-copy message model: every subsystem operates on `MsgId` + `Span` handles into one
  `TrafficStore`, never on cloned byte buffers.
- Async I/O (tokio, axum) at the edges (proxy, web); synchronous, allocation-light logic in the
  middle (bcheck evaluator, intruder plan, tools).
- Explicit, auditable authorization: `Scope` is checked independently in the proxy, in repeater
  sends, in intruder sends, and again inside the scanner's active-audit sender.
- Bounding by refusal, not by discarding completed work: the scanner's audit engine and intruder's
  rate limiter both cap admission rather than running unbounded and dropping results afterward.

## Layers

**Storage layer (`burpsy-core`):**
- Purpose: own the one copy of every captured byte, plus span-based parses, findings, scope rules,
  and the site-map fold.
- Location: `crates/core/src/`
- Contains: `TrafficStore`, `StoredMessage`, `MessageShape`/`Span`, `RequestEdit`, `FindingStore`,
  `Scope`, `SiteMap`.
- Depends on: `bytes`, `parking_lot`, `serde`.
- Used by: every other crate.

**Protocol/DSL layer (`burpsy-bcheck`):**
- Purpose: parse and evaluate PortSwigger's BCheck scan-check DSL.
- Location: `crates/bcheck/src/`
- Contains: `lexer.rs`, `parser.rs`, `ast.rs`, `eval.rs` (evaluator + `Sender` trait), `funcs.rs`
  (builtin functions), `insertion.rs` (payload placement).
- Depends on: `burpsy-core`, `regex`.
- Used by: `burpsy-scanner`.

**Network layer (`burpsy-proxy`, `burpsy-repeater`):**
- Purpose: move bytes on and off the wire — as an intercepting MITM proxy, and as a byte-exact
  outbound sender for repeater/intruder/scanner traffic.
- Location: `crates/proxy/src/`, `crates/repeater/src/`
- Depends on: `burpsy-core`, `burpsy-bcheck` (proxy only, for the scanner wiring), `burpsy-scanner`
  (proxy only), tokio, rustls/rcgen (proxy only).
- Used by: `burpsy-web`, `burpsy-cli`.

**Attack layer (`burpsy-intruder`, `burpsy-scanner`):**
- Purpose: generate and dispatch attack/scan traffic against captured requests, under explicit
  rate/time/request budgets.
- Location: `crates/intruder/src/`, `crates/scanner/src/`
- Depends on: `burpsy-core` (both); `burpsy-bcheck` (scanner only).
- Used by: `burpsy-web` (intruder), `burpsy-cli`/`burpsy-web` (scanner via the `AuditHook` closure).

**Tooling layer (`burpsy-tools`):**
- Purpose: pure, I/O-free transformations reused by the proxy, the UI, and tests — Decoder,
  Comparer, Logger, Organizer, match-and-replace.
- Location: `crates/tools/src/`
- Depends on: `burpsy-core`, `flate2` (pinned to the pure-Rust `rust_backend`), `regex`.
- Used by: `burpsy-web`.

**Presentation layer (`burpsy-web`):**
- Purpose: JSON API + embedded single-page UI over one shared `TrafficStore`; wires repeater,
  intruder, tools and (via a closure) scanner auditing into HTTP routes.
- Location: `crates/web/src/lib.rs`, `crates/web/src/routes/`
- Depends on: `burpsy-core`, `burpsy-repeater`, `burpsy-intruder`, `burpsy-tools`, `burpsy-proxy`
  (dev-only cycle back for integration tests — see Architectural Constraints), axum.
- Used by: `burpsy-cli`.

**Composition root (`burpsy-cli`):**
- Purpose: parse CLI flags, build shared state (`TrafficStore`, `Scope`, `TlsPolicy`,
  `PassiveScanner`), spawn the proxy and web tasks, and select the process exit condition.
- Location: `crates/cli/src/main.rs`
- Depends on: `burpsy-core`, `burpsy-proxy`, `burpsy-web`, `burpsy-scanner`.
- Used by: nothing (binary entry point).

## Data Flow

### Primary Request Path (proxy capture)

1. A client's request arrives at the intercepting proxy (`crates/proxy/src/lib.rs`); if TLS
   interception is enabled and the host is not passthrough-listed, the connection is MITM'd via
   `crates/proxy/src/tls.rs`.
2. The request body is read once, converted to `Bytes`, and written into `TrafficStore::put`
   (`crates/core/src/lib.rs:302`), which parses it into a `MessageShape` of spans and returns a
   `MsgId`. An `Exchange` row indexing the request `MsgId` is added via `TrafficStore::add_exchange`.
3. If a passive scanner is configured (`--bchecks`), once the response arrives the proxy hands
   `(exchange_id, response_id)` off `tokio::spawn` to `PassiveScanner::scan`
   (`crates/scanner/src/lib.rs:197`) — off the proxy's hot path — which runs `given response`
   BCheck rules and records findings into the shared `FindingStore`.
4. The web UI (`crates/web/src/lib.rs`) reads the same `TrafficStore` through `AppState` to serve
   `/api/history` (index rows only), `/api/message/{id}` (fetches bytes only when a message is
   opened), and `/api/exchange/{id}`.

### Active Audit Path (operator-triggered)

1. Operator issues `POST /api/audit/{id}` in the web UI (`crates/web/src/lib.rs:186`, `run_audit`).
2. The request is offloaded via `tokio::task::spawn_blocking` to the `AuditHook` closure built in
   `crates/cli/src/main.rs:130`, which owns a `burpsy_proxy::sender::NetSender` and calls
   `PassiveScanner::audit` (`crates/scanner/src/lib.rs:272`).
3. `audit_item` (`crates/scanner/src/lib.rs:372`) checks scope first, builds a dispatch plan
   grouping active checks by `DispatchScope` (host/path/request), then runs each check through the
   BCheck evaluator (`burpsy_bcheck::eval::run_active`), sending probes through the `Metered`
   wrapper around `NetSender`, which re-checks scope on every spliced request.
4. The result is an `AuditOutcome` whose nine disposition counters always sum to the number of
   checks considered — every check lands in exactly one disposition, so a caller can distinguish
   "ran everything, found nothing" from "stopped looking".

### Repeater / Intruder send path

1. `POST /api/repeater/send` or `POST /api/intruder/run` (`crates/web/src/lib.rs:301`, `:478`)
   authorizes the target against `Scope` before a byte leaves the process.
2. Repeater calls `burpsy_repeater::send` (`crates/repeater/src/lib.rs`), which opens a raw
   `tokio::net::TcpStream` (+ `tokio-rustls` for HTTPS) and writes the exact bytes the operator
   typed — no HTTP client normalizes headers or rewrites `Content-Length`.
3. Intruder resolves insertion points via `burpsy_intruder::find_points`, builds an `AttackPlan`
   (`crates/intruder/src/plan.rs`) that stores only the attack's *shape* (mode, position count,
   payload-set lengths) rather than materializing every combination, then runs `burpsy_intruder::run`
   under a `RateLimit` and a per-request `Guard` closure that re-authorizes scope on the spliced
   bytes (because a payload landing in a URL-path position rewrites the path).
4. Responses are written back into `TrafficStore` via a `RecordFn` closure so results carry only a
   `MsgId`/ordinal, never a payload copy; a bucketed `AttackReport` resolves ordinals back to
   payload combinations on demand (`payloads_at`, `crates/web/src/lib.rs:701`).

**State Management:**
- All shared mutable state lives behind `Arc<TrafficStore>` (`RwLock<StoreInner>` internally,
  `parking_lot`), `Arc<Scope>`, and `Arc<RwLock<FindingStore>>`. There is no database; state is
  in-process and lost on restart.

## Key Abstractions

**`MsgId` + `Span` (zero-copy message handles):**
- Purpose: represent "a stored message" and "a piece of a stored message" without ever copying
  bytes; `Bytes::slice` bumps a refcount instead of allocating.
- Examples: `crates/core/src/lib.rs:37` (`MsgId`), `:41` (`Span`), `:70` (`MessageShape`).
- Pattern: every downstream crate (repeater, intruder, scanner, tools, web) holds these handles
  instead of `Vec<u8>`/`String`; a parsed message costs ~100 bytes regardless of body size.

**`AttackPlan` (lazy attack shape):**
- Purpose: represent a cluster-bomb-scale attack (potentially far more combinations than fit in
  memory) as a pure function of an ordinal, not a materialized list.
- Examples: `crates/intruder/src/plan.rs`.
- Pattern: `AttackPlan::fill(ordinal, &mut Assignment)` derives one request's payload combination
  arithmetically; results store only the ordinal, so any request is reconstructable later.

**`AuditOutcome` / `Disposition` (accounted-for bounding):**
- Purpose: make every bound on scan work explicit and summable, rather than silently discarding
  overflow the way Burp's `LIMIT_EXCEEDED` does.
- Examples: `crates/scanner/src/lib.rs` (`AuditOutcome::considered`, `Disposition` enum).
- Pattern: nine disposition counters partition the full active check set; `considered()` must equal
  the check-set size whenever an item was dispatched (enforced by `debug_assert_eq!`).

**`AuditHook` (capability closure, not a dependency)**
- Purpose: let `burpsy-web` expose "audit this exchange" without depending on the scanner or the
  sender crate.
- Examples: `pub type AuditHook = Arc<dyn Fn(u64) -> serde_json::Value + Send + Sync>;`
  (`crates/web/src/lib.rs:48`), constructed in `crates/cli/src/main.rs:130`.
- Pattern: the binary owns cross-crate wiring; library crates receive capabilities as closures/traits
  (see also `Sender` in `crates/bcheck/src/eval.rs`) rather than taking concrete dependencies.

**`Scope` (authorization, enforced independently at each edge):**
- Purpose: encode which hosts/paths are authorized for capture and attack.
- Examples: `crates/core/src/scope.rs`.
- Pattern: checked once per subsystem boundary (proxy capture, repeater send, intruder send/guard,
  scanner scan/audit, and again inside the `Metered` sender wrapper) — never hoisted or cached
  across a batch, so one in-scope item can never authorize traffic to an out-of-scope neighbor.

## Entry Points

**`burpsy` binary:**
- Location: `crates/cli/src/main.rs`
- Triggers: process start; CLI flags select proxy/web bind addresses, TLS policy, interception,
  BCheck directory, and scope rules.
- Responsibilities: build shared state, spawn the proxy task and the web task, exit on the first
  task failure or Ctrl-C.

**Proxy listener:**
- Location: `burpsy_proxy::run_with` (`crates/proxy/src/lib.rs`)
- Triggers: inbound TCP connections on the proxy bind address.
- Responsibilities: parse HTTP or tunnel CONNECT, apply TLS policy/interception, store traffic,
  dispatch to the passive scanner off the hot path.

**Web/API listener:**
- Location: `burpsy_web::serve_audit` (`crates/web/src/lib.rs:133`)
- Triggers: inbound HTTP requests on the web bind address.
- Responsibilities: serve the embedded single-page UI and the JSON API (`router_audit`,
  `crates/web/src/lib.rs:71`), merging per-feature routers from `crates/web/src/routes/`.

**BCheck conformance binary (dev tool):**
- Location: `crates/bcheck/src/bin/conform.rs`
- Triggers: manual invocation against a directory of `.bcheck` files.
- Responsibilities: parse every file and report accept/reject counts, validated against
  PortSwigger's own `BCheckChecker-1.9.jar` as an oracle.

## Architectural Constraints

- **Crate dependency direction:** `burpsy-proxy` depends on `burpsy-scanner` (to wire passive
  scanning into the proxy hot-path handoff), so `burpsy-scanner` must NOT depend on `burpsy-proxy`.
  This is why the outbound `NetSender` used for active audit probes lives in
  `crates/proxy/src/sender.rs` rather than beside the scanner code that calls it — the sender needs
  TLS config from the proxy crate, and the scanner cannot reach back up to get it.
- **Deliberate dev-only dependency cycle:** `burpsy-proxy`'s `[dev-dependencies]` include
  `burpsy-web` (`crates/proxy/Cargo.toml`), used only by `crates/proxy/examples/intercept_e2e.rs`
  and `crates/proxy/tests/interception.rs` to drive the real HTTP API end-to-end. Cargo permits this
  because `burpsy-web` depends on `burpsy-proxy` for real (production code), while `burpsy-proxy`
  depends on `burpsy-web` only to test itself (dev code) — do not "fix" this by removing it.
- **Threading:** Async I/O (proxy, web) runs on the tokio multi-threaded runtime
  (`#[tokio::main]` in `crates/cli/src/main.rs`). Synchronous, CPU/blocking-bound work — the BCheck
  evaluator during an active audit, and the outbound `NetSender`'s blocking `std::net` calls
  (`crates/proxy/src/sender.rs`) — runs on `tokio::task::spawn_blocking`
  (`crates/web/src/lib.rs:197`), never on a runtime worker thread.
- **Global/shared state:** `Arc<TrafficStore>`, `Arc<Scope>`, `Arc<RwLock<FindingStore>>` are
  cloned into both the proxy and web tasks; no crate holds process-global mutable state outside
  these explicitly shared handles.
- **Two scan paths must not be conflated:** `PassiveScanner::scan` (`crates/scanner/src/lib.rs:197`)
  is fully automatic, runs off the proxy hot path via `tokio::spawn`, and sends no traffic.
  `PassiveScanner::audit`/`audit_session` (`:272`, `:311`) send real probes to the target and are
  only ever triggered by an explicit operator action (`POST /api/audit/{id}`). This separation is a
  safety property — never wire the active path to run automatically off captured traffic.
- **Route modules are split per feature area** specifically so concurrent feature work does not
  collide on one route table (see Structure below) — new endpoints belong in a new file under
  `crates/web/src/routes/`, not appended to `crates/web/src/lib.rs`.

## Anti-Patterns

### Materializing an attack or a message body

**What happens:** Building a `Vec` of every payload combination, or holding a `Vec<u8>`/`String`
copy of a message body inside a new abstraction (e.g. a tree node, a result row).
**Why it's wrong:** This is exactly the memory blowup the project exists to avoid — a cluster bomb
over three 1,000-entry sets is a billion requests; a site-map node that "keeps the request that
created me" doubles memory it doesn't need to. See `crates/intruder/src/plan.rs` module docs and
`crates/core/src/sitemap.rs` module docs.
**Do this instead:** Store the shape (mode, lengths) and derive elements on demand
(`AttackPlan::fill`), or store `MsgId`/`Span` and slice via `TrafficStore::get`/`StoredMessage::slice`
when the bytes are actually needed.

### Silently discarding overflow instead of refusing admission

**What happens:** Running unbounded work and dropping results once a limit is hit, the way Burp's
`Zq5.LIMIT_EXCEEDED` does.
**Why it's wrong:** A caller cannot tell "ran everything, found nothing" from "gave up partway",
and completed work gets thrown away for capacity the engine already spent computing it.
**Do this instead:** Refuse the *next* unit of work at admission and report the refusal in a
disposition counter (see `AuditOutcome`/`Disposition` in `crates/scanner/src/lib.rs`, and
`AttackPlan::truncated` in `crates/intruder/src/plan.rs`), so every bound is visible to the caller.

## Error Handling

**Strategy:** `anyhow::Result` at process/task boundaries (`crates/cli/src/main.rs`,
`crates/proxy/src/lib.rs`, `crates/web/src/lib.rs`); typed enums for domain errors that callers must
branch on (`ParseError` in `crates/core/src/lib.rs`, `EvalError::SendFailed` in
`crates/bcheck/src/eval.rs`).

**Patterns:**
- Parsing is tolerant, not strict, where traffic is attacker-controlled: `parse()` in
  `crates/core/src/lib.rs` never panics on malformed HTTP, since real proxied/pentest traffic is
  frequently malformed.
- A failing check must never silence the rest of a check set (`crates/scanner/src/lib.rs`,
  `a_broken_check_does_not_silence_the_others` test) — errors are caught and skipped per-check, not
  propagated to abort a batch.
- HTTP handlers return typed `(StatusCode, message)` responses rather than panicking or 500ing on
  bad input (`crates/web/src/lib.rs`, e.g. `intruder_run` validation).

## Cross-Cutting Concerns

**Logging:** `tracing` + `tracing-subscriber`, configured via `RUST_LOG`/`EnvFilter` in
`crates/cli/src/main.rs`; used throughout for startup/config/audit visibility.

**Validation:** Extensive request-level validation in `crates/web/src/lib.rs` (rps floor/ceiling,
insertion-point range/uniqueness, payload-set/position count matching per attack mode) — validated
close to the HTTP boundary, before constructing an `Attack`.

**Authentication:** None — burpsy has no user auth; the only authorization concept is `Scope`
(target host/path allowlisting for capture and attack), not user identity.
