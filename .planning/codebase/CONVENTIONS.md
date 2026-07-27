# Coding Conventions

**Analysis Date:** 2026-07-27

## Naming Patterns

**Files:**
- One module per concern, named after the domain noun: `edit.rs` (request editing), `scope.rs` (target scope), `limit.rs` (rate limiting), `eval.rs` (BCheck evaluator). Not `utils.rs` / `helpers.rs` grab-bags.
- Crate names are prefixed `burpsy_*` (e.g. `burpsy_core`, `burpsy_proxy`) but directories under `crates/` use the short domain name (`crates/core`, `crates/proxy`).

**Functions:**
- Standard Rust `snake_case`. Constructors are `new`, fallible parsers are `from_raw` / `parse`.
- Public API favors small single-purpose functions with a doc comment stating the one decision that matters (e.g. why `to_raw` recomputes Content-Length).

**Test functions — this is a real, enforced convention:**
Tests are named as full sentences describing the property being proved, not the method under test. Examples from the codebase:
- `crates/intruder/src/limit.rs`: `serial_acquires_cannot_exceed_the_configured_rate`, `no_window_holds_more_grants_than_the_bucket_allows`
- `crates/core/src/scope.rs`: `an_excluded_path_is_refused_even_though_the_host_is_allowed`, `a_whole_host_exclude_does_put_the_host_out_of_reach`, `an_empty_scope_authorises_nothing`
- `crates/bcheck/src/eval.rs`: `a_failed_send_abandons_the_check_instead_of_reporting`, `a_misnamed_binding_produces_no_finding`, `a_check_that_uses_differs_from_is_not_counted_as_m3_runnable`
- `crates/tools/src/logger.rs`: `a_failed_send_is_kept_because_a_reset_after_a_payload_is_itself_evidence`

When adding a test, name it as the sentence a reviewer would use to describe the guarantee ("a/an/no <subject> <verb phrase>"), never `test_foo` or `foo_works`.

**Types:**
- `PascalCase` structs/enums named after the domain object: `RequestEdit`, `RateLimit`, `ParseError`, `ScopeRule`.
- Error types are small and local to the module that produces them (`ParseError` in `crates/core/src/lib.rs`, `EditError` in `crates/core/src/edit.rs`), not one giant crate-wide error enum.

## Code Style

**Formatting:**
- No `rustfmt.toml` present — default `rustfmt` settings apply.
- Rust 2024 edition (`crates/*/Cargo.toml` inherit `workspace.package.edition = "2024"`, see `Cargo.toml:6`).

**Linting:**
- Clippy is part of the definition of "good" (`verify.sh`), run with `--workspace --all-targets`, and **zero clippy warnings is the bar**, not "no errors."
- Build warnings are also treated as hard failures: `verify.sh` counts `cargo build --workspace` warnings and fails the tree if any exist, not just build errors. Do not leave `#[allow(dead_code)]` or unused-import warnings uncommitted.
- Clippy must be invoked via `rustup which cargo`/`rustup which rustc` pinned explicitly (see the toolchain-mismatch comment block in `verify.sh:34-58`) — do not assume a bare `cargo clippy` is safe on this machine.

## Comment Style (the load-bearing convention)

Comments explain **why**, never restate **what**. Module-level doc comments (`//!`) state a design decision and the evidence for it — often citing the actual decompiled Burp class the behavior was reverse-engineered from. Representative headers:

- `crates/core/src/edit.rs` — states three specific correctness hazards (stale Content-Length, chunked bodies, absolute- vs origin-form targets) and why each matters, with `[to_raw]` doc-links.
- `crates/intruder/src/limit.rs` — justifies why rate limiting is a correctness feature not a "politeness knob," cites `burp.Zuwo.Zz` (resource-pool validator, Burp 2026.7.1 teardown) and `burp.Zgao` (`ResourcePoolConfiguration`), and states the exact bound the limiter's tests must measure: "in any window of length T the limiter grants at most `burst + per_second * T` requests."
- `crates/bcheck/src/eval.rs` — documents evaluator milestones (M1/M2/M3) and lists semantics that are "easy to get backwards" (containment direction of `in`, `base` vs `latest`, absent-vs-empty bindings).

When writing a new module or non-trivial function, follow this pattern: state the decision, state why the naive alternative is wrong, and cite the concrete evidence (a decompiled class name, a corpus count, a measured bound) if one exists. Do not write comments that just describe control flow.

## Error Handling

- `thiserror` and `anyhow` are both workspace dependencies (`Cargo.toml:14-15`) but hand-rolled small error enums/structs with manual `Display`/`std::error::Error` impls are the dominant pattern in `core` (see `ParseError` in `crates/core/src/lib.rs:127-146` and `EditError` in `crates/core/src/edit.rs:41-50`, a unit struct wrapping `&'static str`).
- Parsing is tolerant, not strict, by design: `parse()` in `crates/core/src/lib.rs` accepts both CRLF and bare LF because "RE and pentest traffic is frequently malformed, and a strict parser would reject exactly the requests you most want to inspect."
- Some call sites return `Result<(), String>` for simpler internal validation paths (`crates/core/src/scope.rs:244`).
- Fallible parsing uses `.ok_or(SpecificError)?` chains rather than `unwrap()`/`expect()` in library code; `unwrap()` is reserved for test code and places where a prior check has already guaranteed success (e.g. `TcpListener::bind(...).local_addr().unwrap()` in test helpers, `crates/proxy/tests/interception.rs:26`).

## Derive Conventions

Structs/enums consistently derive the minimal useful set for their role:
- Plain-old-data value types: `#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]` (`crates/core/src/lib.rs:36,40,59`).
- Owned/heap-backed config types: `#[derive(Debug, Clone, Serialize, Deserialize)]`, sometimes with `Default` (`crates/core/src/scope.rs:33,153`).
- Error types: `#[derive(Debug, Clone, PartialEq, Eq)]` plus manual `Display`/`Error` impls (never `thiserror` for these small local errors).
- `Serialize, Deserialize` (serde) is added to any type that crosses the web API boundary (`crates/web`).

## Import Organization

- Standard `use` grouping: external crates first (`serde`, `bytes`, `tokio`), then intra-workspace crates (`burpsy_core::...`), then `std`. See `crates/bcheck/src/eval.rs:31-36` and `crates/proxy/tests/interception.rs:8-15`.
- No path aliasing conventions observed beyond standard crate-qualified paths (`burpsy_core::edit::RequestEdit`).

## Function Design

- Functions are kept small and single-purpose; larger flows are composed from named helpers with their own doc comments (e.g. `find_header_end`, `find_line_end`, `split3` in `crates/core/src/lib.rs`).
- Doc comments on public functions state invariants that matter operationally, not just parameter descriptions — e.g. "Never allocates for the body" on `parse()`.

## Module Design

- Each crate under `crates/` owns one architectural concern (proxy, repeater, intruder, scanner, bcheck, tools, web, cli, core). Cross-crate reuse goes through `burpsy_core` (message parsing/spans, scope, edit, traffic store).
- `crates/core` is the shared foundation: message shapes (`MessageShape`, `StoredMessage`, `MsgId`, `Direction`), scope rules (`scope.rs`), and request editing (`edit.rs`).
- Domain crates (`intruder`, `bcheck`) build directly on `burpsy_core` types rather than duplicating parsing/editing logic.

---

*Convention analysis: 2026-07-27*
