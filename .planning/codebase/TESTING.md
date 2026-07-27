# Testing Patterns

**Analysis Date:** 2026-07-27

## Test Framework

**Runner:**
- Standard `cargo test` (Rust built-in test harness), no external test runner crate.
- `tokio` async tests via `#[tokio::test]` (workspace dependency, `Cargo.toml:13`, `full` features).
- ~385 `#[test]`/`#[tokio::test]` functions across the workspace (verify with `grep -rc '#\[test\]\|#\[tokio::test\]' -r crates` — do not trust this number blindly, re-check after changes).

**Assertion Library:**
- Plain `std` `assert!`/`assert_eq!` with explicit failure-message format strings that restate the property being checked (see `crates/intruder/src/limit.rs` tests) — no `assert2`/`pretty_assertions`/etc.

**Run Commands:**
```bash
cargo test --workspace              # all unit + integration tests
QUICK=1 ./verify.sh                 # full gate minus the 1-minute e2e suites
./verify.sh                         # the single definition of "this tree is good"
./e2e.sh                            # one specific e2e suite (also e2e-tls.sh, e2e-scan.sh, e2e-audit.sh, e2e-intercept.sh)
```

## Test File Organization

**Unit tests:** inline, co-located with the code they test, inside `#[cfg(test)] mod tests { ... }` at the bottom of the source file. This is universal in the codebase — e.g. `crates/core/src/scope.rs`, `crates/intruder/src/limit.rs`, `crates/bcheck/src/eval.rs`, `crates/tools/src/logger.rs`.

**Integration tests:** separate files under `crates/<crate>/tests/`, only where a test needs to exercise real sockets/processes that a unit test cannot fake. Found in:
- `crates/core/tests/`
- `crates/proxy/tests/interception.rs` — spins up `burpsy_proxy::serve` on an ephemeral port with a real TCP origin server, because "the properties under test are all about what happens *between* connections... and none of those can be observed by calling the interceptor directly."

**Naming:** sentence-form test function names describing the property under test (see CONVENTIONS.md "Test functions" section for the full house style and examples). Do not name tests `test_x` or `x_works`.

## The stated testing rule

**A test that only proves "it didn't panic" is worthless.** Every test in this codebase asserts a concrete, specific value or bound — never merely that a call returned `Ok` or didn't crash. Two concrete illustrations:

- `crates/intruder/src/limit.rs`, `no_window_holds_more_grants_than_the_bucket_allows`: asserts the *exact* bound `count as f64 <= burst + rps * window` for every sliding window in the trace, not an approximation.
- `crates/bcheck/src/eval.rs` module doc: BCheck corpus conformance requires "≥381 modifier clauses captured" — a specific number cross-checked against an independent grep of the corpus, because a silent drop below that number means the parser started discarding request mutations again (see `verify.sh` BCheck corpus step).

## Paired guard tests (fires / does-not-over-fire)

Tests are frequently written in matched pairs: one proving a guard/rule triggers correctly, one proving it does not fire when it should not. Examples in `crates/core/src/scope.rs`:
- `a_path_scoped_exclude_does_not_put_the_whole_host_out_of_reach` paired with `a_whole_host_exclude_does_put_the_host_out_of_reach`
- `an_excluded_path_is_refused_even_though_the_host_is_allowed` paired with `a_host_scoped_to_a_path_prefix_is_not_refused_wholesale`

When adding a new validation/guard rule, add both the positive case (it fires when it should) and the negative case (it does not fire when it should not) as separate, explicitly named tests — do not rely on one test covering both directions implicitly.

## Test Structure

```rust
// crates/intruder/src/limit.rs
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The bound is `elapsed >= (n - burst) / rps`, derived directly from the bucket starting full.
    #[tokio::test]
    async fn serial_acquires_cannot_exceed_the_configured_rate() {
        let rps = 100.0;
        let n = 21;
        let l = RateLimiter::new(RateLimit::new(Some(rps), 1, 8));
        let t0 = Instant::now();
        for _ in 0..n { let _p = l.acquire().await; }
        let elapsed = t0.elapsed();
        let floor = Duration::from_secs_f64((f64::from(n) - 1.0) / rps);
        assert!(elapsed >= floor, "21 requests at 100rps took {elapsed:?}, faster than the {floor:?} floor");
    }
}
```

Each non-trivial test carries a doc comment (`///`) directly above it stating what mathematical/logical property it proves and, where relevant, why the assertion has no upper bound to avoid flaking (e.g. "a loaded machine can only push the measurement further above the floor").

## Mocking

- No mocking framework (no `mockall`, no trait-object test doubles observed). The house style is **real dependencies, not mocks**:
  - `crates/proxy/tests/interception.rs` spins up a genuine `TcpListener`-based origin server (`spawn_origin`) that counts real hits via `Arc<AtomicUsize>`.
  - The five root-level e2e suites start a real Python `http.server` origin and a real compiled `./target/debug/burpsy` binary listening on real ports (`e2e.sh:16-27`).
- What NOT to mock: HTTP/TCP behavior, timing-sensitive rate-limiting behavior, anything where "did it actually happen on the wire" is the property under test.
- What can be faked cheaply: pure data construction (`RateLimit::new(...)`, `ScopeRule` literals) — these are plain value construction, not mocks.

## Fixtures and Factories

- No fixture/factory framework. Test data is constructed inline as plain struct literals/constructors per test (e.g. `RateLimiter::new(RateLimit::new(Some(rps), burst, max_in_flight))`).
- BCheck corpus tests pull real `.bcheck` files from an external corpus directory `/tmp/BChecks` (264 files) — `verify.sh` "BCheck corpus conformance" step; conformance is skipped gracefully if that directory is absent.

## Coverage

- No coverage tool/threshold configured (no `tarpaulin`/`llvm-cov` config found). Coverage is enforced socially via `verify.sh`'s test-count and modifier-clause-count assertions, not measured via a coverage tool.

## Test Types

**Unit tests:** inline `#[cfg(test)] mod tests` per crate; the large majority of the ~385 tests. Cover parsing, scope rules, rate limiting, BCheck evaluation, request editing.

**Integration tests:** `crates/*/tests/*.rs`, using real sockets against an in-process `serve()` call. Currently `crates/core/tests/` and `crates/proxy/tests/interception.rs`.

**End-to-end tests:** five bash suites at repo root, run against the actual compiled binary — not mocked at any layer:

| Suite | Focus |
|---|---|
| `e2e.sh` | Core proxy/history/repeater/intruder wiring via the real HTTP web API |
| `e2e-tls.sh` | TLS interception |
| `e2e-scan.sh` | Scanner flows |
| `e2e-audit.sh` | Audit flows |
| `e2e-intercept.sh` | Interactive intercept behavior |

~75 e2e checks total across the five suites (re-verify count; grep `ok "` / `no "` call sites per script).

**House pattern for every e2e script** (see `e2e.sh:1-35`, consistent across all five):
```bash
PASS=0; FAIL=0
ok(){ echo "  PASS  $1"; PASS=$((PASS+1)); }
no(){ echo "  FAIL  $1"; FAIL=$((FAIL+1)); }
cleanup(){ pkill -x burpsy 2>/dev/null; kill ${ORIGIN_PID:-0} 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
# ... start a real origin server (usually python3 http.server) and the real burpsy binary ...
# poll with curl/exec-on-/dev/tcp loops until each real port is listening, then assert on real responses
echo "############ $PASS passed, $FAIL failed ############"
[ "$FAIL" -eq 0 ]
```

**Critical operational rule — `pkill -x`, never `pkill -f`:** every e2e script's cleanup uses `pkill -x burpsy` (exact process-name match). Using `pkill -f burpsy` instead would also match the `pkill` invocation's own command line (since `-f` matches the full command line, which itself contains the string being searched for) and produce false cleanup failures / self-kills. This is a hard-won rule — do not "simplify" it to `-f` in new scripts. See `e2e.sh:16`, `e2e-audit.sh:16`, `e2e-scan.sh:15`, `e2e-tls.sh:18`, `e2e-intercept.sh:25`.

`verify.sh` runs the e2e suites **sequentially, not in parallel**, specifically because each script's `pkill -x burpsy` cleanup would kill its siblings' processes if run concurrently (`verify.sh`, "e2e suites" step comment).

## Common Patterns

**Async testing:**
```rust
#[tokio::test]
async fn concurrent_acquires_are_spaced_not_released_together() {
    let l = RateLimiter::new(RateLimit::new(Some(50.0), 1, 20));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let l = l.clone();
        set.spawn(async move { let _p = l.acquire().await; /* ... */ });
    }
    while let Some(r) = set.join_next().await { /* collect */ }
}
```
Concurrency-sensitive properties (rate limiting) are tested by spawning real concurrent tasks with `tokio::task::JoinSet`, not by simulating time.

**Error/negative-path testing:**
Errors are tested by asserting the specific `Err` variant returned, matching the small hand-rolled error enums (`ParseError`, `EditError`) described in CONVENTIONS.md — not just `assert!(result.is_err())`.

**Verification gate (`verify.sh`) order, for reference when adding new gates:**
1. `cargo build --workspace` — zero warnings required, not just zero errors
2. clippy via pinned rustup toolchain, `--workspace --all-targets`, zero warnings
3. `cargo test --workspace`
4. BCheck corpus conformance (264 files, ≥381 modifier clauses) — skipped gracefully if `/tmp/BChecks` absent
5. All `e2e*.sh` suites, sequentially, unless `QUICK=1`

`integrate.sh` merges a branch and then re-runs `verify.sh` against the merge result, so a merge is never held to a weaker bar than the branch itself was.

---

*Testing analysis: 2026-07-27*
