---
phase: 1
slug: store-scope-chokepoint
# status lifecycle: draft (seeded by plan-phase) → validated (set by validate-phase §6)
# audit-milestone §5.5 distinguishes NOT-VALIDATED (draft) from PARTIAL (validated + nyquist_compliant: false) (#2117)
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-27
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Test infrastructure, sampling rate, and Wave 0 gaps below are lifted from
> `01-RESEARCH.md` § Validation Architecture (verified against the workspace this session).

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` — standard library `#[test]` / `#[tokio::test]`. Confirmed as the *only* test tooling in the workspace: no `proptest`, `quickcheck`, `criterion`, or test-runner config appears in any `Cargo.toml` |
| **Config file** | none — plain `cargo test` per crate, consistent with every existing crate |
| **Quick run command** | `cargo test -p burpsy-core` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~15–60s workspace-wide (existing suite; grows with this phase's additions) |

---

## Sampling Rate

- **After every task commit:** `cargo test -p burpsy-core` (plus `-p <sender-crate>` for HARD-03 tasks)
- **After every plan wave:** `cargo test --workspace`
- **Before `/gsd-verify-work`:** full workspace suite green **and** the source-scan
  "no alternate egress" test passing
- **Max feedback latency:** ~60 seconds

---

## Per-Task Verification Map

Task IDs bind at planning time. This map is seeded at **requirement** level from research so the
planner has a target to satisfy; the planner and `/gsd-validate-phase` bind each row to concrete
task IDs. A row whose Task ID is still `pending` is not yet validated coverage.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| pending | pending | pending | STORE-01 | — | Segments seal at a message boundary and are never remapped; capture bounded by disk, not RAM | unit + integration | `cargo test -p burpsy-core segment` | ❌ W0 | ⬜ pending |
| pending | pending | pending | STORE-02 | — | `get` / `set_response` / `exchange` / `counts` resolve without a linear scan | unit | `cargo test -p burpsy-core` | ❌ W0 | ⬜ pending |
| pending | pending | pending | STORE-03 | — | id assignment and index population never observed out of order under concurrent `put` / `add_exchange` | concurrent stress (`multi_thread`) | `cargo test -p burpsy-core concurrent` | ❌ W0 | ⬜ pending |
| pending | pending | pending | STORE-04 | — | `related` / `ChildRef` slot exists, empty by default, addressable per exchange id | unit | `cargo test -p burpsy-core related` | ❌ W0 | ⬜ pending |
| pending | pending | pending | STORE-05 | T-1-02 | Mechanism A (differential parity vs the `Vec` store) **and** Mechanism B (CRC32C scan that *names* a mismatching id) | property/differential + unit | `cargo test -p burpsy-core verify` | ❌ W0 | ⬜ pending |
| pending | pending | pending | HARD-03 | T-1-01 | `AuthorisedSender` is the only path to a socket for every constructed-request sender; a new `std::net` / `tokio::net` call site outside it fails the source scan | unit + workspace source-scan | `cargo test --workspace no_alternate_egress` | ❌ W0 | ⬜ pending |

**Threat refs** point at the threat model the planner emits per `<threat_model>` (ASVS V4 access
control for the chokepoint, V5 input validation for the record-header parser). They are named here
so the planner wires them rather than inventing new ids.

**STORE-03 evidence caveat (carried forward from research):** a high-iteration multi-thread stress
test is the *minimum*. It is weaker evidence than the requirement's wording implies — a stress test
that passes has not proven the interleaving cannot happen. `loom` would prove it exhaustively but
costs a `cfg(loom)`-gated abstraction over `parking_lot::RwLock`; research sized this as an
**optional stretch goal, not mandatory** for Phase 1. If the stress test is the only evidence
shipped, that limit must be stated in the phase summary, not glossed.

---

## Wave 0 Requirements

- [ ] `crates/core/src/segment.rs` — new module, no existing file to extend
- [ ] `crates/core` test-module additions for the race-free index, the `related` slot, and both
      STORE-05 verification mechanisms
- [ ] Chokepoint home (new crate or `crates/core` addition) plus its own test module for
      `AuthorisedSender`
- [ ] A workspace-level source-scan test — **no existing precedent in this workspace.** Decide where
      it lives: a new `xtask`-style crate, or a `#[test]` that walks relative paths from inside the
      chokepoint crate. Research recommends the latter (simpler; this workspace has no `xtask`)
- [ ] `proptest` added as a dev-dependency wherever the differential/concurrent tests live
- [ ] `Cargo.toml` feature narrowing for `intruder` / `bcheck` / `scanner` (`tokio` features
      restricted in `[dependencies]`, restored under `[dev-dependencies]`). A config change rather
      than a test file, but it belongs in the same wave as the source-scan test — it is the
      structural half of the same guarantee

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| A multi-GB capture stays bounded by disk rather than RAM | STORE-01 | The bound is the *point* of the phase, but proving it needs a sustained multi-GB capture — too slow and too disk-hungry for the per-commit suite | Run the proxy against a high-volume target (or replay a large capture) until total captured bytes exceed available RAM; watch RSS stay flat while disk grows. Record peak RSS and total captured bytes in the phase summary |
| `AuthorisedSender` coverage is *complete* across surfaces, not just across today's senders | HARD-03 | The source-scan test proves no *known* alternate egress path exists today. It cannot prove a future surface (crawler, plugins, MCP, browser) will route through the chokepoint — those surfaces do not exist yet | At each later phase that adds a request-originating surface, add that surface's own chokepoint test. HARD-03's "verified by a test per surface" is satisfied incrementally, and Phase 1 delivers only the surfaces that exist now |

**Honest bound on the source-scan test:** narrowing per-crate `tokio` features blocks the *async*
egress path, but `std::net` remains reachable from any crate regardless of feature flags. The scan
is a backstop that catches new call sites in review, not a compile-time impossibility proof. Do not
report it as the latter.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
