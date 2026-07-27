# Technology Stack

**Analysis Date:** 2026-07-27

## Languages

**Primary:**
- Rust (edition **2024**, workspace-wide via `Cargo.toml` `[workspace.package] edition = "2024"`) — every crate under `crates/`. Edition 2024 is relied upon for **let-chains** (`if let ... && let ... {}`) used throughout the codebase, not just incidentally available.

**Secondary:**
- Python 3 — `crates/scanner/tools/gen_catalog.py`, a one-shot code generator, not part of the runtime.
- Shell (bash) — top-level orchestration/verification scripts: `verify.sh`, `integrate.sh`, `e2e.sh`, `e2e-audit.sh`, `e2e-intercept.sh`, `e2e-scan.sh`, `e2e-tls.sh`, `serve.sh`.

## Runtime

**Environment:**
- Async runtime: `tokio` 1.x, `features = ["full"]`, pinned once in `[workspace.dependencies]` in `/root/burpsy/Cargo.toml` and inherited by every crate that needs it (`core`, `proxy`, `intruder`, `web`, `cli`).
- Target: native binary, `x86_64-unknown-linux-gnu` (per `rustup show` on this box); no cross-compilation config present.

**Package Manager / Toolchain:**
- Cargo workspace, `resolver = "3"`, 9 members declared in `/root/burpsy/Cargo.toml`: `crates/core`, `crates/proxy`, `crates/repeater`, `crates/intruder`, `crates/web`, `crates/cli`, `crates/bcheck`, `crates/scanner`, `crates/tools`.
- Lockfile: `Cargo.lock` present at repo root (committed).
- No `rust-toolchain.toml` file exists in the repo.

**⚠️ Split toolchain — read before running clippy:**
There are two independent Rust installs on this machine, and they do not agree with each other:
- `/usr/bin/cargo` / `/usr/bin/rustc` — a distro build, **rustc 1.92.0**, and it sits ahead of rustup's shims in `PATH`, so it is what plain `cargo ...` invokes.
- rustup-managed toolchains — `stable` (1.92.0), `1.93.0`, and `nightly`, installed under `/root/.rustup`. Critically, `clippy-driver` exists **only** here, not for the distro build.

Running plain `cargo clippy` therefore mixes a rustup-built `clippy-driver` (1.95.0-era in earlier observations, currently tracks whichever rustup `stable` is active) against crates compiled by the distro `rustc` 1.92 — every workspace crate then fails with `E0514` ("found crate X compiled by an incompatible version of rustc"). A `rust-toolchain.toml` would **not** fix this, since it's a rustup-only feature and `/usr/bin/cargo` ignores it entirely.

`/root/burpsy/verify.sh` documents and works around this with three explicit fixes (see the comment block at the top of its "clippy" step, ~line 30-65):
1. Invoke clippy through `rustup which cargo`, not bare `cargo`, so cargo and clippy-driver come from the same toolchain.
2. Additionally pin `RUSTC="$(rustup which rustc)"` — cargo resolves the rustc it shells out to via a bare `PATH` lookup regardless of which cargo binary you ran, so without this cargo would still compile dependencies with the wrong (distro) rustc.
3. Use a dedicated `CARGO_TARGET_DIR=target/clippy`, separate from the normal `target/`, because clippy sets `RUSTC_WORKSPACE_WRAPPER` which changes every workspace crate's build fingerprint — sharing `target/` would cause clippy and plain `cargo build` to invalidate each other's cache on every alternation.

Anyone running `cargo clippy` naively (not through `verify.sh`) will lose time to spurious `E0514` errors. Always use `verify.sh`, or replicate its `RUSTUP_CARGO`/`RUSTC`/`CARGO_TARGET_DIR` pattern manually.

## Frameworks

**Core:**
- `axum` 0.8 — HTTP web framework for the UI/API server, `crates/web/Cargo.toml` (and as a dev-dependency in `crates/proxy/Cargo.toml` for integration tests).
- `tokio` 1.x (`full` features) — async runtime underpinning the proxy, web server, repeater, and intruder.
- `rustls` 0.23.42 (no default features; `std`, `aws-lc-rs`, `tls12`, `logging`) + `tokio-rustls` 0.26.4 + `rustls-pemfile` 2.2.0 + `rustls-pki-types` 1.15.1 — TLS stack for the intercepting proxy, `crates/proxy/Cargo.toml`.
- `rcgen` 0.14.8 (no default features; `aws_lc_rs`, `pem`, `x509-parser`) — dynamic CA/leaf certificate generation for TLS interception, `crates/proxy/Cargo.toml`.

**Testing:**
- Built-in `cargo test` harness (no separate test framework crate); tests are colocated `#[cfg(test)] mod tests` blocks plus dedicated integration-test binaries/examples in crates like `proxy` (`intercept_e2e` example) and a `conform` binary (BCheck corpus conformance, invoked by `verify.sh`).
- End-to-end shell-driven tests: `e2e.sh`, `e2e-audit.sh`, `e2e-intercept.sh`, `e2e-scan.sh`, `e2e-tls.sh` at repo root.

**Build/Dev:**
- `verify.sh` — single source of truth for "this tree is good": build (zero warnings required), clippy (via the rustup-toolchain workaround above), unit tests, and BCheck corpus conformance.
- `integrate.sh` — runs `verify.sh` after every branch merge.
- `serve.sh` — local dev launcher.

## Key Dependencies

**Critical:**
- `serde` 1.x (`derive`) + `serde_json` 1.x — pervasive (de)serialization across every crate; declared once in `[workspace.dependencies]`.
- `bytes` 1.x — zero-copy buffer type used across proxy/core/intruder/repeater for HTTP body handling.
- `anyhow` 1.x / `thiserror` 2.x — error handling; `anyhow` for application-level `Result`, `thiserror` available for typed errors.
- `parking_lot` 0.12 — synchronization primitives (mutexes/locks) in `core`, `proxy`, `intruder`, `scanner`, `tools`, `web`, replacing `std::sync`.
- `regex` 1.x — used in `crates/bcheck` (BCheck condition matching) and `crates/tools` (payload/response processing).
- `tracing` 0.1 + `tracing-subscriber` 0.3 (with `env-filter` in `cli`) — structured logging across the workspace.

**Infrastructure:**
- `flate2` 1.x, **explicitly** `default-features = false, features = ["rust_backend"]` — in `crates/tools/Cargo.toml` only. This is a deliberate, documented exception to the project's otherwise hand-rolled-crypto/codec policy: a correct DEFLATE/inflate implementation is a few thousand lines of Huffman decoding, and getting it wrong on attacker-controlled bytes (this tool decompresses responses from attack targets) is a memory-safety bug, not a cosmetic one. `rust_backend` resolves to `miniz_oxide` (pure Rust, no C toolchain, no libz), pinned explicitly so a future flate2 default change cannot silently pull in a `cc` build dependency.
- **Hand-rolled base64**: `crates/bcheck/src/funcs.rs` implements its own `base64_decode` (line ~181, standard alphabet, tolerant of missing padding and embedded whitespace) rather than depending on the `base64` crate — consistent with the project's general preference to hand-roll small, well-scoped codecs used inside the BCheck function library (`to_lower`, `base64_decode`, etc.) rather than add dependencies, reserving actual third-party crates for things that are genuinely hard to get right (see `flate2` above).
- `time` 0.3 — used alongside the TLS stack in `crates/proxy` (certificate validity periods).
- `axum` 0.8 as a **dev-dependency** in `crates/proxy/Cargo.toml`: the proxy crate depends on `burpsy-web` only for tests (the `intercept_e2e` example drives the real HTTP API that `web` exposes), while `web` depends on `proxy` for real — a documented, intentional dev-dependency cycle (see comment in `crates/proxy/Cargo.toml`).

## Configuration

**Environment:**
- No `.env` files present in the repository (confirmed via `find . -name ".env*"`).
- Logging verbosity controlled via `tracing_subscriber::EnvFilter` (`RUST_LOG`-style), defaulting to `"info"` — `crates/cli/src/main.rs`.
- Runtime behavior is configured entirely via CLI flags, not environment variables: `--proxy`, `--web`, `--tls-passthrough`, `--tls-passthrough-port`, `--tls-defaults`, `--intercept-tls`, `--bchecks <dir>`, `--scope-include`, `--scope-exclude`, `--ca-dir` (`crates/cli/src/main.rs`).

**Build:**
- Root `/root/burpsy/Cargo.toml` — workspace manifest, single place shared dependency versions are pinned.
- Per-crate `crates/*/Cargo.toml` — 9 manifests, each declaring only the extra dependencies that crate needs beyond the workspace-shared set.
- `.gitignore` at repo root (excludes `target/`, etc.).
- No `.eslintrc`/`tsconfig`/JS-ecosystem config — this is a pure Rust workspace, no frontend build tooling detected beyond whatever static assets `crates/web` serves directly (not inspected here).

## Platform Requirements

**Development:**
- Rust via rustup, **plus** awareness that a second, distro-installed Rust toolchain (`/usr/bin/cargo`/`rustc` 1.92.0) exists on `PATH` ahead of rustup's shims — see the toolchain warning above. `clippy-driver` is only available through rustup.
- Optional: `/tmp/BChecks` (PortSwigger's public BCheck corpus) for the conformance test suite; its absence is tolerated (`verify.sh` skips conformance and marks it OK if the directory is missing).
- Optional: `/root/burp-re/` (decompiled Burp 2026.7.1 teardown) for regenerating the scanner's issue catalog via `crates/scanner/tools/gen_catalog.py`; not required for normal build/test.
- Python 3 only needed to run `gen_catalog.py`, not for building/running burpsy itself.

**Production:**
- Single self-contained Rust binary, `burpsy` (`crates/cli`, `[[bin]] name = "burpsy"`), which runs both the intercepting proxy and the web UI over one shared `TrafficStore` (per `crates/cli/src/main.rs` doc comment) — no separate deployment target, container, or service dependency detected.
- Default bind addresses: proxy `127.0.0.1:8080`, web UI `127.0.0.1:8081` (overridable via `--proxy`/`--web` flags).

---

*Stack analysis: 2026-07-27*
</content>
