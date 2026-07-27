# Stack Research

**Domain:** Rust web-application-security testing platform (Burp Suite reimplementation) — platform/plugin-era dependency decisions for an existing 9-crate workspace
**Researched:** 2026-07-27
**Confidence:** MEDIUM overall (crate versions verified directly against crates.io/GitHub source; architectural comparisons corroborated across multiple independent sources but not primary-source-exhaustive — see per-item notes and Gaps)

This file covers only the six new-dependency questions for this milestone (mmap store, plugin host, HTTP/2, expression language, JS engine, MCP server). It does **not** re-litigate the existing stack in `.planning/codebase/STACK.md` (tokio, axum 0.8, rustls 0.23, rcgen 0.14, parking_lot, bytes, regex, serde, flate2) — those are assumed and, where relevant, checked for compatibility against new additions.

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `memmap2` | 0.9.11 (2026-06-22) | mmap the sealed segment files of the traffic store | The de facto safe Rust mmap wrapper (7.5M+ downloads); MSRV 1.65. It does not solve the growth/remap hazard for you — that has to be designed around (see Architecture Notes below) — but it is the correct low-level primitive once the design avoids remapping live data. |
| `bytes` | 1.12.1 (2026-07-08, already a workspace dep) | `Bytes::from_owner(mmap)` — once per sealed segment — to keep the existing zero-copy `Span{offset,len}` + `Bytes` API unchanged when the backing store becomes mmap segments | Confirmed on docs.rs: `Bytes::from_owner<T>(owner: T) -> Self where T: AsRef<[u8]> + Send + 'static`, documented explicitly as enabling "zero-copy construction from mapped memory." `memmap2::Mmap` itself already implements `AsRef<[u8]> + Send + Sync + 'static` (confirmed on docs.rs), so it can be passed directly to `from_owner` — no `Arc` wrapper needed; `from_owner` already does the refcount-and-drop-on-last-clone internally. Call it **once per sealed segment**, producing one `Bytes` covering the whole segment, then resolve every `Span` in that segment via `segment_bytes.slice(offset..offset+len)` — a refcount bump, not a new allocation or a new `from_owner` call. This is the one fact the whole mmap migration hinges on, and it's present — no version bump needed. **Hand-roll-vs-dependency: dependency, correctly.** Wrapping a raw mapped region in a refcounted, thread-safe, drop-tracked handle by hand is exactly the kind of memory-safety-adjacent job this project reserves for a dependency (same bar as `flate2`). |
| `wasmtime` | 47.0.2 (2026-07-21) | Low-level WASM runtime backing whichever plugin path is chosen | Standards-first (Bytecode Alliance, WASI, Component Model), the most widely embedded WASM runtime in Rust server software, and — importantly — the runtime `extism` itself defaults to. Recommend depending on it *indirectly* via `extism`, not directly (see Plugin Host below), unless a phase later needs raw Component Model control extism doesn't expose. |
| `extism` | 1.30.0 (2026-06-04) | Rust host SDK for the in-process WASM plugin path (Rust/Go/AssemblyScript-authored plugins, and JS/TS plugins compiled to WASM) | See "Plugin Host — Decision" below. Confidence: MEDIUM. |
| `h2` | 0.4.15 (2026-06-15, hyperium), `unstable` feature enabled | Well-formed HTTP/2 client + server, and the frame-level primitive for the malformed-frame research feature | See "HTTP/2 — Decision" below. Confidence: MEDIUM, with one open verification flagged. |
| `rhai` | 1.25.1 (2026-05-29) | Bambda-style filter/highlight expression language evaluated per proxied message | Confirms the incumbent suggestion in PROJECT.md. See "Expression Language — Decision." Confidence: MEDIUM. |
| `boa_engine` | 0.21.1 (2026-03-29) | Embedded JS engine for DOM/JS analysis | See "JS Engine — Decision." Confidence: MEDIUM. |
| `rmcp` | 2.2.0 (2026-07-08) | Official Rust MCP SDK, mounted onto the existing `burpsy-web` axum router | See "MCP Server — Decision." Confidence: MEDIUM-HIGH (version-compatibility claim verified against rmcp's own Cargo.toml). |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| A small hand-rolled frame-header writer (no crate) | n/a | Emitting the ~10% of malformed HTTP/2 frames `h2`'s own type constructors still refuse to encode (lying length field, undefined frame type, reserved bits, oversized padding) | Only inside the deliberately-malformed research path; never for the well-formed proxy path, which stays on `h2` end to end. |
| One HPACK crate, if `h2 unstable`'s exposed `Codec` turns out not to expose header (de)compression directly usable outside a full `h2::Connection` | TBD — do not add speculatively | Only if the phase-4 spike (see Gaps) shows `h2 unstable` can't be driven for standalone frame-level HPACK; then reach for `fluke-hpack` (actively forked/maintained lineage, last release ~1 year ago per crates.io) over `httlib-hpack` (~5 years stale). |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `cargo add extism@1.30 wasmtime@47.0` (or pin via workspace deps) | Add plugin-host deps | `wasmtime` will already be pulled in transitively by `extism`; only add it directly if a later phase needs raw Component Model APIs extism's high-level surface doesn't cover. |
| `cargo add h2 --features unstable` in the crate that needs frame-level access only (e.g. a new `crates/http2` or inside `proxy`) | Enable frame-level HTTP/2 access | Keep `unstable` scoped to the smallest crate possible — it is explicitly "no backwards-compatibility guarantee," so isolate the blast radius of a future breaking `h2` release. |

## Installation

```toml
# workspace Cargo.toml [workspace.dependencies] additions
memmap2 = "0.9"
extism = "1.30"
rhai = { version = "1.25", default-features = false, features = ["sync"] }  # "sync" only if plugin/eval runs off the tokio worker pool from multiple threads
boa_engine = "0.21"
rmcp = { version = "2.2", features = ["server", "transport-streamable-http-server"] }  # exact feature names to confirm against rmcp's feature table at implementation time
h2 = { version = "0.4", features = ["unstable"] }  # scope this feature to the one crate that needs raw frames
```

```bash
# per-crate additions, e.g.:
cd crates/core && cargo add memmap2
cd crates/plugins && cargo add extism wasmtime
cd crates/proxy && cargo add h2 --features unstable   # or a new crates/http2
cd crates/core && cargo add rhai --no-default-features --features sync
cd crates/tools && cargo add boa_engine
cd crates/web && cargo add rmcp --features server,transport-streamable-http-server
```

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| `memmap2` + segmented, never-remapped files | One growing `MmapMut` with `remap(may_move: true)` | Never, for this project. `remap` can move the mapping; every `Bytes` built from the old base pointer is left dangling. This is the exact class of bug the project explicitly wants to avoid (see Constraints in PROJECT.md: "never clone a body," judged on memory correctness). Segments sidestep the hazard entirely by never remapping a mapping something else already holds slices into. |
| `extism` (in-process, WASM) as primary plugin host | `wasmtime`/`wasmer` directly, hand-rolling the host-call ABI | If plugin authors will only ever write Rust and the team wants full Component Model control (typed interfaces, resource types) rather than extism's bytes-in/bytes-out convention. Costs: reinventing extism's PDK ergonomics, memory limiters, and host-function linking from scratch. Not recommended here — extism exists precisely to avoid this. |
| `extism` | `wasmer` as the runtime | If native-code AOT compilation to a portable serialized artifact, or WASIX (threads/sockets), becomes a hard requirement. Wasmer is a lower-level "universal runtime," not a plugin framework — you'd still build extism-equivalent bytes-in/bytes-out plumbing yourself. Not recommended as a replacement for extism; only as an alternative backend if extism's default wasmtime backend becomes a bottleneck (extism supports pluggable backends). |
| A JSON-RPC/stdio child-process plugin host, run **alongside** extism for Python and "real interpreter" plugins | JSON-RPC child process as the *only* plugin mechanism | If TypeScript/Python plugin support is a hard requirement from day one and the team does not want to maintain two plugin runtimes. See "Plugin Host — Decision" for why this project's stated requirement (TS/Python plugins) argues for at least a hybrid, not extism alone. |
| `h2` + `unstable` feature, hand-rolled raw frame bytes only where `h2`'s constructors refuse | Hand-roll the entire HTTP/2 frame + HPACK layer | If `h2 unstable`'s exposed types turn out (after the phase-4 spike) to still validate away every malformation of interest, forcing a full bypass anyway. Even then, prefer reusing an HPACK crate (`fluke-hpack`) for the *decode* side over hand-rolling Huffman decompression of attacker-controlled bytes — same argument as `flate2`. |
| `rhai` | `mlua`/Luau | If the team later prefers Lua familiarity over Rhai's Rust-flavored syntax, or needs Luau's native sandboxing primitives (`Lua::sandbox()`). Rhai's own sandboxing (`set_max_operations`, `set_max_call_levels`, `disable_symbol`) is adequate and it's already the PROJECT.md incumbent — no reason found in this research to switch. |
| `boa_engine` | `rquickjs` (bindings to C QuickJS) | If test262 conformance for a specific missing boa feature is a hard blocker and the project were willing to take on a C dependency. Not recommended here: the project already made an explicit, documented decision (`flate2` pinned to `rust_backend`/`miniz_oxide`) to avoid a `cc` build dependency wherever a pure-Rust option is credible. `rquickjs` breaks that consistency; `boa_engine` (pure Rust, ~95.5% test262) doesn't. |
| `boa_engine` | `deno_core`/`rusty_v8` | If real-world JS spec/API compatibility (not just test262) is a hard requirement — e.g. running actual minified production JS bundles that lean on V8-specific behavior. Costs: V8 is 600k+ LOC of C++, historically ~30-minute builds from source (mitigated somewhat by rusty_v8's prebuilt static libs), and the heaviest binary footprint of the three options. Given DOM/JS analysis is explicitly sequenced *last* in PROJECT.md (lowest priority, most likely to get cut or descoped), the lighter, pure-Rust option is the better default; escalate to V8 only if boa's conformance gaps concretely block a specific test case. |
| `rmcp` | Hand-rolled JSON-RPC over the existing axum app | If MCP's spec surface were trivial (it isn't — see "MCP Server — Decision"). Not recommended. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| A single ever-growing `MmapMut` that gets `remap()`-ed as the store grows | `remap` can move the mapping; every previously-issued `Bytes`/slice pointing at the old address becomes a dangling pointer the moment that happens. This is UB, not a panic — it can silently return garbage bytes into an active BCheck evaluation or Repeater tab. | Fixed-size, immutable, rolling segments (see Architecture Notes) — the same shape as Kafka's log segments and the pattern the Rust crates `commitlog`/`seglog` already implement. |
| `MmapMut` for the *write* path in general | Writing through a mutable mapping ties torn-write/durability/flush semantics to page-cache behavior the OS controls, not you — exactly the caution the "Are You Sure You Want to Use MMAP in Your DBMS?" literature (and sled's own move away from mmap) is about. | Append with ordinary buffered `File` writes to the currently-open segment; only mmap a segment **read-only**, after it is sealed (full or explicitly rotated) and its bytes are therefore immutable. This removes torn-write and flush-ordering concerns from the design outright — there is nothing to tear if nothing is written through the mapping. |
| Embedding a JVM for the plugin host | Explicitly rejected in PROJECT.md already; restating here only to record that nothing in this research reopens it — no JVM-embedding crate approaches WASM or a child process on sandboxing, binary size, or build complexity for this use case. | `extism` (in-process) + a JSON-RPC child process (for Python and other non-WASM-PDK languages) |
| `extism` (or any WASM plugin host) as the *sole* plugin mechanism if Python plugin support is a real, near-term requirement | Extism's official PDK list (extism.org/docs/concepts/pdk) is Rust, JavaScript, Go, Haskell, AssemblyScript, C, Zig, .NET — **no Python**, and every PDK including JS compiles to a `.wasm` binary; there is no interpreted/native execution path. A Python plugin author gets nothing from the WASM path today. | A JSON-RPC (or gRPC) child-process plugin protocol run in parallel, so Python (and any other language) gets a real interpreter as a subprocess, at the cost of process-boundary IPC instead of in-process calls. |
| `hyperium/h2` in its default (stable) feature set, for the malformed-frame research capability | `h2`'s frame module is deliberately private in the stable API; GitHub issue #294 ("Allow access to low-level API to facilitate custom protocols") has been open for years asking for exactly this and remains unresolved. Stable `h2` will not let a caller construct or transmit a syntactically-invalid frame — correct behavior for a compliant client/server, disqualifying for this specific feature. | `h2` with `unstable` cargo feature enabled (exposes `h2::frame` and `Codec` at the crate root) for the frame-level primitives, falling back to hand-written raw bytes only where `h2`'s own frame constructors still enforce structural invariants you need to violate. |
| Any high-level, "batteries-included" HTTP/2 abstraction (e.g. building this feature on top of `hyper`'s h2 support, or `reqwest`) | These sit a layer above `h2` specifically to hide framing details — the opposite of what's needed here. | Depend on `h2` directly (already true for well-formed h2 support) rather than through `hyper`. |
| `rhai`'s `unchecked` feature | Strips `set_max_operations`/`set_max_call_levels`/size-limit enforcement for raw speed — turns a sandboxed expression language into an arbitrary-compute footgun evaluated once per proxied message, i.e. per attacker-influenced traffic item. | Leave checks enabled; compile expressions to `AST` once and reuse across messages (see Expression Language — Decision) to recover the speed `unchecked` would have bought, without giving it up on safety. |
| `rquickjs` or `deno_core`/V8 as the *default* JS engine | Both pull in a C/C++ toolchain dependency (`cc` build step for QuickJS; V8's own from-scratch-or-prebuilt build system), inconsistent with this project's documented preference (see `flate2` `rust_backend` pin) for avoiding a `cc` dependency wherever a pure-Rust option is credible. | `boa_engine` as default; treat V8 as an escalation path only if a specific, named boa conformance gap blocks a specific DOM/JS test case (unlikely to be worth it given DOM/JS analysis is explicitly the lowest-priority, last-sequenced item in PROJECT.md). |
| Hand-rolling MCP's JSON-RPC framing, capability negotiation, and resource/tool/prompt schema plumbing directly on axum | This is exactly the "genuinely hard, worth a dependency" side of the project's own stated bar — MCP is a versioned protocol with capability negotiation, multiple transport modes (stdio, SSE, streamable HTTP), and a JSON-RPC method surface that changes across spec revisions (rmcp itself has both a stable 2.x and a churning 3.0.0-beta line). Getting session/capability negotiation subtly wrong isn't a memory-safety bug, but it is exactly the kind of protocol-compliance surface a hand roll reliably drifts out of sync with. | `rmcp` 2.2.0, mounted via `StreamableHttpService` (a `tower::Service`) onto the existing `burpsy-web` `axum::Router`. |

## Stack Patterns by Variant

**If the mmap store must survive external truncation/corruption of the on-disk file without corrupting the process:**
- Treat `SIGBUS` as a hard operational fact: if another process (or a bug) truncates a segment file while it's mapped and something reads past the new EOF, the OS delivers `SIGBUS`, which is **not** a Rust panic and is not catchable by normal `unsafe`-block auditing — it terminates the process. Mitigate by opening segment files with an exclusive lock (or at minimum, by owning the directory and never memory-mapping a file this process didn't create/seal itself) rather than trying to catch the signal.
- Preallocate (or `ftruncate`) each segment to its fixed target size before mapping, so "growth" never happens to a live mapping — a segment is either being appended-to via ordinary writes (not mapped) or sealed-and-mapped (never written to again).

**If plugin authors will realistically want Python and TypeScript, not just Rust:**
- Do not pick WASM (extism or otherwise) as the sole mechanism. Ship both: `extism` for in-process, Rust/Go/AssemblyScript-authored (and JS-PDK-compiled) plugins where startup latency and sandboxing strength matter most (e.g. per-message filter hooks), and a JSON-RPC (stdio or local-socket) child-process protocol for anything that needs a real, unrestricted interpreter (Python via CPython, or "just run your existing Node/TS project" without a WASM compile step). This is a legitimate hybrid, not scope creep — it directly answers the question's explicit TS/Python requirement, which extism alone cannot.

**If the malformed-HTTP/2-frame research feature turns out to need HPACK-level malformation (not just frame-header malformation):**
- Prefer reusing `h2 unstable`'s own HPACK implementation for the *decode* side (parsing what a server sends back) — that is untrusted-bytes decompression, the same memory-safety argument that justifies `flate2`. Only take on a standalone HPACK crate (`fluke-hpack`) if a phase-4 spike shows `h2 unstable` cannot be driven headless of a full `h2::Connection`.

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `rmcp` 2.2.0 | `axum` 0.8, `http` 1.x, `tower-service` 0.3 | Verified directly against `rmcp`'s own `crates/rmcp/Cargo.toml` on GitHub: it declares `axum = "0.8"` (dev-dependency, features `http1`, `tokio`) plus `http = "1"` and `tower-service = "0.3"` as optional deps for its transport layer — an exact match to burpsy's existing `axum 0.8`. No version bridging needed. |
| `rmcp` 2.2.0 vs `rmcp` 3.0.0-beta.2 | Pin-and-watch | A 3.0.0 pre-release is already circulating alongside the 2.x stable line — treat this as active API churn upstream. Pin `2.2` explicitly (not `2`) and revisit before any milestone that touches the MCP surface again. |
| `bytes` 1.12.1 | `memmap2` 0.9.11 | Direct interface dependency confirmed both directions: `memmap2::Mmap` implements `AsRef<[u8]> + Send + Sync + 'static` (docs.rs), which is exactly what `Bytes::from_owner<T: AsRef<[u8]> + Send + 'static>` requires — pass the `Mmap` itself, not an `Arc<Mmap>` (`Arc<T>` is `AsRef<T>`, not `AsRef<[u8]>`, so wrapping in `Arc` first would not satisfy the bound without an extra newtype). Confirm the exact `bytes` version already in `Cargo.lock` has `from_owner` (it should, at 1.12.1). |
| `h2` 0.4.15 `unstable` feature | `h2` releases generally | Cargo.toml's own doc comment: "no backwards compatibility guarantees" on anything gated by `unstable`. Isolate usage to the smallest possible crate/module so a breaking upstream `h2` release has minimal blast radius. |
| `extism` 1.30.0 | `wasmtime` (pulled in transitively) | Do not also pin a conflicting direct `wasmtime` version — let `extism`'s Cargo.toml drive the wasmtime version unless a specific need for a newer/older wasmtime is identified. |

## Sources

- crates.io registry API (direct fetch, canonical version/release-date source) — `memmap2`, `bytes`, `rhai`, `wasmtime`, `wasmer`, `extism`, `h2`, `boa_engine`, `rquickjs`, `rmcp`. Confidence: MEDIUM (verified provider tier per this project's classify-confidence seam; registry API responses are authoritative for version numbers specifically).
- docs.rs `bytes::Bytes::from_owner` and `memmap2::Mmap` trait list — direct fetches confirming the `from_owner` signature and that `Mmap: AsRef<[u8]> + Send + Sync` (so no `Arc` wrapper is needed). MEDIUM.
- GitHub `hyperium/h2` `Cargo.toml` and `src/lib.rs` (raw source fetch) — confirms `unstable` feature gates `frame` module and `Codec`/`SendError`/`UserError` exports. MEDIUM. **Not fully verified:** whether `h2 unstable`'s own frame constructors still enforce per-type structural invariants that would block genuinely malformed encodes — flagged as a Gap below.
- GitHub `hyperium/h2` issue #294 ("Allow access to low-level API to facilitate custom protocols") — corroborated across two independent search passes; long-open, unresolved. MEDIUM.
- extism.org `/docs/concepts/pdk` (direct fetch) — official PDK language list, confirms no Python PDK and WASM-compile-only model for all PDKs including JS. MEDIUM.
- GitHub `modelcontextprotocol/rust-sdk` `crates/rmcp/Cargo.toml` (raw source fetch) — confirms axum 0.8 dev-dependency and transport-layer deps. MEDIUM.
- Cloudflare `h3i` (docs.rs, blog.cloudflare.com) — corroborates the "hand-roll a deliberately-rule-bending frame sender alongside a compliant crate" pattern as proven prior art (HTTP/3 case), not HTTP/2-specific. LOW-MEDIUM (single-vendor source, but directly on-point and technically detailed).
- Web search corroboration (multiple independent queries, LOW individually, MEDIUM where 2+ independent results agreed) — `redb`/`sled`/LMDB mmap-database design tradeoffs, Kafka/`commitlog`/`seglog` segmented-log pattern, `wasmtime` vs `wasmer` vs `extism` positioning, `rhai` sandboxing primitives (`set_max_operations`, `set_max_call_levels`), `boa_engine` ~95.5% test262 conformance, `rquickjs`/`deno_core` build-cost characteristics, `fluke-hpack`/`loona-hpack`/`httlib-hpack` maintenance signal.
- Context7 MCP tools and the `ctx7` CLI fallback were both unavailable in this environment (checked and confirmed absent) — every finding above went through direct crates.io/GitHub/docs.rs fetches or web search instead. This is why overall confidence is capped at MEDIUM rather than HIGH: no item here has Context7-tier (first-party curated docs) provenance.

---

## Decision Detail (supporting the tables above)

### Mmap Store — Decision

**Recommendation:** `memmap2` 0.9.11, used only to map **sealed, read-only, fixed-size segment files**; live writes go through ordinary buffered `File::write` on the currently-open segment, which is not memory-mapped while it's being written to. Once per **sealed** segment, wrap its `Mmap` directly in `Bytes::from_owner(mmap)` (no `Arc` needed — `Mmap` already satisfies `AsRef<[u8]> + Send + 'static`, and `from_owner` does the refcounting internally). Every `Span` whose data lives in that segment then resolves via `segment_bytes.slice(span.offset..span.offset + span.len)` — a cheap refcount bump on the one `Bytes`, not a fresh mapping or allocation per span. This keeps the existing `Span{offset,len}` + `Bytes` API completely unchanged from the caller's perspective.

**The active (not-yet-sealed) segment's read path is a second, deliberately different code path.** A request captured a second ago must be immediately readable (proxy history, live view) even though its segment isn't sealed or mapped yet. Resolve spans into the active segment from the in-memory `Bytes` buffer the writer already holds (the same buffered-write path that's about to be flushed to disk) — not from a mapping. Only once a segment is sealed does span resolution for that segment's data switch over to the mmap-backed `Bytes::from_owner` path described above. `TrafficStore` needs an explicit id → (segment, is-sealed, request-span, response-span) index that tracks which of the two paths applies per segment; this index is also the direct fix for the linear-scan `set_response` problem named in PROJECT.md (see below), not an incidental side effect.

**This is the concrete fix for the debt PROJECT.md names as the mmap store's own justification:** `TrafficStore::set_response` is currently a linear scan because responses arrive after requests and there's no O(1) way to find "the request this response belongs to." The id → (segment, request span, response span) index above *is* that O(1) lookup — replacing the scan is a direct consequence of the index this design already needs for segment/seal-state tracking, not separate work.

**Why this shape, not one growing mapping:** `memmap2::MmapMut::remap` can move the mapping in virtual memory (`RemapOptions::may_move`); every previously-issued slice or `Bytes` built from the old base address is then dangling. This is a genuine correctness hazard (UB, not a panic) directly at odds with the project's stated performance/correctness bar ("never clone a body," judged on memory correctness for the whole subsystem). LMDB's own well-known answer to this is to reserve a large fixed virtual-address `mapsize` up front and never remap; Kafka's answer (and the Rust `commitlog`/`seglog` crates that already implement this shape) is fixed-size rolling segments, each mapped once and never touched again once sealed. Segments are the better fit here because the store is genuinely unbounded (multi-GB captures is the explicit goal) where a single fixed `mapsize` would eventually need the same "stop the world and reopen" LMDB has to do anyway — segmenting gets that property for free, incrementally, without a stop-the-world step.

**Correctness hazards to design around, in order of severity:**
1. **Remap invalidates outstanding slices** — solved by never remapping (segments, sealed-then-mapped).
2. **Torn writes / durability** — solved by never writing *through* a mapping; writes are ordinary buffered file I/O to the not-yet-mapped active segment, so there is nothing to tear via mmap semantics. Durability (fsync timing) becomes an ordinary buffered-I/O concern, already well understood elsewhere in the codebase, not a new mmap-specific one.
3. **SIGBUS on external truncation** — mmap's fundamental hazard: if the backing file shrinks (or the containing filesystem/device fails) while mapped, an access past the new EOF delivers `SIGBUS`, which kills the process and cannot be caught the way a Rust panic can. Mitigate by exclusive ownership of segment files (only this process creates/truncates/deletes them) rather than trying to handle the signal.
4. **Platform differences** — `memmap2` abstracts Unix `mmap`/Windows `MapViewOfFile` adequately for the read-only-after-seal use case; the main platform-sensitive knob (huge pages, `MAP_POPULATE`-equivalent) is a tuning question, not a correctness one, and can be deferred.

**Hand-roll-vs-dependency:** `memmap2` itself — dependency (wrapping raw OS mmap syscalls safely is exactly the "getting it wrong is a memory-safety bug" case). The segment-rotation/sealing logic and the id → (segment, spans) index on top of it — hand-roll (it's workspace-specific bookkeeping — a few hundred lines, not a general-purpose problem worth a crate). Do not add `commitlog` or `seglog` as dependencies; they were surfaced as *pattern* references (proven design to copy), not as recommended crates — both are far less downloaded/maintained than `memmap2` itself and burpsy's `Span`/index format is already bespoke, so adopting a full third-party log-storage crate would mean conforming to its record format rather than reusing the project's own.

### Plugin Host — Decision

**Recommendation:** Two-tier plugin host, not a single winner:
- **`extism` 1.30.0** (in-process, WASM, wraps `wasmtime` by default) for plugins authored in Rust, Go, AssemblyScript, C, Zig, .NET, or JS/TS-compiled-to-WASM via the JS PDK, where in-process latency and extism's built-in memory/operation limiters matter most (e.g. a per-message filter/highlight hook called on every proxied item).
- **A JSON-RPC child-process protocol** (stdio or local Unix socket, hand-rolled JSON-RPC framing over the existing `serde_json` dependency — this is squarely the hand-roll side of the bar, since JSON-RPC 2.0 framing is trivial and there is no untrusted-bytes memory-safety exposure in implementing it) for Python plugins and any plugin that wants a real, unrestricted interpreter rather than a WASM-compiled subset of its language.

**Build order:** ship `extism` first. The nearer-term, higher-frequency need described in PROJECT.md is a per-message filter/highlight hook (Bambda-adjacent), which is exactly extism's sweet spot (in-process, low per-call latency, built-in limiters) and covers Rust/Go/AssemblyScript/JS-via-PDK authors immediately. Add the JSON-RPC child-process tier as a follow-on once a concrete Python (or "run my existing Node project unmodified") plugin use case is actually in front of the team — it's a materially bigger, separately-scoped piece of work (process lifecycle, IPC framing, crash isolation) that shouldn't block the first, narrower win. If Python plugin support is *already* a named near-term requirement rather than a future one, invert this order.

**Why not extism alone:** Extism's official PDK list (Rust, JavaScript, Go, Haskell, AssemblyScript, C, Zig, .NET) has no Python entry, and every PDK — including JavaScript — works by compiling the plugin to a `.wasm` artifact ahead of time; there is no path to running an existing, unmodified Python (or arbitrary Node) codebase as an extism plugin. The question explicitly names "plugins written in TypeScript/Python," and Python specifically has no WASM story here at all. A child process closes that gap completely (real CPython, real Node) at the cost of IPC instead of in-process calls — the standard tradeoff, and the same one mitmproxy (Python-native addons) and Caido (in-process JS backend for its plugin runtime) each resolved in their own single-language-optimized way; this project's requirement spans both worlds, so it needs both mechanisms.

**Why `extism` over raw `wasmtime`/`wasmer` for the WASM tier:** Extism is a high-level layer *on top of* wasmtime (its default backend) specifically providing the plumbing this project would otherwise have to build itself: a bytes-in/bytes-out host-call convention, multi-language PDKs, persistent plugin-scoped state, HTTP allowlisting without full WASI, and built-in operation/memory limiters. Building that directly on `wasmtime` means re-deriving all of it. `wasmer` is a comparable-tier low-level runtime (not a plugin framework) with a different philosophy (WASIX, native-code AOT, "forget the runtime exists" ergonomics) — a credible `wasmtime` alternative if extism's default backend becomes a bottleneck (extism supports swapping backends), but not itself a reason to skip extism.

**Known cost regardless of runtime choice:** every message handed across the host↔guest WASM boundary is a copy — WASM linear memory cannot alias host `Bytes` without copying. This is real friction against the project's zero-copy design principle, unavoidable for the WASM tier specifically (not a reason to avoid WASM plugins, since the alternative — a JIT-compiled native plugin ABI — reopens the JVM-style embedding problem this milestone explicitly rejects; just something to budget for when sizing the phase: expect one copy per message per active WASM plugin hook, not zero).

**Confidence:** MEDIUM. The PDK-language and bytes-in/bytes-out claims are direct-fetch verified against extism.org; the wasmtime-vs-wasmer positioning is corroborated web search, not primary-source.

### HTTP/2 — Decision

**Recommendation:** `h2` 0.4.15 for all well-formed HTTP/2 traffic (client and server sides of the proxy), with the `unstable` Cargo feature enabled specifically for the malformed-frame research capability, scoped to the smallest crate that needs it.

**Why not stable `h2` for the research feature:** `h2`'s frame module is deliberately private in the default feature set. GitHub issue #294 ("Allow access to low-level API to facilitate custom protocols") has requested exactly this capability for years and remains open/unresolved — `h2` will not let a caller construct or transmit a frame that violates its own type invariants. That's correct behavior for a compliant implementation and precisely why it's unusable, unmodified, for deliberately-malformed-frame testing.

**Why `unstable` rather than hand-rolling the whole layer:** Verified directly against `h2`'s own `Cargo.toml` and `src/lib.rs` on GitHub — the `unstable` feature makes the `frame` module and `Codec`/`SendError`/`UserError` public at the crate root. This gives frame-level read/write while reusing `h2`'s own HPACK implementation for the *decode* side (parsing what a server sends back) — the genuinely hard, attacker/server-controlled-bytes decompression job, same bar as `flate2`. Building a fresh, correct HPACK Huffman decoder from scratch to avoid depending on `h2 unstable` would be taking on real memory-safety risk for no benefit, since the dependency is already there.

**Open verification (flag for the implementing phase):** it is not yet confirmed whether `h2 unstable`'s own frame-type constructors still enforce structural invariants that would block the *specific* malformations request-smuggling research needs (a length field that lies about payload size, an undefined frame-type byte, reserved bits set, oversized padding). If they do — likely, since these are basic wire-format invariants, not protocol-semantic ones — the plan needs a small, explicitly-scoped raw-byte writer (a ~10-line, 9-byte-frame-header serializer) that writes directly to the same `AsyncWrite` the unstable `Codec` uses, for exactly the fields that must be lied about. This is squarely hand-roll territory: it only ever *sends* deliberately-wrong bytes (no untrusted-input parsing), so getting it "wrong" produces a differently-malformed packet, not a memory-safety bug. Cloudflare's `h3i` (built on `quiche`, for HTTP/3) is the direct design precedent for this exact pattern — "bend RFC rules to test server behavior" as a deliberate library feature — confirming this is proven prior art, not an invented approach; there is no HTTP/2-specific equivalent tool in the Rust ecosystem, which is why it has to be built here rather than borrowed.

**Confidence:** MEDIUM. The `unstable`-feature-exposes-`frame`-module claim is source-verified; the depth of remaining structural validation inside those exposed constructors is not, and is called out as a Gap.

### Expression Language — Decision

**Recommendation:** `rhai` 1.25.1 — confirms the PROJECT.md incumbent suggestion; nothing in this research surfaced a reason to switch.

**Sandboxing:** Real and built-in, not bolted on: `Engine::set_max_operations` bounds total operations per evaluation (stops infinite loops), `Engine::set_max_call_levels` bounds recursion depth (default 64, 8 in debug builds), plus size limits on strings/arrays/maps, and `disable_symbol` to remove specific builtins. No file or network I/O is available to a script unless the host explicitly registers a function for it — this project should register none beyond whatever message-inspection accessors the filter/highlight feature needs. **Do not enable the `unchecked` feature** — it strips every one of these checks for raw speed, which is precisely wrong for an expression evaluated once per attacker-influenced proxied message.

**Per-message evaluation speed (the actual open question, not just sandboxing):** Rhai is a tree-walking interpreter — this research did not find published per-message-scale benchmarks specific to a filter/highlight workload, so treat "fast enough per message" as unverified until measured against real traffic volume in the implementing phase. The mitigating pattern, consistent with the existing "passive scanning off the proxy hot path" architectural decision already in PROJECT.md: (1) compile each user-defined expression to a Rhai `AST` once when the filter is saved/edited, never per message; (2) reuse a prepared `Scope` across evaluations rather than rebuilding it; (3) put cheap native predicates (host, status, method, MIME — already a separate table-stakes requirement in PROJECT.md's Active list) in front of Rhai evaluation as a short-circuiting fast path, so Rhai only runs for messages that need the genuinely arbitrary Bambda-style expression, not for every message unconditionally.

**Hand-roll-vs-dependency:** Dependency, clearly. A sandboxed general expression language with recursion/operation limits is exactly the kind of "genuinely hard to get right, and getting it wrong is a security bug (arbitrary compute/DoS on attacker-influenced input), not a memory-safety bug" case this project already takes dependencies for (mirroring the `flate2` reasoning, just for CPU/DoS safety rather than memory safety).

### JS Engine — Decision

**Recommendation:** `boa_engine` 0.21.1 as the default/only JS engine for DOM/JS analysis.

**Why:** Pure Rust, ~95.5% test262 (ECMAScript conformance test suite) pass rate — comparable to production browser engines — and it embeds with a plain `cargo build`, no C/C++ toolchain step. This is directly consistent with a decision already made elsewhere in this codebase: `crates/tools/Cargo.toml` pins `flate2` to `default-features = false, features = ["rust_backend"]` specifically so a future `flate2` default change "cannot silently pull in a `cc` build dependency." `rquickjs` (bindings to the C QuickJS engine, 0.12.1, very high spec coverage, small footprint) and `deno_core`/`rusty_v8` (full real-world V8 compatibility, 600k+ LOC of C++, historically ~30-minute builds even with prebuilt static libs mitigating most of that) both reintroduce exactly the C/C++ build dependency this project has already decided to avoid. Given DOM/JS analysis is explicitly sequenced *last* in PROJECT.md ("Deferred within this milestone, by sequence" — lowest priority, most likely candidate to shrink or slip), the lighter, consistency-preserving choice is the right default; escalate to `rquickjs` or V8 only if a specific, named boa conformance gap concretely blocks a specific analysis case, not preemptively.

**Scope-sizing fact for the roadmap:** none of `boa_engine`, `rquickjs`, or `deno_core` ship a DOM. "DOM/JS analysis" needs a DOM/BOM shim (a `document`/`window`-shaped host API implemented against the chosen engine's embedding surface) regardless of which JS engine is picked — that shim is a separate, non-trivial piece of scope this research did not find an off-the-shelf Rust crate for, and the phase that builds it should be sized assuming it's built here, not imported.

**Confidence:** MEDIUM. Version and test262 figures are corroborated across multiple sources; the DOM-shim-is-not-included fact is a reasoned inference from what each engine's own docs describe as in-scope (a JS engine, not a browser), not a directly-quoted claim from a single source.

### MCP Server — Decision

**Recommendation:** `rmcp` 2.2.0, the official Rust SDK (`modelcontextprotocol/rust-sdk`), mounted onto the existing `burpsy-web` `axum::Router` via its `StreamableHttpService` (a `tower::Service`), rather than hand-rolling MCP on top of the existing JSON API.

**Why take the dependency:** the JSON-RPC framing itself is trivial (this project already hand-rolls comparably-sized codecs like base64) — but MCP is not just JSON-RPC framing. It's a versioned protocol with capability negotiation, multiple transport modes (stdio, SSE, streamable HTTP), and a tool/resource/prompt schema surface that has already moved across major spec revisions (evidenced by `rmcp` itself currently shipping both a stable `2.2.0` and a churning `3.0.0-beta.2`). Tracking that drift correctly over time is the genuinely-hard, dependency-justifying part — same shape of argument as `flate2`, just for protocol-compliance drift instead of memory safety.

**Compatibility, verified not assumed:** `rmcp`'s own `crates/rmcp/Cargo.toml` (fetched directly from GitHub) declares `axum = "0.8"` as a dev-dependency with `http1`/`tokio` features, plus `http = "1"` and `tower-service = "0.3"` as optional transport-layer deps — an exact match against burpsy's existing `axum 0.8`. No version-bridging shim is needed to mount `rmcp`'s service on the existing router.

**Watch item:** pin `rmcp = "2.2"` explicitly (not a bare `2` or `*`) given the `3.0.0-beta.2` pre-release already circulating — revisit the pin the next time the MCP surface is touched, rather than floating onto a beta by accident.

**Confidence:** MEDIUM-HIGH on the "take the dependency, use rmcp" call and the axum-version-compatibility claim (both source-verified); MEDIUM on "which rmcp features/transport exactly" since the exact Cargo feature names for `StreamableHttpService` weren't enumerated from primary source in this pass and should be confirmed against rmcp's docs.rs feature list at implementation time.

## Gaps to Address (implementation-phase spikes, not blocking the roadmap)

- **h2 `unstable` frame-constructor validation depth.** Confirmed `unstable` exposes `h2::frame`/`Codec` publicly; not confirmed how much structural malformation those exposed constructors still refuse to encode. Needs a small spike before committing the phase plan to "h2 unstable handles X% of the malformed-frame surface."
- **Exact `rmcp` Cargo feature names** for the streamable-HTTP transport (used a plausible name, `transport-streamable-http-server`, above — confirm against rmcp's published feature table before writing it into a phase plan).
- **Rhai per-message throughput** at the traffic volumes this project targets (multi-GB captures) — no benchmark found specific to this workload shape; needs measurement, not just a sandboxing check, before sizing the phase.
- **Segment size and rotation policy** for the mmap store (this research established the *pattern* — fixed-size, sealed, never-remapped segments — but not a specific segment-size number for burpsy's traffic profile; that's a phase-4 design decision, not a stack decision).

---
*Stack research for: Rust web-application-security testing platform — platform/plugin milestone*
*Researched: 2026-07-27*
