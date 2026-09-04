<!-- Generated: 2026-08-25 | Updated: 2026-08-25 -->
<!-- Parent: ../AGENTS.md -->

# extension

## Purpose

The plugin host behind the EXTENDER tool tab: it runs operator-allowlisted executables as child
processes and speaks newline-delimited JSON-RPC 2.0 to them over their own stdin/stdout. It is the
substrate `ROADMAP.md` chose over embedding a JVM or a WASM runtime, and it is **not** a Montoya
implementation — there is no JVM here and nothing in this tree is binary- or source-compatible with
`MontoyaApi`, so a Burp extension cannot be pointed at burpsy. Consumed by `internal/web`
(`api_extensions.go`) and constructed in `cmd/burpsy` from the `-plugins name=path` flag. No Rust
counterpart: Phase 8 never shipped on that side.

## Key Files

| File | Description |
|------|-------------|
| `protocol.go` | The package doc (why a child process, why three registration points and not thirteen), `ProtocolVersion`, every default bound, `Kind`/`validKinds`, the wire types, and `MethodSpecs` — the documented method set the tests check against the dispatched one |
| `session.go` | One running process: `spawn`, the stdout reader and its dispatcher, the `inbound` table, `call`, the three-step `stop` (ask, close stdin, kill), `childEnv` and `passedEnv` |
| `host.go` | `Host` over the allowlist: `Load`/`Unload`/`Invoke`/`Console`/`List`/`Policy`/`Close`, the five-state model, registration validation, and the crash watcher |
| `console.go` | The bounded per-plugin output and error consoles, with attribution (`Source`) and eviction/truncation counts |
| `views.go` | The wire shapes the HTTP layer serves, and `API()` — the contract generated from `MethodSpecs` |
| `plugin_helper_test.go` | A real plugin: the test binary re-execs itself with `-test.run=^TestHelperPlugin$` and a behaviour named in the environment |
| `host_test.go` | Load/unload/crash/timeout/bounds/console/registration-refusal behaviour, driven against real processes |
| `protocol_test.go` | Parses this package's own source and fails if the documented method set and the dispatched one disagree |

## For AI Agents

- **The allowlist is the whole safety model.** A name that is not a key of `Config.Plugins` cannot be
  loaded, and no request body anywhere carries a path. This is deliberately the same gate
  `scanner.execToolRunner.Run` puts in front of a bcheck `run tool`, and `-plugins` is parsed by the same
  function as `-tools`. Never add a route or a method that takes a path.
- **Three registration kinds, and the other ten are absent on purpose.** Ten of Montoya's thirteen
  `userInterface()` registration points hand Burp a Swing object; a JSON schema for a "component" whose
  only consumer is the thing that defined it is a fiction. `KindEditorTab` is the read-only half of
  `registerHttpRequestEditorProvider` only — Burp gives that provider the caret and the live selection,
  which a request/response round trip cannot carry. Adding a fourth kind means deciding what it renders
  as, and `Test_every_registration_kind_has_exactly_one_invocation_method` will make you say so.
- **`MethodSpecs` is checked, not maintained.** Every method name passed to `session.call` is a string
  literal because `Test_the_documented_method_set_is_the_dispatched_method_set` reads those literals out
  of the source and compares them with this table — the same technique
  `internal/web/route_manifest_test.go` uses on the route manifest. A name built from a variable fails
  `Test_every_dispatched_method_name_is_a_literal` rather than quietly escaping the check.
- **Five states, because four of them are ways of not being loaded.** `unloaded` (never started or
  stopped on request), `loading`, `loaded`, `failed` (never completed the handshake) and `crashed`
  (loaded, then the process ended unasked). A `loaded bool` would render the last three identically.
  `ListView` has no total field: the five counts partition `Allowlisted` exactly, asserted by a test.
- **stdout is the transport, so "the plugin's output" cannot mean "whatever it printed".** A console line
  carries a `Source`: `plugin` (a `log` notification), `stderr`, `host` (a load/unload/crash note) or
  `protocol` (a stdout line that was not JSON-RPC). Folding any of the last three into the first would
  attribute the host's words, or a syntax error, to the plugin.
- **Nothing a child produces is unbounded, and every bound counts what it dropped.** Consoles evict
  oldest-first and report `OutputDropped`/`ErrorDropped`/`Truncated` plus the `Limit` in force; a line
  over `MaxMessageBytes` ends the session rather than being resynchronised, because after a truncated
  read the next byte could be anywhere inside a message.
- **`console` has its own mutex, deliberately not the plugin's.** The load path holds `plugin.mu` across
  a handshake that itself produces log lines; one shared lock would deadlock the first plugin that
  logged during `initialize`.
- **One reaper, and `stop` never calls `Wait`.** `os/exec` documents that `Wait` closes the pipes, so the
  reaper goroutine waits on both readers first and is the only caller; `stop` waits on `s.exited`. An
  unload returns only once the child has actually been reaped — reporting success while the process was
  still running is a lie the next load would trip over.
- **A plugin has no route to this process's traffic store, and cannot originate a request.** Message
  bytes are handed to it in the invocation. A send method would have to bind `sender.AuthorisedSender`
  per call; it is not wired, and it is declared in `UnsupportedCapabilities` rather than left silent.
- **There is no registry, store or install path,** and `PolicyView.Registry` is a nullable field holding
  null rather than an omission, so a caller reads "there is no store" instead of inferring it.

## Testing Requirements

```bash
go test ./internal/extension/...
go test -race ./internal/extension/...   # four goroutines per session; worth it here
```

The helper plugin is this test binary re-executed, so the suite needs no toolchain and no build step.
`os.Exit` at the end of every helper branch is load-bearing: without it the framework prints `PASS` on
the child's stdout and the host correctly records it as a protocol violation.

## Dependencies

### Internal

- None. The host is self-contained; `web` and `cmd/burpsy` depend on it, not the other way around.

### External

- `go.uber.org/zap` (the host's logger), stdlib otherwise (`os/exec`, `bufio`, `encoding/json`, `sync`)

<!-- MANUAL: -->
