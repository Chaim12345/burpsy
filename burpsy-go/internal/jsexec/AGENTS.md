<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# jsexec

## Purpose

A DOM-less JavaScript execution tier built on goja (pure Go, no cgo, no external binary). It is
**not a browser and cannot replace one**: goja implements ECMAScript, not the DOM — no
`document`, no `innerHTML`, no event loop, no fetch/XHR. The ~40 DOM-based declined catalog
rows are served by `internal/domexec` (real Chrome), not by this package. Building a half-DOM
over goja was considered and rejected because every unimplemented corner is a silent false
negative, and a half-DOM reporting "no findings" is worse than none — it gets mistaken for evidence.

Two jobs a real browser is the wrong tool for:

1. **Prototype pollution.** Decided by evaluating a merge/extend snippet in-process and
   inspecting `Object.prototype` before/after — no DOM required, deterministic, far cheaper than
   a browser launch, and not confoundable by unrelated page script.
2. **Graceful degradation when Chrome is absent.** On a minimal container with no browser, this
   lets a caller still evaluate an *extracted* script snippet for a source-to-sink flow — a
   strictly weaker answer that callers MUST label as such.

There is no matching Rust crate; this is Go-only.

## Key Files

| File | Description |
|------|-------------|
| `jsexec.go` | Everything: the bounded `run` harness, prototype-pollution probing (`PollutionPayloads`, `TestPrototypePollution`, `PollutionEvidence`), and DOM-less snippet source-to-sink evaluation (`EvaluateSnippet`, `SnippetSink`, `SnippetObservation`) |
| `jsexec_test.go` | Unit tests for both tiers |

## For AI Agents

- **Every entry point is bounded by construction.** Hostile script is expected input, so `run`
  executes on a goroutine with `vm.Interrupt(ErrTimeout)` on expiry — goja is single-threaded and
  a `while(true){}` would otherwise wedge the scan forever. `ErrTimeout` is a distinct, reportable
  observation about the target's code (the DOM-based DoS family), not merely a harness failure.
- **No host bindings of any kind.** `run` binds nothing onto the VM — no filesystem, network, or
  process — which is what makes running attacker-influenced script acceptable.
- **`TestPrototypePollution` proves absence before claiming pollution.** It checks the property is
  `undefined` on `Object.prototype` *before* the merge runs; if it already exists it errors out
  rather than falsely attributing pollution. It is a genuine before/after comparison, not a
  source-text pattern match — that is the entire reason to have an engine. `mergeSource` must
  evaluate to a two-argument `(target, source)` function; a merge that throws on the payload is a
  clean result for that payload, not an error.
- **`PollutionPayloads` are documented forms, not recovered Burp literals.** The `__proto__` and
  `constructor.prototype` shapes; burp.Zi2p's own table decoded to ZKM ciphertext residue, so
  there was nothing to recover.
- **`EvaluateSnippet` is strictly weaker than `domexec` and MUST be reported that way.** Its
  observable sinks are only plain globals — `eval`, `Function`, `setTimeout(string)`,
  `JSON.parse` — because without a DOM only global functions can be shimmed honestly. Anything
  touching `document`, `innerHTML`, `location.assign`, storage or `postMessage` throws or
  no-ops rather than being observed. A clean result means "no flow observed by the DOM-less tier",
  never "no DOM vulnerability".
- **The shims return `undefined` rather than executing the argument.** Actually evaluating
  attacker text in the same VM would let a snippet rewrite the shims and hide later flows. A
  snippet that throws mid-run keeps whatever was recorded before the throw — throwing is common
  without a DOM and discarding those observations would lose real flows.

## Testing Requirements

```bash
go test ./internal/jsexec/...
```

Fully in-process (no Chrome, no network), so these run everywhere.

## Dependencies

No other `internal/` packages are imported — `jsexec` is a leaf. External:
`github.com/dop251/goja` only. Positioned as the DOM-less complement to `internal/domexec`.
