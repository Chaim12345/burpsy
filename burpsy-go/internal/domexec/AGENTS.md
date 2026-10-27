<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# domexec

## Purpose

A headless-Chrome DOM taint-observation harness for scanner checks that cannot be answered
from the raw HTTP exchange alone. About forty declined catalog rows (DOM-based XSS, DOM-based
open redirection, WebSocket URL poisoning, HTML5 storage / cookie / document-domain
manipulation, client-side SQL/XPath/JSON injection, prototype pollution, DOM-based DoS) share
one decline reason: they need a real browser to observe what a page's own script does with
attacker-controlled data *after* the parser and JS engine run. This package supplies that
runtime. It is a **taint harness, not a payload library**: it plants a canary in a chosen
controllable DOM source, loads the page under real Chrome (via chromedp), and reports every
instrumented sink call whose argument contained the canary. It answers only "did
attacker-controlled data reach a dangerous sink at runtime" — whether that constitutes an
exploitable finding is the caller's decision.

There is no matching Rust crate; this is a Go-only capability that exists to reclaim declined
rows the HTTP-only scanner cannot reach.

## Key Files

| File | Description |
|------|-------------|
| `browser.go` | `Browser` lifecycle: Chrome path resolution, launch, per-tab isolation, `Available`/`Close`. Owns the chromedp allocator and browser contexts |
| `taint.go` | The taint model: `SourceKind`/`SinkKind` enums, `instrumentationJS`, `ObserveTaint`, `RenderedDOM`, `ObservationsForSink`. This is where the sink wrappers and the navigation-based location observer live |
| `browser_test.go` | Browser launch / lifecycle tests |
| `newsinks_test.go` | Tests for the later-added sink families (WebSQL, XPath, JSON.parse, anchor.href, RegExp, FileReader, prototype pollution) |

## For AI Agents

- **The honest-failure contract is the whole point.** `NewBrowser` returns an error naming the
  binaries it searched (`chromium`, `google-chrome`, `google-chrome-stable`, or an explicit
  `Options.ChromePath`) when no Chrome is found. A caller MUST surface that as "no DOM
  execution available" and MUST NOT report a clean, zero-finding result: zero observations from
  a working browser and zero because there was no browser are different facts.
- **A sink this harness does not wrap produces zero observations — that is a false negative, not
  proof of safety.** `sinkTags` in `taint.go` is the authoritative list; keep it in sync with
  the JS-side tags `instrumentationJS` pushes onto `window.__burpsyTaint`.
- **`SinkLocationAssign` is deliberately absent from `sinkTags`.** Bare `location = x` cannot
  be intercepted by a JS property override in this Chrome build, so it is observed a different
  way: `ObserveTaint` watches CDP frame-navigation events (`EventFrameNavigated` with empty
  `ParentID`, and `EventNavigatedWithinDocument`) for a main-frame navigation, distinct from
  the one this call itself issued, whose URL contains the canary.
- **The planted navigation must not be reported as a flow.** `sameNavigation` canonicalises
  before comparing (empty path vs `/`) because CDP normalises URLs; an exact string compare
  previously made every hash-probed page report a spurious DOM open redirection.
- **`NewBrowser` warms the browser with a no-op `Run` so launch failure surfaces at
  construction, not at first use.** The startup timeout is a timer *beside* the Run, never a
  context derived from `browserCtx` — deriving it and `defer cancel()` tore the browser down
  the instant `NewBrowser` returned, producing the worst failure shape (reported success, then
  every call fails "context canceled").
- **`NoSandbox` is mandatory** because this scanner commonly runs as root in a container, where
  Chrome's sandbox refuses to initialise. The long flag set mirrors chromedp's default allocator
  options (which `NewExecAllocator` does *not* apply on its own) to skip first-run/telemetry/
  keychain machinery — pure wall-clock savings across the harness's many launches, no web-platform
  behaviour changed.
- Each observation runs in its own isolated tab (`newTab`) so concurrent or sequential calls
  never see each other's instrumentation state. `RenderedDOM` runs through the same instrumented
  pipeline on purpose: it doubles as proof the sink wrappers call through correctly.

## Testing Requirements

```bash
go test ./internal/domexec/...
```

Tests that need a real Chrome skip when none can be launched, but the skip is counted, not silent:
they skip through `domexectest.Skip`, and `TestMain` (via `domexectest.Main`) then fails the package
unless `BURPSY_ALLOW_NO_CHROME=1`. `domexectest/` is that skip ledger, shared by every package whose
tests drive a browser (domexec, dominvader, blindxss, browser, crawler, scanner, web) so none of them
can report green over tests that never ran. It imports nothing from `internal/`, so this package's
own tests can use it.

## Dependencies

No other `internal/` packages are imported — `domexec` is a leaf capability. External:
`github.com/chromedp/chromedp` and `github.com/chromedp/cdproto/page` (CDP navigation events).
