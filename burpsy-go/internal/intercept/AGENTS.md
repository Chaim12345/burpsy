<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# intercept

## Purpose

The request/response hold queue that lets an operator pause live proxy traffic, inspect it, and forward
or drop it. Two rule lists (requests and responses) decide what gets held; a held message blocks its
proxy connection until the operator resolves it, and the resolution carries the possibly-edited raw
bytes back to the proxy — the only channel through which an edited message ever reaches the wire. It is
consumed by `internal/proxy` (which calls `Hold`/`Wait` on the hot path) and `internal/web` (the API and
live-update stream). In the Rust reference this lives inside `crates/proxy/src/intercept.rs`; here it is
its own package.

## Key Files

| File | Description |
|------|-------------|
| `intercept.go` | The whole package: `Engine` (the controller), `Rule`/`List`/`Field`/`Category`/`Direction`, `Message` and `ParseMessage`, `Held` with its once-only `resolve`/`Wait`, and the raw-HTTP helpers `StatusOf`/`ContentTypeOf`/`rewriteContentLength` |
| `intercept_test.go` | Unit tests for the hold-decision states, rule matching, and content-length rewrite |

## For AI Agents

- **A list has three states, and they are distinct on purpose.** Off (`Active == false`) never holds;
  unconditional (`Active` with *no rules at all*) holds everything in that direction; on-with-rules holds
  only matching messages, and on-with-rules-but-all-disabled holds **nothing**. `Unconditional()` means
  the list is empty, not that nothing in it is enabled — unticking the last box holds nothing, only
  deleting the rows means everything. `shouldHold` encodes exactly this ladder.
- **The engine's lock is a 1-buffered channel, not a `sync.Mutex`.** `e.mu <- struct{}{}` acquires and
  `<-e.mu` releases. The change signal (`OnChange`/`signalChange`) must **never** fire with the lock held —
  a held message blocks its proxy connection, so a subscriber ordering against this lock would put its
  business ahead of the next message the proxy wants to hold. Mutators register `defer e.signalChange()`
  *before* the unlock defer so LIFO runs the signal after the unlock.
- **`Held.resolve` is once-only.** A duplicate API call (a forward/drop arriving twice) is ignored, so the
  proxy cannot act on a stale decision. `Forward`/`Drop` return an error if the message was already
  resolved, and both `delete` the entry from the hold map afterward so a long-running proxy does not leak
  one full raw message per intercepted exchange.
- **A rule whose field the direction cannot supply never matches — it is not an error.** A request has no
  status code or content type; `FieldValue` returns `""` for those and `Match` bails on an empty value. A
  response rule left in the request list is dead weight, read honestly.
- **A malformed regex is refused at save time, not at fire time.** `NewRule` and `SetRules` compile the
  pattern and return an error, leaving the list unchanged — matching Burp, which reports a bad pattern
  when the list is saved. Literal matches are case-insensitive `strings.Contains`; regex matches use the
  compiled `*regexp.Regexp`.
- **`rewriteContentLength` only touches a message that already has a `Content-Length`.** A chunked message
  or one with no `Content-Length` is returned unchanged — inventing a length for a framing the code does
  not own would corrupt the exchange. It is applied by `Forward` when `fixContentLength` is set, since
  editing a body without fixing its length produces a corrupt exchange.
- **`ParseMessage` derives response-only fields from the raw bytes.** Status and content type are filled
  only for `DirectionResponse`, via `StatusOf`/`ContentTypeOf`. `ContentTypeOf` requires the header name to
  be exactly `Content-Type` followed by a colon, so `Content-Type-Options` is not misread.

## Testing Requirements

```bash
go test ./internal/intercept/...
```

## Dependencies

### Internal

- None. The package is self-contained; the proxy and web layers depend on it, not the other way around.

### External

- stdlib only (`net/http` for `StatusText`, `regexp`, `strconv`, `strings`, `sync`, `time`)

<!-- MANUAL: -->
