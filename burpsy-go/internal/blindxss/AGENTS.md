<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# blindxss

## Purpose

A callback channel for **blind** cross-site scripting: a payload planted in one place, rendered
somewhere burpsy cannot observe (an admin panel, another user's session, a log viewer, an HTML
email client), calling home with a correlation token. A stored-XSS canary is only confirmable when
the scanner can read the page that renders it; the blind case has no response body to match
against, so the only available evidence is a callback from that browser.

This package owns a real `net/http` listener that serves a bounded capture script at a
token-carrying path and records the JSON each execution posts back.

There is no matching Rust crate; this is a Go-only capability.

## Key Files

| File | Description |
|------|-------------|
| `listener.go` | Everything stateful: `Listener` lifecycle (`NewListener`, `Close`), `Options`, the typed `BindError`, token minting, `GeneratePayload`, `HitsFor`, the `Hit` struct, and the two HTTP handlers |
| `script.go` | The served payload: the fixed `scriptTemplate`, `renderScript` substitution, and `jsonString` literal encoding |
| `listener_test.go` | Tests, including two that render a real victim page in headless Chrome via `internal/domexec` |

## For AI Agents

- **It is a sibling of `internal/oob`, not a layer on it or a replacement for it.** Both mint a
  correlation token, plant something carrying it, and poll for hits later — deliberately the same
  API shape. They differ in what the callback proves: `oob` proves a *server* reached out, so a DNS
  or bare HTTP hit suffices and it can lean on a public Interactsh instance with no listener of its
  own. `blindxss` proves a *browser rendered attacker-controlled markup as script*, which needs a
  document to execute, which means serving JavaScript, which means owning a socket. Interactsh's
  protocol has nowhere to put a JS payload or the structured page context that comes back. A check
  may reasonably use both.
- **The honest-failure contract, twice over.** A bind failure is a typed `*BindError` naming the
  address; a caller MUST surface it as "no blind-XSS channel available" and MUST NOT report a clean
  result. Separately — and this edge is specific to this channel — a hit proves execution but *no*
  hit never proves absence: the rendering browser may be offline for days, may never load the page,
  or may sit behind egress filtering. Outstanding is not clean; report it in the vocabulary
  `StoredLedger`'s `Outstanding` state uses.
- **Safety is load-bearing, not incidental.** The served script reads five properties
  (`document.cookie`, a capped `outerHTML` prefix, `location.href`, `document.referrer`,
  `navigator.userAgent`), POSTs them once, and stops. No persistence, no scheduled work, no
  handlers, no storage reads, no secondary requests, and the POST response is ignored so the
  payload has no channel to receive instructions through. It runs in a third party's browser
  session — very often a real person who is not the engagement's subject — and the only thing
  justifying that is proving the vulnerability and getting out. **Do not extend the template** with
  keylogging, session riding, screenshotting, or persistence, however easy it would be.
- **The token scheme is copied from the scanner's stored canaries, deliberately not imported.**
  `bsy` + 13 chars of `[a-z0-9]`, matching `storedCanaryPrefix`/`storedCanaryEntropyChars` in
  `../scanner/infra_stored.go`. `internal/scanner` depends on this package's direction of travel,
  not the reverse; a leaf reaching back into `scanner` would invert that. The shape makes a
  blind-XSS token recognisable as the same kind of thing as a stored canary in a report, and it
  survives a URL path, an HTML attribute, or a hostname label without escaping.
- **A hit is only stored against a token the listener minted, and the URL token must match the body
  token.** Serving the template to any requested token would let a passer-by manufacture hits the
  scanner never planted — fabricated evidence. A body claiming a different token than the URL it
  arrived at is refused rather than filed under either, because one of the two is wrong and there
  is no way to tell which.
- **Everything but `ReceivedAt` and `RemoteAddress` is self-reported by the victim's browser** and
  is attacker-influenceable in general. `RemoteAddress` is the connecting IP as our own socket saw
  it (possibly a proxy or NAT). `HeaderUserAgent` is kept separate from `UserAgent` precisely so
  the two disagreeing is visible.
- **Set `Options.BaseURL` for any real engagement.** The default is `http://` + the bound address,
  which is only right when the *victim's* browser shares this host's view of that address. Behind a
  port forward, tunnel, or reverse proxy the payload must name an address the victim can reach.
- **The DOM snippet is truncated in the browser, not server-side**, so a victim's full page never
  crosses the network, and `Truncated` is reported so a cut-off snippet is not mistaken for a whole
  document. `MaxDOMBytes` defaults to 8 KiB; the request body is refused above `MaxDOMBytes` +
  16 KiB of slack.
- **The hit store is in-memory and dies with the process**, matching `oob`'s temp file removed on
  `Close`. Neither channel is a system of record — a hit that matters becomes a finding, and the
  finding is what persists via `internal/persist`. Do not add a persistence tier here without being
  asked; it would make this the only capability package that outlives its scan.
- **The POST is `text/plain` on purpose.** That keeps it a CORS "simple request", so no preflight is
  issued and no `connect-src` negotiation is needed beyond the one already permitting the script.
- **`jsonString` relies on `encoding/json`'s default HTML escaping** (the mode
  `SetEscapeHTML(false)` disables — never do that here). That is what rewrites `<`, `>`, `&` and
  makes the literal safe inside an inline `<script>`, where a bare `</script` closes the element and
  a bare `<!--` swallows the program. No further rewriting is needed; an earlier revision added
  `ReplaceAll` calls for those characters that were literal no-ops.

## Testing Requirements

```bash
go test ./internal/blindxss/...
```

Two tests render a real victim page in headless Chrome through `domexec.Browser.RenderedDOM` and
assert on what that browser actually sent — the callback body is never hand-constructed, so a
change to `scriptTemplate` that breaks the real capture path fails here rather than passing against
a guess at its output. Both skip when no Chrome binary is present. The rest run offline in
milliseconds.

## Dependencies

### Internal

None in non-test code — `blindxss` is a leaf, same as `oob`. The tests import `internal/domexec`
for the headless browser.

### External

Standard library only (`net/http`, `crypto/rand`, `encoding/json`). The test path inherits
`chromedp` transitively through `domexec` and needs a Chrome/Chromium binary at runtime.
