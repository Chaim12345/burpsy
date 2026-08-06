# UI interaction map — verification and test execution

The map in this directory was produced by reading the source. This file is the separate step: what
the *running* application actually does, measured against it. A map nobody checked is a document,
not evidence.

Measured against a live build with the demo target on `127.0.0.1:9091`, the proxy on `:8091` and the
web UI on `:8081`.

## 1. Coverage

| Surface | Mapped in | Verified how |
|---|---|---|
| Target: Site map, Issues, Scope | `01-target.md` | live DOM census + driven flows |
| Proxy: Intercept, History, WS history, Match/Replace | `02-proxy.md` | live DOM census + driven flows |
| Attack: Intruder, Repeater, Sequencer, Session | `03-attack.md` | live DOM census + driven flows |
| Workbench: Decoder, Comparer, Organizer, Logger, Dashboard, Settings | `04-workbench.md` | live DOM census + driven flows |
| Shell: routing, hotkeys, menu bar, palette, shared components | `05-shell.md` | route sweep + dispatched hotkeys |
| Data layer and HTTP API | `06-data-api.md`, `06b-endpoint-cross-check.md` | every endpoint probed live |

## 2. Route sweep

All 17 routes reached, rendered, and checked for console errors and error banners.

**Result: 17/17 render, 0 console errors, 0 error banners.** Every route has a designed empty state
rather than a blank pane — `No path selected`, `Queue is clear`, `Nothing run yet`, `No base request`,
`Nothing compared yet`, `Nothing logged yet`, `Nothing saved yet`, and so on.

## 3. Interactive element census

Counted from the rendered DOM, not from source, so anything conditionally rendered is counted as the
operator actually meets it.

- **233** interactive elements across 17 routes.
- **214** controls that require an accessible name.
- **0** without one.

The three that failed initially were leaf `tree-toggle` buttons in the site map: the toggle was
rendered for every node, and a leaf's copy had no children to describe, so it carried no name. Leaves
now render a spacer, matching how the Issues tree already did it.

## 4. Endpoint probe

Every endpoint the frontend calls, hit against the live server.

**Result: 26/26 reachable.** Two apparent 404s were investigated and are not defects:

| Path | Status | Verdict |
|---|---|---|
| `/api/intercept/rules/request` | 404 | Test error. The grammar is plural — `requests` / `responses` — and the UI sends the plural. Both return 200. |
| `/ca.crt` | 404 | Correct. TLS interception is off unless started with `-intercept-tls`, and the handler says exactly that rather than serving an empty file. Verified 200 with the flag on. |

The second one did surface a real UI defect — see §6.

## 5. Flows driven end to end

| Flow | Result |
|---|---|
| Decoder: paste base64 → run pipeline | Smart-detect reported `BASE64` and produced `hello burpsy`. It names what it detected rather than transforming silently. |
| History → send to Repeater → Send | Live response returned and rendered. |
| Repeater resend lineage | New exchange recorded `parent_id` pointing at the exchange it was built from. |
| Site map → Filter history | Emits `host = … AND path ~ "…"`, returns the matching rows, no error banner. |
| Issues tree → select finding | Advisory / Request / Response tabs all populate. |
| Keyboard focus | Real Tab presses produce a 2px accent ring at 3.64:1 — passes 1.4.11. |
| Tool hotkeys `alt+1`..`alt+0` | Handler verified by dispatched event; all ten switch tools. See the caveat below. |

**Caveat, stated rather than glossed:** a *physical* Alt keypress never reached the page under
automation — the browser chrome consumed it. The binding is correct and fires when the event reaches
the document, but whether Alt arrives is the browser's business. This needs one manual check in a
real browser; it is not something this pass can honestly certify either way.

## 6. Defects found by testing the map

1. **Repeater resend grew a phantom site-map branch.** A captured proxy request is stored in
   absolute form (RFC 7230 §5.3), so a resend's request line is
   `POST http://127.0.0.1:9091/login HTTP/1.1`. The whole URI became the exchange's path, and the
   tree split it on its own slashes into `http:` → `` → `127.0.0.1:9091` → `login` — four nodes for
   one request, with the resource listed twice. Fixed: targets are reduced to origin form, leaving
   `OPTIONS *` and `CONNECT host:443` alone since neither is a path.

2. **Three dead CA-certificate affordances.** The status bar link, the Help menu item and the command
   palette action all offered `/ca.crt` unconditionally, and TLS interception is off by default — so
   all three led to a 404. The Settings page already gated on `useCaCert()`; the shell now does too.
   The status bar reads `no CA` with the reason on hover, the menu item disables, and the palette
   entry states the situation instead of failing. Both branches verified.

3. **Contrast, type scale, and the editor focus ring** — see the craft/accessibility pass. Summary:
   841 text nodes across 17 routes now measure zero WCAG 1.4.3 failures, down from failures on
   severity colours (2.64:1), muted text (2.88:1), editor header names and values (3.71 / 3.52) and
   line numbers (2.10).

## 7. Known gaps, not defects

Recorded so a later reader does not rediscover them as bugs:

- **Intruder creates no exchanges.** Its record callback stores raw response *messages* only, so an
  attack contributes nothing to history or the site map and the dashboard reports
  `intruder 0 exchanges`.
- **The crawler is not wired to the web server** (roadmap Phase 6), so no crawl task exists.
- **Sequencer live capture is stubbed** in the Go port — nothing fills the accumulator yet.
- **Match & Replace scope/query conditions are not persisted** by this build's rule endpoint. The UI
  says so in a warning rather than dropping them silently.
