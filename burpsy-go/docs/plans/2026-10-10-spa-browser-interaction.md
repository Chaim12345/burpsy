# SPA browser-driven crawling — plan (2026-10-10)

Goal, from the owner: **the crawler drives a single-page app in a real browser — auto-click
navigational elements, explore the links/routes a click reveals, fill fields and submit forms.**

## What already exists (do not rebuild)

The crawler is further along than it looks. Verified in source:

- `crawler.Config.Render` / `RenderWithOutcome` (crawler.go:478) render a page with
  `domexec.Browser.RenderedDOMWithOptions` and admit the links the rendered DOM carries that the
  wire parse did not (`render` block, crawler.go:~2305, `FoundByRender` edge tag).
- The same render records the **run-time XHR/fetch requests the page issues** and admits the
  same-origin GETs among them (`admitRenderedRequests`, crawler.go:2366; `RenderOutcome.Requests`,
  taint.go). That is the SPA's API surface, already reachable.
- `domexec.Session` (session.go) is an isolated browser context with a **scope-gating proxy** and
  a per-tab gate; `Session.RenderedDOMWithOptions` renders inside the logged-in jar.
- `Session.ReplayLogin` (login.go) already has `goto`/`click`/`type`/`totp`/`key`/`wait` steps —
  the primitive for scripted interaction exists, it just is not used for discovery.
- `SubmitForms` builds an HTTP request from a **wire-parsed** form and replays it through
  `AuthorisedSender` (`admitForm`, crawler.go:2933). Destructive-link refusal exists
  (destructive.go) for link text/targets.

## What is missing (the actual gap)

1. **No interaction.** `renderedDOMIn` navigates once, waits for settle, reads `outerHTML`. It
   never clicks. A SPA whose nav is `<button>`/`[role=button]`/`[onclick]`/JS-routed yields only
   the seed page.
2. **No clickable enumeration.** `parsePage` reads `<a href>` and `<form>`; a SPA's real controls
   are buttons and div handlers with no href.
3. **Form filling is wire-side only.** No typing into the live DOM and submitting, so a script-
   rendered form or one needing client-side handlers is never exercised.
4. **No scope-gated interaction.** A new API on the raw `Browser` has no gate; interaction
   (which navigates and can change state) must run in a gated `Session`.

## Design

### Increment 1 — `domexec`: a bounded interaction pass

New file `internal/domexec/interact.go`:

```go
// InteractOptions bounds one interaction pass. Zero takes the defaults; every bound exists so a
// page with a thousand buttons or one that never settles cannot hang or explode a crawl.
type InteractOptions struct {
    MaxClicks   int           // default 25
    MaxForms    int           // default 5
    MaxWait     time.Duration // whole-pass cap, default 30s
    Settle      RenderOptions // reuse the existing settle windows per view
    FillForms   bool          // type defaults + submit (state-changing: caller decides)
    Screenshot  bool
}

// Interaction is what one interaction pass produced.
type Interaction struct {
    Views     []InteractionView // one per click/form, in order
    Requests  []RenderedRequest // every XHR/fetch seen across all views
    Dropped   int
    Capped    bool
    Waited    time.Duration
}

type InteractionView struct {
    Action   string // "click" | "submit"
    Selector string
    Label    string // visible text, for the destructive classifier and the report
    URL      string // location after the action
    DOM      string // rendered outerHTML of the resulting page
    Changed  bool   // URL or DOM differs from the base — an honest "did this do anything"
}
```

Mechanism, per click: read the base URL+DOM; enumerate candidate selectors with one `Evaluate`
(a JS `querySelectorAll` over a documented selector set), then for each: `Click` (via
`chromedp`), settle, read URL+DOM, record, and `Navigate` back to the base to reset. Bounded by
`MaxClicks` and the pass deadline. Form fill: enumerate `form`, set each visible `input`/`select`
to a default (the same defaults `discover.go` already computes for the wire path), submit, settle,
record.

**Honesty rules** (the project's value, applied here):
- A pass that hits a cap sets `Capped` — a truncated exploration is never presented as a complete
  one.
- A click that changes nothing is recorded with `Changed:false`, not dropped.
- The selector set is documented; an element kind outside it is a stated limitation, not silence.

### Increment 2 — crawler wiring

- `Config.Interact bool` + `Config.InteractOptions`, **off by default** (it navigates and, with
  `FillForms`, writes).
- In the render block: when `Interact` is set, call the interaction pass, then for each view
  admit its links **and** its requests through the existing `admit` / `admitRenderedRequests`
  paths, tagging the edge with a new origin (`foundByInteraction`) so a report can attribute a
  discovery to a click.
- Report counters: `InteractionsRun`, `InteractionClicks`, `InteractionCapped`, and a skip reason
  `SkipInteractionUnavailable` when the pass could not run (no browser) — never silence.
- Destructive guard: reuse `classifyDestructive` on each candidate's `Label` before clicking, and
  refuse a destructive control into the skip ledger.
- Scope: run the pass in a `domexec.Session` (gated), not the raw `Browser`. A click that
  navigates off-scope is refused at the session's proxy and counted, exactly as a fetch is.

### Increment 3 — web/UI wiring

`api_crawl.go` supplies the interaction function (session-aware, like `crawlRendererIn`); the New
Scan dialog exposes the switch next to "submit forms", worded so the operator knows it is
state-changing. Gated route unchanged.

### Increment 4 — verification

- Unit tests in `domexec` (a fixture page whose route only exists after a click; a form that only
  submits via `onsubmit`) — skip without Chrome, as the package's convention.
- A crawler test with a faked interaction hook proving the links/requests are admitted and counted.
- **Live**: a purpose-built SPA fixture served by `vulnapp` (or a `cmd/` driver) plus the real
  browser, asserting the crawler reaches a route no static parse can see. VulnerableApp itself is a
  SPA whose level pages are script-built, so it is a second live target.

## Bounds and refusals (must hold)

| Bound | Value | Why |
|---|---|---|
| clicks per page | 25 | a page of nav links, not an unbounded click farm |
| forms per page | 5 | |
| whole pass | 30s | a page that never settles must not hang the crawl |
| views recorded | bounded by the click/form caps | |
| state-changing | `FillForms` + `SubmitForms`, both off by default | writing to the application is the operator's call |

## Not in scope

- Recorded-login replay (already built, `ReplayLogin`).
- The DOM-taint checks (separate family).
- Driving a remote CDP engine: `NewSession` already refuses remote for the login path; interaction
  inherits that refusal rather than silently running ungated.

## Decisions already given

The owner asked for this capability explicitly, so the §8 "changes product scope / security
posture" question is answered: **build it, default OFF, report it honestly.** The destructive and
scope guards are not optional and are part of every increment.
