# Research: injection-context classification, and a cheaper browser

Written 2026-08-18. Two questions, both raised by a measured result rather than a hunch, and both
answered here so the implementation that follows does not have to re-derive them.

## What prompted it

`cmd/xsschallenge` is a zero-knowledge XSS target: 28 endpoints designed from the public XSS context
taxonomy, declaring no rows, in no manifest, contributing to no coverage number, with every case
proven exploitable-or-not in a real browser before any scoring happens. The scanner scored
**16 of 22 exploitable endpoints detected, 1 of 6 safe endpoints falsely reported**.

Four of those five failures share one root cause. `analyzeXSSReflection` in `internal/scanner/xss.go`
decides by `strings.Contains` over the raw response body and never establishes **where** the canary
landed:

|Failure|Endpoint|Why substring matching cannot decide it|
|---|---|---|
|MISS|unquoted attribute value|the payload needs no quote, so no quote-based marker appears|
|MISS|`javascript:` in `href`|the scheme is the exploit; no tag is ever opened|
|MISS|`<iframe srcdoc>`|the attribute parser unescapes the payload *back* into markup|
|FALSE POSITIVE|`json.Marshal` into `<script>`|JSON does not escape `'`, and it doubles the payload's load-bearing backslash to `\\`, neutralising it invisibly|

The remaining two misses (`stored`, and reflections sourced from a request header or cookie) are
insertion-point and flow gaps. **Parsing cannot fix those** and this document does not claim it can.

## Question A — how to classify injection context in Go

### goquery is the wrong tool, and this was the original hypothesis

goquery is a jQuery-style API over a parsed tree. The question here is not "which elements match a
selector" but "at byte offset N, am I in a text node, an attribute value (which attribute, quoted
how), a comment, RCDATA, or a script". A tree normalises exactly the information needed away. goquery
stays useful for the tree work it already does in `infra_forms.go`; it is not the tool for this.

### `x/net/html` suffices — no new dependency

Two contradictory claims came back from research, so both were tested directly. The results:

- **Offsets ARE recoverable**, contrary to the claim that they are not. `Tokenizer` exposes no
  `Position()` method, but `Raw()` returns the exact source bytes of the current token, so a running
  sum of `len(z.Raw())` is the offset of each token. Measured against
  `<p>hi CANARY</p><input value=CANARY><a href="javascript:CANARY">x</a>`: offsets 3, 16 and 36, each
  landing on the right token.
- **Quoting is recoverable, but not from `Token().Attr`.** That path decodes and discards it:
  `value=UNQUOTED` and `value="QUOTED"` both come back as `value` → `UNQUOTED` / `QUOTED`, with
  nothing to tell them apart. `Raw()` retains the original start-tag text including the quote
  characters, so quoting has to be read off the raw bytes.

So the price of using the dependency already present is scanning the raw start-tag text yourself.
`github.com/tdewolff/parse/v2/html` hands both facts over directly — its `Lexer` reports offsets and
its `AttrVal()` includes the quote delimiters — and it was added, measured, and then **reverted**: it
is one more module for something `x/net/html` can already do, and this go.mod is deliberately small
(69 modules).

**Recommendation: `x/net/html`'s tokenizer, offsets by summing `Raw()`, quoting read from `Raw()`.**

### The design to copy: ZAP's context re-verification

ZAP's `HtmlContextAnalyser.getHtmlContexts` (zap-extensions,
`addOns/ascanrules/.../httputils/HtmlContextAnalyser.java`) finds every occurrence of the canary,
resolves the enclosing element, and records the surrounding quote character, the attribute name, the
parent-tag chain, and flags for URL attributes, script attributes and comments. `HtmlContext.matches`
then requires the reflected payload to appear in **the same context it was injected into** before it
counts as evidence.

That re-verification step is the false-positive killer, and it is precisely what burpsy lacks. Its
payloads are also context-specific rather than universal — `performTagAttack` closes the tag with the
context's own quote; the unquoted case injects a space plus an event handler;
`isJavaScriptSchemeInjectionValid` checks the payload sits at the *start* of a URL attribute value.

Nuclei and Dalfox both rely on a headless browser to confirm execution instead, which is a heavier
answer to the same question. ZAP's is the one to copy because it needs no browser.

### The JS half: goja, already a dependency

For "is the canary inside a string literal, and which quote encloses it", `github.com/dop251/goja` is
already present and sufficient: `parser.ParseFile` yields an `*ast.Program`; `ast.StringLiteral`
carries `Idx0()`/`Idx1()` source offsets, `Literal` (raw, quotes included — so the quote character is
`Literal[0]`) and `Value` (decoded). `ast.TemplateLiteral` exposes `OpenQuote`/`CloseQuote`.

**A backslash-parity check alone is not sufficient**, which matters because it is the tempting shortcut
for the JSON false positive. Parity tells you whether *these* bytes are escaped; it cannot tell you
which quote opened the literal, and after an encoding layer has rewritten the backslashes you are no
longer looking at the script's own escaping. A lexer answers both.

Not recommended: `tdewolff/parse/v2/js` (a new module, lexer-only, needs a hand-rolled state machine),
`otto` (another module for the same capability), esbuild's Go API (not shaped as a library for this).

### What context classification still cannot do

Stored flows, and reflections whose source is a request header or a cookie. Those are insertion-point
coverage, and conflating them with a parsing fix would misrepresent both.

## Question B — Lightpanda as a cheaper browser

Measured directly against a live Lightpanda rather than taken from its README, because a research pass
over the repository reported two blocking gaps that **do not exist**: it concluded `document.write` was
absent and that `Object.defineProperty`-based prototype wrapping was unsupported. Both are present and
working. Absence in a grep is not absence in a browser.

### What was actually measured

Of the 22 sinks burpsy's taint instrumentation wraps, **20 are present**. The two that are not:

- `document.evaluate` — a real gap. The Client-side XPath injection rows cannot be observed here.
- `openDatabase` (WebSQL) — irrelevant; Chromium removed it too, which is why those rows are already
  undemonstrated.

`Element.prototype.innerHTML` and the anchor `href` setter both report `configurable: true`, so they
can be wrapped, and an end-to-end taint flow was confirmed: a page whose own inline script read
`location.hash` and assigned it to `innerHTML` produced the wrapper record
`innerHTML:<img src=x onerror=window.__pwned=1>`, and the resulting `<img>` appeared in the DOM.
Inline scripts execute; `dispatchEvent` fires listeners; an inline `onclick` attribute runs when the
element is clicked programmatically.

**The boundary: Lightpanda does not load subresources, so no `error` event ever fires.** The `<img>`
above was created and the `onerror` attribute was parsed, and `window.__pwned` stayed `false`.

### Verdict

|Use|Verdict|
|---|---|
|Taint observation — "did tainted data reach a sink"|**Viable.** This is what burpsy's DOM rows actually do, and the wrapper fires.|
|Execution confirmation — "did the payload run"|**Not viable.** No subresource loading means load/error-triggered handlers never fire. `cmd/xsschallenge` phase 1 must stay on Chrome.|
|Client-side XPath rows|**Not viable** — `document.evaluate` is missing.|

Lightpanda is Zig with its own JS engine, speaks CDP with custom extensions, ships prebuilt binaries
with no cgo, and publishes ~16x lower memory and ~9x faster figures over 100 pages. Those numbers are
its own; they were not independently reproduced here, and the sink probe above is the only measurement
in this document taken first-hand.

### Cheaper without changing engine

Ranked by return, and these apply to the render pass that currently dominates the suite:

1. **Scope the stored-DOM render pass.** Every stored-DOM audit currently renders every
   script-bearing page in the manifest, once per `/sdm/` endpoint, and almost none of those renders can
   show that audit's canary. This is burpsy's own waste, not Chrome's, and it is the largest single win
   available.
2. **Block images, fonts and stylesheets** via request interception. JS still runs, which is all the
   taint model needs.
3. **Pool browsers and reuse page contexts** rather than paying startup per audit.

`go-rod` is reported to scale better than `chromedp` at high page concurrency. Not worth a driver
migration until 1–3 are done, since they address the actual cost.

## Recommended order of work

1. Context classifier over `x/net/html` (`internal/scanner/`), offsets from `Raw()`, quoting from the
   raw start tag, plus a hand-maintained attribute taxonomy for the URL-valued and HTML-valued
   attributes (`href`, `src`, `action`, `formaction`, `srcdoc`).
2. Gate the script-breakout claim on goja-derived JS context. This is the false-positive fix and
   should land first of the two, because a wrong finding against correctly-escaped code is worse than
   a missed one.
3. Context-specific payloads for the unquoted-attribute, `javascript:`-URL and `srcdoc` cases.
4. Re-run `cmd/xsschallenge` and record the new score. The number is the deliverable, not the diff.

Insertion-point coverage for header and cookie sources, and the stored flow, are separate work and
should not be folded into the above.

## Provenance

Four parallel research passes over `x/net/html`, goja, `tdewolff/parse`, Lightpanda, ZAP's
`CrossSiteScriptingScanRule` / `HtmlContextAnalyser`, Nuclei and Dalfox. Three findings in this
document contradict what came back and were corrected by direct measurement: that `x/net/html` cannot
recover offsets (it can), that Lightpanda lacks `document.write` and prototype wrapping (it has both),
and that the JSON false positive is reachable by a backslash-parity check (it is not). Every
first-hand measurement here is reproducible: the sink probe against a live Lightpanda, the offset and
quoting probe against `x/net/html`, and `go run ./cmd/xsschallenge` with a `DISPLAY` available.

Unverified and repeated only as a caution: research cited CVEs against `x/net/html` requiring
v0.38.0+. The advisory IDs were not checked and should be before they are relied on. This repo is on
v0.57.0.
