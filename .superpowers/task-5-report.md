# Task 5 report — history row highlight + comment, filter toggles (UX-15, UX-18)

## What changed

- `burpsy-go/internal/web/ui/src/lib/types.ts`
  - Moved `HIGHLIGHTS` and `HIGHLIGHT_TONE` out of `organizer.tsx` into a shared module (top of file,
    right after the header comment) so `history.tsx` can use the same vocabulary. `gray` and `none`
    stay deliberately unmapped in `HIGHLIGHT_TONE`, as before.
  - Added `highlight: string` to `Exchange` (not optional — `exchangeView()` on the Go side always
    populates it per Task 1's report).
- `burpsy-go/internal/web/ui/src/pages/organizer.tsx` — replaced the local `HIGHLIGHTS`/`HIGHLIGHT_TONE`
  consts with an import from `../lib/types`. No behaviour change.
- `burpsy-go/internal/web/ui/src/lib/data.ts` — added `useAnnotateExchange()` beside
  `useOrganizerMutations`, calling `PATCH /api/exchange/:id` with `{notes?, highlight?}` and
  invalidating the `["history"]` prefix (matches the existing `INVALIDATION` map's own shape for the
  same key).
- `burpsy-go/internal/web/ui/src/pages/history.tsx` — the bulk of the work:
  - `scopeToQueryFragment`, `combineQuery`, `stripFragment`, `hostPatternRegex`, `isHostInScope`
    (lines 30–126): the DSL-composition logic for "In scope only" — see below.
  - `FilterToggle` (131–157), `HighlightPicker` (159–181), `CommentIndicator` (183–190): local
    components built from `design/jsx/filter-toggle-{off,on}.jsx`,
    `design/jsx/highlight-picker-default.jsx`, `design/jsx/comment-indicator-default.jsx`. Not
    exported — nothing else in the app needs them yet, and the task's file list doesn't include a
    shared `ui/` file for them.
  - `HistoryPage`: new state (`scopeOnly`, `hideNoResponse`, `note`), `useScopeView()` +
    `useAnnotateExchange()`, an effect that splices/removes the scope DSL fragment into `term`, the
    `rows` filter extended with `hideNoResponse` and a client-side scope fallback, a note-sync effect
    keyed on `selectedId`, the `#` column's cell rendering a `CommentIndicator` when `row.notes` is
    set, an `annotate-bar` in the detail pane (`HighlightPicker` + a note `Input`, save-on-blur), the
    two `FilterToggle`s beside the filter box, and `rowClassName` now also emits
    `row-highlight-<colour>` alongside the existing `row-flag-*` classes.
- `burpsy-go/internal/web/ui/src/styles.css` — one new section appended at the end (see "Tokens
  added" and "Contrast" below); nothing existing edited.
- `burpsy-go/internal/web/ui/e2e/specs/behaviour.spec.ts` — three new tests in a new
  `describe("History row annotation and scope filter — UX-15, UX-18")` block, appended after the
  UX-17 intercept-reordering block.

## The row-tint mechanism, and why

The survey's finding stands: `rowClassName` is a class hook only, and `row-flag-bad`/`row-flag-warn`
render as a 2px inset shadow, not a fill — no mechanism existed for an arbitrary per-row background.

**Chosen: one class per colour** (`row-highlight-red` … `row-highlight-gray`, `table.tsx` untouched),
not a new inline-style prop on `VirtualTable`. The class only binds a custom property:

```css
.row-highlight-red { --row-tint: var(--highlight-red); }
/* × 9 */
.data-row.row-highlight:not(:hover):not(.selected-row) td {
  background: color-mix(in srgb, var(--row-tint) var(--row-tint-alpha), var(--paper-raised));
}
```

Tradeoff considered: a `rowStyle?: (row) => CSSProperties` prop on `VirtualTable` would have avoided
nine CSS classes and let the colour ride in as one custom property set inline, without editing
`styles.css` at all for the per-colour bindings. It was rejected for two reasons: (1) it's a second,
parallel row-decoration channel next to `rowClassName` on the same component, for a case (a *closed*
9-colour vocabulary, not an arbitrary colour) that a fixed set of classes already covers exactly;
(2) `table.tsx` is explicitly "only if the row-tint mechanism genuinely requires it", and the class
approach needed no change there — `rowClassName`'s existing `string | undefined` return already
composes multiple classes via `cn()`.

The one place this route needed care: the CSS lives in `styles.css` only (no `table.tsx` change), and
resolving 9 colours × 3 states (rest/hover/selected) without duplicating `color-mix()` nine times over
is what the `--row-tint` custom property buys — 9 one-line class rules bind it, and one shared rule
reads it, instead of 27 near-identical declarations.

## Contrast — measured, not eyeballed

Computed with a standalone Node script (WCAG relative-luminance formula, not `color-mix` — same
arithmetic, verified independently) against `--paper-raised` (`#414547` dark / `#FFFFFF` light) and
`--text` (`#BBBBBB` dark / `#1E1E1E` light), for all 9 `highlight.*` hexes from DESIGN.md:

- **Dark theme is the binding constraint.** `--text` is *light*-on-dark, so mixing a highlight colour
  into `--paper-raised` *raises* the background's luminance and *reduces* contrast — the opposite of
  light theme, where the same mix darkens a near-white background and only ever gains contrast.
  Sweeping alpha from 2%–22%, dark's worst colour (yellow, the brightest hue) fails above ~5%; at 4%
  every colour clears 4.5:1, worst case yellow at **4.62:1**, next-worst gray at 4.82:1, best magenta
  at 4.95:1 — chosen with margin over the floor per DESIGN.md's "aim past the threshold" rule, not at
  its edge.
- **Light theme has enormous headroom** — even at 24% every colour stays above 12:1 against `#1E1E1E`.
  Landed on **14%** for a visibly present tint rather than the least value that would pass.
- **Hover and selection compound past what's safe in dark theme.** `.data-row:hover td` already mixes
  `--info` at 7% into `--paper-raised`, and `.selected-row td` mixes `--accent` at 13% — both are
  *lightening* mixes, same direction as the highlight tint. Stacking the tint on top of either
  measured **below 4.5:1 for most of the 9 colours in dark theme** (e.g. hover+yellow: 4.10:1,
  selected+gray: 4.24:1) even at the already-conservative 4% base alpha. Rather than ship a
  highlighted row that fails contrast the moment the pointer or keyboard reaches it, the highlight
  rule is scoped `:not(:hover):not(.selected-row)` — hover and selection simply take over the
  background exactly as they did before this task, and the tint reappears once the pointer/selection
  moves off. Light theme's margin would have tolerated stacking, but the mechanism is one rule for
  both themes rather than a themed exception.

## Tokens added

None of these existed in `src/tokens/*.css` (confirmed again by grep, same as the survey's finding);
hand-authored in `styles.css` following the `--skeleton-*`/`--editor-*` convention:

- `--highlight-red`, `--highlight-orange`, `--highlight-yellow`, `--highlight-green`,
  `--highlight-cyan`, `--highlight-blue`, `--highlight-pink`, `--highlight-magenta`,
  `--highlight-gray` — theme-independent (`:root` only), per DESIGN.md's "Identical in both themes".
- `--row-tint-alpha` — **is** theme-split (`:root` 4%, `[data-theme="light"]` 14%), the one value in
  this set that has to differ per theme; see "Contrast" above for why.
- `--row-tint` — not a colour value, a per-row indirection: each `row-highlight-<colour>` class binds
  it to one of the nine tokens above.

No new token was needed for the comment indicator or the filter toggle's "off" state — those reuse
existing tokens (`--paper-sunken`, `--line-strong`, `--text`, `--highlight-gray`, `--accent-bright`,
and `--grey-900`, the primitive already used for `--accent-contrast`'s dark value). The comment
indicator's exact `#52565A`/`#E8E8E8` are literal, undocumented in DESIGN.md's semantic table (a
single fixed component, like the skeleton bars) — flagged rather than mapped to a near token, since
neither existing token matches.

## How the toggles compose with the DSL

- **"In scope only"** (`scopeToQueryFragment`, history.tsx:30–68): translates the operator's scope
  rules into the same grammar the filter box already parses — `NOT host = "x"`, `(host = "a" OR
  host = "b")`, or both AND'd — and splices it directly into the visible `term`/`Input`, so what the
  box shows is real, editable DSL the operator could have typed, exactly matching the task's "so the
  operator can see what it did and learn the language." Mirrors `core.Scope.Contains` exactly for the
  case it covers: excludes always win, no include rules means default-allow.
  - It returns `null` (not expressible) when scope is `allow_all`/empty (nothing to add) or when any
    rule's host pattern contains `*` — the DSL's `=`/`~` operators have no glob equivalent, and
    showing an *approximate* query in the box would misdescribe the filter, which is exactly the kind
    of dishonesty DESIGN.md's "the numbers must be honest" section rules out. In that case the toggle
    still filters correctly via `isHostInScope` (a client-side port of `core.Scope.Contains`'s regex
    construction), it just doesn't touch the query text.
  - Toggling off removes exactly the substring this component injected (tracked in a ref); a
    hand-edit of the box between toggle-on and toggle-off is left alone rather than mangled.
  - The UI's own `/api/scope` never exposes port or path (see `types.policy.ts`'s comment on
    `ScopeRuleView`, and `settings.tsx`'s), so neither the DSL translation nor the client fallback
    needs to consider them — consistent with what the rest of the app already does.
- **"Hide items without responses"** is always client-side (`rows` filter on `row.response === null`).
  The DSL cannot express it: per `query.go`'s own doc comment, "every comparison on an absent field is
  false — never true", so no `status` comparison can ever select "has no response yet" (a comparison
  needing it to be *true* for pending rows is exactly what that rule forbids). This matches the
  existing status/method `Select`s, which are also client-side and also not reflected into the query.

## Tests

`e2e/specs/behaviour.spec.ts`, new `describe` block:
- `"highlighting a history row tints it and survives a reload"` — clicks "Highlight row red" from
  the detail pane's picker, asserts the `row-highlight-red` class, asserts the *computed* background
  colour differs from an unhighlighted row's (not just that a class landed — the survey's whole
  complaint was a class that painted nothing), reloads, and re-asserts the class survived (Task 1's
  persistence).
- `"a note on a history row shows the comment indicator"` — types a note, blurs (save-on-blur), and
  asserts `.comment-indicator` appears with `title="Has a note"`.
- `"the in-scope-only toggle filters the rows and shows in the query"` — adds a real `exclude` scope
  rule via `page.request.post("/api/scope", ...)` against the harness's real host (all 5 seeded rows
  share one host), clicks the toggle, asserts the query box reads `NOT host = "127.0.0.1"` and the
  table goes to its empty state, then un-toggles and asserts both revert. Cleans up the scope rule in
  a `finally` (the suite runs `workers: 1` against one shared server, so a rule left behind would take
  every later test's traffic out of scope too).

## Verification

```
$ bunx tsc --noEmit
(clean — pre-existing errors in menubar.ts/theme.ts/syntax.ts are untouched files, confirmed via
 `git status` showing no changes to them; my only fix was one `pattern[i] ?? ""` for
 noUncheckedIndexedAccess in the new hostPatternRegex loop)

$ bun run build
$ bun run gen:tokens && bun run build:js && bun run build:css
wrote src/tokens/primitives.css, src/tokens/semantic.css, src/tokens/pending.css   (no diff — Penpot
export unchanged, confirmed via git status)
Bundled 263 modules in 473ms
  app.js  1.40 MB  (entry point)
Bundled 4 modules in 35ms
  style.css  49.49 KB  (asset)
```

Both clean.

**e2e (`behaviour.spec.ts`, `a11y.spec.ts`) could NOT be run — BLOCKED, and not by anything in this
task's diff.** `./e2e-ui.sh --check` passes (Chromium present), but the harness's `go build
./cmd/burpsy` fails on this branch's current `HEAD` (before any of my changes):

```
internal/web/api_tools.go:90:77: not enough arguments in call to s.toolLog.Record
internal/web/api_tools.go:137:18: cannot use ex.ID (uint64 vs core.ExchangeID) in struct literal
internal/web/api_tools.go:742:18: method Server.handleSequencerCapture already declared at
  internal/web/api_sequencer_capture.go:597:18
internal/mcp/handlers.go:48:33: cannot use id (uint64) as core.ExchangeID in argument
```

Confirmed pre-existing and unrelated to this task: `git status` before my edit showed a clean tree on
this branch, `git log -1` shows the current HEAD is `merge: bring master into ui-react-comparison`
(commit c89c398), which brought in `internal/mcp/handlers.go` and changed `internal/web/api_tools.go`
from master — those files are outside every list of files this task (or Task 1–4) was scoped to, and
`go build ./...` fails on them with zero files of mine touched. I did not attempt to fix it: it is a
non-trivial Go signature/type mismatch across two files this task has no ownership of, and "fix an
unrelated backend merge conflict" is a materially different, riskier task than UX-15/18.

What I *could* verify without a running backend:
- `bunx tsc --noEmit` and `bun run build` — both clean, above.
- `npx playwright test --list` (no backend needed) — all 150 specs across all 4 files still parse,
  including the 3 new UX-15/18 tests, confirming no syntax/import errors in the new spec file.
- The contrast numbers above, computed independently in Node against the WCAG formula.
- Manual trace of the DSL fragment logic against `query.go`'s grammar and `core.Scope.Contains`'s
  exact algorithm (both read in full — see the file citations above).

## Concerns

1. **The Go backend does not build on this branch right now**, for reasons unrelated to Task 5. This
   blocks `e2e-ui.sh`, `e2e-go.sh`, `verify.sh`, and Task 1's own Go tests from being re-confirmed on
   this HEAD. Whoever owns `internal/web/api_tools.go`/`internal/mcp/handlers.go` needs to resolve
   the merge before any e2e suite (mine or the pre-existing ones) can run again.
2. The note field saves on blur/Enter, not per-keystroke — matches the density/toolbar-control idiom
   used elsewhere in this file, but means a note typed and never blurred (e.g. closing the tab) is
   lost. Not different from how Organizer's own draft works before its explicit Save, so treated as
   consistent rather than a gap.
3. `scopeToQueryFragment`'s DSL translation is exact for the plain-hostname case and deliberately
   inert (falls back to client-side filtering) for any wildcard pattern — this is a real functional
   gap versus a hypothetical scope with wildcards, called out rather than fixed, because approximating
   a wildcard into `~` would show an inaccurate query, which is worse than showing none.
