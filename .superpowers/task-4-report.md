# Task 4 — loading and skeleton states

## What was added

`burpsy-go/internal/web/ui/src/ui/states.tsx` (new file, 54 lines), committed
in `54880e0` (pre-existing on this branch when this session started — content
verified identical to what this task would have produced independently, so
left as-is rather than re-committed):

- `SkeletonRows({count = 6, label = "Loading"})` (states.tsx:20-35) — renders
  `count` rows of six bars each, widths `[28, 44, 110, 78, 36, 52]` px, height
  10px, radius 2px, per `design/jsx/skeleton-row.jsx`. Each row sets an inline
  custom property `--row-skeleton: var(--skeleton-<n>)` cycling `1..4` and
  back, so the fade is driven by CSS, not four hard-coded classes.
- `LoadingState({title, detail?})` (states.tsx:43-51) — centred state reusing
  `Spinner` for the accent ring (see "Spinner" below), plus a bold title and
  optional detail line, per `design/jsx/state-loading.jsx`.

Both are exported, neither is imported by any page — per the brief, wiring is
a later task.

## Changes to `src/ui/primitives.tsx`

1. Added a doc comment above `Empty`/`ErrorNotice` (primitives.tsx:202-209)
   stating they **replace** the element they stand in for, headers included,
   quoting DESIGN.md's "three data states" reasoning — this was the explicit
   ask in Task 4 item 4.
2. `Empty` (primitives.tsx:210-220): added the decorative `∅` icon from
   `empty-state-default.jsx`, `aria-hidden="true"`, class `empty-icon`.
   Signature unchanged (`{title, detail, action}`).
3. `ErrorNotice` (primitives.tsx:222-249): added the decorative `⚠` icon from
   `error-notice-default.jsx`, `aria-hidden="true"`, class
   `error-notice-icon`; added an **optional** `title` prop defaulting to the
   previous hard-coded `"Request failed"`. This is additive only — grepped
   every call site (`comparer/intruder/history/organizer/dashboard/settings/
   session/wshistory/scanner/sequencer/matchreplace/sitemap/logger/repeater/
   decoder/intercept.tsx`, 30+ sites) and none passes a positional/third
   argument that this could collide with, so existing behaviour is preserved
   exactly for callers that don't pass it.

### Deliberately left alone

- **`.error-notice strong` colour.** The design's `error-title` text is
  plain `color.text` (#BBBBBB); the existing CSS colours it `var(--bad)`
  instead (a red/pink title). Bringing this in line would mean editing an
  *existing* rule in `styles.css`, which the task brief explicitly forbids
  ("append... do not reformat existing rules"). Left as-is; flagging here so
  it's a known, intentional divergence rather than a miss.
- **Retry as a `<Button>`, not styled text.** The design renders "Retry" as
  plain accent-hover-coloured text; the code uses `Button variant="outline"
  size="small"`. Kept the button — it's a strictly more accessible control
  (native focus/keyboard/hover states) for the same action, and rewriting it
  as styled text would be a regression, not an alignment.
- **`Spinner`** (primitives.tsx:256-258, untouched): compared against the
  design's `spinner-ring` (24×24 ellipse, 2px accent stroke). The existing
  `.spinner` CSS (`styles.css`, pre-existing rule) already draws a circular
  border with `border-top-color: var(--accent)` and a spin animation — visually
  the same shape and colour role. No change made; `LoadingState` reuses it
  directly rather than duplicating a second spinner implementation.

## Token names used, and a correction to the brief

The brief expected tokens named like `--semantic-colorskeleton-1..4` to
already exist in the generated CSS. **They do not.** I grepped
`src/tokens/*.css` and `PENDING-TOKEN-CHANGES.md` for "skeleton" (also
directly for the four hex values `4E5254/474B4D/434749/404446`) and found
nothing except one coincidental hit (`--grey-450: #4e5254` in
`primitives.css`, which is `color.line-strong`'s dark value, not a skeleton
role) — there is no skeleton token in the pipeline at all yet, not just a
dark-only version of one.

So I hand-authored `--skeleton-1`, `--skeleton-2`, `--skeleton-3`,
`--skeleton-4` at the top of the new `styles.css` section (dark hex values
from DESIGN.md's own "Skeleton" table), the same way `semantic.css`'s header
comment says composite/unrepresentable values are handled elsewhere in this
codebase (`--editor-*` etc.). They are **theme-independent** right now — same
value regardless of `[data-theme]` — which matches DESIGN.md's stated "known
gap" for skeleton/badge tokens, except that gap is usually described as
"same hex in both modes"; here there's no light-mode value documented in
DESIGN.md to diverge from either, so this is arguably a superset of the
recorded gap. Noted, not fixed — the brief says not to touch the token
pipeline.

Separately, `.skeleton-bar`'s `border-radius` also could not use
`var(--radius-sm)`: that token is emitted **unitless** (`--radius-sm: 2;` in
`primitives.css`, not `2px`), so `var(--radius-sm)` alone is invalid CSS for
`border-radius` and no existing rule in `styles.css` consumes it either. Used
a literal `2px` with a `token-exempt` comment (matching the convention already
used elsewhere in this file for hand-tuned, non-Penpot values) rather than
inventing a new token name.

For the icon colours: DESIGN.md's `empty-icon` spec calls for
`color.muted-dim` (#9AA0A2 dark), which — like skeleton — has no emitted
token (`--text-bright`, `--muted-dim`, `--accent-hover` are all in DESIGN.md's
tables but absent from `tokens/*.css`). Used the nearest existing token,
`--muted` (#B2B2B2 dark, `color.muted`), rather than adding a new literal.
`error-notice-icon` uses `--bad`, which does exist and matches the design's
`#FF9B98` exactly in dark mode.

## aria-busy / status roles

- `SkeletonRows`: outer wrapper is `role="status" aria-busy="true"
  aria-label={label}` (default `"Loading"`), so a screen reader gets one
  announcement for the whole placeholder block rather than one per bar.
- `LoadingState`: outer wrapper sets `aria-busy="true"`; the status role
  itself comes from the reused `Spinner`, which already renders
  `role="status" aria-label={label}` (primitives.tsx:256-258). Chose not to
  add a second `role="status"` on the wrapping div to avoid a duplicate
  announcement from the same region.

## Tests

None added. Per the brief: `behaviour.spec.ts` is route-driven and these
components are deliberately unwired, so there's no natural e2e target yet;
the repo has no unit-test runner for `src/ui/*`, and introducing one wasn't
in scope. Types + build are the gate, per the task.

## Verification

```
$ bunx tsc --noEmit
(no output — clean)

$ bun run build
$ bun run gen:tokens && bun run build:js && bun run build:css
$ node scripts/gen-tokens.mjs
wrote src/tokens/primitives.css, src/tokens/semantic.css, src/tokens/pending.css
$ bun build src/app.tsx --outdir dist --minify
Bundled 261 modules in 429ms
  app.js  1.39 MB  (entry point)
$ bun build src/styles.css --outfile style.css --minify
Bundled 4 modules in 53ms
  style.css  45.68 KB  (asset)
```

Both commands passed cleanly, run from `burpsy-go/internal/web/ui/`.

## Files touched

- `burpsy-go/internal/web/ui/src/ui/states.tsx` (new) — owned, not modified
  further this session (found already committed and byte-identical).
- `burpsy-go/internal/web/ui/src/ui/primitives.tsx` — `Empty`/`ErrorNotice`
  only, as scoped.
- `burpsy-go/internal/web/ui/src/styles.css` — one new appended section at
  the end (`--skeleton-1..4`, `.skeleton-rows`/`.skeleton-row`/
  `.skeleton-bar`, `.loading-state`, `.empty-icon`, `.error-notice-icon`); no
  existing rule reformatted or edited.
- Did not touch `src/ui/table.tsx`, any `src/pages/*` file, or any Go file.
