# Design analysis — burpsy web console (light theme, 1440×900)

Measured, not eyeballed. Screenshots and computed styles captured with Playwright at 1440×900 and
390×844 @2×; palette and composition sampled from the rendered pixels of the desktop fold.

Playwright renders with `prefers-color-scheme: light`, so **this measures the light theme**. The dark
theme is the default an operator normally sees and was audited separately.

**Style signature**: A monochrome instrument panel — IBM Plex Mono labels over Avenir Next prose,
zero border-radius anywhere, hairline borders and no shadows, brand orange held to a tenth of a
percent of the screen.

**Genre**: Developer/technical tool, FlatLaf-lineage. Deliberately styled after Burp Suite rather
than after contemporary web dashboards.

| Dimension | Reading |
|---|---|
| Typography | Avenir Next (54 runs) + IBM Plex Mono (47) · 7 sizes, two clusters · weights 400/700 only |
| Color | Light key, 99.6% neutral, accent share **0.1%** · no tinting in the greys |
| Layout | Full-bleed panels, no max-width container · mirror symmetry 0.96 · ink 42.6% |
| Imagery | None. Zero photographs, zero illustrations. Lucide line icons only |
| Space | Fractional fluid gaps: 4.32 / 8.352 / 12.24 / 15.84px · integer paddings 8/12/20 |
| Shape/depth | **Radius: 0 everywhere. Shadows: none on this page.** Borders carry all elevation |
| Motion | 120ms ease on `background-color`, `color`, `border-color`. No keyframes, nothing loops |

## Typography

Two families, near-evenly split — 54 text runs in Avenir Next (humanist sans), 47 in IBM Plex Mono.
That is not a display/body pairing; it is a **prose/data pairing**. Mono carries every label, metric,
status chip and table cell; the sans carries headings and explanatory sentences. For a tool whose
content is literally bytes on a wire, that division is the right one and it is applied consistently.

**The scale is two clusters, not a ladder.** Measured sizes in use:

`24 · 22 · 15 · 14 · 13 · 12 · 11`

Counted by usage: 11px×45, 12px×29, 14px×10, 22px×10, 24px×5, 15px×1, 13px×1. So five sizes
(11–15px) live inside a 4px span and do almost all the work, then the scale jumps to 22/24 for metric
numbers. There is nothing between 15 and 22. The steps inside the low cluster are 1px apart — below
the threshold where a reader perceives a level change, which means those five sizes are not
communicating five levels of hierarchy.

**The fluid scale is effectively static.** The tokens are `clamp(floor, 0.5–0.95vw, ceiling)`. At
1440px, `0.76vw` = 10.9px, so `--fs-md` clamps to its 13px floor. Every token sits on its floor until
roughly 1450px viewport width. The middle term is unreachable on any laptop — the system *looks*
fluid and behaves fixed.

**Weights: 400 and 700, plus a single 800.** No 500 or 600. Hierarchy is carried by a hard
regular→bold jump with no intermediate step, which is why the mono labels lean on `letter-spacing:
1.1px` and uppercase instead — tracking is doing the job weight isn't.

Tracking measured: `normal` (54), `1.1px` (15, the uppercase mono eyebrows), `0.22px` (10),
`-0.648px` (10, the large metric numerals). Negative tracking on display numerals is a considered
touch.

## Color

Sampled from the desktop fold. **99.6% of the screen is achromatic.**

| Hex | Role | Share | Source |
|---|---|---|---|
| `#ffffff` | Panel / card surface | 86.6% | both |
| `#e4e4e4` | Chrome, toolbar, sunken wells | 9.3% | both |
| `#cccccc` | — | 1.8% | sampled |
| `#a4a4a4` | Hairline border (`--line-strong`) | 1.1% | both |
| `#8c8c8c` | Muted text | 0.4% | computed |
| `#1e1e1e` | Ink | 0.2% | computed |
| `#96600a` | Warning amber | 0.1% | both |
| `#ff6633` / `#d1490f` | **Brand orange** | below 0.1% | computed only |

Average chroma across the whole fold: **1** (out of 255). The brand orange does not reach the top ten
sampled colours — it survives only as the 24px logo tile and a 2px active-tab underline.

This is a defensible choice for a security tool, and it is Burp's own choice. Worth naming plainly
rather than treating as an accident: **the palette is a greyscale instrument panel with colour
reserved entirely for meaning** — amber for a coverage gap, green for complete, blue for a gated
count, red for a failure. Nothing is coloured to look nice.

Contrast in light mode is generous: `#1e1e1e` on `#ffffff` measures **16.67:1**, and the muted
`#6e6e6e` on `#f2f2f2` measures 4.55:1 — just over AA.

One craft note: the surface is `#ffffff` and the page `#f2f2f2`, both untinted. Pure white at 86.6%
area share is the one place this palette is a default rather than a decision — a fractionally warm or
cool off-white would cost nothing and would stop the panels reading as raw canvas.

## Layout & composition

- **No container.** Panels run full-bleed to a ~16px page gutter at every width; `commonWidths`
  reports no repeated max-width. For a dense operator tool that is correct — screen real estate goes
  to the table, not to a reading column.
- **Ink coverage 42.6%**, edge density 12.9%. Denser than a marketing page (~17%) and above a typical
  panelled dashboard (~32%). This is a full screen.
- **Mirror symmetry 0.96**, horizontal centroid 0.49. Almost perfectly balanced left/right.
  `colDensity` is nearly flat (0.63–1.0 across all 24 bands) — content spans the full width evenly
  with no column structure at all.
- **`rowDensity` tells the real story**: `[1, 1, 0.95, 0.57, 0.08, 0.44, 0.04, 0.49, 0.97, 0.97, 0.91,
  0.69, 0.08, 0.08, 0.06, 0.12, 0.04, 0.4, 0.06, 0.03, 0.04, 0.08, 0.03, 0.95]`. Bands 12–22 — the
  bottom **45% of the fold** — are near-empty. That region is three panels whose entire content is
  "No tool traffic", "No events", "No tasks".
- **One fold, no scroll** (`scrollHeight` 900 = viewport). The shell is a fixed application frame,
  which is right.

**Focal path**: the eye lands on the four metric numerals (22–24px, the only large type), reads left
to right, then drops into the Coverage strip. The empty lower half is skipped entirely. Nothing
competes with the numerals — but nothing rewards continuing down the page either.

## Imagery & media

None. Zero `<img>`, zero video, zero illustration. The only graphics are Lucide line icons at 11–13px,
stroke-consistent with the type weight. For this genre that is correct and I would not add any.

## Space & scale

Padding is a clean integer ladder: **8 / 12 / 16 / 20px** (8px×46, 12px×22, 20px×6).

Gaps are not: **4.32 / 8.352 / 12.24 / 15.84px**. These are `clamp()` fluid values resolving to
fractional pixels. On a dense grid of hairline-bordered panels, sub-pixel gaps mean the rhythm between
elements is never quite the rhythm inside them, and 1px borders adjacent to a 0.352px offset land on
half-pixels. The paddings were left as integers and the gaps were made fluid — so the two systems
disagree.

## Shape, depth & texture

**Radii: none.** Not a single non-zero `border-radius` on the page. **Shadows: none** on this page —
they exist only on menus and dialogs, which is exactly the right restriction.

So the elevation language is: hairline borders, one weight, one neutral ramp (`#a4a4a4`, `#c4c4c4`).
Panels are separated by a 1px line and a background step, nothing else. Status is carried by a 2px
coloured top border on a card — the only structural use of colour, and a good one.

This is the most disciplined dimension of the design. It commits to a single language and never
breaks it.

## Motion

Three transitions, all named properties, all 120ms `ease`:
`background-color 0.12s ease` (17 elements), `color 0.12s ease` (17), `border-color 0.12s ease` (2).

No `transition: all`. No keyframe animations. Nothing loops. 120ms sits at the fast end of the
120–250ms UI band, appropriate for a tool where hover feedback should feel instant.

## Voice & content design

The strongest dimension, and unusually so. Every empty state states a fact and then tells you what to
do: *"Requests that burpsy itself sends — Repeater, Intruder, Scanner — are logged here."*
*"Crawls, audits and attacks appear here with their progress and bounded results."*

The Coverage panel's subhead — *"Findings are a floor, not a total. Skipped, errored and gated work is
counted separately."* — is a claim about epistemics, not a label. A card reads `1 GATED` and
`1 PASSIVE CHECK SETS WITHOUT A VERDICT` rather than rounding to a clean number. That honesty is the
product's actual differentiator and the copy carries it.

Two nits: `1 PASSIVE CHECK SETS` and `1 EXCHANGES` don't singularise.

## Responsive

`viewportMeta` present; breakpoints at 600 / 620 / 760 / 980 / 1100 / 1280px.

At 390px the four metric cards stack to full-width, the tool tabs collapse to icons, and the menu bar
is dropped. Content survives the squeeze intact. The 1100px breakpoint (tool labels → icons) was added
after the type scale was corrected, because ten labelled tabs no longer fit beside the brand and
status chips.

## Design tokens

The page exposes its own custom properties; these are the author's names, not invented ones.

```css
:root {                             /* light */
  --paper: #f2f2f2;                 /* page */
  --paper-raised: #ffffff;          /* panels — 86.6% of the fold */
  --paper-deep: #e8e8e8;
  --line: #c4c4c4;
  --line-strong: #a6a6a6;
  --text: #1e1e1e;                  /* 16.67:1 on white */
  --muted: #6e6e6e;                 /* 4.55:1 on --paper */
  --accent: #d1490f;                /* brand; fills/borders/focus, not body text */
  --good: #2e7d32;  --warn: #96600a;
  --bad:  #c62828;  --info: #1565c0;

  --font-ui:   "Avenir Next", sans-serif;
  --font-mono: "IBM Plex Mono", monospace;
  --fs-xs: 11px; --fs-sm: 12px; --fs-md: 13px; --fs-lg: 14px;
  --fs-2xl: 22px; --fs-3xl: 24px;

  --radius: 0;                      /* deliberate, everywhere */
  --ease-ui: 120ms ease;
}
```

## Critique

### What works

- **The elevation language is fully committed.** Zero radius, hairline borders, no shadows outside
  overlays. Most interfaces hedge here; this one doesn't, and it is why the density reads as
  instrument rather than as clutter.
- **Colour is reserved for meaning.** 0.1% accent share is not an oversight — every coloured pixel
  says something (gated, complete, warning, failure). Adding brand colour would cost information.
- **The copy is the product's thesis.** "Findings are a floor, not a total" is a design decision
  expressed in words, and the UI never contradicts it.

### What's inconsistent

- **The bottom 45% of the dashboard says nothing.** Three stacked panels, each a full card with
  heading, subhead and centred empty message, to communicate three zeroes. `rowDensity` bands 12–22
  are near-flat. The first thing a new operator sees is mostly a report of absence. Collapse the three
  into one "nothing running yet" strip and give the space back to Coverage, which is the panel that
  actually carries the thesis.
- **Five type sizes inside a 4px span.** 11/12/13/14/15 cannot express five levels. Cut to three
  (11 mono label / 13 body / 15 emphasis) and the hierarchy gets sharper for free. The 15→22 gap is
  fine; the 11→15 crowd is not.
- **Fractional gaps against integer padding.** `4.32 / 8.352 / 12.24 / 15.84px` beside `8 / 12 / 20`.
  Two spacing systems in one layout, and the fluid one never actually flexes below ~1450px. Make the
  gaps integers on the same 4px base as the padding and nothing visible is lost.

### Handoff

The craft and accessibility passes are already done and their fixes are in. The one lens not yet
applied is **`cognitive-load-conversion`** — specifically for the dashboard's empty-state economics
above, which is a layout-priority question rather than a craft question.

## Confidence & limits

- Typography, colour, spacing, shape and motion values are **measured** from computed styles and
  sampled pixels.
- Area shares are from the **desktop fold only**, in **light** theme, with a near-empty capture
  (3 exchanges). A loaded session would push `inkCoverage` up and shrink the empty-panel share — the
  45%-empty finding is about the first-run state specifically, which is also the first impression.
- Not captured here: hover and focus states, the dark theme (audited separately), any modal or menu
  surface, and the tool pages other than Dashboard.
