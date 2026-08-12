---
name: burpsy
description: An open-source Burp Suite equivalent — a dense, keyboard-first HTTP interception and security-testing console for operators
version: 1.0.0
tags: [security-tool, desktop-density, dark-first, operator-console]
source_of_truth: burpsy-go/internal/web/ui/design/burpsy-roundtrip.fig
tokens: burpsy-go/internal/web/ui/src/tokens/
---

# burpsy design system

This file is the contract between the design source and the React app. Values
here are measured from the design file, not estimated — regenerate the component
specs with `bun scripts/export-design-jsx.ts` and the token list with the
`design_to_tokens` tool rather than editing numbers by hand.

## Design philosophy

**Density is the product.** An operator watches thousands of requests scroll by
and needs as many on screen as possible. Rows are 24px, body text is 12–13px,
chrome bands are 22–38px. Anything that trades rows for whitespace is working
against the tool. When a choice is between comfortable and dense, choose dense —
but never below the readability floor (12px text, 4.5:1 contrast).

**The numbers must be honest.** This is the house rule that outranks visual
preference: a UI that shows a partial result as if it were complete is a defect
here, even when it passes its tests. Practically —

- Never show a count the data does not support. A statusbar reading "1,204
  requests captured" on a screen that failed to load is a lie; it should say the
  history is unavailable.
- Distinguish *empty* from *failed* from *loading*. They mean different things to
  someone deciding whether their attack worked.
- Say what did **not** happen when that is the user's real fear. The history
  error state says "traffic is still being proxied and nothing has been lost",
  because data loss is the thing an operator dreads.
- `1 EXCHANGES` undercuts a tool whose differentiator is careful counting.
  Pluralise.

**Flat, not decorated.** Elevation is carried by 1px hairlines and small
background steps between surfaces, never by shadows or gradients. Radius is
0–4px. There are no decorative colours: every hue means something (severity,
scope, a user's chosen highlight).

**Keyboard first.** Every destination is reachable without a mouse (`mod+K`
palette, `?` for the shortcut sheet, `alt+1…0` for tools). Anything mouse-only
is an accessibility bug, not a nice-to-have.

## Colors

Dark is the shipped default; both themes are defined. All 47 tokens live in the
design file as a `semantic` variable collection with `dark` and `light` modes,
and 99% of fills in the design are bound to them.

### Surfaces

| Token | Dark | Light | Use |
|---|---|---|---|
| `color.paper` | `#3C3F41` | `#F2F2F2` | Page background |
| `color.paper-raised` | `#414547` | `#FFFFFF` | Toolbars, cards sitting above the page |
| `color.paper-deep` | `#323232` | `#E8E8E8` | Panels recessed from the page |
| `color.paper-sunken` | `#2B2B2B` | `#DCDCDC` | Wells: editors, inputs |
| `color.paper-deepest` | `#1A1A1A` | `#FFFFFF` | Deepest wells |
| `color.chrome` | `#313335` | `#E4E4E4` | Menubar, statusbar |
| `color.chrome-hover` | `#4B5052` | `#D4D4D4` | Chrome hover |
| `color.line` | `#4E5254` | `#C4C4C4` | Hairlines, table rules |
| `color.line-strong` | `#646464` | `#A6A6A6` | Emphasised borders |

### Text

| Token | Dark | Light | Use |
|---|---|---|---|
| `color.text` | `#BBBBBB` | `#1E1E1E` | Body |
| `color.text-bright` | `#E0E0E0` | `#1A1A1A` | Emphasis, state titles |
| `color.text-soft` | `#A9B7C6` | `#3C3C3C` | Secondary |
| `color.muted` | `#B2B2B2` | `#6E6E6E` | Labels, column headers |
| `color.muted-dim` | `#9AA0A2` | `#646464` | De-emphasised / out-of-scope rows |
| `color.text-on-chrome` | `#C6C6C6` | `#1A1A1A` | Text on `chrome-hover` — `color.text` only reaches 4.26:1 there |

### Accent

The accent is PortSwigger orange. It has four roles because one value cannot do
all four jobs at AA:

| Token | Dark | Light | Use |
|---|---|---|---|
| `color.accent` | `#FF6633` | `#D1490F` | Fills, borders, icons — **not small text on dark** |
| `color.accent-bright` | `#FF6633` | `#FF6633` | Identity orange, chrome accents |
| `color.accent-strong` | `#FF9670` | `#A8380A` | **Accent as text.** `#FF6633` is 3.32–4.40:1 on our greys and fails |
| `color.accent-deep` | `#CE480F` | `#CE480F` | Accent-filled control behind white text (`#D1490F` rounds to 4.49:1) |
| `color.accent-contrast` | `#FFFFFF` | `#FFFFFF` | Label on an accent-filled control |
| `color.accent-hover` | `#FF7A4D` | `#FF7A4D` | Hover on accent controls |

### Semantic and severity

| Token | Dark | Light | Use |
|---|---|---|---|
| `color.good` | `#9BC47F` | `#2E7D32` | Pass, healthy |
| `color.warn` | `#C9C33A` | `#96600A` | Warning, medium severity |
| `color.bad` | `#FF9B98` | `#C62828` | Error, high severity |
| `color.info` | `#93BDE0` | `#1565C0` | Informational |
| `color.badge-bad-bg` | `#3C1414` | — | High-severity badge surface |
| `color.badge-warn-bg` | `#3C3714` | — | Medium-severity badge surface |
| `color.badge-info-bg` | `#14283C` | — | Info badge surface |

### Row highlights

A closed vocabulary the operator picks from, mirroring `HIGHLIGHTS` in
`pages/organizer.tsx`. **Identical in both themes** — a highlight someone chose
should not change meaning when they switch theme.

`highlight.red #E5484D` · `orange #F76B15` · `yellow #F5D90A` · `green #30A46C` ·
`cyan #12A594` · `blue #0091FF` · `pink #E93D82` · `magenta #AB4ABA` ·
`gray #8B8D98`. "none" is the absence of a highlight, drawn as an outlined
transparent swatch.

Applied to a row, a highlight is a low-alpha tint of these values, never the
full-strength colour — the row text must stay readable.

### Skeleton

`skeleton-1 #4E5254` → `skeleton-2 #474B4D` → `skeleton-3 #434749` →
`skeleton-4 #404446`. The steps are the pattern, not decoration: each loading
row is dimmer than the one above, which is what makes it read as a list.

**Known gap:** badge and skeleton values are currently dark-only — they carry
the same hex in light mode and will look wrong there. Fix before shipping light
theme.

## Typography

Two families. `Inter` (or the system sans) for UI; **IBM Plex Mono** for
anything that is literally data — URLs, paths, headers, payloads, hex. Reaching
for mono is a semantic act: it means "this is the wire, not our words".

The scale is fluid (`clamp`), floor first:

| Token | Range | Use |
|---|---|---|
| `--fs-2xs` | 11→12px | Mono eyebrow labels, statusbar |
| `--fs-xs` | 11→13px | Dense table cells |
| `--fs-sm` | 12→14px | Body, most UI |
| `--fs-md` | 13→15px | Emphasised body, state titles |
| `--fs-lg` | 14→16px | Panel titles |
| `--fs-xl` | 15→18px | Section headings |
| `--fs-2xl` | 19→26px | Metric values |
| `--fs-3xl` | 21→30px | Large metrics |
| `--fs-4xl` | 30→54px | Display |

Weights are 400 and 700 only. Uppercase + letter-spacing is reserved for small
mono eyebrow labels (`PROTOCOLS`, `SITE MAP`).

## Spacing

4px base, fluid steps: `--s1` 3→6 · `--s2` 6→11 · `--s3` 9→16 · `--s4` 12→21 ·
`--s5` 15→26 · `--s6` 18→31 · `--s8` 22→40.

Fixed chrome heights, measured from the design: menubar **24px**, toolbar
**38px**, sub-tab strip **28px**, statusbar **22px**, table row **24px**,
control height **26–28px**.

Radius: `none 0` · `sm 2px` (controls, chips) · `md 3px` (panels, cards). Pills
(`10px`) are used only for toggle chips. Borders: hairline **1px**, focus ring
**2px**.

## Components

Every component below is exported from the design as JSX in
`burpsy-go/internal/web/ui/design/jsx/` — exact geometry, colours and copy. Read
that file before implementing, rather than working from a screenshot.

### Buttons
Height 28px, radius 2, 12px label. `primary` = `accent-deep` fill with
`accent-contrast` label. `secondary` = `paper-raised` fill, hairline border.
`ghost` = transparent until hover. Each has default/hover/active/disabled.

### Tabs
Tool tabs 30px in the 38px toolbar; the active tab gets a `paper` pill behind it
and an `accent-strong` bold label. Sub-tabs are 14px text in a 28px strip.
**The active state must be real markup, not an instance override** — see the note
in the design README about overrides not surviving save.

### Tables
24px rows, 11px bold `muted` column headers, 1px `line` rules. Sort and resize
exist; column show/hide is driven by `menu / column-visibility` (a checkbox list
plus a "Reset columns" action in `accent-strong`). A highlighted row tints its
background with the chosen `highlight.*` value at low alpha.

### Filter toggles
Pill, height 18px, radius 10, 11px label. `off` = `paper-sunken` fill with a
`line-strong` hairline and a `muted` dot. `on` = `accent` fill with near-black
dot and label. Used for discoverable boolean filters ("In scope only", "Hide
items without responses") beside the DSL box.

### Highlight picker
A 148×18 row of ten 10px swatches, gap 4, on `paper-raised`, radius 4. "none" is
an outlined transparent circle. Inline in a row — not a modal.

### Reorder handle
10×16 six-dot grip in `highlight.gray`, for lists whose order is their meaning
(match & replace rules, intercept rules, session steps). Order-is-semantics lists
must expose reordering; a list you can only append to is a bug.

### The three data states
Every view that loads data needs all three, and they are not interchangeable:

- **Loading** — keep the column headers (a loading table is still going to be a
  table) and fill the body with skeleton rows fading down the list.
- **Empty** — *replace* the table, headers included. Leaving headers strands
  column titles over nothing, which is the exact mistake the empty state exists
  to prevent. Say what is missing, why, and the action ("Point your browser at
  the proxy on 127.0.0.1:8080").
- **Error** — replace the table. Say what failed, what was *not* lost, and offer
  Retry plus a diagnostic route.

Reference boards: `13 States / HTTP history — loading | empty | error`.

### Feedback
Toasts 304×40, radius 3, one drop shadow — the only place a shadow is allowed.
Error notices carry a 3px `accent-strong` accent bar, a title, a detail line and
a retry action.

## Accessibility

Non-negotiable, and enforced rather than aspirational:

- **4.5:1 minimum** for text (3:1 for ≥18.66px bold / ≥24px). The design file is
  verified at **zero** failures by `scripts/fix-design-contrast.ts --dry-run`;
  the app is verified by axe in `e2e/specs/a11y.spec.ts`. Both must stay at zero.
- Aim **past** the threshold, not at it. `#A4A9AB` measured 4.47:1 and had to be
  redone; `#D1490F` rounds to 4.49:1. Leave margin.
- Every input has a programmatic label — `Field` generates an id and wires it, or
  an explicit `aria-label` for dense toolbar controls where a visible label would
  cost the density that is the point.
- Contrast is a **text** rule. Do not "fix" a rectangle's contrast against its
  parent; the built-in design linter does this and is wrong.

## When you change something

1. Change the design source first, then the code — otherwise the two drift and
   the file stops being a contract.
2. Re-export: `bun scripts/export-design-jsx.ts`.
3. Re-verify contrast: `bun scripts/fix-design-contrast.ts --dry-run` → 0.
4. Verify the design by **reopening the saved file**, not from the editor's live
   state; instance overrides do not survive a save.
5. `./verify.sh` is the definition of done for the app.
