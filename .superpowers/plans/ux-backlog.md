# UX backlog: ship the four designed features

## Context

The design source carries components for four backlog items the React app does
not implement. Each is exported as JSX in
`burpsy-go/internal/web/ui/design/jsx/` with exact geometry, colours and copy.

**Read these two files before writing code:**
- `DESIGN.md` (repo root) — the design contract, and the reasoning behind it.
- `.superpowers/survey.md` — a measured survey of the code you are changing:
  exact signatures, what already exists, and what does not. It corrects several
  things a reasonable person would assume.

Two corrections worth stating up front, because they change the shape of the
work: the table is **TanStack**, so column visibility is supported by the
library and simply never wired; and `matchreplace.tsx` and `session.tsx`
**already have** reorder controls — only `intercept.tsx` lacks them.

## Global constraints

These bind every task. A task that violates one is not done.

1. **Tokens, not literals.** Use the CSS custom properties in `src/tokens/`.
   A raw hex in a component is a defect. If a value you need has no token, say
   so in your report rather than inventing one inline.
2. **Contrast is enforced.** 4.5:1 for text (3:1 for ≥18.66px bold).
   `e2e/specs/a11y.spec.ts` runs axe over every route in both themes and
   currently reports **zero** violations. It must still report zero.
3. **Every control has an accessible name.** `Field` is the guard — it mints a
   branded `LabelledId`, and `Input`/`Select`/`Textarea` will not typecheck
   without one (or an explicit `aria-label`). Use `IconButton`, whose `label`
   prop is mandatory, for icon-only controls. Keyboard operation is required;
   mouse-only is a bug.
4. **Density is the product.** 24px rows, 26–28px controls, 11–13px text. Do not
   add padding that costs visible rows.
5. **Honest states.** Never render a count the data does not support; keep
   loading, empty and error distinct. See DESIGN.md → "The numbers must be
   honest".
6. **Tests assert behaviour, not mechanism** — match the style and voice of
   `e2e/specs/behaviour.spec.ts`, which states the rule in its own header. Use
   role/label locators. Carry the requirement id in the test name.
7. **`bunx tsc --noEmit` and `bun run build` must both pass** before you report
   DONE. Run them and paste the output in your report.
8. Do not reformat or refactor outside your task's files.

## Tasks

Tasks 1–4 touch disjoint files and are dispatched in parallel. Task 5 depends on
1 and 2.

---

### Task 1 — Exchange highlight and comment (Go backend)

**Files:** `burpsy-go/internal/core/store.go`, `internal/web/api_types.go`,
`internal/web/api_capture.go`, `internal/persist/persist.go`,
`internal/web/route_manifest_test.go`, plus a test file.

`core.Exchange` has `Notes *string`, persisted in `internal/persist/persist.go`
(save at `nullStr(ex.Notes)`, load at `ex.Notes = &v`) and exposed read-only via
`api_types.go:46`. **Nothing can write it**, and there is no highlight field.

Add:

1. `Highlight string` on `core.Exchange`. Empty means none. Valid values are
   exactly `red orange yellow green cyan blue pink magenta gray` — this matches
   `HIGHLIGHTS` in `pages/organizer.tsx` minus its `"none"` sentinel, which the
   wire represents as `""`. Reject anything else with 400; never coerce.
2. Persist beside `Notes` using the existing `persist.addColumn` migration
   pattern, so existing databases keep working and old rows load with `""`.
3. Expose as `highlight` on the exchange DTO.
4. `PATCH /api/exchange/{id}` taking `{"notes": string|null, "highlight": string}`.
   Both optional: an omitted field is unchanged, an explicit `null` clears notes.
   Return the updated DTO. Register it in the style of its neighbours and add it
   to `route_manifest_test.go` with risk class `riskLocal` — it mutates local
   annotation and sends no traffic.

**Tests** (Go, full-sentence names carrying the id):
- `TestPatchExchangeStoresHighlightAndNotes_UX-15`
- `TestPatchExchangeRejectsAnUnknownHighlightColour_UX-15`
- `TestPatchExchangeLeavesOmittedFieldsUnchanged_UX-15`
- `TestExchangeHighlightSurvivesAReload_UX-15`

**Verify:** `cd burpsy-go && go build ./... && go vet ./... && go test ./...`

---

### Task 2 — Column show/hide in the shared table

**Files:** `src/ui/table.tsx`, a new menu component file if you want one,
`src/styles.css`.

The table is TanStack and already calls `row.getVisibleCells()` — visibility
state is supported and never set. This is wiring plus a menu, not a rewrite.

Design: `design/jsx/menu-column-visibility.jsx` — 132×109, `paper-sunken` fill,
hairline border, radius 3; a checkbox row per column (14px box, 12px label, 6px
gap); under a hairline divider a "Reset columns" action in `accent-strong`.

- Add an optional column-visibility capability to `VirtualTable`, with hidden
  columns exposed so a page can persist the choice. Keep it optional — tables
  that do not opt in must behave exactly as today.
- A trigger in the header opens the menu; hidden columns vanish from header and
  body; sort and resize keep working on what remains.
- "Reset columns" restores everything.
- A page can mark a column non-hideable — an identifier column like `#` should
  not be removable. Use TanStack's `enableHiding: false` rather than inventing a
  parallel concept.
- Keyboard: the trigger is a real `button`; `Escape` closes and returns focus to
  it; every checkbox is reachable by `Tab`. `Checkbox` already exists in
  primitives and renders a visible label.

**Tests** in `e2e/specs/behaviour.spec.ts`:
- `"hiding a column removes it from the header and every row"` — UX-16
- `"resetting columns restores the hidden ones"` — UX-16

**Verify:** `bunx tsc --noEmit`, `bun run build`, new specs pass.

---

### Task 3 — Reorder controls for intercept rules

**Files:** `src/pages/intercept.tsx`, `src/styles.css` if needed.

Intercept's request-rule and response-rule lists inside `RuleEditor` can be
added to (137-143) and removed from (237-245) but not reordered — and intercept
rules match **in order**, so the order is the meaning.

**The pattern already exists — copy it, do not invent one.**
`matchreplace.tsx:102-110` has `move()`; `matchreplace.tsx:322-340` renders the
`ArrowUp`/`ArrowDown` `IconButton`s with labels `Move rule N up` / `down`,
disabled at the ends. `session.tsx:372-382,462-472` uses the same shape for
macro steps. Match it, including the label wording, so the three pages behave
identically.

Apply to both rule lists in `RuleEditor`. Do not change rule semantics, only
order, and keep the existing dirty-tracking/persistence path intact.

Design reference for the grip, if you add a visual handle:
`design/jsx/reorder-handle-default.jsx` — 10×16 six-dot grip in `highlight.gray`.
The **buttons are the requirement**; drag is optional and must not replace them.

Two details the existing pattern does not cover, and that you should add:
- after a move, focus stays on the control that moved, so a second press repeats
  it (today focus can land on a disabled button at the ends).
- announce the new position through an `aria-live="polite"` region.

**Tests** in `e2e/specs/behaviour.spec.ts`:
- `"moving an intercept rule down changes the order it matches in"` — UX-17
- `"the move-up control is disabled on the first intercept rule"` — UX-17

**Verify:** `bunx tsc --noEmit`, `bun run build`, specs pass.

---

### Task 4 — Loading and skeleton states

**Files:** `src/ui/states.tsx` (new), `src/styles.css`. Do not wire into pages.

`primitives.tsx` **already exports** `Empty({title, detail, action})` (203-211),
`ErrorNotice({error, onRetry})` (213-228) and `Spinner({label})` (256-258). Do
not duplicate them. What is missing is the loading/skeleton pattern, and the
existing three are not aligned to the design.

1. Add `<SkeletonRows count>` from `design/jsx/skeleton-row.jsx` — six bars at
   28/44/110/78/36/52px, height 10, radius 2. Rows fade down the list using
   `--skeleton-1..4` in order; **that gradient is the pattern**, not decoration —
   it is what makes it read as a list rather than a block.
2. Add `<LoadingState title detail>` from `design/jsx/state-loading.jsx` — a
   centred accent ring, title, detail line. Reuse `Spinner` if it fits; if it
   does not, say why in your report rather than silently duplicating it.
3. Both set `aria-busy` and carry a status role so a screen reader announces the
   wait.
4. Check `Empty` and `ErrorNotice` against `design/jsx/empty-state-default.jsx`
   and `error-notice-default.jsx`. If they differ, bring them to the design.
   Report what you changed and what you deliberately left.

Document with a comment above `Empty` and `ErrorNotice` that they **replace** the
element they stand in for, headers included — leaving column headers stranded
above an empty state is the specific mistake they exist to prevent.

No product strings baked in: all copy comes from props.

**Tests:** `behaviour.spec.ts` is route-driven and these are unwired, so there is
no natural e2e. If the repo has no unit-test path, say so in your report rather
than introducing a framework. Types plus the build are the gate.

**Verify:** `bunx tsc --noEmit`, `bun run build`.

---

### Task 5 — History: row highlight, comment, and filter toggles

**Depends on Tasks 1 and 2.** **Files:** `src/pages/history.tsx`,
`src/lib/types.ts`, `src/lib/data.ts`, `src/pages/organizer.tsx` (import only),
`src/ui/table.tsx` only if the row-colour mechanism needs it, `src/styles.css`.

**5a — highlight and comment on the row itself.** The vocabulary exists only for
Organizer items, so "Add to Organizer" files a row in a *different tool* instead
of annotating it in place.

- Move `HIGHLIGHTS` (organizer.tsx:12) and `HIGHLIGHT_TONE` (14-23) to a shared
  module; keep Organizer working off the shared copy. Note `gray` and `none` are
  deliberately unmapped in `HIGHLIGHT_TONE`.
- Add `highlight` to the `Exchange` type and a mutation hook beside
  `useOrganizerMutations` (data.ts:293-309) calling the Task 1 `PATCH` route and
  invalidating the history key.
- Add a swatch picker per `design/jsx/highlight-picker-default.jsx`: ten 10px
  swatches, gap 4, on `paper-raised`, radius 4; "none" is an outlined transparent
  circle. Each swatch is a real control with an `aria-label`
  ("Highlight row red"). Reach it from the row context menu (`menuGroups`
  already exists on the table) or inline — your call, but it must be keyboard
  reachable.
- **A highlighted row tints its background** with the chosen colour at low alpha.
  Note from the survey: `rowClassName` is a *class* hook only, and the existing
  `row-flag-*` classes render as a 2px left inset shadow, not a fill. So this
  needs a real mechanism — either one class per colour (nine classes, tokens
  already exist as `--semantic-highlightred` etc.) or a new prop allowing an
  inline background. Choose one, and say in your report why.
  The tint must keep row text at 4.5:1 in **both** themes.
- `Exchange.notes` is already on the wire type (types.ts:40) and never used. Wire
  it: a row with a note shows the indicator from
  `design/jsx/comment-indicator-default.jsx`, and the note is editable.

**5b — filter toggles.** The DSL box is more powerful than Burp's popup and
strictly less discoverable; there is no toggle UI at all today.

Per `design/jsx/filter-toggle-off.jsx` / `-on.jsx`: pill, 18px tall, radius 10,
11px label, 6px dot. `off` = `paper-sunken` + `line-strong` hairline + `muted`
dot; `on` = `accent` fill with near-black dot and label. Use `aria-pressed`.

Add **"In scope only"** and **"Hide items without responses"** beside the filter
box. They compose with the DSL rather than replacing it: when a toggle is
expressible in the query language, reflect it in the query text so the operator
can see what it did and learn the language. If a toggle cannot be expressed in
the DSL, apply it client-side like the existing status/method `Select`s and say
so in your report.

**Tests** in `e2e/specs/behaviour.spec.ts`:
- `"highlighting a history row tints it and survives a reload"` — UX-15
- `"a note on a history row shows the comment indicator"` — UX-15
- `"the in-scope-only toggle filters the rows and shows in the query"` — UX-18

**Verify:** `bunx tsc --noEmit`, `bun run build`, specs pass, and
`e2e/specs/a11y.spec.ts` still reports zero violations.

---

## Definition of done

`./verify.sh` is the verdict. The fast gate per task is
`bunx tsc --noEmit && bun run build` plus that task's specs; the full script runs
once at the end.
