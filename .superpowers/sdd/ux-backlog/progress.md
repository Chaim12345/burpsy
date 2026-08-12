# SDD ledger — plan: .superpowers/plans/ux-backlog.md

BASE: 3891c7718f2e399ac9ae9087f48fcbb22b4cfe93

Wave 1 dispatched in parallel (disjoint file ownership):
- Task 1: Go backend — Exchange.Highlight + notes + PATCH /api/exchange/{id}
- Task 2: src/ui/table.tsx — column show/hide (TanStack visibility, already supported, never wired)
- Task 3: src/pages/intercept.tsx — reorder (pattern copied from matchreplace.tsx)
- Task 4: src/ui/states.tsx — loading + skeleton (Empty/ErrorNotice/Spinner already exist)

Wave 2 (after 1 and 2 land):
- Task 5: src/pages/history.tsx — row highlight + comment + filter toggles

Plan corrections from the code survey, before dispatch:
- matchreplace.tsx and session.tsx ALREADY have reorder; only intercept.tsx lacked it.
  Task 3 shrank from three pages to one, and now says copy the existing pattern.
- Table is TanStack: column visibility is library-supported and merely unwired.
  Task 2 shrank from "build it" to "wire it + menu".
- primitives.tsx already exports Empty, ErrorNotice, Spinner.
  Task 4 shrank to loading/skeleton + aligning the existing three.

## Wave 1 results

Task 1: complete (b6d565c) — Exchange.Highlight + notes + PATCH /api/exchange/{id};
  4 UX-15 Go tests pass, full go build/vet/test clean.
  Concern (accepted): also had to classify Highlight as ruleAbsent in
  internal/proxy/parity_test.go — an exhaustive Exchange-field parity check the
  brief did not list. Correct call; the build required it.
  Concern (deferred): PATCH fires no SSE live-update. Reasonable — changeHistory
  means "exchange captured". Revisit if two windows need to see annotations sync.

Task 2: complete (1fef344) — column-visibility menu, wired on Logger.
Task 3: complete (acdadc9 + bc8e47a) — intercept rule reordering, UX-17 specs pass.
Task 4: complete (54880e0, d6aaba4, 5a1e987) — SkeletonRows + LoadingState;
  Empty/ErrorNotice aligned to design.

Combined verification after all four merged: bunx tsc --noEmit clean,
bun run build clean, go build ./... clean, go test (web/core/persist) clean.

## Findings the agents surfaced that the plan got wrong

1. TOKEN PIPELINE GAP (real, confirmed independently): the design's tokens are
   NOT in the code pipeline at all. grep for skeleton/highlight across
   src/tokens/*.css returns 0 in every file. My Task 4 brief assumed
   --semantic-colorskeleton-1..4 existed; they do not. The agent hand-authored
   --skeleton-1..4 following the --editor-* convention, which is the right
   stopgap. This is task #28 and it is now load-bearing.
2. --radius-sm and --radius-md are emitted UNITLESS (`--radius-sm: 2;`), so they
   cannot be used in CSS at all. Confirmed by direct read of primitives.css:83-87.
   --border-hairline/--border-focus have the same defect. Nothing owns this file,
   so it is filed as a follow-up rather than patched mid-wave.
3. Shared working tree contention: agents' `bun run build` picked up each other's
   uncommitted WIP into dist/. Task 3 noticed and reverted the generated files
   rather than committing another agent's work. Worth designing around next time
   (per-agent worktrees, or nobody commits dist/).

## Task 2 — verified without its report

The Task 2 agent ended without writing `.superpowers/task-2-report.md`, so its
work was verified directly instead of taken on trust:
- commit 1fef344 adds `src/ui/column-visibility-menu.tsx`, +133 lines in
  `src/ui/table.tsx`, the Logger wiring, and 88 lines of CSS.
- both UX-16 specs exist in behaviour.spec.ts (231, 252) and are substantive:
  they assert the header disappears, the row's cell count drops by one, focus
  returns to the trigger after Escape, and the non-hideable identifier column is
  never offered as a checkbox. House style throughout (role/label locators,
  consoleErrors asserted).
- combined tsc/build/go verification after merge was clean.

Treated as complete. One question for the final review: the spec comments call
"Age" the identifier column on Logger — worth confirming that is the intended
non-hideable column rather than "#".

Deferred to the final whole-branch review:
- missing task-2-report.md (process gap, not a code gap)
- the "Age" vs "#" non-hideable column question
- a11y spec has not been re-run since wave 1 merged; global constraint 2
  requires zero violations, so the final gate must run it
