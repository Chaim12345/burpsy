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
