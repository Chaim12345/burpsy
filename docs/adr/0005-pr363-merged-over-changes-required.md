# ADR 0005 — PR #363 was merged with review-gate at changes-required

- **Status:** Accepted (owner's decision; recorded so the exception is not mistaken for the rule)
- **Date:** 2026-10-27
- **Context artefacts:** PR #363 (merge `60a37fb6`), independent review comment 6435363644, hotfix PR #367

## Context

`review-gate` (DEVELOPMENT-PROCESS §7) requires an independent `agent-review: approve <sha>` for a
PR that touches risk-class paths. PR #363 (backlog-b9, 483 commits) received
`agent-review: changes-required` at `1253ce36`. The reviewer confirmed the earlier blocking findings
fixed and named two new blocking defects:

1. A data race: `Sender.ApplyNetwork` reset `closeDelimitedAuthorities` with `= sync.Map{}` while
   in-flight sends used it without the lock. A network-settings save mid-send could end in a fatal
   mutex error.
2. `SendOutcome.Note` (Connection: close added, an h3 body cut at the cap) never reached the stored
   Repeater exchange, so a modified request or a truncated response read as untouched.

All other checks were green.

## Decision

The repository owner merged #363 to master as `60a37fb6` over the verdict, with both defects
deferred, and recorded that in the merge commit message. The fixes followed as hotfix PR #367:
`Clear()` in place of reassignment, and the note carried onto the exchange and into the tool log.

## Consequences

- GitHub does not enforce `review-gate` on master: a red gate is advisory to whoever presses merge.
  Merging over it is an owner's decision, and must be recorded in the merge commit and here.
- Between `60a37fb6` and #367's merge, master carries the race above.
