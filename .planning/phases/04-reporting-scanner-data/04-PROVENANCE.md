# Phase 4 — provenance note

**Date:** 2026-07-28

## `04-DESIGN.md` was committed under two Phase 2 commit messages

The 735-line design was not committed by a commit that mentions it. It arrived in two pieces, both
swept in by `git add -A` from a session running Phase 2 and Phase 4 work concurrently:

| Commit | Message says | Also contained |
|---|---|---|
| `5654af1` | `docs(02): adjudicate the HTTP/2 design …` | the first 329 lines of `04-DESIGN.md`, mid-write |
| `6b25994` | `http2: a frame layer that corrects nothing …` | the remaining 484 lines |

Nothing was lost — the complete document is in the tree and the working tree was clean afterwards. But
two commit messages describe a narrower scope than their contents, and `5654af1` additionally asserts
"No code yet. Nothing under crates/ changed", which was true of `crates/` and silent about this file.

**Recorded rather than rewritten**, following the rule this repo already applies to its research notes:
*"They are historical records — correct them, do not silently rewrite them"* (`docs/AGENTS.md`). The
commits are reachable and their contents are honest even where their subject lines are incomplete;
rebasing to fix a subject line would trade a documented inaccuracy for an undocumented rewrite.

**Cause, and the practice change.** `git add -A` is unsafe while other agents are writing files — it
stages whatever happens to exist at that instant, including another task's half-finished output. Stage
explicit paths when concurrent work is in flight. The two commits above are what that looks like when
it goes wrong; the Phase 4 architect noticed and reported it, which is the only reason it is written
down here rather than discovered later by someone reading `git log` and finding a Phase 4 design in a
Phase 2 commit.

## Incidental findings from the design pass, verified independently

The design pass over `scanner` surfaced three defects in shipped code. All three were re-verified from
source before being acted on; none was taken on the design's word.

1. **A false doc comment** on `BUILT_IN_CONFIGS` — fixed in `cd54222`. It claimed no shipped Burp
   configuration sets `pause_task_failed_audit_item_percentage`; two of the 29 do, both `0`
   [VERIFIED: extracted `resources/BuiltInConfigs/*` from the jar and grepped].

2. **Passive scanning swallows evaluator errors with no counter.** `crates/scanner/src/lib.rs:233-235`:

   ```rust
   let Ok(found) = burpsy_bcheck::run_passive(check, &ctx) else { continue; };
   ```

   The `continue` is right and its comment explains why — one bad pattern must not silence every later
   check. What is missing is a counter. A check that errors on *every* response stays counted among the
   105 "runnable" with nothing anywhere recording that it never produced a result. This is the project's
   own honest-counting discipline broken inside the crate whose job is honest counting, and it is
   exactly what REPORT-04 exists to expose. **Phase 4 slice S1 addresses it**; it is not fixed yet.

3. **`esc` is not attribute-safe.** `crates/web/src/lib.rs:847` escapes only `&`, `<`, `>` — not `"` or
   `'`. Safe in the current UI because its output never lands in an attribute. A report writer that
   inherits it has a stored-XSS vector, because findings carry attacker-controlled response bytes. The
   design already routes all HTML text through a single `push_text` chokepoint for this reason; the note
   is here so the trap is not rediscovered.
