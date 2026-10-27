---
name: review-gate
description: Clear the review-gate check on a PR by having a fresh reviewer subagent read the risk-path diff and post the agent-review verdict. Use when review-gate is red with "needs agent review".
---

# Review gate via a reviewer subagent

The author never reviews its own risk paths. It spawns a fresh subagent that has none of the
author's context and gives it only what `docs/DEVELOPMENT-PROCESS.md` §7 allows: the PR number,
the head sha, the risk-path list and the diff.

1. Record the head **before** anything is read:
   `sha=$(git rev-parse origin/<head-branch>)` (or the PR's `head.sha`).
2. List the risk paths: `bash scripts/review-gate.sh origin/master "$sha"`.
3. Spawn the reviewer with the Agent tool (`subagent_type: general-purpose`, not a fork) and this
   brief, filled in:

   > You are the independent reviewer for PR #<N> in <owner>/<repo> at head <sha>. You did not
   > write it. Review ONLY the risk-class paths below, against `git diff origin/master...<sha>`:
   > correctness, scope/egress bypasses, auth and gate weakening, tests that cannot fail.
   > <risk path list>
   > Post exactly one PR comment with your notes, ending with a line that is exactly
   > `agent-review: approve <sha>` if nothing blocks, or `agent-review: changes-required` with the
   > blocking findings listed. Add the line `agent-review-by: subagent` above it. End the comment
   > with the Claude Code footer. Report back the verdict and the comment URL.

4. Do not edit the reviewer's verdict. On `changes-required`, fix, push, and run this again on the
   new head: an approve binds to its sha, and any later risk-path push needs a new one.
