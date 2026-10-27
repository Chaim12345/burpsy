# Development process

How work goes from a bead to master. It exists because a green build that was never run against
the tree that landed is a claim, not evidence — the rule `docs/adr/0001-burp-parity-measurement.md`
applies to parity trackers, applied to our own merges. Where this disagrees with an older
instruction in an `AGENTS.md`, a handoff note or a managed Beads block, this wins.

## 1. Sources of truth

| Question | Answer lives in | Not in |
|---|---|---|
| What is open / closed | `.beads/issues.jsonl` on `master` | a local Dolt DB, `refs/dolt/data` (dead since 2026-09-17), another branch |
| Did it land | `git merge-base --is-ancestor <sha> origin/master` | a bead's status, a PR body, an agent report |
| Does master pass | the `Go` workflow run for master's tip (every master push gets its own run; none is cancelled) | a local run, a PR run against an older base |

A local `bd` database is a scratch copy: rebuild it from master's JSONL before use, and never
`bd dolt push`. The managed Beads blocks in `AGENTS.md` and `CLAUDE.md` still describe the Dolt
sync model; for this repository they are wrong on that point, and this section is the rule.

## 2. Picking a round

A **round** is at most six work items landed together by one round PR.

1. `bd ready`, then order: priority (P0–P2 before P3/P4); within a priority, regressions and
   "reports what it did not do" defects first, then the bead with the most dependents, then the
   oldest.
2. Group beads that share a package or feature into one **item** (one branch, one PR, ≤ ~800 lines).
3. Predict each item's file footprint (two minutes of `git grep`). Two items may not share a file,
   except:
   - `burpsy-go/internal/web/route_schemas.go` / `route_manifest.go`: at most two route-adding items
     per round;
   - `burpsy-go/gaps.md`: rows appended only; the lead resolves conflicts;
   - `dist/app.js`, `style.css`: agents never commit them (§5).
4. At most one item that drives Chrome or the scanner corpus.
5. A bead labelled `decision-needed`, or one whose recorded design the work would contradict, is
   not picked — see §8.
6. `in_progress` beads older than one round go back to `open` when the round closes (§9).

## 3. Branches and worktrees

    round/<YYYY-MM-DD>-<n>               from origin/master, created by the lead
    beads/<round>-<letter>-<slug>        from the round's base, one per item
    /root/wt/<round>/<letter>            its worktree

Only the lead creates or removes worktrees and branches. Agents never run `git worktree
remove|prune`, `git branch -D`, `git push`, or check out a branch other than their own. No branch
outlives its round: the lead deletes item branches once the round PR has merged.

Each clone runs `scripts/dev-setup.sh` once: it registers the merge driver `.gitattributes` names
for the UI bundle and warns when bun or Go differ from what CI uses.

## 4. Test tiers

| Tier | Who | When | What | Where |
|---|---|---|---|---|
| T1 | implementing agent | before reporting | `gofmt -l`, `go vet`, and `go test -count=1 -timeout 30m` on the packages `scripts/affected-go-tests.sh origin/master` prints (changed packages + every package whose tests import one); `bun run check` if `burpsy-go/internal/web/ui/` changed; a negative control for each new test (revert the fix, watch it fail) | local |
| T2 | lead | merging an item into the round branch | the same on the merge result, plus `go build ./...` | local |
| T3 | CI | every PR into master (in practice the round PR) and every push to master | `gate` (aggregates `changes`, `lint` and the `test` shard matrix): `changes` classifies the diff (`scripts/ci-changes.py`) and checks every tracked text file for raw control bytes; `lint` runs gofmt, `go build`, `go vet` on the whole module; `test` runs `go test ./... -count=1` and `go test -race ./internal/web/` split into parallel shards by `scripts/ci-shard.sh` (`ci-shard.sh all` lists them, `ci-shard.sh verify` proves their union is every test; the `race-core` shard additionally keeps `internal/proxy`, `internal/dash`, `internal/pool`, `internal/sender` and `internal/intruder` under `-race` on every run — on a PR, those of them the affected set contains) — on a **push to master the full suite**, on a **PR only the affected set** (`scripts/affected-go-tests.sh` against the PR base; the full suite when the PR touches `go.mod`/`go.sum`, `.github/**`, `scripts/ci-*`, the selector or any `testdata/`); `ui`: `bun install --frozen-lockfile`, `bun run check`, `bun run build`, bundle freshness; `beads`: `scripts/beads-lint.py`; `review-gate`: `scripts/review-gate.sh`. A change to docs, `.beads` data (not hooks) or benchmark scripts only skips `lint`, `test` and `ui`; `gate` still reports | `.github/workflows/go.yml`, `review-gate.yml` |
| Nightly | CI | 03:17 UTC, and on demand | `e2e-go.sh`; every T3 shard except `race-web-*` and `race-core` under `-race` (`CI_SHARD_RACE=1`), so with T3's push-to-master `internal/web` and `race-core` race runs the whole module, `internal/scanner` and `internal/extscan` included, runs under the race detector | `.github/workflows/nightly.yml` |
| Manual | whoever changed the console | before reporting a UI change | the live browser pass: `./ui-live.sh`, driven per `burpsy-go/docs/UI-VERIFICATION.md` | local |

Running the affected set:

    pkgs=$(scripts/affected-go-tests.sh origin/master) || exit 1
    [ -n "$pkgs" ] && (cd burpsy-go && go test -count=1 -timeout 30m $pkgs)

The script reads the import graph of the checked-out tree. It cannot see a test that reads another
directory's file without importing it, except through the explicit rules in its header, and it
cannot see merge skew (two branches that pass alone and fail together). The push to master runs the
whole suite on the exact tree that landed for exactly that reason. On a PR, CI tests the affected
set (on GitHub's merge commit, so skew against the base is covered for every selected package) and
`lint` builds and vets the whole module; a test outside the set that only fails on the merged tree
shows up on the master push, not on the PR. To reproduce one red T3 shard locally, run
`scripts/ci-shard.sh <shard>` from the repository root (set `CI_AFFECTED_BASE=<base>` to reproduce a
PR's affected-mode shard).
`.buildkite/` runs the same shards on Buildkite for comparison; it is optional and never a
required check (see `.buildkite/README.md`).

Whole-module, race and Chrome-heavy runs go through `scripts/capped-run.sh -- <command>`, e.g.
`scripts/capped-run.sh -- scripts/ci-shard.sh rest`. It runs the command in its own cgroup with a
hard CPU quota and memory limit (default: half the machine each, so two runs share it without
starving each other), sets `GOMAXPROCS`, `go -p` and `GOMEMLIMIT` to match, and queues for one of
the machine's slots (`/tmp/burpsy-heavy.<n>.lock`, replacing the single `/tmp/burpsy-heavy.lock`).
A run the memory cap killed says so; rerun with a larger `--mem`, or treat it as a leak. A local
full suite is a diagnostic for a red T3, not a gate. `go test ./...` without `-timeout 30m` is not
a run (`internal/scanner` alone takes ~8 minutes); `bun run build` is not a type check
(`tsc --noEmit` is, via `bun run check`).

An agent report states what ran, what was skipped and why (a missing binary is a skip with a
reason, never a pass). PR bodies link the CI run instead of saying "full suite passes".

## 5. The UI bundle

`burpsy-go/internal/web/ui/dist/app.js` and `style.css` are committed because `go:embed` needs them
and because "shipped" means "in the embedded bundle". They are generated: agents do not commit them;
the lead runs `bun run build` (bun 1.4.2) once on the round branch after the last item merge. CI's
`ui` job rebuilds with the same pinned bun and fails on any difference, so a source change that never
reached the bundle cannot land.

`.gitattributes` marks both files `merge=ours`: a merge keeps the round branch's side instead of
stopping on a conflict in a 2.5 MB minified line, and the rebuild — not the merge — produces the
file. In a clone where `scripts/dev-setup.sh` has not run, git falls back to an ordinary text merge
and stops on conflict markers.

## 6. PRs and merging

1. The agent commits on its branch with substantive messages and a `Bead: <id>` trailer for each
   bead the branch completes (`Bead: ar8v` or the full id; several ids may share a trailer). A bead
   the branch only advances gets no trailer.
2. The lead opens the item's PR **against the round branch** with the agent's report as the body
   (what changed, what was verified, what was not). Risk-class items (§7) get their reviewer now.
   CI does not run on these PRs (workflows run only for PRs into master); T1 and T2 cover them.
3. After T2 the lead merges the item into the round branch:

       git merge --no-ff -m "Merge PR #<N>: <PR title>" <item branch>

   and pushes; GitHub marks the PR merged once its head is in the round branch. The `Merge PR #N:`
   subject is what `scripts/beads-close-merged.py` reads the PR number from (a merge made with
   GitHub's merge button is also understood).
4. The lead rebuilds the bundle, runs the close script (§9), commits both, opens the **round PR to
   master** listing the item PRs and beads, and sets `gh pr merge --auto --merge` (needs "Allow
   auto-merge" in the repository settings).
5. Red T3: fix forward on the round branch, or `git revert -m 1` the offending item merge, take its
   beads out of the closure commit, and say so in the round PR.

Hotfixes: a single PR to master, same required checks, same closure rule.
Merge commits only — no squash, no rebase — so every closure sha stays in master's history.

## 7. Review

The `review-gate` commit status (posted by `.github/workflows/review-gate.yml`; rules in
`scripts/review-gate.sh` and `scripts/review-verdict.sh`) fails while a PR into master touches a
risk-class path without a valid agent review:

- `internal/sender/` and the HTTP/2 authorisation it shares;
- scope and authorisation (`internal/core/scope*.go`, the scope check, authz and same-origin
  handlers, crawler prefix scope, `cli_scope.go`);
- gated/destructive routes (`route_manifest.go`, `confirm_gate.go`, `gen-gated-routes.ts` and the
  UI's gated-route and route-risk lists);
- MCP risk-class placement (`internal/mcp/groups.go`, `route_manifest.go`);
- credential / client-cert / CA / TLS material (`internal/netauth/`, `internal/servercerts/`, the
  proxy's CA, listener-cert and TLS files, the CA, server-cert, TLS-policy and netauth handlers);
- `.github/` (workflows and their pinned versions and hashes), the gate scripts themselves, the UI
  package's `package.json`, `bun.lock`, `bunfig.toml` and `tsconfig.json` (they define what the
  `ui` job runs and installs), `.beads/hooks/`, `.gitattributes`.

The exact globs are the list in `scripts/review-gate.sh`; the list names files, not semantics, so
a risk-class change in an unlisted file is added to the list in the same PR. A file name git has to
quote counts as a risk path. A change to `crates/` (the frozen parity oracle) fails regardless of
any review: it is refused, not reviewed.

**The verdict.** The reviewer is a fresh agent given the diff and this list — never the author. It
reviews the PR at its current head and posts its verdict on the PR, as a PR review (event
`COMMENT` is enough; one account cannot approve its own PR) or a PR comment, containing a line
that is exactly

    agent-review: approve <full 40-hex sha of the head it reviewed>
    agent-review: changes-required

    sha=$(gh pr view <N> --json headRefOid -q .headRefOid)   # BEFORE reading the diff
    git diff origin/master..."$sha"                           # review exactly this
    gh pr comment <N> --body "$(printf 'Review notes...\n\nagent-review: approve %s' "$sha")"

Record the sha when the review starts, not when the verdict is posted: stamping the head at posting
time would approve commits pushed while the review was running.

Only verdicts by an OWNER, MEMBER or COLLABORATOR count; a review's approve counts only if the review
was submitted on that same commit, and a dismissed review does not count. The latest verdict wins.

**How it is judged.** Every run reads the PR's current head and all verdicts from the API when it
runs — nothing but the PR number comes from the triggering event — and passes when the PR touches
no risk path, or when the latest verdict approves a sha S that is in the PR's history and
`git diff S <head>` touches no risk path. So a verdict is about code, not about timing: a later push
that touches a risk path invalidates it automatically, whichever order events arrive or runs finish
in; a later push that touches none (docs, tests elsewhere, the bundle) keeps it; retargeting the
base changes nothing. Merging master into the PR branch invalidates it if master brought risk-path
changes (they are in S..head) — deliberate, and one re-review. A latest verdict of
`changes-required` fails a risk-path PR until a newer approve. Posting a verdict re-runs the check
(`issue_comment` and `pull_request_review` are triggers).

**A round PR.** CI runs only on PRs into master, so a risk-class item is reviewed on its item PR
into the round branch, at the sha the lead then merges. The round PR needs its own verdict at its
head: the lead asks the reviewer for it once the round branch is final, and the reviewer approves
only when every risk-class item was reviewed at the sha that was merged and nothing merged after
touched a risk path (the bundle rebuild and the beads closure do not). A fix-forward on the round
branch that touches a risk path is reviewed like an item, and the round PR needs a new verdict.

**Where the rules come from.** For `pull_request_target` and `issue_comment` the workflow file is
the default branch's, and in every event the two scripts are read from the default branch; the PR's
commits are fetched as data and diffed, never checked out or run, so a PR cannot loosen the rules it
is judged by. A change to them therefore takes effect from the next PR, and #348, which introduced
the workflow, was not judged by it at all — it was reviewed by hand.

**Residual risk, stated plainly.** The status is a name, and anything holding a token with
`statuses: write` can post a `review-gate` status: a PR could add its own workflow (on
`pull_request`, which runs the PR's workflow files on a branch of this repository) that posts
`review-gate: success` on its own head, and for `pull_request_review` runs GitHub uses the PR's
copy of this workflow. Every such PR touches `.github/`, a risk path, and the honest gate's run
posts a failure on the same sha — but whichever status is posted last for a context is the one
GitHub keeps. The real mitigations are CODEOWNERS with required human review on `.github/**`, or
a ruleset restricting who may change workflows; neither works with a single account. Until then,
a PR touching `.github/` is not merged on a green `review-gate` alone: the lead reads its workflow
diff.

## 8. Design decisions

The lead decides implementation choices that keep every recorded decision (ADRs, bead
descriptions, `burpsy-go/gaps.md`) and match Burp. Everything else goes to the user:

- the work would reverse or bypass a recorded decision;
- it changes product scope, security posture, or what is exposed to an MCP client;
- Burp's behaviour and the recorded design disagree.

Stop, park the branch as a draft PR, label the bead `decision-needed`, and send the user one
paragraph: the conflict, the options, what each costs, a recommendation. Build nothing until it is
answered, and do not build both.

## 9. Beads lifecycle

| Event | Action | Who |
|---|---|---|
| Picked | `in_progress`, owner = round | lead |
| Agent finds new work | listed in its report — not filed by the agent | agent |
| Round PR ready | close each landed bead with `Fixed by PR #N (<merge sha on the round branch>): <title>`; file follow-ups; reopen anything whose code did not land; reset `in_progress` items not in this round | lead, `scripts/beads-close-merged.py` |
| CI | `beads` job: JSONL parses, ids unique, no bead deleted, and every bead newly closed by the change cites a sha that resolves to a commit and is an ancestor of the checked-out HEAD — for a PR, GitHub's merge of the PR into master, so the commit is in master or in the PR's own commits; for a push to master, the new tip | CI, `scripts/beads-lint.py` |

Only the lead (or a dedicated beads agent) edits the JSONL.

    python3 -I scripts/beads-close-merged.py origin/master..round/<date>-<n>          # dry run
    python3 -I scripts/beads-close-merged.py origin/master..round/<date>-<n> --apply

The close script reads `Bead:` trailers from the commits each first-parent merge brought in, and
needs no `bd` and no Dolt. It rewrites only the closed beads' lines, in place, byte-for-byte in the
format bd exports; every other line is untouched, so the diff shows exactly the closures. The
`(id)` suffix on commit subjects is listed for the lead but never closes anything: epics and
partly-done beads are named that way too.

A closure without a landed commit is invalid. The lint accepts three closures that cite none,
because they land no code: `Duplicate of <id>` / `Superseded by <id>` naming a bead in the file,
a reason starting `WONTFIX`, `Won't fix`, `INVALID` or `Not a defect`, and an epic whose children
are all closed. Closures already on master are grandfathered; editing one makes it new again.

A conflicted JSONL is reconciled per issue by newest `updated_at` — never by a merge driver (see
`.gitattributes` for what one did to the tracker).

## 10. Hand-off

Every round ends with: the round PR, its CI run, beads closed / filed / reopened, what was not done
and why, and anything waiting on the user.

## 11. Lead actions outside the repository

The PR that introduced this document could not do these; they are the lead's, in this order.

1. **The `review-gate` status needs no setup** beyond this workflow being on master. (An earlier
   draft used an `agent-reviewed` label; labels are not used.)
2. **Branch protection on `master`**, once each requirement has been reported at least once
   (GitHub only offers a check it has seen). `gate` is the aggregator over `lint` and every `test`
   shard, so the shard list can change without touching protection. Required: the `gate`, `ui` and `beads` checks and the
   `review-gate` commit status, each bound to the GitHub Actions app (`app_id` 15368) so that no
   other app can satisfy it; strict (branch up to date before merging); enforced for admins; no
   force-push, no deletion:

       gh api -X PUT repos/Chaim12345/burpsy/branches/master/protection --input - <<'JSON'
       {"required_status_checks": {"strict": true, "checks": [
          {"context": "gate", "app_id": 15368}, {"context": "ui", "app_id": 15368},
          {"context": "beads", "app_id": 15368}, {"context": "review-gate", "app_id": 15368}]},
        "enforce_admins": true, "required_pull_request_reviews": null, "restrictions": null,
        "allow_force_pushes": false, "allow_deletions": false}
       JSON

   Require the `review-gate` STATUS, not the `review-gate-run` check: the status is posted on the
   PR's head sha by design, while a `pull_request_target` check run may be attached to the base
   commit. Confirm on the first PR after #348 that the status appears on the head commit and that
   GitHub lists its app as GitHub Actions (15368); if the app differs, drop `app_id` for that entry.
   The `app_id` binding does not stop another workflow in this repository posting the same status
   with its own token — see the residual risk in section 7.

   Check first that the plan allows it (branch protection on a private repository needs a paid
   plan), and that GitHub's merge queue is not available here before relying on it — on a
   user-owned repository it usually is not, which is why rounds use strict up-to-date checks.
   Enable "Allow auto-merge" for step 6.4.
3. **Beads recovery** (separate work; needs the other machine): there, `bd export` into a branch
   `bd/recover-<host>`; merge per issue by newest `updated_at`; accept a closure from it only if its
   sha is in master (`git merge-base --is-ancestor`), otherwise reopen it with a note. Record in the
   PR that `refs/dolt/data` has been dead since 2026-09-17 and is not a source.
4. **Branch cleanup**, after this lands: delete merged feature branches on the remote. The
   `jules-*` and `palette-*` branches need the user's confirmation first.
