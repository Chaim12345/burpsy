# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

**Active profile for this repository: Conservative.** No agent commits, pushes or runs a Dolt
remote sync unless the current request says to; the lead's round workflow is
`docs/DEVELOPMENT-PROCESS.md`, which wins over older instructions. Two statements in the managed
block above are wrong here and are overridden: `.beads/issues.jsonl` on master is the source of
truth, not a passive export, and `refs/dolt/data` has been dead since 2026-09-17 — never
`bd dolt push`.


## Build & Test

The active tree is `burpsy-go/` (Go module + React console under `internal/web/ui/`); `crates/` is
the frozen Rust reference (`verify.sh`). Full rules: `docs/DEVELOPMENT-PROCESS.md` section 4 and
`AGENTS.md`. Run `scripts/dev-setup.sh` once per clone.

| Tier | Who / when | What runs | Where it is defined |
|---|---|---|---|
| T1 | implementing agent, before reporting | `gofmt -l .`, `go vet ./...`, `go test -count=1 -timeout 30m` on `scripts/affected-go-tests.sh origin/master`; `bun run check` if the UI changed; a negative control per new test | local |
| T2 | lead, per item merge into the round branch | T1 on the merge result, plus `go build ./...` | local |
| T3 | CI, every PR into master and every master push | `gate`: gofmt, build, vet; `go test ./... -count=1` + `go test -race` on `internal/web/` and race-core (`proxy`, `dash`, `pool`, `sender`, `intruder`) — full on a master push, the affected set on a PR (full if it touches go.mod/go.sum, `.github/**`, `scripts/ci-*`, testdata); `ui`: `bun install --frozen-lockfile`, `bun run check`, `bun run build`, bundle freshness; `beads`; `review-gate`; `uat-cli` + `uat-ui` (part of `gate`). Docs/.beads/bench-only changes skip Go and ui | `.github/workflows/go.yml`, `review-gate.yml` |
| Nightly | CI, 03:17 UTC | `e2e-go.sh`; the Playwright console suite (`ui/e2e/specs`, job `e2e-ui`); every shard but `race-web-*` and `race-core` under `-race` (scanner and extscan included); `fuzz` (all targets, `ci-fuzz.sh`); `bench-vulnapp`, `bench-parity` | `.github/workflows/nightly.yml` |
| Manual | whoever changed the console | live browser pass: `./ui-live.sh` + `burpsy-go/docs/UI-VERIFICATION.md` | not in CI |

```bash
pkgs=$(scripts/affected-go-tests.sh origin/master)                  # T1 test set
[ -n "$pkgs" ] && scripts/capped-run.sh -- sh -c "cd burpsy-go && go test -count=1 -timeout 30m $pkgs"
scripts/capped-run.sh -- scripts/ci-shard.sh rest                  # one CI shard; `ci-shard.sh all` lists them
scripts/capped-run.sh -- sh -c 'cd burpsy-go && go test ./... -count=1 -timeout 30m'  # whole suite: a diagnostic
(cd burpsy-go/internal/web/ui && bun run check && bun run build)    # tsc + guards; build does NOT type-check
```

Gotchas: `go test ./...` needs `-timeout 30m` (`internal/scanner` alone is ~8 minutes); `bun run
build` strips types without checking them; agents never commit `dist/app.js` / `style.css` — the
lead rebuilds once per round with bun 1.4.2. A browser-driving package (domexec, dominvader,
blindxss, browser, crawler, scanner, web) FAILS when Chrome cannot launch; `BURPSY_ALLOW_NO_CHROME=1`
accepts that run deliberately (siblings: `BURPSY_ALLOW_UNVERIFIED_COVERAGE`, `_EXTSCAN`; list in
`AGENTS.md` Testing Requirements). CI sets none of them.

## Architecture Overview

_Add a brief overview of your project architecture_

## Conventions & Patterns

_Add your project-specific conventions here_
