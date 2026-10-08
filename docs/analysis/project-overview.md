# Project Overview — burpsy Issue Closure Spec

## Preliminary Direction
Close all 126 open beads issues in `/root/burpsy-react-ui` by implementing missing Burp Suite parity features and capability gaps, worked in the isolated `issue-sweep` worktree without disrupting the main `ui-react-comparison` working area.

## Current Architecture
burpsy is a memory-frugal HTTP testing proxy with a web UI (Burp Suite equivalent).
- **Active tree**: `burpsy-go/` (Go module `github.com/burpsy-go/burpsy`) — all feature work, shipping binary, React web UI under `burpsy-go/internal/web/ui/`
- **Frozen reference**: `crates/` (Rust, 13 crates) — parity oracle, read-only
- **Core thesis**: raw bytes written once, never copied; downstream holds message id + `(offset,len)` spans

## Technology Stack
| Layer | Current |
|:------|:--------|
| Backend | Go (burpsy-go/) |
| Frontend | React + TypeScript + Vite (burpsy-go/internal/web/ui) |
| Build | Go toolchain + bun |
| Issue tracker | .beads (JSONL at .beads/issues.jsonl) |
| VCS | git (remote: Chaim12345/burpsy) |

## Entry Points
- `burpsy-go/cmd/burpsy/` — main binary
- `burpsy-go/internal/web/server.go` — JSON HTTP API
- `burpsy-go/internal/web/ui/src/` — React pages per tool (intruder, repeater, scanner, organizer, etc.)

## Build & Run
- Go: `cd burpsy-go && go build ./... && go test ./...`
- UI: `cd burpsy-go/internal/web/ui && bun run build`
- E2E: `./e2e-go.sh`, `./e2e-ui.sh`

## Testing Baseline
- Go unit tests alongside each package (`*_test.go`)
- React tests: `*.test.ts` / `*.test.tsx` in `ui/src/lib/`
- E2E shell scripts: `e2e-go.sh`, `e2e-ui.sh`, `verify.sh`

## Project Governance
- `AGENTS.md` — shared agent instructions (exists)
- `CLAUDE.md` — Claude Code instructions (exists)
- `.beads/issues.jsonl` — canonical issue tracker (264 records, 126 open)
- Native memory: DeepSeek++ long-term memory (resolved)

## External Integrations
- None external; self-contained proxy/security tool
