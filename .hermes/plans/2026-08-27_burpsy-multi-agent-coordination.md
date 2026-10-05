# burpsy-go Multi-Agent Coordination Plan

> **For Hermes:** You are the team manager. Dispatch coding agents per task with file-leasing to avoid conflicts.

**Goal:** Close the remaining Burp-parity gaps in burpsy-go — scanner engine (A4/S2/S3/A5 phases), runtime demonstration (38 undemonstrated rows), WebSocket interception, and UI parity — while keeping the Go gate green.

**Architecture:** Orchestrator (Hermes) delegates to coding agents via `delegate_task` (leaf subagents) and `am robot inbox` for cross-agent messaging. Each agent leases files before editing. Worktree isolation via `.orchestry/workspaces/`. All deliverables go to `/root/burpsy-parity/` (outside .orchestry, never reaped).

**Tech Stack:** Go 1.26, React/TypeScript, bun, Claude Code (opus), OpenCode (claude-opus-4-8), Cline, OMP workers.

---

## Current Team Roster

| Agent | Name | Model | Strength | Status |
|-------|------|-------|----------|--------|
| PlumOtter | claude-code | opus | Architecture, Go engine, self-audit | Active (orchestry) |
| DustyCanyon | cline | stealth/ox-alpha | UI, toollog, e2e | Active but credit-limited |
| SnowyMink | opencode | claude-opus-4-8 | Long sessions, DOM, scanner refactor | Active (Sisyphus) |
| CobaltKnoll | oh-my-pi | auto | pi/omp worker | Idle |
| ChartreusePike | oh-my-pi | ox-alpha | Merge coordinator | Idle |
| AirTrafficControl | mcp-agent-mail | atc-executor | Liveness probing | Automated |

---

## Priority-Ordered Task List

### P0 — Scanner Engine: Stored/OOB Audit Phases (BIGGEST GAP)

**Problem:** `DispatchScopeStoredPerInsertionPoint.IsReachable() = false`. Burpsy never threads two requests per insertion point. Stored XSS, second-order SQLi, Collaborator-based detection silently skipped.

**Evidence:** `SCANNER_CRAWLER_DEEPDIVE.md:68`, `SCAN_ENGINE.md:62-64`

**Tasks:**
1. Implement A4 phase (stored per-insertion-point) — two-request threading
2. Implement S2 phase (stored + Collaborator/OOB callback)
3. Implement S3 phase (stored XSS + reflected)
4. Implement A5 phase (JavaScript analysis pass)
5. Wire scan config to enable/disable each phase
6. Add tests with mock two-request target

**Files:** `internal/scanner/audit.go`, `internal/scanner/audit_engine.go`, `internal/scanner/dispatch.go` (if exists)

**Lease:** `internal/scanner/*`

---

### P1 — Runtime Demonstration: 38 Undemonstrated Rows

**Problem:** 145/183 catalog rows demonstrated. 38 registered-only. 4 need live interactsh (OOB).

**Evidence:** `BURP_VS_BURPSY_GO_COMPARISON.md:35`, `runtime_coverage_test.go` `wantDemonstrated` pin

**Tasks:**
1. Tabulate the 38 rows by name and required proof type
2. For each: write a runtime test against `internal/vulnapp` or a mock
3. For 4 OOB rows: document "needs live interactsh" as honest skip reason
4. Update `wantDemonstrated` pin to new count
5. Verify `go test ./internal/scanner/ -run TestRuntimeCoverage` passes

**Files:** `internal/scanner/runtime_coverage_test.go`, `internal/scanner/catalog_data.go`, `internal/vulnapp/*`

---

### P2 — WebSocket Interception Engine

**Problem:** `ws.go` only consults scope per-frame for recording. No hold/forward/drop. Panels #53/#54/#55 would be decorative.

**Evidence:** PlumOtter msg_1135 correction, `internal/proxy/ws.go`, `internal/intercept/*.go`

**Tasks:**
1. Add `DirectionWS` to `internal/intercept`
2. Implement `Hold` per-frame in `ws.go` (honor forward/drop)
3. Wire WS intercept rules API
4. Wire WS match/replace rules API
5. Build panel #53 (WS in-scope-only toggle)
6. Build panel #54 (WS interception rules)
7. Build panel #55 (WS match/replace)

**Files:** `internal/proxy/ws.go`, `internal/intercept/*.go`, `internal/web/api_intercept.go`, `ui/src/pages/intercept.tsx`

**Lease:** `internal/proxy/ws.go`, `internal/intercept/**`, `ui/src/pages/intercept.tsx`

---

### P3 — JWT Dedup Merge-on-Secret-Value

**Problem:** `JWT_WEAK_HMAC_SECRET` should dedup on recovered secret value, not generic equality.

**Evidence:** `SCANNER_CRAWLER_DEEPDIVE.md:39`

**Tasks:**
1. Add secret-value extraction to JWT check
2. Implement custom dedup key for JWT_WEAK_HMAC_SECRET
3. Add test: two hosts, same secret → one issue; different secrets → two issues

**Files:** `internal/scanner/checks_jwt.go` (or similar), `internal/scanner/dedup.go`

---

### P4 — UI Parity: Keyboard Shortcuts + Context Menus

**Problem:** 118 KeyHandler classes in Burpsy vs web-only shortcuts. 324 MenuHandler classes vs 3-4 right-click actions.

**Evidence:** `BURP_UI_UX_COMPARISON.md:20-23`

**Tasks:**
1. Add global keyboard shortcut system (Cmd/Ctrl+K palette exists; add Cmd+R for repeater, etc.)
2. Expand history row context menu (add-to-scope, audit, copy-as-curl, send-to-intruder)
3. Expand intercept context menu
4. Add shortcut help modal (? key)

**Files:** `ui/src/app.tsx`, `ui/src/pages/history.tsx`, `ui/src/pages/intercept.tsx`, `ui/src/lib/shortcuts.ts` (new)

---

### P5 — Extensions / Montoya API (STRATEGIC DECISION)

**Problem:** Deliberately not shipped (Phase 8). No plugin API.

**Evidence:** `BURP_FEATURE_INVENTORY_VS_BURPSY.md:28`

**Decision needed from operator:** Build a minimal plugin host (child-process JSON-RPC, which exists as `internal/extension/`) or formally record as deliberate omission.

If build:
- `internal/extension/` already has the host
- Need: registration surface, BApp-equivalent catalog, event hooks
- Large effort — separate planning doc needed

---

## Coordination Rules

1. **Lease before edit.** Every agent runs `am file_reservations reserve --path <files>` before touching anything.
2. **Commit at first coherent point.** This tree destroyed uncommitted work 3x in 2 days.
3. **Deliverables to `/root/burpsy-parity/`.** Never `.orchestry/workspaces/` (reaped).
4. **Gate before merge.** `go build ./... && go vet ./... && gofmt -l . && go test ./...` must be green.
5. **Honest counting.** "Not demonstrated" and "not implemented" are different claims. State which.
6. **No push without operator authorization.** Branch is 25 ahead; push sits with operator.

---

## Communication Channels

- **Agent mail:** `am robot inbox --agent <name>` and `am mail send --to <agent>`
- **Broadcast:** `am mail broadcast --subject "..." --body "..."`
- **Claude logs:** `/root/.claude/bin/logseek context "<query>" --limit 10`
- **OpenCode logs:** `/root/.local/share/opencode/log/opencode.log`
- **OMP logs:** `/root/.omp/logs/omp.<date>.<pid>.log`
- **Cline logs:** `/root/.cline/data/logs/cline.log`
- **Orchestry runs:** `/root/burpsy-react-ui/.orchestry/runs/run_*.jsonl`

---

## Immediate Next Actions

1. Dispatch PlumOtter (or delegate_task) to P0 — scanner A4/S2/S3/A5
2. Dispatch SnowyMink to P1 — runtime demonstration sweep
3. Dispatch CobaltKnoll to P2 — WebSocket interception (with PlumOtter's file lease released on ws.go)
4. ATC monitoring: acknowledge pending probes on DustyCanyon, PlumOtter, SnowyMink, CobaltKnoll
5. Operator decision on P5 (Extensions)

---

## Risks

- **Orch worktree reaping** still destroys uncommitted work. Mitigate: commit early, deliverable outside .orchestry.
- **Cline credit exhaustion** (balance -$1.37). DustyCanyon may be unavailable.
- **Model rate limits** (glm-5.3-flash daily cap hit). Fallback models needed.
- **File conflicts** between P0 (scanner) and P2 (ws.go touches proxy). Serialize: P0 first, then P2.
- **Self-audit bias:** Agents have been wrong 10+ times on their own numbers. Independent re-verification required.
