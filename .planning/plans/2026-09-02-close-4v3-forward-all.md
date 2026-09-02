# Plan: Close first bd issue — `burpsy-react-ui-4v3` (intercept "Forward all")

Date: 2026-09-02
Board state: 184 open / 257 total. This plan closes 1 → 183 open.

## Why this issue first

`burpsy-react-ui-4v3` (P2, task, labels: burp-parity, capability-gap, intercept, ui):
> intercept: no 'Forward all', though 'Drop all' exists — the destructive half of Burp's pair shipped without the safe half.

Chosen because:

1. **Small and symmetric** — the codebase already has `DropAll` as an exact template (engine, API, route, UI button), so "done" is unambiguous.
2. **Machine-checkable acceptance criteria**: (a) the toolbar forwards every held message in one action; (b) each message goes out with its own original bytes, not the selected row's edit buffer; (c) the count actually forwarded is reported the way Drop all reports its count.
3. **Preliminary audit says the fix already landed and the bead was never closed** — if verification confirms that, this becomes a verify-and-close exercise: lowest possible risk for the first closure.

## Finding from recon (already gathered)

The feature appears **fully implemented end-to-end**; the beads record is stale:

| Layer | Evidence |
|---|---|
| Engine | `internal/intercept/intercept.go:732` — `func (e *Engine) ForwardAll() int`: resolves every held message with `h.Raw` (original bytes, **not** the edit buffer, no content-length rewrite), once-only resolve gate, deletes resolved IDs, fires one change signal, returns count actually forwarded. |
| API | `internal/web/api_intercept.go` — `handleInterceptForwardAll` serves `POST /api/intercept/forward-all`, answers `{"forwarded": n}` (mirror of drop-all's `{"dropped": n}`). |
| Route | `internal/web/server.go:820` — `s.mux.HandleFunc("/api/intercept/forward-all", s.handleInterceptForwardAll)`. |
| UI client | `internal/web/ui/src/lib/data.ts:422` — `forwardAll` mutation next to `dropAll`. |
| UI toolbar | `internal/web/ui/src/pages/intercept.tsx:783-808` — "Forward all (N)" button: disabled (not hidden) when the queue is empty, toasts the exact forwarded count, and says so when fewer were forwarded than shown ("resolved elsewhere"). The comment block at :775 even cites `burpsy-react-ui-4v3`. |
| Tests | `internal/intercept/intercept_test.go:348-386` — `TestEngine_ForwardAllForwardsEveryHeldMessageUnmodifiedAndCountsOnlyItsOwn` covers: unmodified bytes, a message resolved elsewhere is not counted, empty queue returns 0. |

## Execution plan

### Phase 1 — Verify each acceptance criterion against HEAD

Criterion → check:

1. **"Forward every held message in one action"** → toolbar button exists and calls `forwardAll` (confirmed statically at `intercept.tsx:783-808`); engine walks the full hold map (`intercept.go:735-740`).
2. **"Original bytes, not the selected row's edit buffer"** → `h.resolve(ActionForward, h.Raw, "")` at `intercept.go:747`; the request body is intentionally empty (no edit payload reaches the engine).
3. **"Count reported the way Drop all reports its"** → `{"forwarded": n}` answer at `api_intercept.go` (`handleInterceptForwardAll`), toast renders `result.forwarded` including the partial-resolution case (`intercept.tsx:790-798`).

### Phase 2 — Run the gates

```bash
cd burpsy-go
go build ./...
go test ./internal/intercept/ -run ForwardAll -v
go test ./internal/web/ -run Intercept -v        # if forward-all hand-tess exist
go vet ./internal/intercept/ ./internal/web/
```

UI side:

```bash
cd burpsy-go/internal/web/ui
bun install && bun run build                    # or the repo's verify.sh UI stage
```

Optional live check (repo ships these scripts):

```bash
./e2e-intercept.sh                              # hold ≥2 messages, then:
curl -s -X POST localhost:PORT/api/intercept/forward-all   # expect {"forwarded": N}
```

**Decision point:**
- All green + all three acceptance criteria confirmed → Phase 3 (close).
- Any gap (e.g., a regression dropped the button, tests fail) → fix first, using `DropAll` as the template layer by layer, re-run gates, then Phase 3.

### Phase 3 — Close the bead

The `bd` CLI is not installed in this environment, and the canonical store is `.beads/issues.jsonl` (one JSON object per issue). Mirror the format used by the 73 already-closed records (e.g. `burpsy-react-ui-01k0`):

1. In `.beads/issues.jsonl`, on the `burpsy-react-ui-4v3` record set:
   - `status`: `"closed"`
   - `updated_at` / `closed_at`: current timestamp in the existing format (`2026-09-02T…+03:00`)
   - `close_reason`: e.g. `"implemented: Engine.ForwardAll (internal/intercept/intercept.go), POST /api/intercept/forward-all, Forward-all toolbar button in pages/intercept.tsx; verified by TestEngine_ForwardAllForwardsEveryHeldMessageUnmodifiedAndCountsOnlyItsOwn"`
   - Leave `description`, `labels`, `created_*` untouched.
2. Sanitize: `python3 -c 'import json; [json.loads(l) for l in open(".beads/issues.jsonl") if l.strip()]'` — every line must still parse.
3. Confirm the count: open should drop 184 → 183.
4. Commit on `arena/01a060d3-burpsy`: `bd: close burpsy-react-ui-4v3 (intercept Forward all — already implemented, verified)`.

### Phase 4 — If verification instead finds the feature missing/broken

Fall-back implementation order (each layer has a DropAll twin to copy):

1. Engine: `ForwardAll() int` beside `DropAll` (`intercept.go`) — resolve with `h.Raw`, count only own resolutions, one `signalChange`.
2. API: `handleInterceptForwardAll` beside `handleInterceptDropAll` (`api_intercept.go`), route in `server.go` beside `/api/intercept/drop-all`.
3. UI: `forwardAll` mutation in `lib/data.ts`, button next to Drop all in `pages/intercept.tsx`, toast the returned count.
4. Tests mirroring `intercept_test.go`'s DropAll coverage. Then gates → Phase 3.

## Runner-up candidates (if this bead gets blocked)

- `burpsy-react-ui-1e4` (P2): message editor non-printing-character toggle — UI-only, self-contained.
- `burpsy-react-ui-10e` (P2): site-map delete — small, one endpoint + one control, but has an open design decision (suppress vs. delete underlying exchanges).
- `burpsy-react-ui-vlf` (P1): history search-modifier wiring — UI-only, but needs a new input + state split, slightly bigger.

## Repeatable loop for the remaining 183

1. Pick highest-priority open non-epic bead. 2. Verify the claimed gap still exists at HEAD (several appear stale). 3. Implement or confirm. 4. Run gates. 5. Close with evidence in `close_reason`.

---

## Execution log — 2026-09-02 ✅ CLOSED

Recon conclusion confirmed: the feature was already fully implemented; the bead was stale. All gates run green at HEAD:

| Gate | Result |
|---|---|
| `go build ./...` (Go 1.26.2) | clean |
| `go vet ./...` | silent |
| `go test ./internal/intercept/` | all pass, incl. `TestEngine_ForwardAllForwardsEveryHeldMessageUnmodifiedAndCountsOnlyItsOwn` |
| `go test ./internal/web/` | pass; `route_manifest_test.go` asserts `/api/intercept/forward-all` registered |
| `go test ./...` (38 pkgs) | all pass with repo-sanctioned env allowances `BURPSY_ALLOW_UNVERIFIED_EXTSCAN=1 BURPSY_ALLOW_NO_CHROME=1 BURPSY_ALLOW_UNVERIFIED_COVERAGE=1` (ffuf and Chrome binaries absent in sandbox; the skipped checks are the DOM/ffuf capability guards, unrelated to intercept) |
| UI `bun install && bun run build` | clean (app.js 311 modules, style.css) |
| UI `bun run check` (tsc --noEmit + token checks + lib tests) | 157 pass / 0 fail |
| Live end-to-end smoke (real proxy + origin) | 9/9: enable → hold POST → client stays blocked → `forward-all` returns `{"forwarded":1}` → held client completes with origin 200 → origin received **byte-exact original body** → empty queue honestly reports `0` |

Acceptance criteria status: (1) one action forwards every held message ✓ live-verified; (2) original bytes, not the edit buffer ✓ byte-exact at origin; (3) count reported like Drop all ✓ `{"forwarded": n}` incl. truthful 0.

Sandbox deviation note: no network to proxy.golang.org — Go 1.26.2 was bootstrapped from source (1.4→1.17→1.20→1.22→1.24→1.26 chain via codeload) and deps served from a local `file://` GOPROXY rebuilt from canonical GitHub mirrors. 50 of 55 module zips **hash-verified against the repo's committed go.sum**; 5 peripheral/unreachable-origin deps were trust-on-first-use from canonical mirrors (modernc.org/{libc,mathutil} via gitlab-snapshot GitHub mirrors, go-toast/v2 windows-only stub, fasttemplate + wails/v2 fetched but not in the linux build graph change paths) — go.sum was restored byte-identical afterwards (`git diff burpsy-go/go.mod go.sum` clean; rebuilt UI dist artifacts also reverted to committed copies).

Bead transition: `burpsy-react-ui-4v3` → `status: closed`, `closed_at` (Asia/Jerusalem), evidence-bearing `close_reason`. Board now **183 open / 74 closed**. Committed on `arena/01a060d3-burpsy`.
