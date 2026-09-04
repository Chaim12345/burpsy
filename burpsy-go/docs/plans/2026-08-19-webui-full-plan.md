# Web UI Burp-Parity — FULL PLAN & TASK LEDGER (all tasks)

> **Created 2026-08-19 (updated with current state).** Companion to the working memory
> (`2026-08-19-webui-parity-working-memory.md` — verified API surface + page status) and the
> desktop bridge plan (`2026-08-19-desktop-app-bridge.md` — Phase 4 here expands it with task IDs).
> This file is the master task ledger: every task has an ID, page, status, and acceptance check.
> Status legend: ⏳ todo · 🔄 in progress · ✅ done · ⛔ deliberately not doing (documented).

## The goal
Bring `burpsy-go/internal/web/ui` (React SPA, 17 pages) to full Burp Suite look-and-feel parity —
menus, data, actions, UX — page by page. Add backend endpoints only when a frontend feature needs
them. Then wrap in a native desktop shell (Wails). **Honest counting throughout**: no headline
parity % until re-verified; gaps are documented, not hidden.

## Phase 0 — Foundations (mostly done)
| Task | Status |
|---|---|
| P0-1 Working memory file with verified API surface | ✅ done |
| P0-2 Go gate + UI gate documented (`bun run check` / `bun run build` / go build/vet/fmt/test) | ✅ done |
| P0-3 Intercept page full parity (drop-all backend, direction filter, context menu, tabs, status bar) | ✅ done (commits a5deab4, cbc043d, e5938a2) |
| P0-4 History page MIME filter + CSV export | ✅ done (commit 599e489) |

## Phase 1 — Core daily-driver pages (highest Burp usage)
| Task | Page | Status | Acceptance |
|---|---|---|---|
| P1-1 History: MIME column in table + status bar counts | history.tsx | ✅ | Commits 599e489 + 9ec0b76: MIME/Type column, status bar with visible/loaded totals, response bytes, pending, selected |
| P1-2 Repeater: multi-tab + per-tab request history + message analyser | repeater.tsx | ✅ | 313 lines: tabs persisted in store, per-tab response history with paging, Inspector analyser |
| P1-3 Repeater: backend wiring via authorised sender | api_tools.go | ✅ | /api/repeater/send exists (repeater is the documented host-level exception) |
| P1-4 Intruder: payload positions + attack types | intruder.tsx | ✅ | 790 lines: Positions tab + sniper/battering_ram/pitchfork/cluster_bomb modes |
| P1-5 Intruder: results table + attack run | intruder.tsx + api_tools.go | ✅ | Results tab; /api/intruder/points + /api/intruder/run routes exist |
| P1-6 Scanner: scan wizard + issue table | scanner.tsx | ✅ | 802 lines: issue table with severity, live audit toggle, /api/scanner/* routes |
| P1-7 Scanner: configuration editor | scanner.tsx | ✅ | Config selector + coverage view + advisory/request/response tabs |
| P1-8 Target/SiteMap | sitemap.tsx | ✅ | 555 lines: host→path→segment tree, expand/collapse, search, actions.menu; scope editor |

## Phase 2 — Tool pages
| Task | Page | Status | Acceptance |
|---|---|---|---|
| P2-1 Dashboard | dashboard.tsx | ✅ | 255 lines: metrics, task table, activity feed via useDashboard |
| P2-2 Decoder | decoder.tsx | ✅ | 391 lines: chained decode/encode/hash steps |
| P2-3 Comparer | comparer.tsx | ✅ | 327 lines: A/B diff with nav + download |
| P2-4 Sequencer | sequencer.tsx | ✅ | 584 lines: paste/live sources, /api/sequencer/analyse |
| P2-5 Logger | logger.tsx | ✅ | 365 lines: filter/search, column visibility, menuGroups |
| P2-6 Organizer | organizer.tsx | ✅ | 333 lines: saved exchanges + notes |
| P2-7 Match/Replace | matchreplace.tsx | ✅ | 457 lines: rules + test against pasted request |
| P2-8 WS History | wshistory.tsx | ✅ | 284 lines: connections + frame detail |
| P2-9 Session | session.tsx | ✅ | 1064 lines: rules, cookies, login macro runner |
| P2-10 Settings | settings.tsx | ✅ | 501 lines: protocols, appearance, CA, diagnostics, scope editor |

## Phase 3 — Backend gaps (add only when a frontend feature needs them)
| Task | Status | Notes |
|---|---|---|
| P3-1 POST /api/intercept/drop-all | ✅ done | `Engine.DropAll`, handler, route, manifest, test |
| P3-2 History CSV | ✅ done (client-side) | Prefer client-side `downloadText`; no endpoint needed |
| P3-3 IP address column | ⛔ deliberate gap | `Exchange` has no ip field; document instead of changing store |
| P3-4 Delete-from-history | ⛔ deliberate gap | TrafficStore is append-only by design; document |

## Phase 4 — Desktop app bridge (Wails v2)
| Task | Status | Acceptance |
|---|---|---|
| P4-1 Wails dependency + cmd/desktop/main.go | ⏳ | `wails build` produces native binary; serves embedded UI |
| P4-2 src/lib/runtime.ts (desktop/web detection + bindings) | ⏳ | `window.wails` branch vs fetch fallback |
| P4-3 System tray + native menus | ⏳ | Tray icon; File/Edit/View/Tools/Help menu bar |
| P4-4 File dialogs + notifications | ⏳ | Save/export dialogs; scan-complete notifications |
| P4-5 Hybrid mode (desktop + web server together) | ⏳ | Both surfaces work; port documented |
| P4-6 docs/DESKTOP.md (build/run/distribute) | ⏳ | Fresh user can build and run |

## Phase 5 — Verification & honest counting
| Task | Status |
|---|---|
| P5-1 Per-page gate: bun check + bun build after each page | ✅ habit |
| P5-2 Go gate when backend touched (build/vet/fmt/test) | ✅ habit |
| P5-3 e2e-ui.sh after major page work | ⏳ |
| P5-4 Final parity re-verification + honest report (no unverified headline) | ⏳ |

## Cross-cutting rules
1. **menuGroups**, not contextMenu — VirtualTable prop (memory line 11).
2. **SplitPane**: orientation/master/detail/storageId (memory line 17).
3. Backend work only when frontend needs it; route + manifest entry + test together.
4. Every send goes through `sender.AuthorisedSender` (repeater is the documented exception — host-level).
5. Update the working memory after every file read/write/verification.
