# burpsy web UI — interaction map, UAT matrix, design analysis

Three layers, in the order they were produced. Each was checked against the running application
rather than trusted from source alone.

## Layer 1 — What exists

Every interactive element, data hook, piece of local state, cross-page effect, action flow and
empty/loading/error state, with copy quoted verbatim.

| File | Covers |
|---|---|
| `01-target.md` | Site map, Issues, Scope |
| `02-proxy.md` | Intercept, HTTP history, WebSocket history, Match & Replace |
| `03-attack.md` | Intruder (5 sub-tabs), Repeater, Sequencer, Session |
| `04-workbench.md` | Decoder, Comparer, Organizer, Logger, Dashboard, Settings |
| `05-shell.md` | Routing, hotkeys, menu bar, command palette, shared components |
| `06-data-api.md`, `06b-endpoint-cross-check.md` | 47 endpoints, query keys, mutations, SSE, store |

## Layer 2 — Every route through it, with a test

`uat/` — **1,298 UAT cases**, one row per distinct path a user can take. Each carries a precondition,
numbered runnable steps, an exact expected result, and a type
(happy / alternate-entry / empty-state / boundary / error / keyboard / a11y).

| File | Cases |
|---|---|
| `uat/01-target-uat.md` | 215 |
| `uat/02-proxy-uat.md` | 292 |
| `uat/03-attack-uat.md` | 413 |
| `uat/04-workbench-shell-uat.md` | 378 |

Every file ends with a `## Coverage` table mapping element → cases, so an untested element is visible
immediately.

**Read this caveat before using the matrix as a gate.** These cases were derived from the source, and
a derived expectation is a hypothesis until it is run. Around 3% initially carried hedged expected
results ("server parses or rejects", "may show"), which are not tests — a case that cannot fail
proves nothing. The filter-DSL cases were resolved against the live parser and rewritten with exact
error strings; the remainder are marked where uncertainty stands. Treat an unrun case as a
specification, not as evidence.

## Layer 3 — Verification and analysis

| File | What it is |
|---|---|
| `00-verification.md` | What the *running* app does, measured against the map: route sweep, element census, endpoint probe, driven flows, and the defects that surfaced |
| `07-design-analysis.md` | Measured design forensics — type scale, palette with area shares, composition, elevation, motion — followed by a short critique |

## Defects this work found

Each was found by testing the map, not by reading it, and each is fixed with a regression test.

1. **Findings reported against the wrong URL.** An exchange was looked up by *message* id; both id
   spaces are dense counters from zero, so the lookup returned a real but unrelated exchange. A
   finding on `/search` was reported against `/login`, and every exported report carried wrong
   hostnames.
2. **Repeater resends grew a phantom site-map branch** — an absolute-form request line became the
   exchange path, splitting into `http:` → `` → `host:port` → `login`.
3. **Exchange 0 was unreachable** in five places — the organizer plus four frontend validators all
   used `<= 0`, rejecting the first request captured in a session.
4. **Three dead CA-certificate affordances** offered a download that 404s whenever TLS interception is
   off, which is the default.
5. **Contrast failures on the security signal itself** — severity colours at 2.64:1, editor header
   values at 3.52:1, line numbers at 2.10:1.
6. **A type scale pinned to its floors** — `0.76vw` meant a 1440px laptop got 11px body text; the
   fluid middle term was unreachable below ~1450px.
7. **No focus ring on the message editors**, the surface an operator spends the most time in.
8. **Unlabelled leaf tree toggles**, and `1 EXCHANGES WITHOUT A VERDICT` failing to singularise.
