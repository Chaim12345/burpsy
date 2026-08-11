# burpsy-go — BCheck coverage (honest count)

burpsy runs PortSwigger's published BCheck corpus against real traffic. This page
states what that means honestly: what "coverage" actually measures, the numbers
recorded in `burpsy-go/gaps.md`, and — importantly — the difference between a
file *parsing* and a check *running*.

> **Coordination note.** The authoritative coverage numbers are owned by
> Security Research (issue **CS-11**, "independent re-verification of scanner
> correctness & honest coverage"). The figures below are transcribed from
> `burpsy-go/gaps.md` with their provenance; the runtime-supported count is
> marked **pending CS-11 confirmation** and must not be presented as final until
> CS-11 signs off. Never inflate these numbers.

## The corpus is not vendored

The `.bcheck` corpus is **not committed to this repository**. burpsy loads it at
runtime from a directory you supply with `-bchecks DIR` (see the
[Quickstart](./QUICKSTART.md#7-passive-scanning-with-bcheck-optional)). The
numbers below were counted against PortSwigger's published corpus as staged at
`/root/.cache/BChecks` during development — **264 files**.

## Two different numbers: parse vs. run

The single most important honesty point on this page:

> **A 100% parse rate says nothing about whether a check can actually run.**

- **Parse conformance** — can burpsy read and compile the file?
- **Runtime coverage** — given live traffic, can the check actually be
  dispatched, evaluate its expressions, and reach a verdict?

These are tracked separately on purpose. `gaps.md` records a runtime defect
(`java_backrefs`) and a class of builtin-argument defects (`base64_decode` and
the other single-argument builtins) that all **parsed at 100%** while evaluating
to `""` at runtime. Parse-green is necessary, not sufficient.

## Parse conformance

Measured with the bundled conformance tool:

```bash
go run ./cmd/conform /root/.cache/BChecks
```

Recorded result (`gaps.md`, "How the corpus was counted"):

> **264 parsed OK, 0 failed, accept rate 100.0%.**

(Run it *with* the path argument; a bare invocation reports `files: 0`.)

## What bounds runtime coverage

Even with every file parsing, several things bound how many checks can actually
run and fire against traffic:

1. **`given` family** — a check only runs when burpsy can produce the input its
   `given` clause asks for. The corpus distribution (`gaps.md`):

   | `given` family | files |
   |---|---|
   | response | 104 |
   | host | 98 |
   | request | 40 |
   | path | 11 |

   The 104 `given response` checks are the family the live-audit pipeline feeds
   most directly off proxied traffic; coverage of that family is *reported, not
   assumed*.

2. **`run tool` checks** — a check that shells out to an external binary is never
   passive and never runs unless you opt in with `-tools name=/abs/path`. Without
   an allowlisted runner it is **counted but not dispatched** (bucket "N need
   tools"); run directly without a runner it is refused as `ActiveUnsupported` —
   the same bucket as a check needing a Collaborator server.

3. **`given insertion point` / active checks** — these need the active-audit
   path, not passive proxying.

4. **The HPACK Huffman seam** — a documented, deliberate seam
   (`HpackHuffmanNotImplemented`) that is **identical in the Rust reference**
   (`slice 2b's seam`), so it is parity, not a Go shortfall.

## How burpsy reports coverage honestly at runtime

You never have to trust a static number. `GET /api/scanner/coverage` reports the
live state of every loaded check:

```bash
curl -s http://127.0.0.1:8081/api/scanner/coverage
```

Each check reports one of four states — `never dispatched`, `ran clean`,
`ran and found`, `errored` — plus a `skips` breakdown with the reason for every
skip (no checks loaded / exchange not in store / **host outside scope** /
response not in store). With nothing loaded the endpoint says
`"no passive checks loaded"` rather than implying a clean scan; the dashboard
likewise reports gated work (`"no passive check set is loaded … start with
--bchecks DIR"`) instead of silently counting zero.

*(Verified: loading a single `.bcheck` file makes the endpoint report
`loaded: 1`, `enabled: true`, and that check in state `never dispatched` until
traffic reaches it — the honest state, not a fabricated pass.)*

## Honest-counting guarantees (from `gaps.md`)

- Parse success ≠ run success: files whose `given` family cannot be produced are
  **declined/skipped and named**, never silently empty.
- Everything not evaluable is *counted*, not dropped (e.g. the nine `filecontent`
  patterns that exceed RE2's 1000-repeat ceiling are named individually in
  `DatasetSummary.NarrowedPatterns`).
- The retire.js dataset embedded for the JS-library checks yields the same counts
  the Rust reference asserts (76 components, 683 vulnerabilities), with real
  version arithmetic rather than a prefix test.

## Provenance and open items

- **Parse conformance (264/264, 100%)** — well-evidenced, reproducible via
  `cmd/conform`.
- **Runtime-supported count** — **pending CS-11 confirmation.** The mechanism
  (per-check `/api/scanner/coverage`) is real and verified; a single headline
  "N of 264 fully supported at runtime" number should be published only once
  Security Research has independently re-verified it under live audit.

> **Known stale metadata (defect filed):** the board/project description still
> reads "232/264 of PortSwigger's published checks". That predates the M3 work
> recorded in `gaps.md` (which reports 264/264 *parse* conformance) and conflates
> parse with runtime coverage. It should not be cited as the coverage number.
> Flagged back to the CEO / Security Research for correction — see the CS-14
> issue thread.
