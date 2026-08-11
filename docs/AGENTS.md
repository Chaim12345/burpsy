<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# docs

## Purpose

Research notes that justify implementation decisions elsewhere in the tree. These are **findings, not
plans** — each one records what was measured against a real oracle (PortSwigger's own parser, the actual
crate APIs) so the code does not have to re-derive it and a reviewer can check the reasoning rather than
take it on trust.

Forward-looking work lives in `.planning/`, not here.

## Key Files

| File | Description |
|------|-------------|
| `BCHECK-RESEARCH.md` | The BCheck DSL: grammar, corpus statistics, and the implementation order they imply (519 lines) |
| `BCHECK-M2-SEMANTICS.md` | BCheck M2 runtime/evaluation semantics — the active-check milestone (623 lines) |
| `TLS-RESEARCH.md` | TLS interception with `rcgen` + `rustls`, verified against the compiler rather than the docs (455 lines) |

## For AI Agents

### Read the relevant note before changing the thing it describes

These files are where the non-obvious constraints are recorded. `BCHECK-RESEARCH.md` is why there is one
v2 parser rather than two (v2-beta is a strict superset of v1-beta), and why coverage is a stated number.
`TLS-RESEARCH.md` is why the CA and leaf-signing code looks the way it does. Changing `crates/bcheck` or
`crates/proxy/src/tls.rs` without reading the corresponding note usually means rediscovering something
already settled.

### They are historical records — correct them, do not silently rewrite them

If implementation reveals a finding here was wrong, say so explicitly and date the correction rather than
editing the claim away. The same discipline applies in `.planning/`: a measured correction to the
tokio-feature-narrowing claim is recorded in `.planning/phases/01-store-scope-chokepoint/01-CONTEXT.md`
and in `.planning/STATE.md` rather than quietly deleted, so a later phase cannot re-derive the wrong
conclusion.

### Verification style to match

Claims here carry their evidence and confidence: `[VERIFIED: ...]` for things checked against a primary
source this session, `[ASSUMED: ...]` for reasoned recommendations. Version numbers are checked against
`Cargo.lock` or the vendored source, not remembered. If you add a note, carry the same markers — an
unmarked assertion is indistinguishable from a verified one, which is the failure these markers exist to
prevent.

## Dependencies

### Internal

Descriptive only — nothing in `crates/` reads these files at build or run time. They inform
`crates/bcheck` (both BCHECK notes) and `crates/proxy/src/tls.rs` (the TLS note).

### External

None.

<!-- MANUAL: -->

## Diagrams

`diagrams/` is a LikeC4 workspace: the architecture model (`src/model.c4`, `src/views.c4`) and
rendered PNGs (`out/src/*.png`, one per view: system landscape, containers, and each crate's
components). The dotted `depends-on` edges mirror the real Cargo edges from the crate manifests;
regenerate after adding or moving a dependency edge:

```bash
cd docs/diagrams
npm install            # first time; installs likec4 CLI
npx likec4 validate    # must stay green
unset ANTHROPIC_API_KEY && npx likec4 export png -o out   # env var otherwise triggers an AI-package install
```
