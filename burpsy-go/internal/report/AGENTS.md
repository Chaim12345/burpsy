<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# report

## Purpose

Renders scan findings in the three downloadable formats the web UI links to and the CLI can emit: plain JSON, SARIF 2.1.0, and a self-contained HTML page. There is no matching Rust crate — this is a Go-side package. It holds no store: findings arrive as already-resolved `Row` values (hosts resolved, advisory HTML pre-sanitised) so both the web layer and the CLI share one renderer instead of drifting.

## Key Files

| File | Description |
|------|-------------|
| `report.go` | `Row`/`Advisory`/`Link`/`Evidence` display types and the three renderers: `JSON`, `SARIF`, `HTML`; plus severity ordering, the embedded CSS, and the per-finding HTML writers |

## For AI Agents

- **The renderer never guesses; the caller resolves.** Hosts are resolved by the caller (they need a store), and `Advisory.DescriptionHTML`/`RemediationHTML` have already been through the caller's `advisory.SanitisedHTML`. `HTML` embeds them verbatim — safe **only** because of that pre-sanitisation, which is why the field names say `HTML` out loud. Do not feed unsanitised strings into these fields.
- **Honest counting is enforced in the types.** `AdvisoryNote` records a *deliberate* catalogue absence ("no entry, and here is why") so it is distinguishable from "nothing looked"; `Evidence` turns a finding from an assertion into something reproducible. A report that has an advisory and does not print it is a defect here even if it renders.
- **HTML links are scheme-guarded.** `safeLinkURL` gates every rendered link; `writeLinks` skips ones that do not pass. Keep new link output going through it.
- **Findings render in severity order** via `severityOrder`/`severityRank` (CRITICAL→HIGH→MEDIUM→LOW→INFO), not input order.

## Testing Requirements

```bash
go test ./internal/report/...
```

## Dependencies

- Internal: none — despite the package doc's mention of `core`, the source imports no internal packages; the display types are defined here so the renderer stays store-free.
- External: standard library only (`encoding/json`, `html`, `net/url`, `sort`, `strconv`, `strings`, `time`, `fmt`).
