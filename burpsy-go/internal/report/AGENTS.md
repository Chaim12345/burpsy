<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-10-08 -->

# report

## Purpose

Renders scan findings in the four downloadable formats the web UI links to and the CLI can emit: plain JSON, SARIF 2.1.0, a self-contained HTML page, and Burp's issue-data XML. There is no matching Rust crate — this is a Go-side package. It holds no store: findings arrive as already-resolved `Row` values (hosts resolved, advisory HTML pre-sanitised) so both the web layer and the CLI share one renderer instead of drifting.

## Key Files

| File | Description |
|------|-------------|
| `report.go` | `Row`/`Advisory`/`Link`/`Evidence` display types and the renderers: `JSON`, `SARIF`, `HTML`, and `HTMLWithSettings`; the `Settings` type (Burp's report-settings choices — title, organisation, TOC depth, issue-detail sections, message mode and length); severity ordering; the embedded CSS; and the per-finding HTML writers |
| `burpxml.go` | `BurpXML`, the Burp-XML issue export: Burp's internal DTD embedded verbatim, the per-issue element sequence, Base64 `requestresponse` pairs, and the escapers that keep text round-tripping through a validating parser |

## For AI Agents

- **The renderer never guesses; the caller resolves.** Hosts are resolved by the caller (they need a store), and `Advisory.DescriptionHTML`/`RemediationHTML` have already been through the caller's `advisory.SanitisedHTML`. `HTML` embeds them verbatim — safe **only** because of that pre-sanitisation, which is why the field names say `HTML` out loud. Do not feed unsanitised strings into these fields.
- **Honest counting is enforced in the types.** `AdvisoryNote` records a *deliberate* catalogue absence ("no entry, and here is why") so it is distinguishable from "nothing looked"; `Evidence` turns a finding from an assertion into something reproducible. A report that has an advisory and does not print it is a defect here even if it renders.
- **HTML links are scheme-guarded.** `safeLinkURL` gates every rendered link; `writeLinks` skips ones that do not pass. Keep new link output going through it.
- **Findings render in severity order** via `severityOrder`/`severityRank` (CRITICAL→HIGH→MEDIUM→LOW→INFO), not input order. The grouped organisations (`groupRows`, by type and by URL) keep that worst-first order *within* each group.
- **Settings widen the report, they never replace it.** Zero `Settings` must render what `HTML()` always rendered; `sectionOn` with no list prints every section. A new setting that changes the zero-value output is a regression, not a feature.
- **Messages are caller-attached and already bounded.** `Row.Messages` (`AttachedMessage`) carry the bytes the export holds — the caller picked the mode ("relevant" extract or "full") and applied `MaxMessageLen` before attaching. Renderers print what is there and mark `Truncated`/`HeadersOnly`; they never read the store or second-guess the caller. See gaps.md for why "relevant" is the header block.
- **The Burp-XML writer reproduces Burp's grammar, not an approximation.** The DTD in `burpXMLDTD` is verbatim from the decompiled writer (`burp.Zb2g.ZI`); element order follows the content model; required elements are written even when empty. Messages are always `base64="true"` — the `base64="false"` variant cannot carry byte-exact data (see gaps.md). Anything that would deviate goes through the escapers `xmlText`/`xmlAttrValue`, and a deliberate divergence is recorded in gaps.md with its decompiled citation.
- **`sanitisedHTMLToText` is safe only on `SanitisedHTML` output.** It is a tag scanner, not an HTML parser; its input grammar is the sanitiser's (allowed elements, no attributes, no comments). Pointing it at anything wider would be an HTML parser written in `IndexByte`. The contract is stated in its doc comment — keep it that way.

## Testing Requirements

```bash
go test ./internal/report/...
```

The Burp-XML tests validate with `xmllint --valid` when it is installed and skip with a reason naming the missing binary otherwise — the same honest-skip convention as the extscan live tests. CI installs `libxml2-utils` so the skip does not happen there.

## Dependencies

- Internal: none — despite the package doc's mention of `core`, the source imports no internal packages; the display types are defined here so the renderer stays store-free.
- External: standard library only (`encoding/json`, `encoding/base64`, `html`, `net/url`, `sort`, `strconv`, `strings`, `time`, `fmt`).
