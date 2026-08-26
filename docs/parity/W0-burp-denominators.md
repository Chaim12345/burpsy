# W0 — Burp-Side Denominators

Author: CTO. Measured from Burp Suite 2026.7.1's own shipped jar resources
(`/root/burp-re`). **Reconstructed** after the original was destroyed with the reaped
workspace; the numbers below are the verified values as published to shared context key
`parity_w0`, not re-derived. Any re-derivation should confirm them.

## Resource file counts (Burp's shipped `resources/`)

| Dir | Files |
|---|---|
| BuiltInConfigs | 29 |
| PayloadStrings | 48 |
| KnowledgeBase | 366 |
| WebApi | 37 |
| Preferences | 10 |
| Documentation | 672 |

## Scan configuration depth — the sharpest gap found

Burp's 29 shipped configs set **83 distinct leaf keys across 20 sections**. 6 of those are
`description.*` metadata, leaving **77 functional keys**.

burpsy's `BuiltInConfig` struct has exactly **4 knobs**.

- **4 / 77 functional keys (5.2%)**, spanning **2 / 20 sections**.
- All 4 burpsy `burpKeys` were **VERIFIED present in Burp's JSON** — the transcription is
  honest, it is just tiny.
- **Entirely unrepresentable in burpsy:**
  - `scanner.insertion_point_types` — 8 keys. Controls **WHERE** the scanner injects.
  - `scanner.issues_reported` — 12 keys. Controls **WHICH** checks run.

A scanner whose insertion points and check selection cannot be expressed is not a
configurable scanner. This is the single largest capability gap on the Burp side of the
comparison.

## Intruder

- Burp ships **48 `.pay` wordlists**. burpsy bundles **ZERO** (`find -name '*.pay'` = 0),
  though it does have 6 generators.
- Attack types: **4 / 4 at parity.**

## Extender

- Montoya API = **282 class files across 25 packages**.
- burpsy implements **3 of Montoya's 13 `userInterface()` registration points**, and says
  so itself at `internal/extension/protocol.go:19-33`.
- Per TAXONOMY rule 7 this is a **DOCUMENTED DELIBERATE CAPABILITY GAP, not a defect.**

## FALSIFIED TRACKER CLAIM — Burp AI / MCP

`BURP_FEATURE_INVENTORY_VS_BURPSY.md` states: *"MCP server: Not present in 2026.7.1 = N/A"*.

**This is FALSE.** Burp 2026.7.1 bundles:
- **306 `io/modelcontextprotocol` classes**
- `burp/agentic/tool/McpBurpTool`
- its own strings `burpai.mcp.url`, `BURPAI_MCP_URL`, `Portswigger-Burp-Ai-Mcp-Nonce`,
  `setMcpConnectionState` (`map_root.tsv` lines 1575, 1579, 5465, 11575, 11665)

Burp AI total = **881 first-party classes** (agentic 813 + ai 68). burpsy has **none**.

**THE TRAP — record this, it is methodological:** `grep -rl modelcontextprotocol
out/clean/renamed_final/` returns **0** and would falsely *confirm* the tracker. That
corpus **excludes bundled `io/**` libraries**. A negative grep run in the wrong corpus is
exactly how the false "N/A" got ratified. This is the origin of TAXONOMY rule 3.

## NO AGGREGATE PERCENTAGE

None is offered and none should be. Config keys, wordlists, class counts and tool tabs do
not share a unit.
