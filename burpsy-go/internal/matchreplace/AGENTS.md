<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# matchreplace

## Purpose

Ordered rewrite rules applied to proxied requests and responses on the proxy hot path — the Go home of what the Rust `burpsy-tools` crate keeps in its `matchreplace` module. Compiled regex (or literal) rules with per-rule scope, the Burp-compatible `rule_type` taxonomy, and optional Content-Length fix-up after a body rewrite.

## Key Files

| File | Description |
|------|-------------|
| `matchreplace.go` | Everything: `Target`/`Category`/`Direction` enums, `Rule` + `NewRule` (compiles the regex), `RuleSet` (`SetRules`/`AddRule`/`Apply`/`Affects`), and the header/body/first-line appliers |

## For AI Agents

- **`Target` values mirror Burp's `rule_type` config strings** (request/response × header/body/first-line), so a Burp config maps across directly. Keep them aligned.
- **`Apply` dispatches by section, not by blind whole-message regex.** `applyBody`, `applyHeaders` and `applyFirstLine` are separate so a header rule cannot corrupt the body and vice versa. A rule targeting a section that does not apply to the given `Direction` is skipped (`targetsDir`).
- **Content-Length is only corrected when opted in.** `fixContentLength` runs after a body rewrite only if `SetUpdateContentLength(true)`; otherwise the header is left exactly as the rule produced it. Do not make this automatic — a rule may be deliberately testing a mismatched length.
- **`Affects(dir)` lets the proxy skip the whole pass** when no rule targets a direction — the cheap check before touching the bytes.

## Testing Requirements

```bash
go test ./internal/matchreplace/...
```

## Dependencies

- Internal: none — a leaf package.
- External: standard library only (`bytes`, `regexp`, `strconv`, `sync`).
