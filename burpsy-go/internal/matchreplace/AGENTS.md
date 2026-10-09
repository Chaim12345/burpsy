<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# matchreplace

## Purpose

Ordered rewrite rules applied to proxied requests and responses on the proxy hot path — the Go home of what the Rust `burpsy-tools` crate keeps in its `matchreplace` module. Compiled regex (or literal) rules, the Burp-compatible `rule_type` taxonomy, optional Content-Length fix-up after a body rewrite, and Burp's set-wide "Only apply to in-scope items" restriction.

**There is no per-rule scope, and that is Burp's model rather than a gap.** Burp persists a rule as `rule_type`, `enabled`, `category`, `string_match`, `string_replace` and `comment` and nothing else (`Zejh.ZY`), and its rule table has no scope column (`CoreComponent5002`). Its one scope control is the panel checkbox, persisted as `proxy.match_replace_disable_out_of_scope` — which reads as the opposite of the control, so the field here is named after the checkbox and the key is written down in `SetInScopeOnly`'s comment. A wire rule carrying the Rust-era per-rule `scope`/`query` is **refused** by `internal/web`, not saved without it.

## Key Files

| File | Description |
|------|-------------|
| `matchreplace.go` | Everything: `Target`/`Category`/`Direction` enums, `Rule` + `NewRule` (compiles the regex), `RuleSet` (`SetRules`/`AddRule`/`Apply`/`Affects`, plus the set-wide `SetUpdateContentLength` and `SetInScopeOnly` switches and the `ScopeSkipped` count), and the header/body/first-line appliers |

## For AI Agents

- **`Target` values mirror Burp's `rule_type` config strings** (request/response × header/body/first-line), so a Burp config maps across directly. Keep them aligned.
- **`Apply` dispatches by section, not by blind whole-message regex.** `applyBody`, `applyHeaders` and `applyFirstLine` are separate so a header rule cannot corrupt the body and vice versa. A rule targeting a section that does not apply to the given `Direction` is skipped (`targetsDir`).
- **A blank match means "add a header" and nothing else.** On a request/response header rule (literal or regex) the replacement is appended as a new header line, per Burp; every other target refuses a blank match in `NewRule` (wrapping `ErrEmptyMatch`), as does a blank-match header rule whose replacement is empty, multi-line or starts with whitespace. `applyOne` re-checks, so a `Rule` built without `NewRule` is inert. Never let a blank match reach `bytes.ReplaceAll`/`regexp.ReplaceAll` — it matches between every byte (burpsy-react-ui-wtm2).
- **Use `regexReplaceAll`, not `r.re.ReplaceAll`.** The latter returns nil for an input rewritten to nothing, and nil means "did not fire" to every applier.
- **Content-Length is only corrected when opted in.** `fixContentLength` runs after a body rewrite only if `SetUpdateContentLength(true)`; otherwise the header is left exactly as the rule produced it. Do not make this automatic — a rule may be deliberately testing a mismatched length.
- **`Affects(dir)` lets the proxy skip the whole pass** when no rule targets a direction — the cheap check before touching the bytes.
- **The in-scope restriction is a *flag* here and a *decision* in the proxy.** `Apply` deliberately does not consult it: this package sits below `core` and imports neither the scope matcher nor the store, so it cannot answer an in-scope question, and the caller (`proxy.applyMatchReplace`) holds both the target and the scope and reports what it turned away via `NoteScopeSkipped`. Do not give this package a scope dependency to "simplify" that — it is the dependency direction the whole tree is built on.
- **`Apply` is the byte-level primitive, not the call-site contract.** It does not check `Affects` or the restriction; the proxy's single door onto the set does both. Calling `Apply` directly from a new surface re-introduces the bug the helper exists to prevent.

## Testing Requirements

```bash
go test ./internal/matchreplace/...
```

## Dependencies

- Internal: none — a leaf package.
- External: standard library only (`bytes`, `regexp`, `strconv`, `sync`).
