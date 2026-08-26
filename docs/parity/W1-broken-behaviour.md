# W1 — STATE 5 hunt: reachable but WRONG (proxy / matchreplace / intercept / session)

Author: agt_sGUCorh (Backend). **Reconstructed** from shared context keys `parity_w1` and
`finding_matchreplace_param_targets` after the original was destroyed with the reaped
workspace. The defect below was proven behaviourally TWICE — once at `ede8f1f` and
re-proven at `a619c9a`.

## Headline

**1 confirmed STATE 5 in scope.** All other accepted-vs-handled tables across
`intercept`, `netauth`, `session`, `upstream`, proxy-options and toolkit came back
**clean** at `a619c9a`.

## STATE 5 — match/replace param targets silently rewrite the whole body

**Status at `a619c9a`: LIVE, not fixed.** A prior analyst reported this fixed; both
statements were partly true and the reconciliation is: **only the unknown-garbage
`rule_type` case was fixed.** These two known-but-unimplemented values still pass the
parser.

### The accepted-vs-handled mismatch

| Layer | File:line | Behaviour |
|---|---|---|
| API vocabulary | `api_toolkit.go:566-567` | lists `request_param_name`, `request_param_value` |
| API parser | `api_toolkit.go:595-598` | returns a **valid Target with nil error** |
| Handler | — | `NewRule` -> `s.matchReplace.SetRules()` into the **LIVE proxy ruleset**, answers `200 {"compiled":N}` |
| Engine switch | `matchreplace.go:242-253` | `applyOne` has **NO case for either**; both fall through to `default: return applyBody(raw)` |

### Behavioural proof (scratch copy at HEAD, no production code touched)

```
rule:   {request_param_name, literal, "secret" -> "harmless"}
body:   user=admin&secret=hunter2&nonsecret=keep
result: user=admin&harmless=hunter2&nonharmless=keep
                                    ^^^^^^^^^^^^^ UNRELATED parameter corrupted
```

It rewrote `nonsecret` -> `nonharmless` via **substring collision**, because the rule was
applied body-wide instead of to parameter names. `request_param_value` produces
**BYTE-IDENTICAL** output, which proves neither target is implemented — they are not two
bugs, they are one missing switch arm reached by two names.

### Why it is unguarded

`internal/matchreplace` tests **PASS** at HEAD. Nothing covers the accepted-but-unhandled
targets.

### Two false statements in the code and UI

1. The UI dropdown offers only 5 targets (`matchreplace.tsx:18-23`), so a user cannot
   reach this from the UI — but the API is public and accepts it.
2. The comment at `matchreplace.tsx:17` claims unknown targets *"silently become a no-op
   rule"*. **False on both counts:** these two are *accepted*, and `default` is a
   **body-wide rewrite**, not a no-op.

This is the same bug class the code comment at `api_toolkit.go:573-585` says the project
is built against — the guard was added for unknown values and missed the known ones.

## THE BUG CLASS (for W2/W3/W5 to sweep)

> An API-layer vocabulary — a string->enum parser, a switch on a `type` field, an accepted
> config key — that **ADMITS MORE VALUES than the engine-layer switch IMPLEMENTS**,
> terminating in a **silent non-error `default`** branch.

Method: tabulate ACCEPTED set (parser side) vs HANDLED set (engine side) with `file:line`
for both; anything in `accepted - handled` reaching a non-error default is a candidate;
prove each behaviourally in `/tmp`.

## NOT DETERMINED
- Whether any external consumer (extension, script, CI) actually sends these two
  `rule_type` values in practice. The defect is reachable; its field incidence is unknown.
