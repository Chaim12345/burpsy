<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# session

## Purpose

Recorded-login re-authentication policy for authenticated scanning: scoped per target, bounded,
collapsed under concurrency, and honest about giving up. A recorded login survives session loss
automatically, on the operator's own terms for what "valid" means, without looping forever. This is
the Go port of `crates/session`; the shape matches (rule list, macro, extraction, validity, cookie
jar), but the Go version differs in one structural way — see below.

## Session handling is a rule *list*, not one always-on macro

`Coordinator` holds an ordered list of `SessionRule`s (`rules` map keyed by `RuleID`, plus an
`order` slice). Each rule has its own name, its own optional host scope, its own macro, its own
`ValidityRule` and its own `max_attempts` bound. `MatchingRule` walks `order` and returns the
*first* rule whose scope covers a host, so evaluation order decides which login runs. A request no
rule covers is reported as `RecoveryNoRuleApplies`, never logged into with another rule's
credentials.

## What differs from the Rust reference

Rust makes `SessionRule::new` the only door to a runnable rule, so an invalid rule cannot exist. Go
cannot: `SessionRule` is a plain struct callers assemble field by field (`NewSessionRule` is
deliberately permissive — the inert spec, holding one proves nothing has been checked). So validation
is a **separate pass** (`ValidateRule` / `validateRule` in `validate.go`) that `AddRule`,
`UpdateRule` and `RestoreRule` each run, so no install path can smuggle an unchecked rule in.

## For AI Agents

- **`RestoreRule` is not `AddRule`.** `AddRule` mints a fresh id from `nextID`; `RestoreRule` keeps
  the id a saved rule already carries. Using `AddRule` on a restore renumbers rule 3 to rule 1, and
  every recorded `RuleID` (an operator note, `POST /api/session/rules/3/run`) then names a different
  login macro — a call that *succeeds* against the wrong target. `RestoreRule` refuses id <= 0 and
  returns `ErrDuplicateRuleID` on collision, and advances `nextID` past every restored id.
- **Single-flight login is *per rule*, not global.** `runs map[RuleID]*loginRun` collapses N
  concurrent session-loss observations for one rule into one login the rest wait on. Per rule because
  two rules are two different logins; collapsing them would hand a caller a session for a target it
  never asked about.
- **`UpdateMacro` promotes only `observed` steps** — the steps the last *successful* login actually
  sent — so a failed run can never overwrite a working macro with a broken one.
- **`Indeterminate` is never treated as `Valid`.** `ValidityRule.Evaluate` returns `Valid` /
  `Invalid` / `Indeterminate`; a `status == 0` (nothing came back) is `Indeterminate`, not a pass.
- **Sending is a seam, not a call into the sender.** `MacroStepRunner` (`func(MacroStep)
  (*StepResult, error)`) is the only way this package reaches the wire; the web/CLI layer supplies a
  closure over the authorising sender. This package imports no transport and every test runs against
  a fake runner.
- **The JSON path is a deliberate subset** (`jsonpath.go`): top-level and nested keys, array index,
  optional leading `$`/`$.`. No recursive descent, wildcards, slices or filters — an extraction lifts
  exactly one value. An unsupported path is refused *at configuration time* by name, because a path
  accepted-then-unwalkable reads to an operator as "the token was not in the response" — blaming the
  target for a limit of this scanner. Numbers are lifted as the digits the server sent, never
  re-formatted through a float, so a 64-bit id survives.
- **`{{name}}` substitution is not a template language.** `Extraction` names one value out of a
  step's response (regex group, JSON path, or whole header); a later step writes `{{name}}`. A
  placeholder no *earlier* step extracts is refused — values resolve immediately before a step is
  sent, so a self- or forward-reference would go out on the wire verbatim.

## Key Files

| File | Description |
|------|-------------|
| `session.go` | `Coordinator`, `SessionRule`, `ValidityRule`, `Extraction`, `ExtractOutcome`, the cookie-jar manager, `RunMacro`, and `AddRule`/`RestoreRule`/`UpdateRule`/`RemoveRule`/`HandleResponse` |
| `recovery.go` | Named outcome types (`LoginOutcome`, `RecoveryOutcome`, `UpdateMacroOutcome`) and the recovery engine: bounding (`max_attempts`), per-rule single-flight (`ensureLoggedIn`, `loginRun`), `HandleRecovery`, `UpdateMacro`, and `{{name}}` resolve/untemplate |
| `validate.go` | Config-time validation (`ValidateRule`, `ValidateRuleStatedScope`, `RuleError`) — the separate pass that replaces Rust's construct-time check |
| `jsonpath.go` | The hand-rolled JSON-path subset and its by-name refusals (`parseJSONPath`, `walkJSON`) |

## Testing Requirements

```bash
go test ./internal/session/...
```

Tests reach no socket by construction — every one runs against a fake `MacroStepRunner`
(`recovery_test.go`'s `fakeSender`). Named as full-sentence claims, e.g.
`TestNConcurrentInvalidObservationsCauseOneLoginNotN`.

## Dependencies

Internal: none — `session` imports no other `internal/` package (it defines its own `MacroStep` /
`StepResult` and the `MacroStepRunner` seam rather than reaching for `sender` or `core`).

External: `go.uber.org/zap` (logging); standard library only otherwise (`regexp`, `sync`,
`sync/atomic`, `encoding/json` via struct tags).
