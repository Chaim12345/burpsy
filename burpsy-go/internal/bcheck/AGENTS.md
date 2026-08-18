<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->
<!-- Parent: ../AGENTS.md -->

# bcheck

## Purpose

Parser and evaluator for PortSwigger's BCheck DSL. The premise is unchanged from the Rust
reference: Burp's scan checks are largely **data, not code**, so one interpreter inherits
PortSwigger's published corpus instead of porting hundreds of Java checks by hand.

This package owns the whole DSL pipeline — lexer, recursive-descent parser, the passive and
active evaluators, and insertion-point enumeration — plus the seams a check needs to reach the
outside world: the `Sink` interface (where a send goes), `Target` (the exchange's own authority),
and the `ToolRunner` interface (the `run tool` external-process seam). It has **no transport of
its own**, on purpose: every send is handed to the caller's `Sink`, and every send is built from
the base request, never from the previous send.

## Key Files

| File | Description |
|------|-------------|
| `bcheck.go` | Package root. AST types (`Check`, `Statement` and its variants, `Value`, `BoolExpr`), `Context`, the passive evaluator and shared statement machinery (`runCheckBody`, `executeBlock`, `evalBoolExpr`, `interpolate`), and the milestone-classification methods (`IsPassive`, `NeedsCollaborator`, `NeedsTool`, `M2Runnable`) |
| `parser.go` | Lexer (`lex`) and recursive-descent parser (`Parse`). Whitespace and newlines are insignificant; the token stream is flat and `end if` is the only block terminator |
| `active.go` | The active evaluator: `send request` (M2) and `given insertion point` / `send payload` (M3). Defines the `Sink` and `ToolRunner` interfaces, `Target`, `RequestModifier`, and `RunActive` |
| `insertion.go` | Insertion points — `Enumerate`, `InsertionPoint`, `IpKind`. Each point is a byte range into one component of the base request, not a copy |
| `bcheck_test.go`, `active_test.go`, `insertion_test.go`, `run_tool_test.go` | Unit tests, including `mockToolRunner` and other doubles that prove traffic/tool runs did or did not happen |

## For AI Agents

### The passive and active paths share one evaluator

`active.go` is built on the same statement evaluator the passive path uses — both go through
`runCheckBody`, `executeBlock`, and `evalBoolExpr`. A statement's meaning cannot diverge between
passive and active; do not fork the semantics.

### Send semantics that are easy to get backwards

- `base` and `latest` are different messages after a send. Every send updates `latest` (named or
  not, `send request` or `send payload`); before the first send they are the same exchange.
- Every send is built from `base.request`, never from the previous send. Modifiers within one
  `send request` accumulate; sends do not. A second `send payload` is base+payload, not
  payload+payload.
- A failed send abandons the check — continuing would leave `{check.response}` absent and invite
  the exact false positive the absence rules prevent.
- A `given insertion point` check runs once per point, mutating **exactly one** point per send, so
  a finding is attributable to a single parameter. `Finding.Param` carries that name and is empty
  outside a `given insertion point` check — a per-host/per-request finding is about a resource, not
  a parameter, and leaving `Param` empty is what keeps the report's Parameter column honest.

### Egress goes through the caller's Sink, bound to Target

The check chooses the bytes; it never chooses the connection. A raw `send request` naming a
different Host still travels to the exchange the scan started from. This is the evaluator's half of
the egress chokepoint (`internal/sender` is the authorising path on the other side). The `Sink`
and `ToolRunner` interfaces are open so tests can substitute doubles and prove what reached a
socket or spawned a process — keep them open.

### Honest counting is enforced at classification time

`IsPassive` requires `given response` and no send and no `run tool`; `NeedsCollaborator`,
`NeedsTool`, and `M2Runnable` bucket everything else. A `run tool` statement counts as outbound
activity, so a check carrying one is never passive and is refused without a configured runner rather
than run against nothing. Do not widen these predicates to make an unrunnable check look runnable.

### Insertion points are offsets into the base request

`Enumerate` returns byte ranges, not request clones, so enumerating every point costs labels, not
copies. Apply must always be handed the request the point was enumerated from — applying twice, or
to an already-mutated request, splices at offsets that no longer mean what they meant. Nested points
are deliberately **not** enumerated (a miss, never a false positive); `any` **includes headers**
(JWT checks depend on it).

### Go-specific hardening not in the Rust reference

- `compiledRegexCache` (a `sync.Map`) memoises regex compilation across `run for each` iterations.
  Go's `regexp` is RE2 (linear-time), so this is a performance fix, not a ReDoS fix.
- `maxForEachDim` (10000) and `maxForEachProduct` (100000) bound `run for each` lists and their
  cartesian product, stopping a hostile check from turning the evaluator into a DoS.

## Testing Requirements

```bash
go test ./internal/bcheck/...
```

Parse conformance against the real corpus is run separately via the `conform` driver under
`cmd/` (see `burpsy-go/cmd/AGENTS.md`); a missing corpus is reported as a loud skip, not a pass.

## Dependencies

### Internal

- `internal/core` — `RequestEdit` and the message model checks evaluate against (via `MsgId` /
  `Span` / stored messages)

### External

- Standard library only for evaluation: `regexp` (RE2), `context`, `sort`, `strconv`, `strings`,
  `sync`, `unicode/utf8`. Unlike the Rust crate, there is no third-party `regex` dependency —
  Go's stdlib `regexp` is used directly.
