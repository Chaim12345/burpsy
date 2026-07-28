<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-07-28 | Updated: 2026-07-28 -->

# bcheck (`burpsy-bcheck`)

## Purpose

Parser and evaluator for PortSwigger's BCheck DSL. The premise: Burp's scan checks are largely **data,
not code**, so implementing one interpreter inherits PortSwigger's published corpus instead of porting
hundreds of Java checks by hand.

The grammar was established empirically against `BCheckChecker-1.9.jar` — PortSwigger's own CongoCC
parser, shipped in the BChecks repo — used as a conformance oracle rather than guessed from the docs.
Four findings shaped the implementation, and they are written out in `src/lib.rs`; the load-bearing one
is that **v2-beta is a strict superset of v1-beta** (four added tokens, none removed), so a single v2
parser accepts 100% of the corpus even though 78% of files declare v1-beta.

This crate also owns the `Sender` trait and `Target` — the seam between a check that wants to send
something and whatever actually does. It has **no transport of its own**, on purpose.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | Crate root; the four empirical grammar findings and what they imply |
| `src/lexer.rs` | Tokeniser. Whitespace and newlines are insignificant — a whole check on one line parses |
| `src/parser.rs` | Recursive-descent parser over the token stream |
| `src/ast.rs` | The M1 (passive) AST subset, with the shape already reserved for M2/M3 |
| `src/eval.rs` | The evaluator, plus the `Sender` trait and `Target`. Deliberately synchronous and recursive |
| `src/funcs.rs` | Expressions inside `{…}` |
| `src/insertion.rs` | Insertion points — where in a request a payload can be placed |
| `src/bin/conform.rs` | Conformance runner: parse a tree of `.bcheck` files and report what we accept |

## For AI Agents

### The evaluator is synchronous on purpose

`eval.rs` is recursive and blocking. Making it async would force `Box::pin` through every `exec` /
`eval_bool` for no benefit, and the crate's doc comment says so. This is why `burpsy-sender` keeps a
blocking transport at all — do not "modernise" this into an async evaluator and then bridge it with a
blocking runtime call, which would undo the reasoning rather than satisfy it.

### `Sender` must stay an open trait

It is implemented by test doubles here (`TargetSpy`, `MockSender`) and in `scanner`
(`SlowSender`, `RecordingSender`, `FailingSender`) precisely so tests can prove traffic did or did not
reach a socket. Sealing it would remove the mechanism that makes egress testable. See
`../sender/AGENTS.md` for the property that is enforced instead.

### Conformance is the measure, not unit tests alone

`src/bin/conform.rs` parses a corpus tree and reports acceptance. `verify.sh` runs it as a gate step
and reports "corpus not present, conformance skipped" when the corpus is absent — which is a *skip*,
loudly, not a pass. If you change the grammar, run conformance against the real corpus rather than
inferring from the unit tests.

### Testing Requirements

```bash
cargo test -p burpsy-bcheck            # 103 tests
cargo run -p burpsy-bcheck --bin conform -- <corpus-dir>
```

### Common Patterns

- Acceptance is counted and reported, never rounded up. The project's stated coverage — currently 105
  of 264 published checks runnable, the rest active or Collaborator-dependent — is a stated number.
  Code that makes an unrunnable check look runnable is a defect here even if it parses.
- The AST reserves shape for milestones that do not exist yet. Extending it is expected; silently
  changing what an existing node means is not.

## Dependencies

### Internal

- `burpsy-core` — `MsgId`, `Span`, `StoredMessage`, the message model checks evaluate against

### External

- `regex` — matching inside checks
- `bytes`, `serde`

<!-- MANUAL: -->
