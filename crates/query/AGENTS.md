<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-02 | Updated: 2026-08-02 -->

# query (`burpsy-query`)

## Purpose

A typed filter grammar over proxy history, evaluated against a trait rather than a concrete type.
The one query language shared by the consumers that filter on traffic: history filters (DSL-01),
match-and-replace rule selection (DSL-02), and — once Phase 6 lands — crawl/audit scoping (DSL-03).

## Why not `rhai`, or any embedded scripting language

The project considered and rejected an embedded interpreter. A script buys expressiveness an
operator filtering history does not need, and gives up the property they do need: `status > "abc"`
must be rejected before a single row is compared, not evaluated to `false` because comparing a
number to a string happens to be falsy. A typed grammar makes that a parse-time error; a
general-purpose script only offers a runtime one, in the one place — a history filter — where a
runtime failure is easiest to mistake for "no matches". DSL-04 exists to close exactly that gap, and
it can only be a compile-time guarantee if the grammar is typed and closed, not an interpreter over
an open language.

## Why this crate does not depend on `burpsy-core`

The obvious model is a query over `Exchange`. That is also the wrong dependency: it would make the
grammar and evaluator untestable without a store, a message parser, and everything else `core` pulls
in. Instead the grammar evaluates against `Queryable`, a trait a consumer implements over whatever
its own row type is. DSL-02 is proved directly by running one parsed `Query` against two unrelated
`Queryable` fakes.

## Grammar

```
query      := or_expr
or_expr    := and_expr ( "or" and_expr )*
and_expr   := unary_expr ( "and" unary_expr )*
unary_expr := "not" unary_expr | primary
primary    := "(" or_expr ")" | comparison
comparison := field op value
field      := "host" | "status" | "method" | "mime" | "body"
```

- `not` binds tighter than `and`, which binds tighter than `or`.
- `host`, `method`, `mime`: `==`, `!=`, `~` (contains), quoted string value. `host` and `mime`
  compare case-insensitively; `method` does not (the method token is case-sensitive per RFC 7230).
- `status`: `==`, `!=`, `<`, `<=`, `>`, `>=` with an integer, or `in low..high` inclusive range. A
  literal that doesn't fit `u16` is rejected at parse time.
- `body`: `~` only, against the raw bytes. No equality — matching a whole body byte-for-byte is
  never what an operator means.
- Quoted strings support `\"`, `\\`, `\n`, `\t`, `\r`.

## Key Files

| File | Description |
|------|-------------|
| `src/lib.rs` | `Query` façade, grammar rationale |
| `src/lexer.rs` | Tokenisation, including string escapes |
| `src/parser.rs` | Recursive-descent parser; precedence and per-field operators checked here |
| `src/ast.rs` | The closed AST |
| `src/eval.rs` | Evaluation against `Queryable`; absent fields make comparisons false, never true |
| `src/error.rs` | `QueryError` / `render` — where and why a parse failed, caret included (DSL-04) |

## Testing Requirements

```bash
cargo test -p burpsy-query      # 42 tests, all inline, against bare fakes
cargo test --workspace
```

No store, no network, no `core` — the crate is testable in isolation by construction.

## Dependencies

### Internal

None. A leaf: `core`, `tools`, and `web` depend on it.

### External

None — the `[dependencies]` table is deliberately empty. A closed grammar needs no JSON layer of its
own; consumers (`web`) turn it into and out of their own wire types.

<!-- MANUAL: -->
