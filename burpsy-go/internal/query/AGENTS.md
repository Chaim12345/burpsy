<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-08-18 | Updated: 2026-08-18 -->

# query

## Purpose

burpsy's filter grammar over captured traffic: one small, closed, typed language shared by the History filter box, the CLI's `history --query`, and any other consumer that describes its own row type through the `Queryable` interface (DSL-02). Like the Rust `burpsy-query` crate it evaluates against a trait rather than a concrete `Exchange`, so it is testable with no store, no network and no dependency on `core`. The design rationale — a closed typed grammar rather than an embedded script, so `status > "abc"` is a *parse-time* error rather than a silent false — is in the `query.go` package doc.

## Key Files

| File | Description |
|------|-------------|
| `query.go` | The whole language in one file: `Queryable`, `Expr`, `Parse` (recursive-descent, reading characters directly with no token slice), `Match`, `QueryError`/`Render`. Rust splits this across lexer/parser/ast/eval/error |
| `fields.go` | `Expr.Fields()` — read-only introspection naming every field a query compares on, so the crawler frontier gate (DSL-03) can refuse queries it cannot honestly evaluate before a response exists |

## For AI Agents

- **Type-checking lives in `Parse`, so `Match` cannot fail.** `Match` returns a plain `bool`, not `(bool, error)`: every `*Expr` came from `Parse`, which already checked field/operator/value shape. `Expr`'s fields are unexported so `Parse` is the only constructor — "this Expr is type-checked" is an invariant of the type. A malformed query is an *error value*; a query that selects nothing is a valid `*Expr` whose `Match` returns false. Keep those two distinct.
- **Absent fields are absent, not zero.** `Queryable` models "no response yet" as `Status() == 0` and "no Content-Type" as `Mime() == ""`. Every comparison on an absent field is false — never true, never an error. Before this was explicit, `status < 400` matched every still-pending request because `0 < 400`.
- **Documented divergences from `crates/query` (verify against the doc block, do not assume Rust parity):**
  - Go adds a **`path`** field; Rust's field set is host/status/method/mime/body.
  - `=` is accepted as a synonym for `==` (Rust rejects a lone `=`).
  - An unquoted bare word is accepted as a string value (`host = example.com`); Rust requires quotes. A bare word that is *all digits* is still refused — quote it (`host = "8080"`) to mean the text.
  - One `QueryError` with offset + message, not Rust's ten-variant enum; `Render` still carries the caret.
- **Case folding is per-field and load-bearing:** `host` and `mime` compare case-insensitively; `method` and `path` do not (HTTP method is case-sensitive per RFC 7230, path per RFC 3986). `body` supports `~` only — there is no equality on a whole body.
- **An inverted range (`status in 299..200`) parses and matches nothing** — bounds are compared, not reordered, matching Rust.

## Testing Requirements

```bash
go test ./internal/query/...
```

Inline tests against bare `Queryable` fakes — no store, no network, no `core`. `fields_test.go` pins that `Fields()` names every compared field, since a missed field is a query silently evaluated against a value that does not exist.

## Dependencies

- Internal: none — a leaf. Consumers (`web`, CLI) turn it into and out of their own wire types.
- External: standard library only (`bytes`, `errors`, `fmt`, `strconv`, `strings`).
