//! The parsed query tree. Built only by `parser::parse`, so every `Comparison` in existence has
//! already been checked against its field's operators and value type — there is no
//! `Comparison::Host` variant that could carry a `StatusCmp`, because `StrOp` and `StatusCmp` are
//! different types. A malformed comparison is a `QueryError`, never an `Expr`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp(Comparison),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Comparison {
    Host(StrOp, String),
    Method(StrOp, String),
    Mime(StrOp, String),
    Status(StatusCmp),
    /// `body ~ "needle"` — the only comparison `body` supports. Stored as bytes because
    /// `Queryable::body_contains` takes `&[u8]`; the grammar's needle is still written as a
    /// quoted (UTF-8) string, so this is always valid UTF-8 in practice.
    Body(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrOp {
    Eq,
    Ne,
    Contains,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusCmp {
    Eq(u16),
    Ne(u16),
    Lt(u16),
    Le(u16),
    Gt(u16),
    Ge(u16),
    /// Inclusive both ends: `status in 200..299` matches 200 and 299.
    Range(u16, u16),
}
