//! Evaluating a parsed query against a [`Queryable`].
//!
//! Deliberately generic over a trait rather than any concrete type. `core`'s
//! `Exchange`/`StoredMessage` gets an `impl Queryable` in a later slice, once this crate is wired
//! in; every test in this crate runs against a bare fake, which is what keeping `query` free of
//! `burpsy-core` buys. DSL-02 — the same grammar selecting rows to display *and* rows a
//! match-and-replace rule applies to — falls out for free: both consumers just implement this
//! trait over whatever their own row type is, and the same parsed [`crate::Query`] drives both.

use crate::ast::{Comparison, Expr, StatusCmp, StrOp};

/// The five fields a query can filter on, read from whatever a consumer's history row actually
/// is.
///
/// `status` and `mime` are `Option` because a captured request with no matching response has
/// neither. A query naming either field must be able to say "this row has none" without the
/// evaluator inventing a value to compare against — see `eval_cmp`, where a `None` makes every
/// comparison on that field false rather than panicking or fabricating a sentinel.
pub trait Queryable {
    fn host(&self) -> &str;
    fn status(&self) -> Option<u16>;
    fn method(&self) -> &str;
    fn mime(&self) -> Option<&str>;
    fn body_contains(&self, needle: &[u8]) -> bool;
}

pub(crate) fn eval<Q: Queryable + ?Sized>(expr: &Expr, item: &Q) -> bool {
    match expr {
        Expr::And(a, b) => eval(a, item) && eval(b, item),
        Expr::Or(a, b) => eval(a, item) || eval(b, item),
        Expr::Not(a) => !eval(a, item),
        Expr::Cmp(c) => eval_cmp(c, item),
    }
}

fn eval_cmp<Q: Queryable + ?Sized>(c: &Comparison, item: &Q) -> bool {
    match c {
        // Hostnames compare case-insensitively: DNS names are, and an operator who typed
        // `Example.COM` means the same host as `example.com`. Burp's own history search treats
        // case-insensitive as the default and exposes a separate "Case sensitive" opt-in
        // (`RepeaterSearchCheckbox`), which is the same call made here.
        Comparison::Host(op, v) => str_op(*op, item.host(), v, true),
        // The method token is case-sensitive per RFC 7230 — a server that defines only `GET`
        // does not also recognise `get`. Folding case here would accept a query that describes a
        // different wire request than the one actually sent.
        Comparison::Method(op, v) => str_op(*op, item.method(), v, false),
        // Type and subtype are case-insensitive per RFC 2045; `Text/HTML` and `text/html` name
        // the same MIME type.
        Comparison::Mime(op, v) => match item.mime() {
            Some(m) => str_op(*op, m, v, true),
            None => false,
        },
        Comparison::Status(cmp) => match item.status() {
            Some(actual) => status_cmp(cmp, actual),
            None => false,
        },
        Comparison::Body(needle) => item.body_contains(needle),
    }
}

fn str_op(op: StrOp, actual: &str, expected: &str, case_insensitive: bool) -> bool {
    match (op, case_insensitive) {
        (StrOp::Eq, true) => actual.eq_ignore_ascii_case(expected),
        (StrOp::Eq, false) => actual == expected,
        (StrOp::Ne, true) => !actual.eq_ignore_ascii_case(expected),
        (StrOp::Ne, false) => actual != expected,
        (StrOp::Contains, true) => actual
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase()),
        (StrOp::Contains, false) => actual.contains(expected),
    }
}

fn status_cmp(cmp: &StatusCmp, actual: u16) -> bool {
    match *cmp {
        StatusCmp::Eq(v) => actual == v,
        StatusCmp::Ne(v) => actual != v,
        StatusCmp::Lt(v) => actual < v,
        StatusCmp::Le(v) => actual <= v,
        StatusCmp::Gt(v) => actual > v,
        StatusCmp::Ge(v) => actual >= v,
        StatusCmp::Range(lo, hi) => actual >= lo && actual <= hi,
    }
}
