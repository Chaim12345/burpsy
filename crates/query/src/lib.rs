//! burpsy-query — a typed filter grammar over proxy history, evaluated against a trait rather
//! than a concrete type.
//!
//! # Why not `rhai`, or any embedded scripting language
//!
//! The project considered and rejected an embedded interpreter for this. A script buys
//! expressiveness an operator filtering history does not need, and gives up the property they do
//! need: `status > "abc"` must be rejected before a single row is compared, not evaluated to
//! `false` because comparing a number to a string happens to be falsy. A typed grammar makes that
//! a parse-time error; a general-purpose script only offers a runtime one, in the one place — a
//! history filter — where a runtime failure is easiest to mistake for "no matches". DSL-04 exists
//! to close exactly that gap, and it can only be a compile-time guarantee if the grammar is typed
//! and closed, not an interpreter over an open language.
//!
//! # Why this crate does not depend on `burpsy-core`
//!
//! The obvious model is a query over `Exchange`. That is also the wrong dependency: it would make
//! the grammar and evaluator untestable without a store, a message parser, and everything else
//! `core` pulls in along with it. Instead the grammar evaluates against [`Queryable`], a trait a
//! consumer implements over whatever its own row type is. `core`'s `Exchange`/`StoredMessage`
//! gets an impl in a later slice; every test here runs against a bare fake. DSL-02 — the same
//! query language selecting both the rows a filter shows *and* the rows a match-and-replace rule
//! applies to — is proved directly by running one parsed [`Query`] against two unrelated
//! `Queryable` fakes (see `tests::dsl_02_the_same_parsed_query_drives_two_unrelated_consumers`).
//!
//! # Grammar
//!
//! ```text
//! query      := or_expr
//! or_expr    := and_expr ( "or" and_expr )*
//! and_expr   := unary_expr ( "and" unary_expr )*
//! unary_expr := "not" unary_expr | primary
//! primary    := "(" or_expr ")" | comparison
//! comparison := field op value
//! field      := "host" | "status" | "method" | "mime" | "body"
//! ```
//!
//! `not` binds tighter than `and`, which binds tighter than `or` — `a or b and c` parses as
//! `a or (b and c)`. Parentheses override both, and `not` needs none of its own: `not host ==
//! "x"` is valid, since `not`'s operand is any `unary_expr`, and a bare comparison is one.
//!
//! Field-specific operators, all checked at parse time:
//!
//! - `host`, `method`, `mime`: `==`, `!=`, `~` (contains), each with a quoted string value.
//!   `host` and `mime` compare case-insensitively (DNS names and MIME type/subtype both are);
//!   `method` does not, because the HTTP method token is case-sensitive per RFC 7230.
//! - `status`: `==`, `!=`, `<`, `<=`, `>`, `>=` with an integer value, or `in low..high` for an
//!   inclusive range. A literal that doesn't fit `u16` (0-65535) is rejected at parse time.
//! - `body`: `~` only, with a quoted string value matched against the raw bytes. There is no
//!   equality on `body` — matching a whole message body byte-for-byte is never what an operator
//!   means by "filter on body content".
//!
//! Quoted strings support the escapes `\"`, `\\`, `\n`, `\t`, `\r`.
//!
//! `status` and `mime` read as absent (no response yet, or no `Content-Type`) make every
//! comparison on that field `false` rather than erroring — a query naming a field the row simply
//! doesn't have yet is not a fault in the query.
//!
//! # DSL-04: a parse failure is never a silent empty match
//!
//! [`parse`] returns `Result<Query, QueryError>`. There is no function anywhere in this crate that
//! turns a [`QueryError`] into a [`Query`] that matches nothing — the two are different types, so
//! that conflation cannot happen by accident, only by a caller deliberately discarding the `Err`.
//! [`QueryError::render`] reproduces the offending line with a caret under the byte that failed,
//! for callers presenting the fault in a UI rather than a log line.

mod ast;
mod error;
mod eval;
mod lexer;
mod parser;

pub use error::QueryError;
pub use eval::Queryable;

use ast::Expr;

/// A parsed, type-checked query. The only way to obtain one is [`parse`] — every `Query` that
/// exists has already passed the grammar's type rules, so [`Query::matches`] is infallible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query(Expr);

/// Parse a query string.
///
/// Errors carry a byte offset into `input` — see [`QueryError::at`] and [`QueryError::render`].
/// This is DSL-04: a malformed query says where and why, rather than being treated as a query
/// that simply matches nothing.
pub fn parse(input: &str) -> Result<Query, QueryError> {
    parser::parse(input).map(Query)
}

impl Query {
    /// Whether `item` matches this query.
    ///
    /// Returns a plain `bool`, not a `Result` — every `Query` was already type-checked when it
    /// was parsed, so evaluating it cannot fail. A query that legitimately matches nothing looks
    /// exactly like this: `Ok(query)` followed by `query.matches(_) == false`. That is
    /// distinguishable, at the type level, from `parse` returning `Err` — the two are never the
    /// same value.
    pub fn matches<Q: Queryable + ?Sized>(&self, item: &Q) -> bool {
        eval::eval(&self.0, item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, directly-constructed `Queryable` — the "first consumer" fake most field/op
    /// tests use.
    struct Fake {
        host: &'static str,
        status: Option<u16>,
        method: &'static str,
        mime: Option<&'static str>,
        body: &'static [u8],
    }

    impl Queryable for Fake {
        fn host(&self) -> &str {
            self.host
        }
        fn status(&self) -> Option<u16> {
            self.status
        }
        fn method(&self) -> &str {
            self.method
        }
        fn mime(&self) -> Option<&str> {
            self.mime
        }
        fn body_contains(&self, needle: &[u8]) -> bool {
            self.body.windows(needle.len().max(1)).any(|w| w == needle) || needle.is_empty()
        }
    }

    const ROW: Fake = Fake {
        host: "Example.com",
        status: Some(200),
        method: "GET",
        mime: Some("text/html"),
        body: b"<html>hello world</html>",
    };

    const NO_RESPONSE: Fake = Fake {
        host: "example.com",
        status: None,
        method: "GET",
        mime: None,
        body: b"",
    };

    fn matches(src: &str, item: &Fake) -> bool {
        parse(src)
            .unwrap_or_else(|e| panic!("{src:?} should parse: {e}"))
            .matches(item)
    }

    // ---- host --------------------------------------------------------------------------------

    #[test]
    fn host_equality_is_case_insensitive() {
        assert!(matches(r#"host == "example.com""#, &ROW));
        assert!(matches(r#"host == "EXAMPLE.COM""#, &ROW));
    }

    #[test]
    fn host_inequality_is_the_negation_of_equality() {
        assert!(!matches(r#"host != "example.com""#, &ROW));
        assert!(matches(r#"host != "other.com""#, &ROW));
    }

    #[test]
    fn host_contains_matches_a_substring() {
        assert!(matches(r#"host ~ "ample""#, &ROW));
        assert!(!matches(r#"host ~ "xyz""#, &ROW));
    }

    // ---- status --------------------------------------------------------------------------------

    #[test]
    fn status_equality_and_inequality() {
        assert!(matches("status == 200", &ROW));
        assert!(!matches("status == 404", &ROW));
        assert!(matches("status != 404", &ROW));
        assert!(!matches("status != 200", &ROW));
    }

    #[test]
    fn status_ordering_operators() {
        assert!(matches("status > 199", &ROW));
        assert!(!matches("status > 200", &ROW));
        assert!(matches("status >= 200", &ROW));
        assert!(matches("status < 201", &ROW));
        assert!(!matches("status < 200", &ROW));
        assert!(matches("status <= 200", &ROW));
    }

    #[test]
    fn status_range_matches_inclusive_of_both_ends() {
        assert!(matches("status in 200..299", &ROW));
        assert!(matches("status in 200..200", &ROW));
        assert!(!matches("status in 201..299", &ROW));
        assert!(!matches("status in 100..199", &ROW));
    }

    #[test]
    fn a_missing_status_never_matches_any_status_comparison() {
        assert!(!matches("status == 200", &NO_RESPONSE));
        assert!(!matches("status != 200", &NO_RESPONSE));
        assert!(!matches("status in 0..999", &NO_RESPONSE));
    }

    // ---- method --------------------------------------------------------------------------------

    #[test]
    fn method_equality_is_case_sensitive() {
        assert!(matches(r#"method == "GET""#, &ROW));
        assert!(
            !matches(r#"method == "get""#, &ROW),
            "the HTTP method token is case-sensitive per RFC 7230"
        );
    }

    #[test]
    fn method_contains_matches_a_substring() {
        assert!(matches(r#"method ~ "E""#, &ROW));
        assert!(!matches(r#"method ~ "POST""#, &ROW));
    }

    // ---- mime --------------------------------------------------------------------------------

    #[test]
    fn mime_equality_is_case_insensitive() {
        assert!(matches(r#"mime == "text/html""#, &ROW));
        assert!(matches(r#"mime == "TEXT/HTML""#, &ROW));
    }

    #[test]
    fn mime_contains_matches_a_substring() {
        assert!(matches(r#"mime ~ "html""#, &ROW));
        assert!(!matches(r#"mime ~ "json""#, &ROW));
    }

    #[test]
    fn a_missing_mime_never_matches_any_mime_comparison() {
        assert!(!matches(r#"mime == "text/html""#, &NO_RESPONSE));
        assert!(!matches(r#"mime ~ "html""#, &NO_RESPONSE));
    }

    // ---- body --------------------------------------------------------------------------------

    #[test]
    fn body_contains_matches_a_substring_of_the_bytes() {
        assert!(matches(r#"body ~ "hello world""#, &ROW));
        assert!(!matches(r#"body ~ "goodbye""#, &ROW));
    }

    // ---- boolean composition -------------------------------------------------------------------

    #[test]
    fn and_requires_both_sides() {
        assert!(matches(r#"host == "example.com" and status == 200"#, &ROW));
        assert!(!matches(r#"host == "example.com" and status == 404"#, &ROW));
    }

    #[test]
    fn or_requires_either_side() {
        assert!(matches(r#"status == 404 or status == 200"#, &ROW));
        assert!(!matches(r#"status == 404 or status == 500"#, &ROW));
    }

    #[test]
    fn not_negates_its_operand() {
        assert!(matches(r#"not status == 404"#, &ROW));
        assert!(!matches(r#"not status == 200"#, &ROW));
    }

    #[test]
    fn parentheses_override_the_default_precedence() {
        // Without parens `host == "x" or status == 200 and status == 404` is
        // `host=="x" or (200==200 and 200==404)` = `false or false` = false. Grouping the left
        // side instead flips it.
        assert!(matches(
            r#"(host == "example.com" or status == 200) and status == 404"#,
            &Fake {
                status: Some(404),
                ..ROW
            }
        ));
    }

    /// The precedence claim from the grammar doc, made operational: `a or b and c` must parse as
    /// `a or (b and c)`. Constructed so the two readings disagree — under `(a or b) and c` this
    /// row would NOT match, because the row's status is not 404.
    #[test]
    fn or_binds_looser_than_and_a_test_that_would_fail_under_the_other_reading() {
        let row = Fake {
            host: "example.com", // a: true
            status: Some(200),   // c: false (query checks status == 404)
            method: "GET",       // b: true
            mime: None,
            body: b"",
        };
        // a=true, b=true, c=false.
        // Documented precedence: a or (b and c) = true or (true and false) = true.
        // The other reading:    (a or b) and c  = (true or true) and false = false.
        assert!(
            matches(
                r#"host == "example.com" or method == "GET" and status == 404"#,
                &row
            ),
            "must be true under 'and' binding tighter than 'or'"
        );
    }

    // ---- DSL-04: type errors are parse-time, and are distinguishable from a real non-match ------

    #[test]
    fn status_greater_than_a_quoted_string_is_a_parse_error_not_a_false_match() {
        let result = parse(r#"status > "abc""#);
        assert!(
            result.is_err(),
            "this must fail to parse; it must never silently become a Query that matches false"
        );
    }

    #[test]
    fn a_query_that_parses_but_matches_nothing_is_distinguishable_from_a_parse_failure() {
        // Parses fine — the row just doesn't have status 999.
        let parsed = parse("status == 999");
        assert!(parsed.is_ok(), "a query with no matching rows still parses");
        assert!(
            !parsed.unwrap().matches(&ROW),
            "and then legitimately matches nothing"
        );

        // A malformed query never reaches this state at all — it is an `Err`, a different type,
        // never a `Query` a caller could call `.matches()` on.
        let malformed = parse(r#"status > "abc""#);
        assert!(
            malformed.is_err(),
            "a malformed query is an Err, not an always-false Query"
        );
    }

    // ---- DSL-02: one grammar, two unrelated consumers -------------------------------------------

    /// A second, differently-shaped `Queryable` — not just a copy of `Fake` with renamed fields,
    /// but a type that computes its answers from an entirely different internal representation
    /// (a raw pseudo-request line plus a header list), the way a match-and-replace rule candidate
    /// might. Proves the grammar doesn't secretly assume `Fake`'s shape.
    struct RuleCandidate {
        request_line: &'static str, // "METHOD host"
        response_status: u16,
        content_type_header: Option<&'static str>,
        raw_body: &'static str,
    }

    impl Queryable for RuleCandidate {
        fn host(&self) -> &str {
            self.request_line.split(' ').nth(1).unwrap_or("")
        }
        fn status(&self) -> Option<u16> {
            Some(self.response_status)
        }
        fn method(&self) -> &str {
            self.request_line.split(' ').next().unwrap_or("")
        }
        fn mime(&self) -> Option<&str> {
            self.content_type_header
        }
        fn body_contains(&self, needle: &[u8]) -> bool {
            let Ok(needle) = std::str::from_utf8(needle) else {
                return false;
            };
            self.raw_body.contains(needle)
        }
    }

    #[test]
    fn dsl_02_the_same_parsed_query_drives_two_unrelated_queryable_consumers() {
        let query = parse(r#"status == 200 and host == "example.com" and body ~ "hi""#).unwrap();

        let history_row = Fake {
            host: "Example.com",
            status: Some(200),
            method: "POST",
            mime: None,
            body: b"say hi to the world",
        };
        let rule_candidate = RuleCandidate {
            request_line: "GET EXAMPLE.COM",
            response_status: 200,
            content_type_header: Some("application/json"),
            raw_body: "hi there",
        };

        assert!(
            query.matches(&history_row),
            "must match the history-filter-shaped consumer"
        );
        assert!(
            query.matches(&rule_candidate),
            "the same parsed Query, unmodified, must also match a structurally unrelated \
             match-and-replace-shaped consumer — that consumer-agnosticism is DSL-02"
        );
    }
}
