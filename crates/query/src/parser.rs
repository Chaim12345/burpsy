//! Recursive-descent parser over `lexer`'s token stream.
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
//! `a or (b and c)`, and parentheses override both.
//!
//! Type checking is not a separate pass. It happens inline, at the single point a field, an
//! operator token and a value token come together in `str_comparison` / `status_comparison` /
//! `body_comparison` below — by the time an `ast::Comparison` exists, its operator and value have
//! already been checked against its field. There is no code path from a token stream to an
//! `Expr` that skips this.

use crate::ast::{Comparison, Expr, StatusCmp, StrOp};
use crate::error::QueryError;
use crate::lexer::{Tok, Token, lex};

const FIELD_EXPECTED: &str = "a field name (host, status, method, mime, body) or '('";

pub(crate) fn parse(input: &str) -> Result<Expr, QueryError> {
    if input.trim().is_empty() {
        return Err(QueryError::EmptyQuery { at: 0 });
    }
    let toks = lex(input)?;
    let mut p = Parser { toks, i: 0 };
    let expr = p.or_expr()?;
    p.expect_eof()?;
    Ok(expr)
}

struct Parser {
    toks: Vec<Token>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.i].tok
    }

    fn at(&self) -> usize {
        self.toks[self.i].at
    }

    fn bump(&mut self) -> Tok {
        let t = self.toks[self.i].tok.clone();
        if self.i + 1 < self.toks.len() {
            self.i += 1;
        }
        t
    }

    fn eat_keyword(&mut self, want: &str) -> bool {
        if matches!(self.peek(), Tok::Ident(w) if w.eq_ignore_ascii_case(want)) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect_eof(&mut self) -> Result<(), QueryError> {
        match self.peek() {
            Tok::Eof => Ok(()),
            other => Err(QueryError::UnexpectedToken {
                at: self.at(),
                expected: "end of query",
                found: describe(other),
            }),
        }
    }

    // ---- boolean composition ----------------------------------------------------------------

    fn or_expr(&mut self) -> Result<Expr, QueryError> {
        let mut lhs = self.and_expr()?;
        while self.eat_keyword("or") {
            let rhs = self.and_expr()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn and_expr(&mut self) -> Result<Expr, QueryError> {
        let mut lhs = self.unary_expr()?;
        while self.eat_keyword("and") {
            let rhs = self.unary_expr()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn unary_expr(&mut self) -> Result<Expr, QueryError> {
        if self.eat_keyword("not") {
            let inner = self.unary_expr()?;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<Expr, QueryError> {
        if matches!(self.peek(), Tok::LParen) {
            self.bump();
            let inner = self.or_expr()?;
            return match self.peek() {
                Tok::RParen => {
                    self.bump();
                    Ok(inner)
                }
                Tok::Eof => Err(QueryError::UnexpectedEnd {
                    at: self.at(),
                    expected: "')'",
                }),
                other => Err(QueryError::UnexpectedToken {
                    at: self.at(),
                    expected: "')'",
                    found: describe(other),
                }),
            };
        }
        self.comparison()
    }

    // ---- one `field op value` comparison -----------------------------------------------------

    fn comparison(&mut self) -> Result<Expr, QueryError> {
        let field_at = self.at();
        let name = match self.peek() {
            Tok::Ident(w) => w.clone(),
            Tok::Eof => {
                return Err(QueryError::UnexpectedEnd {
                    at: field_at,
                    expected: FIELD_EXPECTED,
                });
            }
            other => {
                return Err(QueryError::UnexpectedToken {
                    at: field_at,
                    expected: FIELD_EXPECTED,
                    found: describe(other),
                });
            }
        };
        self.bump();

        match name.to_ascii_lowercase().as_str() {
            "host" => self.str_comparison("host", Comparison::Host),
            "method" => self.str_comparison("method", Comparison::Method),
            "mime" => self.str_comparison("mime", Comparison::Mime),
            "status" => self.status_comparison(),
            "body" => self.body_comparison(),
            _ => Err(QueryError::UnknownField {
                at: field_at,
                found: name,
            }),
        }
    }

    /// Shared by `host`, `method` and `mime`: `==`, `!=` or `~`, followed by a quoted string.
    /// `make` builds the field-specific `Comparison` variant, so the operator/value parsing and
    /// error reporting is written once for all three string fields.
    fn str_comparison(
        &mut self,
        field: &'static str,
        make: impl Fn(StrOp, String) -> Comparison,
    ) -> Result<Expr, QueryError> {
        const STR_OPS: &str = "an operator (==, !=, ~)";
        let op_at = self.at();
        let op = match self.peek() {
            Tok::Eq => StrOp::Eq,
            Tok::Ne => StrOp::Ne,
            Tok::Tilde => StrOp::Contains,
            Tok::Lt | Tok::Le | Tok::Gt | Tok::Ge => {
                let op = op_symbol(self.peek());
                return Err(QueryError::UnsupportedOperator {
                    at: op_at,
                    field,
                    op,
                });
            }
            Tok::Ident(w) if w.eq_ignore_ascii_case("in") => {
                return Err(QueryError::UnsupportedOperator {
                    at: op_at,
                    field,
                    op: "in",
                });
            }
            Tok::Eof => {
                return Err(QueryError::UnexpectedEnd {
                    at: op_at,
                    expected: STR_OPS,
                });
            }
            other => {
                return Err(QueryError::UnexpectedToken {
                    at: op_at,
                    expected: STR_OPS,
                    found: describe(other),
                });
            }
        };
        self.bump();

        let value_at = self.at();
        let value = match self.peek().clone() {
            Tok::Str(s) => s,
            Tok::Eof => {
                return Err(QueryError::UnexpectedEnd {
                    at: value_at,
                    expected: "a quoted string",
                });
            }
            other => {
                return Err(QueryError::TypeMismatch {
                    at: value_at,
                    field,
                    expected: "a quoted string",
                    found: describe(&other),
                });
            }
        };
        self.bump();

        Ok(Expr::Cmp(make(op, value)))
    }

    fn status_comparison(&mut self) -> Result<Expr, QueryError> {
        const STATUS_OPS: &str = "an operator (==, !=, <, <=, >, >=, in)";
        enum Op {
            Eq,
            Ne,
            Lt,
            Le,
            Gt,
            Ge,
            In,
        }
        let op_at = self.at();
        let op = match self.peek() {
            Tok::Eq => Op::Eq,
            Tok::Ne => Op::Ne,
            Tok::Lt => Op::Lt,
            Tok::Le => Op::Le,
            Tok::Gt => Op::Gt,
            Tok::Ge => Op::Ge,
            Tok::Tilde => {
                return Err(QueryError::UnsupportedOperator {
                    at: op_at,
                    field: "status",
                    op: "~",
                });
            }
            Tok::Ident(w) if w.eq_ignore_ascii_case("in") => Op::In,
            Tok::Eof => {
                return Err(QueryError::UnexpectedEnd {
                    at: op_at,
                    expected: STATUS_OPS,
                });
            }
            other => {
                return Err(QueryError::UnexpectedToken {
                    at: op_at,
                    expected: STATUS_OPS,
                    found: describe(other),
                });
            }
        };
        self.bump();

        if matches!(op, Op::In) {
            let lo = self.status_number()?;
            let dotdot_at = self.at();
            match self.peek() {
                Tok::DotDot => {
                    self.bump();
                }
                Tok::Eof => {
                    return Err(QueryError::UnexpectedEnd {
                        at: dotdot_at,
                        expected: "'..'",
                    });
                }
                other => {
                    return Err(QueryError::UnexpectedToken {
                        at: dotdot_at,
                        expected: "'..'",
                        found: describe(other),
                    });
                }
            }
            let hi = self.status_number()?;
            return Ok(Expr::Cmp(Comparison::Status(StatusCmp::Range(lo, hi))));
        }

        let value = self.status_number()?;
        let cmp = match op {
            Op::Eq => StatusCmp::Eq(value),
            Op::Ne => StatusCmp::Ne(value),
            Op::Lt => StatusCmp::Lt(value),
            Op::Le => StatusCmp::Le(value),
            Op::Gt => StatusCmp::Gt(value),
            Op::Ge => StatusCmp::Ge(value),
            Op::In => unreachable!("Op::In returned above"),
        };
        Ok(Expr::Cmp(Comparison::Status(cmp)))
    }

    fn status_number(&mut self) -> Result<u16, QueryError> {
        let at = self.at();
        match self.peek().clone() {
            Tok::Num(text) => {
                self.bump();
                text.parse::<u16>()
                    .map_err(|_| QueryError::NumberOutOfRange { at, text })
            }
            Tok::Eof => Err(QueryError::UnexpectedEnd {
                at,
                expected: "a number",
            }),
            other => Err(QueryError::TypeMismatch {
                at,
                field: "status",
                expected: "a number",
                found: describe(&other),
            }),
        }
    }

    fn body_comparison(&mut self) -> Result<Expr, QueryError> {
        const BODY_OPS: &str = "'~'";
        let op_at = self.at();
        match self.peek() {
            Tok::Tilde => {
                self.bump();
            }
            Tok::Eq | Tok::Ne | Tok::Lt | Tok::Le | Tok::Gt | Tok::Ge => {
                let op = op_symbol(self.peek());
                return Err(QueryError::UnsupportedOperator {
                    at: op_at,
                    field: "body",
                    op,
                });
            }
            Tok::Ident(w) if w.eq_ignore_ascii_case("in") => {
                return Err(QueryError::UnsupportedOperator {
                    at: op_at,
                    field: "body",
                    op: "in",
                });
            }
            Tok::Eof => {
                return Err(QueryError::UnexpectedEnd {
                    at: op_at,
                    expected: BODY_OPS,
                });
            }
            other => {
                return Err(QueryError::UnexpectedToken {
                    at: op_at,
                    expected: BODY_OPS,
                    found: describe(other),
                });
            }
        }

        let value_at = self.at();
        let needle = match self.peek().clone() {
            Tok::Str(s) => s,
            Tok::Eof => {
                return Err(QueryError::UnexpectedEnd {
                    at: value_at,
                    expected: "a quoted string",
                });
            }
            other => {
                return Err(QueryError::TypeMismatch {
                    at: value_at,
                    field: "body",
                    expected: "a quoted string",
                    found: describe(&other),
                });
            }
        };
        self.bump();

        Ok(Expr::Cmp(Comparison::Body(needle.into_bytes())))
    }
}

/// The operator symbol for a token that is known to be one of the ordering operators, for
/// `UnsupportedOperator` messages.
fn op_symbol(t: &Tok) -> &'static str {
    match t {
        Tok::Eq => "==",
        Tok::Ne => "!=",
        Tok::Tilde => "~",
        Tok::Lt => "<",
        Tok::Le => "<=",
        Tok::Gt => ">",
        Tok::Ge => ">=",
        Tok::DotDot => "..",
        _ => "?",
    }
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Ident(w) => format!("the word '{w}'"),
        Tok::Str(s) => format!("the string {s:?}"),
        Tok::Num(n) => format!("the number {n}"),
        Tok::Eq => "'=='".to_string(),
        Tok::Ne => "'!='".to_string(),
        Tok::Tilde => "'~'".to_string(),
        Tok::Lt => "'<'".to_string(),
        Tok::Le => "'<='".to_string(),
        Tok::Gt => "'>'".to_string(),
        Tok::Ge => "'>='".to_string(),
        Tok::DotDot => "'..'".to_string(),
        Tok::LParen => "'('".to_string(),
        Tok::RParen => "')'".to_string(),
        Tok::Eof => "end of input".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(src: &str) -> Expr {
        parse(src).unwrap_or_else(|e| panic!("expected {src:?} to parse, got {e}"))
    }

    fn err(src: &str) -> QueryError {
        parse(src).expect_err("expected a parse error")
    }

    #[test]
    fn a_host_equality_comparison_parses() {
        assert_eq!(
            ok(r#"host == "example.com""#),
            Expr::Cmp(Comparison::Host(StrOp::Eq, "example.com".into()))
        );
    }

    #[test]
    fn precedence_is_not_then_and_then_or() {
        // `a or b and c` must be `Or(a, And(b, c))`, not `And(Or(a, b), c)`.
        let e = ok(r#"host == "a" or method == "GET" and status == 1"#);
        match e {
            Expr::Or(lhs, rhs) => {
                assert!(matches!(*lhs, Expr::Cmp(Comparison::Host(..))));
                assert!(matches!(*rhs, Expr::And(_, _)));
            }
            other => panic!("expected Or(host, And(method, status)), got {other:?}"),
        }
    }

    #[test]
    fn an_unbalanced_open_paren_reports_the_offset_where_input_ran_out() {
        let src = "(status == 200";
        let e = err(src);
        assert_eq!(e.at(), src.len(), "the ')' was expected once input ran out");
    }

    #[test]
    fn an_unmatched_close_paren_reports_its_own_offset() {
        let src = "status == 200)";
        let e = err(src);
        let paren_at = src.find(')').unwrap();
        assert_eq!(
            e.at(),
            paren_at,
            "the stray ')' is what end-of-query rejects"
        );
    }

    #[test]
    fn an_unknown_field_reports_the_words_offset() {
        let e = err(r#"foo == "x""#);
        assert_eq!(e.at(), 0);
        assert!(matches!(e, QueryError::UnknownField { found, .. } if found == "foo"));
    }

    #[test]
    fn a_trailing_operator_reports_the_offset_a_value_was_expected_at() {
        let src = "status ==";
        let e = err(src);
        assert_eq!(e.at(), src.len());
    }

    #[test]
    fn an_empty_query_reports_offset_zero() {
        assert_eq!(err("").at(), 0);
        assert_eq!(err("   ").at(), 0);
    }

    #[test]
    fn status_greater_than_a_quoted_string_is_a_type_error_not_a_false_match() {
        let e = err(r#"status > "abc""#);
        assert!(
            matches!(
                e,
                QueryError::TypeMismatch {
                    field: "status",
                    ..
                }
            ),
            "the wrong branch here would be a Query that always evaluates false; this must not \
             parse at all"
        );
    }

    #[test]
    fn ordering_on_a_string_field_is_rejected() {
        let e = err(r#"host < "example.com""#);
        assert!(matches!(
            e,
            QueryError::UnsupportedOperator {
                field: "host",
                op: "<",
                ..
            }
        ));
    }

    #[test]
    fn equality_on_body_is_rejected() {
        let e = err(r#"body == "x""#);
        assert!(matches!(
            e,
            QueryError::UnsupportedOperator {
                field: "body",
                op: "==",
                ..
            }
        ));
    }

    #[test]
    fn contains_on_status_is_rejected() {
        let e = err(r#"status ~ "200""#);
        assert!(matches!(
            e,
            QueryError::UnsupportedOperator {
                field: "status",
                op: "~",
                ..
            }
        ));
    }

    #[test]
    fn a_status_value_out_of_u16_range_is_rejected_at_the_numbers_offset() {
        let src = "status > 99999";
        let e = err(src);
        let num_at = src.find("99999").unwrap();
        assert_eq!(e.at(), num_at);
        assert!(matches!(e, QueryError::NumberOutOfRange { .. }));
    }

    #[test]
    fn a_status_range_is_inclusive_of_both_ends() {
        assert_eq!(
            ok("status in 200..299"),
            Expr::Cmp(Comparison::Status(StatusCmp::Range(200, 299)))
        );
    }
}
