//! A fault found while parsing a query string, always carrying the byte offset it was found at.
//!
//! Shaped the same way as `burpsy_core::segment::CorruptRecord`: a small local enum, every
//! variant carrying `at`, a hand-written [`Display`](fmt::Display) whose arms say what the
//! failure *means to the operator* rather than which token disagreed, an `impl Error`, and an
//! [`at`](QueryError::at) accessor so a caller can report position uniformly without matching on
//! the variant. This crate re-derives that shape instead of reusing `core`'s because this crate
//! must not depend on `core` — see the crate root doc comment for why.
//!
//! This type is the whole of DSL-04. [`crate::parse`] returns `Result<Query, QueryError>`, and
//! there is no function anywhere in this crate that turns a `QueryError` into a `Query` that
//! matches nothing — the two are different types, so silently downgrading a parse failure into
//! an empty match cannot happen by accident. A caller that wants to *show* the fault to an
//! operator, rather than just log it, calls [`QueryError::render`], which reproduces the
//! offending line with a caret under the byte the fault was found at.

use std::fmt;

/// A parse fault, with the byte offset it was found at and enough detail to say why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// The query string was empty, or entirely whitespace — there is nothing to filter on.
    EmptyQuery { at: usize },
    /// A character begins no token this grammar has.
    UnexpectedCharacter { at: usize, ch: char },
    /// A `"` was opened but the query ended before a matching `"` closed it.
    UnterminatedString { at: usize },
    /// A backslash inside a string escapes a character other than `" \\ n t r`.
    InvalidEscape { at: usize, ch: char },
    /// A bare word appeared where a field name was expected, and it is none of the five fields.
    UnknownField { at: usize, found: String },
    /// A specific token was required and a different one was found.
    UnexpectedToken {
        at: usize,
        expected: &'static str,
        found: String,
    },
    /// The query ended while a token was still required.
    UnexpectedEnd { at: usize, expected: &'static str },
    /// The operator does not apply to the field — e.g. ordering (`<`) on `host`, or equality
    /// (`==`) on `body`.
    UnsupportedOperator {
        at: usize,
        field: &'static str,
        op: &'static str,
    },
    /// The value's literal type does not fit what the field requires — `status > "abc"` is
    /// this, at parse time, rather than a comparison that is simply always false.
    TypeMismatch {
        at: usize,
        field: &'static str,
        expected: &'static str,
        found: String,
    },
    /// A numeric literal for `status` does not fit a `u16` (0-65535).
    NumberOutOfRange { at: usize, text: String },
}

impl QueryError {
    /// The byte offset the fault was found at, so callers can report position uniformly without
    /// matching on the variant.
    pub fn at(&self) -> usize {
        match self {
            QueryError::EmptyQuery { at }
            | QueryError::UnexpectedCharacter { at, .. }
            | QueryError::UnterminatedString { at }
            | QueryError::InvalidEscape { at, .. }
            | QueryError::UnknownField { at, .. }
            | QueryError::UnexpectedToken { at, .. }
            | QueryError::UnexpectedEnd { at, .. }
            | QueryError::UnsupportedOperator { at, .. }
            | QueryError::TypeMismatch { at, .. }
            | QueryError::NumberOutOfRange { at, .. } => *at,
        }
    }

    /// Render the message with the offending line reproduced underneath a caret pointing at
    /// [`at`](QueryError::at). A byte offset alone in a JSON field is not "where" for an operator
    /// typing a query into a UI — this is.
    pub fn render(&self, source: &str) -> String {
        let at = self.at().min(source.len());
        let line_start = source[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let line_end = source[at..]
            .find('\n')
            .map(|i| at + i)
            .unwrap_or(source.len());
        let line = &source[line_start..line_end];
        let col = source[line_start..at].chars().count();
        let caret = format!("{}^", " ".repeat(col));
        format!("{self}\n{line}\n{caret}")
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Each arm says what the failure means for an operator, not which field disagreed.
        match self {
            QueryError::EmptyQuery { at } => write!(
                f,
                "the query is empty at byte {at} — there is nothing to filter on; write at \
                 least one comparison, e.g. `status == 200`"
            ),
            QueryError::UnexpectedCharacter { at, ch } => write!(
                f,
                "byte {at} is '{ch}', which does not begin any token this grammar recognises — \
                 check for a stray character or a mistyped operator"
            ),
            QueryError::UnterminatedString { at } => write!(
                f,
                "the quoted string opened at byte {at} is never closed — add a closing '\"' \
                 before the end of the query"
            ),
            QueryError::InvalidEscape { at, ch } => write!(
                f,
                "byte {at} escapes '\\{ch}', which is not a recognised escape — use \\\", \\\\, \
                 \\n, \\t, or \\r"
            ),
            QueryError::UnknownField { at, found } => write!(
                f,
                "byte {at} names field '{found}', which this grammar does not have — the fields \
                 are host, status, method, mime, and body"
            ),
            QueryError::UnexpectedToken {
                at,
                expected,
                found,
            } => write!(f, "byte {at} expected {expected} but found {found}"),
            QueryError::UnexpectedEnd { at, expected } => write!(
                f,
                "the query ended at byte {at} while {expected} was still expected"
            ),
            QueryError::UnsupportedOperator { at, field, op } => write!(
                f,
                "byte {at}: '{op}' does not apply to {field} — {field} supports {}",
                allowed_ops(field)
            ),
            QueryError::TypeMismatch {
                at,
                field,
                expected,
                found,
            } => write!(
                f,
                "byte {at}: {field} expects {expected} but found {found} — a comparison whose \
                 types do not fit is rejected here rather than silently matching nothing"
            ),
            QueryError::NumberOutOfRange { at, text } => write!(
                f,
                "byte {at}: {text} is not a valid status code — status is a 16-bit value \
                 (0-65535)"
            ),
        }
    }
}

impl std::error::Error for QueryError {}

/// The operators a field accepts, for the `UnsupportedOperator` message. Spelled out per field
/// rather than left generic, so the error tells the operator what *would* have worked.
fn allowed_ops(field: &str) -> &'static str {
    match field {
        "status" => "==, !=, <, <=, >, >=, and 'in low..high'",
        "body" => {
            "~ (contains) only — matching a whole body exactly is rarely what 'filter on \
                   body content' means"
        }
        _ => "==, != (case-insensitive), and ~ (contains)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_reports_the_offset_it_carries() {
        let cases: Vec<(usize, QueryError)> = vec![
            (0, QueryError::EmptyQuery { at: 0 }),
            (3, QueryError::UnexpectedCharacter { at: 3, ch: '@' }),
            (5, QueryError::UnterminatedString { at: 5 }),
            (7, QueryError::InvalidEscape { at: 7, ch: 'q' }),
            (
                9,
                QueryError::UnknownField {
                    at: 9,
                    found: "foo".into(),
                },
            ),
            (
                11,
                QueryError::UnexpectedToken {
                    at: 11,
                    expected: "')'",
                    found: "'('".into(),
                },
            ),
            (
                13,
                QueryError::UnexpectedEnd {
                    at: 13,
                    expected: "a value",
                },
            ),
            (
                15,
                QueryError::UnsupportedOperator {
                    at: 15,
                    field: "host",
                    op: "<",
                },
            ),
            (
                17,
                QueryError::TypeMismatch {
                    at: 17,
                    field: "status",
                    expected: "a number",
                    found: "a string".into(),
                },
            ),
            (
                19,
                QueryError::NumberOutOfRange {
                    at: 19,
                    text: "99999".into(),
                },
            ),
        ];
        for (expected_at, err) in cases {
            assert_eq!(
                err.at(),
                expected_at,
                "at() must return the offset the variant was constructed with"
            );
            assert!(
                !err.to_string().is_empty(),
                "Display must produce a non-empty operator-facing message"
            );
        }
    }

    /// The caret rendering points at the right column: DSL-04 requires *where*, not just a
    /// number, and this is the property that makes the offset legible.
    #[test]
    fn the_caret_rendering_points_at_the_right_column() {
        let src = r#"status > "abc""#;
        let err = QueryError::TypeMismatch {
            at: 9,
            field: "status",
            expected: "a number",
            found: "a string".into(),
        };
        let rendered = err.render(src);
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 3, "message line, source line, caret line");
        assert_eq!(lines[1], src);
        assert_eq!(
            lines[2],
            format!("{}^", " ".repeat(9)),
            "caret must sit under byte 9, the '\"' that starts the offending value"
        );
    }
}
