//! Tokeniser for the query grammar. Every token carries the byte offset of its first character —
//! that offset is what lets a parse failure report *where*, which is the whole of DSL-04 (see
//! `error::QueryError`). Hand-rolled rather than pulled from a crate: the token set is nine
//! symbols, one string form and one number form, and a lexer generator would cost more in
//! dependency surface than it saves in code.

use crate::error::QueryError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Tok {
    Ident(String),
    Str(String),
    /// Kept as the literal digit text, not parsed here — parsing into `u16` happens in the
    /// parser, at the point the field is known, so an out-of-range literal can name the field it
    /// was rejected for.
    Num(String),
    Eq,
    Ne,
    Tilde,
    Lt,
    Le,
    Gt,
    Ge,
    DotDot,
    LParen,
    RParen,
    Eof,
}

#[derive(Debug, Clone)]
pub(crate) struct Token {
    pub tok: Tok,
    pub at: usize,
}

pub(crate) fn lex(src: &str) -> Result<Vec<Token>, QueryError> {
    let chars: Vec<(usize, char)> = src.char_indices().collect();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        let (at, c) = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                out.push(Token {
                    tok: Tok::LParen,
                    at,
                });
                i += 1;
            }
            ')' => {
                out.push(Token {
                    tok: Tok::RParen,
                    at,
                });
                i += 1;
            }
            '~' => {
                out.push(Token {
                    tok: Tok::Tilde,
                    at,
                });
                i += 1;
            }
            '=' if chars.get(i + 1).map(|&(_, c)| c) == Some('=') => {
                out.push(Token { tok: Tok::Eq, at });
                i += 2;
            }
            '!' if chars.get(i + 1).map(|&(_, c)| c) == Some('=') => {
                out.push(Token { tok: Tok::Ne, at });
                i += 2;
            }
            '<' if chars.get(i + 1).map(|&(_, c)| c) == Some('=') => {
                out.push(Token { tok: Tok::Le, at });
                i += 2;
            }
            '<' => {
                out.push(Token { tok: Tok::Lt, at });
                i += 1;
            }
            '>' if chars.get(i + 1).map(|&(_, c)| c) == Some('=') => {
                out.push(Token { tok: Tok::Ge, at });
                i += 2;
            }
            '>' => {
                out.push(Token { tok: Tok::Gt, at });
                i += 1;
            }
            '.' if chars.get(i + 1).map(|&(_, c)| c) == Some('.') => {
                out.push(Token {
                    tok: Tok::DotDot,
                    at,
                });
                i += 2;
            }
            '"' => {
                let (s, next_i) = lex_string(&chars, i)?;
                out.push(Token {
                    tok: Tok::Str(s),
                    at,
                });
                i = next_i;
            }
            c if c.is_ascii_digit() => {
                let start = i;
                while i < chars.len() && chars[i].1.is_ascii_digit() {
                    i += 1;
                }
                let text: String = chars[start..i].iter().map(|&(_, c)| c).collect();
                out.push(Token {
                    tok: Tok::Num(text),
                    at,
                });
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].1.is_alphanumeric() || chars[i].1 == '_') {
                    i += 1;
                }
                let text: String = chars[start..i].iter().map(|&(_, c)| c).collect();
                out.push(Token {
                    tok: Tok::Ident(text),
                    at,
                });
            }
            other => return Err(QueryError::UnexpectedCharacter { at, ch: other }),
        }
    }
    out.push(Token {
        tok: Tok::Eof,
        at: src.len(),
    });
    Ok(out)
}

/// Scans a quoted string starting at `chars[open]` (the opening `"`). Returns the unescaped text
/// and the index one past the closing `"`.
fn lex_string(chars: &[(usize, char)], open: usize) -> Result<(String, usize), QueryError> {
    let open_at = chars[open].0;
    let mut i = open + 1;
    let mut s = String::new();
    loop {
        match chars.get(i) {
            None => return Err(QueryError::UnterminatedString { at: open_at }),
            Some(&(_, '"')) => return Ok((s, i + 1)),
            Some(&(_, '\\')) => match chars.get(i + 1) {
                None => return Err(QueryError::UnterminatedString { at: open_at }),
                Some(&(esc_at, esc)) => {
                    let mapped = match esc {
                        '"' => '"',
                        '\\' => '\\',
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        other => {
                            return Err(QueryError::InvalidEscape {
                                at: esc_at,
                                ch: other,
                            });
                        }
                    };
                    s.push(mapped);
                    i += 2;
                }
            },
            Some(&(_, c)) => {
                s.push(c);
                i += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        lex(src).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn symbols_lex_to_their_operators() {
        assert_eq!(
            toks("== != ~ < <= > >= .. ( )"),
            vec![
                Tok::Eq,
                Tok::Ne,
                Tok::Tilde,
                Tok::Lt,
                Tok::Le,
                Tok::Gt,
                Tok::Ge,
                Tok::DotDot,
                Tok::LParen,
                Tok::RParen,
                Tok::Eof,
            ]
        );
    }

    #[test]
    fn a_quoted_string_with_every_escape_unescapes_correctly() {
        let t = toks(r#""a\"b\\c\nd\te\rf""#);
        assert_eq!(t[0], Tok::Str("a\"b\\c\nd\te\rf".to_string()));
    }

    #[test]
    fn an_unterminated_string_reports_the_opening_quote_offset() {
        let err = lex(r#"host == "abc"#).unwrap_err();
        assert_eq!(err, QueryError::UnterminatedString { at: 8 });
    }

    #[test]
    fn an_invalid_escape_reports_the_escaped_characters_offset() {
        let err = lex(r#""a\qb""#).unwrap_err();
        assert_eq!(err, QueryError::InvalidEscape { at: 3, ch: 'q' });
    }

    #[test]
    fn a_stray_character_is_reported_at_its_own_offset() {
        let err = lex("host == @").unwrap_err();
        assert_eq!(err, QueryError::UnexpectedCharacter { at: 8, ch: '@' });
    }

    #[test]
    fn a_lone_equals_sign_is_not_silently_read_as_double_equals() {
        // '=' alone begins no token; only '==' does.
        let err = lex("host = \"x\"").unwrap_err();
        assert_eq!(err, QueryError::UnexpectedCharacter { at: 5, ch: '=' });
    }
}
