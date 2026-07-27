//! BCheck lexer.
//!
//! # Two facts that shape this entirely
//!
//! **Whitespace and newlines are insignificant.** Verified against PortSwigger's own parser
//! (`BCheckChecker-1.9.jar`): an entire check body on one line parses, and arbitrary indentation
//! parses. `end if` is the only block terminator. So there is no offside rule and no INDENT/DEDENT
//! token — this is a flat token stream.
//!
//! **There are two string types with different lexical rules:**
//! * `"…"` — literal. **No interpolation.** Braces inside are ordinary characters.
//! * `` `…` `` — interpolatable. `{…}` expands; `\{` escapes a brace.
//!
//! That distinction is not cosmetic. The corpus contains `"oy2[a-z0-9]{43}"` — a regex in a literal
//! string. Treating `{43}` as an interpolation would corrupt 80+ secret-scanner checks, so the
//! lexer must decide interpolation by *quote type*, never by content.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Tok {
    /// Bare word: keyword or identifier. The parser decides which.
    Word(String),
    /// `"…"` — no interpolation.
    LitStr(String),
    /// `` `…` `` — interpolation permitted; raw inner text, expanded later.
    TemplateStr(String),
    /// `{…}` outside a string: a variable reference.
    VarRef(String),
    Colon,
    Comma,
    Equals,
    LParen,
    RParen,
    Eof,
}

impl fmt::Display for Tok {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tok::Word(w) => write!(f, "{w}"),
            Tok::LitStr(s) => write!(f, "\"{s}\""),
            Tok::TemplateStr(s) => write!(f, "`{s}`"),
            Tok::VarRef(v) => write!(f, "{{{v}}}"),
            Tok::Colon => f.write_str(":"),
            Tok::Comma => f.write_str(","),
            Tok::Equals => f.write_str("="),
            Tok::LParen => f.write_str("("),
            Tok::RParen => f.write_str(")"),
            Tok::Eof => f.write_str("<eof>"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub tok: Tok,
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LexError {
    pub msg: String,
    pub line: usize,
    pub col: usize,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at line {} col {}", self.msg, self.line, self.col)
    }
}

impl std::error::Error for LexError {}

pub fn lex(src: &str) -> Result<Vec<Token>, LexError> {
    let b: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut line = 1usize;
    let mut col = 1usize;

    macro_rules! push {
        ($t:expr, $l:expr, $c:expr) => {
            out.push(Token {
                tok: $t,
                line: $l,
                col: $c,
            })
        };
    }

    while i < b.len() {
        let c = b[i];
        // whitespace — insignificant, only tracked for diagnostics
        if c == '\n' {
            line += 1;
            col = 1;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            col += 1;
            continue;
        }
        // comment to end of line
        if c == '#' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
            continue;
        }

        let (sl, sc) = (line, col);
        match c {
            ':' => {
                push!(Tok::Colon, sl, sc);
                i += 1;
                col += 1;
            }
            ',' => {
                push!(Tok::Comma, sl, sc);
                i += 1;
                col += 1;
            }
            '=' => {
                push!(Tok::Equals, sl, sc);
                i += 1;
                col += 1;
            }
            '(' => {
                push!(Tok::LParen, sl, sc);
                i += 1;
                col += 1;
            }
            ')' => {
                push!(Tok::RParen, sl, sc);
                i += 1;
                col += 1;
            }
            '"' => {
                // Literal string: consume verbatim to the closing quote. Braces are NOT special.
                i += 1;
                col += 1;
                let mut s = String::new();
                loop {
                    if i >= b.len() {
                        return Err(LexError {
                            msg: "unterminated \" string".into(),
                            line: sl,
                            col: sc,
                        });
                    }
                    match b[i] {
                        '"' => {
                            i += 1;
                            col += 1;
                            break;
                        }
                        // ONLY \" is an escape. \\ is NOT — the corpus contains JSON-in-JSON
                        // payloads like \\"alert('x')\\" where treating \\ as an escape would end
                        // the string at the next quote and leave the rest to be lexed as code.
                        '\\' if i + 1 < b.len() && b[i + 1] == '"' => {
                            s.push('"');
                            i += 2;
                            col += 2;
                        }
                        ch => {
                            if ch == '\n' {
                                line += 1;
                                col = 1;
                            } else {
                                col += 1;
                            }
                            s.push(ch);
                            i += 1;
                        }
                    }
                }
                push!(Tok::LitStr(s), sl, sc);
            }
            '`' => {
                // Interpolatable string: keep raw inner text; expansion happens at eval time.
                i += 1;
                col += 1;
                let mut s = String::new();
                loop {
                    if i >= b.len() {
                        return Err(LexError {
                            msg: "unterminated ` string".into(),
                            line: sl,
                            col: sc,
                        });
                    }
                    match b[i] {
                        '`' => {
                            i += 1;
                            col += 1;
                            break;
                        }
                        '\\' if i + 1 < b.len() => {
                            // \{ escapes a brace; preserve the pair for the interpolator.
                            s.push('\\');
                            s.push(b[i + 1]);
                            i += 2;
                            col += 2;
                        }
                        ch => {
                            if ch == '\n' {
                                line += 1;
                                col = 1;
                            } else {
                                col += 1;
                            }
                            s.push(ch);
                            i += 1;
                        }
                    }
                }
                push!(Tok::TemplateStr(s), sl, sc);
            }
            '{' => {
                // Variable reference outside a string.
                i += 1;
                col += 1;
                let mut s = String::new();
                let mut depth = 1usize;
                while i < b.len() {
                    // Skip over quoted strings: a function argument may contain a brace, e.g.
                    // regex_replace({body}, "[}]$", {p}) — counting that '}' closes the ref early.
                    if b[i] == '"' || b[i] == '`' {
                        let q = b[i];
                        s.push(q);
                        i += 1;
                        col += 1;
                        while i < b.len() && b[i] != q {
                            if b[i] == '\\' && i + 1 < b.len() {
                                s.push(b[i]);
                                s.push(b[i + 1]);
                                i += 2;
                                col += 2;
                                continue;
                            }
                            if b[i] == '\n' {
                                line += 1;
                                col = 1;
                            } else {
                                col += 1;
                            }
                            s.push(b[i]);
                            i += 1;
                        }
                        if i < b.len() {
                            s.push(q);
                            i += 1;
                            col += 1;
                        }
                        continue;
                    }
                    match b[i] {
                        '{' => {
                            depth += 1;
                            s.push('{');
                            i += 1;
                            col += 1;
                        }
                        '}' => {
                            depth -= 1;
                            i += 1;
                            col += 1;
                            if depth == 0 {
                                break;
                            }
                            s.push('}');
                        }
                        ch => {
                            if ch == '\n' {
                                line += 1;
                                col = 1;
                            } else {
                                col += 1;
                            }
                            s.push(ch);
                            i += 1;
                        }
                    }
                }
                if depth != 0 {
                    return Err(LexError {
                        msg: "unterminated { reference".into(),
                        line: sl,
                        col: sc,
                    });
                }
                push!(Tok::VarRef(s.trim().to_string()), sl, sc);
            }
            _ => {
                // Bare word. Hyphens and dots are part of words (`v2-beta`, `latest.response`).
                let mut s = String::new();
                while i < b.len() {
                    let ch = b[i];
                    if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '.' || ch == '/' {
                        s.push(ch);
                        i += 1;
                        col += 1;
                    } else {
                        break;
                    }
                }
                if s.is_empty() {
                    return Err(LexError {
                        msg: format!("unexpected character {c:?}"),
                        line: sl,
                        col: sc,
                    });
                }
                push!(Tok::Word(s), sl, sc);
            }
        }
    }
    push!(Tok::Eof, line, col);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Tok> {
        lex(s).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn braces_in_a_literal_string_are_not_interpolation() {
        // The trap: 80+ corpus secret-scanners use regexes like this.
        let t = toks(r#""oy2[a-z0-9]{43}""#);
        assert_eq!(t[0], Tok::LitStr("oy2[a-z0-9]{43}".into()));
    }

    #[test]
    fn backtick_string_keeps_raw_interpolation_text() {
        let t = toks("`hello {latest.response} world`");
        assert_eq!(t[0], Tok::TemplateStr("hello {latest.response} world".into()));
    }

    #[test]
    fn varref_outside_string() {
        let t = toks("{latest.response} matches \"x\"");
        assert_eq!(t[0], Tok::VarRef("latest.response".into()));
        assert_eq!(t[1], Tok::Word("matches".into()));
        assert_eq!(t[2], Tok::LitStr("x".into()));
    }

    #[test]
    fn whitespace_and_newlines_are_insignificant() {
        // Verified against PortSwigger's own parser: the whole body on one line is valid.
        let a = toks("given response then\n  if x then\n  end if");
        let b = toks("given response then if x then end if");
        assert_eq!(a, b);
    }

    #[test]
    fn comments_are_stripped() {
        assert_eq!(
            toks("# leading comment\nname # trailing\n"),
            vec![Tok::Word("name".into()), Tok::Eof]
        );
    }

    #[test]
    fn regex_escapes_survive_literal_strings() {
        // \w must not be mangled — the DSL hands the pattern to Java's regex engine verbatim.
        let t = toks(r#""\w+\s\d{2}""#);
        assert_eq!(t[0], Tok::LitStr(r"\w+\s\d{2}".into()));
    }

    #[test]
    fn hyphens_and_dots_are_word_chars() {
        let t = toks("v2-beta latest.response");
        assert_eq!(t[0], Tok::Word("v2-beta".into()));
        assert_eq!(t[1], Tok::Word("latest.response".into()));
    }

    #[test]
    fn unterminated_strings_error_with_position() {
        let e = lex("\"oops").unwrap_err();
        assert!(e.msg.contains("unterminated"));
        assert_eq!(e.line, 1);
    }
}
