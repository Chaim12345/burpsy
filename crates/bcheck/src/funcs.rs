//! Expressions inside `{…}`.
//!
//! A brace reference is not just a variable name. The corpus nests function calls inside it:
//!
//! ```text
//! replacing path: `{regex_replace({regex_replace({base.request.url},"^.*?/.*?/.*?/","/")},"([^/]+)$","")}{potential_path}`
//! ```
//!
//! So the inner text of every `{…}` is parsed as a small expression: a path, a string, or a call
//! whose arguments are themselves expressions. Arguments may be brace-wrapped (`{base.request.url}`)
//! or bare (`to_lower(check1.response.body)`) — the corpus does both.
//!
//! The four non-Collaborator builtins, with corpus counts: `regex_replace` 38, `random_str` 30,
//! `to_lower` 16, `base64_decode` 5. `generate_collaborator_address` (54) is deliberately absent —
//! checks that need it are gated out before evaluation, because inventing an address that nothing
//! polls would turn every OOB check into a silent false negative.

/// A parsed brace-reference expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// An object path or a `define:`d variable.
    Path(String),
    /// `"…"` — used verbatim.
    Str(String),
    /// `` `…` `` — interpolated by the evaluator.
    Template(String),
    Call(String, Vec<Expr>),
}

/// Parse the text between braces. Never fails: anything unrecognised becomes a `Path`, which then
/// resolves to absent and is handled as such.
pub fn parse_expr(src: &str) -> Expr {
    let s = src.trim();
    // A call is `name(args)` where the parens wrap the whole remainder.
    if let Some(open) = s.find('(')
        && s.ends_with(')')
        && s[..open].chars().all(|c| c.is_alphanumeric() || c == '_')
        && !s[..open].is_empty()
        && balanced_to_end(&s[open..])
    {
        let name = s[..open].to_string();
        let inner = &s[open + 1..s.len() - 1];
        return Expr::Call(name, split_args(inner).iter().map(|a| parse_expr(a)).collect());
    }
    atom(s)
}

/// Classify a non-call atom.
///
/// Recursion here is only ever on a *strictly shorter* slice (brace stripping), which is what makes
/// the mutual recursion with [`parse_expr`] terminate. An earlier version fell back to `parse_expr`
/// for anything containing `(`, so text like `foo(a) bar` — a `(` that is not a call — recursed on
/// its own full input and overflowed the stack.
fn atom(s: &str) -> Expr {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        return Expr::Str(s[1..s.len() - 1].to_string());
    }
    if s.len() >= 2 && s.starts_with('`') && s.ends_with('`') {
        return Expr::Template(s[1..s.len() - 1].to_string());
    }
    // A brace-wrapped argument is just a nested expression.
    if s.len() >= 2 && s.starts_with('{') && s.ends_with('}') {
        return parse_expr(&s[1..s.len() - 1]);
    }
    Expr::Path(s.to_string())
}

/// True when the parens starting at index 0 close exactly at the end of the slice.
fn balanced_to_end(s: &str) -> bool {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (Some(q), _) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"') | (None, '`') => quote = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => {
                depth -= 1;
                if depth == 0 {
                    return i + 1 == s.len();
                }
            }
            _ => {}
        }
    }
    false
}

/// Split on commas at depth zero, ignoring commas inside quotes, braces or nested calls.
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), '\\') => {
                // Keep escapes intact so a regex argument survives.
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                let _ = q;
            }
            (Some(q), _) if c == q => {
                quote = None;
                cur.push(c);
            }
            (Some(_), _) => cur.push(c),
            (None, '"') | (None, '`') => {
                quote = Some(c);
                cur.push(c);
            }
            (None, '(') | (None, '{') => {
                depth += 1;
                cur.push(c);
            }
            (None, ')') | (None, '}') => {
                depth -= 1;
                cur.push(c);
            }
            (None, ',') if depth == 0 => {
                out.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Standard-alphabet base64 decode, tolerant of missing padding and embedded whitespace.
/// Returns lossy UTF-8, because callers compare it as text.
pub fn base64_decode(s: &str) -> String {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Characters `random_str` draws from. Alphanumeric only, so a value is safe in a path or a query
/// without escaping.
const RAND_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Deterministic-per-seed random string.
///
/// Seeded rather than drawn from the OS so a scan is reproducible: re-running a check against the
/// same response yields the same probe value, which makes a finding re-checkable. Different targets
/// get different values because the seed is derived from the message being scanned, which is what
/// cache-busting actually needs.
pub fn random_str(state: &mut u64, len: usize) -> String {
    let mut s = String::with_capacity(len);
    for _ in 0..len.min(4096) {
        // xorshift64* — small, no dependency, good enough to avoid collisions between probes.
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        let r = state.wrapping_mul(0x2545F4914F6CDD1D);
        s.push(RAND_ALPHABET[(r >> 33) as usize % RAND_ALPHABET.len()] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_path_parses_as_a_path() {
        assert_eq!(parse_expr("latest.response.body"), Expr::Path("latest.response.body".into()));
    }

    #[test]
    fn a_nested_regex_replace_parses_to_the_right_shape() {
        // The hardest real corpus reference: a call whose first argument is another call.
        let e = parse_expr(r#"regex_replace({regex_replace({base.request.url},"^.*?/","/")},"([^/]+)$","")"#);
        let Expr::Call(name, args) = &e else { panic!("expected a call, got {e:?}") };
        assert_eq!(name, "regex_replace");
        assert_eq!(args.len(), 3, "subject, pattern, replacement");
        assert!(matches!(&args[0], Expr::Call(n, _) if n == "regex_replace"));
        assert_eq!(args[1], Expr::Str("([^/]+)$".into()));
        assert_eq!(args[2], Expr::Str(String::new()));
    }

    #[test]
    fn a_bare_path_argument_parses() {
        // `to_lower(check1.response.body)` — no braces around the argument.
        let e = parse_expr("to_lower(check1.response.body)");
        let Expr::Call(name, args) = &e else { panic!("expected a call") };
        assert_eq!(name, "to_lower");
        assert_eq!(args[0], Expr::Path("check1.response.body".into()));
    }

    #[test]
    fn a_comma_inside_a_regex_argument_does_not_split_it() {
        // `{2,3}` in a pattern must stay in one argument.
        let e = parse_expr(r#"regex_replace({x},"a{2,3}","z")"#);
        let Expr::Call(_, args) = &e else { panic!("expected a call") };
        assert_eq!(args.len(), 3, "the brace quantifier must not become an argument break");
        assert_eq!(args[1], Expr::Str("a{2,3}".into()));
    }

    #[test]
    fn a_backtick_argument_is_a_template() {
        let e = parse_expr("regex_replace({p},\"(.)/?$\",`$1{extension}`)");
        let Expr::Call(_, args) = &e else { panic!("expected a call") };
        assert_eq!(args[2], Expr::Template("$1{extension}".into()));
    }

    #[test]
    fn a_path_containing_parens_is_not_mistaken_for_a_call() {
        // Not a call: the parens do not wrap the whole remainder.
        assert!(matches!(parse_expr("foo(a) bar"), Expr::Path(_)));
    }

    #[test]
    fn base64_decodes_with_and_without_padding() {
        assert_eq!(base64_decode("SGVsbG8="), "Hello");
        assert_eq!(base64_decode("SGVsbG8"), "Hello");
        assert_eq!(base64_decode("SGVs bG8="), "Hello", "whitespace is ignored");
    }

    #[test]
    fn random_str_has_the_requested_length_and_a_safe_alphabet() {
        let mut st = 12345u64;
        let a = random_str(&mut st, 10);
        assert_eq!(a.len(), 10);
        assert!(a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        let b = random_str(&mut st, 10);
        assert_ne!(a, b, "successive draws must differ or probes collide");
    }

    #[test]
    fn random_str_is_reproducible_for_a_given_seed() {
        // Reproducibility is what makes a reported finding re-checkable.
        let (mut a, mut b) = (99u64, 99u64);
        assert_eq!(random_str(&mut a, 12), random_str(&mut b, 12));
    }
}
