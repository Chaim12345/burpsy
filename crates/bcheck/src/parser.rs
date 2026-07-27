//! Recursive-descent BCheck parser.
//!
//! Flat descent with no indentation handling, because PortSwigger's own parser treats whitespace and
//! newlines as insignificant — `end if` is the only block terminator. Multi-word keywords
//! (`run for each`, `differs from`, `end if`, `and continue`, `insertion point`) are matched by
//! peeking a short window rather than lexed as single tokens.
//!
//! Parses the whole v2-beta grammar so no corpus file is rejected; statements outside M1 are
//! represented in the AST and skipped by the evaluator rather than causing a parse failure.

use crate::ast::*;
use crate::lexer::{LexError, Tok, Token, lex};
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    pub msg: String,
    pub line: usize,
    pub col: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at line {} col {}", self.msg, self.line, self.col)
    }
}

impl std::error::Error for ParseError {}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError { msg: e.msg, line: e.line, col: e.col }
    }
}

pub fn parse(src: &str) -> Result<Check, ParseError> {
    let toks = lex(src)?;
    Parser { t: toks, i: 0 }.check()
}

struct Parser {
    t: Vec<Token>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.t[self.i.min(self.t.len() - 1)].tok
    }

    fn at(&self, off: usize) -> &Tok {
        &self.t[(self.i + off).min(self.t.len() - 1)].tok
    }

    fn pos(&self) -> (usize, usize) {
        let t = &self.t[self.i.min(self.t.len() - 1)];
        (t.line, t.col)
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ParseError> {
        let (line, col) = self.pos();
        Err(ParseError { msg: msg.into(), line, col })
    }

    fn bump(&mut self) -> Tok {
        let t = self.peek().clone();
        if self.i < self.t.len() - 1 {
            self.i += 1;
        }
        t
    }

    /// Case-insensitive bare-word check.
    fn is_word(&self, off: usize, w: &str) -> bool {
        matches!(self.at(off), Tok::Word(x) if x.eq_ignore_ascii_case(w))
    }

    fn eat_word(&mut self, w: &str) -> bool {
        if self.is_word(0, w) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect_word(&mut self, w: &str) -> Result<(), ParseError> {
        if self.eat_word(w) {
            Ok(())
        } else {
            self.err(format!("expected {w:?}, found {}", self.peek()))
        }
    }

    fn expect_colon(&mut self) -> Result<(), ParseError> {
        if matches!(self.peek(), Tok::Colon) {
            self.bump();
            Ok(())
        } else {
            self.err(format!("expected ':', found {}", self.peek()))
        }
    }

    /// Multi-word keyword: all words present in sequence.
    fn is_phrase(&self, words: &[&str]) -> bool {
        words.iter().enumerate().all(|(k, w)| self.is_word(k, w))
    }

    fn eat_phrase(&mut self, words: &[&str]) -> bool {
        if self.is_phrase(words) {
            for _ in words {
                self.bump();
            }
            true
        } else {
            false
        }
    }

    // ---- top level ------------------------------------------------------------------------

    fn check(&mut self) -> Result<Check, ParseError> {
        let metadata = self.metadata()?;
        let mut defines = Vec::new();
        let mut for_each = Vec::new();

        // `define:` and `run for each:` may appear in either order, and the corpus does both.
        for _ in 0..2 {
            self.define_block(&mut defines)?;
            self.for_each_block(&mut for_each)?;
        }

        self.expect_word("given")?;
        let frequency = self.frequency()?;
        self.expect_word("then")?;
        let body = self.statements()?;

        Ok(Check { metadata, defines, for_each, frequency, body })
    }

    /// True when the current token begins a new top-level section.
    fn at_section(&self) -> bool {
        self.is_word(0, "given")
            || self.is_word(0, "define")
            || self.is_phrase(&["run", "for", "each"])
            || matches!(self.peek(), Tok::Eof)
    }

    fn define_block(&mut self, defines: &mut Vec<(String, Value)>) -> Result<(), ParseError> {
        if !(self.is_word(0, "define") && matches!(self.at(1), Tok::Colon)) {
            return Ok(());
        }
        self.bump();
        self.bump();
        while let Tok::Word(_) = self.peek() {
            if self.at_section() {
                break;
            }
            let name = match self.bump() {
                Tok::Word(w) => w,
                other => return self.err(format!("expected variable name, found {other}")),
            };
            if !matches!(self.peek(), Tok::Equals) {
                return self.err("expected '=' in define");
            }
            self.bump();
            defines.push((name, self.value()?));
        }
        Ok(())
    }

    fn for_each_block(&mut self, for_each: &mut Vec<(String, Vec<Value>)>) -> Result<(), ParseError> {
        if !self.is_phrase(&["run", "for", "each"]) {
            return Ok(());
        }
        self.bump();
        self.bump();
        self.bump();
        self.expect_colon()?;
        while let Tok::Word(_) = self.peek() {
            if self.at_section() {
                break;
            }
            let name = match self.bump() {
                Tok::Word(w) => w,
                other => return self.err(format!("expected variable name, found {other}")),
            };
            if !matches!(self.peek(), Tok::Equals) {
                return self.err("expected '=' in run for each");
            }
            self.bump();
            let mut vals = vec![self.value()?];
            while matches!(self.peek(), Tok::Comma) {
                self.bump();
                vals.push(self.value()?);
            }
            for_each.push((name, vals));
        }
        Ok(())
    }

    fn metadata(&mut self) -> Result<Metadata, ParseError> {
        self.expect_word("metadata")?;
        self.expect_colon()?;
        let mut m = Metadata::default();
        loop {
            if self.is_word(0, "given")
                || self.is_word(0, "define")
                || self.is_phrase(&["run", "for", "each"])
                || matches!(self.peek(), Tok::Eof)
            {
                break;
            }
            let key = match self.peek().clone() {
                Tok::Word(w) => w.to_ascii_lowercase(),
                other => return self.err(format!("expected metadata field, found {other}")),
            };
            self.bump();
            self.expect_colon()?;
            match key.as_str() {
                "language" => {
                    let v = match self.bump() {
                        Tok::Word(w) => w,
                        Tok::LitStr(s) | Tok::TemplateStr(s) => s,
                        other => return self.err(format!("bad language value {other}")),
                    };
                    m.language = match v.to_ascii_lowercase().as_str() {
                        "v1-beta" => Some(Language::V1Beta),
                        "v2-beta" => Some(Language::V2Beta),
                        _ => return self.err(format!("unknown language {v:?}")),
                    };
                }
                "name" => m.name = self.value()?.raw().to_string(),
                "description" => m.description = Some(self.value()?.raw().to_string()),
                "author" => m.author = Some(self.value()?.raw().to_string()),
                "tags" => {
                    m.tags.push(self.value()?.raw().to_string());
                    while matches!(self.peek(), Tok::Comma) {
                        self.bump();
                        m.tags.push(self.value()?.raw().to_string());
                    }
                }
                other => return self.err(format!("unknown metadata field {other:?}")),
            }
        }
        Ok(m)
    }

    fn frequency(&mut self) -> Result<Frequency, ParseError> {
        // Insertion-point form, optionally qualified: `any|query|header|body|cookie [or …]`.
        let mut ips = Vec::new();
        loop {
            let t = match self.peek() {
                Tok::Word(w) => w.to_ascii_lowercase(),
                _ => break,
            };
            let ip = match t.as_str() {
                "any" => IpType::Any,
                "query" => IpType::Query,
                "header" => IpType::Header,
                "body" => IpType::Body,
                "cookie" => IpType::Cookie,
                _ => break,
            };
            ips.push(ip);
            self.bump();
            if !self.eat_word("or") {
                break;
            }
        }
        if !ips.is_empty() {
            if self.eat_phrase(&["insertion", "point"]) {
                return Ok(Frequency::InsertionPoint(ips));
            }
            return self.err("expected 'insertion point' after insertion point type");
        }
        if self.eat_phrase(&["insertion", "point"]) {
            return Ok(Frequency::InsertionPoint(vec![IpType::Any]));
        }
        if self.eat_word("response") {
            return Ok(Frequency::Response);
        }
        if self.eat_word("host") {
            return Ok(Frequency::Host);
        }
        if self.eat_word("request") {
            return Ok(Frequency::Request);
        }
        if self.eat_word("path") {
            return Ok(Frequency::Path);
        }
        self.err(format!(
            "expected host|path|request|response|insertion point, found {}",
            self.peek()
        ))
    }

    fn statements(&mut self) -> Result<Vec<Statement>, ParseError> {
        let mut out = Vec::new();
        loop {
            if matches!(self.peek(), Tok::Eof)
                || self.is_phrase(&["end", "if"])
                || self.is_word(0, "else")
            {
                break;
            }
            out.push(self.statement()?);
        }
        Ok(out)
    }

    fn statement(&mut self) -> Result<Statement, ParseError> {
        if self.is_word(0, "if") {
            return self.if_block();
        }
        if self.is_phrase(&["report", "issue"]) {
            return Ok(Statement::Report(self.report_issue()?));
        }
        if self.is_phrase(&["send", "request"]) {
            return self.send_request();
        }
        if self.is_phrase(&["send", "payload"]) {
            return self.send_payload();
        }
        self.err(format!("unexpected statement start {}", self.peek()))
    }

    fn if_block(&mut self) -> Result<Statement, ParseError> {
        self.expect_word("if")?;
        let cond = self.bool_expr()?;
        self.expect_word("then")?;
        let then = self.statements()?;

        let mut otherwise = Vec::new();
        if self.is_word(0, "else") {
            self.bump();
            if self.is_word(0, "if") {
                // `else if … then …` — nested, and it does NOT carry its own `end if`.
                otherwise = vec![self.if_block_no_end()?];
                return Ok(Statement::If { cond, then, otherwise });
            }
            // Bare `else` is invalid; `else then` is required.
            self.expect_word("then")?;
            otherwise = self.statements()?;
        }
        if !self.eat_phrase(&["end", "if"]) {
            return self.err(format!("expected 'end if', found {}", self.peek()));
        }
        Ok(Statement::If { cond, then, otherwise })
    }

    /// `else if` chain: consumes the shared trailing `end if` at the outermost level only.
    fn if_block_no_end(&mut self) -> Result<Statement, ParseError> {
        self.expect_word("if")?;
        let cond = self.bool_expr()?;
        self.expect_word("then")?;
        let then = self.statements()?;
        let mut otherwise = Vec::new();
        if self.is_word(0, "else") {
            self.bump();
            if self.is_word(0, "if") {
                otherwise = vec![self.if_block_no_end()?];
                return Ok(Statement::If { cond, then, otherwise });
            }
            self.expect_word("then")?;
            otherwise = self.statements()?;
        }
        // The `end if` belongs to the enclosing `if`.
        self.eat_phrase(&["end", "if"]);
        Ok(Statement::If { cond, then, otherwise })
    }

    fn report_issue(&mut self) -> Result<ReportIssue, ParseError> {
        self.expect_word("report")?;
        self.expect_word("issue")?;
        let and_continue = self.eat_phrase(&["and", "continue"]);
        self.expect_colon()?;

        let mut name = None;
        let mut severity = None;
        let mut confidence = None;
        let mut detail = None;
        let mut remediation = None;

        loop {
            let key = match self.peek().clone() {
                Tok::Word(w) => w.to_ascii_lowercase(),
                _ => break,
            };
            // Stop at anything that starts a new statement or closes the block.
            if matches!(key.as_str(), "if" | "end" | "else" | "report" | "send") {
                break;
            }
            if !matches!(self.at(1), Tok::Colon) {
                break;
            }
            self.bump();
            self.expect_colon()?;
            match key.as_str() {
                "name" => name = Some(self.value()?),
                "severity" => {
                    let v = self.word_or_str()?;
                    severity = Some(match v.to_ascii_lowercase().as_str() {
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        "low" => Severity::Low,
                        "info" | "information" => Severity::Info,
                        o => return self.err(format!("bad severity {o:?}")),
                    });
                }
                "confidence" => {
                    let v = self.word_or_str()?;
                    confidence = Some(match v.to_ascii_lowercase().as_str() {
                        "certain" => Confidence::Certain,
                        "firm" => Confidence::Firm,
                        "tentative" => Confidence::Tentative,
                        o => return self.err(format!("bad confidence {o:?}")),
                    });
                }
                "detail" => detail = Some(self.value()?),
                "remediation" => remediation = Some(self.value()?),
                o => return self.err(format!("unknown report issue field {o:?}")),
            }
        }

        let Some(severity) = severity else {
            return self.err("report issue requires 'severity'");
        };
        let Some(confidence) = confidence else {
            return self.err("report issue requires 'confidence'");
        };
        Ok(ReportIssue { name, severity, confidence, detail, remediation, and_continue })
    }

    /// M2 statement: parsed structurally so M1 never rejects an active check.
    fn send_request(&mut self) -> Result<Statement, ParseError> {
        self.expect_word("send")?;
        self.expect_word("request")?;
        let called = if self.eat_word("called") {
            match self.bump() {
                Tok::Word(w) => Some(w),
                Tok::LitStr(s) | Tok::TemplateStr(s) => Some(s),
                other => return self.err(format!("bad request name {other}")),
            }
        } else {
            None
        };
        self.expect_colon()?;
        // Either a whole raw request as one string, or a list of modifier clauses.
        let (raw, mods) = match self.peek().clone() {
            Tok::TemplateStr(s) => {
                self.bump();
                (Some(Value::Template(s)), Vec::new())
            }
            Tok::LitStr(s) => {
                self.bump();
                (Some(Value::Literal(s)), Vec::new())
            }
            _ => (None, self.request_mods()?),
        };
        Ok(Statement::SendRequest { called, raw, mods })
    }

    fn send_payload(&mut self) -> Result<Statement, ParseError> {
        self.expect_word("send")?;
        self.expect_word("payload")?;
        let called = if self.eat_word("called") {
            match self.bump() {
                Tok::Word(w) => Some(w),
                Tok::LitStr(s) | Tok::TemplateStr(s) => Some(s),
                other => return self.err(format!("bad payload name {other}")),
            }
        } else {
            None
        };
        self.expect_colon()?;
        // Only `appending:` / `replacing:` exist — there is no `inserting:`.
        let appending = if self.eat_word("appending") {
            true
        } else if self.eat_word("replacing") {
            false
        } else {
            return self.err(format!(
                "expected 'appending' or 'replacing', found {}",
                self.peek()
            ));
        };
        self.expect_colon()?;
        Ok(Statement::SendPayload { called, appending, value: self.value()? })
    }

    /// Parse the modifier clauses of a `send request:` block.
    ///
    /// Grammar, from the corpus rather than from the docs:
    ///
    /// ```text
    /// mods   := mod*
    /// mod    := ("replacing" | "appending")? target ":" payload
    /// target := method | path | query_string | queries | headers | body
    /// ```
    ///
    /// The prefix is **optional and usually absent** — a bare `path:` sets the path. Payload shape
    /// depends on the target: `headers` is `name: value` pairs, `queries` is a comma-separated list,
    /// everything else is a single value.
    fn request_mods(&mut self) -> Result<Vec<RequestMod>, ParseError> {
        let mut mods = Vec::new();
        loop {
            // A clause always starts with a word, and the word after any prefix must be followed by
            // a colon. Anything else is the next statement or the end of the block.
            let (op, target_off) = match self.peek() {
                Tok::Word(w) => match w.to_ascii_lowercase().as_str() {
                    "replacing" => (ModOp::Replace, 1),
                    "appending" => (ModOp::Append, 1),
                    _ => (ModOp::Replace, 0),
                },
                _ => break,
            };
            let Tok::Word(target) = self.at(target_off).clone() else { break };
            let target = target.to_ascii_lowercase();
            // Statement keywords end the block; they never take a colon here.
            if matches!(target.as_str(), "if" | "end" | "else" | "report" | "send") {
                break;
            }
            if !matches!(self.at(target_off + 1), Tok::Colon) {
                break;
            }
            for _ in 0..=target_off {
                self.bump();
            }
            self.expect_colon()?;

            mods.push(match target.as_str() {
                "method" => {
                    if op == ModOp::Append {
                        return self.err("'appending method' is not meaningful");
                    }
                    RequestMod::Method(self.value()?)
                }
                "path" => RequestMod::Path { op, value: self.value()? },
                "query_string" => {
                    if op == ModOp::Append {
                        // `appending queries` is the additive form; keep the distinction sharp.
                        return self.err("use 'appending queries' to add query parameters");
                    }
                    RequestMod::QueryString(self.value()?)
                }
                "queries" => {
                    let mut vs = vec![self.value()?];
                    while matches!(self.peek(), Tok::Comma) {
                        self.bump();
                        vs.push(self.value()?);
                    }
                    RequestMod::Queries(vs)
                }
                "headers" => RequestMod::Headers { op, pairs: self.header_pairs()? },
                "body" => RequestMod::Body { op, value: self.value()? },
                o => return self.err(format!("unknown request modifier {o:?}")),
            });
        }
        Ok(mods)
    }

    /// `name: value` pairs, comma separated. A bare entry with no colon is a whole header line
    /// (`"X-Foo: bar"`), which the builder splits at send time.
    fn header_pairs(&mut self) -> Result<Vec<(Value, Value)>, ParseError> {
        let mut pairs = Vec::new();
        loop {
            let name = self.value()?;
            let value = if matches!(self.peek(), Tok::Colon) {
                self.bump();
                self.value()?
            } else {
                // Signalled by an empty literal: "the name field already holds the whole line".
                Value::Literal(String::new())
            };
            pairs.push((name, value));
            if matches!(self.peek(), Tok::Comma) {
                self.bump();
                continue;
            }
            break;
        }
        Ok(pairs)
    }

    // ---- expressions ----------------------------------------------------------------------

    fn bool_expr(&mut self) -> Result<BoolExpr, ParseError> {
        let mut lhs = self.bool_term()?;
        loop {
            if self.eat_word("and") {
                // `and continue` belongs to `report issue`, not to a boolean chain.
                if self.is_word(0, "continue") {
                    self.i -= 1;
                    break;
                }
                lhs = BoolExpr::And(Box::new(lhs), Box::new(self.bool_term()?));
            } else if self.eat_word("or") {
                lhs = BoolExpr::Or(Box::new(lhs), Box::new(self.bool_term()?));
            } else {
                break;
            }
        }
        Ok(lhs)
    }

    fn bool_term(&mut self) -> Result<BoolExpr, ParseError> {
        if self.eat_word("not") {
            if !matches!(self.peek(), Tok::LParen) {
                return self.err("expected '(' after 'not'");
            }
            self.bump();
            let e = self.bool_expr()?;
            if !matches!(self.peek(), Tok::RParen) {
                return self.err("expected ')'");
            }
            self.bump();
            return Ok(BoolExpr::Not(Box::new(e)));
        }
        if matches!(self.peek(), Tok::LParen) {
            self.bump();
            let e = self.bool_expr()?;
            if !matches!(self.peek(), Tok::RParen) {
                return self.err("expected ')'");
            }
            self.bump();
            return Ok(e);
        }
        // `<type> interactions` — Collaborator poll.
        if let Tok::Word(w) = self.peek().clone() {
            let lw = w.to_ascii_lowercase();
            if matches!(lw.as_str(), "any" | "dns" | "http" | "smtp") && self.is_word(1, "interactions")
            {
                self.bump();
                self.bump();
                return Ok(BoolExpr::Interactions(match lw.as_str() {
                    "dns" => InteractionType::Dns,
                    "http" => InteractionType::Http,
                    "smtp" => InteractionType::Smtp,
                    _ => InteractionType::Any,
                }));
            }
        }

        let lhs = self.value()?;
        let op = if self.eat_word("matches") {
            CmpOp::Matches
        } else if self.eat_word("in") {
            CmpOp::In
        } else if self.eat_word("is") {
            CmpOp::Is
        } else if self.eat_phrase(&["differs", "from"]) {
            CmpOp::DiffersFrom
        } else {
            return self.err(format!(
                "expected matches|in|is|'differs from', found {}",
                self.peek()
            ));
        };
        let rhs = self.value()?;
        Ok(BoolExpr::Cmp { lhs, op, rhs })
    }

    fn value(&mut self) -> Result<Value, ParseError> {
        match self.bump() {
            Tok::LitStr(s) => Ok(Value::Literal(s)),
            Tok::TemplateStr(s) => Ok(Value::Template(s)),
            Tok::VarRef(v) => Ok(Value::Var(v)),
            // A bare word in value position (e.g. an unquoted enum) is treated as a literal.
            Tok::Word(w) => Ok(Value::Literal(w)),
            other => {
                self.i = self.i.saturating_sub(1);
                self.err(format!("expected a value, found {other}"))
            }
        }
    }

    fn word_or_str(&mut self) -> Result<String, ParseError> {
        match self.bump() {
            Tok::Word(w) => Ok(w),
            Tok::LitStr(s) | Tok::TemplateStr(s) => Ok(s),
            other => self.err(format!("expected a word, found {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F1 from the research: the minimal passive check, and the `{43}` regex trap.
    const F1: &str = r#"
metadata:
  language: v1-beta
  name: "NuGet API Key"
  description: "Looks for NuGet API keys in page source."
  author: "@puzzlepeaches"
  tags: "nuget", "token", "exposure"

given response then
  if {latest.response} matches "oy2[a-z0-9]{43}" then
      report issue:
          severity: info
          confidence: tentative
          detail: "NuGet API key found in page."
          remediation: "Review and remove unnecessary exposure."
  end if
"#;

    #[test]
    fn parses_f1_minimal_passive() {
        let c = parse(F1).unwrap();
        assert_eq!(c.metadata.language, Some(Language::V1Beta));
        assert_eq!(c.metadata.name, "NuGet API Key");
        assert_eq!(c.metadata.tags, vec!["nuget", "token", "exposure"]);
        assert_eq!(c.frequency, Frequency::Response);
        assert!(c.is_passive());
        assert!(!c.needs_collaborator());

        let Statement::If { cond, then, .. } = &c.body[0] else {
            panic!("expected an if")
        };
        // The regex must survive with its brace quantifier intact.
        let BoolExpr::Cmp { rhs, op, .. } = cond else { panic!("expected a cmp") };
        assert_eq!(*op, CmpOp::Matches);
        assert_eq!(rhs.raw(), "oy2[a-z0-9]{43}");
        assert!(matches!(&then[0], Statement::Report(r) if r.severity == Severity::Info));
    }

    #[test]
    fn whole_body_on_one_line_parses() {
        // Verified behaviour of PortSwigger's parser: no offside rule.
        let src = r#"metadata: language: v2-beta name: "x" given response then if {latest.response} matches "a" then report issue: severity: high confidence: firm end if"#;
        let c = parse(src).unwrap();
        assert_eq!(c.frequency, Frequency::Response);
    }

    #[test]
    fn severity_and_confidence_are_order_independent() {
        let a = r#"metadata: name: "x" given response then if {latest.response} is "a" then report issue: severity: low confidence: firm end if"#;
        let b = r#"metadata: name: "x" given response then if {latest.response} is "a" then report issue: confidence: firm severity: low end if"#;
        for s in [a, b] {
            let c = parse(s).unwrap();
            let Statement::If { then, .. } = &c.body[0] else { panic!() };
            let Statement::Report(r) = &then[0] else { panic!() };
            assert_eq!((r.severity, r.confidence), (Severity::Low, Confidence::Firm));
        }
    }

    #[test]
    fn missing_severity_or_confidence_is_rejected() {
        // Both are mandatory per the official validator.
        let s = r#"metadata: name: "x" given response then if {latest.response} is "a" then report issue: severity: low end if"#;
        assert!(parse(s).unwrap_err().msg.contains("confidence"));
    }

    #[test]
    fn bare_else_is_rejected_but_else_then_parses() {
        let bad = r#"metadata: name: "x" given response then if {latest.response} is "a" then report issue: severity: low confidence: firm else report issue: severity: high confidence: firm end if"#;
        assert!(parse(bad).is_err(), "bare else must be rejected");

        let good = r#"metadata: name: "x" given response then if {latest.response} is "a" then report issue: severity: low confidence: firm else then report issue: severity: high confidence: firm end if"#;
        let c = parse(good).unwrap();
        let Statement::If { otherwise, .. } = &c.body[0] else { panic!() };
        assert_eq!(otherwise.len(), 1);
    }

    #[test]
    fn boolean_operators_and_grouping() {
        let s = r#"metadata: name: "x" given response then if not({latest.response} in "a") and ({latest.response} matches "b" or {latest.response} is "c") then report issue: severity: info confidence: certain end if"#;
        let c = parse(s).unwrap();
        let Statement::If { cond, .. } = &c.body[0] else { panic!() };
        assert!(matches!(cond, BoolExpr::And(_, _)));
    }

    #[test]
    fn all_five_given_forms_parse_and_rejected_ones_fail() {
        for (src, want) in [
            ("response", Frequency::Response),
            ("host", Frequency::Host),
            ("request", Frequency::Request),
            ("path", Frequency::Path),
        ] {
            let s = format!(
                r#"metadata: name: "x" given {src} then if {{latest.response}} is "a" then report issue: severity: info confidence: firm end if"#
            );
            assert_eq!(parse(&s).unwrap().frequency, want);
        }
        // `given url` / `given query` / `given header` are rejected by the official validator.
        for bad in ["url", "somethingelse"] {
            let s = format!(
                r#"metadata: name: "x" given {bad} then if {{latest.response}} is "a" then report issue: severity: info confidence: firm end if"#
            );
            assert!(parse(&s).is_err(), "given {bad} must be rejected");
        }
    }

    // ---- request modifiers ---------------------------------------------------------------
    //
    // Shapes taken verbatim from the corpus. Before these, `skip_modifiers` discarded all 381
    // modifier clauses, so active checks parsed but carried no request mutation at all.

    /// Prefix the mandatory `metadata:` block so each test source can show only the send block.
    fn with_meta(body: &str) -> String {
        format!("metadata:\n  language: v2-beta\n  name: \"t\"\n{body}")
    }

    fn only_send(src: &str) -> (Option<String>, Vec<RequestMod>) {
        let src = with_meta(src);
        let c = parse(&src).unwrap_or_else(|e| panic!("should parse: {e}\n--- src ---\n{src}"));
        for st in &c.body {
            if let Statement::SendRequest { called, mods, .. } = st {
                return (called.clone(), mods.clone());
            }
        }
        panic!("no send request in {src:?}");
    }

    #[test]
    fn bare_targets_mean_replace() {
        // The Nacos shape: a `replacing headers:` block followed by bare `path:` and `body:`.
        let (called, mods) = only_send(
            r#"given host then
                 send request called check:
                   replacing headers:
                     "Content-Type": "application/json"
                   path: {potential_path}
                   body: "x=1"
                 if "y" in {check.response} then
                   report issue:
                     severity: high
                     confidence: certain
                 end if"#,
        );
        assert_eq!(called.as_deref(), Some("check"));
        assert_eq!(mods.len(), 3, "headers + path + body");
        assert!(matches!(&mods[0], RequestMod::Headers { op: ModOp::Replace, pairs } if pairs.len() == 1));
        assert!(matches!(&mods[1], RequestMod::Path { op: ModOp::Replace, .. }));
        assert!(matches!(&mods[2], RequestMod::Body { op: ModOp::Replace, .. }));
    }

    #[test]
    fn header_pairs_are_comma_separated() {
        // log4shell: four headers in one clause.
        let (_, mods) = only_send(
            r#"given request then
                 send request:
                   method: "GET"
                   appending queries: `x={p}`
                   replacing headers:
                     "Cookie": `{p}={p}`,
                     "Location": {p},
                     "Origin": {p},
                     "Referer": {p}"#,
        );
        assert_eq!(mods.len(), 3);
        assert!(matches!(&mods[0], RequestMod::Method(_)));
        assert!(matches!(&mods[1], RequestMod::Queries(v) if v.len() == 1));
        match &mods[2] {
            RequestMod::Headers { op: ModOp::Replace, pairs } => assert_eq!(pairs.len(), 4),
            o => panic!("expected headers, got {o:?}"),
        }
    }

    #[test]
    fn a_backtick_name_value_header_pair_parses() {
        // waf-bypass writes the pair with both sides interpolated.
        let (_, mods) = only_send(
            "given host then\n send request:\n  replacing headers: `{h}`:`{v}`",
        );
        match &mods[0] {
            RequestMod::Headers { pairs, .. } => {
                assert_eq!(pairs.len(), 1);
                assert_eq!(pairs[0].0, Value::Template("{h}".into()));
                assert_eq!(pairs[0].1, Value::Template("{v}".into()));
            }
            o => panic!("expected headers, got {o:?}"),
        }
    }

    #[test]
    fn multiple_queries_in_one_clause() {
        // Blind-SSRF appends two query parameters in a single clause.
        let (_, mods) = only_send(
            "given request then\n send request:\n  appending queries:\n   `proxy={a}`,\n   `url={b}`",
        );
        assert!(matches!(&mods[0], RequestMod::Queries(v) if v.len() == 2));
    }

    #[test]
    fn append_and_replace_are_distinguished() {
        let (_, mods) = only_send(
            "given path then\n send request:\n  appending path: \"/x\"\n  replacing body: \"b\"",
        );
        assert!(matches!(&mods[0], RequestMod::Path { op: ModOp::Append, .. }));
        assert!(matches!(&mods[1], RequestMod::Body { op: ModOp::Replace, .. }));
    }

    #[test]
    fn modifiers_stop_at_the_next_statement() {
        // The block must not swallow the `if` that follows it.
        let c = parse(&with_meta(
            r#"given host then
                 send request:
                   path: "/a"
                 if "x" in {latest.response} then
                   report issue:
                     severity: low
                     confidence: firm
                 end if"#,
        ))
        .unwrap();
        assert_eq!(c.body.len(), 2, "send and if must be separate statements");
        assert!(matches!(c.body[1], Statement::If { .. }));
    }

    #[test]
    fn a_raw_string_send_carries_no_modifiers() {
        let (_, mods) = only_send(
            "given host then\n send request: `GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n`",
        );
        assert!(mods.is_empty());
    }

    #[test]
    fn an_unknown_modifier_target_is_rejected() {
        // Better to fail loudly than to silently drop a clause, which is what the old code did.
        assert!(parse(&with_meta("given host then\n send request:\n  frobnicate: \"x\"")).is_err());
    }

    #[test]
    fn insertion_point_forms_parse() {
        let s = r#"metadata: name: "x" given query or header insertion point then if {latest.response} is "a" then report issue: severity: info confidence: firm end if"#;
        let c = parse(s).unwrap();
        assert_eq!(
            c.frequency,
            Frequency::InsertionPoint(vec![IpType::Query, IpType::Header])
        );
    }

    #[test]
    fn define_and_run_for_each_parse() {
        let s = r#"metadata: name: "x"
define:
  probe = "abc"
run for each:
  ext = "bak", "old", "zip"
given response then
  if {latest.response} in "x" then report issue: severity: info confidence: firm end if"#;
        let c = parse(s).unwrap();
        assert_eq!(c.defines.len(), 1);
        assert_eq!(c.for_each.len(), 1);
        assert_eq!(c.for_each[0].1.len(), 3);
    }

    #[test]
    fn collaborator_use_is_detected() {
        let s = r#"metadata: name: "x" given response then if any interactions then report issue: severity: high confidence: certain end if"#;
        let c = parse(s).unwrap();
        assert!(c.needs_collaborator());
    }

    #[test]
    fn and_continue_is_not_parsed_as_a_boolean() {
        let s = r#"metadata: name: "x" given response then if {latest.response} is "a" then report issue and continue: severity: info confidence: firm end if"#;
        let c = parse(s).unwrap();
        let Statement::If { then, .. } = &c.body[0] else { panic!() };
        let Statement::Report(r) = &then[0] else { panic!() };
        assert!(r.and_continue);
    }
}
