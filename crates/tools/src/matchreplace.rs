//! Match and replace — ordered rewrite rules applied to proxied requests and responses.
//!
//! # This runs on the proxy hot path, so compilation happens once — structurally
//!
//! Every proxied message is a chance to recompile a regex. Compilation is three to four orders of
//! magnitude more expensive than matching, so a rule set that compiles per message turns the proxy
//! into the bottleneck. The usual defence is a comment saying "don't do that". This module makes it
//! unrepresentable instead:
//!
//! * [`Rule`] has private fields and no public constructor other than [`Rule::new`], which
//!   compiles. You cannot write a `Rule { .. }` literal from outside this module.
//! * `Rule`'s `Deserialize` is `#[serde(try_from = "RuleSpec")]`, so the config-loading path — the
//!   one place where a "just parse it later" pattern normally sneaks in — runs the same
//!   constructor and fails at load time on a bad pattern.
//!
//! There is therefore no path from a pattern string to [`RuleSet::apply`] that skips compilation,
//! and a malformed regex is a startup error rather than a per-request one.
//!
//! Operator-supplied patterns are safe to run here for a reason worth stating: Rust's `regex` is
//! finite-automata based with no backtracking, so match time is linear in the subject and cannot be
//! blown up by a pathological pattern. The same design in a PCRE-backed proxy would be a
//! self-inflicted denial of service.
//!
//! [`RuleSet::apply`] returns `None` when nothing matched, so the proxy keeps its original `Bytes`
//! and no body is copied on the overwhelmingly common no-match path. [`RuleSet::affects`] is a
//! precomputed bool for the check before that.
//!
//! # The rule model is Burp's, on purpose
//!
//! [`RuleSpec`] deserialises Burp's own `proxy.match_replace_rules` entries verbatim —
//! `rule_type`, `category`, `enabled`, `string_match`, `string_replace`, `comment` — so an
//! operator's existing rule list pastes straight in. The taxonomy comes from `Zxvb.java`
//! (REQUEST_HEADER, REQUEST_BODY, RESPONSE_HEADER, RESPONSE_BODY, REQUEST_PARAM_NAME,
//! REQUEST_PARAM_VALUE, REQUEST_FIRST_LINE), and the two special cases are what Burp's shipped
//! defaults do:
//!
//! * **Absent match, literal category, header target = add a header.** ("Add spoofed CORS origin",
//!   `{"category":"literal","rule_type":"request_header","string_replace":"Origin: …"}`.)
//! * **Absent replacement = delete the matched text, and drop the header line if that empties it.**
//!   ("Hide Referer header", `{"string_match":"^Referer.*$"}`.)
//!
//! Header rules are applied to **one header line at a time**, which is why Burp's own defaults can
//! write `^User-Agent.*$` and `^Host: foo.example.org$` and have the anchors mean what they look
//! like. Applying them to the whole header block would make `^` match only the first line.
//!
//! There is no `response_first_line` in Burp's taxonomy, so `response_header` rules here see the
//! status line as well as the headers — otherwise no rule could reach it at all.
//!
//! # Content-Length is not silently fixed
//!
//! Match and replace is the tool operators use *specifically* to build malformed messages:
//! CL/TE desync, request smuggling, header-injection probes. Recomputing Content-Length after a
//! body rewrite would destroy exactly the test being run, so [`RuleSetSpec::update_content_length`]
//! is **off by default**. Turned on, it still stands down if a rule targeted the Content-Length
//! header itself — at that point the operator has said what they want the value to be.
//!
//! Body rules are skipped entirely on a `Transfer-Encoding: chunked` message: those body bytes
//! carry chunk framing, and rewriting inside it corrupts the stream rather than the content.

use burpsy_core::{Direction, Scope};
use regex::bytes::{NoExpand, Regex};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Which part of which message a rule rewrites. Names match Burp's `rule_type` config values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    RequestFirstLine,
    RequestHeader,
    RequestBody,
    /// Includes the status line: Burp has no `response_first_line`.
    ResponseHeader,
    ResponseBody,
}

impl Target {
    pub fn direction(self) -> Direction {
        match self {
            Target::RequestFirstLine | Target::RequestHeader | Target::RequestBody => {
                Direction::Request
            }
            Target::ResponseHeader | Target::ResponseBody => Direction::Response,
        }
    }

    /// True for the two line-oriented header targets, where an empty match means "add a header"
    /// and an emptied line is dropped.
    pub fn is_header(self) -> bool {
        matches!(self, Target::RequestHeader | Target::ResponseHeader)
    }

    pub fn is_body(self) -> bool {
        matches!(self, Target::RequestBody | Target::ResponseBody)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Target::RequestFirstLine => "request_first_line",
            Target::RequestHeader => "request_header",
            Target::RequestBody => "request_body",
            Target::ResponseHeader => "response_header",
            Target::ResponseBody => "response_body",
        }
    }
}

/// How `string_match` is interpreted. Burp's `category` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    #[default]
    Regex,
    Literal,
}

fn enabled_by_default() -> bool {
    true
}

/// The serialisable form of a rule. Wire-compatible with Burp's `proxy.match_replace_rules`.
///
/// This type is *inert*: holding one proves nothing has been compiled. Turn it into a [`Rule`] to
/// get something that can run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    pub rule_type: Target,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Empty means "add" for a header target, and is an error anywhere else.
    #[serde(default)]
    pub string_match: String,
    /// Empty means "delete what matched".
    #[serde(default)]
    pub string_replace: String,
    #[serde(default)]
    pub category: Category,
    /// The operator's label for the rule. Burp calls it a comment.
    #[serde(default)]
    pub comment: String,
    /// Apply only to messages whose host, port, path and scheme match. `None` applies everywhere.
    ///
    /// A burpsy addition: Burp has one global `match_replace_disable_out_of_scope` switch for the
    /// whole list, which cannot express "spoof this header, but only on the staging host".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
}

impl RuleSpec {
    /// A regex rule over `target`.
    pub fn new(target: Target, pattern: impl Into<String>, replace: impl Into<String>) -> Self {
        Self {
            rule_type: target,
            enabled: true,
            string_match: pattern.into(),
            string_replace: replace.into(),
            category: Category::Regex,
            comment: String::new(),
            scope: None,
        }
    }

    /// A rule that adds a header line, Burp's `{"category":"literal","string_match":""}` form.
    pub fn add_header(target: Target, line: impl Into<String>) -> Self {
        Self {
            rule_type: target,
            enabled: true,
            string_match: String::new(),
            string_replace: line.into(),
            category: Category::Literal,
            comment: String::new(),
            scope: None,
        }
    }

    pub fn with_comment(mut self, c: impl Into<String>) -> Self {
        self.comment = c.into();
        self
    }

    pub fn with_scope(mut self, s: Scope) -> Self {
        self.scope = Some(s);
        self
    }

    pub fn literal(mut self) -> Self {
        self.category = Category::Literal;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    /// The rule's comment, or its pattern when it has no comment.
    pub rule: String,
    pub message: String,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "match/replace rule {:?}: {}", self.rule, self.message)
    }
}

impl std::error::Error for RuleError {}

#[derive(Debug, Clone)]
enum Action {
    /// Substitute every match of the pattern.
    Replace(Regex),
    /// Append `string_replace` as a new header line.
    AddHeader,
}

/// A compiled, runnable rule. Construction is the only way in, and construction compiles.
#[derive(Debug, Clone)]
pub struct Rule {
    spec: RuleSpec,
    action: Action,
}

impl Rule {
    /// Compile a rule. Every error a pattern can cause surfaces here, once, at config time.
    pub fn new(spec: RuleSpec) -> Result<Self, RuleError> {
        let label = if spec.comment.is_empty() {
            spec.string_match.clone()
        } else {
            spec.comment.clone()
        };
        let err = |m: &str| RuleError {
            rule: label.clone(),
            message: m.to_string(),
        };

        // A scope with no rules matches nothing, so the rule would silently never fire. That is a
        // configuration mistake worth refusing rather than a rule that quietly does nothing.
        if let Some(s) = &spec.scope
            && s.is_empty()
        {
            return Err(err(
                "the scope has no rules, so it authorises nothing; omit `scope` to apply everywhere",
            ));
        }

        let action = if spec.string_match.is_empty() {
            if !spec.rule_type.is_header() {
                return Err(err(
                    "an empty match would match everywhere; empty is only meaningful on a header \
                     rule, where it means add a header",
                ));
            }
            if spec.string_replace.is_empty() {
                return Err(err(
                    "neither a match nor a replacement: this rule does nothing",
                ));
            }
            Action::AddHeader
        } else {
            let pattern = match spec.category {
                Category::Regex => spec.string_match.clone(),
                Category::Literal => regex::escape(&spec.string_match),
            };
            // `(?m)` is deliberately not forced: header rules already see one line at a time, and
            // a body rule that wants multiline anchors can say so itself.
            Action::Replace(Regex::new(&pattern).map_err(|e| err(&e.to_string()))?)
        };

        Ok(Self { spec, action })
    }

    pub fn spec(&self) -> &RuleSpec {
        &self.spec
    }

    pub fn target(&self) -> Target {
        self.spec.rule_type
    }

    pub fn enabled(&self) -> bool {
        self.spec.enabled
    }

    pub fn comment(&self) -> &str {
        &self.spec.comment
    }

    fn in_scope(&self, ctx: &Ctx<'_>) -> bool {
        self.spec
            .scope
            .as_ref()
            .is_none_or(|s| s.contains(ctx.host, ctx.port, ctx.path, ctx.tls))
    }

    /// Rewrite one region. Returns true when it changed.
    fn rewrite(&self, v: &mut Cow<'_, [u8]>) -> bool {
        let Action::Replace(re) = &self.action else {
            return false;
        };
        let rep = self.spec.string_replace.as_bytes();
        // A literal rule is literal on both sides: `$1` in the replacement of a literal rule is a
        // dollar sign, not a capture group.
        let replaced = if self.spec.category == Category::Literal {
            match re.replace_all(v.as_ref(), NoExpand(rep)) {
                Cow::Borrowed(_) => None,
                Cow::Owned(o) => Some(o),
            }
        } else {
            match re.replace_all(v.as_ref(), rep) {
                Cow::Borrowed(_) => None,
                Cow::Owned(o) => Some(o),
            }
        };
        match replaced {
            Some(o) => {
                *v = Cow::Owned(o);
                true
            }
            None => false,
        }
    }
}

impl TryFrom<RuleSpec> for Rule {
    type Error = RuleError;
    fn try_from(spec: RuleSpec) -> Result<Self, Self::Error> {
        Rule::new(spec)
    }
}

impl From<Rule> for RuleSpec {
    fn from(r: Rule) -> Self {
        r.spec
    }
}

// The whole point: even the deserialisation path compiles. There is no way to obtain a `Rule`
// whose regex has not been through `Rule::new`.
impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let spec = RuleSpec::deserialize(d)?;
        Rule::new(spec).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Rule {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.spec.serialize(s)
    }
}

/// Everything about the message a rule's scope condition needs.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub tls: bool,
}

/// The serialisable form of a rule set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSetSpec {
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
    /// Rewrite `Content-Length` when a body rule changed the body's length. Off by default: see
    /// the module docs.
    #[serde(default)]
    pub update_content_length: bool,
}

/// An ordered, compiled rule set. Each rule sees the output of the ones before it.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    any_request: bool,
    any_response: bool,
    update_content_length: bool,
}

impl RuleSet {
    /// Compile a whole set. The first bad rule stops the load and names itself.
    pub fn compile(spec: RuleSetSpec) -> Result<Self, RuleError> {
        let rules = spec
            .rules
            .into_iter()
            .map(Rule::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_rules(rules, spec.update_content_length))
    }

    pub fn from_rules(rules: Vec<Rule>, update_content_length: bool) -> Self {
        let any_request = rules
            .iter()
            .any(|r| r.enabled() && r.target().direction() == Direction::Request);
        let any_response = rules
            .iter()
            .any(|r| r.enabled() && r.target().direction() == Direction::Response);
        Self {
            rules,
            any_request,
            any_response,
            update_content_length,
        }
    }

    pub fn spec(&self) -> RuleSetSpec {
        RuleSetSpec {
            rules: self.rules.iter().map(|r| r.spec.clone()).collect(),
            update_content_length: self.update_content_length,
        }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether any enabled rule targets this direction. One bool load — the proxy's first check.
    pub fn affects(&self, direction: Direction) -> bool {
        match direction {
            Direction::Request => self.any_request,
            Direction::Response => self.any_response,
        }
    }

    /// Apply every applicable rule in order. `None` means nothing changed, so the caller keeps its
    /// original bytes.
    pub fn apply(&self, direction: Direction, ctx: &Ctx<'_>, raw: &[u8]) -> Option<Vec<u8>> {
        if !self.affects(direction) || raw.is_empty() {
            return None;
        }
        // Cheapest possible early exit: no rule for this direction is even in scope.
        let applicable: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| r.enabled() && r.target().direction() == direction && r.in_scope(ctx))
            .collect();
        if applicable.is_empty() {
            return None;
        }

        let parsed = parse_message(raw);
        let chunked = parsed.lines.iter().skip(1).any(|l| {
            header_name(l.text).is_some_and(|n| n.eq_ignore_ascii_case(b"transfer-encoding"))
                && contains_ignore_ascii_case(l.text, b"chunked")
        });

        let mut lines: Vec<Option<Cow<'_, [u8]>>> = parsed
            .lines
            .iter()
            .map(|l| Some(Cow::Borrowed(l.text)))
            .collect();
        let mut added: Vec<Vec<u8>> = Vec::new();
        let mut body: Cow<'_, [u8]> = Cow::Borrowed(parsed.body);
        let mut changed = false;
        let mut body_changed = false;
        let mut content_length_touched = false;

        for rule in applicable {
            let target = rule.target();
            if target.is_body() {
                // Chunk framing is not content; rewriting inside it corrupts the stream.
                if chunked {
                    continue;
                }
                if rule.rewrite(&mut body) {
                    changed = true;
                    body_changed = true;
                }
                continue;
            }
            if matches!(rule.action, Action::AddHeader) {
                added.push(rule.spec.string_replace.clone().into_bytes());
                changed = true;
                continue;
            }
            for i in line_range(target, lines.len()) {
                let Some(line) = lines[i].as_mut() else {
                    continue;
                };
                let was_content_length =
                    header_name(line).is_some_and(|n| n.eq_ignore_ascii_case(b"content-length"));
                if rule.rewrite(line) {
                    changed = true;
                    content_length_touched |= was_content_length;
                    // An emptied header line is a deleted header — Burp's "Hide Referer header".
                    // The start line is exempt: an empty first line is not a message.
                    if i > 0 && line.is_empty() {
                        lines[i] = None;
                    }
                }
            }
        }

        if !changed {
            return None;
        }

        if self.update_content_length && body_changed && !chunked && !content_length_touched {
            let new_len = body.len().to_string();
            for slot in lines.iter_mut().skip(1) {
                let Some(line) = slot.as_mut() else { continue };
                if header_name(line).is_some_and(|n| n.eq_ignore_ascii_case(b"content-length")) {
                    let mut v = Vec::with_capacity(new_len.len() + 16);
                    v.extend_from_slice(b"Content-Length: ");
                    v.extend_from_slice(new_len.as_bytes());
                    *line = Cow::Owned(v);
                    break;
                }
            }
        }

        Some(rebuild(&parsed, &lines, &added, &body))
    }
}

/// Which line indices a target addresses. Requests split the start line out because Burp has a
/// dedicated `request_first_line` type; responses have no such type, so their header rules cover
/// the status line too.
fn line_range(target: Target, n: usize) -> std::ops::Range<usize> {
    match target {
        Target::RequestFirstLine => 0..n.min(1),
        Target::RequestHeader => n.min(1)..n,
        Target::ResponseHeader => 0..n,
        _ => 0..0,
    }
}

struct Line<'a> {
    text: &'a [u8],
    /// The exact terminator bytes that followed. Preserved so a bare-LF message stays bare-LF —
    /// line endings are load-bearing when you are testing request smuggling.
    term: &'a [u8],
}

struct Parsed<'a> {
    lines: Vec<Line<'a>>,
    blank_term: &'a [u8],
    body: &'a [u8],
}

fn parse_message(raw: &[u8]) -> Parsed<'_> {
    let mut lines = Vec::new();
    let mut blank_term: &[u8] = b"";
    let mut body_start = raw.len();
    let mut i = 0;
    while i < raw.len() {
        match raw[i..].iter().position(|&c| c == b'\n') {
            Some(rel) => {
                let nl = i + rel;
                let text_end = if nl > i && raw[nl - 1] == b'\r' {
                    nl - 1
                } else {
                    nl
                };
                let term = &raw[text_end..nl + 1];
                if text_end == i {
                    blank_term = term;
                    body_start = nl + 1;
                    break;
                }
                lines.push(Line {
                    text: &raw[i..text_end],
                    term,
                });
                i = nl + 1;
            }
            None => {
                lines.push(Line {
                    text: &raw[i..],
                    term: b"",
                });
                break;
            }
        }
    }
    Parsed {
        lines,
        blank_term,
        body: &raw[body_start.min(raw.len())..],
    }
}

fn rebuild(
    parsed: &Parsed<'_>,
    lines: &[Option<Cow<'_, [u8]>>],
    added: &[Vec<u8>],
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 512);
    let mut last_term: &[u8] = b"\r\n";
    for (i, slot) in lines.iter().enumerate() {
        let Some(text) = slot else { continue };
        let term = parsed.lines[i].term;
        out.extend_from_slice(text);
        out.extend_from_slice(term);
        if !term.is_empty() {
            last_term = term;
        }
    }
    for line in added {
        out.extend_from_slice(line);
        out.extend_from_slice(last_term);
    }
    out.extend_from_slice(parsed.blank_term);
    out.extend_from_slice(body);
    out
}

/// The header name in a `Name: value` line, or `None` when there is no colon.
fn header_name(line: &[u8]) -> Option<&[u8]> {
    let i = line.iter().position(|&c| c == b':')?;
    Some(&line[..i])
}

fn contains_ignore_ascii_case(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len()
        && hay
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::ScopeRule;

    const REQ: &[u8] =
        b"POST /login HTTP/1.1\r\nHost: x.test\r\nUser-Agent: curl/8\r\nContent-Length: 7\r\n\r\na=1&b=2";

    fn ctx() -> Ctx<'static> {
        Ctx {
            host: "x.test",
            port: 443,
            path: "/login",
            tls: true,
        }
    }

    fn set(rules: Vec<RuleSpec>) -> RuleSet {
        RuleSet::compile(RuleSetSpec {
            rules,
            update_content_length: false,
        })
        .unwrap()
    }

    fn s(v: Vec<u8>) -> String {
        String::from_utf8_lossy(&v).into_owned()
    }

    #[test]
    fn a_bad_pattern_is_rejected_at_construction_not_at_request_time() {
        let e = Rule::new(RuleSpec::new(Target::RequestHeader, "([unclosed", "")).unwrap_err();
        assert!(
            e.message.contains("regex")
                || e.message.contains("repetition")
                || e.message.contains("class"),
            "{e}"
        );
        // And through serde, which is the path a config file takes.
        let json = r#"{"rule_type":"request_header","string_match":"([unclosed"}"#;
        assert!(serde_json::from_str::<Rule>(json).is_err());
    }

    #[test]
    fn burps_own_shipped_rules_deserialise_verbatim() {
        // Copied from Burp 2026.7.1 ProjectDefaults.json, `proxy.match_replace_rules`.
        let json = r#"[
            {"category":"regex","comment":"Emulate Edge","enabled":false,
             "rule_type":"request_header","string_match":"^User-Agent.*$",
             "string_replace":"User-Agent: Mozilla/5.0 (Windows NT 10.0)"},
            {"category":"regex","comment":"Hide Referer header","enabled":false,
             "rule_type":"request_header","string_match":"^Referer.*$"},
            {"category":"literal","comment":"Add spoofed CORS origin","enabled":false,
             "rule_type":"request_header","string_replace":"Origin: foo.example.org"},
            {"category":"regex","comment":"Ignore cookies","enabled":false,
             "rule_type":"response_header","string_match":"^Set-Cookie.*$"}
        ]"#;
        let rules: Vec<Rule> = serde_json::from_str(json).unwrap();
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].comment(), "Emulate Edge");
        assert_eq!(rules[2].target(), Target::RequestHeader);
        assert!(
            matches!(rules[2].action, Action::AddHeader),
            "absent match means add"
        );
        assert!(
            rules.iter().all(|r| !r.enabled()),
            "all shipped defaults are off"
        );
    }

    #[test]
    fn a_header_rule_is_anchored_to_one_header_line() {
        // `^User-Agent.*$` must not match at the start of the whole header block only, nor spill
        // across lines. This is why Burp's own defaults can be written that way.
        let rs = set(vec![RuleSpec::new(
            Target::RequestHeader,
            "^User-Agent.*$",
            "User-Agent: burpsy",
        )]);
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(out.contains("User-Agent: burpsy"), "{out}");
        assert!(
            out.contains("Host: x.test"),
            "other headers untouched: {out}"
        );
        assert!(
            out.starts_with("POST /login HTTP/1.1"),
            "request line untouched: {out}"
        );
    }

    #[test]
    fn an_emptied_header_line_is_dropped_entirely() {
        // Burp's "Hide Referer header": match the whole line, replace with nothing.
        let rs = set(vec![RuleSpec::new(
            Target::RequestHeader,
            "^User-Agent.*$",
            "",
        )]);
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(!out.contains("User-Agent"), "{out}");
        assert!(
            !out.contains("\r\n\r\nHost"),
            "no blank line left behind: {out:?}"
        );
        assert!(
            out.starts_with("POST /login HTTP/1.1\r\nHost: x.test\r\nContent-Length: 7\r\n\r\n"),
            "{out:?}"
        );
    }

    #[test]
    fn an_empty_match_adds_a_header_and_is_refused_on_a_body_rule() {
        let rs = set(vec![RuleSpec::add_header(
            Target::RequestHeader,
            "Origin: foo.example.org",
        )]);
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(
            out.contains("Content-Length: 7\r\nOrigin: foo.example.org\r\n\r\n"),
            "{out:?}"
        );

        // The same shape on a body target would match at every position and mangle the body, so
        // it is a construction error rather than a surprise at run time.
        let e = Rule::new(RuleSpec::add_header(Target::RequestBody, "x")).unwrap_err();
        assert!(e.message.contains("empty match"), "{e}");
    }

    #[test]
    fn rules_run_in_order_and_each_sees_the_previous_output() {
        let rs = set(vec![
            RuleSpec::new(Target::RequestHeader, "curl/8", "wget/1"),
            RuleSpec::new(Target::RequestHeader, "wget/1", "burpsy/0"),
        ]);
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(out.contains("User-Agent: burpsy/0"), "{out}");
    }

    #[test]
    fn no_match_returns_none_so_the_proxy_keeps_its_original_bytes() {
        let rs = set(vec![RuleSpec::new(
            Target::RequestHeader,
            "^Nothing.*$",
            "x",
        )]);
        assert!(rs.apply(Direction::Request, &ctx(), REQ).is_none());
    }

    #[test]
    fn a_direction_with_no_enabled_rules_is_rejected_by_a_single_bool() {
        let rs = set(vec![RuleSpec::new(Target::RequestHeader, "curl", "x")]);
        assert!(rs.affects(Direction::Request));
        assert!(!rs.affects(Direction::Response));
        let resp = b"HTTP/1.1 200 OK\r\nServer: curl\r\n\r\n";
        assert!(rs.apply(Direction::Response, &ctx(), resp).is_none());
    }

    #[test]
    fn a_disabled_rule_does_not_run_and_does_not_arm_its_direction() {
        let mut spec = RuleSpec::new(Target::ResponseHeader, "^Server.*$", "Server: none");
        spec.enabled = false;
        let rs = set(vec![spec]);
        assert!(!rs.affects(Direction::Response));
    }

    #[test]
    fn content_length_is_left_stale_by_default_because_that_is_the_test() {
        // A CL/TE desync probe depends on the mismatch surviving. Fixing it silently would make
        // the tool quietly refuse to run the experiment.
        let rs = set(vec![RuleSpec::new(Target::RequestBody, "b=2", "b=22222")]);
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(
            out.contains("Content-Length: 7"),
            "stale length preserved: {out:?}"
        );
        assert!(out.ends_with("a=1&b=22222"), "{out:?}");
    }

    #[test]
    fn content_length_is_rewritten_when_the_operator_asks_for_it() {
        let rs = RuleSet::compile(RuleSetSpec {
            rules: vec![RuleSpec::new(Target::RequestBody, "b=2", "b=22222")],
            update_content_length: true,
        })
        .unwrap();
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(out.contains("Content-Length: 11"), "{out:?}");
        assert_eq!(out.matches("Content-Length").count(), 1);
    }

    #[test]
    fn an_explicit_content_length_rule_wins_over_the_automatic_rewrite() {
        // The operator named the value they want; the convenience must stand down.
        let rs = RuleSet::compile(RuleSetSpec {
            rules: vec![
                RuleSpec::new(Target::RequestBody, "b=2", "b=22222"),
                RuleSpec::new(
                    Target::RequestHeader,
                    "^Content-Length: .*$",
                    "Content-Length: 4",
                ),
            ],
            update_content_length: true,
        })
        .unwrap();
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(out.contains("Content-Length: 4"), "{out:?}");
    }

    #[test]
    fn a_chunked_body_is_left_alone_rather_than_rewritten_inside_its_framing() {
        let raw = b"POST /f HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n";
        let rs = set(vec![RuleSpec::new(Target::RequestBody, "Wiki", "Pedia")]);
        assert!(
            rs.apply(Direction::Request, &ctx(), raw).is_none(),
            "rewriting inside chunk framing corrupts the stream, so the rule is skipped"
        );
    }

    #[test]
    fn a_response_header_rule_can_reach_the_status_line() {
        // Burp has no `response_first_line`, so `response_header` has to cover it.
        let resp = b"HTTP/1.1 403 Forbidden\r\nServer: nginx\r\n\r\nnope";
        let rs = set(vec![RuleSpec::new(
            Target::ResponseHeader,
            "^HTTP/1.1 403 Forbidden$",
            "HTTP/1.1 200 OK",
        )]);
        let out = s(rs.apply(Direction::Response, &ctx(), resp).unwrap());
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out:?}");
        assert!(out.ends_with("nope"));
    }

    #[test]
    fn a_request_header_rule_cannot_touch_the_request_line() {
        let rs = set(vec![RuleSpec::new(Target::RequestHeader, "POST", "GET")]);
        assert!(
            rs.apply(Direction::Request, &ctx(), REQ).is_none(),
            "the request line needs an explicit request_first_line rule"
        );
        let rs = set(vec![RuleSpec::new(
            Target::RequestFirstLine,
            "^POST",
            "GET",
        )]);
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(out.starts_with("GET /login HTTP/1.1"), "{out:?}");
    }

    #[test]
    fn the_start_line_is_never_deleted_even_if_a_rule_empties_it() {
        // An empty first line is not a message; dropping it would produce a truncated head.
        let rs = set(vec![RuleSpec::new(Target::RequestFirstLine, "^.*$", "")]);
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(
            out.starts_with("\r\nHost: x.test"),
            "kept as an empty line: {out:?}"
        );
    }

    #[test]
    fn a_scope_condition_limits_a_rule_to_the_hosts_it_names() {
        let mut scope = Scope::new();
        scope.add(ScopeRule::include("staging.test"));
        let rs = set(vec![
            RuleSpec::new(Target::RequestHeader, "^Host: .*$", "Host: rewritten").with_scope(scope),
        ]);
        assert!(
            rs.apply(Direction::Request, &ctx(), REQ).is_none(),
            "x.test is out of scope"
        );
        let staging = Ctx {
            host: "staging.test",
            ..ctx()
        };
        let out = s(rs.apply(Direction::Request, &staging, REQ).unwrap());
        assert!(out.contains("Host: rewritten"), "{out}");
    }

    #[test]
    fn an_empty_scope_is_refused_because_it_would_silently_disable_the_rule() {
        let e = Rule::new(RuleSpec::new(Target::RequestHeader, "a", "b").with_scope(Scope::new()))
            .unwrap_err();
        assert!(e.message.contains("authorises nothing"), "{e}");
    }

    #[test]
    fn bare_lf_line_endings_survive_a_rewrite() {
        // Line endings are load-bearing when you are testing smuggling; rebuilding with CRLF would
        // quietly repair the very thing under test.
        let raw = b"GET / HTTP/1.1\nHost: x\nX-A: 1\n\nbody";
        let rs = set(vec![RuleSpec::new(
            Target::RequestHeader,
            "^X-A: 1$",
            "X-A: 2",
        )]);
        let out = rs.apply(Direction::Request, &ctx(), raw).unwrap();
        assert_eq!(s(out), "GET / HTTP/1.1\nHost: x\nX-A: 2\n\nbody");
    }

    #[test]
    fn a_literal_rule_does_not_treat_its_pattern_or_replacement_as_regex() {
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\n\r\ncost=$1.50 (approx)";
        let rs = set(vec![
            RuleSpec::new(Target::RequestBody, "$1.50 (approx)", "$2.00").literal(),
        ]);
        let out = s(rs.apply(Direction::Request, &ctx(), raw).unwrap());
        assert!(out.ends_with("cost=$2.00"), "{out:?}");
    }

    #[test]
    fn a_regex_rule_expands_capture_groups_in_its_replacement() {
        let rs = set(vec![RuleSpec::new(
            Target::RequestHeader,
            "^User-Agent: (.*)$",
            "User-Agent: $1 burpsy",
        )]);
        let out = s(rs.apply(Direction::Request, &ctx(), REQ).unwrap());
        assert!(out.contains("User-Agent: curl/8 burpsy"), "{out}");
    }

    #[test]
    fn a_body_rule_leaves_every_header_byte_identical() {
        let rs = set(vec![RuleSpec::new(Target::RequestBody, "a=1", "a=9")]);
        let out = rs.apply(Direction::Request, &ctx(), REQ).unwrap();
        let split = |m: &[u8]| {
            let i = m.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
            m[..i].to_vec()
        };
        assert_eq!(split(&out), split(REQ), "the head must be byte-identical");
        assert!(s(out).ends_with("a=9&b=2"));
    }

    #[test]
    fn a_rule_set_round_trips_through_its_spec() {
        let spec = RuleSetSpec {
            rules: vec![
                RuleSpec::new(Target::ResponseBody, "secret", "[redacted]").with_comment("redact"),
                RuleSpec::add_header(Target::RequestHeader, "X-Test: 1"),
            ],
            update_content_length: true,
        };
        let before = serde_json::to_string(&spec).unwrap();
        let rs = RuleSet::compile(spec).unwrap();
        assert_eq!(serde_json::to_string(&rs.spec()).unwrap(), before);
        // And the serialised form loads back into an equivalent, already-compiled set.
        let reloaded = RuleSet::compile(serde_json::from_str(&before).unwrap()).unwrap();
        assert_eq!(serde_json::to_string(&reloaded.spec()).unwrap(), before);
        assert!(reloaded.affects(Direction::Request) && reloaded.affects(Direction::Response));
    }
}
