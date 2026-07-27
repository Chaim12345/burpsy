//! BCheck AST — M1 (passive) subset, with the shape reserved for M2/M3.
//!
//! Field spellings here are the ones PortSwigger's parser actually accepts, several of which are not
//! what you would guess:
//!
//! * the issue-title field is **`name:`** (`issue name:` / `issue_name:` are rejected)
//! * the request part is **`query_string`** with an underscore
//! * bare `else` is invalid — it is **`else then`**
//! * there is no `inserting:`; payload modifiers are `appending:` / `replacing:` only
//!
//! Notably absent: **any arithmetic**. `{{1337*1337}}` in the corpus is an SSTI *payload* inside a
//! literal string, not a BCheck expression — the author hand-computed the expected output. So there
//! is deliberately no expression node here.

use serde::{Deserialize, Serialize};

/// Declared dialect. v2-beta is a strict superset of v1-beta — the token-set difference is four
/// additions and zero removals — so one v2 parser accepts 100% of the corpus and this field is
/// recorded rather than used to select a grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    V1Beta,
    V2Beta,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub language: Option<Language>,
    pub name: String,
    pub description: Option<String>,
    pub author: Option<String>,
    pub tags: Vec<String>,
}

/// Which scan point the check binds to.
///
/// The authoritative set in PortSwigger's parser is exactly these five. `given url`, `given query`
/// and `given header` are **rejected** — those words exist only as insertion-point qualifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frequency {
    /// 39.8% of the corpus. Maps to the passive scanner, not to one of the seven active
    /// dispatch scopes.
    Response,
    Host,
    Request,
    Path,
    InsertionPoint(Vec<IpType>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpType {
    Any,
    Query,
    Header,
    Body,
    Cookie,
}

/// A string or a variable reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// `"…"` — no interpolation, ever.
    Literal(String),
    /// `` `…` `` — `{…}` expanded at eval time.
    Template(String),
    /// `{…}` — a bare reference.
    Var(String),
}

impl Value {
    /// The raw text, for cases where interpolation is not wanted (e.g. a regex RHS).
    pub fn raw(&self) -> &str {
        match self {
            Value::Literal(s) | Value::Template(s) | Value::Var(s) => s,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpOp {
    /// Regex match. RHS is always a literal string.
    Matches,
    /// Substring / containment.
    In,
    /// Exact equality.
    Is,
    /// Whole-object inequality (compares named request/response pairs). 0.8% of the corpus.
    DiffersFrom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteractionType {
    Any,
    Dns,
    Http,
    Smtp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BoolExpr {
    Cmp {
        lhs: Value,
        op: CmpOp,
        rhs: Value,
    },
    /// Collaborator poll: `<type> interactions`.
    Interactions(InteractionType),
    And(Box<BoolExpr>, Box<BoolExpr>),
    Or(Box<BoolExpr>, Box<BoolExpr>),
    Not(Box<BoolExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    Certain,
    Firm,
    Tentative,
}

/// `report issue:` — severity and confidence are both mandatory but order-independent;
/// `detail`/`remediation` optional; `name:` must come first if present.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportIssue {
    pub name: Option<Value>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub detail: Option<Value>,
    pub remediation: Option<Value>,
    /// `report issue and continue:` — keep evaluating instead of stopping at the first finding.
    pub and_continue: bool,
}

/// How a modifier combines with the base request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModOp {
    /// `replacing x:` — and also the bare `x:` form, which is the *dominant* spelling in the
    /// corpus: 305 bare clauses (`method:` 147, `path:` 111, `body:` 25, `headers:` 22) against 76
    /// prefixed ones, 381 in total. The conformance runner tallies these and the numbers agree
    /// exactly, which is what proves no clause is silently dropped.
    Replace,
    Append,
}

/// One clause inside a `send request:` block.
///
/// Modelled per-target rather than as a `(String, Value)` bag because the payload grammar differs:
/// `headers` is a name→value pair list, `queries` is a list of `k=v` clauses, and the rest take a
/// single value. Flattening them would push that difference into the evaluator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RequestMod {
    /// Replace-only in practice; `appending method` is meaningless and rejected.
    Method(Value),
    Path { op: ModOp, value: Value },
    QueryString(Value),
    /// `appending queries:` — each entry is one `k=v` clause, joined with `?` or `&` depending on
    /// whether the request already has a query.
    Queries(Vec<Value>),
    Headers { op: ModOp, pairs: Vec<(Value, Value)> },
    Body { op: ModOp, value: Value },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Statement {
    If {
        cond: BoolExpr,
        then: Vec<Statement>,
        /// `else then …` or `else if … then …`; the latter carries no `end if` of its own.
        otherwise: Vec<Statement>,
    },
    Report(ReportIssue),
    /// `send request` — optionally named, which binds `<name>.request` / `<name>.response`.
    SendRequest {
        called: Option<String>,
        /// A whole raw request supplied as one string, instead of modifiers.
        raw: Option<Value>,
        /// Mutations applied to the base request.
        mods: Vec<RequestMod>,
    },
    /// M3.
    SendPayload {
        called: Option<String>,
        appending: bool,
        value: Value,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Check {
    pub metadata: Metadata,
    /// `define:` — plain variables.
    pub defines: Vec<(String, Value)>,
    /// `run for each:` — the whole check body re-runs once per value. 30.7% of the corpus.
    pub for_each: Vec<(String, Vec<Value>)>,
    pub frequency: Frequency,
    pub body: Vec<Statement>,
}

impl Check {
    /// True when this check needs no outbound traffic — the M1 milestone.
    pub fn is_passive(&self) -> bool {
        self.frequency == Frequency::Response && !contains_send(&self.body)
    }

    /// True when it needs Collaborator, which caps a non-OOB milestone at ~89.8% of the corpus.
    pub fn needs_collaborator(&self) -> bool {
        fn walk(ss: &[Statement]) -> bool {
            ss.iter().any(|s| match s {
                Statement::If { cond, then, otherwise } => {
                    has_interactions(cond) || walk(then) || walk(otherwise)
                }
                _ => false,
            })
        }
        fn has_interactions(e: &BoolExpr) -> bool {
            match e {
                BoolExpr::Interactions(_) => true,
                BoolExpr::And(a, b) | BoolExpr::Or(a, b) => has_interactions(a) || has_interactions(b),
                BoolExpr::Not(a) => has_interactions(a),
                BoolExpr::Cmp { .. } => false,
            }
        }
        walk(&self.body)
            || self
                .defines
                .iter()
                .any(|(_, v)| v.raw().contains("generate_collaborator_address"))
    }

    /// True when the evaluator can run this check with a sender but no interaction server.
    ///
    /// Excludes `given insertion point` and `send payload`, which need payload placement into a
    /// specific parameter — that is M3. Recomputed here rather than derived from a headline
    /// percentage, so the number in the load report always reflects what the code actually runs.
    pub fn m2_runnable(&self) -> bool {
        !self.needs_collaborator()
            && !matches!(self.frequency, Frequency::InsertionPoint(_))
            && !contains_send_payload(&self.body)
    }
}

fn contains_send_payload(ss: &[Statement]) -> bool {
    ss.iter().any(|s| match s {
        Statement::SendPayload { .. } => true,
        Statement::If { then, otherwise, .. } => {
            contains_send_payload(then) || contains_send_payload(otherwise)
        }
        _ => false,
    })
}

fn contains_send(ss: &[Statement]) -> bool {
    ss.iter().any(|s| match s {
        Statement::SendRequest { .. } | Statement::SendPayload { .. } => true,
        Statement::If { then, otherwise, .. } => contains_send(then) || contains_send(otherwise),
        Statement::Report(_) => false,
    })
}
