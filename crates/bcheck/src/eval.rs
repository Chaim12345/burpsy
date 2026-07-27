//! BCheck evaluator.
//!
//! # Milestones
//!
//! **M1** runs `given response` checks with no outbound traffic — 105 of the 264 published checks,
//! because the secret-scanner set is pure regex over the response body.
//!
//! **M2** adds `send request`: the other four scan points (`host` 99, `request` 40, `path` 11,
//! `insertion point` 9) all mutate a base request and send it. That needs three things this module
//! provides — request mutation (via [`burpsy_core::edit::RequestEdit`]), named bindings, and the
//! builtin functions that appear inside `{…}`.
//!
//! # Semantics that are easy to get backwards
//!
//! * **`in` is containment with the needle on the LEFT**: `"secret" in {latest.response}` asks
//!   whether the response contains "secret". Corpus checks are written that way round.
//! * **`matches` takes a literal regex on the right** and never interpolates it, which is what makes
//!   `"oy2[a-z0-9]{43}"` work.
//! * **`base` and `latest` are different messages.** `base.*` is the exchange the scan started from;
//!   `latest.*` is the most recent send. While M1 had no sends they aliased, but treating them as
//!   the same message in M2 would make `differs from` compare a message to itself and never fire.
//! * **An absent binding is not an empty string.** See [`Ctx::value_opt`].
//! * **A failed send abandons the check.** Continuing would leave `{check.response.body}` absent and
//!   invite exactly the false positive the absence rules exist to prevent.

use crate::ast::*;
use crate::funcs::{self, Expr};
use burpsy_core::edit::RequestEdit;
use burpsy_core::{Direction, MsgId, StoredMessage};
use bytes::Bytes;
use regex::Regex;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};

/// Where to send a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

/// Performs the outbound request for `send request`.
///
/// A trait rather than a concrete client so the evaluator is testable without a network, and so the
/// caller owns connection reuse, timeouts and rate limiting — an audit engine must be able to put a
/// limiter in front of every send without the evaluator knowing.
pub trait Sender {
    /// Send raw request bytes, returning raw response bytes. `Err` abandons the check.
    fn send(&self, target: &Target, raw: &[u8]) -> Result<Vec<u8>, String>;
}

/// One request/response pair bound to a name.
#[derive(Debug, Clone, Default)]
struct Bound {
    request: Option<RequestEdit>,
    response: Option<StoredMessage>,
}

impl Bound {
    /// Resolve `<side>.<rest…>` within this binding.
    fn get(&self, side: &str, rest: &[&str]) -> Option<String> {
        // `<x>.response.url` describes the URL that was requested, which lives on the request.
        if rest.first() == Some(&"url") {
            return self.request.as_ref().and_then(|r| url_field(r, &rest[1..]));
        }
        match side {
            "response" => self.response.as_ref().and_then(|m| response_field(m, rest)),
            "request" => self.request.as_ref().and_then(|r| request_field(r, rest)),
            _ => None,
        }
    }
}

fn url_field(r: &RequestEdit, rest: &[&str]) -> Option<String> {
    Some(match rest.first().copied() {
        None => r.url(),
        Some("host") => host_of(r)?,
        Some("path") => r.path.clone(),
        // Java's URL.getFile(): path plus query. Both corpus uses are extension regexes.
        Some("file") => r.file(),
        Some("query") | Some("query_string") => r.query.clone(),
        Some("port") => r.header("host")?.rsplit_once(':').map(|(_, p)| p.to_string())?,
        _ => return None,
    })
}

fn host_of(r: &RequestEdit) -> Option<String> {
    if let Some(o) = &r.origin {
        // "http://host:port" -> "host"
        let after = o.split("://").nth(1).unwrap_or(o);
        return Some(after.split(':').next().unwrap_or(after).to_string());
    }
    let h = r.header("host")?;
    Some(h.split(':').next().unwrap_or(h).to_string())
}

fn request_field(r: &RequestEdit, rest: &[&str]) -> Option<String> {
    Some(match rest.first().copied() {
        None => String::from_utf8_lossy(&r.to_raw()).into_owned(),
        Some("body") => String::from_utf8_lossy(&r.body).into_owned(),
        Some("method") => r.method.clone(),
        Some("headers") => match rest.get(1) {
            Some(name) => r.header(name)?.to_string(),
            None => r
                .headers
                .iter()
                .map(|(n, v)| format!("{n}: {v}"))
                .collect::<Vec<_>>()
                .join("\r\n"),
        },
        Some("query_string") => r.query.clone(),
        Some("path") => r.path.clone(),
        _ => return None,
    })
}

fn response_field(m: &StoredMessage, rest: &[&str]) -> Option<String> {
    Some(match rest.first().copied() {
        // Whole message, headers included — what the secret scanners grep.
        None => String::from_utf8_lossy(&m.raw).into_owned(),
        Some("body") => String::from_utf8_lossy(&m.body()).into_owned(),
        Some("status_code") => m.text(m.shape.second_token),
        Some("headers") => match rest.get(1) {
            Some(name) => String::from_utf8_lossy(&m.header(name)?).into_owned(),
            None => header_block(m),
        },
        _ => return None,
    })
}

/// The raw header block, start line excluded. `{check.response.headers}` (94 corpus uses) is matched
/// against as one blob, so this must be the real bytes rather than a reconstruction.
fn header_block(m: &StoredMessage) -> String {
    let start = m.raw.iter().position(|&c| c == b'\n').map(|i| i + 1).unwrap_or(0);
    let end = m.shape.body.offset.min(m.raw.len()).max(start);
    String::from_utf8_lossy(&m.raw[start..end]).trim_end().to_string()
}

/// Wrap raw response bytes as a `StoredMessage` so a sent response resolves like a stored one.
fn as_stored_response(raw: Vec<u8>) -> Option<StoredMessage> {
    let b = Bytes::from(raw);
    let shape = burpsy_core::parse(&b, Direction::Response).ok()?;
    // Not a store entry; the id is never used for lookup.
    Some(StoredMessage { id: MsgId(u64::MAX), raw: b, shape })
}

/// What the check can see.
pub struct Ctx<'a> {
    /// `base.response` — the exchange the scan started from.
    pub response: &'a StoredMessage,
    /// `base.request`, when the caller has it. Absent for a pure M1 passive scan.
    base_request: Option<RequestEdit>,
    /// Sends performed so far, in order. The last is `latest.*`.
    sent: RefCell<Vec<(Option<String>, Bound)>>,
    /// `define:` bindings plus any `run for each` value for this iteration.
    pub vars: HashMap<String, String>,
    /// Paths a check referenced that this context could not supply.
    unresolved: RefCell<BTreeSet<String>>,
    /// `random_str` state, seeded from the message so probes are reproducible per target.
    rng: Cell<u64>,
}

impl<'a> Ctx<'a> {
    pub fn new(response: &'a StoredMessage) -> Self {
        // Seed from the response bytes: same target and body gives the same probe values, so a
        // reported finding can be re-checked, while different targets get different values.
        let mut seed = 0xcbf29ce484222325u64;
        for &b in response.raw.iter().take(512) {
            seed = (seed ^ b as u64).wrapping_mul(0x100000001b3);
        }
        Self {
            response,
            base_request: None,
            sent: RefCell::new(Vec::new()),
            vars: HashMap::new(),
            unresolved: RefCell::new(BTreeSet::new()),
            rng: Cell::new(seed | 1),
        }
    }

    /// Supply `base.request`, which the active scan points need.
    pub fn with_request(mut self, r: RequestEdit) -> Self {
        self.base_request = Some(r);
        self
    }

    pub fn with_var(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.vars.insert(k.into(), v.into());
        self
    }

    /// Same base data, fresh variable set — used per `run for each` iteration.
    ///
    /// `sent` is deliberately empty: iteration 2 must not see iteration 1's `{check.response}`.
    /// The RNG, by contrast, continues from where the parent left off and is written back after the
    /// iteration, so successive iterations draw *different* random values.
    fn rebind(&self, vars: HashMap<String, String>) -> Ctx<'a> {
        Ctx {
            response: self.response,
            base_request: self.base_request.clone(),
            sent: RefCell::new(Vec::new()),
            vars,
            unresolved: RefCell::new(BTreeSet::new()),
            rng: Cell::new(self.rng.get()),
        }
    }

    /// Paths this context was asked for and could not supply. A non-empty set means the check was
    /// written against data the engine does not expose, which is a bug to fix, not a finding.
    pub fn unresolved(&self) -> Vec<String> {
        self.unresolved.borrow().iter().cloned().collect()
    }

    /// The request a `send request` should be built from: the most recent send, else the base.
    fn latest_request(&self) -> Option<RequestEdit> {
        self.sent
            .borrow()
            .last()
            .and_then(|(_, b)| b.request.clone())
            .or_else(|| self.base_request.clone())
    }

    fn record_send(&self, name: Option<String>, request: RequestEdit, response: Option<StoredMessage>) {
        self.sent.borrow_mut().push((name, Bound { request: Some(request), response }));
    }

    /// Look up a binding by name, honouring `base` and `latest`.
    fn bound(&self, name: &str, f: &mut dyn FnMut(&Bound) -> Option<String>) -> Option<String> {
        match name {
            "base" => f(&Bound {
                request: self.base_request.clone(),
                response: Some(self.response.clone()),
            }),
            "latest" => {
                let sent = self.sent.borrow();
                match sent.last() {
                    Some((_, b)) => f(b),
                    // Before any send, `latest` is the base exchange.
                    None => f(&Bound {
                        request: self.base_request.clone(),
                        response: Some(self.response.clone()),
                    }),
                }
            }
            other => {
                let sent = self.sent.borrow();
                sent.iter().rev().find(|(n, _)| n.as_deref() == Some(other)).and_then(|(_, b)| f(b))
            }
        }
    }

    /// Resolve a dotted object path or a `define:`d variable.
    fn resolve_path(&self, p: &str) -> Option<String> {
        let p = p.trim();
        if let Some(v) = self.vars.get(p) {
            return Some(v.clone());
        }
        let mut it = p.split('.');
        let first = it.next()?;
        // Bare `response.*` / `request.*` mean the base exchange.
        let (bind, side) = match first {
            "response" | "request" => ("base", first),
            b => (b, it.next()?),
        };
        let rest: Vec<&str> = it.collect();
        self.bound(bind, &mut |b| b.get(side, &rest))
    }

    /// Evaluate the text between braces, which may be a path or a builtin call.
    fn resolve(&self, inner: &str) -> Option<String> {
        self.eval_expr(&funcs::parse_expr(inner))
    }

    fn eval_expr(&self, e: &Expr) -> Option<String> {
        match e {
            Expr::Path(p) => self.resolve_path(p),
            Expr::Str(s) => Some(s.clone()),
            Expr::Template(s) => Some(self.interpolate(s)),
            Expr::Call(name, args) => self.call(name, args),
        }
    }

    fn call(&self, name: &str, args: &[Expr]) -> Option<String> {
        match (name, args.len()) {
            ("regex_replace", 3) => {
                let subject = self.eval_expr(&args[0])?;
                let pattern = self.eval_expr(&args[1])?;
                let replacement = self.eval_expr(&args[2])?;
                // An invalid pattern yields absent rather than a panic; Java's flavour is a
                // superset of Rust's in places.
                let re = Regex::new(&pattern).ok()?;
                Some(re.replace_all(&subject, replacement.as_str()).into_owned())
            }
            ("random_str", 1) => {
                let n = self.eval_expr(&args[0])?.trim().parse::<usize>().ok()?;
                let mut st = self.rng.get();
                let s = funcs::random_str(&mut st, n);
                self.rng.set(st);
                Some(s)
            }
            ("to_lower", 1) => Some(self.eval_expr(&args[0])?.to_lowercase()),
            ("to_upper", 1) => Some(self.eval_expr(&args[0])?.to_uppercase()),
            ("base64_decode", 1) => Some(funcs::base64_decode(&self.eval_expr(&args[0])?)),
            _ => None,
        }
    }

    /// Expand `{…}` in a backtick string. `\{` escapes a brace.
    fn interpolate(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let ch: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < ch.len() {
            match ch[i] {
                // Escapes are interpreted here and *only* here — literal `"…"` strings pass through
                // verbatim so a regex keeps its `\d`, `\s`, `\w`. A backtick string is different:
                // the corpus builds wire data in one, e.g.
                // `--{boundary}\r\nContent-Disposition: form-data; …\r\n\r\nARGV\r\n`, which is a
                // multipart body. Emitting a literal backslash-r there produces a malformed body,
                // and the check then silently tests nothing.
                '\\' if i + 1 < ch.len() => {
                    match ch[i + 1] {
                        '{' => out.push('{'),
                        '}' => out.push('}'),
                        'r' => out.push('\r'),
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        '\\' => out.push('\\'),
                        // Anything else is not an escape: keep both characters, so an unrecognised
                        // sequence is passed on rather than silently eaten.
                        other => {
                            out.push('\\');
                            out.push(other);
                        }
                    }
                    i += 2;
                }
                '{' => {
                    // Match the closing brace at depth zero so a nested call survives.
                    let mut j = i + 1;
                    let mut depth = 1usize;
                    let mut name = String::new();
                    while j < ch.len() {
                        match ch[j] {
                            '{' => {
                                depth += 1;
                                name.push('{');
                            }
                            '}' => {
                                depth -= 1;
                                if depth == 0 {
                                    break;
                                }
                                name.push('}');
                            }
                            c => name.push(c),
                        }
                        j += 1;
                    }
                    if j < ch.len() {
                        // Inside message text an absent binding renders empty, matching Java, but
                        // it is still recorded so the gap is visible.
                        match self.resolve(&name) {
                            Some(v) => out.push_str(&v),
                            None => {
                                self.unresolved.borrow_mut().insert(name.trim().to_string());
                            }
                        }
                        i = j + 1;
                    } else {
                        out.push('{');
                        i += 1;
                    }
                }
                c => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        out
    }

    /// Operand value for a **comparison**. `None` means "this context cannot supply that path".
    ///
    /// The distinction is load-bearing. `str::contains("")` is `true`, so coercing an absent
    /// binding to `""` makes `{missing} in {latest.response}` fire on every response — a check
    /// that reports a vulnerability unconditionally. Fifteen corpus checks put a variable on the
    /// left of `in`, and `{check.response.body}` has 156 corpus uses, so any failed or misnamed send
    /// reaches that path. Absent operands therefore make a comparison false, never true.
    fn value_opt(&self, v: &Value) -> Option<String> {
        match v {
            // Literal strings never interpolate — this is what protects regex braces.
            Value::Literal(s) => Some(s.clone()),
            Value::Template(s) => Some(self.interpolate(s)),
            Value::Var(p) => match self.resolve(p) {
                Some(s) => Some(s),
                None => {
                    self.unresolved.borrow_mut().insert(p.trim().to_string());
                    None
                }
            },
        }
    }

    /// Value for **report text**, where an absent binding renders empty as it does in Java.
    fn value_text(&self, v: &Value) -> String {
        self.value_opt(v).unwrap_or_default()
    }
}

/// A finding produced by a check.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub check_name: String,
    pub issue_name: Option<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub detail: Option<String>,
    pub remediation: Option<String>,
}

/// Why a check could not be evaluated.
#[derive(Debug, Clone, PartialEq)]
pub enum Unsupported {
    /// Needs outbound traffic (`send request` / `send payload`).
    NeedsSending,
    /// Needs Collaborator.
    NeedsCollaborator,
    /// A scan point other than `given response`.
    NotPassive(Frequency),
    /// A regex the Rust engine rejects (Java's flavour is a superset in places).
    BadRegex(String),
}

/// Why an active run produced no verdict.
#[derive(Debug, Clone, PartialEq)]
pub enum EvalError {
    Unsupported(Unsupported),
    /// A send failed. The check is abandoned rather than continued, because continuing would leave
    /// its named bindings absent — and a check that cannot see its own probe response cannot judge.
    SendFailed(String),
    /// `send payload` needs an insertion point, which is M3.
    NeedsInsertionPoint,
}

impl From<Unsupported> for EvalError {
    fn from(u: Unsupported) -> Self {
        EvalError::Unsupported(u)
    }
}

/// Run a passive check. `Ok(findings)` — empty means the check simply did not fire.
pub fn run_passive(check: &Check, ctx: &Ctx<'_>) -> Result<Vec<Finding>, Unsupported> {
    if check.frequency != Frequency::Response {
        return Err(Unsupported::NotPassive(check.frequency.clone()));
    }
    if check.needs_collaborator() {
        return Err(Unsupported::NeedsCollaborator);
    }
    if !check.is_passive() {
        return Err(Unsupported::NeedsSending);
    }
    match run_inner(check, ctx, None, None) {
        Ok(f) => Ok(f),
        Err(EvalError::Unsupported(u)) => Err(u),
        // Unreachable for a check that passed `is_passive`, which forbids sends.
        Err(EvalError::SendFailed(_)) | Err(EvalError::NeedsInsertionPoint) => {
            Err(Unsupported::NeedsSending)
        }
    }
}

/// Run a check that may send requests.
///
/// The scan point (`given host` / `request` / `path`) decides *how often* the caller invokes this —
/// once per host, per request, per path — not how the body evaluates, so it is the caller's business.
/// `given insertion point` additionally needs payload placement and is rejected here.
pub fn run_active(
    check: &Check,
    ctx: &Ctx<'_>,
    sender: &dyn Sender,
    target: &Target,
) -> Result<Vec<Finding>, EvalError> {
    if check.needs_collaborator() {
        return Err(Unsupported::NeedsCollaborator.into());
    }
    if matches!(check.frequency, Frequency::InsertionPoint(_)) {
        return Err(EvalError::NeedsInsertionPoint);
    }
    run_inner(check, ctx, Some(sender), Some(target))
}

fn run_inner(
    check: &Check,
    ctx: &Ctx<'_>,
    sender: Option<&dyn Sender>,
    target: Option<&Target>,
) -> Result<Vec<Finding>, EvalError> {
    // `define:` bindings, then each `run for each` value in turn.
    let mut base = HashMap::new();
    for (k, v) in &check.defines {
        base.insert(k.clone(), ctx.value_text(v));
    }

    let iterations: Vec<HashMap<String, String>> = if check.for_each.is_empty() {
        vec![base.clone()]
    } else {
        let mut out = Vec::new();
        // One iteration per value of the first iterable — the corpus does not nest iterables.
        let (name, vals) = &check.for_each[0];
        for v in vals {
            let mut m = base.clone();
            m.insert(name.clone(), ctx.value_text(v));
            out.push(m);
        }
        out
    };

    let mut findings = Vec::new();
    for vars in iterations {
        let it = ctx.rebind(vars);
        let r = exec(&check.body, &it, &check.metadata.name, sender, target, &mut findings);
        // Fold each iteration's unresolved paths back into the caller's context, including on the
        // error path — a diagnostic that only exists inside a temporary is no diagnostic.
        ctx.unresolved.borrow_mut().extend(it.unresolved.borrow().iter().cloned());
        // Carry the RNG forward too. Without this every iteration restarts from the parent's seed,
        // so a cache-busting probe iterated over 30 payloads would send the same nonce 30 times.
        ctx.rng.set(it.rng.get());
        r?;
    }
    Ok(findings)
}

fn exec(
    stmts: &[Statement],
    ctx: &Ctx<'_>,
    check_name: &str,
    sender: Option<&dyn Sender>,
    target: Option<&Target>,
    out: &mut Vec<Finding>,
) -> Result<(), EvalError> {
    for s in stmts {
        match s {
            Statement::If { cond, then, otherwise } => {
                let branch = if eval_bool(cond, ctx)? { then } else { otherwise };
                exec(branch, ctx, check_name, sender, target, out)?;
            }
            Statement::Report(r) => {
                out.push(Finding {
                    check_name: check_name.to_string(),
                    issue_name: r.name.as_ref().map(|v| ctx.value_text(v)),
                    severity: r.severity,
                    confidence: r.confidence,
                    detail: r.detail.as_ref().map(|v| ctx.value_text(v)),
                    remediation: r.remediation.as_ref().map(|v| ctx.value_text(v)),
                });
                // Without `and continue`, the first report ends this check.
                if !r.and_continue {
                    return Ok(());
                }
            }
            Statement::SendRequest { called, raw, mods } => {
                let (Some(sender), Some(target)) = (sender, target) else {
                    return Err(EvalError::Unsupported(Unsupported::NeedsSending));
                };
                let req = build_request(ctx, raw.as_ref(), mods)?;
                let bytes = req.to_raw();
                match sender.send(target, &bytes) {
                    Ok(resp) => {
                        let stored = as_stored_response(resp);
                        if stored.is_none() {
                            return Err(EvalError::SendFailed("unparsable response".into()));
                        }
                        ctx.record_send(called.clone(), req, stored);
                    }
                    // Abandon rather than continue: see EvalError::SendFailed.
                    Err(e) => return Err(EvalError::SendFailed(e)),
                }
            }
            Statement::SendPayload { .. } => return Err(EvalError::NeedsInsertionPoint),
        }
    }
    Ok(())
}

/// Build the request a `send request` should issue.
///
/// Modifiers apply to the most recent request in the chain, so a second send inside the same check
/// builds on the first — which is what the follow-up probes in the corpus assume.
fn build_request(
    ctx: &Ctx<'_>,
    raw: Option<&Value>,
    mods: &[RequestMod],
) -> Result<RequestEdit, EvalError> {
    if let Some(v) = raw {
        let text = ctx.value_text(v);
        return RequestEdit::from_raw(text.as_bytes())
            .map_err(|e| EvalError::SendFailed(format!("raw request: {e}")));
    }
    let mut r = ctx
        .latest_request()
        .ok_or_else(|| EvalError::SendFailed("no base request to modify".into()))?;

    for m in mods {
        match m {
            RequestMod::Method(v) => r.method = ctx.value_text(v),
            RequestMod::Path { op, value } => {
                let v = ctx.value_text(value);
                match op {
                    ModOp::Replace => {
                        // Replacing the path leaves the query string in place. The evidence is
                        // PortSwigger's own grammar: `path` and `query_string` are separate modifier
                        // targets, so they name independent components of the request. This is an
                        // inference from the grammar, not something verified against Burp at
                        // runtime — a check that wants both writes them both, or embeds a `?`.
                        //
                        // A replacement may carry its own query string.
                        match v.split_once('?') {
                            Some((p, q)) => {
                                r.path = p.to_string();
                                r.query = q.to_string();
                            }
                            None => r.path = v,
                        }
                    }
                    ModOp::Append => {
                        // Corpus values are written both with and without a leading slash.
                        let joined = match (r.path.ends_with('/'), v.starts_with('/')) {
                            (true, true) => format!("{}{}", r.path, &v[1..]),
                            (false, false) => format!("{}/{}", r.path, v),
                            _ => format!("{}{}", r.path, v),
                        };
                        r.path = joined;
                    }
                }
            }
            RequestMod::QueryString(v) => r.query = ctx.value_text(v).trim_start_matches('?').to_string(),
            RequestMod::Queries(vs) => {
                for v in vs {
                    r.add_query(&ctx.value_text(v));
                }
            }
            RequestMod::Headers { op, pairs } => {
                for (name, value) in pairs {
                    let n = ctx.value_text(name);
                    let v = ctx.value_text(value);
                    // An empty value marks the whole-line form: `"X-Foo: bar"`.
                    let (n, v) = if v.is_empty() {
                        match n.split_once(':') {
                            Some((a, b)) => (a.trim().to_string(), b.trim().to_string()),
                            None => (n, v),
                        }
                    } else {
                        (n, v)
                    };
                    if n.is_empty() {
                        continue;
                    }
                    match op {
                        ModOp::Replace => r.set_header(&n, &v),
                        ModOp::Append => r.add_header(&n, &v),
                    }
                }
            }
            RequestMod::Body { op, value } => {
                let v = ctx.value_text(value);
                match op {
                    ModOp::Replace => r.body = v.into_bytes(),
                    ModOp::Append => r.body.extend_from_slice(v.as_bytes()),
                }
            }
        }
    }
    Ok(r)
}

fn eval_bool(e: &BoolExpr, ctx: &Ctx<'_>) -> Result<bool, EvalError> {
    Ok(match e {
        BoolExpr::And(a, b) => eval_bool(a, ctx)? && eval_bool(b, ctx)?,
        BoolExpr::Or(a, b) => eval_bool(a, ctx)? || eval_bool(b, ctx)?,
        BoolExpr::Not(a) => !eval_bool(a, ctx)?,
        BoolExpr::Interactions(_) => {
            return Err(EvalError::Unsupported(Unsupported::NeedsCollaborator));
        }
        BoolExpr::Cmp { lhs, op, rhs } => {
            // An operand this context cannot supply makes the comparison false. It can never make
            // it true: absence is not evidence.
            let Some(l) = ctx.value_opt(lhs) else { return Ok(false) };
            match op {
                CmpOp::Matches => {
                    // RHS is always a literal, never interpolated.
                    let pat = rhs.raw();
                    let re = Regex::new(pat)
                        .map_err(|_| EvalError::Unsupported(Unsupported::BadRegex(pat.to_string())))?;
                    re.is_match(&l)
                }
                // Containment, needle on the left — the way the corpus writes it.
                CmpOp::In => {
                    let Some(r) = ctx.value_opt(rhs) else { return Ok(false) };
                    r.contains(&l)
                }
                CmpOp::Is => ctx.value_opt(rhs).is_some_and(|r| l == r),
                // Absent must not read as "differs" — that would report on a missing binding.
                CmpOp::DiffersFrom => ctx.value_opt(rhs).is_some_and(|r| l != r),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;
    use burpsy_core::{Direction, TrafficStore};
    use bytes::Bytes;

    /// Parse a check source, supplying the mandatory `metadata:` block.
    fn parse_check(body: &str) -> Check {
        let src = format!("metadata:\n  language: v2-beta\n  name: \"t\"\n{body}");
        crate::parse(&src).unwrap_or_else(|e| panic!("should parse: {e}\n--- src ---\n{src}"))
    }

    fn resp(raw: &'static [u8]) -> StoredMessage {
        let s = TrafficStore::new();
        let id = s.put(Bytes::from_static(raw), Direction::Response);
        s.get(id).unwrap()
    }

    const NUGET: &str = r#"
metadata:
  language: v1-beta
  name: "NuGet API Key"
given response then
  if {latest.response} matches "oy2[a-z0-9]{43}" then
      report issue:
          severity: info
          confidence: tentative
          detail: "NuGet API key found in page."
  end if
"#;

    #[test]
    fn secret_scanner_fires_on_a_match() {
        let key: String = std::iter::once("oy2").chain(std::iter::repeat_n("a", 43)).collect();
        let body = format!("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nkey={key}");
        let m = {
            let s = TrafficStore::new();
            let id = s.put(Bytes::from(body), Direction::Response);
            s.get(id).unwrap()
        };
        let c = parse(NUGET).unwrap();
        let f = run_passive(&c, &Ctx::new(&m)).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].check_name, "NuGet API Key");
        assert_eq!(f[0].detail.as_deref(), Some("NuGet API key found in page."));
    }

    #[test]
    fn secret_scanner_stays_quiet_otherwise() {
        let m = resp(b"HTTP/1.1 200 OK\r\n\r\nnothing interesting here");
        let c = parse(NUGET).unwrap();
        assert!(run_passive(&c, &Ctx::new(&m)).unwrap().is_empty());
    }

    #[test]
    fn in_is_containment_with_needle_on_the_left() {
        let m = resp(b"HTTP/1.1 200 OK\r\nServer: nginx/1.2\r\n\r\nbody");
        let src = r#"metadata: name: "srv" given response then if "nginx" in {latest.response} then report issue: severity: low confidence: firm end if"#;
        let c = parse(src).unwrap();
        assert_eq!(run_passive(&c, &Ctx::new(&m)).unwrap().len(), 1);
    }

    #[test]
    fn header_lookup_and_status_code() {
        let m = resp(b"HTTP/1.1 403 Forbidden\r\nX-Flag: yes\r\n\r\nnope");
        let src = r#"metadata: name: "h" given response then if {latest.response.headers.X-Flag} is "yes" and {latest.response.status_code} is "403" then report issue: severity: info confidence: certain end if"#;
        let c = parse(src).unwrap();
        assert_eq!(run_passive(&c, &Ctx::new(&m)).unwrap().len(), 1);
    }

    #[test]
    fn backtick_interpolation_in_detail() {
        let m = resp(b"HTTP/1.1 500 Err\r\n\r\nboom");
        let src = r#"metadata: name: "i" given response then if "boom" in {latest.response} then report issue: severity: high confidence: firm detail: `status was {latest.response.status_code}` end if"#;
        let c = parse(src).unwrap();
        let f = run_passive(&c, &Ctx::new(&m)).unwrap();
        assert_eq!(f[0].detail.as_deref(), Some("status was 500"));
    }

    #[test]
    fn and_continue_produces_multiple_findings() {
        let m = resp(b"HTTP/1.1 200 OK\r\n\r\naaa bbb");
        let src = r#"metadata: name: "m" given response then if "aaa" in {latest.response} then report issue and continue: severity: low confidence: firm end if if "bbb" in {latest.response} then report issue: severity: high confidence: firm end if"#;
        let c = parse(src).unwrap();
        assert_eq!(run_passive(&c, &Ctx::new(&m)).unwrap().len(), 2);
    }

    #[test]
    fn run_for_each_iterates_the_body() {
        let m = resp(b"HTTP/1.1 200 OK\r\n\r\nfound .bak and .old");
        let src = r#"metadata: name: "fe"
run for each:
  ext = ".bak", ".zip", ".old"
given response then
  if {ext} in {latest.response} then report issue and continue: severity: low confidence: firm detail: `saw {ext}` end if"#;
        let c = parse(src).unwrap();
        let f = run_passive(&c, &Ctx::new(&m)).unwrap();
        // .bak and .old are present, .zip is not.
        assert_eq!(f.len(), 2, "got {f:?}");
        assert_eq!(f[0].detail.as_deref(), Some("saw .bak"));
        assert_eq!(f[1].detail.as_deref(), Some("saw .old"));
    }

    // ---- gaps the advisor flagged that the earlier tests passed over --------------------

    #[test]
    fn the_header_block_of_a_bodiless_response_is_not_empty() {
        // `{x.response.headers}` has 94 corpus uses. A 204 has headers but no body, so if the block
        // were derived wrongly it would resolve to Some("") — which the absence guard cannot catch,
        // because an empty string is present. That makes it a silent miss, not a false positive.
        let check = parse_check(
            r#"given host then
                 send request called probe:
                   path: "/x"
                 if "X-Marker" in {probe.response.headers} then
                   report issue:
                     severity: info
                     confidence: certain
                 end if"#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(
            b"HTTP/1.1 204 No Content\r\nX-Marker: yes\r\nServer: t\r\n\r\n".to_vec(),
        )]);
        let f = run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        assert_eq!(f.len(), 1, "a 204's headers must still be searchable");
    }

    #[test]
    fn each_run_for_each_iteration_draws_a_different_random_value() {
        // The bug: `rebind` copied the parent's RNG, which never advanced, so all iterations sent
        // the same nonce. A cache-busting probe that repeats one value is not cache-busting.
        let check = parse_check(
            r#"run for each:
                 suffix = "a", "b", "c"

               given host then
                 send request:
                   appending path: `{random_str(8)}{suffix}`"#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![
            Ok(MockSender::ok("1")),
            Ok(MockSender::ok("2")),
            Ok(MockSender::ok("3")),
        ]);
        run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        let sent = m.sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 3);
        let nonces: Vec<&str> = sent
            .iter()
            .map(|s| s.split_whitespace().nth(1).unwrap_or(""))
            .collect();
        assert_ne!(nonces[0], nonces[1], "iterations 1 and 2 reused a nonce: {nonces:?}");
        assert_ne!(nonces[1], nonces[2], "iterations 2 and 3 reused a nonce: {nonces:?}");
    }

    #[test]
    fn crlf_escapes_in_a_backtick_string_become_real_bytes() {
        // The corpus builds a multipart body this way. Literal backslash-r would make it malformed,
        // so the check would send something no server parses and quietly find nothing.
        let check = parse_check(
            r#"given host then
                 send request:
                   method: "POST"
                   replacing body: `--B\r\nContent-Disposition: form-data; name="f"\r\n\r\nARGV\r\n`"#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("x"))]);
        run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        let sent = m.first();
        assert!(sent.contains("--B\r\nContent-Disposition"), "escapes not decoded: {sent:?}");
        assert!(!sent.contains("\\r\\n"), "literal backslash-r survived: {sent:?}");
        // The length must match the decoded body, not the longer escaped text. Split only at the
        // FIRST blank line: a multipart body contains `\r\n\r\n` itself.
        let body = sent.splitn(2, "\r\n\r\n").nth(1).unwrap_or("");
        assert_eq!(body.len(), 55, "decoded body length");
        assert!(sent.contains("Content-Length: 55"), "sent: {sent:?}");
    }

    #[test]
    fn regex_escapes_in_a_literal_string_are_left_alone() {
        // The other half of the rule: literal strings must not be escape-processed, or every
        // secret-scanner regex loses its character classes.
        let check = parse_check(
            r#"given response then
                 if {latest.response.body} matches "a\tb" then
                   report issue:
                     severity: info
                     confidence: certain
                 end if"#,
        );
        // A real tab must match the regex `\t`; the pattern itself stays as backslash-t.
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\na\tb");
        assert_eq!(run_passive(&check, &Ctx::new(&base)).unwrap().len(), 1);
    }

    #[test]
    fn a_raw_string_send_still_goes_to_the_scoped_target() {
        // The one bug in this crate that would matter outside the tool: a check must not be able to
        // steer traffic to a host the operator did not authorise. The request bytes are the check's
        // to choose; the *connection* is not, so the Host header here must not redirect the send.
        let check = parse_check(
            "given host then\n send request: `GET /x HTTP/1.1\\r\\nHost: evil.example\\r\\n\\r\\n`",
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        /// Records the target it was handed, not just the bytes.
        struct TargetSpy(std::sync::Mutex<Vec<Target>>);
        impl Sender for TargetSpy {
            fn send(&self, t: &Target, _raw: &[u8]) -> Result<Vec<u8>, String> {
                self.0.lock().unwrap().push(t.clone());
                Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec())
            }
        }
        let spy = TargetSpy(std::sync::Mutex::new(Vec::new()));
        run_active(&check, &active_ctx(&base), &spy, &tgt()).unwrap();
        let seen = spy.0.lock().unwrap().clone();
        assert_eq!(seen, vec![tgt()], "the send must go to the scoped target, not the Host header");
    }

    // ---- M2: sending ----------------------------------------------------------------------
    //
    // Every assertion here inspects the bytes the sender actually received. A test that only proves
    // "the send did not error" would pass even if all 381 modifier clauses were still discarded.

    /// Records what it was asked to send and replays canned responses in order.
    struct MockSender {
        sent: std::sync::Mutex<Vec<String>>,
        replies: std::sync::Mutex<std::collections::VecDeque<Result<Vec<u8>, String>>>,
    }

    impl MockSender {
        fn new(replies: Vec<Result<Vec<u8>, String>>) -> Self {
            Self {
                sent: std::sync::Mutex::new(Vec::new()),
                replies: std::sync::Mutex::new(replies.into()),
            }
        }
        fn ok(body: &str) -> Vec<u8> {
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
        }
        fn with_status(code: &str, body: &str) -> Vec<u8> {
            format!(
                "HTTP/1.1 {code} X\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes()
        }
        fn first(&self) -> String {
            self.sent.lock().unwrap().first().cloned().unwrap_or_default()
        }
        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    impl Sender for MockSender {
        fn send(&self, _t: &Target, raw: &[u8]) -> Result<Vec<u8>, String> {
            self.sent.lock().unwrap().push(String::from_utf8_lossy(raw).into_owned());
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(MockSender::ok("default")))
        }
    }

    fn tgt() -> Target {
        Target { host: "x.test".into(), port: 80, tls: false }
    }

    fn base_req() -> RequestEdit {
        RequestEdit::from_raw(b"GET /orig?a=1 HTTP/1.1\r\nHost: x.test\r\nAccept: */*\r\n\r\n").unwrap()
    }

    /// Build a ctx with a base request, as an active scan point would.
    fn active_ctx(r: &StoredMessage) -> Ctx<'_> {
        Ctx::new(r).with_request(base_req())
    }

    #[test]
    fn replacing_path_reaches_the_wire() {
        let check = parse_check(
            r#"given host then
                 send request called probe:
                   path: "/admin"
                 if {probe.response.status_code} is "200" then
                   report issue:
                     severity: high
                     confidence: certain
                 end if"#,
        );
        let base = resp(b"HTTP/1.1 404 NF\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("admin page"))]);
        let ctx = active_ctx(&base);
        let f = run_active(&check, &ctx, &m, &tgt()).unwrap();
        // The query survives: `path` and `query_string` are separate modifier targets, so replacing
        // one leaves the other alone. See `RequestMod::Path` for why that reading was chosen.
        assert!(m.first().starts_with("GET /admin?a=1 HTTP/1.1"), "sent: {:?}", m.first());
        assert_eq!(f.len(), 1, "the 200 reply should report");
    }

    #[test]
    fn a_path_replacement_containing_a_question_mark_sets_both_components() {
        let check = parse_check(
            "given host then\n send request:\n  path: \"/new?z=9\"",
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("x"))]);
        run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        assert!(m.first().starts_with("GET /new?z=9 "), "sent: {:?}", m.first());
    }

    #[test]
    fn appending_path_joins_with_exactly_one_slash() {
        let check = parse_check(
            "given path then\n send request:\n  appending path: \"sub\"",
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("x"))]);
        run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        assert!(m.first().starts_with("GET /orig/sub?a=1 "), "sent: {:?}", m.first());
    }

    #[test]
    fn appending_queries_uses_ampersand_when_a_query_exists() {
        let check = parse_check(
            "given request then\n send request:\n  appending queries: `p=1`, `q=2`",
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("x"))]);
        run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        assert!(m.first().starts_with("GET /orig?a=1&p=1&q=2 "), "sent: {:?}", m.first());
    }

    #[test]
    fn replacing_headers_sets_the_header_and_fixes_content_length() {
        let check = parse_check(
            r#"given host then
                 send request:
                   method: "POST"
                   replacing headers:
                     "Content-Type": "application/json",
                     "X-Probe": "yes"
                   body: "{\"a\":1}""#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("x"))]);
        run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        let sent = m.first();
        assert!(sent.starts_with("POST /orig?a=1 "), "method not applied: {sent:?}");
        assert!(sent.contains("Content-Type: application/json"), "sent: {sent:?}");
        assert!(sent.contains("X-Probe: yes"), "sent: {sent:?}");
        // 7 bytes of body; a stale or missing length would truncate the probe server-side.
        assert!(sent.contains("Content-Length: 7"), "sent: {sent:?}");
        assert!(sent.ends_with("{\"a\":1}"), "sent: {sent:?}");
    }

    #[test]
    fn base_and_latest_are_different_messages_after_a_send() {
        // If these aliased, `differs from` would compare a message to itself and never fire.
        let check = parse_check(
            r#"given host then
                 send request:
                   path: "/probe"
                 if {latest.response.status_code} differs from {base.response.status_code} then
                   report issue:
                     severity: medium
                     confidence: firm
                 end if"#,
        );
        let base = resp(b"HTTP/1.1 404 NF\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::with_status("500", "boom"))]);
        let f = run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        assert_eq!(f.len(), 1, "500 from the send differs from the base 404");
    }

    #[test]
    fn a_named_binding_resolves_to_its_own_response() {
        let check = parse_check(
            r#"given host then
                 send request called first:
                   path: "/one"
                 send request called second:
                   path: "/two"
                 if "alpha" in {first.response.body} and "beta" in {second.response.body} then
                   report issue:
                     severity: low
                     confidence: certain
                 end if"#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![
            Ok(MockSender::ok("alpha")),
            Ok(MockSender::ok("beta")),
        ]);
        let f = run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        assert_eq!(m.count(), 2);
        assert_eq!(f.len(), 1, "each name must see its own response");
    }

    #[test]
    fn a_failed_send_abandons_the_check_instead_of_reporting() {
        // The false-positive path: if the check continued, `{probe.response.body}` would be absent
        // and a containment test against it must not be allowed to decide anything.
        let check = parse_check(
            r#"given host then
                 send request called probe:
                   path: "/admin"
                 if "x" in {probe.response.body} then
                   report issue:
                     severity: high
                     confidence: certain
                 end if"#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Err("connection refused".into())]);
        let e = run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap_err();
        assert_eq!(e, EvalError::SendFailed("connection refused".into()));
    }

    #[test]
    fn a_misnamed_binding_produces_no_finding() {
        // `{typo.response.body}` is absent; the containment must not fire.
        let check = parse_check(
            r#"given host then
                 send request called probe:
                   path: "/a"
                 if "anything" in {typo.response.body} then
                   report issue:
                     severity: high
                     confidence: certain
                 end if"#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("anything"))]);
        let ctx = active_ctx(&base);
        assert_eq!(run_active(&check, &ctx, &m, &tgt()).unwrap(), vec![]);
        assert!(
            ctx.unresolved().iter().any(|u| u.contains("typo")),
            "the typo should be reported as unresolved, got {:?}",
            ctx.unresolved()
        );
    }

    #[test]
    fn regex_replace_inside_a_path_modifier_is_evaluated() {
        // The corpus shape: strip the last path segment, then append a probe path.
        let check = parse_check(
            r#"given host then
                 send request:
                   replacing path: `{regex_replace({base.request.url.path}, "([^/]+)$", "")}probe`"#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("x"))]);
        run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        assert!(m.first().starts_with("GET /probe?a=1 "), "sent: {:?}", m.first());
    }

    #[test]
    fn a_second_send_builds_on_the_first() {
        let check = parse_check(
            r#"given host then
                 send request:
                   appending queries: `p=1`
                 send request:
                   appending queries: `q=2`"#,
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("a")), Ok(MockSender::ok("b"))]);
        run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap();
        let all = m.sent.lock().unwrap().clone();
        assert!(all[0].starts_with("GET /orig?a=1&p=1 "), "first: {:?}", all[0]);
        assert!(all[1].starts_with("GET /orig?a=1&p=1&q=2 "), "second: {:?}", all[1]);
    }

    #[test]
    fn an_active_check_needs_a_base_request() {
        // Without one there is nothing to mutate, and silently sending a fabricated request would
        // test something the user never asked about.
        let check = parse_check("given host then\n send request:\n  path: \"/a\"");
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![Ok(MockSender::ok("x"))]);
        let e = run_active(&check, &Ctx::new(&base), &m, &tgt()).unwrap_err();
        assert!(matches!(e, EvalError::SendFailed(_)), "got {e:?}");
        assert_eq!(m.count(), 0, "nothing should have been sent");
    }

    #[test]
    fn insertion_point_checks_are_deferred_not_run() {
        let check = parse_check(
            "given insertion point then\n send payload:\n  appending: \"'\"",
        );
        let base = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let m = MockSender::new(vec![]);
        assert_eq!(
            run_active(&check, &active_ctx(&base), &m, &tgt()).unwrap_err(),
            EvalError::NeedsInsertionPoint
        );
    }

    // ---- absent bindings must never read as evidence -------------------------------------
    //
    // These pin the hazard that `str::contains("")` is `true`: coercing an unresolvable path to the
    // empty string turns `{missing} in {latest.response}` into an unconditional report.

    fn cmp_check(lhs: Value, op: CmpOp, rhs: Value) -> Check {
        Check {
            metadata: Metadata { name: "absence probe".into(), ..Default::default() },
            defines: vec![],
            for_each: vec![],
            frequency: Frequency::Response,
            body: vec![Statement::If {
                cond: BoolExpr::Cmp { lhs, op, rhs },
                then: vec![Statement::Report(ReportIssue {
                    name: None,
                    severity: Severity::High,
                    confidence: Confidence::Certain,
                    detail: None,
                    remediation: None,
                    and_continue: false,
                })],
                otherwise: vec![],
            }],
        }
    }

    #[test]
    fn an_absent_needle_does_not_fire_containment() {
        // The regression: `{no.such.path} in {latest.response}` used to report on every response,
        // because the absent path became "" and every string contains "".
        let r = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nclean");
        let c = cmp_check(
            Value::Var("no.such.path".into()),
            CmpOp::In,
            Value::Var("latest.response".into()),
        );
        let ctx = Ctx::new(&r);
        assert_eq!(run_passive(&c, &ctx).unwrap(), vec![], "absent needle must not report");
        assert_eq!(ctx.unresolved(), vec!["no.such.path".to_string()], "gap must be recorded");
    }

    #[test]
    fn an_absent_haystack_does_not_fire_containment() {
        let r = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nclean");
        let c = cmp_check(
            Value::Literal("clean".into()),
            CmpOp::In,
            Value::Var("check.response.body".into()),
        );
        assert_eq!(run_passive(&c, &Ctx::new(&r)).unwrap(), vec![]);
    }

    #[test]
    fn an_absent_operand_does_not_fire_is_or_differs_from() {
        // `differs from` is the subtle one: absent must not count as "different".
        let r = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nclean");
        for op in [CmpOp::Is, CmpOp::DiffersFrom] {
            let c = cmp_check(
                Value::Literal("x".into()),
                op,
                Value::Var("check.response.body".into()),
            );
            assert_eq!(run_passive(&c, &Ctx::new(&r)).unwrap(), vec![], "{op:?} fired on absence");
        }
    }

    #[test]
    fn a_present_binding_still_fires_normally() {
        // Guard against over-correcting: the fix must not suppress real matches.
        let r = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret");
        let c = cmp_check(
            Value::Literal("secret".into()),
            CmpOp::In,
            Value::Var("latest.response".into()),
        );
        assert_eq!(run_passive(&c, &Ctx::new(&r)).unwrap().len(), 1);
    }

    #[test]
    fn absent_bindings_render_empty_in_report_text() {
        // Report text keeps Java's behaviour — an absent path renders as nothing, not "None".
        let r = resp(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret");
        let mut c = cmp_check(
            Value::Literal("secret".into()),
            CmpOp::In,
            Value::Var("latest.response".into()),
        );
        if let Statement::If { then, .. } = &mut c.body[0] {
            if let Statement::Report(r) = &mut then[0] {
                r.detail = Some(Value::Template("saw [{nope}] here".into()));
            }
        }
        let f = run_passive(&c, &Ctx::new(&r)).unwrap();
        assert_eq!(f[0].detail.as_deref(), Some("saw [] here"));
    }

    #[test]
    fn non_passive_checks_are_reported_not_run() {
        let m = resp(b"HTTP/1.1 200 OK\r\n\r\nx");
        let src = r#"metadata: name: "active" given host then if "x" in {latest.response} then report issue: severity: low confidence: firm end if"#;
        let c = parse(src).unwrap();
        assert!(matches!(
            run_passive(&c, &Ctx::new(&m)),
            Err(Unsupported::NotPassive(Frequency::Host))
        ));
    }

    #[test]
    fn collaborator_checks_are_reported_not_run() {
        let m = resp(b"HTTP/1.1 200 OK\r\n\r\nx");
        let src = r#"metadata: name: "oob" given response then if dns interactions then report issue: severity: high confidence: certain end if"#;
        let c = parse(src).unwrap();
        assert!(matches!(
            run_passive(&c, &Ctx::new(&m)),
            Err(Unsupported::NeedsCollaborator)
        ));
    }
}
