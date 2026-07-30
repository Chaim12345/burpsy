//! Interception: hold a message, let an operator rewrite it, then forward or drop.
//!
//! # The switch is a rule engine, not a valve
//!
//! Interception has three layers, and all three have to say yes before anything is held:
//!
//! 1. The master switch, [`Interceptor::set_enabled`]. One atomic bool.
//! 2. The direction's list being active at all — [`InterceptRulesSpec::active`], Burp's "intercept
//!    requests / responses based on the following rules" checkbox.
//! 3. At least one enabled condition in that direction's list matching the message.
//!
//! Layer 3 has one deliberate hole: **an active list with no conditions at all matches everything.**
//! That is not a special case bolted on for compatibility, it is what "the operator has expressed no
//! condition" means — the master switch alone governs, which is exactly what this module did before
//! conditions existed.
//!
//! The hole is keyed on the list being *empty*, not on nothing in it being *enabled*, and the
//! difference is the whole safety argument. Unchecking the last box in a list of five holds nothing,
//! because no enabled condition matched — the same sentence as any other non-match. Had it instead
//! fallen back to blanket, unchecking one box would have started holding **every response**, which for
//! a browser is indistinguishable from the proxy having broken. Deleting every row is the unambiguous
//! way to say "everything"; unchecking rows is not, so it does not mean that.
//!
//! The two lists' *defaults* differ, and the difference is behavioural, not cosmetic:
//!
//! | list | default | why |
//! |------|---------|-----|
//! | requests | active, no conditions | blanket holding when the master switch is on — what burpsy has always done |
//! | responses | inactive | burpsy has never held a response; switching the master on must not suddenly start |
//!
//! # The rule model is a gate, not a rewriter
//!
//! [`InterceptRule`] deliberately does *not* reuse `burpsy_tools::matchreplace::RuleSpec`. That type
//! rewrites bytes and its taxonomy is about *where in a message* to substitute; this one answers a
//! yes/no question about *whether a message is interesting*, and its taxonomy is Burp's intercept
//! match-type list ([`MatchField`]). Sharing a type between the two would mean one of them carrying
//! fields the other must be documented to ignore.
//!
//! What is mirrored, on purpose, is the compilation invariant: fields are private, [`InterceptRule::new`]
//! is the only constructor, and `Deserialize` goes through it. There is no path from a pattern string
//! to a held message that skips compilation, so a malformed regex is a `PUT` error rather than a
//! per-message one on the proxy's hot path. Rust's `regex` has no backtracking, so an operator's own
//! pattern cannot turn matching into a denial of service.
//!
//! # What conditions must not touch: the ALPN decision
//!
//! [`Interceptor::is_enabled`] answers exactly one other question in this crate — whether the MITM
//! path offers the client `http/1.1` only (see the crate docs on h2). That decision is made from the
//! ClientHello, **before any request exists to match a condition against**, so it can only ever be
//! keyed on the master switch. Conditions therefore narrow *what is held*, never *what is offered*:
//! an operator whose rules match one host still pays the h2 downgrade on every host, because the
//! handshake cannot know which host the first request will name. `is_enabled()` is left as a bare
//! atomic load for that reason, and there is a test asserting rules do not move it.
//!
//! # Why a oneshot per held request rather than a shared "resume" flag
//!
//! The property that matters is that holding one request must not stall anything else. A single
//! gate — one mutex, one condvar, one "paused" boolean — makes every connection wait on the same
//! thing, so inspecting one request freezes the browser. Instead each held request parks *its own*
//! connection task on *its own* [`oneshot`] receiver. Nothing else in the process is touched: other
//! connections are separate tasks that never look at this queue, and the queue mutex is only ever
//! held long enough to insert or remove a map entry, never across an `await`.
//!
//! (`parking_lot::MutexGuard` is `!Send`, so "never across an await" is enforced by the compiler
//! rather than by discipline.)
//!
//! # Why the store write happens after the verdict, not before
//!
//! An operator who edits a request needs history to show what was actually sent — a history that
//! records the pre-edit bytes is worse than useless, because every later replay and every scan
//! would work from a request that never left the machine. The store has no "amend this message"
//! operation by design (messages are immutable so spans into them stay valid forever), so the only
//! way to record the truth is to decide first and store second.
//!
//! The consequence, stated plainly: **a held request does not appear in `/api/history` until it is
//! forwarded or dropped.** While held it is visible only through the interception queue. That is the
//! same split Burp presents, and it is the price of never lying about what was sent.
//!
//! # Fail-open, deliberately
//!
//! If the resume channel is dropped without a verdict — the only way that happens is the whole
//! queue being torn down — [`Interceptor::hold`] forwards the original message rather than hanging
//! the client. A proxy that silently strands connections is indistinguishable from a network fault.
//! The same applies to a held response: the client gets the origin's real answer, late, rather than
//! nothing at all.

use crate::{header_value, parse_status};
use burpsy_core::Direction;
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::oneshot;

/// Which fact about a message a condition tests.
///
/// Burp's intercept match-type list, minus the two burpsy has nothing to feed them: "IP address"
/// (the proxy resolves a hostname, it never receives a client-supplied literal to test) and
/// "listener port" (there is one listener, so the condition would be a constant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchField {
    /// The host the request is addressed to, without the port.
    Host,
    /// The request target, query string included.
    Path,
    /// The path's file extension without the dot, or the empty string when it has none — so `^$`
    /// is how an operator asks for extensionless paths.
    Extension,
    Method,
    /// `scheme://host[:port]/path`, with the port omitted when it is the scheme's default. For
    /// conditions that want to straddle the parts above.
    Url,
    /// Responses only. On a request there is no status yet, so a condition on this can never hold
    /// one — see [`InterceptRules::matches`].
    StatusCode,
    /// The held message's own `Content-Type`, absent when it declares none.
    ContentType,
}

/// How `string_match` is read. The same two-value taxonomy as match-and-replace's `category`, and
/// literal means the same thing there as here: match the text, anywhere in the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchCategory {
    #[default]
    Regex,
    Literal,
}

fn enabled_by_default() -> bool {
    true
}

/// The serialisable form of one condition. Inert: holding one proves nothing has been compiled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptRuleSpec {
    pub field: MatchField,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// The condition. Empty is refused rather than treated as "matches everything": an empty list
    /// already says that, and said as a rule it would hide among five that look specific.
    #[serde(default)]
    pub string_match: String,
    #[serde(default)]
    pub category: MatchCategory,
    /// The operator's label for the rule. Burp calls it a comment.
    #[serde(default)]
    pub comment: String,
}

impl InterceptRuleSpec {
    /// A regex condition over `field`.
    pub fn new(field: MatchField, pattern: impl Into<String>) -> Self {
        Self {
            field,
            enabled: true,
            string_match: pattern.into(),
            category: MatchCategory::Regex,
            comment: String::new(),
        }
    }

    pub fn literal(mut self) -> Self {
        self.category = MatchCategory::Literal;
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn with_comment(mut self, c: impl Into<String>) -> Self {
        self.comment = c.into();
        self
    }
}

/// A rejected condition, named so the operator can find it in their own list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    /// The rule's comment, or its pattern when it has no comment.
    pub rule: String,
    pub message: String,
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "intercept rule {:?}: {}", self.rule, self.message)
    }
}

impl std::error::Error for RuleError {}

/// A compiled, runnable condition. Construction is the only way in, and construction compiles.
#[derive(Debug, Clone)]
pub struct InterceptRule {
    spec: InterceptRuleSpec,
    re: Regex,
}

impl InterceptRule {
    /// Compile a condition. Every error a pattern can cause surfaces here, once, at config time.
    pub fn new(spec: InterceptRuleSpec) -> Result<Self, RuleError> {
        let label = if spec.comment.is_empty() {
            spec.string_match.clone()
        } else {
            spec.comment.clone()
        };
        let err = |m: &str| RuleError {
            rule: label.clone(),
            message: m.to_string(),
        };
        if spec.string_match.is_empty() {
            return Err(err(
                "an empty condition matches every message; a list with no conditions already means \
                 that, so say it that way instead",
            ));
        }
        let pattern = match spec.category {
            MatchCategory::Regex => spec.string_match.clone(),
            MatchCategory::Literal => regex::escape(&spec.string_match),
        };
        let re = Regex::new(&pattern).map_err(|e| err(&e.to_string()))?;
        Ok(Self { spec, re })
    }

    pub fn spec(&self) -> &InterceptRuleSpec {
        &self.spec
    }

    pub fn field(&self) -> MatchField {
        self.spec.field
    }

    pub fn enabled(&self) -> bool {
        self.spec.enabled
    }

    pub fn comment(&self) -> &str {
        &self.spec.comment
    }

    /// Test this condition. `None` means the field it names is not knowable from `f` — a status-code
    /// condition against a request, say. That is a different answer from "did not match", and the
    /// two callers of this want different things done about it, so it is not collapsed here.
    fn test(&self, f: &Facts) -> Option<bool> {
        Some(self.re.is_match(&f.value(self.spec.field)?))
    }
}

impl TryFrom<InterceptRuleSpec> for InterceptRule {
    type Error = RuleError;
    fn try_from(spec: InterceptRuleSpec) -> Result<Self, Self::Error> {
        InterceptRule::new(spec)
    }
}

// The whole point: even the deserialisation path compiles. There is no way to obtain an
// `InterceptRule` whose pattern has not been through `InterceptRule::new`.
impl<'de> Deserialize<'de> for InterceptRule {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let spec = InterceptRuleSpec::deserialize(d)?;
        InterceptRule::new(spec).map_err(serde::de::Error::custom)
    }
}

impl Serialize for InterceptRule {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.spec.serialize(s)
    }
}

/// Everything an intercept condition can test about the message being offered.
///
/// The two response-derived fields are `Option` so a condition on them can be told apart from a
/// condition that genuinely failed — the distinction [`InterceptRules::could_match`] runs on.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
    /// Responses only.
    pub status: Option<u16>,
    /// The offered message's own `Content-Type`.
    pub content_type: Option<String>,
}

impl Facts {
    /// What the route alone establishes: everything judgeable before the message is in hand.
    pub fn route(meta: &HeldMeta) -> Self {
        Self {
            host: meta.host.clone(),
            port: meta.port,
            tls: meta.tls,
            method: meta.method.clone(),
            path: meta.path.clone(),
            status: None,
            content_type: None,
        }
    }

    /// A request: its own `Content-Type`, and no status, because it has not been answered yet.
    pub fn request(meta: &HeldMeta, raw: &[u8]) -> Self {
        Self {
            content_type: header_value(head_of(raw), b"content-type"),
            ..Self::route(meta)
        }
    }

    /// A response: its status line and its own `Content-Type`, on the route that asked for it.
    pub fn response(meta: &HeldMeta, raw: &[u8]) -> Self {
        Self {
            status: parse_status(raw),
            content_type: header_value(head_of(raw), b"content-type"),
            ..Self::route(meta)
        }
    }

    /// `scheme://host[:port]/path`, the port omitted when it is the scheme's default — so a rule
    /// written against a URL an operator pasted from a browser matches it.
    pub fn url(&self) -> String {
        let (scheme, default) = if self.tls {
            ("https", 443)
        } else {
            ("http", 80)
        };
        if self.port == default {
            format!("{scheme}://{}{}", self.host, self.path)
        } else {
            format!("{scheme}://{}:{}{}", self.host, self.port, self.path)
        }
    }

    fn value(&self, field: MatchField) -> Option<Cow<'_, str>> {
        match field {
            MatchField::Host => Some(Cow::Borrowed(&self.host)),
            MatchField::Path => Some(Cow::Borrowed(&self.path)),
            MatchField::Extension => Some(Cow::Borrowed(extension_of(&self.path))),
            MatchField::Method => Some(Cow::Borrowed(&self.method)),
            MatchField::Url => Some(Cow::Owned(self.url())),
            MatchField::StatusCode => self.status.map(|s| Cow::Owned(s.to_string())),
            MatchField::ContentType => self.content_type.as_deref().map(Cow::Borrowed),
        }
    }
}

/// The header block, without the body.
///
/// A condition on a content type must not be satisfiable by a body that happens to contain the text
/// `\ncontent-type:` — bodies are attacker-shaped input, and a rule that fires on one is a rule the
/// operator cannot trust.
fn head_of(raw: &[u8]) -> &[u8] {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => &raw[..i],
        None => raw,
    }
}

/// The extension of a request target: after the last dot of the last path segment, query and
/// fragment stripped first so `/a.js?v=2` is `js` rather than `js?v=2`.
fn extension_of(path: &str) -> &str {
    let p = path.split(['?', '#']).next().unwrap_or(path);
    let seg = p.rsplit('/').next().unwrap_or(p);
    seg.rsplit_once('.').map(|(_, e)| e).unwrap_or("")
}

/// The serialisable form of one direction's condition list.
#[derive(Debug, Clone, Default, Serialize)]
pub struct InterceptRulesSpec {
    /// Whether this direction is held at all — Burp's "intercept … based on the following rules"
    /// checkbox.
    pub active: bool,
    pub rules: Vec<InterceptRuleSpec>,
}

/// What arrives on the wire, before `active` has been settled.
#[derive(Deserialize)]
struct WireRulesSpec {
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    rules: Vec<InterceptRuleSpec>,
}

/// An omitted `active` is inferred from the conditions, and **not** defaulted to true.
///
/// Defaulting it to true looks harmless and is not: `PUT /api/intercept/rules/responses` with `{}` or
/// `{"rules": []}` would then mean "hold every response", and `{"rules": []}` is exactly what a UI
/// sends when an operator deletes their last response rule and saves. The response list ships inactive
/// precisely so that flipping the master switch cannot start holding responses; a wire default that
/// undoes it from the outside would make the guarantee decorative.
///
/// Inferring from the conditions gives every request the reading its sender obviously meant: `{}` is
/// off, a list with an enabled condition is on, and blanket holding stays reachable — but only by
/// saying `"active": true` with no conditions, out loud.
impl<'de> Deserialize<'de> for InterceptRulesSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = WireRulesSpec::deserialize(d)?;
        let active = w
            .active
            .unwrap_or_else(|| w.rules.iter().any(|r| r.enabled));
        Ok(Self {
            active,
            rules: w.rules,
        })
    }
}

/// One direction's ordered condition list, compiled. Conditions are OR'd: the first match is enough,
/// which is what an operator listing "the hosts I care about" means.
#[derive(Debug, Clone)]
pub struct InterceptRules {
    active: bool,
    rules: Vec<InterceptRule>,
}

impl InterceptRules {
    /// Compile a whole list. The first bad pattern stops the load and names itself.
    pub fn compile(spec: InterceptRulesSpec) -> Result<Self, RuleError> {
        let rules = spec
            .rules
            .into_iter()
            .map(InterceptRule::new)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::from_rules(spec.active, rules))
    }

    pub fn from_rules(active: bool, rules: Vec<InterceptRule>) -> Self {
        Self { active, rules }
    }

    /// An active list with no conditions: hold everything this direction carries.
    pub fn unconditional() -> Self {
        Self::from_rules(true, Vec::new())
    }

    /// An inactive list: hold nothing, whatever the master switch says.
    pub fn off() -> Self {
        Self::from_rules(false, Vec::new())
    }

    pub fn spec(&self) -> InterceptRulesSpec {
        InterceptRulesSpec {
            active: self.active,
            rules: self.rules.iter().map(|r| r.spec.clone()).collect(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn rules(&self) -> &[InterceptRule] {
        &self.rules
    }

    /// True when this list holds every message in its direction: active, and empty.
    ///
    /// Emptiness, not "nothing enabled". A list of five unchecked rules holds *nothing* — see the
    /// module docs for why the difference is the safety argument rather than a detail.
    pub fn is_unconditional(&self) -> bool {
        self.active && self.rules.is_empty()
    }

    /// Should this message be held?
    ///
    /// A condition whose field is not knowable from `f` does not match — so a status-code condition
    /// in the *request* list can never hold a request, rather than holding all of them.
    pub fn matches(&self, f: &Facts) -> bool {
        self.decide(f, false)
    }

    /// Could this message still be held once the response's own facts arrive?
    ///
    /// The pre-response question, asked while there is still a choice between streaming and
    /// buffering. Conditions on request facts are answered for real; a condition that only the
    /// response can settle counts as "maybe", because the cost of guessing wrong that way is
    /// latency, and the cost of guessing wrong the other way is streaming past a rule the operator
    /// wrote.
    pub fn could_match(&self, f: &Facts) -> bool {
        self.decide(f, true)
    }

    fn decide(&self, f: &Facts, unknown: bool) -> bool {
        if !self.active {
            return false;
        }
        if self.rules.is_empty() {
            return true;
        }
        self.rules
            .iter()
            .filter(|r| r.enabled())
            .any(|r| r.test(f).unwrap_or(unknown))
    }
}

/// What the operator decided about a held request.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Send these bytes upstream — the original, or the operator's rewrite.
    Forward(Bytes),
    /// Never send it. The client gets a synthetic response carrying this reason.
    Drop(String),
}

/// The routing facts about a held message, taken from the connection that is holding it.
///
/// A held *response* carries the facts of the request that provoked it — the method and path are the
/// question, not the answer — so a response condition can be written against either half. The
/// answer's own facts (status, content type) are read from its bytes, not from here.
#[derive(Debug, Clone)]
pub struct HeldMeta {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
}

/// One queue entry as the API renders it.
///
/// `raw` is lossy UTF-8 because the operator edits it as text. The bytes actually forwarded are
/// whatever comes back from [`Interceptor::forward`], so a request containing invalid UTF-8 that is
/// forwarded *unedited* still goes out byte-exact — only an explicit rewrite can lose bytes, and
/// that is the operator's choice.
#[derive(Debug, Clone, Serialize)]
pub struct HeldView {
    pub id: u64,
    /// `"request"` or `"response"`. Rendered lowercase rather than as `Direction`'s own variant
    /// names, to match the casing of every other field the API emits.
    pub direction: &'static str,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
    /// The held response's status. `None` on a request, which has not been answered yet.
    pub status: Option<u16>,
    /// How long this message has been waiting, so a stale queue is visible rather than mysterious.
    pub held_ms: u64,
    pub len: usize,
    pub raw: String,
}

struct Waiting {
    direction: Direction,
    meta: HeldMeta,
    raw: Bytes,
    since: Instant,
    resume: oneshot::Sender<Verdict>,
}

/// The hold queue. One per proxy; share it with the API layer via `Arc`.
///
/// Requests and responses share one queue and one id space. They have to: a response is held on the
/// same connection task as the request it answers, and an operator stepping through an exchange
/// wants to see both halves in the order they happened, not in two lists that have to be correlated
/// by eye.
pub struct Interceptor {
    enabled: AtomicBool,
    next_id: AtomicU64,
    /// `BTreeMap` rather than `HashMap`: ids are monotonic, so iteration order is arrival order and
    /// the operator sees the queue in the order the messages actually arrived.
    held: Mutex<BTreeMap<u64, Waiting>>,
    /// Read on every message and written only by an operator, so `RwLock` rather than `Mutex`. The
    /// guard is never held across an `await`, which `parking_lot`'s `!Send` guards enforce.
    request_rules: RwLock<InterceptRules>,
    response_rules: RwLock<InterceptRules>,
}

impl std::fmt::Debug for Interceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interceptor")
            .field("enabled", &self.is_enabled())
            .field("pending", &self.pending())
            .field("request_rules", &self.request_rules.read().rules.len())
            .field("response_rules", &self.response_rules.read().rules.len())
            .finish()
    }
}

impl Interceptor {
    /// A disabled interceptor. Interception is opt-in: a proxy that starts by holding traffic looks
    /// broken to whoever pointed a browser at it.
    ///
    /// The two lists start asymmetrically, and the asymmetry is the point — see the module docs.
    /// Requests are unconditional, so switching the master on behaves exactly as it always has.
    /// Responses are off, so switching the master on does *not* start holding a half of every
    /// exchange that burpsy has never held before.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(false),
            next_id: AtomicU64::new(1),
            held: Mutex::new(BTreeMap::new()),
            request_rules: RwLock::new(InterceptRules::unconditional()),
            response_rules: RwLock::new(InterceptRules::off()),
        })
    }

    /// The master switch, and nothing else. Conditions are deliberately not consulted here: this is
    /// also the ALPN/h2 question, which is answered before a request exists to match. See the module
    /// docs.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn request_rules(&self) -> InterceptRules {
        self.request_rules.read().clone()
    }

    pub fn response_rules(&self) -> InterceptRules {
        self.response_rules.read().clone()
    }

    /// Replace the request condition list. Already compiled, so this cannot fail and cannot cost the
    /// hot path a regex compilation.
    pub fn set_request_rules(&self, rules: InterceptRules) {
        *self.request_rules.write() = rules;
    }

    /// Replace the response condition list.
    ///
    /// Unlike [`Self::set_enabled`], this does **not** release anything already held: narrowing the
    /// rules is a statement about future traffic, and silently forwarding a response the operator is
    /// mid-edit would lose their work.
    pub fn set_response_rules(&self, rules: InterceptRules) {
        *self.response_rules.write() = rules;
    }

    /// Turn interception on or off. Turning it **off releases the whole queue unedited** and returns
    /// how many were released: an operator who switches interception off is saying "stop bothering
    /// me", not "strand the requests you already took". Held responses are released the same way —
    /// their clients get the origin's real answer, late.
    ///
    /// The condition lists are left alone. They are configuration; this is a switch.
    pub fn set_enabled(&self, on: bool) -> usize {
        self.enabled.store(on, Ordering::Relaxed);
        if on {
            return 0;
        }
        let drained: Vec<Waiting> = std::mem::take(&mut *self.held.lock())
            .into_values()
            .collect();
        let n = drained.len();
        for w in drained {
            let _ = w.resume.send(Verdict::Forward(w.raw));
        }
        n
    }

    pub fn pending(&self) -> usize {
        self.held.lock().len()
    }

    /// Park this request until the operator decides. Returns instantly when nothing wants it held,
    /// so the uninteresting path costs one relaxed atomic load and, at most, one `RwLock` read.
    pub async fn hold(&self, meta: HeldMeta, raw: Bytes) -> Verdict {
        if !self.is_enabled() || !self.request_rules.read().matches(&Facts::request(&meta, &raw)) {
            return Verdict::Forward(raw);
        }
        self.park(Direction::Request, meta, raw).await
    }

    /// Park a complete response until the operator decides.
    ///
    /// Separate from [`Self::hold`] rather than a direction argument, because the two are reached
    /// from different points on the connection and gated by different lists — a caller that got the
    /// argument wrong would silently consult the other operator's rules.
    pub async fn hold_response(&self, meta: HeldMeta, raw: Bytes) -> Verdict {
        if !self.is_enabled()
            || !self
                .response_rules
                .read()
                .matches(&Facts::response(&meta, &raw))
        {
            return Verdict::Forward(raw);
        }
        self.park(Direction::Response, meta, raw).await
    }

    /// Whether the response on this route has to be buffered instead of streamed.
    ///
    /// Asked before the response exists, because streaming and holding are mutually exclusive: a
    /// byte already on the client's socket cannot be taken back. Everything knowable now is tested
    /// for real, and a condition only the response can settle counts as "maybe" — see
    /// [`InterceptRules::could_match`].
    pub fn may_hold_response(&self, meta: &HeldMeta) -> bool {
        self.is_enabled() && self.response_rules.read().could_match(&Facts::route(meta))
    }

    /// Which half of an exchange `id` is, while it is still held. The API layer needs it to know
    /// whether an edit's `Content-Length` should be re-derived as a request or as a response.
    pub fn direction_of(&self, id: u64) -> Option<Direction> {
        self.held.lock().get(&id).map(|w| w.direction)
    }

    async fn park(&self, direction: Direction, meta: HeldMeta, raw: Bytes) -> Verdict {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        {
            let mut q = self.held.lock();
            q.insert(
                id,
                Waiting {
                    direction,
                    meta,
                    raw: raw.clone(),
                    since: Instant::now(),
                    resume: tx,
                },
            );
        }
        tracing::debug!(
            "held {} {id} ({} byte(s))",
            label(direction),
            raw.len()
        );
        match rx.await {
            Ok(v) => v,
            Err(_) => Verdict::Forward(raw),
        }
    }

    /// The queue, oldest first.
    pub fn list(&self) -> Vec<HeldView> {
        let q = self.held.lock();
        q.iter()
            .map(|(id, w)| HeldView {
                id: *id,
                direction: label(w.direction),
                host: w.meta.host.clone(),
                port: w.meta.port,
                tls: w.meta.tls,
                method: w.meta.method.clone(),
                path: w.meta.path.clone(),
                status: match w.direction {
                    Direction::Request => None,
                    Direction::Response => parse_status(&w.raw),
                },
                held_ms: w.since.elapsed().as_millis() as u64,
                len: w.raw.len(),
                raw: String::from_utf8_lossy(&w.raw).into_owned(),
            })
            .collect()
    }

    /// Release `id`, optionally replacing its bytes. `false` means there is no such held message —
    /// it was already resolved, or the client hung up.
    pub fn forward(&self, id: u64, edited: Option<Bytes>) -> bool {
        let Some(w) = self.held.lock().remove(&id) else {
            return false;
        };
        let bytes = edited.unwrap_or_else(|| w.raw.clone());
        w.resume.send(Verdict::Forward(bytes)).is_ok()
    }

    /// Refuse to forward `id`; its client gets a synthetic response naming `reason`. Named for the
    /// request case it was written for; a held response refused this way is suppressed the same way,
    /// with the same synthetic answer standing in for the origin's.
    pub fn drop_request(&self, id: u64, reason: impl Into<String>) -> bool {
        let Some(w) = self.held.lock().remove(&id) else {
            return false;
        };
        w.resume.send(Verdict::Drop(reason.into())).is_ok()
    }
}

fn label(d: Direction) -> &'static str {
    match d {
        Direction::Request => "request",
        Direction::Response => "response",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn meta() -> HeldMeta {
        HeldMeta {
            host: "a.test".into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            path: "/x".into(),
        }
    }

    #[tokio::test]
    async fn a_disabled_interceptor_forwards_the_original_bytes_without_queueing() {
        let ic = Interceptor::new();
        let v = ic
            .hold(meta(), Bytes::from_static(b"GET /x HTTP/1.1\r\n\r\n"))
            .await;
        match v {
            Verdict::Forward(b) => assert_eq!(&b[..], b"GET /x HTTP/1.1\r\n\r\n"),
            Verdict::Drop(r) => panic!("disabled interceptor dropped: {r}"),
        }
        assert_eq!(ic.pending(), 0, "a disabled hold must not enter the queue");
    }

    #[tokio::test]
    async fn forwarding_with_edited_bytes_returns_the_edit_not_the_original() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"ORIGINAL")).await })
        };
        wait_for_pending(&ic, 1).await;

        let view = ic.list();
        assert_eq!(view.len(), 1);
        assert_eq!(view[0].raw, "ORIGINAL");
        assert_eq!(view[0].path, "/x");
        assert!(ic.forward(view[0].id, Some(Bytes::from_static(b"EDITED"))));

        match held.await.unwrap() {
            Verdict::Forward(b) => assert_eq!(&b[..], b"EDITED"),
            Verdict::Drop(r) => panic!("expected forward, got drop: {r}"),
        }
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn dropping_a_held_request_yields_a_drop_verdict_carrying_the_reason() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"REQ")).await })
        };
        wait_for_pending(&ic, 1).await;
        let id = ic.list()[0].id;
        assert!(ic.drop_request(id, "operator said no"));

        match held.await.unwrap() {
            Verdict::Drop(r) => assert_eq!(r, "operator said no"),
            Verdict::Forward(_) => panic!("expected drop"),
        }
    }

    #[tokio::test]
    async fn resolving_an_unknown_id_reports_failure_rather_than_pretending() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        assert!(!ic.forward(999, None));
        assert!(!ic.drop_request(999, "x"));
    }

    #[tokio::test]
    async fn turning_interception_off_releases_everything_already_held() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        let a = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"A")).await })
        };
        let b = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"B")).await })
        };
        wait_for_pending(&ic, 2).await;

        assert_eq!(
            ic.set_enabled(false),
            2,
            "both held requests must be released"
        );
        for h in [a, b] {
            match h.await.unwrap() {
                Verdict::Forward(_) => {}
                Verdict::Drop(r) => panic!("switching interception off must not drop: {r}"),
            }
        }
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn the_queue_is_listed_in_arrival_order() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        for (n, p) in ["/first", "/second", "/third"].into_iter().enumerate() {
            let spawned = ic.clone();
            let mut m = meta();
            m.path = p.to_string();
            tokio::spawn(async move { spawned.hold(m, Bytes::from_static(b"R")).await });
            // Serialised on purpose: arrival order is only meaningful if arrival is ordered.
            wait_for_pending(&ic, n + 1).await;
        }
        let paths: Vec<String> = ic.list().into_iter().map(|v| v.path).collect();
        assert_eq!(paths, vec!["/first", "/second", "/third"]);
    }

    // ---- conditions ---------------------------------------------------------------------------

    fn rules(specs: Vec<InterceptRuleSpec>) -> InterceptRules {
        InterceptRules::compile(InterceptRulesSpec {
            active: true,
            rules: specs,
        })
        .expect("test rules must compile")
    }

    const RESP_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>hi";
    const RESP_500: &[u8] = b"HTTP/1.1 500 Server Error\r\nContent-Type: application/json\r\n\r\n{}";

    #[tokio::test]
    async fn the_defaults_are_blanket_requests_and_no_responses_at_all() {
        let ic = Interceptor::new();
        assert!(
            ic.request_rules().is_unconditional(),
            "a fresh interceptor must hold every request once the master switch is on — that is \
             what burpsy did before conditions existed"
        );
        assert!(
            !ic.response_rules().is_active(),
            "and must hold no response at all, because burpsy never has"
        );

        ic.set_enabled(true);
        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"REQ")).await })
        };
        wait_for_pending(&ic, 1).await;
        assert!(ic.forward(ic.list()[0].id, None));
        held.await.unwrap();

        // The same switch, the same route, the response half: untouched.
        match ic.hold_response(meta(), Bytes::copy_from_slice(RESP_OK)).await {
            Verdict::Forward(b) => assert_eq!(&b[..], RESP_OK),
            Verdict::Drop(r) => panic!("responses are off by default; got a drop: {r}"),
        }
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn a_request_matching_no_enabled_condition_is_not_held() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        ic.set_request_rules(rules(vec![InterceptRuleSpec::new(
            MatchField::Host,
            "^only\\.example$",
        )]));
        // `meta()` is a.test, which the rule does not name.
        match ic.hold(meta(), Bytes::from_static(b"REQ")).await {
            Verdict::Forward(b) => assert_eq!(&b[..], b"REQ"),
            Verdict::Drop(r) => panic!("no condition matched, so nothing should be held: {r}"),
        }
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn a_matching_condition_holds_and_the_master_switch_still_overrides_it() {
        let ic = Interceptor::new();
        ic.set_request_rules(rules(vec![InterceptRuleSpec::new(MatchField::Path, "^/x$")]));

        // Master off: a matching condition holds nothing. Conditions narrow, they never enable.
        match ic.hold(meta(), Bytes::from_static(b"REQ")).await {
            Verdict::Forward(_) => {}
            Verdict::Drop(r) => panic!("master switch is off: {r}"),
        }

        ic.set_enabled(true);
        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"REQ")).await })
        };
        wait_for_pending(&ic, 1).await;
        assert_eq!(ic.list()[0].direction, "request");
        assert_eq!(ic.list()[0].status, None, "a request has no status yet");
        assert!(ic.forward(ic.list()[0].id, None));
        held.await.unwrap();
    }

    #[tokio::test]
    async fn unchecking_every_condition_holds_nothing_rather_than_falling_back_to_blanket() {
        // Blanket is keyed on the list being *empty*, not on nothing in it being enabled. The bug the
        // distinction prevents: unchecking one box would otherwise start holding every response,
        // which to a browser is indistinguishable from the proxy having broken.
        let ic = Interceptor::new();
        ic.set_enabled(true);
        ic.set_request_rules(rules(vec![
            InterceptRuleSpec::new(MatchField::Host, ".").disabled(),
        ]));
        assert!(
            !ic.request_rules().is_unconditional(),
            "a list with rows in it is never blanket, however many boxes are unchecked"
        );
        match ic.hold(meta(), Bytes::from_static(b"REQ")).await {
            Verdict::Forward(_) => {}
            Verdict::Drop(r) => panic!("no enabled condition matched: {r}"),
        }
        assert_eq!(ic.pending(), 0);

        // Deleting the rows — the unambiguous way to say "everything" — does restore blanket.
        ic.set_request_rules(InterceptRules::unconditional());
        assert!(ic.request_rules().is_unconditional());
        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"REQ")).await })
        };
        wait_for_pending(&ic, 1).await;
        assert!(ic.forward(ic.list()[0].id, None));
        held.await.unwrap();
    }

    #[test]
    fn an_omitted_active_flag_is_inferred_from_the_conditions_and_never_defaulted_on() {
        // `{"rules": []}` is what a UI sends when the operator deletes their last response rule. If
        // that meant "hold every response", the inactive-by-default guarantee would be decorative.
        let off: InterceptRulesSpec = serde_json::from_str("{}").unwrap();
        assert!(!off.active);
        let off: InterceptRulesSpec = serde_json::from_str(r#"{"rules":[]}"#).unwrap();
        assert!(!off.active, "an empty list must not switch itself on");

        let disabled: InterceptRulesSpec = serde_json::from_str(
            r#"{"rules":[{"field":"host","string_match":"x","enabled":false}]}"#,
        )
        .unwrap();
        assert!(!disabled.active, "nothing enabled means nothing to run");

        let on: InterceptRulesSpec =
            serde_json::from_str(r#"{"rules":[{"field":"host","string_match":"x"}]}"#).unwrap();
        assert!(on.active, "a condition plainly wants to be run");

        // Blanket is still reachable — but only by saying so out loud.
        let blanket: InterceptRulesSpec = serde_json::from_str(r#"{"active":true,"rules":[]}"#).unwrap();
        assert!(InterceptRules::compile(blanket).unwrap().is_unconditional());
    }

    #[tokio::test]
    async fn an_inactive_list_holds_nothing_however_well_its_conditions_match() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        ic.set_request_rules(
            InterceptRules::compile(InterceptRulesSpec {
                active: false,
                rules: vec![InterceptRuleSpec::new(MatchField::Host, "a")],
            })
            .unwrap(),
        );
        match ic.hold(meta(), Bytes::from_static(b"REQ")).await {
            Verdict::Forward(_) => {}
            Verdict::Drop(r) => panic!("the list is switched off: {r}"),
        }
        assert_eq!(ic.pending(), 0);
    }

    #[tokio::test]
    async fn a_literal_condition_matches_text_and_not_the_pattern_it_looks_like() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        // `a.test` as a regex matches `axtest`; as a literal it must not.
        ic.set_request_rules(rules(vec![
            InterceptRuleSpec::new(MatchField::Host, "a.test").literal(),
        ]));
        let mut m = meta();
        m.host = "axtest".into();
        match ic.hold(m, Bytes::from_static(b"REQ")).await {
            Verdict::Forward(_) => {}
            Verdict::Drop(r) => panic!("a literal must not match as a pattern: {r}"),
        }
        assert_eq!(ic.pending(), 0);

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move { ic.hold(meta(), Bytes::from_static(b"REQ")).await })
        };
        wait_for_pending(&ic, 1).await;
        assert!(ic.forward(ic.list()[0].id, None));
        held.await.unwrap();
    }

    #[tokio::test]
    async fn a_response_condition_on_the_status_code_holds_only_what_it_names() {
        let ic = Interceptor::new();
        ic.set_enabled(true);
        ic.set_response_rules(rules(vec![InterceptRuleSpec::new(
            MatchField::StatusCode,
            "^5..$",
        )]));

        match ic.hold_response(meta(), Bytes::copy_from_slice(RESP_OK)).await {
            Verdict::Forward(b) => assert_eq!(&b[..], RESP_OK),
            Verdict::Drop(r) => panic!("a 200 does not match ^5..$: {r}"),
        }

        let held = {
            let ic = ic.clone();
            tokio::spawn(async move {
                ic.hold_response(meta(), Bytes::copy_from_slice(RESP_500))
                    .await
            })
        };
        wait_for_pending(&ic, 1).await;
        let view = &ic.list()[0];
        assert_eq!(view.direction, "response");
        assert_eq!(view.status, Some(500));
        assert_eq!(
            view.method, "GET",
            "a held response carries the facts of the request that provoked it"
        );
        assert_eq!(ic.direction_of(view.id), Some(Direction::Response));
        assert!(ic.forward(view.id, Some(Bytes::from_static(b"EDITED"))));
        match held.await.unwrap() {
            Verdict::Forward(b) => assert_eq!(&b[..], b"EDITED"),
            Verdict::Drop(r) => panic!("expected forward, got drop: {r}"),
        }
    }

    #[tokio::test]
    async fn a_status_code_condition_in_the_request_list_can_never_hold_a_request() {
        // Not "holds every request": an unknowable field does not match, or the operator's narrowest
        // possible mistake would become the broadest possible behaviour.
        let ic = Interceptor::new();
        ic.set_enabled(true);
        ic.set_request_rules(rules(vec![InterceptRuleSpec::new(
            MatchField::StatusCode,
            "^2..$",
        )]));
        match ic.hold(meta(), Bytes::from_static(b"REQ")).await {
            Verdict::Forward(_) => {}
            Verdict::Drop(r) => panic!("a request has no status to match: {r}"),
        }
        assert_eq!(ic.pending(), 0);
    }

    #[test]
    fn the_pre_response_prefilter_answers_request_conditions_and_defers_response_ones() {
        let ic = Interceptor::new();
        ic.set_enabled(true);

        // A condition on a request fact is decided for real: no buffering on a route it excludes.
        ic.set_response_rules(rules(vec![InterceptRuleSpec::new(
            MatchField::Host,
            "^other\\.test$",
        )]));
        assert!(
            !ic.may_hold_response(&meta()),
            "a host condition that cannot match this route must leave the relay streaming"
        );

        // A condition only the response can settle has to buffer, or we stream past it.
        ic.set_response_rules(rules(vec![InterceptRuleSpec::new(
            MatchField::ContentType,
            "json",
        )]));
        assert!(ic.may_hold_response(&meta()));

        // And the master switch outranks both.
        ic.set_enabled(false);
        assert!(!ic.may_hold_response(&meta()));
    }

    #[test]
    fn conditions_do_not_move_the_switch_that_decides_alpn() {
        // `is_enabled()` is also the h2-downgrade question, answered from the ClientHello before any
        // request exists to match. If a rule list could move it, the downgrade would depend on
        // traffic that has not arrived yet.
        let ic = Interceptor::new();
        assert!(!ic.is_enabled());
        ic.set_request_rules(rules(vec![InterceptRuleSpec::new(MatchField::Host, ".")]));
        ic.set_response_rules(rules(vec![InterceptRuleSpec::new(MatchField::Host, ".")]));
        assert!(
            !ic.is_enabled(),
            "adding conditions must not switch interception on"
        );

        ic.set_enabled(true);
        ic.set_request_rules(
            InterceptRules::compile(InterceptRulesSpec {
                active: false,
                rules: Vec::new(),
            })
            .unwrap(),
        );
        ic.set_response_rules(InterceptRules::off());
        assert!(
            ic.is_enabled(),
            "switching every list off must not switch interception off: the ALPN offer is already \
             downgraded on connections that are open"
        );
    }

    #[test]
    fn a_bad_pattern_is_refused_at_compile_time_and_names_itself() {
        let e = InterceptRules::compile(InterceptRulesSpec {
            active: true,
            rules: vec![
                InterceptRuleSpec::new(MatchField::Host, "(unclosed").with_comment("my rule"),
            ],
        })
        .expect_err("an unbalanced group must not load");
        assert_eq!(e.rule, "my rule");
        assert!(e.to_string().contains("my rule"), "{e}");

        let e = InterceptRules::compile(InterceptRulesSpec {
            active: true,
            rules: vec![InterceptRuleSpec::new(MatchField::Host, "")],
        })
        .expect_err("an empty condition must be refused rather than matching everything");
        assert!(e.message.contains("no conditions"), "{e}");
    }

    #[test]
    fn the_derived_fields_have_the_shapes_the_docs_promise() {
        let f = Facts {
            host: "a.test".into(),
            port: 8443,
            tls: true,
            method: "GET".into(),
            path: "/assets/app.min.js?v=2".into(),
            status: Some(204),
            content_type: None,
        };
        assert_eq!(f.url(), "https://a.test:8443/assets/app.min.js?v=2");
        assert_eq!(extension_of(&f.path), "js");
        assert_eq!(extension_of("/no/extension/here"), "");
        assert_eq!(extension_of("/"), "");

        // The default port is omitted, so a rule written against a pasted URL matches it.
        let plain = Facts {
            port: 80,
            tls: false,
            ..f.clone()
        };
        assert_eq!(plain.url(), "http://a.test/assets/app.min.js?v=2");
    }

    #[test]
    fn a_content_type_condition_is_not_satisfied_by_a_body_that_merely_mentions_one() {
        // Bodies are attacker-shaped input. A rule that fires on one is a rule nobody can trust.
        let m = meta();
        let f = Facts::response(
            &m,
            b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n\ncontent-type: application/json\n",
        );
        assert_eq!(f.content_type, None);
        assert_eq!(f.status, Some(200));

        let f = Facts::response(&m, RESP_500);
        assert_eq!(f.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn a_rule_set_survives_a_round_trip_through_json() {
        let spec = InterceptRulesSpec {
            active: true,
            rules: vec![
                InterceptRuleSpec::new(MatchField::Extension, "^(js|css)$"),
                InterceptRuleSpec::new(MatchField::ContentType, "text/html")
                    .literal()
                    .disabled()
                    .with_comment("pages only"),
            ],
        };
        let json = serde_json::to_string(&InterceptRules::compile(spec).unwrap().spec()).unwrap();
        let back: InterceptRulesSpec = serde_json::from_str(&json).unwrap();
        let rs = InterceptRules::compile(back).unwrap();
        assert_eq!(rs.rules().len(), 2);
        assert_eq!(rs.rules()[1].comment(), "pages only");
        assert!(!rs.rules()[1].enabled());
        assert_eq!(rs.rules()[1].spec().category, MatchCategory::Literal);
        // One enabled rule, so the list is not unconditional.
        assert!(!rs.is_unconditional());
    }

    /// Poll rather than sleep a fixed time: a fixed sleep is either flaky or slow.
    async fn wait_for_pending(ic: &Interceptor, n: usize) {
        for _ in 0..2000 {
            if ic.pending() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!(
            "timed out waiting for {n} held request(s), have {}",
            ic.pending()
        );
    }
}
