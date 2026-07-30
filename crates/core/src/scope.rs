//! Scope: which hosts and paths this engagement is authorised to touch.
//!
//! # Why this lives in core and is enforced twice
//!
//! Scope is not a UI filter. It is the machine-readable form of "what am I allowed to attack", and
//! getting it wrong means sending payloads at something outside the engagement. So it is enforced in
//! two independent places:
//!
//! * the **proxy**, deciding what gets captured and stored;
//! * every **outbound attack path** (repeater, intruder, later the scanner), which refuses a target
//!   that is not in scope.
//!
//! # Editing scope while the tool is running
//!
//! Scope used to be fixed at startup: `--scope-include`/`--scope-exclude` built one [`Scope`], every
//! subsystem got its own `Arc<Scope>` clone of it, and changing a rule meant a restart. That was
//! justified here by pointing at Burp's *agentic* tool registry, where of 54 tools `add_to_scope` is
//! one of only four marked `ALWAYS_ESCALATE` because it "grants new authorization for hosts".
//!
//! That citation was about a different actor. The thing `ALWAYS_ESCALATE` guards is an autonomous
//! agent widening its **own** authorisation with no human in the loop. An operator clicking "add to
//! scope" on a site-map row is not that: they are the human the escalation exists to reach, and Burp
//! itself has offered exactly that action, from exactly that right-click menu, for its whole life.
//! Refusing to build it here bought no safety — it just made the tool worse than the one it copies.
//!
//! So scope is editable at runtime, through [`SharedScope`], and what is preserved is not
//! immutability but the property that actually mattered:
//!
//! * **Widening is never a side effect.** Nothing in this module adds a rule on its own. The only
//!   mutators are [`Scope::add_rule`] and [`Scope::remove_rule`], and the HTTP surface in front of
//!   them is a named operator action with a confirmation step — not something a scan, a redirect, or
//!   a captured request can trigger.
//! * **One scope, not six copies.** [`SharedScope`] is a handle, so the proxy's capture gate, the
//!   sender's authorisation gate, the scanner and the API all read the *same* rules. Cloning a
//!   `Scope` into each subsystem, as the old wiring did, would mean an edit that visibly changed the
//!   UI while attacks kept using the startup rules — a scope display that lies about what is
//!   authorised is worse than no display.
//! * **Removal can widen too.** Deleting an `exclude` rule authorises everything it was holding
//!   back, so removal is by stable rule id rather than list position: a stale index would delete a
//!   neighbouring rule and silently grant what it was refusing.
//!
//! # Rule model
//!
//! Ordered rules, last match wins, mirroring how include/exclude lists actually behave in practice.
//! Default with no rules is **deny** — an empty scope must not silently authorise the internet.

use parking_lot::{RwLock, RwLockReadGuard};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Include or exclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleKind {
    Include,
    Exclude,
}

/// One scope rule. Any unset field matches anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
    /// Stable identity within one [`Scope`], assigned by [`Scope::add_rule`]. `0` means "not yet in a
    /// scope" — a freshly built rule from [`ScopeRule::include`] has no id until it is added.
    ///
    /// Exists so a rule can be *removed* by name rather than by list position. Order is load-bearing
    /// here (last match wins), so positions shift on every edit, and a caller acting on a stale index
    /// would delete the rule next to the one it meant to. When the rule it hits is an `exclude`, that
    /// mistake silently authorises everything the exclude was holding back.
    #[serde(default)]
    pub id: u64,
    pub kind: RuleKind,
    /// Host pattern: exact, or one leading `*.` wildcard. `None` matches any host.
    pub host: Option<String>,
    /// Exact port. `None` matches any port.
    pub port: Option<u16>,
    /// Path prefix. `None` matches any path.
    pub path_prefix: Option<String>,
    /// If set, only matches when the scheme's TLS-ness agrees.
    pub tls: Option<bool>,
}

impl ScopeRule {
    /// `include host` — any port, any path.
    pub fn include(host: impl Into<String>) -> Self {
        Self {
            id: 0,
            kind: RuleKind::Include,
            host: Some(host.into()),
            port: None,
            path_prefix: None,
            tls: None,
        }
    }

    /// `exclude host` — any port, any path.
    pub fn exclude(host: impl Into<String>) -> Self {
        Self {
            id: 0,
            kind: RuleKind::Exclude,
            host: Some(host.into()),
            port: None,
            path_prefix: None,
            tls: None,
        }
    }

    pub fn with_port(mut self, p: u16) -> Self {
        self.port = Some(p);
        self
    }

    pub fn with_path_prefix(mut self, p: impl Into<String>) -> Self {
        self.path_prefix = Some(p.into());
        self
    }

    pub fn with_tls(mut self, tls: bool) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Everything except the path. Split out because the host-level pre-filter must ignore path
    /// rules entirely — see [`Scope::may_contain_host`].
    fn matches_host(&self, host: &str, port: u16, tls: bool) -> bool {
        if let Some(want) = self.tls
            && want != tls
        {
            return false;
        }
        if let Some(p) = self.port
            && p != port
        {
            return false;
        }
        if let Some(pat) = &self.host
            && !host_matches(pat, host)
        {
            return false;
        }
        true
    }

    fn matches(&self, host: &str, port: u16, path: &str, tls: bool) -> bool {
        if !self.matches_host(host, port, tls) {
            return false;
        }
        if let Some(prefix) = &self.path_prefix
            && !path.starts_with(prefix.as_str())
        {
            return false;
        }
        true
    }
}

/// The path from a raw request's start line, for a scope decision.
///
/// Deliberately minimal: this runs once per outbound request on an attack loop, so it reads the
/// start line and stops rather than parsing headers. Handles origin-form (`GET /a?b=1`) and the
/// absolute-form a proxied request carries (`GET http://h/a?b=1`), and drops the query, because
/// scope rules are prefixes over the path.
///
/// `None` means the bytes do not have a parseable request line. Callers must treat that as
/// *refuse*, never as "no path, so nothing to check".
pub fn request_path(raw: &[u8]) -> Option<&str> {
    let line_end = raw
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(raw.len());
    let line = std::str::from_utf8(&raw[..line_end]).ok()?;
    let mut parts = line.split(' ').filter(|s| !s.is_empty());
    let _method = parts.next()?;
    let target = parts.next()?;

    // Absolute-form: skip scheme://authority and keep what follows.
    let rest = match target.find("://") {
        Some(i) => match target[i + 3..].find('/') {
            Some(j) => &target[i + 3 + j..],
            // `http://host` with no path at all addresses the root.
            None => "/",
        },
        None => target,
    };
    Some(match rest.split_once('?') {
        Some((p, _)) => p,
        None => rest,
    })
}

/// An ordered rule list. Last matching rule wins; no match means out of scope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    pub rules: Vec<ScopeRule>,
    /// When true, everything is in scope. Explicit opt-in, never the default.
    #[serde(default)]
    pub allow_all: bool,
    /// Monotonic id source for [`ScopeRule::id`]. Never reused, so an id that has been removed stays
    /// removed: reusing it would let a stale client delete a rule it never saw.
    #[serde(default)]
    next_rule_id: u64,
}

impl Scope {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deliberately named so it reads as a decision at the call site.
    pub fn allow_everything() -> Self {
        Self {
            rules: Vec::new(),
            allow_all: true,
            next_rule_id: 0,
        }
    }

    /// Append a rule and return the id it was given.
    ///
    /// Appending is what "last match wins" needs: a new rule is the most recent statement about a
    /// target, so it must be able to override everything before it.
    pub fn add_rule(&mut self, mut r: ScopeRule) -> u64 {
        self.next_rule_id += 1;
        r.id = self.next_rule_id;
        self.rules.push(r);
        self.next_rule_id
    }

    /// Chaining form of [`Scope::add_rule`], for building a scope up in one expression.
    pub fn add(&mut self, r: ScopeRule) -> &mut Self {
        self.add_rule(r);
        self
    }

    /// Drop the rule with this id, returning it. `None` when no rule has that id.
    ///
    /// By id, not by index, and the reason is asymmetric risk: removing an `include` narrows scope,
    /// which fails safe, but removing an `exclude` **widens** it. Positions shift on every edit, so
    /// index-based removal against a stale view can delete the exclude sitting next to the include
    /// the caller meant — and authorise everything that exclude was refusing.
    pub fn remove_rule(&mut self, id: u64) -> Option<ScopeRule> {
        let at = self.rules.iter().position(|r| r.id == id)?;
        Some(self.rules.remove(at))
    }

    /// Is this target authorised?
    pub fn contains(&self, host: &str, port: u16, path: &str, tls: bool) -> bool {
        if self.allow_all {
            return true;
        }
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut verdict = false;
        for r in &self.rules {
            if r.matches(&h, port, path, tls) {
                verdict = r.kind == RuleKind::Include;
            }
        }
        verdict
    }

    /// Could *any* path on this host be in scope? A pre-filter, **never an authorisation decision**.
    ///
    /// This replaced a `contains(host, port, "/", tls)` shortcut that was wrong in both directions,
    /// because asking about one arbitrary path cannot answer a question about a host:
    ///
    /// * `include(h).with_path_prefix("/v1/")` made it **false** — every attack on `h` was refused,
    ///   including attacks on `/v1/` paths that were explicitly authorised.
    /// * `include(h)` + `exclude(h).with_path_prefix("/admin")` made it **true**, and callers took
    ///   that as permission for the whole host — so a request that later resolved to `/admin` went
    ///   out against an explicitly excluded path.
    ///
    /// So this answers only "is this host worth considering at all", deliberately permissively: a
    /// path-scoped exclude removes paths, not the host. The real decision belongs to
    /// [`Scope::authorise_request`], on the bytes actually going on the wire.
    pub fn may_contain_host(&self, host: &str, port: u16, tls: bool) -> bool {
        if self.allow_all {
            return true;
        }
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut possible = false;
        for r in &self.rules {
            if !r.matches_host(&h, port, tls) {
                continue;
            }
            match (r.kind, r.path_prefix.is_some()) {
                (RuleKind::Include, _) => possible = true,
                // Only a whole-host exclude puts the host beyond reach. One scoped to a path
                // removes some paths and leaves the rest reachable.
                (RuleKind::Exclude, false) => possible = false,
                (RuleKind::Exclude, true) => {}
            }
        }
        possible
    }

    /// Is *every* path on this host:port authorised? Stricter than [`Scope::may_contain_host`], for
    /// callers that cannot see the path at all.
    ///
    /// This exists for the h2 egress path: a request built from raw HPACK-encoded header fields may
    /// carry a `:path` the sender never decoded, so there is no path string to hand to [`Scope::contains`].
    /// The only sound question left to ask is whether the *whole* host:port is authorised, i.e. every
    /// path on it — not `contains(host, port, "/", tls)`, which answers a question about one specific
    /// path (`/`) and says nothing about the rest. Reusing that shortcut here would repeat the exact
    /// bug [`Scope::may_contain_host`]'s doc comment describes: an `include(h)` + path-scoped
    /// `exclude(h, "/admin")` pair makes `contains(h, p, "/", tls)` true, and a caller treating that as
    /// "the whole host is fine" would send an opaque request straight at `/admin`.
    ///
    /// So this is deliberately the conservative twin of `may_contain_host`, not its synonym:
    ///
    /// * `true` only when `allow_all` is set, or some include rule matches this host/port/tls with no
    ///   `path_prefix` of its own (so it really does cover every path) **and** no exclude rule matches
    ///   this host/port/tls at all — including a path-scoped exclude, which `may_contain_host` ignores
    ///   on purpose but which this method cannot: it has no path to test the exclude's prefix against.
    /// * `false` for an empty scope, for a path-scoped include with no unscoped include backing it up,
    ///   and for any rule naming a different host or a different port.
    ///
    /// The asymmetry is deliberate: a wrong `true` here sends unauthorised traffic outside the
    /// engagement, while a wrong `false` only refuses a request the operator can re-authorise by
    /// widening scope. When in doubt, refuse.
    pub fn authorises_whole_host(&self, host: &str, port: u16, tls: bool) -> bool {
        if self.allow_all {
            return true;
        }
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut host_wide_include = false;
        for r in &self.rules {
            if !r.matches_host(&h, port, tls) {
                continue;
            }
            match r.kind {
                RuleKind::Exclude => return false,
                RuleKind::Include if r.path_prefix.is_none() => host_wide_include = true,
                RuleKind::Include => {}
            }
        }
        host_wide_include
    }

    /// Authorise the request that is about to be sent, from its own bytes.
    ///
    /// This is the decision that matters. Every earlier check is against the target the operator
    /// *named*; this one is against the request actually produced — after an Intruder payload has
    /// been spliced into a path position, or a BCheck `replacing path:` has rewritten it. Those
    /// mutations can move a request onto a path the operator excluded, and nothing upstream sees it.
    ///
    /// Unparseable bytes are refused rather than waved through: a request whose path cannot be read
    /// is a request whose authorisation cannot be established.
    pub fn authorise_request(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        raw: &[u8],
    ) -> Result<(), String> {
        let Some(path) = request_path(raw) else {
            return Err(
                "refused: request has no readable request line to check scope against".into(),
            );
        };
        if self.contains(host, port, path, tls) {
            return Ok(());
        }
        Err(format!(
            "refused: {} — {}",
            path,
            self.explain(host, port, path, tls)
        ))
    }

    /// Why a target was refused, for error messages and audit trails.
    pub fn explain(&self, host: &str, port: u16, path: &str, tls: bool) -> String {
        if self.allow_all {
            return "in scope (scope is set to allow everything)".into();
        }
        if self.rules.is_empty() {
            return format!(
                "out of scope: no scope rules are configured, so nothing is authorised (add an include rule for {host})"
            );
        }
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut last: Option<&ScopeRule> = None;
        for r in &self.rules {
            if r.matches(&h, port, path, tls) {
                last = Some(r);
            }
        }
        match last {
            Some(r) if r.kind == RuleKind::Include => format!("in scope via {r:?}"),
            Some(r) => format!("out of scope: excluded by {r:?}"),
            None => format!("out of scope: {host}:{port} matches no rule"),
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.allow_all && self.rules.is_empty()
    }
}

/// One [`Scope`], shared by every subsystem and editable while the tool runs.
///
/// # Why a handle and not an `Arc<Scope>`
///
/// This replaced `Arc<Scope>`, which was cheap to clone precisely because it could not change. Six
/// subsystems each took `Arc::new(scope.clone())` at startup, so there were six independent scopes
/// that happened to agree. Making one of them mutable would have produced the worst possible
/// outcome — the API showing an edited rule list while the proxy kept capturing by the startup rules
/// and the sender kept authorising by them. Every holder now clones *this*, so there is one rule list
/// and one answer.
///
/// # Why the read methods forward instead of exposing the lock
///
/// [`SharedScope::contains`] and friends mirror the [`Scope`] methods of the same name, taking and
/// dropping the read lock inside the call. That is deliberate: every caller is either a proxy
/// connection task or an attack loop, and a guard handed out to them could be held across an `.await`
/// — where a single operator edit waiting on the write lock would stall every in-flight request. A
/// forwarded call cannot make that mistake. [`SharedScope::read`] exists for the one case that needs
/// the whole value (report generation), and [`SharedScope::snapshot`] is the allocating alternative
/// for callers that would otherwise hold the guard while they work.
#[derive(Clone, Default)]
pub struct SharedScope(Arc<RwLock<Scope>>);

impl SharedScope {
    pub fn new(scope: Scope) -> Self {
        Self(Arc::new(RwLock::new(scope)))
    }

    /// A shared scope that authorises nothing until rules are added.
    pub fn empty() -> Self {
        Self::new(Scope::new())
    }

    /// Same decision as [`Scope::allow_everything`], and named the same so it reads that way here too.
    pub fn allow_everything() -> Self {
        Self::new(Scope::allow_everything())
    }

    /// The rules themselves. Prefer the forwarded methods; see the type docs for why.
    pub fn read(&self) -> RwLockReadGuard<'_, Scope> {
        self.0.read()
    }

    /// An owned copy, for callers that need a `&Scope` for a while without pinning the lock.
    pub fn snapshot(&self) -> Scope {
        self.0.read().clone()
    }

    /// Replace every rule at once. The startup path and nothing else — a partial edit belongs in
    /// [`Self::add_rule`]/[`Self::remove_rule`], which say what changed.
    pub fn replace(&self, scope: Scope) {
        *self.0.write() = scope;
    }

    /// Add a rule and return its id. See [`Scope::add_rule`].
    pub fn add_rule(&self, r: ScopeRule) -> u64 {
        self.0.write().add_rule(r)
    }

    /// Remove the rule with this id. See [`Scope::remove_rule`].
    pub fn remove_rule(&self, id: u64) -> Option<ScopeRule> {
        self.0.write().remove_rule(id)
    }

    /// See [`Scope::contains`].
    pub fn contains(&self, host: &str, port: u16, path: &str, tls: bool) -> bool {
        self.0.read().contains(host, port, path, tls)
    }

    /// See [`Scope::may_contain_host`].
    pub fn may_contain_host(&self, host: &str, port: u16, tls: bool) -> bool {
        self.0.read().may_contain_host(host, port, tls)
    }

    /// See [`Scope::authorises_whole_host`].
    pub fn authorises_whole_host(&self, host: &str, port: u16, tls: bool) -> bool {
        self.0.read().authorises_whole_host(host, port, tls)
    }

    /// See [`Scope::authorise_request`].
    pub fn authorise_request(
        &self,
        host: &str,
        port: u16,
        tls: bool,
        raw: &[u8],
    ) -> Result<(), String> {
        self.0.read().authorise_request(host, port, tls, raw)
    }

    /// See [`Scope::explain`].
    pub fn explain(&self, host: &str, port: u16, path: &str, tls: bool) -> String {
        self.0.read().explain(host, port, path, tls)
    }

    /// See [`Scope::is_empty`].
    pub fn is_empty(&self) -> bool {
        self.0.read().is_empty()
    }

    pub fn allow_all(&self) -> bool {
        self.0.read().allow_all
    }

    /// The rules, cloned. For the API's scope listing, which serialises them anyway.
    pub fn rules(&self) -> Vec<ScopeRule> {
        self.0.read().rules.clone()
    }
}

/// So `with_scope(Scope::allow_everything())` still reads the way it always did.
///
/// Note what this does *not* do: it builds a **new** handle. Passing an owned `Scope` means "start a
/// fresh shared scope from these rules"; sharing an existing one means cloning the `SharedScope`. The
/// distinction is visible at the call site, which is where it needs to be.
impl From<Scope> for SharedScope {
    fn from(s: Scope) -> Self {
        Self::new(s)
    }
}

impl std::fmt::Debug for SharedScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SharedScope").field(&*self.0.read()).finish()
    }
}

/// Is this a host pattern [`host_matches`] can actually act on?
///
/// Lives next to `host_matches` because it is the same knowledge stated the other way round: the
/// matcher understands an exact host or one leading `*.`, and treats anything else as a literal. A
/// pattern like `a*.test` therefore matches nothing, and which way that fails depends on the rule it
/// is attached to:
///
/// * on an `include`, it fails closed — the operator's traffic is refused and they find out at once;
/// * on an `exclude`, it fails **open** — the rule holds nothing back while appearing in the rule list
///   as though it does, and the operator believes a host is protected when it is not.
///
/// That second case is why this is a hard error at the API boundary rather than a lint. It did not
/// need to exist while rules came only from `--scope-include`/`--scope-exclude`, where a typo shows up
/// in the shell the operator is looking at.
pub fn validate_host_pattern(pattern: &str) -> Result<(), String> {
    let p = pattern.trim();
    if p.is_empty() {
        return Err("a scope rule needs a host".into());
    }
    let stars = p.matches('*').count();
    if stars > 1 || (stars == 1 && !p.starts_with("*.")) {
        return Err(format!(
            "{pattern:?} is not a host pattern: exactly one leading `*.` is supported and nothing \
             else wildcards, so this rule would match no host at all"
        ));
    }
    if p == "*." {
        return Err("`*.` on its own has no domain to match under".into());
    }
    if p.contains('/') || p.contains(char::is_whitespace) {
        return Err(format!(
            "{pattern:?} is a host, not a URL — put a path in the rule's path prefix instead"
        ));
    }
    Ok(())
}

/// Case-insensitive host match with one optional leading `*.` wildcard.
///
/// `*.a.com` matches `x.a.com` but NOT the apex `a.com` — matching the parent would silently widen
/// authorisation, which is the failure that matters here.
fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        h.len() > suffix.len()
            && h.ends_with(suffix)
            && h.as_bytes()[h.len() - suffix.len() - 1] == b'.'
    } else {
        h == p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the two-layer authorisation model -------------------------------------------------
    //
    // These pin the defect that `contains_host` used to have: it asked `contains(host, port, "/")`,
    // and one arbitrary path cannot answer a question about a host. It was wrong in both
    // directions, and the fail-open direction let an attack reach an explicitly excluded path.

    fn shop() -> Scope {
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("shop.test"));
        sc.add(ScopeRule::exclude("shop.test").with_path_prefix("/admin"));
        sc
    }

    #[test]
    fn a_path_scoped_exclude_does_not_put_the_whole_host_out_of_reach() {
        // The pre-filter must stay permissive, or scoping out one path would disable the tool.
        assert!(shop().may_contain_host("shop.test", 443, true));
    }

    #[test]
    fn an_excluded_path_is_refused_even_though_the_host_is_allowed() {
        // The fail-open case. The host gate says yes; the request itself must still be refused.
        let sc = shop();
        let raw = b"GET /admin/delete-all HTTP/1.1\r\nHost: shop.test\r\n\r\n";
        let err = sc
            .authorise_request("shop.test", 443, true, raw)
            .expect_err("an excluded path must not be authorised");
        assert!(
            err.contains("/admin/delete-all"),
            "unhelpful refusal: {err}"
        );
        // And the ordinary path on the same host still works, or the fix would be a regression.
        assert!(
            sc.authorise_request("shop.test", 443, true, b"GET /search HTTP/1.1\r\n\r\n")
                .is_ok()
        );
    }

    #[test]
    fn a_host_scoped_to_a_path_prefix_is_not_refused_wholesale() {
        // The fail-closed case: `contains_host` returned false here, so every attack 403'd even
        // against paths that were explicitly in scope.
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("api.test").with_path_prefix("/v1/"));
        assert!(
            sc.may_contain_host("api.test", 443, true),
            "pre-filter must let this through"
        );
        assert!(
            sc.authorise_request("api.test", 443, true, b"GET /v1/orders HTTP/1.1\r\n\r\n")
                .is_ok()
        );
        assert!(
            sc.authorise_request("api.test", 443, true, b"GET /v2/orders HTTP/1.1\r\n\r\n")
                .is_err(),
            "/v2/ is outside the included prefix"
        );
    }

    // ---- authorises_whole_host: the conservative predicate for opaque-path (h2) egress ------

    #[test]
    fn an_empty_scope_does_not_authorise_a_whole_host() {
        let sc = Scope::new();
        assert!(!sc.authorises_whole_host("anything.test", 443, true));
    }

    #[test]
    fn allow_all_authorises_a_whole_host() {
        let sc = Scope::allow_everything();
        assert!(sc.authorises_whole_host("anything.test", 443, true));
    }

    #[test]
    fn a_host_wide_include_authorises_the_whole_host() {
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("api.test"));
        assert!(sc.authorises_whole_host("api.test", 443, true));
    }

    #[test]
    fn a_path_scoped_include_does_not_authorise_the_whole_host_even_though_contains_matches_its_path()
     {
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("api.test").with_path_prefix("/v1/"));
        // contains() is happy about the one path it was asked about...
        assert!(sc.contains("api.test", 443, "/v1/orders", true));
        // ...but that says nothing about paths the caller can't name, which is exactly the gap
        // authorises_whole_host exists to close.
        assert!(!sc.authorises_whole_host("api.test", 443, true));
    }

    #[test]
    fn a_host_wide_include_plus_any_exclude_on_that_host_does_not_authorise_the_whole_host() {
        // Even a path-scoped exclude disqualifies the host here: unlike may_contain_host, this
        // predicate has no path to test the exclude's prefix against, so it must refuse.
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("api.test"));
        sc.add(ScopeRule::exclude("api.test").with_path_prefix("/admin"));
        assert!(!sc.authorises_whole_host("api.test", 443, true));

        let mut sc_whole = Scope::new();
        sc_whole.add(ScopeRule::include("api.test"));
        sc_whole.add(ScopeRule::exclude("api.test"));
        assert!(!sc_whole.authorises_whole_host("api.test", 443, true));
    }

    #[test]
    fn a_rule_for_a_different_host_or_port_does_not_authorise_this_one() {
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("api.test").with_port(443));
        assert!(!sc.authorises_whole_host("other.test", 443, true));
        assert!(!sc.authorises_whole_host("api.test", 8443, true));
    }

    #[test]
    fn a_whole_host_exclude_does_put_the_host_out_of_reach() {
        // The pre-filter is permissive about *path* rules, not about host rules.
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("*.test"));
        sc.add(ScopeRule::exclude("prod.test"));
        assert!(sc.may_contain_host("staging.test", 443, true));
        assert!(!sc.may_contain_host("prod.test", 443, true));
    }

    #[test]
    fn an_empty_scope_authorises_nothing() {
        let sc = Scope::new();
        assert!(!sc.may_contain_host("anything.test", 443, true));
        assert!(
            sc.authorise_request("anything.test", 443, true, b"GET / HTTP/1.1\r\n\r\n")
                .is_err()
        );
    }

    #[test]
    fn a_request_with_no_readable_start_line_is_refused_not_waved_through() {
        // Absence of a path must never read as "nothing to check".
        let mut sc = Scope::new();
        sc.add(ScopeRule::include("shop.test"));
        assert!(sc.authorise_request("shop.test", 443, true, b"").is_err());
        assert!(
            sc.authorise_request("shop.test", 443, true, b"GARBAGE")
                .is_err()
        );
    }

    #[test]
    fn request_path_reads_both_origin_and_absolute_form() {
        assert_eq!(request_path(b"GET /a?b=1 HTTP/1.1\r\n"), Some("/a"));
        assert_eq!(
            request_path(b"GET http://h.test/a?b=1 HTTP/1.1\r\n"),
            Some("/a")
        );
        // A proxied absolute-form request with no path at all addresses the root.
        assert_eq!(request_path(b"GET http://h.test HTTP/1.1\r\n"), Some("/"));
        assert_eq!(request_path(b"POST /x HTTP/1.1"), Some("/x"));
        assert_eq!(request_path(b""), None);
    }

    #[test]
    fn the_query_string_cannot_smuggle_a_path_past_a_prefix_rule() {
        // `/search?next=/admin` is a request for /search. The rule is about the path, and a query
        // that merely mentions the excluded prefix must not trip it.
        let sc = shop();
        assert!(
            sc.authorise_request(
                "shop.test",
                443,
                true,
                b"GET /search?next=/admin HTTP/1.1\r\n\r\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn empty_scope_denies_everything() {
        let s = Scope::new();
        assert!(!s.contains("anything.test", 443, "/", true));
        assert!(s.is_empty());
        assert!(
            s.explain("anything.test", 443, "/", true)
                .contains("no scope rules")
        );
    }

    #[test]
    fn include_then_exclude_last_match_wins() {
        let mut s = Scope::new();
        s.add(ScopeRule::include("*.target.test"))
            .add(ScopeRule::exclude("admin.target.test"));
        assert!(s.contains("app.target.test", 443, "/", true));
        assert!(!s.contains("admin.target.test", 443, "/", true));
        assert!(
            s.explain("admin.target.test", 443, "/", true)
                .contains("excluded by")
        );
    }

    #[test]
    fn exclude_then_reinclude_also_works() {
        // Order matters both ways: a later include must be able to carve back in.
        let mut s = Scope::new();
        s.add(ScopeRule::include("*.target.test"))
            .add(ScopeRule::exclude("*.target.test"))
            .add(ScopeRule::include("ok.target.test"));
        assert!(!s.contains("other.target.test", 443, "/", true));
        assert!(s.contains("ok.target.test", 443, "/", true));
    }

    #[test]
    fn wildcard_never_matches_the_apex() {
        let mut s = Scope::new();
        s.add(ScopeRule::include("*.target.test"));
        assert!(s.contains("a.target.test", 443, "/", true));
        assert!(s.contains("a.b.target.test", 443, "/", true));
        // The apex and lookalikes must stay out.
        assert!(!s.contains("target.test", 443, "/", true));
        assert!(!s.contains("nottarget.test", 443, "/", true));
        assert!(!s.contains("evil-target.test", 443, "/", true));
    }

    #[test]
    fn port_and_path_and_tls_constraints() {
        let mut s = Scope::new();
        s.add(
            ScopeRule::include("api.test")
                .with_port(8443)
                .with_path_prefix("/v1/")
                .with_tls(true),
        );
        assert!(s.contains("api.test", 8443, "/v1/users", true));
        assert!(
            !s.contains("api.test", 8443, "/v2/users", true),
            "path prefix must bind"
        );
        assert!(
            !s.contains("api.test", 443, "/v1/users", true),
            "port must bind"
        );
        assert!(
            !s.contains("api.test", 8443, "/v1/users", false),
            "tls must bind"
        );
    }

    #[test]
    fn allow_everything_is_explicit_and_total() {
        let s = Scope::allow_everything();
        assert!(s.contains("anything.at.all", 1, "/x", false));
        assert!(!s.is_empty());
        assert!(s.explain("x", 1, "/", false).contains("allow everything"));
    }

    // ---- runtime editing ------------------------------------------------------------------------

    #[test]
    fn rule_ids_are_unique_and_never_reused() {
        let mut s = Scope::new();
        let a = s.add_rule(ScopeRule::include("a.test"));
        let b = s.add_rule(ScopeRule::include("b.test"));
        assert_ne!(a, b);
        assert!(s.remove_rule(a).is_some());
        let c = s.add_rule(ScopeRule::include("c.test"));
        assert_ne!(
            c, a,
            "a removed id must not come back — a stale client would reuse it"
        );
        assert_ne!(c, b);
        // The chaining form assigns ids too, or a scope built with `add` could not be edited.
        let mut chained = Scope::new();
        chained
            .add(ScopeRule::include("x.test"))
            .add(ScopeRule::include("y.test"));
        assert!(chained.rules.iter().all(|r| r.id != 0));
    }

    #[test]
    fn removing_a_rule_by_id_survives_the_positions_shifting() {
        // The whole reason ids exist: the exclude is at index 1 now and index 0 after the include
        // goes, so an index-based remove against a stale view would delete the exclude and authorise
        // /admin.
        let mut s = Scope::new();
        let include = s.add_rule(ScopeRule::include("shop.test"));
        let exclude = s.add_rule(ScopeRule::exclude("shop.test").with_path_prefix("/admin"));
        let extra = s.add_rule(ScopeRule::include("other.test"));
        assert!(s.remove_rule(include).is_some());
        assert!(
            !s.contains("shop.test", 443, "/", true),
            "the include is gone"
        );
        let removed = s
            .remove_rule(exclude)
            .expect("the exclude is still addressable by id");
        assert_eq!(removed.kind, RuleKind::Exclude);
        assert_eq!(s.rules.len(), 1);
        assert_eq!(s.rules[0].id, extra);
        assert!(
            s.remove_rule(exclude).is_none(),
            "removing twice is not an error, it is a no-op"
        );
    }

    #[test]
    fn an_added_rule_overrides_the_ones_before_it() {
        // Append, not insert: a new rule is the most recent statement, and "last match wins" is what
        // makes an operator's edit actually take effect.
        let s = SharedScope::empty();
        assert!(!s.contains("shop.test", 443, "/", true));
        s.add_rule(ScopeRule::include("*.shop.test"));
        assert!(s.contains("a.shop.test", 443, "/", true));
        let block = s.add_rule(ScopeRule::exclude("admin.shop.test"));
        assert!(!s.contains("admin.shop.test", 443, "/", true));
        // And removing the exclude widens scope back — the direction that needs a confirmation step
        // in front of it.
        s.remove_rule(block);
        assert!(s.contains("admin.shop.test", 443, "/", true));
    }

    #[test]
    fn every_holder_of_a_cloned_handle_sees_the_edit() {
        // This is the defect the old `Arc<Scope>` wiring had: each subsystem cloned the *value*, so
        // an edit would have moved the UI and left the proxy and the sender on the startup rules.
        let a = SharedScope::empty();
        let b = a.clone();
        let raw = b"GET /x HTTP/1.1\r\nHost: late.test\r\n\r\n";
        assert!(b.authorise_request("late.test", 443, true, raw).is_err());
        a.add_rule(ScopeRule::include("late.test"));
        assert!(
            b.authorise_request("late.test", 443, true, raw).is_ok(),
            "a clone of the handle must read the same rules, not a snapshot of them"
        );
        assert!(a.may_contain_host("late.test", 443, true));
        assert_eq!(b.rules().len(), 1);
        assert!(!b.is_empty());
    }

    #[test]
    fn a_shared_scope_can_be_edited_while_other_threads_read_it() {
        // Reads forward through the lock rather than handing a guard out, so this must not deadlock
        // and must not tear: every read sees either the old rule set or the new one.
        let s = SharedScope::empty();
        s.add_rule(ScopeRule::include("stable.test"));
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let s = s.clone();
                std::thread::spawn(move || {
                    for _ in 0..250 {
                        assert!(s.contains("stable.test", 443, "/", true));
                    }
                })
            })
            .collect();
        for i in 0..250 {
            let id = s.add_rule(ScopeRule::include(format!("churn{i}.test")));
            s.remove_rule(id);
        }
        for r in readers {
            r.join().expect("reader panicked");
        }
        assert_eq!(s.rules().len(), 1);
    }

    #[test]
    fn a_scope_round_trips_through_json_without_its_ids_colliding() {
        // `id` and `next_rule_id` are `#[serde(default)]`, so scope written before they existed still
        // loads — but then the next id must not collide with a rule already in the list.
        let old = r#"{"rules":[{"kind":"Include","host":"a.test","port":null,"path_prefix":null,"tls":null}]}"#;
        let mut s: Scope = serde_json::from_str(old).expect("legacy scope must still deserialise");
        assert_eq!(s.rules[0].id, 0, "a legacy rule has no id");
        let fresh = s.add_rule(ScopeRule::include("b.test"));
        assert_ne!(fresh, 0, "a newly added rule must be addressable");
        assert!(s.remove_rule(fresh).is_some());

        let mut s = Scope::new();
        s.add_rule(ScopeRule::include("a.test"));
        let back: Scope = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        let next = {
            let mut b = back;
            b.add_rule(ScopeRule::include("c.test"))
        };
        assert!(
            next > s.rules[0].id,
            "the id counter must survive the round trip"
        );
    }

    #[test]
    fn trailing_dot_and_case_are_normalised() {
        let mut s = Scope::new();
        s.add(ScopeRule::include("Target.Test"));
        assert!(s.contains("target.test.", 443, "/", true));
        assert!(s.contains("TARGET.TEST", 443, "/", true));
    }
}
