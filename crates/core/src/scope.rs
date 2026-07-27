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
//! Burp treats scope-widening as the one privileged operation in its whole agentic tool registry:
//! of 54 tools, `add_to_scope` is one of only four marked `ALWAYS_ESCALATE`, and its own description
//! says it "grants new authorization for hosts". Adding scope is the act that authorises traffic, so
//! it should be explicit and auditable rather than incidental.
//!
//! # Rule model
//!
//! Ordered rules, last match wins, mirroring how include/exclude lists actually behave in practice.
//! Default with no rules is **deny** — an empty scope must not silently authorise the internet.

use serde::{Deserialize, Serialize};

/// Include or exclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleKind {
    Include,
    Exclude,
}

/// One scope rule. Any unset field matches anything.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeRule {
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
        }
    }

    pub fn add(&mut self, r: ScopeRule) -> &mut Self {
        self.rules.push(r);
        self
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

    #[test]
    fn trailing_dot_and_case_are_normalised() {
        let mut s = Scope::new();
        s.add(ScopeRule::include("Target.Test"));
        assert!(s.contains("target.test.", 443, "/", true));
        assert!(s.contains("TARGET.TEST", 443, "/", true));
    }
}
