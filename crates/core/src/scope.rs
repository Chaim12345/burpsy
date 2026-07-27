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

    fn matches(&self, host: &str, port: u16, path: &str, tls: bool) -> bool {
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
        if let Some(prefix) = &self.path_prefix
            && !path.starts_with(prefix.as_str())
        {
            return false;
        }
        true
    }
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

    /// Convenience for callers that only know host and port.
    pub fn contains_host(&self, host: &str, port: u16, tls: bool) -> bool {
        self.contains(host, port, "/", tls)
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

    #[test]
    fn empty_scope_denies_everything() {
        let s = Scope::new();
        assert!(!s.contains("anything.test", 443, "/", true));
        assert!(s.is_empty());
        assert!(s.explain("anything.test", 443, "/", true).contains("no scope rules"));
    }

    #[test]
    fn include_then_exclude_last_match_wins() {
        let mut s = Scope::new();
        s.add(ScopeRule::include("*.target.test"))
            .add(ScopeRule::exclude("admin.target.test"));
        assert!(s.contains("app.target.test", 443, "/", true));
        assert!(!s.contains("admin.target.test", 443, "/", true));
        assert!(s.explain("admin.target.test", 443, "/", true).contains("excluded by"));
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
        assert!(!s.contains("api.test", 8443, "/v2/users", true), "path prefix must bind");
        assert!(!s.contains("api.test", 443, "/v1/users", true), "port must bind");
        assert!(!s.contains("api.test", 8443, "/v1/users", false), "tls must bind");
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
