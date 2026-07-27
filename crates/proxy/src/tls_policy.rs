//! TLS policy: which hosts get intercepted and which are tunnelled blind.
//!
//! # Why passthrough is mandatory, not a nicety
//!
//! MITM breaks three classes of client outright, and no amount of correct certificate generation
//! helps:
//!
//! * **Certificate pinning** — mobile apps and some desktop clients compare the served cert or its
//!   public key against a baked-in value. A burpsy-signed leaf fails by design.
//! * **TLS client authentication** — the client must present its own cert to the *real* server. We
//!   cannot forward a challenge we terminated.
//! * **Non-HTTP over 443** — gRPC, MQTT-over-TLS, arbitrary tunnels. Parsing them as HTTP corrupts
//!   the stream.
//!
//! Burp ships the same escape hatch for the same reasons. Without it, the first pinned app a tester
//! meets makes the whole proxy unusable and they cannot tell why.
//!
//! Default posture is **intercept everything**, with an explicit deny-list — the opposite would
//! silently hide traffic.

use serde::{Deserialize, Serialize};

/// What to do with a `CONNECT` to a given host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsAction {
    /// Terminate TLS, read plaintext, re-encrypt upstream.
    Intercept,
    /// Splice the sockets without decrypting. Recorded, but opaque.
    Passthrough,
}

/// Host patterns that must not be intercepted.
///
/// Patterns are matched against the `CONNECT` host (no port) and support a single leading `*.`
/// wildcard, which is the form that actually occurs in practice. Deliberately not full regex:
/// a mistyped regex that silently matches nothing would hide traffic, and the failure would be
/// invisible.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsPolicy {
    /// e.g. `["*.apple.com", "pinned.internal", "*.push.example"]`
    pub passthrough: Vec<String>,
    /// Ports never intercepted regardless of host (e.g. non-HTTP TLS services).
    #[serde(default)]
    pub passthrough_ports: Vec<u16>,
}

impl TlsPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// A starting deny-list of hosts that are pinned or hostile to interception in practice.
    ///
    /// Not exhaustive and not meant to be — it exists so a first run does not immediately break
    /// OS/browser background traffic and send the user hunting.
    pub fn with_common_defaults() -> Self {
        Self {
            passthrough: [
                // OS/browser update + telemetry channels, commonly pinned.
                "*.windowsupdate.com",
                "*.apple.com",
                "*.icloud.com",
                "*.googleapis.com",
                "*.gvt1.com",
                "*.mozilla.net",
                "*.mozilla.org",
                // Push/notification transports that are not plain HTTP.
                "*.push.apple.com",
                "mtalk.google.com",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            passthrough_ports: vec![],
        }
    }

    pub fn allow_all_intercept() -> Self {
        Self {
            passthrough: Vec::new(),
            passthrough_ports: Vec::new(),
        }
    }

    pub fn add_passthrough(&mut self, pattern: impl Into<String>) {
        self.passthrough.push(pattern.into());
    }

    /// Decide what to do with `host:port`.
    pub fn action_for(&self, host: &str, port: u16) -> TlsAction {
        if self.passthrough_ports.contains(&port) {
            return TlsAction::Passthrough;
        }
        // An IP literal has no SNI hostname to sign for; a leaf with an IP SAN is possible but
        // browsers are fussy about it, so leave those alone until IP SANs are implemented.
        if is_ip_literal(host) {
            return TlsAction::Passthrough;
        }
        for pat in &self.passthrough {
            if matches_host(pat, host) {
                return TlsAction::Passthrough;
            }
        }
        TlsAction::Intercept
    }

    /// Human-readable reason, for the note recorded on a passthrough exchange.
    pub fn reason_for(&self, host: &str, port: u16) -> Option<String> {
        if self.passthrough_ports.contains(&port) {
            return Some(format!("port {port} is on the passthrough list"));
        }
        if is_ip_literal(host) {
            return Some("IP-literal CONNECT: no SNI hostname to sign for".to_string());
        }
        self.passthrough
            .iter()
            .find(|p| matches_host(p, host))
            .map(|p| format!("host matches passthrough pattern {p:?}"))
    }
}

/// Case-insensitive host match with an optional single leading `*.` wildcard.
///
/// `*.a.com` matches `x.a.com` and `y.x.a.com` but NOT bare `a.com` — matching the parent on a
/// wildcard is a common bug and would silently widen the exemption.
fn matches_host(pattern: &str, host: &str) -> bool {
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

fn is_ip_literal(host: &str) -> bool {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_is_case_insensitive() {
        let mut p = TlsPolicy::new();
        p.add_passthrough("Pinned.Internal");
        assert_eq!(p.action_for("pinned.internal", 443), TlsAction::Passthrough);
        assert_eq!(p.action_for("other.internal", 443), TlsAction::Intercept);
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_the_parent() {
        let mut p = TlsPolicy::new();
        p.add_passthrough("*.a.com");
        assert_eq!(p.action_for("x.a.com", 443), TlsAction::Passthrough);
        assert_eq!(p.action_for("y.x.a.com", 443), TlsAction::Passthrough);
        // The parent must NOT match — widening a wildcard to its parent is the classic bug.
        assert_eq!(p.action_for("a.com", 443), TlsAction::Intercept);
        // And it must not match a domain that merely ends with the same text.
        assert_eq!(p.action_for("nota.com", 443), TlsAction::Intercept);
        assert_eq!(p.action_for("evil-a.com", 443), TlsAction::Intercept);
    }

    #[test]
    fn trailing_dot_is_normalised() {
        let mut p = TlsPolicy::new();
        p.add_passthrough("a.com");
        assert_eq!(p.action_for("a.com.", 443), TlsAction::Passthrough);
    }

    #[test]
    fn ip_literals_are_passed_through() {
        let p = TlsPolicy::allow_all_intercept();
        assert_eq!(p.action_for("127.0.0.1", 443), TlsAction::Passthrough);
        assert_eq!(p.action_for("::1", 443), TlsAction::Passthrough);
        assert!(
            p.reason_for("127.0.0.1", 443)
                .unwrap()
                .contains("IP-literal")
        );
    }

    #[test]
    fn port_list_wins() {
        let mut p = TlsPolicy::allow_all_intercept();
        p.passthrough_ports.push(8883);
        assert_eq!(p.action_for("mqtt.example", 8883), TlsAction::Passthrough);
        assert_eq!(p.action_for("mqtt.example", 443), TlsAction::Intercept);
    }

    #[test]
    fn default_posture_is_intercept() {
        let p = TlsPolicy::new();
        assert_eq!(p.action_for("anything.example", 443), TlsAction::Intercept);
        assert!(p.reason_for("anything.example", 443).is_none());
    }

    #[test]
    fn common_defaults_cover_pinned_hosts() {
        let p = TlsPolicy::with_common_defaults();
        assert_eq!(
            p.action_for("gateway.icloud.com", 443),
            TlsAction::Passthrough
        );
        assert_eq!(p.action_for("app.mytarget.test", 443), TlsAction::Intercept);
    }
}
