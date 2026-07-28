//! A per-host cookie jar carrying state between a macro's steps and into the request it repairs.
//!
//! Real cookie handling (RFC 6265) resolves `Domain`/`Path` attributes against a public suffix
//! list so a cookie set by `sub.example.com` can be scoped correctly to `example.com`. That
//! machinery is deliberately not here: this jar keys strictly by the authority (`host[:port]`) of
//! the URL a step was actually sent to. That is exactly right for what this crate exists for — one
//! recorded macro replayed against one target — and wrong only for a multi-domain federated-login
//! flow, which is out of scope for a first cut. Getting that right later means teaching
//! [`CookieJar::absorb_set_cookie`] to parse the `Domain` attribute, not rearchitecting the jar.

use std::collections::HashMap;

/// Cookies observed so far, grouped by the host they were set on.
///
/// SESSION-03 asks for one jar shared across tools. This type is that jar; the sharing itself —
/// handing the same jar to Proxy, Repeater and Intruder — is wiring this crate does not do, the
/// same way it does not wire [`crate::MacroSender`] to a real transport. See
/// [`crate::ReloginCoordinator::shared_jar`].
#[derive(Debug, Default, Clone)]
pub struct CookieJar {
    by_host: HashMap<String, HashMap<String, String>>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// The `Cookie` header value to send to `host`, or `None` if the jar holds nothing for it —
    /// distinct from an empty string, so a caller never sends a header that names no cookies.
    pub fn cookie_header(&self, host: &str) -> Option<String> {
        let cookies = self.by_host.get(host)?;
        if cookies.is_empty() {
            return None;
        }
        // Sorted by name so the header is deterministic across runs, which is what makes the
        // cookie-jar tests (and a caller that logs the outgoing request) reproducible.
        let mut pairs: Vec<String> = cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
        pairs.sort();
        Some(pairs.join("; "))
    }

    /// Record one `Set-Cookie` header's value against `host`, keeping only the `name=value` pair
    /// and ignoring attributes (`Path`, `Domain`, `Secure`, `Max-Age`, ...) — the jar's replay
    /// scope is already the exact host it is keyed by, so there is nothing an attribute would
    /// narrow or widen it to. A header with no `=` names nothing to store and is ignored rather
    /// than treated as a malformed-input error: a macro replay should not abort over one cookie
    /// this jar cannot make sense of.
    pub fn absorb_set_cookie(&mut self, host: &str, raw: &str) {
        let Some((name, value)) = parse_name_value(raw) else {
            return;
        };
        self.by_host
            .entry(host.to_string())
            .or_default()
            .insert(name, value);
    }
}

fn parse_name_value(raw: &str) -> Option<(String, String)> {
    let first = raw.split(';').next()?.trim();
    let (name, value) = first.split_once('=')?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

/// The authority (`host[:port]`) a URL would be sent to, used as the jar's key.
///
/// Deliberately not a full URL parser: no userinfo, query, or fragment handling beyond what is
/// needed to find where the authority ends. A macro step's URL is operator-recorded, not
/// attacker-controlled, so the failure mode of a too-simple parser here is a wrongly-scoped test
/// cookie, not a security hole.
pub(crate) fn host_of(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    if authority.is_empty() {
        None
    } else {
        Some(authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_jar_has_no_cookie_header_for_any_host() {
        let jar = CookieJar::new();
        assert_eq!(jar.cookie_header("target.test"), None);
    }

    #[test]
    fn an_absorbed_cookie_round_trips_into_the_header_for_its_host() {
        let mut jar = CookieJar::new();
        jar.absorb_set_cookie("target.test", "session=abc123; Path=/; HttpOnly");
        assert_eq!(
            jar.cookie_header("target.test"),
            Some("session=abc123".to_string())
        );
    }

    #[test]
    fn cookies_do_not_leak_across_hosts() {
        let mut jar = CookieJar::new();
        jar.absorb_set_cookie("a.test", "session=for-a");
        assert_eq!(
            jar.cookie_header("b.test"),
            None,
            "a cookie set on a.test must not appear for b.test"
        );
        assert_eq!(
            jar.cookie_header("a.test"),
            Some("session=for-a".to_string())
        );
    }

    #[test]
    fn multiple_cookies_for_one_host_are_joined_in_a_deterministic_order() {
        let mut jar = CookieJar::new();
        jar.absorb_set_cookie("target.test", "zeta=1");
        jar.absorb_set_cookie("target.test", "alpha=2");
        assert_eq!(
            jar.cookie_header("target.test"),
            Some("alpha=2; zeta=1".to_string())
        );
    }

    #[test]
    fn a_later_set_cookie_for_the_same_name_replaces_the_earlier_value() {
        let mut jar = CookieJar::new();
        jar.absorb_set_cookie("target.test", "session=old");
        jar.absorb_set_cookie("target.test", "session=new");
        assert_eq!(
            jar.cookie_header("target.test"),
            Some("session=new".to_string())
        );
    }

    #[test]
    fn a_set_cookie_header_with_no_equals_sign_is_ignored_not_panicked_on() {
        let mut jar = CookieJar::new();
        jar.absorb_set_cookie("target.test", "garbage-no-equals-sign");
        assert_eq!(jar.cookie_header("target.test"), None);
    }

    #[test]
    fn host_of_extracts_the_authority_from_a_url_with_or_without_a_scheme() {
        assert_eq!(host_of("https://target.test/login"), Some("target.test"));
        assert_eq!(
            host_of("http://target.test:8080/a?b=c"),
            Some("target.test:8080")
        );
        assert_eq!(host_of("target.test/no-scheme"), Some("target.test"));
    }
}
