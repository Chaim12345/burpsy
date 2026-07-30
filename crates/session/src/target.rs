//! The pieces of a macro step's URL that scope matching and the cookie jar need — read by *one*
//! parser.
//!
//! Two questions get asked of the same URL: which jar entry it belongs to (the authority, exactly
//! as written) and whether a rule's [`burpsy_core::Scope`] covers it (host, port, path and
//! TLS-ness, with the scheme's defaults filled in). Answering them with two parsers is precisely how
//! the two halves of one URL end up disagreeing about where the host ends, so both answers come
//! from here — the same argument `session_sender::request_target` makes for reusing `parse_target`'s
//! notion of where the authority stops.
//!
//! Scheme defaults deliberately match `burpsy_sender::parse_target` (`https` → 443, `http` → 80,
//! no scheme → 80, unparseable port → the scheme's default): that is the parser the request is
//! actually dialled with, and a rule that matched on a different port than the one dialled would be
//! a scope decision about a request nobody sent.
//!
//! One deliberate divergence: the authority ends at the first `/`, `?` or `#`, where `parse_target`
//! only splits on `/`. That keeps this agreeing with the jar's own key for a URL like
//! `http://h.test?a=1` instead of keying it under `h.test?a=1`, and it is the stricter of the two.

/// The parts of a step URL a scope decision and a jar lookup need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StepTarget<'a> {
    /// `host[:port]` exactly as written — the cookie jar's key, which is deliberately literal.
    pub(crate) authority: &'a str,
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    /// Path only: the query and fragment are dropped, because scope rules are path prefixes and
    /// `burpsy_core::request_path` drops them too.
    pub(crate) path: &'a str,
    pub(crate) tls: bool,
}

/// Split a macro step's URL, or `None` when it names no host at all.
///
/// `None` is a refusal, never "no host, so nothing to check": a scoped rule cannot match a URL it
/// cannot read, and [`crate::SessionRule::new`] rejects such a URL at configuration time.
pub(crate) fn target_of(url: &str) -> Option<StepTarget<'_>> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        (false, url)
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // Whitespace cannot occur in an authority, so this is not a URL. Worth refusing rather than
    // accepting: `parse_target` reads `"not a url at all"` as a host named `not a url at all`, and
    // without this a typed-in sentence becomes a rule scoped to a host that cannot exist, which
    // surfaces only as a send failure later.
    if authority.is_empty() || authority.contains(char::is_whitespace) {
        return None;
    }
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(default_port)),
        None => (authority, default_port),
    };
    if host.is_empty() {
        return None;
    }
    let after = &rest[end..];
    let path = if after.starts_with('/') {
        let path_end = after.find(['?', '#']).unwrap_or(after.len());
        &after[..path_end]
    } else {
        // `http://h.test?a=1` and `http://h.test` both address the root.
        "/"
    };
    Some(StepTarget {
        authority,
        host,
        port,
        path,
        tls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_full_url_into_the_parts_a_scope_decision_needs() {
        let t = target_of("https://target.test:8443/login?next=/home#top").expect("parses");
        assert_eq!(t.authority, "target.test:8443");
        assert_eq!(t.host, "target.test");
        assert_eq!(t.port, 8443);
        assert_eq!(t.path, "/login", "the query must not become part of the path");
        assert!(t.tls);
    }

    #[test]
    fn fills_in_the_schemes_default_port_the_way_the_sender_does() {
        assert_eq!(target_of("https://a.test/x").expect("parses").port, 443);
        assert_eq!(target_of("http://a.test/x").expect("parses").port, 80);
        // No scheme is `parse_target`'s plain-http case, not an error.
        let bare = target_of("a.test/x").expect("parses");
        assert_eq!((bare.port, bare.tls), (80, false));
        // An unreadable port falls back rather than refusing, matching `parse_target`.
        assert_eq!(target_of("https://a.test:wat/x").expect("parses").port, 443);
    }

    #[test]
    fn a_url_naming_no_path_addresses_the_root() {
        assert_eq!(target_of("https://a.test").expect("parses").path, "/");
        assert_eq!(target_of("https://a.test?a=1").expect("parses").path, "/");
        assert_eq!(target_of("https://a.test/").expect("parses").path, "/");
    }

    #[test]
    fn a_url_with_no_host_is_refused_rather_than_defaulted() {
        assert_eq!(target_of(""), None);
        assert_eq!(target_of("https://"), None);
        assert_eq!(target_of("https://:8443/x"), None);
        assert_eq!(target_of("/just-a-path"), None);
    }

    #[test]
    fn something_that_is_not_a_url_is_refused_rather_than_read_as_a_host() {
        // `burpsy_sender::parse_target` accepts these as a host with an odd name; a rule scoped to
        // such a "host" could never match anything real, so a typo must not get that far.
        assert_eq!(target_of("not a url at all"), None);
        assert_eq!(target_of("http://two words.test/x"), None);
    }
}
