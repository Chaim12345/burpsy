//! burpsy-crawler — scope-aware frontier and link discovery over a driven browser.
//!
//! # Why this is native Rust and not delegated to an external tool
//!
//! Once a real browser is under burpsy's own control (`burpsy-browser`), most of what a tool like
//! katana adds on top — dedup, frontier ordering, JS-rendered link extraction — is ordinary logic
//! over CDP output, not something that needs a second language runtime. This crate is that logic.
//! It is deliberately kept separate from `burpsy-browser`: the browser crate knows how to drive one
//! page; this crate knows which page to drive next and whether it is allowed to.
//!
//! # Where scope is actually enforced here
//!
//! [`Frontier::enqueue`] checks [`burpsy_core::Scope::contains`] against the resolved URL's own
//! host/port/path *before* a navigation is ever attempted — a target this crawler was never told
//! to (and isn't authorised to) visit is never handed to the browser at all. This is a second,
//! earlier gate than the proxy's own capture policy, not a replacement for it: the browser's
//! traffic still egresses through burpsy's proxy per `burpsy-browser`'s own design, and that
//! remains the place a request is actually admitted or refused on the wire. Redirects and
//! JS-initiated fetches the frontier never queued are still subject to that gate even though this
//! crate never saw them coming.
//!
//! # What "discovery" means here, deliberately minimally
//!
//! Link extraction is `<a href>` targets read from the rendered DOM via one JS evaluation per
//! page — no form-fill heuristics, no dom-idle/network-idle timing, no JS-string endpoint
//! regexing. Those are real, worthwhile additions (Burp's own `dom_idle_threshold` /
//! `network_idle_threshold` config keys name exactly this problem), and are left for a later
//! phase rather than half-built here, per this project's rule against features that only look
//! finished.

use burpsy_browser::BrowserSession;
use burpsy_core::Scope;
use std::collections::{HashSet, VecDeque};
use url::Url;

/// A scope-gated, deduplicated queue of URLs still to visit.
///
/// Holds a [`Scope`] by value rather than a reference because a frontier's lifetime is a crawl's
/// lifetime, and a crawl should not be able to observe a scope change mid-run — the same
/// "decision made once, at the boundary" argument `AuthorisedSender` makes for attack traffic.
pub struct Frontier {
    scope: Scope,
    seen: HashSet<String>,
    pending: VecDeque<Url>,
}

impl Frontier {
    pub fn new(scope: Scope) -> Self {
        Self {
            scope,
            seen: HashSet::new(),
            pending: VecDeque::new(),
        }
    }

    /// Seed the frontier with a starting URL, bypassing dedup (there is nothing to dedup against
    /// yet) but not scope — a crawl cannot even start outside its own engagement.
    pub fn seed(&mut self, url: Url) -> bool {
        self.enqueue(url)
    }

    /// Resolve `href` against the page it was found on and enqueue the result, if new and in
    /// scope. Returns `false` for a relative reference that fails to resolve, one already queued,
    /// or one outside [`Scope`] — the caller does not need to distinguish those cases, only
    /// whether it should expect this URL to be visited.
    pub fn discover(&mut self, base: &Url, href: &str) -> bool {
        match base.join(href) {
            Ok(resolved) => self.enqueue(resolved),
            Err(_) => false,
        }
    }

    fn enqueue(&mut self, url: Url) -> bool {
        let key = normalize(&url);
        if self.seen.contains(&key) {
            return false;
        }
        let host = url.host_str().unwrap_or("");
        // `port_or_known_default` fills in 80/443 for bare http/https URLs, matching how `Scope`
        // rules are written (an include rule for `shop.test` with no explicit port means "any
        // port", but a request without one still needs a concrete port to check).
        let port = url.port_or_known_default().unwrap_or(0);
        let tls = url.scheme() == "https";
        if !self.scope.contains(host, port, url.path(), tls) {
            return false;
        }
        self.seen.insert(key);
        self.pending.push_back(url);
        true
    }

    /// Pop the next URL to visit, if any.
    pub fn next(&mut self) -> Option<Url> {
        self.pending.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// How many distinct URLs have ever been admitted, visited or not — for progress reporting.
    pub fn seen_count(&self) -> usize {
        self.seen.len()
    }
}

/// Drop the fragment for dedup purposes: `#section` never changes what the server returns, so
/// two URLs differing only there are the same crawl target. Query strings are deliberately kept
/// as-is rather than sorted/canonicalised — a scanner-grade crawler cares about parameter *order*
/// too (it can affect server-side behaviour), so collapsing `?a=1&b=2` and `?b=2&a=1` here would
/// be an assumption this crate has no basis to make.
fn normalize(url: &Url) -> String {
    let mut u = url.clone();
    u.set_fragment(None);
    u.to_string()
}

/// One page visited: what was navigated to, and which of its links were newly admitted to the
/// frontier (already-seen or out-of-scope links are silently dropped, not reported as an error —
/// see [`Frontier::discover`]).
#[derive(Debug)]
pub struct VisitResult {
    pub visited: Url,
    pub discovered: Vec<Url>,
}

/// Visit one URL from `frontier` through `browser`, extract its links, and feed each back into
/// the frontier. Returns `Ok(None)` when the frontier is empty rather than an error — an empty
/// frontier is the normal way a crawl ends, not a failure of it.
pub async fn step(
    browser: &BrowserSession,
    frontier: &mut Frontier,
) -> anyhow::Result<Option<VisitResult>> {
    let Some(target) = frontier.next() else {
        return Ok(None);
    };

    let page = browser.goto(target.as_str()).await?;
    let hrefs = extract_links(browser, &page).await?;

    let mut discovered = Vec::new();
    for href in hrefs {
        if frontier.discover(&target, &href) {
            // `discover` re-resolves internally; re-resolving here too is the price of reporting
            // *which* URL was newly admitted without threading a second return value through it.
            if let Ok(resolved) = target.join(&href) {
                discovered.push(resolved);
            }
        }
    }

    Ok(Some(VisitResult {
        visited: target,
        discovered,
    }))
}

async fn extract_links(
    browser: &BrowserSession,
    page: &chromiumoxide::Page,
) -> anyhow::Result<Vec<String>> {
    const SCRIPT: &str =
        "Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href'))";
    let _ = browser; // kept for symmetry with `browser.content`; evaluation runs on `page` itself.
    let result = page.evaluate(SCRIPT).await?;
    Ok(result.into_value::<Vec<String>>().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::ScopeRule;

    fn shop_scope() -> Scope {
        let mut s = Scope::new();
        s.add(ScopeRule::include("shop.test"));
        s
    }

    #[test]
    fn a_url_outside_scope_is_not_admitted() {
        let mut f = Frontier::new(shop_scope());
        assert!(!f.seed(Url::parse("https://evil.test/").unwrap()));
        assert!(f.is_empty());
    }

    #[test]
    fn a_url_in_scope_is_admitted_exactly_once() {
        let mut f = Frontier::new(shop_scope());
        let u = Url::parse("https://shop.test/cart").unwrap();
        assert!(f.seed(u.clone()));
        assert!(!f.seed(u), "re-seeding the same URL must not duplicate it");
        assert_eq!(f.seen_count(), 1);
    }

    #[test]
    fn a_fragment_only_difference_does_not_create_a_new_entry() {
        let mut f = Frontier::new(shop_scope());
        assert!(f.seed(Url::parse("https://shop.test/cart#top").unwrap()));
        assert!(!f.seed(Url::parse("https://shop.test/cart#bottom").unwrap()));
        assert_eq!(f.seen_count(), 1);
    }

    #[test]
    fn relative_hrefs_resolve_against_the_page_they_were_found_on() {
        let mut f = Frontier::new(shop_scope());
        let base = Url::parse("https://shop.test/catalog/shoes").unwrap();
        assert!(f.discover(&base, "../cart"));
        let next = f.next().unwrap();
        assert_eq!(next.as_str(), "https://shop.test/cart");
    }

    #[test]
    fn a_relative_href_that_resolves_out_of_scope_is_dropped_not_errored() {
        let mut f = Frontier::new(shop_scope());
        let base = Url::parse("https://shop.test/catalog").unwrap();
        assert!(!f.discover(&base, "https://tracker.test/pixel.gif"));
        assert!(f.is_empty());
    }

    #[test]
    fn next_drains_in_fifo_order() {
        let mut f = Frontier::new(Scope::allow_everything());
        f.seed(Url::parse("https://a.test/1").unwrap());
        f.seed(Url::parse("https://a.test/2").unwrap());
        assert_eq!(f.next().unwrap().path(), "/1");
        assert_eq!(f.next().unwrap().path(), "/2");
        assert!(f.next().is_none());
    }
}
