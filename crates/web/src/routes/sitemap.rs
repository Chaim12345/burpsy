//! Site map: the tree view derived from captured history.
//!
//! # Why the tree is owned by this router and not by `AppState`
//!
//! [`SiteMap`] is a *fold* over one `TrafficStore`, so it is only valid alongside the store it was
//! folded from. Hanging it off the shared `AppState` would make it look like global state that any
//! handler may reach for; keeping it captured by this router's closure ties its lifetime to the
//! store the router was built with, and gives every test its own tree for free.
//!
//! # Why one level at a time
//!
//! A tree UI expands one node at a time, so the API answers one node at a time. Serialising the
//! whole tree would put the entire path space on the wire on every poll — the same
//! "send everything you already sent" mistake the history endpoint avoids by returning index rows.
//! `depth` exists for the caller that wants to prefetch a couple of levels; it is capped.
//!
//! The same rule decides where `recent_exchanges` appears: on the node(s) this request *named*, and
//! not on their descendants. A tree listing carries up to `children` × `depth` nodes, and 200 ids on
//! each of them would be a response measured in hundreds of thousands of numbers — so a client that
//! wants a node's traffic asks for that node, which is one request and exactly the shape the rest of
//! this endpoint already has.
//!
//! # Why filtering happens here and not in the fold
//!
//! `q` and `in_scope_only` are a *view* over the built tree. [`SiteMap`] is a single incremental
//! fold shared by every caller, and a filter is per-request and per-operator: folding one would mean
//! either a tree per filter or a re-fold per keystroke, and both give up the property that made the
//! fold incremental in the first place. So nothing here touches `ingest`/`sync` — filtering reads the
//! finished tree and decides what to serialise.

use crate::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use burpsy_core::Scope;
use burpsy_core::sitemap::SiteMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Levels of children returned in one response. Four levels of a wide tree is already a large
/// document; beyond that the caller wants paging, not a bigger page.
const MAX_DEPTH: usize = 4;
/// Children returned per node. `/item/{id}` style paths make levels arbitrarily wide, and the
/// browser is the thing that falls over first.
const MAX_CHILDREN: usize = 2000;

#[derive(Deserialize)]
struct TreeQuery {
    /// `scheme://host:port`. Absent lists the host roots.
    host: Option<String>,
    #[serde(default = "root_path")]
    path: String,
    #[serde(default = "default_depth")]
    depth: usize,
    #[serde(default = "default_children")]
    children: usize,
    /// Case-insensitive substring, matched against a node's own segment and its full path. Absent
    /// or blank matches everything. Burp's filter bar has the same box, and case-sensitivity in a
    /// search field an operator types into is a trap rather than a feature.
    q: Option<String>,
    /// Keep only what the configured [`Scope`] authorises — Burp's "show only in-scope items".
    #[serde(default)]
    in_scope_only: bool,
}

fn root_path() -> String {
    "/".to_owned()
}
fn default_depth() -> usize {
    1
}
fn default_children() -> usize {
    500
}

#[derive(Serialize)]
struct NodeView {
    id: u32,
    segment: String,
    path: String,
    depth: u16,
    /// Requests that ended exactly here.
    exchanges: u32,
    /// False when the node exists only because something below it was requested. Burp shows these
    /// greyed and can filter them out; a tree that conflates them tells the operator a path
    /// responds when nothing ever asked it.
    requested: bool,
    /// Requests at or below here, so a collapsed row still shows its weight.
    subtree_exchanges: u32,
    /// Children this response would show. Under a filter this is the count that *survives* it, so a
    /// twisty never promises children the filter has hidden.
    child_count: usize,
    methods: Vec<String>,
    statuses: Vec<u16>,
    params: Vec<String>,
    last_exchange: Option<u64>,
    /// The exchanges that landed on this exact path, newest first, capped by
    /// [`burpsy_core::sitemap::RECENT_EXCHANGES`].
    ///
    /// Present only on the node(s) this request named — see the module docs. `exchanges` above is
    /// the untruncated count, so a client can say "the newest 200 of 4,812" rather than implying
    /// this is all of them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    recent_exchanges: Vec<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<NodeView>,
}

#[derive(Serialize)]
struct TreeResp {
    /// Exchanges folded into the tree.
    exchanges: u64,
    /// Nodes in the whole tree, not just the ones returned here.
    nodes: usize,
    /// Rows folded to answer this request. Zero on a poll with no new traffic — the cheap case.
    synced: usize,
    /// Folded requests still waiting on a response.
    in_flight: usize,
    /// Nodes the filter kept, out of `nodes`. Absent when no filter was applied.
    ///
    /// Worth a field: a search box that silently returns an empty tree cannot be told apart from a
    /// broken one, and "0 of 12,636 match" is the answer to that.
    #[serde(skip_serializing_if = "Option::is_none")]
    matched: Option<usize>,
    /// The host roots when no `host` was given, otherwise the single requested node.
    tree: Vec<NodeView>,
}

pub fn routes() -> Router<AppState> {
    let map = Arc::new(RwLock::new(SiteMap::new()));
    Router::new().route(
        "/api/sitemap",
        get(
            move |State(s): State<AppState>, Query(q): Query<TreeQuery>| {
                let map = map.clone();
                async move { sitemap(map, s, q).await }
            },
        ),
    )
}

/// Folding is synchronous and, on the first call after a long capture, hundreds of milliseconds.
/// Offloaded for the same reason `run_audit` is: a runtime worker stalled here stalls every other
/// request.
async fn sitemap(map: Arc<RwLock<SiteMap>>, s: AppState, q: TreeQuery) -> impl IntoResponse {
    match tokio::task::spawn_blocking(move || render(&map, &s, &q)).await {
        Ok(r) => r.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("sitemap task failed: {e}"),
        )
            .into_response(),
    }
}

fn render(map: &RwLock<SiteMap>, s: &AppState, q: &TreeQuery) -> axum::response::Response {
    let mut m = map.write();
    let synced = m.sync(&s.store);
    let depth = q.depth.min(MAX_DEPTH);
    let children = q.children.min(MAX_CHILDREN);
    // `SharedScope` is now the runtime-editable handle (see burpsy_core::SharedScope); a read guard
    // borrows to `&Scope` for the duration of this render, which is fine since nothing here awaits.
    let scope_guard = s.scope.read();
    let keep = Filter::of(q).map(|f| keep_set(&m, &scope_guard, &f));
    let keep = keep.as_deref();

    let tree = match &q.host {
        None => m
            .roots()
            .iter()
            .filter(|r| kept(keep, **r))
            .map(|r| top(&m, *r, depth, children, keep))
            .collect(),
        Some(host) => match m.find(host, &q.path) {
            // Returned whether or not it matches the filter. A filter narrows what is *under* a
            // node; the client that asked to expand this one already has it on screen, and hiding it
            // here would answer "expand this" with something that reads as "it is gone".
            Some(id) => vec![top(&m, id, depth, children, keep)],
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    format!("no site map node for {host}{}", q.path),
                )
                    .into_response();
            }
        },
    };

    Json(TreeResp {
        exchanges: m.total_exchanges(),
        nodes: m.len(),
        synced,
        in_flight: m.pending_responses(),
        matched: keep.map(|k| k.iter().filter(|b| **b).count()),
        tree,
    })
    .into_response()
}

/// A per-request predicate over the finished tree. See the module docs for why it is not folded.
struct Filter {
    /// Lowercased once here rather than once per node.
    needle: Option<String>,
    in_scope_only: bool,
}

impl Filter {
    /// `None` when the request asked for no filtering, which is the common case and the one that
    /// must stay free: no keep-set, no per-node path allocation, nothing.
    fn of(q: &TreeQuery) -> Option<Self> {
        let needle = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
        if needle.is_none() && !q.in_scope_only {
            return None;
        }
        Some(Self {
            needle: needle.map(str::to_lowercase),
            in_scope_only: q.in_scope_only,
        })
    }
}

/// Which nodes survive `f`, indexed by node id.
///
/// A node is kept when it matches **or when any descendant does**, because hiding the only route to
/// a match hides the match: `q=passwd` must leave `/api` on screen if `/api/etc/passwd` is under it,
/// and `in_scope_only` must leave `/api` on screen when scope authorises `/api/v1/` but not `/api`
/// itself.
///
/// Two linear passes rather than a subtree walk per rendered node, using the ordering invariant the
/// ids already carry — [`SiteMap`] pushes a child after its parent, so a child's id is always the
/// greater. That makes "propagate down" a forward loop and "propagate up" a reverse one.
fn keep_set(m: &SiteMap, scope: &Scope, f: &Filter) -> Vec<bool> {
    let len = m.len();
    let mut keep = vec![false; len];
    // Which root each node hangs off, so an in-scope test knows which host it is asking about.
    let mut root_of = vec![0u32; len];
    for id in 0..len {
        let Some(n) = m.node(id as u32) else { continue };
        root_of[id] = match n.parent {
            Some(p) => root_of[p as usize],
            None => id as u32,
        };
        keep[id] = matches(m, scope, f, id as u32, root_of[id]);
    }
    for id in (0..len).rev() {
        if keep[id]
            && let Some(p) = m.node(id as u32).and_then(|n| n.parent)
        {
            keep[p as usize] = true;
        }
    }
    keep
}

/// Does this one node match, ignoring its descendants?
fn matches(m: &SiteMap, scope: &Scope, f: &Filter, id: u32, root: u32) -> bool {
    let Some(n) = m.node(id) else { return false };
    // Allocated only under a filter: the tree deliberately does not store paths.
    let path = m.path_of(id);
    if let Some(needle) = &f.needle
        && !n.segment.to_lowercase().contains(needle)
        && !path.to_lowercase().contains(needle)
    {
        return false;
    }
    if f.in_scope_only {
        let Some((host, port, tls)) = m.node(root).and_then(|r| split_authority(&r.segment)) else {
            return false;
        };
        // A display decision, not an authorisation one — those live in `AuthorisedSender`. Asking
        // `Scope` rather than reimplementing "in scope" is the point: an operator who filters the
        // tree by scope must see the same answer the attack paths would give.
        if !scope.contains(host, port, &path, tls) {
            return false;
        }
    }
    true
}

/// Split a root's `scheme://host:port` segment back into the parts a scope decision needs.
///
/// The inverse of `burpsy_core::sitemap::authority`, which is what built the segment. `rsplit_once`
/// so an IPv6 literal keeps its own colons.
fn split_authority(seg: &str) -> Option<(&str, u16, bool)> {
    let (scheme, rest) = seg.split_once("://")?;
    let (host, port) = rest.rsplit_once(':')?;
    Some((host, port.parse().ok()?, scheme == "https"))
}

/// Is this node in the keep-set? Unfiltered requests keep everything.
fn kept(keep: Option<&[bool]>, id: u32) -> bool {
    keep.is_none_or(|k| k.get(id as usize).copied().unwrap_or(false))
}

/// A node at the top of a response: [`view`] plus the exchange ids only a named node carries.
fn top(m: &SiteMap, id: u32, depth: usize, limit: usize, keep: Option<&[bool]>) -> NodeView {
    let mut v = view(m, id, depth, limit, keep);
    v.recent_exchanges = m
        .node(id)
        .map(|n| n.recent_exchanges.iter().rev().copied().collect())
        .unwrap_or_default();
    v
}

fn view(m: &SiteMap, id: u32, depth: usize, limit: usize, keep: Option<&[bool]>) -> NodeView {
    let n = m.node(id).expect("ids come from the map itself");
    NodeView {
        id: n.id,
        segment: n.segment.clone(),
        path: m.path_of(id),
        depth: n.depth,
        exchanges: n.exchanges,
        requested: n.requested(),
        subtree_exchanges: n.subtree_exchanges,
        child_count: match keep {
            None => n.children.len(),
            Some(_) => n.children.iter().filter(|c| kept(keep, **c)).count(),
        },
        methods: n.methods.clone(),
        statuses: n.statuses.clone(),
        params: n.params.clone(),
        last_exchange: n.last_exchange,
        recent_exchanges: Vec::new(),
        children: match depth {
            0 => Vec::new(),
            d => n
                .children
                .iter()
                .filter(|c| kept(keep, **c))
                .take(limit)
                .map(|c| view(m, *c, d - 1, limit, keep))
                .collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burpsy_core::{Direction, Exchange, TrafficStore};

    /// Capture one exchange with a response already attached.
    fn capture(store: &TrafficStore, method: &str, host: &str, path: &str, status: u16) {
        let req = store.put(
            bytes::Bytes::from(format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n")),
            Direction::Request,
        );
        let ex = store.add_exchange(Exchange {
            related: Vec::new(),
            protocol: burpsy_core::Protocol::Http1,
            id: 0,
            request: req,
            response: None,
            host: host.into(),
            port: 443,
            tls: true,
            method: method.into(),
            path: path.into(),
            status: None,
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        });
        let resp = store.put(
            bytes::Bytes::from(format!("HTTP/1.1 {status} x\r\n\r\n")),
            Direction::Response,
        );
        store.set_response(ex, resp, status, 0, 3);
    }

    async fn serve(store: Arc<TrafficStore>) -> String {
        serve_scoped(store, burpsy_core::Scope::allow_everything()).await
    }

    async fn serve_scoped(store: Arc<TrafficStore>, scope: burpsy_core::Scope) -> String {
        let app = crate::router_full(store, None, scope);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn the_endpoint_lists_hosts_then_walks_into_a_path() {
        let store = TrafficStore::new();
        capture(&store, "GET", "a.test", "/api/users?id=1", 200);
        capture(&store, "POST", "a.test", "/api/users", 201);
        capture(&store, "GET", "a.test", "/api/orders", 500);
        capture(&store, "GET", "b.test", "/", 200);
        let base = serve(store.clone()).await;

        // No host: the roots, each with its immediate children.
        let body = get(&format!("{base}/api/sitemap")).await;
        assert!(body.contains("\"exchanges\":4"), "{body}");
        assert!(body.contains("https://a.test:443"), "{body}");
        assert!(body.contains("https://b.test:443"), "{body}");
        assert!(body.contains("\"synced\":4"), "{body}");

        // A second poll with no new traffic folds nothing — the point of the incremental sync.
        let body = get(&format!("{base}/api/sitemap")).await;
        assert!(body.contains("\"synced\":0"), "{body}");

        // Walk into a node: methods, statuses and params of that exact path.
        let body = get(&format!(
            "{base}/api/sitemap?host=https://a.test:443&path=/api/users"
        ))
        .await;
        assert!(body.contains("\"methods\":[\"GET\",\"POST\"]"), "{body}");
        assert!(body.contains("\"statuses\":[200,201]"), "{body}");
        assert!(body.contains("\"params\":[\"id\"]"), "{body}");
        assert!(body.contains("\"exchanges\":2"), "{body}");

        // The intermediate directory was never requested itself, and says so.
        let body = get(&format!(
            "{base}/api/sitemap?host=https://a.test:443&path=/api"
        ))
        .await;
        assert!(body.contains("\"exchanges\":0"), "{body}");
        assert!(body.contains("\"requested\":false"), "{body}");
        assert!(body.contains("\"subtree_exchanges\":3"), "{body}");
        assert!(body.contains("\"child_count\":2"), "{body}");
    }

    #[tokio::test]
    async fn an_unknown_node_is_a_404_not_an_empty_tree() {
        let store = TrafficStore::new();
        capture(&store, "GET", "a.test", "/known", 200);
        let base = serve(store.clone()).await;
        let body = get(&format!(
            "{base}/api/sitemap?host=https://a.test:443&path=/nope"
        ))
        .await;
        assert!(body.starts_with("HTTP/1.1 404"), "{body}");
    }

    #[tokio::test]
    async fn depth_is_capped_so_one_request_cannot_ask_for_the_whole_tree() {
        let store = TrafficStore::new();
        capture(&store, "GET", "a.test", "/1/2/3/4/5/6", 200);
        let base = serve(store.clone()).await;
        let body = get(&format!("{base}/api/sitemap?depth=99")).await;
        // Root plus MAX_DEPTH levels: segments 1..4 are present, 5 and 6 are not.
        assert!(body.contains("\"segment\":\"4\""), "{body}");
        assert!(!body.contains("\"segment\":\"5\""), "{body}");
        assert!(
            body.contains("\"nodes\":7"),
            "the whole tree still exists: {body}"
        );
    }

    /// Minimal GET returning the whole raw response, so tests need no HTTP client dependency.
    async fn get(url: &str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rest = url.trim_start_matches("http://");
        let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
        let mut s = tokio::net::TcpStream::connect(hostport).await.unwrap();
        let req = format!("GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }
}
