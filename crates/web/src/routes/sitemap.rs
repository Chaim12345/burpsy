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

use crate::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
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
    child_count: usize,
    methods: Vec<String>,
    statuses: Vec<u16>,
    params: Vec<String>,
    last_exchange: Option<u64>,
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

    let tree = match &q.host {
        None => m
            .roots()
            .iter()
            .map(|r| view(&m, *r, depth, children))
            .collect(),
        Some(host) => match m.find(host, &q.path) {
            Some(id) => vec![view(&m, id, depth, children)],
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
        tree,
    })
    .into_response()
}

fn view(m: &SiteMap, id: u32, depth: usize, limit: usize) -> NodeView {
    let n = m.node(id).expect("ids come from the map itself");
    NodeView {
        id: n.id,
        segment: n.segment.clone(),
        path: m.path_of(id),
        depth: n.depth,
        exchanges: n.exchanges,
        requested: n.requested(),
        subtree_exchanges: n.subtree_exchanges,
        child_count: n.children.len(),
        methods: n.methods.clone(),
        statuses: n.statuses.clone(),
        params: n.params.clone(),
        last_exchange: n.last_exchange,
        children: match depth {
            0 => Vec::new(),
            d => n
                .children
                .iter()
                .take(limit)
                .map(|c| view(m, *c, d - 1, limit))
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
        let app = crate::router(store);
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
