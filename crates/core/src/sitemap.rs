//! Site map: the host → path tree the UI navigates, folded from the traffic index.
//!
//! # Why this is a view over the store and never a second copy
//!
//! The site map is where a naive implementation quietly doubles memory: a node that keeps "the
//! request that created me" keeps a body alive, and Burp's tree is exactly the structure that is
//! held for the whole session. Nothing here holds bytes. A node holds a segment string, child
//! indices, three counters, three small sorted sets and a capped list of `u64` exchange ids; every
//! link back to traffic is such an id, so opening a node's traffic goes through [`TrafficStore`]
//! exactly as the history table does. Building and serving the entire tree never calls
//! `TrafficStore::get`, so no response body is ever touched.
//!
//! What the tree does grow with is **distinct paths**, not requests and not bytes: 100k requests to
//! `/login` are one node. That is the one axis on which growth is unavoidable, because it is the
//! information the tree exists to show. The id list is the one field whose natural bound would have
//! been request volume instead, which is why it is the one field with an explicit cap — see
//! [`RECENT_EXCHANGES`], which states what keeping it costs and what capping it costs.
//!
//! # Why incremental rather than rebuilt per request
//!
//! Measured, not assumed. Release build, 100k exchanges over 12,636 nodes (6 hosts, 4k distinct
//! leaf paths); the rebuild is three runs, the fast paths are means over twenty:
//!
//! | step                                    | cost            |
//! |-----------------------------------------|-----------------|
//! | `TrafficStore::exchanges(0, 100_000)`   | 22–41 ms        |
//! | folding those 100k rows into the tree   | 101–133 ms      |
//! | **full rebuild**                        | **126–161 ms**  |
//! | `sync`, 100 new exchanges to fold       | **148 µs**      |
//! | `sync`, nothing new                     | **79 ns**       |
//!
//! Roughly a thousand to one, and the expensive half of the rebuild is not ours to fix:
//! `exchanges()` clones index rows (three `String`s each) and it is the store's only way out. A
//! rebuild-per-poll site map re-copies and re-folds 100k rows it has already seen, on every poll,
//! forever — while holding the store's read lock against a proxy that wants the write lock. The
//! incremental cost is proportional to *new* traffic rather than to captured history, so unlike the
//! rebuild it does not degrade as a session goes on. That is the whole argument for
//! [`SiteMap::sync`].
//!
//! The idle poll is 79 ns rather than the 1.8 ms `TrafficStore::counts()` costs when its whole
//! result is used, because `sync` reads only the exchange count and the compiler drops the
//! stored-byte sum it never looks at. Worth knowing, not worth depending on: if that stopped
//! holding, an idle poll would cost 1.8 ms, which is still nothing beside a rebuild.
//!
//! # What the Burp teardown settled
//!
//! Four modelling questions had a right answer rather than a preference, and the decompiled
//! 2026.7.1 jar answers them. Semantics taken, code not:
//!
//! * **A root is scheme + host + port, not a hostname.** Burp keys each root on `Zp42`, which
//!   carries host (`ZL4`), port (`ZL9`) and a secure flag (`ZLX`), so `http://x` and `https://x` are
//!   two roots. Same here — they are two attack surfaces even when they serve the same paths.
//! * **A query string does not make a new node.** `Zsi` hangs *parameterised request variants* off
//!   one path node, grouped by `Zwx2` = `{QUERY, QUERY_BODY_METHOD, METHOD}`, rather than making
//!   `/a?x=1` a sibling of `/a?x=2`. Same here: one node per path, with the parameter *names* it has
//!   been called with. Storing the values would make the tree grow with traffic again.
//! * **The bare `/` is not a generic segment.** `Zice.Zo` special-cases `"/"`. Here it folds into
//!   the host root, which is the same decision expressed as a node count.
//! * **Requested and merely-inferred nodes must stay distinguishable.** Burp keeps a per-node
//!   requested flag — `Zsvz` renders the word `"unrequested"` in the filter bar, and `Zup3` persists
//!   `target.filter.by_request_type.show_only_requested_items`. It needs one because it populates
//!   the tree from parsed links and forms as well as from captures (`Zi__`: *"Adding link %s in
//!   response %s to site map"* beside *"Adding response %s to site map"*). See
//!   [`SiteNode::requested`].
//!
//! Two things Burp does that this does not: it caps nothing on very wide levels (no truncation
//! logic found), and its trailing-slash handling is unstated, so `/a/` and `/a` collapsing to one
//! node is a decision made here, not inherited.
//!
//! # Why late responses need care
//!
//! The proxy calls `add_exchange` when the *request* arrives and `set_response` when the response
//! comes back. An incremental fold that visited each exchange once would therefore record the
//! request and miss the status code. `sync` records such exchanges as pending and re-reads a bounded
//! window of the newest rows on the next call, unioning any status that has since landed — status
//! is a set, so re-reading is idempotent, while the exchange count is folded exactly once.

use crate::{Exchange, TrafficStore};
use std::collections::{HashMap, VecDeque};

/// Sentinel parent for the host roots. Real parents are indices into `nodes`.
const NO_PARENT: u32 = u32::MAX;

/// How many of the newest exchanges `sync` re-reads to pick up responses that landed after their
/// request was folded.
///
/// A response that arrives after this many later requests have been captured keeps its exchange in
/// history but loses its status code from the tree. At proxy rates that is a request outstanding
/// for many seconds while hundreds of others complete — a hung request, which the history table
/// shows correctly either way.
pub const RESOLVE_WINDOW: usize = 512;

/// Exchange ids retained per node in [`SiteNode::recent_exchanges`], newest kept.
///
/// This is the one per-node list whose natural bound is request volume rather than a small set of
/// distinct values, so it is the one that needs an explicit cap: `methods`, `statuses` and `params`
/// are sets of names and codes, and 100k requests to `/login` add nothing to them after the first
/// few. An uncapped id list would put the tree's growth back on the traffic axis the whole module
/// is built to keep it off.
///
/// The cost of keeping it: 200 × 8 bytes = 1.6 KB per *requested* node, so ~6.5 MB across the 4k
/// leaves of the 100k-exchange session measured above — and flat from then on, however long the
/// session runs. Still no bodies, still nothing proportional to request count.
///
/// The cost of the cap: older evidence, never the count. [`SiteNode::exchanges`] keeps counting
/// every request, which is the same trade [`crate::findings::MAX_OCCURRENCES`] makes against
/// `times_seen`.
pub const RECENT_EXCHANGES: usize = 200;

/// One node: a host root, or a single path segment beneath one.
///
/// Deliberately without its own path string — the path is derivable by walking parents
/// ([`SiteMap::path_of`]) and storing it would double the per-node cost for a value only the
/// handful of rendered nodes ever need.
#[derive(Debug, Clone)]
pub struct SiteNode {
    pub id: u32,
    pub parent: Option<u32>,
    /// `scheme://host:port` at a root, otherwise one path segment.
    pub segment: String,
    pub depth: u16,
    pub children: Vec<u32>,
    /// Requests whose path ends exactly here.
    pub exchanges: u32,
    /// Requests at or below here — what a collapsed tree row shows.
    pub subtree_exchanges: u32,
    /// Methods seen at this exact node, sorted.
    pub methods: Vec<String>,
    /// Response statuses seen at this exact node, sorted.
    pub statuses: Vec<u16>,
    /// Query parameter names seen at this exact node, sorted. The tester-facing part of the tree:
    /// this is the input surface, which is why the roadmap's model is host → path → params.
    pub params: Vec<String>,
    /// Newest exchange seen here, so a UI can open one without searching history.
    pub last_exchange: Option<u64>,
    /// The exchanges that landed on this exact node, oldest retained first, capped at
    /// [`RECENT_EXCHANGES`].
    ///
    /// `last_exchange` alone answers "open something here"; selecting a node in a tree asks
    /// "show me what happened here", and one id cannot. Ids only — dereferencing one still goes
    /// through [`TrafficStore`], so this holds no bytes and the "never call `TrafficStore::get`"
    /// property of building and serving the tree is unchanged.
    ///
    /// Ordered by ingestion, which [`SiteMap::sync`] performs in ascending id order, so in the
    /// production path this is oldest-to-newest by id and the back is the newest request seen.
    /// [`SiteMap::from_exchanges`] preserves whatever order it is handed.
    pub recent_exchanges: VecDeque<u64>,
}

impl SiteNode {
    fn new(id: u32, parent: Option<u32>, segment: String, depth: u16) -> Self {
        Self {
            id,
            parent,
            segment,
            depth,
            children: Vec::new(),
            exchanges: 0,
            subtree_exchanges: 0,
            methods: Vec::new(),
            statuses: Vec::new(),
            params: Vec::new(),
            last_exchange: None,
            recent_exchanges: VecDeque::new(),
        }
    }

    /// Was this path itself ever requested, or does the node exist only because something below it
    /// was?
    ///
    /// Burp keeps this as a stored boolean because it also builds nodes from links and forms it
    /// parsed but never fetched. Every node here comes from a captured exchange, so the same
    /// distinction is exactly `exchanges > 0` and needs no field — and when a crawler starts adding
    /// discovered-but-unfetched paths, they will arrive with no exchange and read as unrequested
    /// without changing this.
    pub fn requested(&self) -> bool {
        self.exchanges > 0
    }
}

/// The tree, plus enough bookkeeping to fold only what the store has gained.
#[derive(Debug, Default)]
pub struct SiteMap {
    nodes: Vec<SiteNode>,
    roots: Vec<u32>,
    /// `parent -> segment -> child`. One map per parent that has children, rather than one per
    /// node, so leaves (the overwhelming majority at scale) carry no hash table.
    index: HashMap<u32, HashMap<String, u32>>,
    /// Smallest exchange id not yet folded. Ids are assigned monotonically by the store, so this
    /// advances only over a contiguous run — an id that appears out of order is simply left for the
    /// next sync rather than risking a double fold.
    next_id: u64,
    /// `(exchange id, node)` for exchanges folded before their response existed.
    pending: Vec<(u64, u32)>,
    folded: u64,
}

impl SiteMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold a batch of index rows. Used for one-shot derivation and by [`SiteMap::sync`].
    pub fn from_exchanges<'a>(it: impl IntoIterator<Item = &'a Exchange>) -> Self {
        let mut m = Self::new();
        for ex in it {
            m.ingest(ex);
        }
        m
    }

    /// Fold one exchange. Never dereferences a message id, so no body is loaded.
    pub fn ingest(&mut self, ex: &Exchange) {
        let root = self.child_of(NO_PARENT, &authority(ex), 0);
        self.nodes[root as usize].subtree_exchanges += 1;

        let (path, query) = split_target(&ex.path);
        let mut cur = root;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            cur = self.child_of(cur, seg, self.nodes[cur as usize].depth + 1);
            self.nodes[cur as usize].subtree_exchanges += 1;
        }

        let n = &mut self.nodes[cur as usize];
        n.exchanges += 1;
        insert_sorted(&mut n.methods, &ex.method);
        for name in param_names(query) {
            insert_sorted(&mut n.params, name);
        }
        n.last_exchange = Some(match n.last_exchange {
            Some(prev) => prev.max(ex.id),
            None => ex.id,
        });
        push_recent(&mut n.recent_exchanges, ex.id);
        match ex.status {
            Some(s) => insert_status(&mut n.statuses, s),
            // Recorded, not dropped: the response is probably still in flight.
            None => self.pending.push((ex.id, cur)),
        }
        self.folded += 1;
    }

    /// Fold everything the store has gained since the last call; returns how many rows were folded.
    ///
    /// Reads only the index rows it needs. `counts()` is the store's only way to answer "is there
    /// anything new"; it is nominally O(messages) because it also sums stored bytes, but this call
    /// discards that half and it optimises away — an idle poll measures 79 ns.
    pub fn sync(&mut self, store: &TrafficStore) -> usize {
        let (total, _, _) = store.counts();
        let behind = (total as u64).saturating_sub(self.next_id) as usize;
        if behind == 0 && self.pending.is_empty() {
            return 0;
        }

        // Overshoot by the resolve window when something is pending, so late statuses are visible
        // even on a sync that has no new traffic to fold.
        let want = behind
            + if self.pending.is_empty() {
                0
            } else {
                RESOLVE_WINDOW
            };
        let batch = store.exchanges(0, want);
        let by_id: HashMap<u64, &Exchange> = batch.iter().map(|e| (e.id, e)).collect();

        let mut folded = 0usize;
        while let Some(ex) = by_id.get(&self.next_id).copied() {
            self.ingest(ex);
            self.next_id += 1;
            folded += 1;
        }
        self.resolve_pending(&by_id, batch.last().map(|e| e.id).unwrap_or(0));
        folded
    }

    /// Union statuses that have arrived since their exchange was folded, and forget the ones that
    /// have fallen out of the re-read window.
    fn resolve_pending(&mut self, by_id: &HashMap<u64, &Exchange>, oldest_read: u64) {
        let mut keep = Vec::with_capacity(self.pending.len());
        for (ex_id, node) in std::mem::take(&mut self.pending) {
            match by_id.get(&ex_id) {
                Some(ex) => match ex.status {
                    Some(s) => insert_status(&mut self.nodes[node as usize].statuses, s),
                    None => keep.push((ex_id, node)),
                },
                // Not in the window we read: unresolvable from here on, so stop tracking it.
                None if ex_id >= oldest_read => keep.push((ex_id, node)),
                None => {}
            }
        }
        self.pending = keep;
    }

    /// Find or create the child of `parent` named `segment`.
    fn child_of(&mut self, parent: u32, segment: &str, depth: u16) -> u32 {
        if let Some(id) = self.index.get(&parent).and_then(|m| m.get(segment)) {
            return *id;
        }
        let id = self.nodes.len() as u32;
        let owner = if parent == NO_PARENT {
            None
        } else {
            Some(parent)
        };
        self.nodes
            .push(SiteNode::new(id, owner, segment.to_owned(), depth));
        match owner {
            Some(p) => self.nodes[p as usize].children.push(id),
            None => self.roots.push(id),
        }
        self.index
            .entry(parent)
            .or_default()
            .insert(segment.to_owned(), id);
        id
    }

    pub fn node(&self, id: u32) -> Option<&SiteNode> {
        self.nodes.get(id as usize)
    }

    /// Host roots, in the order they were first seen.
    pub fn roots(&self) -> &[u32] {
        &self.roots
    }

    /// Resolve `scheme://host:port` plus a path to a node.
    pub fn find(&self, authority: &str, path: &str) -> Option<u32> {
        let mut cur = *self.index.get(&NO_PARENT)?.get(authority)?;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            cur = *self.index.get(&cur)?.get(seg)?;
        }
        Some(cur)
    }

    /// Path from the host root, e.g. `/api/users`. Derived, not stored.
    pub fn path_of(&self, id: u32) -> String {
        let mut segs = Vec::new();
        let mut cur = self.nodes.get(id as usize);
        while let Some(n) = cur {
            match n.parent {
                Some(p) => {
                    segs.push(n.segment.as_str());
                    cur = self.nodes.get(p as usize);
                }
                None => break,
            }
        }
        if segs.is_empty() {
            return "/".to_owned();
        }
        segs.reverse();
        format!("/{}", segs.join("/"))
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Exchanges folded into the tree so far.
    pub fn total_exchanges(&self) -> u64 {
        self.folded
    }

    /// Exchanges folded but still waiting on a response.
    pub fn pending_responses(&self) -> usize {
        self.pending.len()
    }
}

/// `scheme://host:port` — the tree's root key. The scheme is part of it because `http://x` and
/// `https://x` are different attack surfaces even when they serve the same paths.
pub fn authority(ex: &Exchange) -> String {
    let scheme = if ex.tls { "https" } else { "http" };
    format!("{scheme}://{}:{}", ex.host, ex.port)
}

/// Split a request target into `(path, query)`.
///
/// Absolute-form targets (`GET http://host/p HTTP/1.1`) reach the store from hand-written repeater
/// requests, and a fragment can survive a pasted URL. Both are normalised away so an absolute-form
/// request lands on the same node as the origin-form request it is equivalent to.
fn split_target(target: &str) -> (&str, &str) {
    let p = match target.find("://") {
        Some(i) => match target[i + 3..].find('/') {
            Some(j) => &target[i + 3 + j..],
            None => "/",
        },
        None => target,
    };
    let p = p.split('#').next().unwrap_or(p);
    match p.split_once('?') {
        Some((path, query)) => (path, query),
        None => (p, ""),
    }
}

/// Parameter names from a query string, values discarded — the name is the insertion point.
fn param_names(query: &str) -> impl Iterator<Item = &str> {
    query
        .split('&')
        .map(|kv| kv.split('=').next().unwrap_or(kv))
        .filter(|k| !k.is_empty())
}

fn insert_sorted(v: &mut Vec<String>, item: &str) {
    if let Err(at) = v.binary_search_by(|p| p.as_str().cmp(item)) {
        v.insert(at, item.to_owned());
    }
}

/// Retain the newest [`RECENT_EXCHANGES`] ids, dropping the oldest.
///
/// A deque rather than a `Vec`, because this runs once per folded exchange: shifting a 200-element
/// list down by one on every request past the cap would put an O(cap) memmove on the fold's hot
/// path, where a pop is O(1). No duplicate check is needed — [`SiteMap::sync`] advances `next_id`
/// over a contiguous run, so `ingest` sees each exchange id exactly once.
fn push_recent(v: &mut VecDeque<u64>, id: u64) {
    if v.len() == RECENT_EXCHANGES {
        v.pop_front();
    }
    v.push_back(id);
}

fn insert_status(v: &mut Vec<u16>, s: u16) {
    if let Err(at) = v.binary_search(&s) {
        v.insert(at, s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Direction, MsgId, Protocol};
    use bytes::Bytes;

    fn ex(
        id: u64,
        host: &str,
        tls: bool,
        method: &str,
        path: &str,
        status: Option<u16>,
    ) -> Exchange {
        Exchange {
            related: Vec::new(),
            protocol: Protocol::Http1,
            id,
            request: MsgId(id),
            response: status.map(|_| MsgId(id)),
            host: host.into(),
            port: if tls { 443 } else { 80 },
            tls,
            method: method.into(),
            path: path.into(),
            status,
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        }
    }

    #[test]
    fn paths_become_a_tree_of_segments_under_a_host_root() {
        let rows = [
            ex(0, "a.test", false, "GET", "/api/users", Some(200)),
            ex(1, "a.test", false, "GET", "/api/orders", Some(200)),
            ex(2, "a.test", false, "GET", "/static/app.js", Some(200)),
        ];
        let m = SiteMap::from_exchanges(&rows);

        assert_eq!(m.roots().len(), 1, "one host seen");
        let root = m.node(m.roots()[0]).unwrap();
        assert_eq!(root.segment, "http://a.test:80");
        assert_eq!(root.subtree_exchanges, 3);
        assert_eq!(root.exchanges, 0, "nothing was requested at / itself");

        let api = m.find("http://a.test:80", "/api").unwrap();
        assert_eq!(m.node(api).unwrap().children.len(), 2);
        assert_eq!(m.node(api).unwrap().subtree_exchanges, 2);
        assert_eq!(m.path_of(api), "/api");

        let users = m.find("http://a.test:80", "/api/users").unwrap();
        assert_eq!(m.node(users).unwrap().exchanges, 1);
        assert_eq!(m.node(users).unwrap().depth, 2);
        assert_eq!(m.path_of(users), "/api/users");
        assert!(m.find("http://a.test:80", "/api/missing").is_none());
    }

    #[test]
    fn a_directory_nobody_requested_is_distinguishable_from_one_that_was() {
        // Conflating the two misleads the operator: `/admin` appearing in the tree because
        // `/admin/login.js` was fetched is not evidence that `/admin` responds.
        let rows = [
            ex(0, "a.test", false, "GET", "/admin/login.js", Some(200)),
            ex(1, "a.test", false, "GET", "/public", Some(200)),
        ];
        let m = SiteMap::from_exchanges(&rows);

        let admin = m
            .node(m.find("http://a.test:80", "/admin").unwrap())
            .unwrap();
        assert!(!admin.requested(), "inferred from a deeper path only");
        assert_eq!(
            admin.subtree_exchanges, 1,
            "but it does have traffic beneath it"
        );
        assert!(admin.methods.is_empty(), "nothing was ever sent to it");

        let js = m
            .node(m.find("http://a.test:80", "/admin/login.js").unwrap())
            .unwrap();
        assert!(js.requested());
        let public = m
            .node(m.find("http://a.test:80", "/public").unwrap())
            .unwrap();
        assert!(public.requested());
    }

    #[test]
    fn scheme_and_port_separate_the_roots() {
        // Same host over http and https is two attack surfaces, not one.
        let rows = [
            ex(0, "a.test", false, "GET", "/", Some(200)),
            ex(1, "a.test", true, "GET", "/", Some(200)),
        ];
        let m = SiteMap::from_exchanges(&rows);
        assert_eq!(m.roots().len(), 2);
        let names: Vec<&str> = m
            .roots()
            .iter()
            .map(|r| m.node(*r).unwrap().segment.as_str())
            .collect();
        assert_eq!(names, vec!["http://a.test:80", "https://a.test:443"]);
    }

    #[test]
    fn one_node_carries_every_method_status_and_param_seen_there() {
        let rows = [
            ex(0, "a.test", false, "GET", "/search?q=x&page=2", Some(200)),
            ex(1, "a.test", false, "POST", "/search?q=y", Some(302)),
            ex(2, "a.test", false, "GET", "/search?q=z&sort=asc", Some(200)),
            ex(3, "a.test", false, "GET", "/search", Some(500)),
        ];
        let m = SiteMap::from_exchanges(&rows);
        let n = m
            .node(m.find("http://a.test:80", "/search").unwrap())
            .unwrap();
        assert_eq!(
            n.exchanges, 4,
            "distinct query strings are one node, not four"
        );
        assert_eq!(n.methods, vec!["GET", "POST"]);
        assert_eq!(n.statuses, vec![200, 302, 500]);
        assert_eq!(n.params, vec!["page", "q", "sort"]);
        assert_eq!(n.last_exchange, Some(3));
        assert_eq!(
            n.recent_exchanges, [0, 1, 2, 3],
            "and the ids themselves, so selecting the node can show its four requests"
        );
    }

    #[test]
    fn a_nodes_id_list_keeps_the_newest_and_never_grows_with_traffic() {
        // The memory claim for the one field that would otherwise grow per request. `exchanges`
        // must still count every request, or capping would cost the count and not just the older
        // evidence.
        let rows: Vec<Exchange> = (0..RECENT_EXCHANGES as u64 + 50)
            .map(|i| ex(i, "a.test", false, "GET", "/busy", Some(200)))
            .collect();
        let m = SiteMap::from_exchanges(&rows);
        let n = m
            .node(m.find("http://a.test:80", "/busy").unwrap())
            .unwrap();

        assert_eq!(n.exchanges, RECENT_EXCHANGES as u32 + 50);
        assert_eq!(n.recent_exchanges.len(), RECENT_EXCHANGES);
        assert_eq!(
            n.recent_exchanges.front().copied(),
            Some(50),
            "the oldest 50 fell off the front"
        );
        assert_eq!(
            n.recent_exchanges.back().copied(),
            n.last_exchange,
            "the newest id is retained, and agrees with last_exchange"
        );
    }

    #[test]
    fn the_id_list_belongs_to_the_exact_node_that_was_requested() {
        // A directory that only has traffic beneath it must not claim that traffic as its own: the
        // ids follow `exchanges`, not `subtree_exchanges`.
        let rows = [
            ex(0, "a.test", false, "GET", "/admin/login", Some(200)),
            ex(1, "a.test", false, "GET", "/admin", Some(403)),
        ];
        let m = SiteMap::from_exchanges(&rows);

        let admin = m
            .node(m.find("http://a.test:80", "/admin").unwrap())
            .unwrap();
        assert_eq!(admin.recent_exchanges, [1], "only the request to /admin");
        let login = m
            .node(m.find("http://a.test:80", "/admin/login").unwrap())
            .unwrap();
        assert_eq!(login.recent_exchanges, [0]);
    }

    #[test]
    fn absolute_form_and_fragments_land_on_the_origin_form_node() {
        let rows = [
            ex(0, "a.test", false, "GET", "/docs/index.html", Some(200)),
            ex(
                1,
                "a.test",
                false,
                "GET",
                "http://a.test/docs/index.html",
                Some(200),
            ),
            ex(2, "a.test", false, "GET", "/docs/index.html#top", Some(200)),
        ];
        let m = SiteMap::from_exchanges(&rows);
        let n = m
            .node(m.find("http://a.test:80", "/docs/index.html").unwrap())
            .unwrap();
        assert_eq!(n.exchanges, 3);
        assert_eq!(m.len(), 3, "root + docs + index.html, nothing else");
    }

    #[test]
    fn a_request_to_the_bare_root_counts_on_the_host_node() {
        let rows = [ex(0, "a.test", false, "GET", "/", Some(200))];
        let m = SiteMap::from_exchanges(&rows);
        let root = m.node(m.roots()[0]).unwrap();
        assert_eq!(root.exchanges, 1);
        assert_eq!(m.len(), 1);
        assert_eq!(m.path_of(root.id), "/");
    }

    #[test]
    fn sync_folds_only_what_is_new() {
        let store = TrafficStore::new();
        let put = |path: &str| {
            let id = store.put(
                Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"),
                Direction::Request,
            );
            store.add_exchange(Exchange {
                related: Vec::new(),
                protocol: Protocol::Http1,
                id: 0,
                request: id,
                response: None,
                host: "a.test".into(),
                port: 80,
                tls: false,
                method: "GET".into(),
                path: path.into(),
                status: Some(200),
                response_len: 0,
                started_ms: 0,
                duration_ms: 0,
                notes: None,
            })
        };
        put("/a");
        put("/b");

        let mut m = SiteMap::new();
        assert_eq!(m.sync(&store), 2, "first sync folds the backlog");
        assert_eq!(m.sync(&store), 0, "second sync has nothing to do");
        assert_eq!(m.total_exchanges(), 2);

        put("/c");
        assert_eq!(m.sync(&store), 1, "only the new row is folded");
        assert_eq!(m.total_exchanges(), 3, "no row is folded twice");
        assert_eq!(m.node(m.roots()[0]).unwrap().subtree_exchanges, 3);
    }

    #[test]
    fn a_status_arriving_after_its_request_was_folded_still_reaches_the_tree() {
        // The proxy adds the exchange when the request arrives and fills the status later; a fold
        // that visited each row once would show the path with no status forever.
        let store = TrafficStore::new();
        let req = store.put(
            Bytes::from_static(b"GET /late HTTP/1.1\r\n\r\n"),
            Direction::Request,
        );
        let ex_id = store.add_exchange(Exchange {
            related: Vec::new(),
            protocol: Protocol::Http1,
            id: 0,
            request: req,
            response: None,
            host: "a.test".into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            path: "/late".into(),
            status: None,
            response_len: 0,
            started_ms: 0,
            duration_ms: 0,
            notes: None,
        });

        let mut m = SiteMap::new();
        assert_eq!(m.sync(&store), 1);
        let node = m.find("http://a.test:80", "/late").unwrap();
        assert!(m.node(node).unwrap().statuses.is_empty(), "no response yet");
        assert_eq!(m.pending_responses(), 1);

        let resp = store.put(
            Bytes::from_static(b"HTTP/1.1 503 x\r\n\r\n"),
            Direction::Response,
        );
        store.set_response(ex_id, resp, 503, 0, 7);

        assert_eq!(m.sync(&store), 0, "no new exchange, only a late status");
        assert_eq!(m.node(node).unwrap().statuses, vec![503]);
        assert_eq!(
            m.node(node).unwrap().exchanges,
            1,
            "the row is still counted once"
        );
        assert_eq!(m.pending_responses(), 0);
    }

    #[test]
    fn the_tree_grows_with_distinct_paths_not_with_request_volume() {
        // The memory claim, asserted: 20k requests over 200 distinct paths must not produce 20k
        // nodes. Node count is 1 root + 20 directories + 200 leaves.
        let mut rows = Vec::with_capacity(20_000);
        for i in 0..20_000u64 {
            let dir = i % 20;
            let leaf = i % 200;
            rows.push(ex(
                i,
                "a.test",
                true,
                if i % 3 == 0 { "POST" } else { "GET" },
                &format!("/d{dir}/p{leaf}?id={i}"),
                Some(if i % 7 == 0 { 404 } else { 200 }),
            ));
        }
        let m = SiteMap::from_exchanges(&rows);
        assert_eq!(m.len(), 221, "1 root + 20 dirs + 200 leaves");
        assert_eq!(m.total_exchanges(), 20_000);
        assert_eq!(m.node(m.roots()[0]).unwrap().subtree_exchanges, 20_000);

        let leaf = m
            .node(m.find("https://a.test:443", "/d0/p0").unwrap())
            .unwrap();
        assert_eq!(leaf.exchanges, 100, "every 200th request lands here");
        assert_eq!(leaf.methods, vec!["GET", "POST"]);
        assert_eq!(leaf.statuses, vec![200, 404]);
        assert_eq!(
            leaf.params,
            vec!["id"],
            "20k distinct values, one param name"
        );
    }
}
