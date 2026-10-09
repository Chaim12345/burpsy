// Package sitemap builds a tree of hosts → paths from the traffic store.
// Mirrors the Rust burpsy-core sitemap module: the proxy records exchanges,
// and the sitemap aggregates them into a navigable site structure for the web UI.
//
// # Continuous, not rebuilt on read (CRAWL-05)
//
// The requirement is that the site map is built from proxy traffic *continuously,
// with no separate crawl action*. Sync alone did not do that. It rebuilt the whole
// tree from the store, and its only caller was the GET /api/sitemap handler — so
// the map was recomputed from scratch whenever an operator happened to open the
// tab, was empty at every other moment, and cost O(all exchanges) per view. There
// was no crawl action, which is half the requirement, but nothing was continuous.
//
// Follow is the other half. It registers the map as an observer of the traffic
// store, so an exchange lands in the tree as it is recorded rather than when
// someone looks. Sync stays as the backfill primitive Follow uses for the
// exchanges that predate the registration, and as the repair path for a caller
// that needs to rebuild.
//
// Because the registration is on the *store*, every producer feeds it: the proxy,
// the crawler, and anything else that records an exchange. None of them needs to
// know the site map exists. The read handler deliberately no longer calls Sync —
// if it did, a broken observer would be invisible, which is exactly the
// ported-but-uncalled failure this project has shipped before.
package sitemap

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// PathNode represents one URL path on a host, with the exchanges that touched it.
type PathNode struct {
	Path     string
	Methods  map[string]int // method → count
	Statuses map[int]int    // status → count
	// Mimes is the distinct media-type words (core.Exchange.Mime, already stripped of parameters
	// and lowercased — see MimeEssence) recorded at this path. Keyed for dedup; order comes from the
	// serialiser, not from insertion. Populated only for nodes with responses, so a folder
	// synthesised to hold children aggregates its subtree on the way back up (foldPaths' assemble).
	Mimes       map[string]struct{}
	ExchangeIDs []core.ExchangeID
}

// HostNode groups all paths under one host.
type HostNode struct {
	Host  string
	Port  uint16
	TLS   bool
	Paths map[string]*PathNode
}

// SiteMap is the aggregated tree.
type SiteMap struct {
	mu    sync.RWMutex
	hosts map[string]*HostNode // key = host:port:tls
	// suppressed holds the host keys and host-prefixed path keys the operator removed
	// (burpsy-react-ui-10e). Removal is a SUPPRESSION, not a deletion: the map is a projection of
	// the exchange store, and deleting the underlying exchanges would renumber nothing but break
	// HTTP history rows, findings and audit references that name them. The suppression is the
	// recorded decision — the map stops showing what the operator removed, the store keeps every
	// byte — and Add consults it before folding, so a re-capture of a suppressed host stays out.
	//
	// Key shapes mirror hostKey/host+path identity, with the verb Burp distinguishes:
	//   "h:p:t"                    — whole host ("Delete host")
	//   "h:p:t|item|<path>"        — one path node exactly ("Delete item")
	//   "h:p:t|branch|<path>"      — the path and every descendant ("Delete branch")
	// Item and branch are different sentences an operator can mean, so they are stored apart and
	// answered differently: an item delete of /api must leave /api/data visible (it is a different
	// row), while a branch delete of /api must take /api/data with it even though nothing ever
	// requested /api itself — the folder was synthesised, its children live at their own path keys,
	// and only a prefix rule reaches them.
	suppressed map[string]struct{}
	// inserted is every host/path an operator added to the map themselves (amu). A SEPARATE map
	// rather than entries in `hosts`, for the reason the decision recorded: the observed tree is
	// rebuilt from the traffic store by Sync, so anything written into it would be erased on the next
	// rebuild and would make reference.ts's disclosure ("a host on the map was observed at some
	// point") false for every node on it. The two sets are merged on read, never on write.
	inserted map[string]*InsertedNode
	// unrequested is every URL the live passive crawl saw linked from proxied traffic and nobody has
	// requested yet (burpsy-react-ui-t3zk), Burp's grey "unrequested items". Kept apart from the
	// observed tree for the reason inserted is, and bounded by MaxUnrequested.
	//
	// Grouped by node — outer key insertKey(host, port, tls, NodePath(path)), inner key the URL as
	// linked (insertKey with the raw path) — so the moment a node becomes covered by traffic its
	// items can be dropped with one lookup instead of a scan of the whole set on the capture path
	// (burpsy-react-ui-vc98). unrequestedN is the item count the cap is checked against.
	unrequested  map[string]map[string]*UnrequestedNode
	unrequestedN int
	// pinned is every exchange an operator recorded into the map by id (burpsy-react-ui-4bfp) — Burp's
	// add_to_sitemap. The map already follows the store, so a captured exchange is on it unless a
	// suppression hides it; a pin is the operator saying "this one, anyway". It outranks the
	// suppression that was in force when it was made, survives Sync rebuilds, and is dropped by a
	// LATER suppression that covers it, because that is the newer decision.
	pinned map[core.ExchangeID]pin
	// nodes counts, per map node, the stored path keys that fold onto it: key is
	// insertKey(host, port, tls, NodePath(path)), value the number of raw keys in hosts[..].Paths
	// with that identity (burpsy-react-ui-u6f8). The observed tree is keyed on the path as captured,
	// query included, so "/search?q=1" and "/search?q=2" are two path keys — but one node, which is
	// how the web layer folds them and what an operator reads. "Is this already observed?" is a
	// question about the node, and answering it from the raw keys left a linked /search?q=1 grey
	// after /search?q=1 itself was requested. Counted rather than a set so a Suppress that drops one
	// raw key leaves the node observed while another still holds it.
	nodes map[string]int
	// folders counts, per folder, the observed nodes strictly beneath it: key is
	// insertKey(host, port, tls, folder) for every folder of a node's NodePath ("/" and "/a" for
	// /a/b), value how many observed nodes sit under it (burpsy-react-ui-vc98). GET /api/sitemap
	// treats a folder anything observed sits beneath as observed — the fold synthesises that folder
	// row, so an item there would be a second row for it — and the store has to agree with the read,
	// or an item the read hides keeps one of the MaxUnrequested slots for the life of the process.
	// Moved only when a node appears or disappears, never per exchange.
	folders map[string]int
}

// NodePath is the identity a path has on the map: the path with any query string removed,
// a leading slash, and no trailing slash, so "/search?q=1", "/search?q=2", "/search" and "/search/"
// are the one node (burpsy-react-ui-u6f8). This is the rule GET /api/sitemap folds the observed
// tree by — two requests differing only in query string are one node and the query strings become
// that node's parameter list — and the rule every "already observed?" check uses, so an item is
// cleared by exactly the traffic that makes its node requested.
func NodePath(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}

// NodeDepth is a node's depth on the map: the number of segments in its NodePath, so a host is 0
// (it has no path), "/" and "/a" are 1 and "/a/b" is 2. GET /api/sitemap reports observed, inserted
// and unrequested nodes with this one rule, so a grey /a/b is drawn at the depth of an observed /a/b
// rather than at 0 under its host (burpsy-react-ui-vc98).
func NodeDepth(p string) int {
	return strings.Count(NodePath(p), "/")
}

// MaxUnrequested bounds the unrequested set: a site that links to a calendar or a search with a fresh
// query on every page would otherwise grow it without end.
const MaxUnrequested = 20000

// UnrequestedNode is a URL seen linked from proxied traffic but never requested (t3zk). From is the
// page that linked to it.
type UnrequestedNode struct {
	Host string
	Port uint16
	TLS  bool
	Path string
	From string
	Seen time.Time
}

// AddUnrequested records a linked-but-never-requested URL. It reports false when the URL's node is
// already covered by traffic, or the URL is inserted, suppressed, already known as unrequested, or
// the set is full. "Covered" is by node (NodePath): a link to /search?q=2 is not recorded once
// /search?q=1 has been requested, because both are the requested /search node and its parameter
// list; and a link to a folder something observed sits beneath (/api once /api/users was requested)
// is not recorded either, because the map already draws that folder.
//
// Unrequested items are stored by the URL as linked, query included, so the parameter names of every
// link to a node survive; GET /api/sitemap draws them as the one grey node at NodePath. An item whose
// node becomes covered later is dropped from the set at that moment (see countNodeLocked), so the
// MaxUnrequested slots hold only items the map can still show.
func (sm *SiteMap) AddUnrequested(host string, port uint16, tls bool, path, from string, seen time.Time) bool {
	if host == "" || path == "" {
		return false
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.coveredLocked(host, port, tls, path) || sm.suppressedByLocked(hostKey(host, port, tls), path) {
		return false
	}
	key := insertKey(host, port, tls, path)
	if _, ok := sm.inserted[key]; ok {
		return false
	}
	nk := insertKey(host, port, tls, NodePath(path))
	group := sm.unrequested[nk]
	if _, ok := group[key]; ok || sm.unrequestedN >= MaxUnrequested {
		return false
	}
	if group == nil {
		if sm.unrequested == nil {
			sm.unrequested = make(map[string]map[string]*UnrequestedNode)
		}
		group = make(map[string]*UnrequestedNode, 1)
		sm.unrequested[nk] = group
	}
	group[key] = &UnrequestedNode{Host: host, Port: port, TLS: tls, Path: path, From: from, Seen: seen}
	sm.unrequestedN++
	return true
}

// dropUnrequestedNodeLocked removes every unrequested item stored under one node key. Callers hold
// sm.mu.
func (sm *SiteMap) dropUnrequestedNodeLocked(nodeKey string) {
	if group, ok := sm.unrequested[nodeKey]; ok {
		sm.unrequestedN -= len(group)
		delete(sm.unrequested, nodeKey)
	}
}

// Unrequested returns the unrequested set, sorted by host and path.
func (sm *SiteMap) Unrequested() []*UnrequestedNode {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make([]*UnrequestedNode, 0, sm.unrequestedN)
	for _, group := range sm.unrequested {
		for _, n := range group {
			c := *n
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// pin is where a pinned exchange sits, kept so a later Suppress can tell which pins it covers.
type pin struct {
	hostKey string
	path    string
}

// InsertedNode is a host/path an operator put on the map without sending traffic to it.
//
// Carries no counts, no methods and no statuses, because there are none: nothing was observed here.
// That absence IS the node's meaning, and the wire says so explicitly rather than rendering zeroes an
// operator would read as observations.
type InsertedNode struct {
	Host  string
	Port  uint16
	TLS   bool
	Path  string
	Added time.Time
}

func New() *SiteMap {
	return &SiteMap{
		hosts:      make(map[string]*HostNode),
		suppressed: make(map[string]struct{}),
		inserted:   make(map[string]*InsertedNode),

		unrequested: make(map[string]map[string]*UnrequestedNode),
		pinned:      make(map[core.ExchangeID]pin),
		nodes:       make(map[string]int),
		folders:     make(map[string]int),
	}
}

// RecordResult is what Record did.
type RecordResult struct {
	// AlreadyOnMap: the exchange was already in its path node; nothing changed.
	AlreadyOnMap bool
	// WasSuppressed: a host, branch or item suppression hid it, and the pin now shows it anyway.
	WasSuppressed bool
	HostKey       string
}

// Record puts one stored exchange on the map by id, whatever suppression is in force
// (burpsy-react-ui-4bfp). Idempotent: recording an exchange the map already holds changes nothing
// and says so.
func (sm *SiteMap) Record(ex *core.Exchange) RecordResult {
	key := hostKey(ex.Host, ex.Port, ex.TLS)
	sm.mu.Lock()
	defer sm.mu.Unlock()
	res := RecordResult{HostKey: key}
	if hn := sm.hosts[key]; hn != nil {
		if pn := hn.Paths[ex.Path]; pn != nil {
			if _, dup := idSlot(pn.ExchangeIDs, ex.ID); dup {
				res.AlreadyOnMap = true
				return res
			}
		}
	}
	res.WasSuppressed = sm.suppressedByLocked(key, ex.Path)
	if sm.pinned == nil {
		sm.pinned = make(map[core.ExchangeID]pin)
	}
	sm.pinned[ex.ID] = pin{hostKey: key, path: ex.Path}
	sm.addExchangeLocked(ex)
	return res
}

// Insert records a host/path an operator added to the map (amu).
//
// Idempotent on the exact node: adding the same one twice keeps the first Added time, because "when
// did you add this" is a fact about the first time, and a re-add that moved it would make the
// timestamp a record of the last click rather than of the decision.
//
// An inserted path that is ALREADY observed is recorded as nothing new: the observation is the
// stronger fact about that node, the caller is told so, and the map does not gain a second entry
// claiming a URL was never looked at when it was.
func (sm *SiteMap) Insert(host string, port uint16, tls bool, path string, added time.Time) (alreadyObserved bool) {
	if host == "" {
		return false
	}
	if path == "" && port == 0 {
		// A host with no port cannot be named: HostKey folds the port into the key, and "app.test:0"
		// would be a node that matches no authority. Refuse by returning, leaving the map unchanged.
		return false
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.observedLocked(host, port, tls, path) {
		return true
	}
	key := insertKey(host, port, tls, path)
	if _, ok := sm.inserted[key]; ok {
		return false
	}
	sm.inserted[key] = &InsertedNode{Host: host, Port: port, TLS: tls, Path: path, Added: added}
	return false
}

// observedLocked reports whether the observed tree already holds that node: the host for path "",
// otherwise any captured path with the same NodePath. Callers hold sm.mu.
func (sm *SiteMap) observedLocked(host string, port uint16, tls bool, path string) bool {
	if path == "" {
		return sm.hosts[hostKey(host, port, tls)] != nil
	}
	return sm.nodes[insertKey(host, port, tls, NodePath(path))] > 0
}

// coveredLocked reports whether traffic already accounts for this path's place on the map: its node
// is observed, or it names a folder some observed node sits beneath ("/" under any host with a path
// at all). This is the store-side twin of GET /api/sitemap's observedIndex, and the two must agree:
// an item the read hides but the store keeps is a MaxUnrequested slot nothing can ever free
// (burpsy-react-ui-vc98). Callers hold sm.mu.
func (sm *SiteMap) coveredLocked(host string, port uint16, tls bool, path string) bool {
	if path == "" {
		return sm.hosts[hostKey(host, port, tls)] != nil
	}
	k := insertKey(host, port, tls, NodePath(path))
	return sm.nodes[k] > 0 || sm.folders[k] > 0
}

// countNodeLocked moves the per-node count for one raw path key of hn by delta. Callers hold sm.mu.
//
// When a node appears (its count leaves zero) it, and every folder above it, become covered, and the
// unrequested items stored at any of them are dropped then and there: they are hidden by the read
// from this moment on, and keeping them would spend MaxUnrequested slots on rows nobody will see
// (burpsy-react-ui-vc98). Pruning at the transition rather than counting only visible items keeps
// the cap a bound on memory, which is what it exists for; the cost is one map lookup per folder
// level, paid only when a new node appears, never per exchange.
func (sm *SiteMap) countNodeLocked(hn *HostNode, rawPath string, delta int) {
	if sm.nodes == nil {
		sm.nodes = make(map[string]int)
	}
	if sm.folders == nil {
		sm.folders = make(map[string]int)
	}
	np := NodePath(rawPath)
	k := insertKey(hn.Host, hn.Port, hn.TLS, np)
	before := sm.nodes[k]
	if n := before + delta; n > 0 {
		sm.nodes[k] = n
	} else {
		delete(sm.nodes, k)
	}
	after := sm.nodes[k]
	switch {
	case before == 0 && after > 0:
		sm.dropUnrequestedNodeLocked(k)
		forEachFolder(np, func(folder string) {
			fk := insertKey(hn.Host, hn.Port, hn.TLS, folder)
			sm.folders[fk]++
			sm.dropUnrequestedNodeLocked(fk)
		})
	case before > 0 && after == 0:
		forEachFolder(np, func(folder string) {
			fk := insertKey(hn.Host, hn.Port, hn.TLS, folder)
			if n := sm.folders[fk] - 1; n > 0 {
				sm.folders[fk] = n
			} else {
				delete(sm.folders, fk)
			}
		})
	}
}

// forEachFolder calls fn with every folder a node path sits beneath, "/" first: "/", "/a" and "/a/b"
// for /a/b/c. The root node "/" sits beneath nothing.
func forEachFolder(np string, fn func(string)) {
	if np == "/" {
		return
	}
	fn("/")
	for i := 1; i < len(np); i++ {
		if np[i] == '/' {
			fn(np[:i])
		}
	}
}

// Inserts returns every operator-added node, in a stable order so the UI and the API agree on what
// the map contains. Callers hold sm.mu.
func (sm *SiteMap) insertsLocked() []*InsertedNode {
	out := make([]*InsertedNode, 0, len(sm.inserted))
	for _, n := range sm.inserted {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// Inserts is the public read: every operator-added node, host and path alike.
func (sm *SiteMap) Inserts() []*InsertedNode {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.insertsLocked()
}

// Inserted reports whether the operator added this exact node. A node that is also observed answers
// false here: the observation is the fact the map will draw.
func (sm *SiteMap) Inserted(host string, port uint16, tls bool, path string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	_, ok := sm.inserted[insertKey(host, port, tls, path)]
	return ok
}

func insertKey(host string, port uint16, tls bool, path string) string {
	return hostKey(host, port, tls) + "\x00" + path
}

// Sync rebuilds the sitemap from the traffic store's current exchanges.
//
// A full rebuild, so calling it twice is idempotent rather than doubling every
// count. Follow is what keeps the map current; this is the backfill and repair
// path.
// The store is read *before* this map's lock is taken, and that ordering is
// load-bearing rather than incidental. core.TrafficStore.AddExchange runs its
// observers — including Add — while holding the store's own lock, so the live
// path acquires ts.mu and then sm.mu. Taking sm.mu here and then calling
// store.Exchanges(), which acquires ts.mu, would be the opposite order: a
// classic AB-BA inversion that deadlocks the entire capture path the first time
// a Sync overlaps an arriving response, permanently and with no way out.
// Snapshotting first means this function only ever holds one lock at a time.
func (sm *SiteMap) Sync(store *core.TrafficStore) {
	exchanges := store.Exchanges()
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.hosts = make(map[string]*HostNode)
	sm.nodes = make(map[string]int)
	sm.folders = make(map[string]int)
	for _, ex := range exchanges {
		sm.addExchangeLocked(ex)
	}
}

// Follow makes the map continuous: it subscribes to the store and folds in the
// exchanges already recorded, with no window in which one could be missed or
// counted twice — see core.TrafficStore.ObserveExchanges for why that is one
// call and not two.
//
// Call once per map, before traffic flows and after any Restore. Following the
// same store twice would subscribe twice and count every later arrival twice.
func (sm *SiteMap) Follow(store *core.TrafficStore) {
	if store == nil {
		return
	}
	for _, ex := range store.ObserveExchanges(sm.Add) {
		sm.Add(ex)
	}
}

// Add folds one exchange into the tree. This is the observer Follow registers,
// and it is safe to call from the store's append path: it takes only this map's
// own lock and never reaches back into the store.
func (sm *SiteMap) Add(ex *core.Exchange) {
	if ex == nil {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.addExchangeLocked(ex)
}

func (sm *SiteMap) addExchangeLocked(ex *core.Exchange) {
	// An isolated scan's traffic stays out of the site map (13uw).
	if ex.Source.Isolated() {
		return
	}
	key := hostKey(ex.Host, ex.Port, ex.TLS)
	// A suppressed host or branch stays suppressed for re-captures too: Add runs before this on the
	// live path, but Sync's rebuild walks every stored exchange through here, so the check lives at
	// the fold rather than only at the observer.
	if sm.suppressedByLocked(key, ex.Path) {
		if _, pinned := sm.pinned[ex.ID]; !pinned {
			return
		}
	}
	hn := sm.hosts[key]
	if hn == nil {
		hn = &HostNode{
			Host:  ex.Host,
			Port:  ex.Port,
			TLS:   ex.TLS,
			Paths: make(map[string]*PathNode),
		}
		sm.hosts[key] = hn
	}
	pn := hn.Paths[ex.Path]
	if pn == nil {
		pn = &PathNode{
			Path:     ex.Path,
			Methods:  make(map[string]int),
			Statuses: make(map[int]int),
			Mimes:    make(map[string]struct{}),
		}
		hn.Paths[ex.Path] = pn
		sm.countNodeLocked(hn, ex.Path, 1)
	}
	// The id decides whether this exchange is new to the node, and it is checked
	// before any counter moves: a path already holding this id has already had
	// its method and status counted, and incrementing first would let a repeat
	// add double the counts while leaving the id list right.
	at, dup := idSlot(pn.ExchangeIDs, ex.ID)
	if dup {
		return
	}
	pn.Methods[ex.Method]++
	if ex.Status != nil {
		pn.Statuses[int(*ex.Status)]++
	}
	if ex.Mime != "" {
		pn.Mimes[ex.Mime] = struct{}{}
	}
	insertIDAt(pn, at, ex.ID)
}

const (
	// suppressItem and suppressBranch are the two path-level verbs stored in the suppression set.
	// Values are opaque; they exist so the map keys read the same in logs as in code.
	suppressItem   = "item"
	suppressBranch = "branch"
)

// suppressedByLocked reports whether this host or this path under it is suppressed. A whole-host
// entry answers for every path; an item entry answers its node (NodePath, so an item delete of /a
// covers /a?x=1 and /a/ too) or, when the delete named a URL with a query, that exact URL; a branch
// entry answers the node and anything beneath it (prefix on segment boundaries, so /api/ does not
// swallow /apiary). Callers hold sm.mu.
func (sm *SiteMap) suppressedByLocked(hostKey string, path string) bool {
	if _, ok := sm.suppressed[hostKey]; ok {
		return true
	}
	if path == "" {
		return false
	}
	clean := NodePath(path)
	if _, ok := sm.suppressed[hostKey+"|"+suppressItem+"|"+clean]; ok {
		return true
	}
	if clean != path {
		if _, ok := sm.suppressed[hostKey+"|"+suppressItem+"|"+path]; ok {
			return true
		}
	}
	prefix := hostKey + "|" + suppressBranch + "|"
	if _, ok := sm.suppressed[prefix+clean]; ok {
		return true
	}
	// Branches also cover anything under the deleted path. Walk ancestors rather than every key:
	// the capture path is short, and a host key prefix already answered the whole-host case.
	for cut := clean; ; {
		i := strings.LastIndexByte(cut, '/')
		if i <= 0 {
			return false
		}
		cut = cut[:i]
		if _, ok := sm.suppressed[prefix+cut]; ok {
			return true
		}
	}
}

// Suppress removes a host, a branch or a single item from the map's view
// (burpsy-react-ui-10e): Burp's "Delete host"/"Delete branch"/"Delete item". hostKey is
// HostKey(host, port, tls); path "" suppresses the whole host; kind picks item (exact path only)
// or branch (path and every descendant). The dropped nodes leave the tree immediately and stay out
// across Sync rebuilds and re-captures; the exchanges themselves are untouched, which is the
// recorded decision on the issue — history, findings and audit rows keep their references. There
// is deliberately no undo: re-capturing traffic re-populates the map, and a suppressed entry that
// keeps blocking honest traffic is an operator-visible decision they can revisit by restarting
// with a fresh capture. An Unsuppress would also need a "list what is suppressed" surface to be
// usable, which is a bigger feature than this issue.
func (sm *SiteMap) Suppress(hostKey string, path string, kind string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.suppressed == nil {
		sm.suppressed = make(map[string]struct{})
	}
	// A suppression is newer than any pin it covers, so those pins go: the operator's latest
	// decision about that host or branch is what the map shows. Checked after the key is stored, by
	// the same predicate the fold uses, so "covers" means exactly what it means everywhere else.
	defer func() {
		for id, p := range sm.pinned {
			if sm.suppressedByLocked(p.hostKey, p.path) {
				delete(sm.pinned, id)
			}
		}
		// Grey items under what was just deleted go with it: AddUnrequested already refuses a link
		// into a suppressed host or branch, and one recorded before the delete would otherwise
		// stay drawn — and keep its MaxUnrequested slot — under a node the operator removed. One
		// scan of the bounded set, on an operator action, never on the capture path.
		for nk, group := range sm.unrequested {
			for k, un := range group {
				if hostKey == HostKey(un.Host, un.Port, un.TLS) && sm.suppressedByLocked(hostKey, un.Path) {
					delete(group, k)
					sm.unrequestedN--
				}
			}
			if len(group) == 0 {
				delete(sm.unrequested, nk)
			}
		}
	}()
	if path == "" {
		sm.suppressed[hostKey] = struct{}{}
		// Dropping the host drops its whole subtree from the in-memory tree now; suppressing each
		// path individually is not needed — the host key answers for all of them.
		if hn, ok := sm.hosts[hostKey]; ok {
			for p := range hn.Paths {
				sm.countNodeLocked(hn, p, -1)
			}
		}
		delete(sm.hosts, hostKey)
		return
	}
	// The stored key and the live removal both work on node identity (burpsy-react-ui-vc98): the
	// tree an operator deletes from draws /a, /a?x=1 and /a/ as one row, so "Delete item" on that row
	// has to take every raw key folded into it — removing only the exact key "/a" left /a?x=1 on
	// screen and the node counted as observed until the next Sync. A path that carries a query names
	// one captured URL rather than a row, and is kept as that exact URL.
	exact := strings.IndexByte(path, '?') >= 0 && kind != suppressBranch
	stored := path
	if !exact {
		stored = NodePath(path)
	}
	sm.suppressed[hostKey+"|"+kind+"|"+stored] = struct{}{}
	if hn, ok := sm.hosts[hostKey]; ok {
		for p := range hn.Paths {
			var drop bool
			switch {
			case exact:
				drop = p == path
			case kind == suppressBranch:
				// Prefix removal for the live tree: every path at or under the branch goes now, not
				// on the next fold. The stored suppression set is what keeps them out afterwards.
				np := NodePath(p)
				drop = np == stored || strings.HasPrefix(np, stored+"/")
			default:
				drop = NodePath(p) == stored
			}
			if drop {
				delete(hn.Paths, p)
				sm.countNodeLocked(hn, p, -1)
			}
		}
		// A host with nothing left shows an empty branch forever; drop it too.
		if len(hn.Paths) == 0 {
			delete(sm.hosts, hostKey)
		}
	}
}

// HostKey exposes the host-key shape the suppression set and the web layer agree on.
func HostKey(host string, port uint16, tls bool) string {
	return hostKey(host, port, tls)
}

// idSlot returns where id belongs in an ascending slice, and whether it is
// already there.
func idSlot(ids []core.ExchangeID, id core.ExchangeID) (int, bool) {
	n := len(ids)
	if n == 0 || ids[n-1] < id {
		return n, false
	}
	at := sort.Search(n, func(i int) bool { return ids[i] >= id })
	return at, at < n && ids[at] == id
}

// insertIDAt keeps ExchangeIDs ascending, because the readers of that slice
// ("the last 20", "the most recent") take its tail as the newest.
//
// The append is the fast path and the only one live traffic takes: ids are
// assigned in order, so a new arrival belongs at the end. The shifting insert
// covers Follow's backfill, which races its own subscription by design — an
// exchange arriving mid-backfill is added before the older ones behind it, and
// without this the site map would report a page's oldest capture as its latest.
func insertIDAt(pn *PathNode, at int, id core.ExchangeID) {
	if at == len(pn.ExchangeIDs) {
		pn.ExchangeIDs = append(pn.ExchangeIDs, id)
		return
	}
	pn.ExchangeIDs = append(pn.ExchangeIDs, 0)
	copy(pn.ExchangeIDs[at+1:], pn.ExchangeIDs[at:])
	pn.ExchangeIDs[at] = id
}

// Hosts returns all host nodes, sorted by host name.
//
// # Why this deep-copies, and why a shallower version was a process-killing bug
//
// This used to copy only the top-level slice and hand back the live *HostNode
// pointers, releasing the lock on return. Every caller then walked hn.Paths,
// pn.ExchangeIDs, pn.Methods and pn.Statuses with no lock held at all — while
// addExchangeLocked wrote those exact structures from the store's append path.
// Reading a Go map while another goroutine writes it is not a stale read: the
// runtime raises `fatal error: concurrent map iteration and map write`, which is
// not a panic. There is no recover, no graceful shutdown; the proxy listener dies
// with the process and any capture not yet mirrored to SQLite is gone.
//
// It was reachable the whole time and needed only an operator opening the site-map
// tab while traffic flowed. It became routine when the tab started refetching
// itself about once a second under live push, which is what turned a rare race
// into an ordinary one.
//
// The fix is a snapshot rather than a documented "callers must hold the lock",
// because that contract cannot be enforced and every caller is an HTTP handler in
// another package. Returning immutable copies makes the unsafe read unwritable.
// Note what it deliberately does NOT do: reach into the store. The live path holds
// ts.mu and then sm.mu, so anything here that acquired ts.mu while holding sm.mu
// would deadlock capture permanently — see the note on Sync.
//
// The cost is real and worth stating: this allocates proportionally to the whole
// tree on every read, and the site-map tab now reads about once a second. That is
// the price of a read that cannot crash the process, and it is the right trade —
// but it is why the tree's size, not the read frequency, is what to watch if this
// ever shows up in a profile.
func (sm *SiteMap) Hosts() []*HostNode {
	sm.mu.RLock()
	out := make([]*HostNode, 0, len(sm.hosts))
	for _, hn := range sm.hosts {
		out = append(out, hn.clone())
	}
	sm.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// clone deep-copies a host node so a reader can walk it after the lock is gone.
// Called with sm.mu held.
func (hn *HostNode) clone() *HostNode {
	out := &HostNode{
		Host:  hn.Host,
		Port:  hn.Port,
		TLS:   hn.TLS,
		Paths: make(map[string]*PathNode, len(hn.Paths)),
	}
	for k, pn := range hn.Paths {
		out.Paths[k] = pn.clone()
	}
	return out
}

// clone deep-copies a path node, including the three structures the append path
// mutates in place: the two count maps and the id slice. Copying the maps by
// reference would leave exactly the crash this snapshot exists to prevent.
// Called with sm.mu held.
func (pn *PathNode) clone() *PathNode {
	out := &PathNode{
		Path:        pn.Path,
		Methods:     make(map[string]int, len(pn.Methods)),
		Statuses:    make(map[int]int, len(pn.Statuses)),
		Mimes:       make(map[string]struct{}, len(pn.Mimes)),
		ExchangeIDs: make([]core.ExchangeID, len(pn.ExchangeIDs)),
	}
	for m, n := range pn.Methods {
		out.Methods[m] = n
	}
	for s, n := range pn.Statuses {
		out.Statuses[s] = n
	}
	for m := range pn.Mimes {
		out.Mimes[m] = struct{}{}
	}
	copy(out.ExchangeIDs, pn.ExchangeIDs)
	return out
}

// PathsFor returns all paths for a host, sorted.
func (hn *HostNode) PathsSorted() []*PathNode {
	out := make([]*PathNode, 0, len(hn.Paths))
	for _, pn := range hn.Paths {
		out = append(out, pn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// MethodsSorted returns method names sorted.
func (pn *PathNode) MethodsSorted() []string {
	out := make([]string, 0, len(pn.Methods))
	for m := range pn.Methods {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// StatusesSorted returns status codes sorted.
func (pn *PathNode) StatusesSorted() []int {
	out := make([]int, 0, len(pn.Statuses))
	for s := range pn.Statuses {
		out = append(out, s)
	}
	sort.Ints(out)
	return out
}

// hostKey builds a stable key for a host node.
func hostKey(host string, port uint16, tls bool) string {
	return strings.Join([]string{host, intToStr(int(port)), boolToStr(tls)}, ":")
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func boolToStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
