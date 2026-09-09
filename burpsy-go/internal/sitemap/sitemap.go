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
}

func New() *SiteMap {
	return &SiteMap{hosts: make(map[string]*HostNode), suppressed: make(map[string]struct{})}
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
	key := hostKey(ex.Host, ex.Port, ex.TLS)
	// A suppressed host or branch stays suppressed for re-captures too: Add runs before this on the
	// live path, but Sync's rebuild walks every stored exchange through here, so the check lives at
	// the fold rather than only at the observer.
	if sm.suppressedByLocked(key, ex.Path) {
		return
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
// entry answers for every path; an item entry answers its exact path; a branch entry answers the
// path and anything beneath it (prefix on segment boundaries, so /api/ does not swallow /apiary).
// Callers hold sm.mu.
func (sm *SiteMap) suppressedByLocked(hostKey string, path string) bool {
	if _, ok := sm.suppressed[hostKey]; ok {
		return true
	}
	if path == "" {
		return false
	}
	clean := path
	if i := strings.IndexByte(clean, '?'); i >= 0 {
		clean = clean[:i]
	}
	if _, ok := sm.suppressed[hostKey+"|"+suppressItem+"|"+clean]; ok {
		return true
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
	if path == "" {
		sm.suppressed[hostKey] = struct{}{}
		// Dropping the host drops its whole subtree from the in-memory tree now; suppressing each
		// path individually is not needed — the host key answers for all of them.
		delete(sm.hosts, hostKey)
		return
	}
	sm.suppressed[hostKey+"|"+kind+"|"+path] = struct{}{}
	if hn, ok := sm.hosts[hostKey]; ok {
		if kind == suppressBranch {
			// Prefix removal for the live tree: every path at or under the branch goes now, not on
			// the next fold. The stored suppression set is what keeps them out afterwards.
			for p := range hn.Paths {
				if p == path || strings.HasPrefix(p, path+"/") {
					delete(hn.Paths, p)
				}
			}
		} else {
			delete(hn.Paths, path)
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
