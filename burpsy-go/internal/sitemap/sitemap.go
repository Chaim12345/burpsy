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
	Path        string
	Methods     map[string]int // method → count
	Statuses    map[int]int    // status → count
	ExchangeIDs []uint64
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
}

func New() *SiteMap { return &SiteMap{hosts: make(map[string]*HostNode)} }

// Sync rebuilds the sitemap from the traffic store's current exchanges.
//
// A full rebuild, so calling it twice is idempotent rather than doubling every
// count. Follow is what keeps the map current; this is the backfill and repair
// path.
func (sm *SiteMap) Sync(store *core.TrafficStore) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.hosts = make(map[string]*HostNode)
	for _, ex := range store.Exchanges() {
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
	insertIDAt(pn, at, ex.ID)
}

// idSlot returns where id belongs in an ascending slice, and whether it is
// already there.
func idSlot(ids []uint64, id uint64) (int, bool) {
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
func insertIDAt(pn *PathNode, at int, id uint64) {
	if at == len(pn.ExchangeIDs) {
		pn.ExchangeIDs = append(pn.ExchangeIDs, id)
		return
	}
	pn.ExchangeIDs = append(pn.ExchangeIDs, 0)
	copy(pn.ExchangeIDs[at+1:], pn.ExchangeIDs[at:])
	pn.ExchangeIDs[at] = id
}

// Hosts returns all host nodes, sorted by host name.
func (sm *SiteMap) Hosts() []*HostNode {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	out := make([]*HostNode, 0, len(sm.hosts))
	for _, hn := range sm.hosts {
		out = append(out, hn)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
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
