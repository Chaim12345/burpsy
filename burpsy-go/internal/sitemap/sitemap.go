// Package sitemap builds a tree of hosts → paths from the traffic store.
// Mirrors the Rust burpsy-core sitemap module: the proxy records exchanges,
// and the sitemap aggregates them into a navigable site structure for the web UI.
package sitemap

import (
	"sort"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/core"
)

// PathNode represents one URL path on a host, with the exchanges that touched it.
type PathNode struct {
	Path       string
	Methods    map[string]int // method → count
	Statuses   map[int]int    // status → count
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
func (sm *SiteMap) Sync(store *core.TrafficStore) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.hosts = make(map[string]*HostNode)
	for _, ex := range store.Exchanges() {
		sm.addExchangeLocked(ex)
	}
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
	pn.Methods[ex.Method]++
	if ex.Status != nil {
		pn.Statuses[int(*ex.Status)]++
	}
	pn.ExchangeIDs = append(pn.ExchangeIDs, ex.ID)
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
	if n == 0 { return "0" }
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg { n = -n }
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg { pos--; buf[pos] = '-' }
	return string(buf[pos:])
}

func boolToStr(b bool) string {
	if b { return "1" }
	return "0"
}
