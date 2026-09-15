package web

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/organizer"
	"github.com/burpsy-go/burpsy/internal/sitemap"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/tools"
)

// ---- Site map ----------------------------------------------------------------------------------

// sitemapNodeView mirrors sitemap.ts's NodeView.
type sitemapNodeView struct {
	// Key is the node's identity: the host for a host node, host + path for a path node, joined by a
	// NUL so no host/path split is ambiguous. It replaced an `id` that was a 31-based string hash
	// folded into an int — a value that could collide, could not be looked up, and meant nothing to
	// the server that emitted it. The UI had already stopped trusting it and re-derived host+path
	// itself, with a comment saying so; this makes the identity the UI actually uses the one the
	// server states.
	Key     string `json:"key"`
	Segment string `json:"segment"`
	Path    string `json:"path"`
	// Port and TLS repeat the host-node identity on every node, so a client acting on one row
	// (DELETE /api/sitemap, burpsy-react-ui-10e) can name the exact (host, port, tls) tuple without
	// parsing the composed `key` back into parts — a second grammar that can drift from the first.
	Port         uint16   `json:"port"`
	TLS          bool     `json:"tls"`
	Depth        int      `json:"depth"`
	Exchanges    int      `json:"exchanges"`
	Requested    bool     `json:"requested"`
	SubtreeCount int      `json:"subtree_exchanges"`
	ChildCount   int      `json:"child_count"`
	Methods      []string `json:"methods"`
	Statuses     []int    `json:"statuses"`
	// Mimes is the distinct media-type words (mimeLabel's vocabulary: "html", "json", "css", …)
	// seen in the subtree, so the UI's MIME filter bucket works without reading a single response
	// body — the same index-row rule the rest of the wire shape follows.
	Mimes  []string `json:"mimes"`
	Params []string `json:"params"`
	// Issues is the findings recorded at this exact path; SubtreeIssues includes everything beneath
	// it, and WorstSeverity is the worst of those. Burp marks a collapsed branch with what is inside
	// it, which is the whole point of a tree over a flat list: it says where to look before it is
	// expanded. Empty WorstSeverity means the subtree is clean.
	Issues        int    `json:"issues"`
	SubtreeIssues int    `json:"subtree_issues"`
	WorstSeverity string `json:"worst_severity,omitempty"`
	// InScope is whether the tools are allowed to touch this node. Burp dims out-of-scope branches
	// because the site map records everything the proxy saw, including third-party hosts the operator
	// has no authorisation for — and a map that shows an unauthorised host identically to an
	// authorised one invites someone to right-click it and attack it.
	//
	// A path node asks Scope.Contains, the same question the per-request gate asks. A host node is in
	// scope when its own root is, *or* when anything beneath it is — the truthful question for a
	// branch is "does this contain something you may touch", and answering it any other way misreads
	// two real rule shapes in opposite directions. An `include(h)` plus a path-scoped
	// `exclude(h, "/admin")` must leave the host lit, and an `include(h).with_path_prefix("/v1/")`
	// must also leave it lit even though `h`'s root is not itself in scope.
	//
	// Deliberately not MayContainHost: that is a pre-filter for attacks and answers a coarser question
	// than the sitemap asks. It refuses a host no include rule names, agreeing with Contains on the
	// "unlisted third party" case — but a path-scoped include (`include(h, "/v1/")`) still lights the
	// whole host to it, because "may an attack invent a path here" has to stay open for the host whose
	// /v1/ paths are authorised. The sitemap instead asks Contains per node, so it has the precision to
	// light /v1/ and dim the host root. This value only decides what is greyed; authorisation stays on
	// the bytes going out.
	InScope      bool              `json:"in_scope"`
	LastExchange *int64            `json:"last_exchange"`
	Recent       []core.ExchangeID `json:"recent_exchanges"`
	Children     []sitemapNodeView `json:"children,omitempty"`
}

// sitemapTreeResp mirrors sitemap.ts's TreeResp.
type sitemapTreeResp struct {
	Exchanges int               `json:"exchanges"`
	Nodes     int               `json:"nodes"`
	Synced    int               `json:"synced"`
	InFlight  int               `json:"in_flight"`
	Matched   *int              `json:"matched,omitempty"`
	Tree      []sitemapNodeView `json:"tree"`
}

// handleSitemap serves GET /api/sitemap?host=&path=&depth= and DELETE /api/sitemap
// (burpsy-react-ui-10e). The Go sitemap aggregates hosts → paths → methods/statuses from captured
// exchanges; this folds it into the same tree the UI renders, treating each path segment as a node.
//
// DELETE is Burp's "Delete host"/"Delete branch"/"Delete item". The body names the node the way
// the tree identifies it — {"host","port","tls","path","kind"} — rather than a pre-built key
// string: parsing a composed key back into its parts is a second grammar that can drift from the
// first, and the fields are what the UI already holds in the row object. kind is "item" (that one
// path node only) or "branch" (the path and everything beneath it); path "" means the whole host.
// Removal is a SUPPRESSION (sitemap.SiteMap.Suppress): the projection drops the branch and keeps
// it out across rebuilds and re-captures, while the exchanges themselves stay — HTTP history rows,
// findings and audit references keep naming them. That decision is recorded on the issue and in
// Suppress's doc comment; deleting store bytes from a map view would have broken every other
// tool's currency.
func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.sitemapGet(w, r)
	case http.MethodDelete:
		s.sitemapDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// sitemapDelete validates the node fields the UI sent and suppresses that host, branch or item.
// A wrong-verb answer is the mux's business; a body naming no host, or a path with no kind, is a
// 400 saying what was wrong — not a silent success that removed nothing.
func (s *Server) sitemapDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
		TLS  bool   `json:"tls"`
		Path string `json:"path"`
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Host == "" {
		http.Error(w, "body must be JSON {\"host\": \"h\", \"port\": n, \"tls\": bool, \"path\": \"\", \"kind\": \"host\"} (path \"\" = whole host) or {.., \"path\": \"/p\", \"kind\": \"item\"|\"branch\"}", http.StatusBadRequest)
		return
	}
	// The literals match sitemap's suppressItem/suppressBranch values; they are spelled here rather
	// than exported from sitemap because the wire vocabulary is this API's contract, not the map
	// package's.
	if req.Path != "" && req.Kind != "item" && req.Kind != "branch" {
		http.Error(w, "kind must be \"item\" or \"branch\" when a path is given", http.StatusBadRequest)
		return
	}
	if req.Path == "" {
		req.Kind = "host"
	}
	s.sitemap.Suppress(sitemap.HostKey(req.Host, req.Port, req.TLS), req.Path, req.Kind)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"suppressed": req.Host + req.Path, "kind": req.Kind})
}

func (s *Server) sitemapGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hostFilter := q.Get("host")
	pathFilter := q.Get("path")

	// No Sync here. The map follows the store (see the sitemap package docs on CRAWL-05), so it is
	// already current; rebuilding it on every read would also make a broken subscription invisible,
	// because the read path would quietly do the subscription's job.
	exchanges := s.store.Exchanges()
	// Built once for the whole tree rather than per node: findings are indexed by node key, and
	// re-walking every finding at every node would be quadratic in a map that only needs building
	// once.
	issues := s.issuesByNode()
	var tree []sitemapNodeView
	var nodeCount int

	for _, host := range s.sitemap.Hosts() {
		if hostFilter != "" && host.Host != hostFilter {
			continue
		}
		children := s.foldPaths(host, pathFilter, &nodeCount, issues)
		lastEx := lastExchangeID(exchanges, host.Host)
		hostIssues, hostWorst := 0, -1
		hostMimes := map[string]struct{}{}
		for _, c := range children {
			hostIssues += c.SubtreeIssues
			if r := severityRankOf(c.WorstSeverity); r > hostWorst {
				hostWorst = r
			}
			for _, m := range c.Mimes {
				hostMimes[m] = struct{}{}
			}
		}
		tree = append(tree, sitemapNodeView{
			Key:           nodeKey(host.Host, host.Port, host.TLS, ""),
			Segment:       host.Host,
			Path:          host.Host,
			Port:          host.Port,
			TLS:           host.TLS,
			Depth:         0,
			Exchanges:     len(host.Paths),
			Requested:     true,
			SubtreeCount:  len(host.Paths),
			ChildCount:    len(children),
			Methods:       []string{},
			Statuses:      []int{},
			Mimes:         sortedSetKeys(hostMimes),
			LastExchange:  lastEx,
			Recent:        []core.ExchangeID{},
			SubtreeIssues: hostIssues,
			WorstSeverity: severityName(hostWorst),
			InScope:       s.scope.Contains(host.Host, host.Port, "/", host.TLS) || anyInScope(children),
			Children:      children,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sitemapTreeResp{
		Exchanges: len(exchanges),
		Nodes:     nodeCount,
		Synced:    len(exchanges),
		InFlight:  0,
		Tree:      tree,
	})
}

// anyInScope reports whether any node in these subtrees is in scope, so a host stays lit when only
// some prefix beneath it is authorised. Recursive rather than a scan of the top level: an
// `include(h).with_path_prefix("/v1/deep/")` puts the only in-scope node several levels down.
func anyInScope(nodes []sitemapNodeView) bool {
	for _, n := range nodes {
		if n.InScope || anyInScope(n.Children) {
			return true
		}
	}
	return false
}

// pathAgg accumulates every captured path that folds onto one tree node.
//
// Two requests differing only in query string are one node in Burp's site map and one node here, so
// the aggregation is keyed on the path alone and the query strings survive as the node's parameter
// list rather than as tree structure. Keying on the raw path instead produced two visible defects:
// `/search?q=<script>alert(1)</script>` split on the slash inside `</script>` and rendered a node
// literally named `script>`, and every distinct query string became its own sibling leaf.
type pathAgg struct {
	// requested distinguishes a path something actually asked for from a folder synthesised only to
	// hold children. Burp greys the latter; the UI needs the same signal.
	requested bool
	methods   map[string]int
	statuses  map[int]int
	mimes     map[string]struct{}
	ids       []core.ExchangeID
	params    map[string]struct{}
}

// foldPaths turns a host's path map into the node tree the UI renders. Each *path* becomes one node
// at its segment depth, query strings are folded into the node's parameter list, and the folders
// leading to a requested resource are synthesised so the tree nests instead of listing leaves flat.
func (s *Server) foldPaths(host *sitemap.HostNode, pathFilter string, nodeCount *int, issues map[string]*issueAgg) []sitemapNodeView {
	aggs := map[string]*pathAgg{}
	ensure := func(p string) *pathAgg {
		a := aggs[p]
		if a == nil {
			a = &pathAgg{methods: map[string]int{}, statuses: map[int]int{}, mimes: map[string]struct{}{}, params: map[string]struct{}{}}
			aggs[p] = a
		}
		return a
	}

	for _, pn := range host.PathsSorted() {
		// Filter against the path as captured, query string included, so searching for a parameter
		// value still finds the node it belongs to even though the node is keyed on the path.
		if pathFilter != "" && !strings.Contains(pn.Path, pathFilter) {
			continue
		}
		clean, rawQuery := splitPathQuery(pn.Path)
		a := ensure(clean)
		a.requested = true
		for m, n := range pn.Methods {
			a.methods[m] += n
		}
		for st, n := range pn.Statuses {
			a.statuses[st] += n
		}
		for m := range pn.Mimes {
			a.mimes[m] = struct{}{}
		}
		a.ids = append(a.ids, pn.ExchangeIDs...)
		for _, name := range queryParamNames(rawQuery) {
			a.params[name] = struct{}{}
		}
		// Burp shows the folders on the way to a resource even when nothing requested the folder
		// itself. Without these, /api/debug has no /api to nest under and surfaces as a root.
		for _, anc := range ancestorPaths(clean) {
			ensure(anc)
		}
	}

	keys := make([]string, 0, len(aggs))
	for p := range aggs {
		keys = append(keys, p)
	}
	sort.Strings(keys)

	views := make(map[string]*sitemapNodeView, len(aggs))
	childOf := map[string][]string{}
	var roots []string
	for _, p := range keys {
		a := aggs[p]
		sort.Slice(a.ids, func(i, j int) bool { return a.ids[i] < a.ids[j] })
		a.ids = dedupeExchangeIDs(a.ids)
		*nodeCount++
		agg := issues[nodeKey(host.Host, host.Port, host.TLS, p)]
		own, ownWorst := 0, -1
		if agg != nil {
			own, ownWorst = agg.count, agg.worst
		}
		views[p] = &sitemapNodeView{
			Key:           nodeKey(host.Host, host.Port, host.TLS, p),
			Segment:       pathSegment(p),
			Path:          p,
			Port:          host.Port,
			TLS:           host.TLS,
			Depth:         strings.Count(p, "/"),
			Exchanges:     len(a.ids),
			Requested:     a.requested,
			Methods:       sortedStringKeys(a.methods),
			Statuses:      statusInts(a.statuses),
			Mimes:         sortedSetKeys(a.mimes),
			Params:        sortedSetKeys(a.params),
			LastExchange:  lastExchangeForPath(host.Host, a.ids),
			Recent:        lastN(a.ids, 20),
			Issues:        own,
			SubtreeIssues: own,
			WorstSeverity: severityName(ownWorst),
			InScope:       s.scope.Contains(host.Host, host.Port, p, host.TLS),
			Children:      []sitemapNodeView{},
		}
		if parent := parentOfPath(p); parent != "" && aggs[parent] != nil {
			childOf[parent] = append(childOf[parent], p)
		} else {
			roots = append(roots, p)
		}
	}

	// Subtree totals are summed on the way back up rather than assigned per node, so a folder that
	// was never requested still reports the traffic underneath it instead of zero.
	var assemble func(p string) sitemapNodeView
	assemble = func(p string) sitemapNodeView {
		v := *views[p]
		total := v.Exchanges
		issueTotal := v.Issues
		worst := severityRankOf(v.WorstSeverity)
		// Mimes union up the tree like the counts do, so a folder's MIME filter bucket sees what its
		// descendants serve. views[p].Mimes is the node's own set; the copy here is the union.
		mimes := make(map[string]struct{}, len(v.Mimes))
		for _, m := range v.Mimes {
			mimes[m] = struct{}{}
		}
		for _, c := range childOf[p] {
			cv := assemble(c)
			total += cv.SubtreeCount
			issueTotal += cv.SubtreeIssues
			if r := severityRankOf(cv.WorstSeverity); r > worst {
				worst = r
			}
			for _, m := range cv.Mimes {
				mimes[m] = struct{}{}
			}
			v.Children = append(v.Children, cv)
		}
		v.ChildCount = len(v.Children)
		v.SubtreeCount = total
		v.SubtreeIssues = issueTotal
		v.WorstSeverity = severityName(worst)
		v.Mimes = sortedSetKeys(mimes)
		return v
	}
	out := make([]sitemapNodeView, 0, len(roots))
	for _, p := range roots {
		out = append(out, assemble(p))
	}
	return out
}

// splitPathQuery separates the path component from the query string and normalises the path, so the
// tree is built from path structure alone.
func splitPathQuery(p string) (string, string) {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return normalisePath(p[:i]), p[i+1:]
	}
	return normalisePath(p), ""
}

// normalisePath gives every path a leading slash and no trailing one, so `/a`, `/a/` and a stored
// `a` are the one node an operator reads them as.
func normalisePath(p string) string {
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

// parentOfPath returns the folder one segment up, or "" for a top-level path.
//
// "/" is never a parent: the host node is the tree's root, exactly as in Burp, so `/api` hangs off
// the host rather than off a synthesised "/" wrapper. A requested "/" is still a node — the root
// document is real traffic — it is just a sibling of `/api`, not its parent.
func parentOfPath(p string) string {
	if p == "" || p == "/" {
		return ""
	}
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// ancestorPaths lists every folder between p and the host root, nearest first.
func ancestorPaths(p string) []string {
	var out []string
	for cur := parentOfPath(p); cur != ""; cur = parentOfPath(cur) {
		out = append(out, cur)
	}
	return out
}

// pathSegment is the node's own label: its last path component, or "/" at the root.
func pathSegment(p string) string {
	if p == "/" || p == "" {
		return "/"
	}
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// queryParamNames lists the parameter names in a raw query string. A name that will not unescape is
// reported as written rather than dropped — the operator saw it on the wire that way.
func queryParamNames(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		name := pair
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name = pair[:i]
		}
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func dedupeExchangeIDs(sorted []core.ExchangeID) []core.ExchangeID {
	out := sorted[:0]
	for i, v := range sorted {
		if i == 0 || sorted[i-1] != v {
			out = append(out, v)
		}
	}
	return out
}

func sortedStringKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSetKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lastExchangeID(exchanges []*core.Exchange, host string) *int64 {
	for i := len(exchanges) - 1; i >= 0; i-- {
		if exchanges[i].Host == host {
			v := int64(exchanges[i].ID)
			return &v
		}
	}
	return nil
}

func lastExchangeForPath(host string, ids []core.ExchangeID) *int64 {
	if len(ids) == 0 {
		return nil
	}
	v := int64(ids[len(ids)-1])
	return &v
}

func statusInts(statuses map[int]int) []int {
	out := make([]int, 0, len(statuses))
	for st := range statuses {
		out = append(out, st)
	}
	// deterministic order
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func lastN(ids []core.ExchangeID, n int) []core.ExchangeID {
	if len(ids) <= n {
		return ids
	}
	return ids[len(ids)-n:]
}

// issueAgg is the findings recorded at one site-map node.
type issueAgg struct {
	count int
	// worst is a core.Severity rank, or -1 for none. Not a string: the roll-up compares ranks, and
	// comparing severity names as text would order Critical below Informational.
	worst int
}

// issuesByNode indexes findings by the tree node they belong to.
//
// Attribution goes through ExchangeByRequest — the same rule as the issues API — so a finding is
// counted against the URL it was actually found at. The path is normalised exactly as the tree
// normalises it, query string removed, so a finding on /search?q=1 lands on the /search node rather
// than on a node that does not exist.
func (s *Server) issuesByNode() map[string]*issueAgg {
	out := map[string]*issueAgg{}
	if s.findings == nil {
		return out
	}
	for _, f := range s.findings.All() {
		// core.Finding's own contract: a dismissed finding stays in the store but "the severity
		// counts exclude it" — the Issues page honours that, and the site map's per-node counts
		// are the same severity counts by another door. A node that kept counting what the
		// operator dismissed would disagree with the page that triage happened on.
		if f.FalsePositive {
			continue
		}
		// EffectiveSeverity, not the engine's Severity: an override is the operator's call on
		// how the finding reads, and the dot on the node paints that call.
		rank := int(f.EffectiveSeverity())
		// One finding seen at three places marks three nodes; that is what "where are my issues" means.
		for _, occ := range f.Occurrences {
			ex, err := s.store.ExchangeByRequest(occ.Request)
			if err != nil {
				continue // unresolvable: counted nowhere rather than blamed on a guess
			}
			clean, _ := splitPathQuery(ex.Path)
			key := nodeKey(ex.Host, ex.Port, ex.TLS, clean)
			agg := out[key]
			if agg == nil {
				agg = &issueAgg{worst: -1}
				out[key] = agg
			}
			agg.count++
			if rank > agg.worst {
				agg.worst = rank
			}
		}
	}
	return out
}

// severityName renders a core.Severity rank, or "" for the -1 that means no finding. The empty
// string is the signal a node is clean; it is not a severity called "unknown".
func severityName(rank int) string {
	if rank < 0 {
		return ""
	}
	return core.Severity(rank).String()
}

// severityRankOf is severityName's inverse, so a roll-up can compare a child's reported severity
// against a parent's without either side holding two representations of the same thing.
func severityRankOf(name string) int {
	if name == "" {
		return -1
	}
	for r := int(core.SeverityInformational); r <= int(core.SeverityCritical); r++ {
		if core.Severity(r).String() == name {
			return r
		}
	}
	return -1
}

// nodeKey is a tree node's exact identity.
//
// The NUL separator is what makes it exact rather than merely usually-right: without it, host "a"
// with path "/b" and a host literally named "a/b" would produce the same key, and a hostname cannot
// contain NUL. An empty path means the node is the host itself.
//
// The scheme and port are part of that identity, because the site map's own host table is keyed on
// (host, port, TLS) — see internal/sitemap's hosts map — so one hostname reached over both http and
// https is two host nodes in the tree. Keying on the hostname alone gave those two nodes the same
// key, and their `/` children the same key again: the response carried duplicate ids for distinct
// rows while this comment claimed exactness. The UI uses `key` as its React key, its expansion-state
// key and its cursor/selection id (pages/sitemap.tsx), so the collision made two real branches
// collapse into one selectable row.
func nodeKey(host string, port uint16, tls bool, path string) string {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	authority := scheme + "://" + host + ":" + strconv.Itoa(int(port))
	if path == "" {
		return authority
	}
	return authority + "\x00" + path
}

// ---- Match & Replace ---------------------------------------------------------------------------

// matchReplaceRuleSpec mirrors the UI's RuleSpec.
//
// # Why Scope and Query are declared only to be refused
//
// Both come from the Rust-era wire shape, which carried a per-rule scope and a query
// condition. Burp's match/replace rule model has neither: its persisted rule is exactly
// rule_type, enabled, category, string_match, string_replace and comment (see
// Zho_/CoreComponent5145 in the decompiled build, and Ekijh's serializer, which write those
// six and nothing else), its rule table has seven columns and none of them is a scope (see
// CoreComponent5002), and its documentation's only scope control is the panel-wide "Only
// apply to in-scope items" checkbox. So there is no per-rule scope to persist, and the old
// behaviour — accept the field, drop it on save, warn in the UI — was the worst of the three
// options: a rule that survives one save and not the next is a rule whose behaviour changed
// without anyone editing it.
//
// Declared here rather than ignored so the refusal can name the field. `*any` and `*string`
// are nil for an absent key and for an explicit null, and non-nil for anything a caller
// actually meant to set, which is the distinction the refusal needs.
type matchReplaceRuleSpec struct {
	RuleType      string  `json:"rule_type"`
	Enabled       bool    `json:"enabled"`
	StringMatch   string  `json:"string_match"`
	StringReplace string  `json:"string_replace"`
	Category      string  `json:"category"`
	Comment       string  `json:"comment"`
	Scope         *any    `json:"scope,omitempty"`
	Query         *string `json:"query,omitempty"`
}

// matchReplaceSetSpec mirrors the UI's RuleSetSpec.
//
// InScopeOnly is Burp's "Only apply to in-scope items"; its config key is
// `proxy.match_replace_disable_out_of_scope` and this field is named after the checkbox,
// for the reason matchreplace.RuleSet.SetInScopeOnly gives.
type matchReplaceSetSpec struct {
	Rules               []matchReplaceRuleSpec `json:"rules"`
	UpdateContentLength bool                   `json:"update_content_length"`
	InScopeOnly         bool                   `json:"in_scope_only"`
}

// matchReplaceGetResp mirrors the UI's RulesGetResp.
//
// ScopeSkipped is the live count of messages the rules declined to rewrite because they were
// out of scope. It is on this response rather than on the proxy's options snapshot because
// it is a property of the rule set and it is the only evidence an operator has that a rule
// which stopped matching did so because scope was narrowed rather than because the site
// changed — the same distinction proxy.Options draws with its Skipped* counters.
type matchReplaceGetResp struct {
	AffectsRequests  bool                `json:"affects_requests"`
	AffectsResponses bool                `json:"affects_responses"`
	ScopeSkipped     uint64              `json:"scope_skipped"`
	Config           matchReplaceSetSpec `json:"config"`
}

// matchReplaceTargetNames is the accepted rule_type vocabulary, in the engine's own
// declaration order. It is the single list both directions use: targetToCategory refuses
// anything outside it, and the error names it so a caller learns the vocabulary from the
// rejection rather than from the source.
var matchReplaceTargetNames = []string{
	"request_header",
	"request_body",
	"request_first_line",
	"response_header",
	"response_body",
	"websocket_to_server",
	"websocket_to_client",
	"request_param_name",
	"request_param_value",
}

// targetToCategory maps the UI's rule_type to the engine's Target.
//
// # Why the unknown case is an error and not a default
//
// It used to return `0, nil`, and both call sites discarded the error with `target, _ :=`.
// `matchreplace.Target` is an iota enum whose zero value is TargetRequestHeader, so a
// misspelled or unsupported rule_type did not fail — it silently produced a rule that
// rewrote **request headers on live traffic**. The operator asked to rewrite one thing and
// got a rule against another, with a 200 and a `{"compiled":N}` that counted it as accepted.
//
// That is the exact failure mode this project is built against, and it was worse than an
// ordinary tolerant-parser bug because the affected surface is the proxy: the wrong answer
// was applied to real requests, not merely displayed. A rule the engine cannot express is
// now a 400 that names what is accepted.
//
// request_param_name / request_param_value were refused here for months (see 4469cf1 and
// the incident in applyOne's history): the engine declared the Targets but nothing applied
// them, so accepting them silently rewrote whole bodies. The appliers now exist
// (applyParamName / applyParamValue in internal/matchreplace) and are field-boundary-honest:
// a literal name rule matches the whole name, so `secret` cannot rename `nonsecret`. They
// are accepted again, with the boundary semantics pinned by tests in unapplied_target_test.go.
func targetToCategory(ruleType string) (matchreplace.Target, error) {
	switch ruleType {
	case "request_first_line":
		return matchreplace.TargetRequestFirstLine, nil
	case "request_header":
		return matchreplace.TargetRequestHeader, nil
	case "request_body":
		return matchreplace.TargetRequestBody, nil
	case "response_header":
		return matchreplace.TargetResponseHeader, nil
	case "response_body":
		return matchreplace.TargetResponseBody, nil
	case "websocket_to_server":
		return matchreplace.TargetWebSocketToServer, nil
	case "websocket_to_client":
		return matchreplace.TargetWebSocketToClient, nil
	case "":
		return 0, fmt.Errorf("rule_type is required; accepted values are %s", strings.Join(matchReplaceTargetNames, ", "))
	case "request_param_name":
		return matchreplace.TargetRequestParamName, nil
	case "request_param_value":
		return matchreplace.TargetRequestParamValue, nil
	default:
		return 0, fmt.Errorf("unknown rule_type %q; accepted values are %s", ruleType, strings.Join(matchReplaceTargetNames, ", "))
	}
}

func (s *Server) matchReplaceRulesHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.matchReplaceGet(w, r)
	case http.MethodPut:
		s.matchReplacePut(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) matchReplaceGet(w http.ResponseWriter, r *http.Request) {
	rules := s.matchReplace.Rules()
	specs := make([]matchReplaceRuleSpec, 0, len(rules))
	for _, rule := range rules {
		specs = append(specs, matchReplaceRuleSpec{
			RuleType:      matchReplaceTargetName(rule.Target),
			Enabled:       rule.Enabled,
			StringMatch:   rule.StringMatch,
			StringReplace: rule.StringReplace,
			Category:      matchReplaceCategoryName(rule.Category),
			Comment:       rule.Comment,
		})
	}
	config := matchReplaceSetSpec{
		Rules:               specs,
		UpdateContentLength: s.matchReplace.UpdateContentLength(),
		InScopeOnly:         s.matchReplace.InScopeOnly(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(matchReplaceGetResp{
		AffectsRequests:  s.matchReplace.Affects(matchreplace.DirRequest),
		AffectsResponses: s.matchReplace.Affects(matchreplace.DirResponse),
		ScopeSkipped:     s.matchReplace.ScopeSkipped(),
		Config:           config,
	})
}

func (s *Server) matchReplacePut(w http.ResponseWriter, r *http.Request) {
	var set matchReplaceSetSpec
	if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	rules := make([]*matchreplace.Rule, 0, len(set.Rules))
	for i, spec := range set.Rules {
		// Rejected before any rule is installed, and the index is named: this is a
		// whole-list PUT, so a rule the engine cannot express must leave the live set
		// untouched rather than replacing it with a partially-correct one.
		target, err := targetToCategory(spec.RuleType)
		if err != nil {
			http.Error(w, fmt.Sprintf("Rule %d: %s", i, err.Error()), http.StatusBadRequest)
			return
		}
		if err := refuseUnrepresentableRuleFields(i, spec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cat := matchreplace.CategoryLiteral
		if spec.Category == "regex" {
			cat = matchreplace.CategoryRegex
		}
		rule, err := matchreplace.NewRule(target, cat, spec.StringMatch, spec.StringReplace, spec.Comment)
		if err != nil {
			http.Error(w, "Invalid rule: "+err.Error(), http.StatusBadRequest)
			return
		}
		rule.Enabled = spec.Enabled
		rules = append(rules, rule)
	}
	s.matchReplace.SetRules(rules)
	s.matchReplace.SetUpdateContentLength(set.UpdateContentLength)
	s.matchReplace.SetInScopeOnly(set.InScopeOnly)
	s.persistMatchReplace()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"compiled": len(rules)})
}

// matchReplaceTargetName is targetToCategory's inverse, and must stay total over the
// engine's enum.
//
// TargetRequestParamName and TargetRequestParamValue were missing and fell through to a
// `return "request_body"` default, so a param rule read back as a body rule. Combined with
// PUT's old coercion that made the round trip actively destructive: GET a param rule, PUT it
// back unchanged, and it became a body rule against live traffic. Both are named now.
//
// The default no longer guesses. An enum value with no wire name is a build where this
// function was not updated alongside the engine, and answering "request_body" would let that
// omission reach the operator disguised as a real rule; the string says what happened
// instead, and the round-trip test in api_toolkit_test.go asserts every declared Target maps
// to a name that targetToCategory accepts back.
func matchReplaceTargetName(t matchreplace.Target) string {
	switch t {
	case matchreplace.TargetRequestFirstLine:
		return "request_first_line"
	case matchreplace.TargetRequestHeader:
		return "request_header"
	case matchreplace.TargetRequestBody:
		return "request_body"
	case matchreplace.TargetRequestParamName:
		return "request_param_name"
	case matchreplace.TargetRequestParamValue:
		return "request_param_value"
	case matchreplace.TargetResponseHeader:
		return "response_header"
	case matchreplace.TargetResponseBody:
		return "response_body"
	case matchreplace.TargetWebSocketToServer:
		return "websocket_to_server"
	case matchreplace.TargetWebSocketToClient:
		return "websocket_to_client"
	default:
		return fmt.Sprintf("unrecognised_target_%d", int(t))
	}
}

func matchReplaceCategoryName(c matchreplace.Category) string {
	if c == matchreplace.CategoryRegex {
		return "regex"
	}
	return "literal"
}

// refuseUnrepresentableRuleFields rejects a rule carrying a field this build's model — which is
// Burp's model — has no place for.
//
// # Why a refusal and not a silent drop
//
// The previous behaviour accepted `scope` and `query`, saved the rule without either, and
// warned about it in the UI. That is the failure this project refuses everywhere else: the
// operator's rule is stored, the next GET reads it back without the condition, and the rule
// then applies to traffic the operator believed was excluded. A dropped condition is worse
// than a rejected rule, because a rejected rule is a 400 they can act on and a dropped one is
// a silent widening of what the rules touch.
//
// The message names the alternative rather than only the rejection: an operator who wanted
// "only these items" has one control available, and it is the panel-wide toggle.
func refuseUnrepresentableRuleFields(index int, spec matchReplaceRuleSpec) error {
	if spec.Scope != nil {
		return fmt.Errorf("Rule %d: per-rule scope is not part of Burp's match/replace model, and this build has no way to honour it; to limit the rules to in-scope traffic use the 'Only apply to in-scope items' setting", index)
	}
	if spec.Query != nil {
		return fmt.Errorf("Rule %d: a per-rule query condition is not part of Burp's match/replace model, and this build has no way to honour it", index)
	}
	return nil
}

func (s *Server) handleMatchReplaceRules(w http.ResponseWriter, r *http.Request) {
	s.matchReplaceRulesHandler(w, r)
}

// handleMatchReplaceTest compiles draft rules and applies them to an input, mirroring the UI's
// "original vs auto-modified" test.
//
// It deliberately does not consult the set's "Only apply to in-scope items" restriction, and it takes
// no target to consult it against: the box holds raw bytes someone pasted, which name no URL this
// server can resolve. Burp's own rule test behaves the same way — it answers "what do these rules do
// to this input", and scope is a question about an exchange. Reporting a rule as skipped here would
// be inventing a verdict from a URL nobody supplied.
func (s *Server) handleMatchReplaceTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Input      string                 `json:"input"`
		Direction  string                 `json:"direction"`
		DraftRules []matchReplaceRuleSpec `json:"draft_rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	rules := make([]*matchreplace.Rule, 0, len(req.DraftRules))
	for i, spec := range req.DraftRules {
		// The dry-run path refuses the same input the live path refuses. If it coerced
		// where the live path rejects, the preview would be a demonstration of behaviour
		// the operator can never actually install — the one thing a dry run must not do.
		target, err := targetToCategory(spec.RuleType)
		if err != nil {
			http.Error(w, fmt.Sprintf("Draft rule %d: %s", i, err.Error()), http.StatusBadRequest)
			return
		}
		if err := refuseUnrepresentableRuleFields(i, spec); err != nil {
			http.Error(w, "Draft "+err.Error(), http.StatusBadRequest)
			return
		}
		cat := matchreplace.CategoryLiteral
		if spec.Category == "regex" {
			cat = matchreplace.CategoryRegex
		}
		rule, err := matchreplace.NewRule(target, cat, spec.StringMatch, spec.StringReplace, spec.Comment)
		if err != nil {
			http.Error(w, "Invalid rule: "+err.Error(), http.StatusBadRequest)
			return
		}
		rule.Enabled = spec.Enabled
		rules = append(rules, rule)
	}
	rs := matchreplace.NewRuleSet()
	rs.SetRules(rules)
	dir := matchreplace.DirRequest
	if req.Direction == "response" {
		dir = matchreplace.DirResponse
	}
	output := rs.Apply(dir, []byte(req.Input))
	changed := !bytesEqual([]byte(req.Input), output)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"changed": changed,
		"output":  bytesView(output),
	})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- Tool log ----------------------------------------------------------------------------------

// toolLogEntry mirrors toollog.ts's LogEntry.
type toolLogEntry struct {
	ID   uint64 `json:"id"`
	Tool string `json:"tool"`
	Host string `json:"host"`
	Port uint16 `json:"port"`
	// TLS is whether the exchange this row records was carried over TLS.
	//
	// toollog.Entry has carried the flag since the log existed; this projection dropped it, so the
	// Logger pane had to infer the scheme from the port — honestly, and it said so in a comment — and
	// therefore emitted `http://` for every HTTPS service not on 443. Copy URL and Copy as curl both
	// read that, so an operator pasted a wrong-scheme URL into a terminal or a report and debugged
	// their copy rather than their target. Most internal and staging targets are HTTPS on a port
	// other than 443.
	TLS    bool   `json:"tls"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status *int   `json:"status"`
	// ResponseLen is null when no response was received, for the same reason Status is: a row that
	// reported 0 bytes for a send that failed would be claiming a measurement it never made. See
	// toollog.Entry.ResponseLen. Both /api/tools/log and /api/dashboard project through
	// toolLogEntryView, so neither can drift back to a hardcoded zero on its own.
	ResponseLen *int `json:"response_len"`
	// StartedMs is when the request went out, in Unix milliseconds. The UI's Dashboard pane has
	// always rendered a relative time from this field; until now the wire shape did not carry it, so
	// every row read "NaNs ago". Part of DASH-02: an event log with no times on it is not one.
	StartedMs  uint64  `json:"started_ms"`
	DurationMs uint64  `json:"duration_ms"`
	Error      *string `json:"error"`
	// Comment is the operator's annotation, distinct from Error (the producer's note).
	Comment string `json:"comment"`
	// Highlight is the operator's colour tag, "" when unset. Same vocabulary as the
	// organizer's (core.ValidHighlights) so the three surfaces agree on what red means.
	Highlight string `json:"highlight"`
	// Exchange is the traffic-store exchange this row's bytes live under, or null when the row has
	// none to show — Logger's message viewer fetches request/response through it on demand. Null,
	// never 0: the traffic store counts rows from zero, so 0 is a real exchange and a null-less zero
	// would show the viewer the wrong message pair.
	Exchange *uint64 `json:"exchange"`
}

// toolLogResp mirrors toollog.ts's LogResp.
type toolLogResp struct {
	// Total is how many entries matched the filter, which is not how many are returned when a limit
	// applies — Shown is. Both are reported so a caller showing 20 of 4000 can say so.
	Total   int            `json:"total"`
	Shown   int            `json:"shown"`
	Dropped uint64         `json:"dropped"`
	Counts  map[string]int `json:"counts"`
	Entries []toolLogEntry `json:"entries"`
	// Capturing is the capture axis: which tools are being recorded at all,
	// distinct from the display axis the caller filters by. A tool absent here
	// is a tool whose requests were sent and deliberately not kept.
	Capturing map[string]bool `json:"capturing"`
	// Uncaptured reports, per tool, how many requests capture refused. The
	// honest-counting counterpart of the capture axis: switching a tool off must
	// read as "N requests not captured", never as a short log.
	Uncaptured map[string]uint64 `json:"uncaptured"`
	// UncapturedTotal is the sum of Uncaptured, so a caller showing 20 of 4000
	// can also say how many request-gone-forever the log is silent about.
	UncapturedTotal uint64 `json:"uncaptured_total"`
	// FilteredTotal counts what the capture filter refused, beside Dropped (evicted).
	FilteredTotal uint64 `json:"filtered_total"`
	// Capacity is the memory bound in rows.
	Capacity int `json:"capacity"`
	// ScopeAttached says whether ScopeOnly can filter: without a scope it is inert.
	ScopeAttached bool `json:"scope_attached"`
	// Filter echoes the capture filter in force, so the page renders what the server
	// enforces rather than a second copy of it.
	Filter toolLogFilterView `json:"filter"`
}

// toolLogFilterView mirrors toollog.CaptureFilter for the capture-filter surface.
type toolLogFilterView struct {
	Status    []int  `json:"status"`
	Term      string `json:"term"`
	Regex     bool   `json:"regex"`
	Case      bool   `json:"case_sensitive"`
	Negate    bool   `json:"negate"`
	ScopeOnly bool   `json:"scope_only"`
	// MIME is Burp's "Capture by MIME type" as an EXCLUSION list (burpsy-react-ui-73vm): each
	// entry is a media type whose rows are refused, so an empty list captures everything — which
	// is what every existing caller means by omitting it, and what the log did before this existed.
	// Burp presents per-type checkboxes over a fixed category list; this is the open set of
	// Content-Type essences core.MimeEssence actually produces, so a type Burp never listed can
	// still be excluded. A row whose type was never measured is never judged by it.
	MIME []string `json:"mime,omitempty"`
}

func (s *Server) handleToolLog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.toolLogGet(w, r)
	case http.MethodPost:
		s.toolLogSetCapture(w, r)
	case http.MethodDelete:
		s.toolLogClear(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// toolLogSetCaptureReq drives the capture surface. The historical {tool, on} toggle keeps
// working; filter and capacity ride the same endpoint so the whole capture filter is one
// round trip, and absent keys leave their axes untouched rather than resetting them.
type toolLogSetCaptureReq struct {
	Tool     string             `json:"tool"`
	On       bool               `json:"on"`
	Filter   *toolLogFilterView `json:"filter"`
	Capacity *int               `json:"capacity"`
}

// toolLogSetCapture serves POST /api/tools/log — the destructive arm of the
// two axes: turning a tool's capture off means its next requests are sent and
// deliberately not recorded, and the uncaptured counters start counting them.
func (s *Server) toolLogSetCapture(w http.ResponseWriter, r *http.Request) {
	var req toolLogSetCaptureReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "body must be JSON with tool and on", http.StatusBadRequest)
		return
	}
	if req.Filter != nil {
		f := toollog.CaptureFilter{
			Status:    req.Filter.Status,
			ScopeOnly: req.Filter.ScopeOnly,
			MIME:      req.Filter.MIME,
		}
		f.Search.Term = req.Filter.Term
		f.Search.Regex = req.Filter.Regex
		f.Search.CaseSensitive = req.Filter.Case
		f.Search.Negate = req.Filter.Negate
		if err := s.toolLog.SetFilter(f); err != nil {
			http.Error(w, "Invalid filter: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Capacity != nil {
		if err := s.toolLog.SetCapacity(*req.Capacity); err != nil {
			http.Error(w, "Invalid capacity: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	// The legacy toggle: present only when the caller names a tool. A filter-only POST
	// carries no tool and must not touch the axis.
	if req.Tool != "" {
		tool, ok := toollog.ToolFromName(req.Tool)
		if !ok {
			http.Error(w, "unknown tool", http.StatusBadRequest)
			return
		}
		s.toolLog.SetCapturing(tool, req.On)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{req.Tool + ".capturing": s.toolLog.Capturing(tool)})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// toolLogGet serves GET /api/tools/log?filter=&search=&limit=.
//
// limit used to be accepted and ignored, which is why the Dashboard pane's `?limit=20` rendered the
// entire log. Worse, the entries came back in append order, so the twenty rows an operator wanted
// were the last twenty of however many thousand. A limit now takes the *newest* matches, in newest-
// first order; without a limit the whole matching log comes back in append order, which is what the
// Logger tab reads.
func (s *Server) toolLogGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := q.Get("filter")
	search := q.Get("search")
	limit := 0
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}

	entries := s.toolLog.All()
	// Counts are over every match, not over the returned window: a per-tool histogram that shrank
	// because the caller asked for twenty rows would be a histogram of the window, not of the log.
	// Seeded from ToolAll so a tool added to the log is not silently absent from the histogram — the
	// hard-coded four-key seed this replaces reported nothing at all for session, sequencer and
	// comparer activity, and reported a permanent zero for a "bcheck" tool that does not exist.
	counts := make(map[string]int, len(toollog.ToolAll))
	for _, t := range toollog.ToolAll {
		counts[t.String()] = 0
	}
	matched := make([]*toollog.Entry, 0, len(entries))
	for _, e := range entries {
		if !toolLogMatches(e, filter, search) {
			continue
		}
		matched = append(matched, e)
		counts[e.Tool.String()]++
	}

	view := make([]toolLogEntry, 0, len(matched))
	if limit > 0 {
		for i := len(matched) - 1; i >= 0 && len(view) < limit; i-- {
			view = append(view, toolLogEntryView(matched[i]))
		}
	} else {
		for _, e := range matched {
			view = append(view, toolLogEntryView(e))
		}
	}

	capturing := make(map[string]bool, len(toollog.ToolAll))
	uncaptured := make(map[string]uint64, len(toollog.ToolAll))
	var uncapturedTotal uint64
	for _, t := range toollog.ToolAll {
		capturing[t.String()] = s.toolLog.Capturing(t)
		n := s.toolLog.Uncaptured(t)
		uncaptured[t.String()] = n
		uncapturedTotal += n
	}

	f := s.toolLog.Filter()
	// The filter echoes as wire shape, so its arrays must be arrays: a nil Status would
	// marshal as null and every client reading filter.status.length crashes on a fresh
	// server that has never had a capture filter set. "No classes accepted yet" is an
	// empty list, not an absent one.
	status := f.Status
	if status == nil {
		status = []int{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toolLogResp{
		Total:           len(matched),
		Shown:           len(view),
		Dropped:         s.toolLog.Dropped(),
		Counts:          counts,
		Entries:         view,
		Capturing:       capturing,
		Uncaptured:      uncaptured,
		UncapturedTotal: uncapturedTotal,
		FilteredTotal:   s.toolLog.Filtered(),
		Capacity:        s.toolLog.Capacity(),
		ScopeAttached:   s.toolLog.ScopeAttached(),
		Filter: toolLogFilterView{
			Status:    status,
			Term:      f.Search.Term,
			Regex:     f.Search.Regex,
			Case:      f.Search.CaseSensitive,
			Negate:    f.Search.Negate,
			ScopeOnly: f.ScopeOnly,
			// Read back so the choice survives a reload: the filter is server state, and a page
			// that could set it but not see it would show an empty list over a live exclusion.
			MIME: f.MIME,
		},
	})
}

// toolLogSetComment serves PATCH /api/tools/log/{id} — Burp's log comment
// (burpsy-react-ui-5da). The body carries the whole comment; empty clears it. Unknown ids
// 404 rather than succeeding quietly, so a note addressed at a trimmed row cannot read as saved.
func (s *Server) toolLogSetComment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/tools/log/")
	if !ok {
		http.Error(w, "Usage: PATCH /api/tools/log/{id} with {comment}", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseUint(strings.TrimSuffix(rest, "/"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid log entry id", http.StatusBadRequest)
		return
	}
	// Comment and Highlight are *string, not string, for the reason toolLogSetCaptureReq's Filter and
	// Capacity (above) are already pointers: a plain string cannot tell "the caller wrote {}" apart
	// from "the caller wrote {comment: \"\"}", and burpsy-react-ui-iyb6 was exactly that collapse — a
	// comment-only PATCH decoded the absent highlight key as "" and SetHighlight wrote it over
	// whatever colour the row already had. A key that is absent from the body now leaves that axis
	// alone; a key present with "" still clears it, same as before.
	var req struct {
		Comment   *string `json:"comment"`
		Highlight *string `json:"highlight"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Highlight != nil && *req.Highlight != "" && !core.ValidHighlights[*req.Highlight] {
		http.Error(w, "Invalid highlight; use one of red orange yellow green cyan blue pink magenta gray or empty", http.StatusBadRequest)
		return
	}
	// SetComment and SetHighlight both refuse an unknown id on their own, and both look it up in the
	// same entries slice — so for one id they can only ever agree on whether it exists. Each call here
	// is gated on its own field being present, and 404s immediately rather than letting a later call
	// paper over a bad id with an unrelated field's success.
	if req.Comment != nil {
		if !s.toolLog.SetComment(id, *req.Comment) {
			http.Error(w, "No such log entry", http.StatusNotFound)
			return
		}
	}
	if req.Highlight != nil {
		if !s.toolLog.SetHighlight(id, *req.Highlight) {
			http.Error(w, "No such log entry", http.StatusNotFound)
			return
		}
	}
	if req.Comment == nil && req.Highlight == nil {
		// Neither axis given: there is nothing to change, but a PATCH addressed at an id that does not
		// exist must still 404 rather than silently succeed at doing nothing to nothing. ToolLog has no
		// bare existence check — SetComment/SetHighlight fold theirs into a mutation — so this is the
		// one path that has to look rather than set.
		found := false
		for _, e := range s.toolLog.All() {
			if e.ID == id {
				found = true
				break
			}
		}
		if !found {
			http.Error(w, "No such log entry", http.StatusNotFound)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Server) toolLogClear(w http.ResponseWriter, r *http.Request) {
	s.toolLog.Clear()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"cleared": true})
}

func strPtrIf(cond bool, s string) *string {
	if !cond {
		return nil
	}
	return &s
}

// ---- Decoder / Encoder / Hash / Compare ---------------------------------------------------------

// bytesView mirrors the UI's BytesView.
type bytesViewShape struct {
	Text      string `json:"text"`
	Len       int    `json:"len"`
	UTF8      bool   `json:"utf8"`
	Truncated bool   `json:"truncated"`
}

func bytesView(b []byte) bytesViewShape {
	return bytesViewShape{
		Text: string(b),
		Len:  len(b),
		UTF8: isUTF8(b),
	}
}

func isUTF8(b []byte) bool {
	return strings.ToValidUTF8(string(b), "") == string(b)
}

func (s *Server) handleToolsDecode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Input    string `json:"input"`
		Encoding string `json:"encoding"`
		Guess    bool   `json:"guess_alphabets"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	dec := tools.NewDecoder()
	if req.Encoding == "" || req.Encoding == "auto" {
		// Explicit-mode passthrough when no layer is named.
		out, layers := smartDecode(dec, req.Input, req.Guess)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode":   "explicit",
			"layers": layers,
			"output": bytesView([]byte(out)),
		})
		return
	}
	decoded, layers, partial, err := decodeLayer(dec, req.Encoding, req.Input)
	if err != nil {
		http.Error(w, "decode failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mode":   "explicit",
		"layers": layers,
		// True when a compressed stream only partly decompressed: the output is a
		// prefix, not the whole plaintext, and searching it can mislead.
		"partial": partial,
		"output":  bytesView([]byte(decoded)),
	})
}

// decodeLayer resolves the named layer through tools.ParseLayer so the handler
// covers exactly the codec table — previously it hand-rolled a partial switch, so
// gzip and deflate fell through to a default that returned the input unchanged
// while still reporting the layer as applied, and base64url was decoded with the
// standard alphabet. The returned bool is the codec's partial-decompression flag:
// a truncated gzip stream must never be reported as a clean decode.
func decodeLayer(dec *tools.Decoder, encoding, input string) (string, []string, bool, error) {
	// ASCII is a Decoder helper, not one of the codec layers.
	if strings.EqualFold(strings.TrimSpace(encoding), "ascii") {
		return dec.ToASCII(input), []string{"ascii"}, false, nil
	}
	layer, ok := tools.ParseLayer(encoding)
	if !ok {
		names := make([]string, 0, len(tools.AllLayers())+1)
		for _, l := range tools.AllLayers() {
			names = append(names, l.String())
		}
		names = append(names, "ascii")
		return "", nil, false, fmt.Errorf("unknown encoding %q: expected one of %s", encoding, strings.Join(names, ", "))
	}
	out, partial, err := tools.Decode(layer, []byte(input))
	if err != nil {
		return "", nil, false, err
	}
	return string(out), []string{layer.String()}, partial, nil
}

// smartDecode runs the input through the known layers in order until decoding stops changing it.
// guessBase64 accepts the unpadded alphabets the strict decoder rejects.
//
// tools.Decoder.DecodeBase64 already tries standard and URL-safe, both *padded*. Raw
// (unpadded) base64 is what every JWT segment uses, so on a tool whose operators paste
// tokens all day the strict path fails on the single most common input.
func guessBase64(dec *tools.Decoder, s string) (string, error) {
	if out, err := dec.DecodeBase64(s); err == nil {
		return out, nil
	}
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("not base64 under any known alphabet")
}

// guessHex accepts the separators the strict decoder does not.
//
// DecodeHex strips spaces and a single leading "0x". It rejects the framings a security tool
// actually meets: colon-delimited fingerprints and MAC addresses (de:ad:be:ef), dash- or
// comma-delimited dumps, per-byte 0x prefixes, and anything spanning lines.
func guessHex(dec *tools.Decoder, s string) (string, error) {
	if out, err := dec.DecodeHex(s); err == nil {
		return out, nil
	}
	cleaned := strings.NewReplacer(
		":", "", "-", "", ",", "", ".", "",
		" ", "", "\t", "", "\n", "", "\r", "",
		"0x", "", "0X", "",
	).Replace(s)
	if cleaned == "" || len(cleaned)%2 != 0 {
		// An odd number of nibbles is not hex with separators removed; it is something else.
		// Guessing a leading zero would invent a byte the operator never pasted.
		return "", fmt.Errorf("not hex after removing separators")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return "", fmt.Errorf("not hex after removing separators")
	}
	return string(b), nil
}

// smartDecode peels encoding layers off input, reporting which layers it removed.
//
// # guess is a real parameter now
//
// It used to be accepted and never referenced — the four steps ran in a fixed order whichever
// way the Decoder's "guess base64 / hex alphabets" checkbox was set. The parity audit found it
// as the *one* decorative control in roughly eighty (§5.1): it rendered, accepted input,
// returned 200 and plausible output, and changed nothing. On a security-analysis toggle that
// is the worst possible place for it, because the operator reads the output as evidence.
//
// Now it selects the alphabet-tolerant decoders above. Off keeps the strict behaviour exactly,
// so nothing that worked before decodes differently; on additionally accepts unpadded base64
// and separator-delimited hex.
//
// A guessed layer is *named* as guessed in the returned layer list — "base64 (guessed
// alphabet)" rather than "base64". The operator is told which of their input's layers needed a
// looser reading, because "this decoded cleanly" and "this decoded once I relaxed the
// alphabet" are different facts about a payload, and on this tool the difference can matter.
// plausibleDecode still gates every acceptance, so relaxing the alphabet does not relax the
// bar for calling something decoded.
func smartDecode(dec *tools.Decoder, input string, guess bool) (string, []string) {
	current := input
	var layers []string

	// strictThenGuess returns the decoded value and whether the strict decoder had to be
	// relaxed to get it. The bool is what lets the layer list stay honest about which reading
	// succeeded, rather than reporting a guessed layer as if it had decoded cleanly.
	strictThenGuess := func(strict, loose func(string) (string, error)) func(string) (string, bool, error) {
		return func(s string) (string, bool, error) {
			if out, err := strict(s); err == nil {
				return out, false, nil
			}
			if !guess {
				return "", false, fmt.Errorf("strict decode failed and alphabet guessing is off")
			}
			out, err := loose(s)
			return out, err == nil, err
		}
	}
	never := func(fn func(string) (string, error)) func(string) (string, bool, error) {
		return func(s string) (string, bool, error) {
			out, err := fn(s)
			return out, false, err
		}
	}

	steps := []struct {
		name string
		fn   func(string) (string, bool, error)
	}{
		{"base64", strictThenGuess(dec.DecodeBase64, func(s string) (string, error) { return guessBase64(dec, s) })},
		{"url", never(dec.DecodeURL)},
		{"hex", strictThenGuess(dec.DecodeHex, func(s string) (string, error) { return guessHex(dec, s) })},
		{"html", never(func(s string) (string, error) { return dec.DecodeHTML(s), nil })},
	}
	for _, step := range steps {
		for i := 0; i < 3; i++ { // repeated layers (e.g. double-encoding)
			next, guessed, err := step.fn(current)
			if err != nil || next == current || !plausibleDecode(current, next) {
				break
			}
			current = next
			name := step.name
			if guessed {
				name += " (guessed alphabet)"
			}
			layers = append(layers, name)
		}
	}
	if len(layers) == 0 {
		return input, nil
	}
	return current, layers
}

// plausibleDecode rejects decodes that turn binary-looking input into gibberish (high ratio of
// non-printable characters).
func plausibleDecode(before, after string) bool {
	if after == "" {
		return false
	}
	nonPrint := 0
	for _, c := range after {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' {
			nonPrint++
		}
	}
	return float64(nonPrint)/float64(len(after)) < 0.1
}

func (s *Server) handleToolsEncode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Input    string `json:"input"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	dec := tools.NewDecoder()
	out, err := encodeNamed(dec, req.Encoding, req.Input)
	if err != nil {
		http.Error(w, "encode failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"encoding": req.Encoding,
		"output":   bytesView([]byte(out)),
	})
}

// encodeNamed resolves the named encoding through tools.ParseLayer, so the handler covers exactly the
// codec table plus the two helpers that are not codec layers. It is decodeLayer's mirror, and exists
// for the same reason: the hand-rolled switch it replaces mapped base64url onto tools.Decoder's
// standard-alphabet encoder, emitting the `+` and `/` that URL-safe base64 exists to avoid — so the
// one encoding named for URLs was the one that broke in them, and encode disagreed with decode, which
// has distinguished the two alphabets since it was routed through ParseLayer.
//
// An unknown encoding is refused rather than passed through. Returning the input unchanged while
// still reporting the requested encoding meant a caller storing {encoding, output} recorded a
// transformation that never happened, which is the failure a codec table exists to make impossible.
func encodeNamed(dec *tools.Decoder, encoding, input string) (string, error) {
	// ASCII and rot13 are Decoder helpers, not codec layers, so they are named here rather than
	// looked up — the same split decodeLayer makes for ascii.
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "ascii":
		out, err := dec.FromASCII(input)
		if err != nil {
			return "", fmt.Errorf("ascii decode failed: %w", err)
		}
		return out, nil
	case "rot13":
		return dec.Rot13(input), nil
	}
	layer, ok := tools.ParseLayer(encoding)
	if !ok {
		return "", fmt.Errorf("unknown encoding %q: expected one of %s",
			encoding, strings.Join(encodableNames(), ", "))
	}
	out, err := tools.Encode(layer, []byte(input))
	if err != nil {
		// JWT reaches here: it parses as a layer but has no inverse without the signing key, and
		// tools.Encode says so rather than emitting an unsigned token shaped like the original.
		return "", err
	}
	return string(out), nil
}

// encodableNames lists what this endpoint accepts, which is not every layer: a layer with no inverse
// is left out rather than offered and then refused.
func encodableNames() []string {
	names := make([]string, 0, len(tools.AllLayers())+2)
	for _, l := range tools.AllLayers() {
		if _, err := tools.Encode(l, nil); err != nil {
			continue
		}
		names = append(names, l.String())
	}
	return append(names, "ascii", "rot13")
}

func (s *Server) handleToolsHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Input     string `json:"input"`
		Algorithm string `json:"algorithm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	h := tools.NewHasher()
	var digest string
	// Named exhaustively, with no default branch. An unknown algorithm used to fall through to SHA-256
	// while the reply echoed back the algorithm that was *asked for*, so a caller storing
	// {algorithm, output} recorded a digest under a name that did not produce it — and a typo in the
	// field ("sha-256", "sha265") silently returned a plausible-looking hash rather than a complaint.
	// An empty algorithm still means SHA-256, because that is the documented default and every existing
	// caller that omits the field relies on it; a *stated* algorithm now has to be one this can compute.
	switch strings.ToLower(strings.TrimSpace(req.Algorithm)) {
	case "md5":
		digest = h.MD5(req.Input)
	case "sha1":
		digest = h.SHA1(req.Input)
	case "sha512":
		digest = h.SHA512(req.Input)
	case "sha256", "":
		digest = h.SHA256(req.Input)
	default:
		http.Error(w, fmt.Sprintf("unknown algorithm %q: expected one of md5, sha1, sha256, sha512",
			req.Algorithm), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"algorithm": req.Algorithm,
		"output":    bytesView([]byte(digest)),
	})
}

// compareOp mirrors comparer.ts's OpView.
type compareOp struct {
	Kind    string `json:"kind"`
	AOffset int    `json:"a_offset"`
	ALen    int    `json:"a_len"`
	BOffset int    `json:"b_offset"`
	BLen    int    `json:"b_len"`
	Text    string `json:"text,omitempty"`
	// Uninteresting marks a difference lying entirely inside a header line the operator has told
	// burpsy to discount — W6 #81/#82. The op is still reported with its real offsets and text:
	// the console dims it and counts it separately rather than dropping it, because "the only
	// differences were in headers you chose to ignore" and "these messages are identical" are
	// different facts and only one of them is true.
	Uninteresting bool `json:"uninteresting,omitempty"`
}

// handleToolsCompare mirrors comparer.ts's CompareResp. The engine aligns the two inputs —
// byte-by-byte or word-by-word, the operator's choice — and this folds consecutive differences into
// equal/replace/insert/delete ops so the UI can render unified columns.
//
// The response echoes the granularity that actually ran, so the console can label the result rather
// than leave the operator guessing which mode produced it. An unknown value is refused instead of
// silently defaulting: "I asked for words and got bytes" is exactly the kind of quiet substitution
// this engine does not do.
func (s *Server) handleToolsCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		A string `json:"a"`
		B string `json:"b"`
		// Response selects which uninteresting-header list applies. Defaults to false, i.e. the
		// request list, which is empty unless the operator populated it — so an old client that
		// does not send this field gets exactly the behaviour it had before the field existed.
		Response bool `json:"response"`
		// Granularity is "bytes" (default, and what a client that omits it gets) or "words".
		Granularity string `json:"granularity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	a, b := []byte(req.A), []byte(req.B)
	granularity := strings.ToLower(strings.TrimSpace(req.Granularity))
	if granularity == "" {
		granularity = "bytes"
	}
	var diff diffResult
	switch granularity {
	case "bytes":
		diff = diffBytes(a, b)
	case "words":
		diff = diffWords(a, b)
	default:
		http.Error(w, `granularity must be "bytes" or "words", got `+strconv.Quote(req.Granularity), http.StatusBadRequest)
		return
	}
	ops := diff.Ops

	// Tag differences that fall inside a discounted header. Spans are computed per side because the
	// same header sits at different offsets in two messages of different lengths, and an op's A and B
	// ranges must each be inside one for the difference to be attributable to that header alone.
	spansA := uninterestingSpansIn(a, s.uninteresting, req.Response)
	spansB := uninterestingSpansIn(b, s.uninteresting, req.Response)

	// The deleted/inserted counters are byte lengths when the comparison is byte-level, and token
	// counts when it is word-level. Summing bytes under a field the console labels in tokens would
	// report "12 tokens" for one changed word; the token starts let the count be exact instead.
	deleted, inserted, discounted := 0, 0, 0
	var startsA, startsB []int
	if granularity == "words" {
		for _, w := range tokeniseWords(a) {
			startsA = append(startsA, w.start)
		}
		for _, w := range tokeniseWords(b) {
			startsB = append(startsB, w.start)
		}
	}
	countIn := func(starts []int, off, ln int) int {
		if starts == nil {
			return ln
		}
		return sort.SearchInts(starts, off+ln) - sort.SearchInts(starts, off)
	}
	for i := range ops {
		op := &ops[i]
		if op.Kind == "equal" {
			continue
		}
		switch op.Kind {
		case "delete":
			// Present only in A, so only A's spans can account for it.
			op.Uninteresting = coveredBy(spansA, op.AOffset, op.ALen)
		case "insert":
			op.Uninteresting = coveredBy(spansB, op.BOffset, op.BLen)
		default:
			// A replace must be discounted on both sides. Covered in A alone would mean the bytes it
			// was replaced *with* are somewhere the operator did not discount.
			op.Uninteresting = coveredBy(spansA, op.AOffset, op.ALen) &&
				coveredBy(spansB, op.BOffset, op.BLen)
		}
		if op.Uninteresting {
			discounted++
		}
		if op.Kind == "delete" {
			deleted += countIn(startsA, op.AOffset, op.ALen)
		} else if op.Kind == "insert" {
			inserted += countIn(startsB, op.BOffset, op.BLen)
		}
	}

	identical := len(ops) == 1 && ops[0].Kind == "equal"
	// True when every difference was discounted. Deliberately distinct from `identical`: these
	// messages are not identical, and a UI that conflated the two would tell the operator the bytes
	// matched when they did not.
	identicalIgnoring := identical
	if !identical {
		identicalIgnoring = true
		for _, op := range ops {
			if op.Kind != "equal" && !op.Uninteresting {
				identicalIgnoring = false
				break
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"identical":                        identical,
		"identical_ignoring_uninteresting": identicalIgnoring,
		"uninteresting_ops":                discounted,
		"uninteresting_headers_applied":    s.uninteresting.headers(req.Response),
		// Echoed so the console labels the result with the mode that produced it.
		"granularity":     granularity,
		"deleted_tokens":  deleted,
		"inserted_tokens": inserted,
		"truncated":       diff.Truncated,
		"ops_omitted":     0,
		"ops":             ops,
	})
}

// ---- Organizer ---------------------------------------------------------------------------------

func (s *Server) handleOrganizer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		// organizerView, not organizer.List(): the console's in-scope/status/MIME filters need fields
		// an organizer.Item does not have, and the resolution happens here because that is where the
		// traffic store and the scope are. See api_organizer_view.go, particularly for what happens
		// to an item whose exchange has been evicted.
		//
		// Collections ride the same response: the page renders groups and items from one fetch, and
		// a separate endpoint would let the two drift apart mid-triage (a group shown after its last
		// member was moved out).
		json.NewEncoder(w).Encode(map[string]interface{}{"items": s.organizerView(), "collections": s.organizer.Collections()})
	case http.MethodPost:
		var req struct {
			Exchange int `json:"exchange"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		// `< 0`, not `<= 0`. Exchange ids are a dense counter from zero, so exchange 0 is the first
		// request ever captured in a session — and it is the one an operator is most likely to reach
		// for first. Rejecting it as "not positive" refused a real row, and the message ("A positive
		// exchange id is required") asserted something about the id space that is not true.
		if req.Exchange < 0 {
			http.Error(w, "An exchange id cannot be negative", http.StatusBadRequest)
			return
		}
		if _, err := s.store.GetExchange(core.ExchangeID(req.Exchange)); err != nil {
			// Checked rather than trusted: the organizer stores the id, and saving one that resolves
			// to nothing produces an entry whose "open in history" goes nowhere.
			http.Error(w, fmt.Sprintf("No exchange %d has been captured", req.Exchange), http.StatusNotFound)
			return
		}
		item := s.organizer.Add(req.Exchange)
		s.organizerChanged()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(item)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleOrganizerItem(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/tools/organizer/")
	idStr = strings.TrimSuffix(idStr, "/")
	// The status write is a subpath, not the item id: /{id}/status must be split before the id is
	// parsed, or Atoi("1/status") fails and every status PUT would be answered "Invalid item id".
	// Same shape as the session-rule detail handler's /update-macro and /run suffix routes.
	if statusStr, ok := strings.CutSuffix(idStr, "/status"); ok {
		s.organizerItemStatus(w, r, statusStr)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid item id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var req struct {
			Title     string `json:"title"`
			Note      string `json:"note"`
			Highlight string `json:"highlight"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if !s.organizer.Update(id, req.Title, req.Note, req.Highlight) {
			http.Error(w, "Item not found", http.StatusNotFound)
			return
		}
		s.organizerChanged()
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		// PUT .../status is handled by organizerItemStatus below (a /{id}/status subpath, split off
		// before the id parse). A PUT of the item resource itself is not implemented: title/note/
		// highlight go through POST, and a bare PUT would otherwise reach the 405 with no handler.
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	case http.MethodDelete:
		if !s.organizer.Remove(id) {
			http.Error(w, "Item not found", http.StatusNotFound)
			return
		}
		s.organizerChanged()
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// organizerItemStatus serves PUT /api/tools/organizer/{id}/status — the workflow-status write
// path, separate from the POST edit form for the same reason the store keeps SetStatus apart
// from Update: setting a status is one deliberate operator decision (Burp applies it from the
// item's status submenu), not a field on the annotate dialog. An unrepresentable value is
// refused with the valid set named, rather than stored and later rendered as a state the UI
// cannot set or filter on. 404 is an unknown item, so "the item is gone" and "the status does
// not exist" stay distinguishable.
func (s *Server) organizerItemStatus(w http.ResponseWriter, r *http.Request, idStr string) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid item id", http.StatusBadRequest)
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	status := organizer.Status(req.Status)
	if !organizer.ValidStatus(status) {
		http.Error(w, fmt.Sprintf("Unknown status %q; the valid statuses are new, in_progress, postponed, done, ignored", req.Status), http.StatusBadRequest)
		return
	}
	if !s.organizer.SetStatus(id, status) {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}
	s.organizerChanged()
	w.WriteHeader(http.StatusOK)
}

// ---- Organizer collections ----------------------------------------------------------------------

// handleOrganizerCollections serves the /api/tools/organizer/collections surface — Burp's
// organizer collections (tools/organizer/collections.html): New / Rename / Duplicate / Delete,
// the About note, and Move to… for the items inside. One handler, because the routes share one
// subtree and one id space:
//
//	POST   /api/tools/organizer/collections                 {name} -> create
//	PUT    /api/tools/organizer/collections/{id}            {name?, note?} -> rename / note
//	POST   /api/tools/organizer/collections/{id}/duplicate  -> duplicate with its items
//	DELETE /api/tools/organizer/collections/{id}?items=inbox|delete
//	                                                        -> delete, items unlinked or deleted
//	PUT    /api/tools/organizer/collections/inbox           {item_ids} -> move back to the inbox
//	PUT    /api/tools/organizer/collections/{id}/items      {item_ids, copy} -> move / copy into it
//
// "inbox" as the literal id in the move path is deliberate: collection 0 is not a collection, and
// making the UI mint a fake numeric id for it would be a second lie about the id space.
func (s *Server) handleOrganizerCollections(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/tools/organizer/collections")
	rest = strings.Trim(rest, "/")

	if rest == "" {
		switch r.Method {
		case http.MethodPost:
			var req struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request body", http.StatusBadRequest)
				return
			}
			name := strings.TrimSpace(req.Name)
			if name == "" {
				http.Error(w, "A collection needs a name", http.StatusBadRequest)
				return
			}
			c, ok := s.organizer.NewCollection(name)
			if !ok {
				http.Error(w, fmt.Sprintf("A collection named %q already exists", name), http.StatusBadRequest)
				return
			}
			s.organizerChanged()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(c)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// Move-to-inbox: the literal "inbox" stands for collection 0.
	if rest == "inbox" {
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ItemIDs []int `json:"item_ids"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		moved := s.organizer.MoveToCollection(req.ItemIDs, 0)
		s.organizerChanged()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"moved": moved})
		return
	}

	// {id}/duplicate and {id}/items have a subpath; plain {id} is rename/note/delete.
	if dup, ok := strings.CutSuffix(rest, "/duplicate"); ok {
		id, err := strconv.Atoi(dup)
		if err != nil {
			http.Error(w, "Invalid collection id", http.StatusBadRequest)
			return
		}
		s.organizerCollectionDuplicate(w, r, id)
		return
	}
	if items, ok := strings.CutSuffix(rest, "/items"); ok {
		id, err := strconv.Atoi(items)
		if err != nil {
			http.Error(w, "Invalid collection id", http.StatusBadRequest)
			return
		}
		s.organizerCollectionItems(w, r, id)
		return
	}

	id, err := strconv.Atoi(rest)
	if err != nil {
		http.Error(w, "Invalid collection id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var req struct {
			Name string  `json:"name"`
			Note *string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if req.Name != "" {
			if !s.organizer.RenameCollection(id, strings.TrimSpace(req.Name)) {
				// Renaming an unknown collection and renaming onto a taken name are different
				// faults; the store's own duplicate check would have refused either, so the
				// distinction is made here before asking.
				if s.collectionExists(id) {
					http.Error(w, fmt.Sprintf("A collection named %q already exists", req.Name), http.StatusBadRequest)
					return
				}
				http.Error(w, "Collection not found", http.StatusNotFound)
				return
			}
		}
		if req.Note != nil {
			if !s.organizer.SetCollectionNote(id, *req.Note) {
				http.Error(w, "Collection not found", http.StatusNotFound)
				return
			}
		}
		s.organizerChanged()
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		// The delete dialog's choice, verbatim from the acceptance criteria: unlink the items back
		// to the inbox (the default, losing nothing) or delete them with the collection. Anything
		// else is refused rather than guessed at.
		disposition := r.URL.Query().Get("items")
		if disposition == "" {
			disposition = "inbox"
		}
		if disposition != "inbox" && disposition != "delete" {
			http.Error(w, fmt.Sprintf("Unknown items disposition %q; use inbox or delete", disposition), http.StatusBadRequest)
			return
		}
		unlinked, ok := s.organizer.DeleteCollection(id, disposition == "delete")
		if !ok {
			http.Error(w, "Collection not found", http.StatusNotFound)
			return
		}
		s.organizerChanged()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"unlinked": unlinked})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) collectionExists(id int) bool {
	for _, c := range s.organizer.Collections() {
		if c.ID == id {
			return true
		}
	}
	return false
}

// organizerCollectionDuplicate copies a collection with every item in it — Burp's "duplicate" —
// giving the items fresh ids (a duplicate is a new copy of the work, not a second pointer to it)
// and the copy a name that does not collide.
func (s *Server) organizerCollectionDuplicate(w http.ResponseWriter, r *http.Request, id int) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var source *organizer.Collection
	for _, c := range s.organizer.Collections() {
		if c.ID == id {
			copied := c
			source = &copied
			break
		}
	}
	if source == nil {
		http.Error(w, "Collection not found", http.StatusNotFound)
		return
	}
	// Find a name: "name (copy)", then "(copy 2)", … — bounded by the count of collections plus
	// one, so the loop cannot run away.
	name := source.Name + " (copy)"
	for attempt := 2; s.nameTaken(name); attempt++ {
		name = fmt.Sprintf("%s (copy %d)", source.Name, attempt)
	}
	created, ok := s.organizer.NewCollection(name)
	if !ok {
		http.Error(w, "Could not create the copy", http.StatusBadRequest)
		return
	}
	s.organizer.SetCollectionNote(created.ID, source.Note)
	// Copy the membership: each item is duplicated into the new collection with a fresh id.
	copied := 0
	for _, it := range s.organizer.List() {
		if it.Collection != id {
			continue
		}
		item := s.organizer.Add(it.Exchange)
		s.organizer.Update(item.ID, it.Title, it.Note, it.Highlight)
		s.organizer.SetStatus(item.ID, it.Status)
		s.organizer.MoveToCollection([]int{item.ID}, created.ID)
		copied++
	}
	s.organizerChanged()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"collection": created, "items_copied": copied})
}

func (s *Server) nameTaken(name string) bool {
	for _, c := range s.organizer.Collections() {
		if c.Name == name {
			return true
		}
	}
	return false
}

// organizerCollectionItems moves (or copies) a set of items into one collection. copy=true
// duplicates each item first — the Copy Link analogue — so the source keeps its own entry.
func (s *Server) organizerCollectionItems(w http.ResponseWriter, r *http.Request, id int) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ItemIDs []int `json:"item_ids"`
		Copy    bool  `json:"copy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if !s.collectionExists(id) {
		http.Error(w, "Collection not found", http.StatusNotFound)
		return
	}
	moved := 0
	if req.Copy {
		for _, itemID := range req.ItemIDs {
			for _, it := range s.organizer.List() {
				if it.ID != itemID {
					continue
				}
				fresh := s.organizer.Add(it.Exchange)
				s.organizer.Update(fresh.ID, it.Title, it.Note, it.Highlight)
				s.organizer.SetStatus(fresh.ID, it.Status)
				s.organizer.MoveToCollection([]int{fresh.ID}, id)
				moved++
				break
			}
		}
	} else {
		moved = s.organizer.MoveToCollection(req.ItemIDs, id)
		if moved < 0 {
			http.Error(w, "Collection not found", http.StatusNotFound)
			return
		}
	}
	s.organizerChanged()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"moved": moved})
}
