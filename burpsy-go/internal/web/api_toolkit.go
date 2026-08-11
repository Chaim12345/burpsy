package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
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
	Key          string   `json:"key"`
	Segment      string   `json:"segment"`
	Path         string   `json:"path"`
	Depth        int      `json:"depth"`
	Exchanges    int      `json:"exchanges"`
	Requested    bool     `json:"requested"`
	SubtreeCount int      `json:"subtree_exchanges"`
	ChildCount   int      `json:"child_count"`
	Methods      []string `json:"methods"`
	Statuses     []int    `json:"statuses"`
	Params       []string `json:"params"`
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
	// Deliberately not MayContainHost: that is a pre-filter for attacks and is documented as
	// permissive — only a whole-host exclude flips it, so with include rules present it calls every
	// unlisted host in scope. Correct there, because the real gate is per-request; wrong here, where
	// it would light up every third party the proxy ever saw. This value only decides what is greyed;
	// authorisation stays on the bytes going out.
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

// handleSitemap serves GET /api/sitemap?host=&path=&depth=. The Go sitemap aggregates hosts → paths
// → methods/statuses from captured exchanges; this folds it into the same tree the UI renders,
// treating each path segment as a node.
func (s *Server) handleSitemap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
		for _, c := range children {
			hostIssues += c.SubtreeIssues
			if r := severityRankOf(c.WorstSeverity); r > hostWorst {
				hostWorst = r
			}
		}
		tree = append(tree, sitemapNodeView{
			Key:           nodeKey(host.Host, ""),
			Segment:       host.Host,
			Path:          host.Host,
			Depth:         0,
			Exchanges:     len(host.Paths),
			Requested:     true,
			SubtreeCount:  len(host.Paths),
			ChildCount:    len(children),
			Methods:       []string{},
			Statuses:      []int{},
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
			a = &pathAgg{methods: map[string]int{}, statuses: map[int]int{}, params: map[string]struct{}{}}
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
		agg := issues[nodeKey(host.Host, p)]
		own, ownWorst := 0, -1
		if agg != nil {
			own, ownWorst = agg.count, agg.worst
		}
		views[p] = &sitemapNodeView{
			Key:           nodeKey(host.Host, p),
			Segment:       pathSegment(p),
			Path:          p,
			Depth:         strings.Count(p, "/"),
			Exchanges:     len(a.ids),
			Requested:     a.requested,
			Methods:       sortedStringKeys(a.methods),
			Statuses:      statusInts(a.statuses),
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
		for _, c := range childOf[p] {
			cv := assemble(c)
			total += cv.SubtreeCount
			issueTotal += cv.SubtreeIssues
			if r := severityRankOf(cv.WorstSeverity); r > worst {
				worst = r
			}
			v.Children = append(v.Children, cv)
		}
		v.ChildCount = len(v.Children)
		v.SubtreeCount = total
		v.SubtreeIssues = issueTotal
		v.WorstSeverity = severityName(worst)
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
		rank := int(f.Severity)
		// One finding seen at three places marks three nodes; that is what "where are my issues" means.
		for _, occ := range f.Occurrences {
			ex, err := s.store.ExchangeByRequest(occ.Request)
			if err != nil {
				continue // unresolvable: counted nowhere rather than blamed on a guess
			}
			clean, _ := splitPathQuery(ex.Path)
			key := nodeKey(ex.Host, clean)
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
func nodeKey(host, path string) string {
	if path == "" {
		return host
	}
	return host + "\x00" + path
}

// ---- Match & Replace ---------------------------------------------------------------------------

// matchReplaceRuleSpec mirrors matchreplace.ts's RuleSpec.
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

// matchReplaceSetSpec mirrors matchreplace.ts's RuleSetSpec.
type matchReplaceSetSpec struct {
	Rules               []matchReplaceRuleSpec `json:"rules"`
	UpdateContentLength bool                   `json:"update_content_length"`
}

// matchReplaceGetResp mirrors matchreplace.ts's RulesGetResp.
type matchReplaceGetResp struct {
	AffectsRequests  bool                `json:"affects_requests"`
	AffectsResponses bool                `json:"affects_responses"`
	Config           matchReplaceSetSpec `json:"config"`
}

// targetToCategory maps the UI's rule_type to the engine's Target.
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
	default:
		return 0, nil
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
	config := matchReplaceSetSpec{Rules: specs}
	if s.matchReplace.UpdateContentLength() {
		config.UpdateContentLength = true
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(matchReplaceGetResp{
		AffectsRequests:  s.matchReplace.Affects(matchreplace.DirRequest),
		AffectsResponses: s.matchReplace.Affects(matchreplace.DirResponse),
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
	for _, spec := range set.Rules {
		target, _ := targetToCategory(spec.RuleType)
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
	s.persistMatchReplace()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"compiled": len(rules)})
}

func matchReplaceTargetName(t matchreplace.Target) string {
	switch t {
	case matchreplace.TargetRequestFirstLine:
		return "request_first_line"
	case matchreplace.TargetRequestHeader:
		return "request_header"
	case matchreplace.TargetRequestBody:
		return "request_body"
	case matchreplace.TargetResponseHeader:
		return "response_header"
	case matchreplace.TargetResponseBody:
		return "response_body"
	default:
		return "request_body"
	}
}

func matchReplaceCategoryName(c matchreplace.Category) string {
	if c == matchreplace.CategoryRegex {
		return "regex"
	}
	return "literal"
}

func (s *Server) handleMatchReplaceRules(w http.ResponseWriter, r *http.Request) {
	s.matchReplaceRulesHandler(w, r)
}

// handleMatchReplaceTest compiles draft rules and applies them to an input, mirroring the UI's
// "original vs auto-modified" test.
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
	for _, spec := range req.DraftRules {
		target, _ := targetToCategory(spec.RuleType)
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
	ID     uint64 `json:"id"`
	Tool   string `json:"tool"`
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
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
}

func (s *Server) handleToolLog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.toolLogGet(w, r)
	case http.MethodDelete:
		s.toolLogClear(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(toolLogResp{
		Total:   len(matched),
		Shown:   len(view),
		Dropped: s.toolLog.Dropped(),
		Counts:  counts,
		Entries: view,
	})
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
func smartDecode(dec *tools.Decoder, input string, guess bool) (string, []string) {
	current := input
	var layers []string
	steps := []struct {
		name string
		fn   func(string) (string, error)
	}{
		{"base64", dec.DecodeBase64},
		{"url", dec.DecodeURL},
		{"hex", dec.DecodeHex},
		{"html", func(s string) (string, error) { return dec.DecodeHTML(s), nil }},
	}
	for _, step := range steps {
		for i := 0; i < 3; i++ { // repeated layers (e.g. double-encoding)
			next, err := step.fn(current)
			if err != nil || next == current || !plausibleDecode(current, next) {
				break
			}
			current = next
			layers = append(layers, step.name)
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
	var out string
	switch req.Encoding {
	case "url":
		out = dec.EncodeURL(req.Input)
	case "html":
		out = dec.EncodeHTML(req.Input)
	case "base64":
		out = dec.EncodeBase64(req.Input)
	case "base64url":
		out = dec.EncodeBase64(req.Input)
	case "hex":
		out = dec.EncodeHex(req.Input)
	case "ascii":
		asciiOut, err := dec.FromASCII(req.Input)
		if err != nil {
			http.Error(w, "ascii decode failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		out = asciiOut
	case "rot13":
		out = dec.Rot13(req.Input)
	default:
		out = req.Input
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"encoding": req.Encoding,
		"output":   bytesView([]byte(out)),
	})
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
	switch req.Algorithm {
	case "md5":
		digest = h.MD5(req.Input)
	case "sha1":
		digest = h.SHA1(req.Input)
	case "sha512":
		digest = h.SHA512(req.Input)
	default:
		digest = h.SHA256(req.Input)
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
}

// handleToolsCompare mirrors comparer.ts's CompareResp. The engine produces a byte-level
// comparison; this folds consecutive differences into equal/replace/insert/delete ops so the
// UI can render unified columns.
func (s *Server) handleToolsCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		A string `json:"a"`
		B string `json:"b"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	a, b := []byte(req.A), []byte(req.B)
	ops := compareOps(a, b)
	deleted, inserted := 0, 0
	for _, op := range ops {
		if op.Kind == "delete" {
			deleted += op.ALen
		} else if op.Kind == "insert" {
			inserted += op.BLen
		}
	}
	identical := len(ops) == 1 && ops[0].Kind == "equal"
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"identical":       identical,
		"deleted_tokens":  deleted,
		"inserted_tokens": inserted,
		"truncated":       false,
		"ops_omitted":     0,
		"ops":             ops,
	})
}

// compareOps converts two byte slices into a run of equal/replace/insert/delete ops.
func compareOps(a, b []byte) []compareOp {
	var ops []compareOp
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	i := 0
	for i < minLen {
		if a[i] == b[i] {
			start := i
			for i < minLen && a[i] == b[i] {
				i++
			}
			ops = append(ops, compareOp{Kind: "equal", AOffset: start, ALen: i - start, BOffset: start, BLen: i - start})
			continue
		}
		startA, startB := i, i
		for i < minLen && a[i] != b[i] {
			i++
		}
		ops = append(ops, compareOp{
			Kind:    "replace",
			AOffset: startA,
			ALen:    i - startA,
			BOffset: startB,
			BLen:    i - startB,
			Text:    string(a[startA:i]),
		})
	}
	if len(a) > minLen {
		ops = append(ops, compareOp{Kind: "delete", AOffset: minLen, ALen: len(a) - minLen, BOffset: len(b), BLen: 0, Text: string(a[minLen:])})
	} else if len(b) > minLen {
		ops = append(ops, compareOp{Kind: "insert", AOffset: len(a), ALen: 0, BOffset: minLen, BLen: len(b) - minLen, Text: string(b[minLen:])})
	}
	return ops
}

// ---- Organizer ---------------------------------------------------------------------------------

func (s *Server) handleOrganizer(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"items": s.organizer.List()})
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
	id, err := strconv.Atoi(strings.TrimSuffix(idStr, "/"))
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
