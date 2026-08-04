package web

import (
	"encoding/json"
	"net/http"
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
	ID           int               `json:"id"`
	Segment      string            `json:"segment"`
	Path         string            `json:"path"`
	Depth        int               `json:"depth"`
	Exchanges    int               `json:"exchanges"`
	Requested    bool              `json:"requested"`
	SubtreeCount int               `json:"subtree_exchanges"`
	ChildCount   int               `json:"child_count"`
	Methods      []string          `json:"methods"`
	Statuses     []int             `json:"statuses"`
	Params       []string          `json:"params"`
	LastExchange *int64            `json:"last_exchange"`
	Recent       []uint64          `json:"recent_exchanges"`
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
	var tree []sitemapNodeView
	var nodeCount int

	for _, host := range s.sitemap.Hosts() {
		if hostFilter != "" && host.Host != hostFilter {
			continue
		}
		children := s.foldPaths(host, pathFilter, &nodeCount)
		lastEx := lastExchangeID(exchanges, host.Host)
		tree = append(tree, sitemapNodeView{
			ID:           nodeID(host.Host),
			Segment:      host.Host,
			Path:         host.Host,
			Depth:        0,
			Exchanges:    len(host.Paths),
			Requested:    true,
			SubtreeCount: len(host.Paths),
			ChildCount:   len(children),
			Methods:      []string{},
			Statuses:     []int{},
			LastExchange: lastEx,
			Recent:       []uint64{},
			Children:     children,
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

// sitemapNode is a folded tree node with its parent pointer for prefix nesting.
type sitemapNode struct {
	view   sitemapNodeView
	parent int
}

// foldPaths turns a host's path map into the depth-limited node tree the UI expects. Each path
// becomes one node at its segment depth; children nest under the first shared prefix.
func (s *Server) foldPaths(host *sitemap.HostNode, pathFilter string, nodeCount *int) []sitemapNodeView {
	var roots []sitemapNodeView
	nodes := map[string]*sitemapNode{}
	var order []string

	paths := host.PathsSorted()
	for _, pn := range paths {
		if pathFilter != "" && !strings.Contains(pn.Path, pathFilter) {
			continue
		}
		*nodeCount++
		seg := pn.Path
		if i := strings.LastIndex(pn.Path, "/"); i >= 0 {
			seg = pn.Path[i+1:]
		}
		lastEx := lastExchangeForPath(host.Host, pn.ExchangeIDs)
		nodes[pn.Path] = &sitemapNode{view: sitemapNodeView{
			ID:           nodeID(host.Host + pn.Path),
			Segment:      seg,
			Path:         pn.Path,
			Depth:        strings.Count(pn.Path, "/"),
			Exchanges:    len(pn.ExchangeIDs),
			Requested:    true,
			SubtreeCount: len(pn.ExchangeIDs),
			ChildCount:   0,
			Methods:      pn.MethodsSorted(),
			Statuses:     statusInts(pn.Statuses),
			Params:       []string{},
			LastExchange: lastEx,
			Recent:       lastN(pn.ExchangeIDs, 20),
			Children:     []sitemapNodeView{},
		}}
		order = append(order, pn.Path)
	}

	// Nest by path prefix: /a/b is a child of /a.
	childOf := map[string][]string{}
	for _, p := range order {
		parent := parentPath(p)
		if parent != "" && nodes[parent] != nil {
			childOf[parent] = append(childOf[parent], p)
		}
	}
	for _, p := range order {
		if parent := parentPath(p); parent != "" && nodes[parent] != nil {
			continue // has a parent; emitted under it
		}
		roots = append(roots, attachChildren(nodes, childOf, p))
	}
	return roots
}

// attachChildren recursively attaches a node's children (by path-prefix).
func attachChildren(nodes map[string]*sitemapNode, childOf map[string][]string, path string) sitemapNodeView {
	n := nodes[path]
	for _, c := range childOf[path] {
		n.view.Children = append(n.view.Children, attachChildren(nodes, childOf, c))
	}
	return n.view
}

// parentPath returns the path prefix one segment up, or "" for a top-level path.
func parentPath(p string) string {
	i := strings.LastIndex(p, "/")
	if i <= 0 {
		return ""
	}
	return p[:i]
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

func lastExchangeForPath(host string, ids []uint64) *int64 {
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

func lastN(ids []uint64, n int) []uint64 {
	if len(ids) <= n {
		return ids
	}
	return ids[len(ids)-n:]
}

// nodeID is a stable pseudo-id for a tree node (the UI only uses it as a DOM key).
func nodeID(s string) int {
	h := 0
	for _, c := range s {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return h
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
	ID          uint64 `json:"id"`
	Tool        string `json:"tool"`
	Host        string `json:"host"`
	Port        uint16 `json:"port"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Status      *int   `json:"status"`
	ResponseLen int    `json:"response_len"`
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
	decoded, layers, err := decodeLayer(dec, req.Encoding, req.Input)
	if err != nil {
		http.Error(w, "decode failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"mode":   "explicit",
		"layers": layers,
		"output": bytesView([]byte(decoded)),
	})
}

func decodeLayer(dec *tools.Decoder, encoding, input string) (string, []string, error) {
	switch encoding {
	case "url":
		out, err := dec.DecodeURL(input)
		return out, []string{"url"}, err
	case "html":
		return dec.DecodeHTML(input), []string{"html"}, nil
	case "base64":
		out, err := dec.DecodeBase64(input)
		return out, []string{"base64"}, err
	case "base64url":
		out, err := dec.DecodeBase64(input)
		return out, []string{"base64url"}, err
	case "hex":
		out, err := dec.DecodeHex(input)
		return out, []string{"hex"}, err
	case "jwt":
		_, payload, _, err := dec.DecodeJWT(input)
		if err != nil {
			return "", nil, err
		}
		return payload, []string{"jwt"}, nil
	case "ascii":
		return dec.ToASCII(input), []string{"ascii"}, nil
	default:
		return input, []string{encoding}, nil
	}
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
		if req.Exchange <= 0 {
			http.Error(w, "A positive exchange id is required", http.StatusBadRequest)
			return
		}
		item := s.organizer.Add(req.Exchange)
		s.persistOrganizer()
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
		s.persistOrganizer()
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if !s.organizer.Remove(id) {
			http.Error(w, "Item not found", http.StatusNotFound)
			return
		}
		s.persistOrganizer()
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
