package web

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Burp's suite-wide search (burpsy-react-ui-vs9k) -------------------------------------------
//
// Burp's Search dialog (tools/search.html) is the one search that crosses tools: "You can perform
// suite-wide searches in the search dialog. To access the search dialog, click Search on the tab
// bar." The options it offers are case sensitivity, literal/regex, negative matches, in-scope only,
// a request-versus-response axis and a headers-versus-body axis, plus which tools to cross.
//
// burpsy had search in exactly one place — the History page's own field, which filters the rows that
// page has already fetched. That is a different feature wearing the same word: it cannot see
// Repeater's resends, it cannot look at a response body the list column never loaded, and it has no
// answer at all for traffic on another tool's page. This endpoint is the missing one.
//
// # Where the search runs, and why it is here rather than in the browser
//
// The browser cannot do this: /api/history deliberately serves index rows and never payloads (see
// Exchange.Mime's comment), so the rows the console holds carry no bytes to search. A client-side
// "suite-wide" search would therefore search only what each page happened to fetch, and report
// "no matches" for traffic it never looked at — a partial result presented as a complete one, which
// this project treats as a defect wherever it appears. So the scan runs over the store, and what
// crosses the wire is one row per matched exchange plus the byte offsets of the matches, never a
// copy of the haystack.
//
// # What is searched
//
// The bytes that travelled — the Edited reading, not a retained Original or Auto-modified stage.
// Those stages exist so a rewrite can be *compared* (burpsy-react-ui-c05); searching them would
// surface rows for bytes no peer ever sent, and would make one rewrite report as two hits.

// suiteSearchTool is one entry in the dialog's tool list.
type suiteSearchTool struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// suiteSearchToolOptions is the canonical vocabulary of tools the search can cross, in the order the
// dialog shows them.
//
// Served to the client in every response rather than duplicated in TypeScript, for the reason the
// session tools-scope checklist is served (see api_session.go's ruleTools): a client able to tick a
// tool the endpoint refuses would offer the operator a filter that silently does nothing. One list,
// in the package that enforces it.
//
// The set is burpsy's own, not Burp's four (Target/Repeater/Proxy/Organizer). Burp offers those
// because they are the message-bearing surfaces it has; burpsy keeps crawler, intruder and scanner
// traffic in the same store, and leaving those axes out would make the dialog narrower than the
// traffic it is supposed to cross.
//
// "proxy" covers unattributed traffic as well. An exchange no producer claimed is real captured
// traffic — hiding it would make it invisible rather than absent — and the History page already
// reads it that way; the two lists must not disagree about what Proxy history is.
var suiteSearchToolOptions = []suiteSearchTool{
	{ID: "proxy", Label: "Proxy history"},
	{ID: "crawler", Label: "Crawler"},
	{ID: "repeater", Label: "Repeater"},
	{ID: "intruder", Label: "Intruder"},
	{ID: "scanner", Label: "Scanner"},
	{ID: "organizer", Label: "Organizer"},
}

// suiteSearchMaxTermLen bounds the compiled pattern. Go's regexp is linear in the input, so the
// pattern is not a ReDoS risk, but a kilobyte-long "term" is a paste accident rather than a search,
// and refusing it names the accident instead of running something the operator did not mean.
const suiteSearchMaxTermLen = 4096

// suiteSearchDefaultLimit and suiteSearchMaxLimit bound the result rows, and so bound the response.
const (
	suiteSearchDefaultLimit = 200
	suiteSearchMaxLimit     = 1000
)

// suiteSearchMaxMatchesPerMessage bounds the offsets recorded for one message. match_count carries
// the true total, so a capped list is reported as capped rather than passed off as everything.
const suiteSearchMaxMatchesPerMessage = 200

// suiteSearchLocation is Burp's request-versus-response axis.
type suiteSearchLocation int

const (
	suiteSearchLocationBoth suiteSearchLocation = iota
	suiteSearchLocationRequest
	suiteSearchLocationResponse
)

// suiteSearchArea is Burp's headers-versus-body axis. "headers" means the whole head — request line
// or status line included, everything before the body — which is the region StoredMessage's own
// header lookups cover.
type suiteSearchArea int

const (
	suiteSearchAreaBoth suiteSearchArea = iota
	suiteSearchAreaHeaders
	suiteSearchAreaBody
)

// suiteSearchOptions is one search's compiled request.
type suiteSearchOptions struct {
	term          string
	caseSensitive bool
	regex         bool
	negate        bool
	inScope       bool
	location      suiteSearchLocation
	area          suiteSearchArea
	tools         []string
	limit         int
}

// suiteSearchMatchView is one match location. offset/len index the bytes /api/message/{id} returns
// for message_id, so the console can highlight the exact bytes this search matched instead of
// re-running its own matcher and hoping the two agreements agree.
type suiteSearchMatchView struct {
	// Direction is "request" or "response" — which half of the exchange the bytes belong to.
	Direction string `json:"direction"`
	// Area is "headers" or "body", so the console can label the hit without re-parsing the message.
	Area      string `json:"area"`
	MessageID uint64 `json:"message_id"`
	Offset    int    `json:"offset"`
	Len       int    `json:"len"`
}

// suiteSearchResultView is one matched exchange.
//
// ExchangeView is embedded, not re-derived: Burp's results table has the same columns as the history
// table (Source/Host/URL/Status/Length/Time), the console already renders an Exchange, and a second
// row shape would be a second thing to keep in step with the first for no gain.
type suiteSearchResultView struct {
	*ExchangeView
	// Organizer says whether this exchange is also on the Organizer shortlist, so a row found under
	// several tools is distinguishable from one that is only in Proxy history.
	Organizer bool `json:"organizer"`
	// MatchCount is the true number of matches in the searched regions; Matches holds at most
	// suiteSearchMaxMatchesPerMessage of them.
	MatchCount int `json:"match_count"`
	// Matches is never nil: an empty slice marshals to [], and the console reads .length on it.
	Matches          []suiteSearchMatchView `json:"matches"`
	MatchesTruncated bool                   `json:"matches_truncated"`
}

// suiteSearchResponse is the wire body.
type suiteSearchResponse struct {
	Term string `json:"term"`
	// Scanned is how many exchanges the scan actually examined, so "no matches" can be told apart
	// from "nothing was looked at".
	Scanned int `json:"scanned"`
	// Returned is len(Results), and Truncated is true when the scan stopped at the limit with more
	// traffic left unexamined. Both are reported rather than inferred: a caller that wants to know
	// whether it has the whole answer must not have to reconstruct it from a row count.
	Returned  int  `json:"returned"`
	Truncated bool `json:"truncated"`
	Negate    bool `json:"negate"`
	// Tools echoes the selection (empty means every tool) and ToolOptions is the vocabulary.
	Tools       []string                `json:"tools"`
	ToolOptions []suiteSearchTool       `json:"tool_options"`
	Results     []suiteSearchResultView `json:"results"`
}

// handleSearch serves GET /api/search.
//
// An absent or blank `q` is not an error and not a search: it describes the facility, so the console
// can populate the dialog's checklist and empty state without a second endpoint. That is the same
// contract compileHistorySearch already documents on the client ("empty text means no search is
// active, whatever the modifiers hold").
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	opts, err := parseSuiteSearchOptions(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	body := suiteSearchResponse{
		Term:        opts.term,
		Negate:      opts.negate,
		Tools:       opts.tools,
		ToolOptions: suiteSearchToolOptions,
		Results:     []suiteSearchResultView{},
	}
	if body.Tools == nil {
		body.Tools = []string{}
	}
	if opts.term == "" {
		writeJSON(w, http.StatusOK, body)
		return
	}

	matcher, err := newSuiteSearchMatcher(opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	saved := s.organizerExchangeIDs()

	// Newest first, the same order the History and Logger tables read in: an operator searching a
	// live capture is nearly always asking about traffic they just made.
	exchanges := s.store.Exchanges()
	for i := len(exchanges) - 1; i >= 0; i-- {
		ex := exchanges[i]
		if !suiteSearchToolMatches(opts.tools, ex, saved) {
			continue
		}
		if opts.inScope && !s.scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
			continue
		}
		body.Scanned++

		matches, total := s.searchExchange(ex, opts, matcher)
		if opts.negate {
			// A negative match lists the items the term is *absent* from — Burp's "negative
			// matches" — so this row is kept exactly when the regions held nothing.
			if total != 0 {
				continue
			}
		} else if total == 0 {
			continue
		}

		if len(body.Results) == opts.limit {
			// The limit is a page, not a filter: say so rather than letting a full page read as
			// the complete set.
			body.Truncated = true
			break
		}

		view := suiteSearchResultView{
			ExchangeView:     exchangeView(ex),
			Organizer:        saved[ex.ID],
			MatchCount:       total,
			Matches:          matches,
			MatchesTruncated: total > len(matches),
		}
		if view.Matches == nil {
			view.Matches = []suiteSearchMatchView{}
		}
		body.Results = append(body.Results, view)
	}
	body.Returned = len(body.Results)

	writeJSON(w, http.StatusOK, body)
}

// organizerExchangeIDs is the Organizer's exchange set, as a lookup.
func (s *Server) organizerExchangeIDs() map[core.ExchangeID]bool {
	if s.organizer == nil {
		return nil
	}
	items := s.organizer.List()
	saved := make(map[core.ExchangeID]bool, len(items))
	for _, item := range items {
		saved[core.ExchangeID(item.Exchange)] = true
	}
	return saved
}

// suiteSearchToolMatches reports whether an exchange belongs to any selected tool. An empty
// selection means every tool, which is the dialog's opening state.
//
// An unknown id cannot reach here: parseSuiteSearchOptions refuses it. That is deliberate rather
// than defensive — a filter naming a tool this build does not have would otherwise select nothing,
// and a search that returns no rows because of a typo in a query string is indistinguishable from
// one that returns no rows because the term is absent.
func suiteSearchToolMatches(selected []string, ex *core.Exchange, saved map[core.ExchangeID]bool) bool {
	if len(selected) == 0 {
		return true
	}
	for _, tool := range selected {
		switch tool {
		case "proxy":
			// Unattributed traffic is captured traffic; see suiteSearchToolOptions.
			if ex.Source == core.SourceProxy || ex.Source == core.SourceUnattributed {
				return true
			}
		case "crawler":
			if ex.Source == core.SourceCrawl {
				return true
			}
		case "repeater":
			if ex.Source == core.SourceRepeater {
				return true
			}
		case "intruder":
			if ex.Source == core.SourceIntruder {
				return true
			}
		case "scanner":
			if ex.Source == core.SourceScanner {
				return true
			}
		case "organizer":
			if saved[ex.ID] {
				return true
			}
		}
	}
	return false
}

// parseSuiteSearchOptions reads and validates the query string.
//
// Every enum is refused rather than defaulted when it is present and unrecognised, and so is an
// unknown tool: the alternative is answering a question the operator did not ask with a filter they
// cannot see, which is the failure mode this whole endpoint exists to avoid on the client side too.
func parseSuiteSearchOptions(values url.Values) (suiteSearchOptions, error) {
	opts := suiteSearchOptions{
		term:          values.Get("q"),
		caseSensitive: truthy(values.Get("case")),
		regex:         truthy(values.Get("regex")),
		negate:        truthy(values.Get("negate")),
		inScope:       truthy(values.Get("in_scope")),
		location:      suiteSearchLocationBoth,
		area:          suiteSearchAreaBoth,
		limit:         suiteSearchDefaultLimit,
	}
	if len(opts.term) > suiteSearchMaxTermLen {
		return opts, fmt.Errorf("The search term is %d bytes; the maximum is %d", len(opts.term), suiteSearchMaxTermLen)
	}

	switch values.Get("location") {
	case "", "both":
	case "request":
		opts.location = suiteSearchLocationRequest
	case "response":
		opts.location = suiteSearchLocationResponse
	default:
		return opts, fmt.Errorf("location must be both, request or response; got %q", values.Get("location"))
	}

	switch values.Get("area") {
	case "", "both":
	case "headers":
		opts.area = suiteSearchAreaHeaders
	case "body":
		opts.area = suiteSearchAreaBody
	default:
		return opts, fmt.Errorf("area must be both, headers or body; got %q", values.Get("area"))
	}

	if raw := values.Get("tools"); strings.TrimSpace(raw) != "" {
		known := make(map[string]bool, len(suiteSearchToolOptions))
		for _, tool := range suiteSearchToolOptions {
			known[tool.ID] = true
		}
		seen := map[string]bool{}
		for _, id := range strings.Split(raw, ",") {
			id = strings.TrimSpace(id)
			if id == "" || seen[id] {
				continue
			}
			if !known[id] {
				return opts, fmt.Errorf("Unknown search tool %q; known tools are %s", id, suiteSearchToolIDs())
			}
			seen[id] = true
			opts.tools = append(opts.tools, id)
		}
	}

	if raw := values.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return opts, fmt.Errorf("limit must be a positive integer; got %q", raw)
		}
		if n > suiteSearchMaxLimit {
			n = suiteSearchMaxLimit
		}
		opts.limit = n
	}
	return opts, nil
}

// suiteSearchToolIDs renders the vocabulary for an error message.
func suiteSearchToolIDs() string {
	ids := make([]string, 0, len(suiteSearchToolOptions))
	for _, tool := range suiteSearchToolOptions {
		ids = append(ids, tool.ID)
	}
	return strings.Join(ids, ", ")
}

// truthy reads an on/off query parameter. "1" is what the console sends; the words are accepted
// because a hand-written or curl'd URL is a legitimate way to drive this endpoint.
func truthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ---- the matcher -------------------------------------------------------------------------------

// suiteSearchMatcher finds a term's occurrences in a byte message.
//
// It works on bytes, not on a string, because the offsets it returns must index the same buffer
// /api/message/{id} serves — and converting a message to a string would be a copy of the haystack,
// which is the one thing this store's design forbids (see the package doc's "raw bytes are written
// once and never copied").
type suiteSearchMatcher struct {
	// re is non-nil for a regex search. Go's regexp is linear in the input, so a hostile pattern
	// costs O(n) rather than the exponential blow-up a backtracking engine would allow.
	re *regexp.Regexp
	// lit is the literal needle, already folded when the search is case-insensitive. Folding the
	// needle once is what keeps indexFold from re-lowercasing it at every offset.
	lit    []byte
	folded bool
}

func newSuiteSearchMatcher(opts suiteSearchOptions) (*suiteSearchMatcher, error) {
	if opts.regex {
		pattern := opts.term
		if !opts.caseSensitive {
			// (?i) rather than regexp/syntax's fold flag, because this is the spelling an operator
			// would use themselves and it composes with flags already in their pattern.
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("The search pattern is not a valid regular expression: %v", err)
		}
		return &suiteSearchMatcher{re: re}, nil
	}
	m := &suiteSearchMatcher{lit: []byte(opts.term)}
	if !opts.caseSensitive {
		m.folded = true
		m.lit = bytes.ToLower(m.lit)
	}
	return m, nil
}

// allIn returns every match inside hay, with offsets relative to hay. Each pair is [start, end).
func (m *suiteSearchMatcher) allIn(hay []byte) [][]int {
	if m.re != nil {
		return m.re.FindAllIndex(hay, -1)
	}
	if len(m.lit) == 0 {
		return nil
	}
	var out [][]int
	from := 0
	for {
		i := indexFold(hay[from:], m.lit, m.folded)
		if i < 0 {
			return out
		}
		start := from + i
		out = append(out, []int{start, start + len(m.lit)})
		// Overlapping occurrences are not reported: a search for "aa" in "aaa" answers once, the
		// way every text search does. Advancing by one byte instead would report a match at 0 and
		// at 1 for the same three bytes.
		from = start + len(m.lit)
	}
}

// indexFold finds the first occurrence of needle in hay, comparing ASCII case-insensitively when
// folded is set.
//
// The scan is anchored on the first byte rather than folding the whole haystack. bytes.ToLower on a
// message would allocate a copy as large as the message, which is exactly the per-message copy the
// store is built to avoid; this reads the haystack in place and allocates nothing.
func indexFold(hay, needle []byte, folded bool) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(hay) {
		return -1
	}
	first := needle[0]
	if folded {
		first = lowerASCII(first)
	}
	last := len(hay) - len(needle)
	for i := 0; i <= last; i++ {
		if folded {
			if lowerASCII(hay[i]) != first {
				continue
			}
		} else if hay[i] != first {
			continue
		}
		if asciiEqualFold(hay[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

// asciiEqualFold compares two equal-length byte slices, folding ASCII letters only.
//
// Non-ASCII bytes compare exactly. That is deliberate: lowercasing UTF-8 properly means decoding it
// and re-encoding it, and a byte offset into a re-encoded string is not a byte offset into the
// message — the offsets this returns are handed to a client that will slice the original bytes with
// them. ASCII folding is what every byte-oriented search does and it keeps the offset a fact.
func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// ---- the scan ----------------------------------------------------------------------------------

// suiteSearchRegion is a slice of a message the search is allowed to look at, tagged with which of
// Burp's two areas it is.
type suiteSearchRegion struct {
	start int
	end   int
	area  string
}

// searchRegions resolves Burp's headers/body axis for one direction.
//
// The two regions are disjoint and cover the message, so "both" is exactly their union and the areas
// on the returned matches never disagree with the option that produced them.
func searchRegions(msg *core.StoredMessage, area suiteSearchArea) []suiteSearchRegion {
	if msg == nil {
		return nil
	}
	total := msg.Len()
	bodyStart := msg.Shape.Body.Offset
	// A shape parsed from a message this process never re-parsed could carry a span past the end
	// (a truncated segment read, say). Clamping to the readable length keeps a match offset inside
	// the buffer the client will slice with it.
	if bodyStart < 0 || bodyStart > total {
		bodyStart = total
	}
	var regions []suiteSearchRegion
	if area == suiteSearchAreaBoth || area == suiteSearchAreaHeaders {
		regions = append(regions, suiteSearchRegion{start: 0, end: bodyStart, area: "headers"})
	}
	if area == suiteSearchAreaBoth || area == suiteSearchAreaBody {
		regions = append(regions, suiteSearchRegion{start: bodyStart, end: total, area: "body"})
	}
	return regions
}

// searchExchange scans the directions and regions one exchange's options select, returning the
// recorded matches (capped) and the true total.
//
// An empty result is honest about the ways it can happen: a message whose bytes cannot be read
// (a segment read that failed) yields nothing rather than a shorter haystack, because searching a
// partial buffer would report a term as absent from bytes that were never looked at.
func (s *Server) searchExchange(ex *core.Exchange, opts suiteSearchOptions, matcher *suiteSearchMatcher) ([]suiteSearchMatchView, int) {
	var out []suiteSearchMatchView
	total := 0

	scan := func(id core.MsgId, direction string) {
		msg, err := s.store.Get(id)
		if err != nil || msg == nil {
			return
		}
		raw := msg.Raw()
		if raw == nil {
			return
		}
		for _, region := range searchRegions(msg, opts.area) {
			if region.start >= region.end || region.end > len(raw) {
				continue
			}
			for _, span := range matcher.allIn(raw[region.start:region.end]) {
				total++
				if len(out) >= suiteSearchMaxMatchesPerMessage {
					continue
				}
				offset := region.start + span[0]
				out = append(out, suiteSearchMatchView{
					Direction: direction,
					Area:      region.area,
					MessageID: uint64(id),
					Offset:    offset,
					Len:       span[1] - span[0],
				})
			}
		}
	}

	if opts.location == suiteSearchLocationBoth || opts.location == suiteSearchLocationRequest {
		scan(ex.Request, "request")
	}
	if (opts.location == suiteSearchLocationBoth || opts.location == suiteSearchLocationResponse) && ex.Response != nil {
		scan(*ex.Response, "response")
	}
	return out, total
}
