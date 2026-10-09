package web

// GET/POST /api/scope/check: "is this URL in scope?" (burpsy-react-ui-z5z3).
//
// Burp's Montoya API has Scope.isInScope(url) — "query whether a specified URL is within the current
// Suite-wide target scope". burpsy had GET (the rules) and POST (edit the rules), and in_scope
// computed only per stored exchange, so an agent, a plugin or an operator who wanted to know whether a
// URL would be captured or attacked had to re-implement the include/exclude matcher — the one piece of
// this program a re-implementation must not disagree with.
//
// The answer is core.Scope.Decide, which walks the rules exactly as Contains does (and is held to
// Contains' answer by a test). It reports two verdicts, because the scope gives two answers that
// differ exactly when the drop switch is off:
//
//   - in_scope: Contains — the request is retained in history, and the tools (Repeater, Intruder,
//     Scanner) may send it. Tools refuse an out-of-scope target either way (AuthoriseRaw).
//   - proxy_forwards: AuthoriseRequest — the proxy forwards a browser's request at all. With
//     drop_out_of_scope off it forwards out-of-scope traffic unrecorded, which is Burp's default.
//
// It is riskRead: it reads the rules and sends nothing.

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// scopeCheckReq is POST /api/scope/check's body.
type scopeCheckReq struct {
	URLs []string `json:"urls" desc:"absolute http:// or https:// URLs to check, at most 1000"`
}

// maxScopeCheckURLs bounds one bulk check. A scope decision is cheap, but an unbounded list is an
// unbounded response, and 1000 covers a site map's worth of a host.
const maxScopeCheckURLs = 1000

// scopeCheckResult is one URL's verdict.
type scopeCheckResult struct {
	URL string `json:"url"`
	// Error is set, and every verdict field is zero, when the URL could not be read as an http(s) URL.
	Error string `json:"error,omitempty"`
	Host  string `json:"host,omitempty"`
	Port  uint16 `json:"port,omitempty"`
	Path  string `json:"path,omitempty"`
	TLS   bool   `json:"tls"`
	// InScope is the retention verdict, and the one every tool's send gate applies.
	InScope bool `json:"in_scope"`
	// ProxyForwards is whether the proxy forwards a browser request for this URL at all.
	ProxyForwards bool `json:"proxy_forwards"`
	// Reason is core's reason code: allow_all, fault, excluded, included, no_include_rules,
	// no_include_match.
	Reason string `json:"reason,omitempty"`
	// MatchedRule is the rule that decided, for "included" and "excluded"; null otherwise.
	MatchedRule *core.ScopeRuleRef `json:"matched_rule"`
	// Explanation is the sentence a tool's refusal would carry (core.Scope.Explain).
	Explanation string `json:"explanation,omitempty"`
	// Fault names the uninterpretable rule that makes the whole scope refuse everything.
	Fault string `json:"fault,omitempty"`
}

// scopeCheckView is the reply: the verdicts, and the drop switch they were computed under.
type scopeCheckView struct {
	Results         []scopeCheckResult `json:"results"`
	DropOutOfScope  bool               `json:"drop_out_of_scope"`
	AllowAll        bool               `json:"allow_all"`
	InScopeCount    int                `json:"in_scope_count"`
	InvalidURLCount int                `json:"invalid_url_count"`
}

// checkScopeURL decides one URL. The path is the escaped request path without the query — what the
// proxy and the tools hand Contains, read off the request line on the wire.
func (s *Server) checkScopeURL(raw string) scopeCheckResult {
	res := scopeCheckResult{URL: raw}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		res.Error = "not a URL: " + err.Error()
		return res
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		res.TLS = true
	case "http":
	default:
		res.Error = fmt.Sprintf("the URL must be absolute http:// or https://; got scheme %q", u.Scheme)
		return res
	}
	res.Host = strings.ToLower(u.Hostname())
	if res.Host == "" {
		res.Error = "the URL names no host"
		return res
	}
	res.Port = 80
	if res.TLS {
		res.Port = 443
	}
	if p := u.Port(); p != "" {
		n, perr := strconv.ParseUint(p, 10, 16)
		if perr != nil || n == 0 {
			res.Error = fmt.Sprintf("port %q is not a TCP port", p)
			return res
		}
		res.Port = uint16(n)
	}
	res.Path = u.EscapedPath()
	if res.Path == "" {
		res.Path = "/"
	}
	d := s.scope.Decide(res.Host, res.Port, res.Path, res.TLS)
	res.InScope = d.InScope
	res.Reason = d.Reason
	res.MatchedRule = d.Rule
	res.Fault = d.Fault
	res.ProxyForwards = s.scope.AuthoriseRequest(res.Host, res.Port, res.Path, res.TLS)
	res.Explanation = s.scope.Explain(res.Host, res.Port, res.Path, res.TLS)
	return res
}

func (s *Server) scopeCheckView(urls []string) scopeCheckView {
	view := scopeCheckView{
		Results:        make([]scopeCheckResult, 0, len(urls)),
		DropOutOfScope: s.scope.DropOutOfScope(),
		AllowAll:       s.scope.AllowAll(),
	}
	for _, raw := range urls {
		r := s.checkScopeURL(raw)
		if r.Error != "" {
			view.InvalidURLCount++
		} else if r.InScope {
			view.InScopeCount++
		}
		view.Results = append(view.Results, r)
	}
	return view
}

// handleScopeCheck serves GET /api/scope/check?url=… (one URL) and POST {urls:[…]} (many).
func (s *Server) handleScopeCheck(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw := r.URL.Query().Get("url")
		if strings.TrimSpace(raw) == "" {
			http.Error(w, "url is required: GET /api/scope/check?url=https://host/path", http.StatusBadRequest)
			return
		}
		view := s.scopeCheckView([]string{raw})
		if view.Results[0].Error != "" {
			writeJSON(w, http.StatusBadRequest, view)
			return
		}
		writeJSON(w, http.StatusOK, view)
	case http.MethodPost:
		var req scopeCheckReq
		if err := requestJSON(w, r, nil).Decode(&req); err != nil {
			http.Error(w, "body must be JSON {\"urls\": [...]}", http.StatusBadRequest)
			return
		}
		if len(req.URLs) == 0 {
			http.Error(w, "urls is empty: name at least one URL to check", http.StatusBadRequest)
			return
		}
		if len(req.URLs) > maxScopeCheckURLs {
			http.Error(w, fmt.Sprintf("%d URLs is more than the %d one check accepts; split the list", len(req.URLs), maxScopeCheckURLs), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, s.scopeCheckView(req.URLs))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
