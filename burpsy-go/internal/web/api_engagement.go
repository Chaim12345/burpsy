package web

// Engagement tools over the site map (burpsy-react-ui-1s07): Burp's "Find comments",
// "Find scripts" and "Find references (links) to a particular URL" — tools/search.html's
// three site-map searches. Each scans the responses the map holds and reports where the
// construct appears, with the response body kept where it already is: in the store, read
// through the message ids the exchange carries, never copied into an index.

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// engagementKind is which of Burp's three searches a request names.
type engagementKind string

const (
	engagementComments   engagementKind = "comments"
	engagementScripts    engagementKind = "scripts"
	engagementReferences engagementKind = "references"
)

// engagementRow is one match: the exchange it was found in, and enough of the surrounding
// line to be readable without opening the response. Context is capped — a minified bundle
// is one enormous line, and an unbounded window around a match in one would be the whole
// bundle repeated per match.
type engagementRow struct {
	ExchangeID uint64 `json:"exchange_id"`
	Host       string `json:"host"`
	Port       uint16 `json:"port"`
	TLS        bool   `json:"tls"`
	Path       string `json:"path"`
	// Snippet is the match with a bounded margin, whitespace-collapsed so a row stays one
	// readable line whatever the source's formatting.
	Snippet string `json:"snippet"`
}

// handleEngagement serves GET /api/engagement/{kind}?q=URL[&host=][&limit=] — the site-map
// side of Burp's Engagement tools. Results are computed per request over stored responses:
// the store is the index this tool needs (raw bytes once, read here), and a second structure
// kept in step with every capture would be the kind of duplicate state this codebase keeps
// deleting.
//
// "Find references" takes the target URL in q and matches it anywhere an HTML attribute
// carries a URL — href, src, action, formaction — substring, case-insensitive, the way an
// operator types it rather than as a canonical URL that may not match how the page wrote it.
func (s *Server) handleEngagement(w http.ResponseWriter, r *http.Request) {
	kind := engagementKind(strings.TrimPrefix(r.URL.Path, "/api/engagement/"))
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	hostFilter := strings.TrimSpace(r.URL.Query().Get("host"))

	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 {
			http.Error(w, "limit must be between 1 and 1000", http.StatusBadRequest)
			return
		}
		limit = n
	}

	var re *regexp.Regexp
	switch kind {
	case engagementComments:
		re = regexp.MustCompile(`<!--[\s\S]{0,1000}?-->`)
	case engagementScripts:
		re = regexp.MustCompile(`(?i)<script\b[^>]*\bsrc\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	case engagementReferences:
		if q == "" {
			http.Error(w, "find references needs the target URL in q", http.StatusBadRequest)
			return
		}
		// The URL arrives escaped into the query string the same way it arrives from a page's
		// own attributes; match it as the operator typed it, not after round-tripping through
		// a parser that might re-encode it.
		re = regexp.MustCompile(`(?i)\b(?:href|src|action|formaction)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	default:
		http.Error(w, "unknown engagement kind "+strconv.Quote(string(kind))+"; the kinds are comments, scripts, references", http.StatusNotFound)
		return
	}
	rows := []engagementRow{}
	matchesTotal := 0
	truncated := false

	for _, ex := range s.store.Exchanges() {
		if ex.Response == nil {
			continue
		}
		if hostFilter != "" && ex.Host != hostFilter {
			continue
		}
		msg, err := s.store.Get(*ex.Response)
		if err != nil {
			continue // unreadable response: skipped rather than guessed at
		}
		_, body := splitHeadBody(msg.Raw())
		contentType := ""
		if raw := msg.Header("content-type"); raw != nil {
			contentType = strings.ToLower(string(raw))
		}
		// Comments and scripts are HTML constructs; references can appear in any textual
		// response. Binary bodies (images, fonts) are skipped by the same test — a regex over
		// a PNG finds nothing honest to report.
		if kind != engagementReferences && !strings.Contains(contentType, "html") {
			continue
		}
		if strings.Contains(contentType, "image/") || strings.Contains(contentType, "font/") ||
			strings.Contains(contentType, "octet-stream") {
			continue
		}

		for _, m := range re.FindAllString(string(body), 20) {
			snippet := collapseSpace(m)
			if kind == engagementReferences && !strings.Contains(strings.ToLower(snippet), strings.ToLower(q)) {
				continue
			}
			if len(snippet) > 300 {
				snippet = snippet[:297] + "..."
			}
			matchesTotal++
			if len(rows) < limit {
				rows = append(rows, engagementRow{
					ExchangeID: uint64(ex.ID),
					Host:       ex.Host,
					Port:       ex.Port,
					TLS:        ex.TLS,
					Path:       ex.Path,
					Snippet:    snippet,
				})
			} else {
				truncated = true
			}
		}
		if truncated {
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"kind":      kind,
		"matches":   matchesTotal,
		"truncated": truncated,
		"rows":      rows,
	})
}

// collapseSpace folds runs of whitespace to single spaces, so a match from a pretty-printed
// page and the same match from a minified one read the same in a table row.
func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
