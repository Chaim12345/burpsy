package web

import (
	"net/url"
	"path"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// Logger's view filter (burpsy-react-ui-uvpb): Burp's "Show only in-scope items", "Hide items without
// responses", "Show only parameterized requests", "Filter by MIME type" and "Filter by file extension"
// (desktop/tools/logger/filter/view.html).
//
// These are VIEW axes, judged at query time over rows already recorded, and they are reversible —
// switching one off brings every row back. They are deliberately separate from the capture filter
// (toollog.CaptureFilter), which decides what is recorded at all and cannot be undone; Burp keeps the
// same two-axis split (toollog.go's Zfp2 note). In-scope is judged against the scope as it is NOW, so
// a scope change re-judges every row rather than freezing yesterday's answer.
type toolLogView struct {
	ScopeOnly     bool
	HasResponse   bool
	Parameterized bool
	// Mimes and Exts are inclusion sets; empty means "no constraint on this axis".
	Mimes map[string]bool
	Exts  map[string]bool
}

func (v toolLogView) active() bool {
	return v.ScopeOnly || v.HasResponse || v.Parameterized || len(v.Mimes) > 0 || len(v.Exts) > 0
}

func lowerSet(raw string, trim string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		if v := strings.Trim(strings.ToLower(strings.TrimSpace(part)), trim); v != "" {
			out[v] = true
		}
	}
	return out
}

// parseToolLogView reads the view axes from GET /api/tools/log's query: scope_only, has_response,
// parameterized (booleans), mime (comma list of media types, e.g. text/html,application/json) and
// ext (comma list of file extensions, with or without the dot).
func parseToolLogView(q url.Values) toolLogView {
	return toolLogView{
		ScopeOnly:     truthy(q.Get("scope_only")),
		HasResponse:   truthy(q.Get("has_response")),
		Parameterized: truthy(q.Get("parameterized")),
		Mimes:         lowerSet(q.Get("mime"), ""),
		Exts:          lowerSet(q.Get("ext"), "."),
	}
}

// pathExt is the lower-cased extension of the path's last segment, without the dot and without any
// query or fragment; "" when there is none.
func pathExt(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	ext := path.Ext(p)
	return strings.ToLower(strings.TrimPrefix(ext, "."))
}

func queryParams(p string) int {
	i := strings.IndexByte(p, '?')
	if i < 0 {
		return 0
	}
	q := p[i+1:]
	if j := strings.IndexByte(q, '#'); j >= 0 {
		q = q[:j]
	}
	n := 0
	for _, pair := range strings.Split(q, "&") {
		if pair != "" {
			n++
		}
	}
	return n
}

// toolLogViewMatches applies the view axes to one row. The cheap axes run first; parameterized is
// last because it may read the linked exchange.
func (s *Server) toolLogViewMatches(e *toollog.Entry, v toolLogView) bool {
	if !v.active() {
		return true
	}
	if v.HasResponse && e.ResponseLen == nil {
		return false
	}
	if len(v.Mimes) > 0 {
		// A row with no measured type (nil) cannot be shown as matching a type it never had.
		if e.Mime == nil || !v.Mimes[strings.ToLower(*e.Mime)] {
			return false
		}
	}
	if len(v.Exts) > 0 && !v.Exts[pathExt(e.Path)] {
		return false
	}
	if v.ScopeOnly && (s.scope == nil || !s.scope.Contains(e.Host, e.Port, e.Path, e.TLS)) {
		return false
	}
	if v.Parameterized {
		// The exchange's capture-time count covers the query AND a form body (core.Exchange.
		// RequestParams, the number HTTP history's own filter reads), so Logger and History agree on
		// what "parameterized" means. A row with no linked exchange — or one counted before the field
		// existed (negative) — falls back to the query string, which the row itself carries.
		if e.Exchange != nil {
			if ex, err := s.store.GetExchange(core.ExchangeID(*e.Exchange)); err == nil && ex != nil && ex.RequestParams >= 0 {
				return ex.RequestParams > 0
			}
		}
		return queryParams(e.Path) > 0
	}
	return true
}
