package crawler

import "testing"

// burpsy-react-ui-8lpc: candidates taken from the dvi7 benchmark run. The junk is JavaScript that the
// miner or the AST pass read as a path — each one used to be admitted, and each admitted candidate is
// a request spent on a URL nobody serves. The routes are real ones from the same run and must survive.
func TestCodeShapedCandidatesAreRefusedAndRealRoutesKept(t *testing.T) {
	junk := []string{
		`/[\-\[\]\/\{\}\`,          // a regex character class
		`/\*/g`,                    // a regex literal with a flag
		`/^`,                       // a regex anchor
		`/:/g`,                     // a regex literal with a flag
		`/g;var`,                   // a statement boundary
		`/this._cachedWidth;e._isLeftThumb&&this._cachedWidth ?this._setTrackActiveStyles`,
		`/assets/i18n/{{reddit}}`,  // an unrendered template
		`/a b`,                     // whitespace
		"/x`y",                     // a backtick
		`/fn(a)`,                   // a call
	}
	for _, raw := range junk {
		if loc, ok := normaliseJSLocation(raw); ok {
			t.Errorf("code fragment %q was admitted as %q", raw, loc)
		}
	}
	real := []string{"/2fa/enter", "/address/create", "/payment", "/socket.io", "/api/Products",
		"/rest/products/search?q=x", "/blog/g", "/.well-known/security.txt", "/assets/i18n/en.json"}
	for _, raw := range real {
		if _, ok := normaliseJSLocation(raw); !ok {
			t.Errorf("real route %q was refused", raw)
		}
	}
}
