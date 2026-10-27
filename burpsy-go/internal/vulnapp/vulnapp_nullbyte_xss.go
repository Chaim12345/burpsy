package vulnapp

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// Null-byte filter bypass (burpsy-react-ui-nulbyte).
//
// OWASP VulnerableApp dedicates a level of two XSS families to one bug: a check that reads the
// value only up to its first NUL byte while the output uses all of it. A C-string habit in a
// language whose strings are not C strings — the validator stops where a C library would, the
// renderer does not. Both are modelled on VulnerableApp's own shape: the endpoint answers an HTML
// fragment as text/plain and a page script inserts it with innerHTML, so they are DOM rows decided
// by rendering the answer (xss_fragment.go).
//
//   - /nullbyte/img is XSSInImgTagAttribute LEVEL_5: the image name must be on an allowlist, but the
//     allowlist is consulted with the part BEFORE the NUL; the whole value is then HTML-escaped and
//     reflected into an UNQUOTED src. Escaping stops quotes and angle brackets, not a space, so
//     `owl.jpg<NUL>x onerror=…` passes the allowlist and injects a handler. A value that is not on
//     the allowlist is not reflected at all, which is why a probe that does not START from the
//     allowed (seed) value can never see this endpoint reflect.
//   - /nullbyte/gallery is the same allowlist defect on an ordinary text/html page, so the breakout
//     is decided on the wire and the variant is exercised without a browser.
//   - /nullbyte/comments is PersistentXSSInHTMLTagVulnerability LEVEL_6: every comment is stored and
//     the answer lists them all, HTML-escaped by a function that escapes only up to the NUL and
//     appends the rest verbatim, so markup after the NUL is live and is served to later requests.
//
// The safe twins are byte-for-byte the same endpoints with the one defect removed: the allowlist is
// consulted with the WHOLE value, and the comment escaper escapes the WHOLE value. They do not
// truncate at the NUL, which is the property under test.

func nullByteXSSEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/nullbyte/img?src=owl.jpg", Row: "Cross-site scripting (reflected)", DOM: true,
			Note: "allowlists the image name up to its first NUL byte, then reflects the whole HTML-escaped value into an unquoted src (VulnerableApp XSSInImgTagAttribute LEVEL_5)"},
		{Path: "/safe/nullbyte/img?src=owl.jpg", Row: "Cross-site scripting (reflected)", DOM: true, Safe: true,
			Note: "allowlists the WHOLE image name, NUL included, before reflecting it into the same unquoted src"},
		// The same allowlist defect on an ordinary HTML page: no script in between, so the breakout
		// is decided on the wire, without a browser.
		{Path: "/nullbyte/gallery?src=owl.jpg", Row: "Cross-site scripting (reflected)",
			Note: "allowlists the image name up to its first NUL byte, then reflects the whole HTML-escaped value into an unquoted src on a text/html page"},
		{Path: "/safe/nullbyte/gallery?src=owl.jpg", Row: "Cross-site scripting (reflected)", Safe: true,
			Note: "allowlists the WHOLE image name, NUL included, before reflecting it into the same unquoted src on a text/html page"},
		{Path: "/nullbyte/comments?comment=hello", Row: "Cross-site scripting (stored)", DOM: true,
			Note: "stores every comment and serves them HTML-escaped only up to the first NUL byte (VulnerableApp PersistentXSSInHTMLTagVulnerability LEVEL_6)"},
		{Path: "/safe/nullbyte/comments?comment=hello", Row: "Cross-site scripting (stored)", DOM: true, Safe: true,
			Note: "stores every comment and serves the WHOLE value HTML-escaped, NUL included"},
		// The pages that consume the fragments. Support routes, crawled rather than audited for a row.
		{Path: "/nullbyte/img/page"},
		{Path: "/nullbyte/comments/page"},
	}
}

// nullByteImageAllowlist is the set of image names the img endpoints accept.
var nullByteImageAllowlist = map[string]bool{"owl.jpg": true, "cat.png": true, "dog.png": true}

// beforeNUL is the value as a C string sees it: everything up to the first NUL byte.
func beforeNUL(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

// escapeBeforeNUL is VulnerableApp LEVEL_6's escaper: it escapes the part before the first NUL and
// appends the rest, NUL included, verbatim.
func escapeBeforeNUL(s string) string {
	i := strings.IndexByte(s, 0)
	if i < 0 {
		return html.EscapeString(s)
	}
	return html.EscapeString(s[:i]) + s[i:]
}

func registerNullByteXSS(mux *http.ServeMux) {
	img := func(allowed func(string) bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			src := r.URL.Query().Get("src")
			if !allowed(src) {
				// Nothing is reflected for a name that is not allowed, as on VulnerableApp.
				return
			}
			fmt.Fprintf(w, `<img src=%s width="400" height="300"/>`, html.EscapeString(src))
		}
	}
	mux.HandleFunc("/nullbyte/img", img(func(s string) bool { return nullByteImageAllowlist[beforeNUL(s)] }))
	mux.HandleFunc("/safe/nullbyte/img", img(func(s string) bool { return nullByteImageAllowlist[s] }))

	gallery := func(allowed func(string) bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			src := r.URL.Query().Get("src")
			fmt.Fprint(w, `<!doctype html><html><body><h1>Gallery</h1>`)
			if allowed(src) {
				fmt.Fprintf(w, `<img src=%s width="400" height="300"/>`, html.EscapeString(src))
			} else {
				fmt.Fprint(w, `<p>No such image.</p>`)
			}
			fmt.Fprint(w, `</body></html>`)
		}
	}
	mux.HandleFunc("/nullbyte/gallery", gallery(func(s string) bool { return nullByteImageAllowlist[beforeNUL(s)] }))
	mux.HandleFunc("/safe/nullbyte/gallery", gallery(func(s string) bool { return nullByteImageAllowlist[s] }))

	vuln, safe := &fragmentComments{}, &fragmentComments{}
	mux.HandleFunc("/nullbyte/comments", func(w http.ResponseWriter, r *http.Request) {
		writeFragmentComments(w, vuln.add(r.URL.Query().Get("comment")), escapeBeforeNUL)
	})
	mux.HandleFunc("/safe/nullbyte/comments", func(w http.ResponseWriter, r *http.Request) {
		writeFragmentComments(w, safe.add(r.URL.Query().Get("comment")), html.EscapeString)
	})

	mux.HandleFunc("/nullbyte/img/page", func(w http.ResponseWriter, _ *http.Request) {
		fragmentPage(w, "/nullbyte/img?src=owl.jpg")
	})
	mux.HandleFunc("/nullbyte/comments/page", func(w http.ResponseWriter, _ *http.Request) {
		fragmentPage(w, "/nullbyte/comments")
	})
}
