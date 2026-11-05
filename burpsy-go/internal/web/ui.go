package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed ui/index.html ui/style.css ui/dist/app.js ui/dist/issues.worker.js
var uiFS embed.FS

// legacyUIPrefix is where the React SPA lives now that the server-rendered console owns "/".
const legacyUIPrefix = "/legacy/"

// uiHandler serves the embedded React console under /legacy/. index.html is served with its
// asset references re-pointed at /legacy/; the bundle (dist/app.js), the issue worker (its own
// script because a module worker cannot be inlined into app.js) and style.css are served there
// and, for the bundle's hard-coded worker URL and for old bookmarks, at their original root
// paths. Hash routing (/legacy/#history) is client-side, so the index is all the routes need.
// Anything else is a 404.
func uiHandler(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
		return
	}
	switch r.URL.Path {
	case "/legacy":
		http.Redirect(w, r, legacyUIPrefix, http.StatusFound)
	case legacyUIPrefix, legacyUIPrefix + "index.html":
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
			return
		}
		page := strings.NewReplacer(
			`src="/app.js"`, `src="`+legacyUIPrefix+`app.js"`,
			`href="/style.css"`, `href="`+legacyUIPrefix+`style.css"`,
		).Replace(string(data))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		// #nosec G705 -- the page is the embedded index.html with two fixed path rewrites.
		_, _ = w.Write([]byte(page))
	case legacyUIPrefix + "app.js", "/app.js":
		serveUIFile(w, sub, "dist/app.js", "text/javascript; charset=utf-8")
	case legacyUIPrefix + "issues.worker.js", "/issues.worker.js":
		serveUIFile(w, sub, "dist/issues.worker.js", "text/javascript; charset=utf-8")
	case legacyUIPrefix + "style.css", "/style.css":
		serveUIFile(w, sub, "style.css", "text/css; charset=utf-8")
	default:
		http.NotFound(w, r)
	}
}

func serveUIFile(w http.ResponseWriter, sub fs.FS, name, contentType string) {
	data, err := fs.ReadFile(sub, name)
	if err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(data)
}
