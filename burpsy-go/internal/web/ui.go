package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui/index.html ui/style.css ui/dist/app.js ui/dist/issues.worker.js
var uiFS embed.FS

// uiHandler serves the embedded web UI. Root requests get index.html; the
// bundled app is served at /app.js from dist/ (bun build src/app.tsx). The issue
// worker is its own script because a module worker cannot be inlined into app.js.
// Every other path (style.css, favicons, ...) falls through to the embedded tree.
func uiHandler(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
		return
	}
	switch r.URL.Path {
	case "/", "":
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	case "/app.js":
		serveUIFile(w, sub, "dist/app.js")
	case "/issues.worker.js":
		serveUIFile(w, sub, "dist/issues.worker.js")
	default:
		fsrv := http.FileServer(http.FS(sub))
		fsrv.ServeHTTP(w, r)
	}
}

func serveUIFile(w http.ResponseWriter, sub fs.FS, name string) {
	data, err := fs.ReadFile(sub, name)
	if err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Write(data)
}
