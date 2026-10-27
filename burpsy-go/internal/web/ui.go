package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed ui/index.html ui/style.css ui/dist/app.js
var uiFS embed.FS

// altFS is the alternative console (altui: Map, Probe, Prove), the landing page. It is the SPA's own
// files only; the Node proxy that develops it (altui/server.mjs) is not embedded and not served.
//
//go:embed altui
var altFS embed.FS

// serveAlt answers "/" (the landing page) and "/alt/..." (its assets). The assets sit under /alt/ so
// they cannot collide with the original console's /app.js and /style.css, which stay where they were.
func serveAlt(w http.ResponseWriter, r *http.Request) bool {
	sub, err := fs.Sub(altFS, "altui")
	if err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
		return true
	}
	switch {
	case r.URL.Path == "/" || r.URL.Path == "":
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
			return true
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(data)
		return true
	case strings.HasPrefix(r.URL.Path, "/alt/"):
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		w.Header().Set("Cache-Control", "no-store")
		http.StripPrefix("/alt/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)
		return true
	}
	return false
}

// uiHandler serves the embedded web UI. Root requests get index.html; the
// bundled app is served at /app.js from dist/ (bun build src/app.ts); every
// other path (style.css, favicons, ...) falls through to the embedded tree.
func uiHandler(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
		return
	}
	if serveAlt(w, r) {
		return
	}
	switch r.URL.Path {
	case "/legacy":
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	case "/app.js":
		data, err := fs.ReadFile(sub, "dist/app.js")
		if err != nil {
			http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write(data)
	default:
		fsrv := http.FileServer(http.FS(sub))
		fsrv.ServeHTTP(w, r)
	}
}
