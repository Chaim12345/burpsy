package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui/index.html
var uiFS embed.FS

// uiHandler serves the embedded web UI. Root requests get index.html;
// everything else is served from the embedded filesystem.
func uiHandler(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
		return
	}
	fsrv := http.FileServer(http.FS(sub))
	if r.URL.Path == "/" || r.URL.Path == "" {
		// Serve index.html directly so it is not a directory listing.
		data, err := fs.ReadFile(sub, "index.html")
		if err != nil {
			http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
		return
	}
	fsrv.ServeHTTP(w, r)
}
