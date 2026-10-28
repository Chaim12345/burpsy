package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"sync"
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
		serveUIFile(w, r, sub, "index.html", "text/html; charset=utf-8")
	case "/app.js":
		serveUIFile(w, r, sub, "dist/app.js", "text/javascript; charset=utf-8")
	case "/issues.worker.js":
		serveUIFile(w, r, sub, "dist/issues.worker.js", "text/javascript; charset=utf-8")
	case "/style.css":
		serveUIFile(w, r, sub, "style.css", "text/css; charset=utf-8")
	default:
		fsrv := http.FileServer(http.FS(sub))
		fsrv.ServeHTTP(w, r)
	}
}

// uiAsset is one embedded file with its validator and gzip form computed once: the bundle is
// 2.7 MB of text, and sending it raw on every load (no validator, no compression) was the largest
// cost of opening the console on a phone connection.
type uiAsset struct {
	once sync.Once
	raw  []byte
	gz   []byte
	etag string
	err  error
}

var uiAssets sync.Map // embedded name -> *uiAsset

func loadUIAsset(sub fs.FS, name string) *uiAsset {
	v, _ := uiAssets.LoadOrStore(name, &uiAsset{})
	a := v.(*uiAsset)
	a.once.Do(func() {
		a.raw, a.err = fs.ReadFile(sub, name)
		if a.err != nil {
			return
		}
		sum := sha256.Sum256(a.raw)
		a.etag = `"` + hex.EncodeToString(sum[:8]) + `"`
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		zw.Write(a.raw)
		zw.Close()
		a.gz = buf.Bytes()
	})
	return a
}

func serveUIFile(w http.ResponseWriter, r *http.Request, sub fs.FS, name, contentType string) {
	a := loadUIAsset(sub, name)
	if a.err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("ETag", a.etag)
	// no-cache means "revalidate", not "never store": a rebuilt console is picked up on the next
	// load, an unchanged one costs a 304.
	h.Set("Cache-Control", "no-cache")
	h.Add("Vary", "Accept-Encoding")
	if r.Header.Get("If-None-Match") == a.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		h.Set("Content-Length", strconv.Itoa(len(a.gz)))
		w.Write(a.gz)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(a.raw)))
	w.Write(a.raw)
}
