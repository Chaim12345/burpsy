package vulnapp

// The active file-upload family (burpsy-react-ui-0vzb.15): upload endpoints that store what they are
// sent and serve it back, so the scanner's file-upload check has a real store-and-fetch round trip
// to prove itself against - and safe twins that store the same files without the defect.
//
// # No filesystem, still the real mechanism
//
// This package never touches the filesystem (vulnapp.go's header), so the "disk" is an in-memory
// map owned by one Handler() and the "directories" are a fixed set of virtual paths. What is kept
// faithful is the behaviour a detector reads:
//
//   - a filename is resolved against the upload directory as a PATH: its directory components are
//     honoured, a component naming a directory that does not exist fails the write (as open(2)
//     does), and "../" climbs to the parent directory;
//   - a stored file is served back with the Content-Type its extension implies, so an .html upload
//     renders and a .png one does not;
//   - the response names where the file was stored, as an application's upload API does.
//
// The store is bounded (uploadStoreCap) so a long scan cannot grow it without limit.

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"
	"sync"
)

// The seed every upload endpoint is captured with: one file part, named the way a browser names it.
const (
	uploadSeedContentType = "multipart/form-data; boundary=burpsyFU"
	uploadSeedBody        = "--burpsyFU\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"notes.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\nhello\r\n--burpsyFU--\r\n"
)

// uploadEndpoints returns this family's manifest entries.
func uploadEndpoints() []Endpoint {
	up := func(p, row string, safe bool, note string) Endpoint {
		return Endpoint{Path: p, Method: http.MethodPost, Row: row, Safe: safe,
			ContentType: uploadSeedContentType, Body: uploadSeedBody, Note: note}
	}
	return []Endpoint{
		// --- the open upload: every claim the check makes is true here ---
		up("/fu/upload", "Cross-site scripting (stored)", false,
			"stores the file under the name it was sent with and serves it back with the Content-Type "+
				"its extension implies, so an uploaded .html document renders with its script"),
		up("/fu/upload", "File path traversal", false,
			"resolves the filename as a path against the upload directory: a missing directory fails "+
				"and \"../\" stores the file in the parent directory"),
		up("/fu/upload", "File upload functionality", false,
			"accepts any extension and reports the stored location under the name it was sent"),
		// --- a bypassable filter: only the mixed-case variant gets through ---
		up("/fu/filtered/upload", "Cross-site scripting (stored)", false,
			"refuses .html/.htm/.svg/.jsp/.php with a CASE-SENSITIVE suffix test, then serves by the "+
				"extension case-insensitively, so x.hTmL is stored and rendered as HTML"),

		// --- safe twins ---
		up("/fu/safe/attachment/upload", "Cross-site scripting (stored)", true,
			"stores any file but serves every one as text/plain with nosniff and an attachment "+
				"disposition, so an uploaded .html document is downloaded, never rendered"),
		up("/fu/safe/attachment/upload", "File path traversal", true,
			"flattens the filename to its last component before storing (a name under a missing "+
				"directory is stored like any other), yet ECHOES the name as sent - including any "+
				"\"../\" - in the location it reports, so only the missing-directory control tells it apart"),
		up("/fu/safe/allowlist/upload", "File upload functionality", false,
			"an extension allowlist alone is NOT a safe twin for this row: .gif is allowed and the "+
				"content is never inspected, so the GIF89a HTML polyglot is stored - true at "+
				"acceptance strength only, since the forced-download serving can never render it"),
		up("/fu/safe/strict/upload", "File upload functionality", true,
			"pairs the extension allowlist with a content check past the magic bytes: a stored "+
				"file whose body carries HTML markup is refused, so the polyglot fails here"),
		// --- a content-sniffing filter: the polyglot is stored, but served by its extension ---
		up("/fu/sniff/upload", "File upload functionality", false,
			"requires image magic bytes for an image extension, and the GIF89a HTML polyglot passes; "+
				"the stored file is served by its extension (image/gif), so nothing renders"),
		up("/fu/sniff/upload", "Cross-site scripting (stored)", true,
			"serves every stored file by its extension, so the polyglot comes back as image/gif and "+
				"no browser renders it as a document"),
		// --- a sniffer that replays the DECLARED Content-Type when serving ---
		up("/fu/trustct/upload", "Cross-site scripting (stored)", false,
			"checks the same magic bytes but serves the stored file with the Content-Type the upload "+
				"declared, so a GIF89a HTML polyglot sent as text/html renders with its script"),
	}
}

// uploadStoreCap bounds the in-memory store; past it the oldest generation is dropped.
const uploadStoreCap = 4096

// uploadStore is one Handler's virtual disk.
type uploadStore struct {
	mu    sync.Mutex
	files map[string][]byte
	// types holds a serving Content-Type stored with the file, for the endpoint that replays the
	// type the upload declared. Empty means "type it by extension".
	types map[string]string
	// dirs are the directories that exist. A write into any other directory fails.
	dirs map[string]bool
}

func newUploadStore() *uploadStore {
	return &uploadStore{files: map[string][]byte{}, types: map[string]string{}, dirs: map[string]bool{
		"/fu":                       true,
		"/fu/files":                 true,
		"/fu/filtered":              true,
		"/fu/filtered/files":        true,
		"/fu/safe/attachment":       true,
		"/fu/safe/attachment/files": true,
		"/fu/safe/allowlist":        true,
		"/fu/safe/allowlist/files":  true,
		"/fu/safe":                  true,
		"/fu/sniff":                 true,
		"/fu/sniff/files":           true,
		"/fu/safe/strict":           true,
		"/fu/safe/strict/files":     true,
		"/fu/trustct":               true,
		"/fu/trustct/files":         true,
	}}
}

// put writes content at dir+name resolved as a path, failing when the resolved file's directory
// does not exist. It returns the resolved path.
func (s *uploadStore) put(dir, name string, content []byte) (string, bool) {
	target := path.Join(dir, name)
	// path.Join cleans "x/../y" to "y", which a real filesystem only does when x exists. Every
	// intermediate directory the name walks through must exist, as open(2) requires.
	walk := dir
	for _, seg := range strings.Split(path.Dir(name), "/") {
		if seg == "" || seg == "." {
			continue
		}
		walk = path.Join(walk, seg)
		if !s.dirs[walk] {
			return "", false
		}
	}
	if !s.dirs[path.Dir(target)] {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) >= uploadStoreCap {
		s.files = map[string][]byte{}
	}
	s.files[target] = content
	return target, true
}

// putTyped is put with a serving Content-Type remembered for the file.
func (s *uploadStore) putTyped(dir, name, contentType string, content []byte) (string, bool) {
	target, ok := s.put(dir, name, content)
	if !ok {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.types[target] = contentType
	return target, true
}

func (s *uploadStore) get(p string) ([]byte, bool) {
	b, _, ok := s.getTyped(p)
	return b, ok
}

// getTyped reads the file and the serving type stored with it, if any.
func (s *uploadStore) getTyped(p string) ([]byte, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.files[p]
	return b, s.types[p], ok
}

// del removes a stored file, reporting whether it existed.
func (s *uploadStore) del(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.files[p]; !ok {
		return false
	}
	delete(s.files, p)
	delete(s.types, p)
	return true
}

// filenameParam reads a part's filename exactly as sent. mime/multipart's FileName() applies
// filepath.Base, which would make every endpoint here traversal-safe by accident.
var filenameParam = regexp.MustCompile(`(?i);\s*filename="([^"]*)"`)

// readUpload returns the first file part's raw filename and content.
func readUpload(r *http.Request) (string, []byte, bool) {
	name, content, _, ok := readUploadTyped(r)
	return name, content, ok
}

// readUploadTyped is readUpload with the part's declared Content-Type.
func readUploadTyped(r *http.Request) (string, []byte, string, bool) {
	mr, err := r.MultipartReader()
	if err != nil {
		return "", nil, "", false
	}
	for {
		part, err := mr.NextPart()
		if err != nil {
			return "", nil, "", false
		}
		m := filenameParam.FindStringSubmatch(part.Header.Get("Content-Disposition"))
		if m == nil {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(part, 1<<20))
		if err != nil {
			return "", nil, "", false
		}
		return m[1], b, part.Header.Get("Content-Type"), true
	}
}

func writeUploadJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// typeByExtension is the Content-Type a static file server would give the name.
func typeByExtension(name string) string {
	if t := mime.TypeByExtension(strings.ToLower(path.Ext(name))); t != "" {
		return t
	}
	return "application/octet-stream"
}

// registerUpload serves this family's routes over one store.
func registerUpload(mux *http.ServeMux) {
	s := newUploadStore()

	// The vulnerable upload: the name is a path, any extension is kept.
	mux.HandleFunc("/fu/upload", func(w http.ResponseWriter, r *http.Request) {
		name, content, ok := readUpload(r)
		if r.Method != http.MethodPost || !ok {
			http.Error(w, "send a multipart file", http.StatusBadRequest)
			return
		}
		if _, ok := s.put("/fu/files", name, content); !ok {
			http.Error(w, "could not store the file", http.StatusInternalServerError)
			return
		}
		writeUploadJSON(w, map[string]any{"stored": true, "location": "/fu/files/" + name})
	})

	// The case-sensitive blocklist.
	mux.HandleFunc("/fu/filtered/upload", func(w http.ResponseWriter, r *http.Request) {
		name, content, ok := readUpload(r)
		if r.Method != http.MethodPost || !ok {
			http.Error(w, "send a multipart file", http.StatusBadRequest)
			return
		}
		for _, bad := range []string{".html", ".htm", ".svg", ".jsp", ".php"} {
			if strings.HasSuffix(name, bad) {
				writeUploadJSON(w, map[string]any{"stored": false, "error": "file type not allowed"})
				return
			}
		}
		if _, ok := s.put("/fu/filtered/files", path.Base(name), content); !ok {
			http.Error(w, "could not store the file", http.StatusInternalServerError)
			return
		}
		writeUploadJSON(w, map[string]any{"stored": true, "location": "/fu/filtered/files/" + path.Base(name)})
	})

	// Safe: stored flattened, served as a download, but the location echoes the name as sent.
	mux.HandleFunc("/fu/safe/attachment/upload", func(w http.ResponseWriter, r *http.Request) {
		name, content, ok := readUpload(r)
		if r.Method != http.MethodPost || !ok || strings.ContainsRune(name, 0) {
			http.Error(w, "send a multipart file", http.StatusBadRequest)
			return
		}
		if _, ok := s.put("/fu/safe/attachment/files", path.Base(name), content); !ok {
			http.Error(w, "could not store the file", http.StatusInternalServerError)
			return
		}
		writeUploadJSON(w, map[string]any{"stored": true, "location": "/fu/safe/attachment/files/" + name})
	})

	// Safe: an extension allowlist, and a refusal that quotes the refused path.
	allowed := map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".txt": true}
	mux.HandleFunc("/fu/safe/allowlist/upload", func(w http.ResponseWriter, r *http.Request) {
		name, content, ok := readUpload(r)
		if r.Method != http.MethodPost || !ok {
			http.Error(w, "send a multipart file", http.StatusBadRequest)
			return
		}
		if strings.ContainsAny(name, "\x00/\\") || !allowed[strings.ToLower(path.Ext(name))] {
			writeUploadJSON(w, map[string]any{"stored": false,
				"error": "file type not allowed, not stored: /fu/safe/allowlist/files/" + name})
			return
		}
		if _, ok := s.put("/fu/safe/allowlist/files", name, content); !ok {
			http.Error(w, "could not store the file", http.StatusInternalServerError)
			return
		}
		writeUploadJSON(w, map[string]any{"stored": true, "location": "/fu/safe/allowlist/files/" + name})
	})

	// Safe: the allowlist AND a content check past the magic bytes - a file whose body carries
	// HTML markup after its image header is refused, so the GIF89a polyglot fails here.
	mux.HandleFunc("/fu/safe/strict/upload", func(w http.ResponseWriter, r *http.Request) {
		name, content, ok := readUpload(r)
		if r.Method != http.MethodPost || !ok {
			http.Error(w, "send a multipart file", http.StatusBadRequest)
			return
		}
		ext := strings.ToLower(path.Ext(name))
		if strings.ContainsAny(name, "\x00/\\") || !allowed[ext] {
			writeUploadJSON(w, map[string]any{"stored": false, "error": "file type not allowed"})
			return
		}
		if ext != ".txt" && !strings.HasPrefix(http.DetectContentType(content), "image/") {
			writeUploadJSON(w, map[string]any{"stored": false, "error": "file content is not an image"})
			return
		}
		rest := content
		if len(rest) > 32 {
			rest = rest[32:]
		}
		if bytes.Contains(bytes.ToLower(rest), []byte("<!doctype")) ||
			bytes.Contains(bytes.ToLower(rest), []byte("<html")) ||
			bytes.Contains(bytes.ToLower(rest), []byte("<script")) ||
			bytes.Contains(bytes.ToLower(rest), []byte("<svg")) {
			writeUploadJSON(w, map[string]any{"stored": false, "error": "file content is not a plain image"})
			return
		}
		base := path.Base(name)
		if _, ok := s.put("/fu/safe/strict/files", base, content); !ok {
			http.Error(w, "could not store the file", http.StatusInternalServerError)
			return
		}
		writeUploadJSON(w, map[string]any{"stored": true, "location": "/fu/safe/strict/files/" + base})
	})

	// A filter that checks magic bytes: an image extension must carry image content. The GIF89a
	// HTML polyglot passes; the stored file is still served by its extension, so nothing renders.
	mux.HandleFunc("/fu/sniff/upload", func(w http.ResponseWriter, r *http.Request) {
		name, content, ok := readUpload(r)
		if r.Method != http.MethodPost || !ok {
			http.Error(w, "send a multipart file", http.StatusBadRequest)
			return
		}
		ext := strings.ToLower(path.Ext(name))
		if strings.ContainsAny(name, "\x00/\\") || !allowed[ext] {
			writeUploadJSON(w, map[string]any{"stored": false, "error": "file type not allowed"})
			return
		}
		if ext != ".txt" && !strings.HasPrefix(http.DetectContentType(content), "image/") {
			writeUploadJSON(w, map[string]any{"stored": false, "error": "file content is not an image"})
			return
		}
		base := path.Base(name)
		if _, ok := s.put("/fu/sniff/files", base, content); !ok {
			http.Error(w, "could not store the file", http.StatusInternalServerError)
			return
		}
		writeUploadJSON(w, map[string]any{"stored": true, "location": "/fu/sniff/files/" + base})
	})

	// The same sniffing filter, but the stored file is served with the Content-Type the upload
	// DECLARED: a polyglot sent as text/html is rendered as a document.
	mux.HandleFunc("/fu/trustct/upload", func(w http.ResponseWriter, r *http.Request) {
		name, content, ct, ok := readUploadTyped(r)
		if r.Method != http.MethodPost || !ok {
			http.Error(w, "send a multipart file", http.StatusBadRequest)
			return
		}
		ext := strings.ToLower(path.Ext(name))
		if strings.ContainsAny(name, "\x00/\\") || !allowed[ext] {
			writeUploadJSON(w, map[string]any{"stored": false, "error": "file type not allowed"})
			return
		}
		if ext != ".txt" && !strings.HasPrefix(http.DetectContentType(content), "image/") {
			writeUploadJSON(w, map[string]any{"stored": false, "error": "file content is not an image"})
			return
		}
		base := path.Base(name)
		if _, ok := s.putTyped("/fu/trustct/files", base, ct, content); !ok {
			http.Error(w, "could not store the file", http.StatusInternalServerError)
			return
		}
		writeUploadJSON(w, map[string]any{"stored": true, "location": "/fu/trustct/files/" + base})
	})

	// Serving and removal. The open store exposes a DELETE on its files; the rest do not. The
	// open and filtered stores serve by extension, trustct serves the declared type, and the
	// safe stores serve downloads.
	serve := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if strings.HasPrefix(r.URL.Path, "/fu/trustct/files/") {
				// A delete API that accepts and does nothing: the file is served afterwards
				// exactly as before.
				w.WriteHeader(http.StatusNoContent)
				return
			}
			if !strings.HasPrefix(r.URL.Path, "/fu/files/") {
				http.Error(w, "no delete is exposed here", http.StatusMethodNotAllowed)
				return
			}
			if !s.del(r.URL.Path) {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		b, declared, ok := s.getTyped(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/fu/safe/"):
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Disposition", "attachment")
		case declared != "":
			w.Header().Set("Content-Type", declared)
		default:
			w.Header().Set("Content-Type", typeByExtension(r.URL.Path))
		}
		_, _ = w.Write(b)
	}
	mux.HandleFunc("/fu/", serve)
}
