package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxPayloadUploadBytes bounds one uploaded wordlist. The server's 16 MiB body cap already
// wraps every request; the upload's own bound is smaller because a payload FILE is not a
// message: Burp's own shipped lists top out well under this, and a list that does not fit in
// 8 MiB of text is a corpus to stream, not a click's upload. Parsed payload lines are also
// bounded by Resolve's per-item length check, so the size bound here is about upload cost,
// not payload legality.
const maxPayloadUploadBytes = 8 << 20

// maxUploadDirEntries bounds how many uploaded files the directory keeps before the oldest is
// dropped: an upload is scratch space for an attack, not a growing store. Without a bound a
// long-running burpsy accumulates every wordlist ever uploaded, which is the memory-profile
// failure this engine refuses everywhere else.
const maxUploadDirEntries = 200

// handleIntruderPayloadUpload serves POST /api/intruder/payload-files: an operator's wordlist
// arrives as the request body (text, one payload per line — the same shape the server-side file
// path already reads) and lands in burpsy's upload directory. The response names the stored
// path, which the UI plugs into the existing {"type":"file","filename":...} wire form — the
// payload source is unchanged, so Resolve's per-line trimming, length checks and cap all apply
// to an uploaded list exactly as they do to a server-side one.
//
// Why a file rather than inline payloads in the run request: the file source streams from disk
// at resolve time and the UI's file-type card already renders the wire shape; reusing it means
// an uploaded list and a server-side list are indistinguishable to the engine, which is the
// point — an operator's own wordlist should not be a second-class payload type.
//
// The name is chosen here, not from the client: a client-supplied filename is a path-traversal
// primitive (../../ anywhere on disk) and a collision vector between two operators uploading
// lists.txt at once. Random names keep both impossible; the response carries the resolved path
// and the operator's original name rides along for display only.
func (s *Server) handleIntruderPayloadUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Body == nil {
		http.Error(w, "request body is the wordlist itself: text, one payload per line", http.StatusBadRequest)
		return
	}

	// OriginalName is display-only; it never touches the filesystem.
	originalName := strings.TrimSpace(r.Header.Get("X-Payload-Filename"))
	if i := strings.LastIndexAny(originalName, "/\\"); i >= 0 {
		originalName = originalName[i+1:]
	}

	dir, err := s.payloadUploadDir()
	if err != nil {
		http.Error(w, fmt.Sprintf("upload directory unavailable: %v", err), http.StatusInternalServerError)
		return
	}

	var raw []byte
	limited := io.LimitReader(r.Body, maxPayloadUploadBytes+1)
	raw, err = io.ReadAll(limited)
	if err != nil {
		http.Error(w, fmt.Sprintf("reading upload: %v", err), http.StatusBadRequest)
		return
	}
	if len(raw) > maxPayloadUploadBytes {
		http.Error(w, fmt.Sprintf("upload exceeds %d bytes; a list that large is a streaming corpus, not a click's upload", maxPayloadUploadBytes), http.StatusRequestEntityTooLarge)
		return
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		http.Error(w, "upload is empty: the body is the wordlist itself, one payload per line", http.StatusBadRequest)
		return
	}

	name := uploadName()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		http.Error(w, fmt.Sprintf("storing upload: %v", err), http.StatusInternalServerError)
		return
	}
	s.trimUploads(dir)

	// lines is the count Resolve will produce (blank lines skipped), so the response says what
	// the attack will actually see — the same honest accounting Resolve applies at run time.
	lines := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		// The absolute path the existing {"type":"file"} source resolves.
		"filename": path,
		"lines":    lines,
		"bytes":    len(raw),
		// Display-only; the stored name is random by design (see the path-traversal note).
		"original_name": originalName,
		"note": "the file is stored in burpsy's upload directory and resolved by the ordinary file " +
			"payload source: one payload per line, blank lines skipped, per-item length checked",
	})
}

// payloadUploadDir creates (once) the directory uploaded wordlists live in, beside the
// project's other scratch state.
func (s *Server) payloadUploadDir() (string, error) {
	dir := filepath.Join(os.TempDir(), "burpsy-payload-uploads")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// uploadName is a random file name: 16 hex characters from the CSPRNG, enough that two uploads
// in the same process cannot collide and a client cannot steer the path.
func uploadName() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read from crypto/rand failing is a system-level break; a timestamp fallback keeps
		// the upload working and stays unique-enough within a process.
		return fmt.Sprintf("upload-%d", jsonNowMs())
	}
	return "ul-" + hex.EncodeToString(b[:]) + ".txt"
}

// trimUploads drops the oldest uploads past the bound. Best-effort: a directory that cannot be
// read fails the next MkdirAll-free upload path, not this trim.
func (s *Server) trimUploads(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) <= maxUploadDirEntries {
		return
	}
	type dated struct {
		name string
		mod  int64
	}
	files := make([]dated, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, dated{name: e.Name(), mod: info.ModTime().UnixNano()})
	}
	// Oldest first, drop just enough.
	for i := 0; i < len(files)-maxUploadDirEntries; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j].mod < files[i].mod {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	for i := 0; i < len(files)-maxUploadDirEntries; i++ {
		_ = os.Remove(filepath.Join(dir, files[i].name))
	}
}

// jsonNowMs is a millisecond timestamp for the fallback name.
func jsonNowMs() int64 {
	return time.Now().UnixMilli()
}
