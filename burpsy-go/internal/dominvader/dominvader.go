// Package dominvader is burpsy's operator-side DOM auditor (burpsy-react-ui-wl94): Burp's DOM Invader
// in the shape burpsy can ship it — a Manifest V3 extension loaded into the operator's pre-wired
// browser (burpsy-react-ui-bufa), watching a canary through a page's own sources and sinks while the
// operator browses, rather than only what a scan decides to run.
//
// This package owns two things: the embedded extension and its materialisation (writing it to a temp
// directory with the current canary and report URL baked in, for --load-extension), and the Store the
// extension reports hits to. The scanner-side dynamic analyser (internal/domexec) is a separate tier
// and keeps its own extension-free instrumentation; the two share only the sink vocabulary.
package dominvader

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed extension/*
var extensionFS embed.FS

// Config is what the extension needs baked in at launch: the canary to watch, whether to watch at
// all, and where to report. It is written into the materialised extension as config.js.
type Config struct {
	// Canary is the operator's marker string. The extension reports a flow only when a value carrying
	// this string reaches a source or a sink.
	Canary string `json:"canary"`
	// Enabled gates the whole instrumentation: off, the content script returns immediately and the
	// page runs untouched. Burp's DOM Invader is off until the operator turns it on.
	Enabled bool `json:"enabled"`
	// Report is the absolute URL the service worker POSTs each hit to — burpsy's own loopback API,
	// which the browser's proxy settings bypass so the report is never itself proxied or recorded.
	Report string `json:"report"`
}

// NewCanary mints a fresh canary: a short, pronounceable-enough marker unlikely to occur in a page by
// accident, with a fixed prefix so an operator recognises burpsy's marker in a response.
func NewCanary() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "burpsyDI0000"
	}
	return "burpsyDI" + hex.EncodeToString(b[:])
}

// Materialise writes the extension into a fresh directory under parent, with cfg baked into
// config.js, and returns the directory for browser.Spec.Extensions. The caller owns the directory's
// lifetime (the browser profile's, in practice); a per-launch temp dir is the natural home.
func Materialise(parent string, cfg Config) (string, error) {
	dir, err := os.MkdirTemp(parent, "burpsy-dom-auditor-")
	if err != nil {
		return "", fmt.Errorf("dom auditor: making the extension directory: %w", err)
	}
	entries, err := fs.ReadDir(extensionFS, "extension")
	if err != nil {
		return "", fmt.Errorf("dom auditor: reading the embedded extension: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := extensionFS.ReadFile("extension/" + e.Name())
		if err != nil {
			return "", fmt.Errorf("dom auditor: reading %s: %w", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o644); err != nil {
			return "", fmt.Errorf("dom auditor: writing %s: %w", e.Name(), err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config.js"), []byte(configJS(cfg)), 0o644); err != nil {
		return "", fmt.Errorf("dom auditor: writing config.js: %w", err)
	}
	return dir, nil
}

// configJS renders the config as a script that sets self.__burpsyDI_config — the one file loaded into
// the MAIN world (by the content script) and the service worker (by importScripts), each of which has
// its own `self`.
func configJS(cfg Config) string {
	blob, _ := json.Marshal(cfg)
	return "self.__burpsyDI_config = " + string(blob) + ";\n"
}

// Hit is one reported flow: the canary seen in a source, or reaching a sink.
type Hit struct {
	// ID is assigned by the Store on arrival, so the console can key rows and a live update can
	// address one. Not set by the extension.
	ID uint64 `json:"id"`
	// Kind is "source" (the canary entered the page) or "sink" (it reached a sink).
	Kind string `json:"kind"`
	// Sink is the sink tag (the domexec vocabulary: innerHTML, eval, document-write, ...) for a sink
	// hit, or the source name for a source hit.
	Sink string `json:"sink"`
	// Sources are the browser-readable sources that carried the canary when the hit fired, so a sink
	// hit reads as source -> sink.
	Sources []string `json:"sources"`
	// Excerpt is the value around the canary, bounded, so the operator sees how it was framed without
	// the whole document coming back.
	Excerpt string `json:"excerpt"`
	// Stack is the JS stack at the sink, so the operator can find the vulnerable line.
	Stack string `json:"stack"`
	// URL is the document the hit fired in; Frame says whether that was the top document or an iframe.
	URL   string `json:"url"`
	Frame string `json:"frame"`
	// Dedupe is the extension's collision key for one hit shape, used to collapse the repeats a busy
	// page produces. Not shown.
	Dedupe string `json:"dedupe"`
	// TS is the extension's millisecond timestamp; ReceivedUnixMs is burpsy's, set on arrival.
	TS             int64 `json:"ts"`
	ReceivedUnixMs int64 `json:"received_unix_ms"`
}

// maxHits bounds the store: a ring, because an operator browsing a busy app generates them steadily
// and the console shows the recent ones. Old hits fall off the back.
const maxHits = 2000

// Store holds the operator's canary, the on/off switch, and the recent hits. One per server; the
// browser materialises its config from this, and the report endpoint adds to it.
type Store struct {
	mu       sync.RWMutex
	canary   string
	enabled  bool
	hits     []*Hit
	nextID   uint64
	seen     map[string]uint64 // dedupe key -> hit id, so a repeat bumps the existing row's count
	onChange func()
}

// NewStore makes a store with a fresh canary and the feature off, Burp's default.
func NewStore() *Store {
	return &Store{canary: NewCanary(), seen: map[string]uint64{}}
}

// OnChange installs the single live-update signal, fired after any mutation. Nil removes it.
func (s *Store) OnChange(fn func()) {
	s.mu.Lock()
	s.onChange = fn
	s.mu.Unlock()
}

func (s *Store) signal() {
	if s.onChange != nil {
		s.onChange()
	}
}

// Config is the snapshot the browser bakes into the extension at launch, with the report URL the
// caller supplies (the server knows its own address, this package does not).
func (s *Store) Config(reportURL string) Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Config{Canary: s.canary, Enabled: s.enabled, Report: reportURL}
}

// Canary returns the current canary.
func (s *Store) Canary() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.canary
}

// Enabled reports whether instrumentation is on.
func (s *Store) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// SetCanary replaces the canary. An empty value is refused: the extension watches for a string, and
// an empty one matches everything.
func (s *Store) SetCanary(canary string) error {
	canary = strings.TrimSpace(canary)
	if canary == "" {
		return fmt.Errorf("a canary cannot be empty")
	}
	s.mu.Lock()
	s.canary = canary
	s.mu.Unlock()
	s.signal()
	return nil
}

// SetEnabled turns instrumentation on or off. Takes effect for browsers launched after it — the
// config is baked in at launch — which the console says.
func (s *Store) SetEnabled(on bool) {
	s.mu.Lock()
	s.enabled = on
	s.mu.Unlock()
	s.signal()
}

// Add records one reported hit, collapsing an extension-identified repeat onto the existing row
// rather than growing the list. Returns the stored hit.
func (s *Store) Add(h *Hit) *Hit {
	s.mu.Lock()
	h.ReceivedUnixMs = time.Now().UnixMilli()
	if h.Dedupe != "" {
		if id, ok := s.seen[h.Dedupe]; ok {
			for _, existing := range s.hits {
				if existing.ID == id {
					existing.ReceivedUnixMs = h.ReceivedUnixMs
					s.mu.Unlock()
					s.signal()
					return existing
				}
			}
		}
	}
	s.nextID++
	h.ID = s.nextID
	if h.Dedupe != "" {
		s.seen[h.Dedupe] = h.ID
	}
	s.hits = append(s.hits, h)
	if len(s.hits) > maxHits {
		drop := s.hits[0]
		s.hits = s.hits[1:]
		delete(s.seen, drop.Dedupe)
	}
	s.mu.Unlock()
	s.signal()
	return h
}

// Hits returns a copy of the recent hits, oldest first.
func (s *Store) Hits() []*Hit {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Hit, len(s.hits))
	copy(out, s.hits)
	return out
}

// Clear drops every hit, keeping the canary and the switch.
func (s *Store) Clear() {
	s.mu.Lock()
	s.hits = nil
	s.seen = map[string]uint64{}
	s.mu.Unlock()
	s.signal()
}
