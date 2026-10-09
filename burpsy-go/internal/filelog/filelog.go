// Package filelog is Burp's Project settings → Logging (settings/project/logging.html,
// project_options.misc.logging; burpsy-react-ui-nvfl): "which of Burp's tools can add HTTP requests
// and responses to the log files". Each of requests and responses maps a tool — or all_tools — to a
// file path; an empty path is off, which is Burp's default for every tool.
//
// Every exchange any tool records reaches the traffic store, so the store's exchange observer is the
// one place that sees them all. The observer contract forbids file writes under the store's lock, so
// it only enqueues the exchange (non-blocking; a full queue counts a drop rather than slowing the
// proxy), and one goroutine reads the bytes back from the store and appends them to the files.
//
// Each entry has Burp's log-file shape: a rule of '=' characters, a line with the time, the target's
// URL and the server IP when known, another rule, the raw message, and a blank line.
package filelog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Tools are Burp's keys, in Burp's order.
var Tools = []string{"all_tools", "proxy", "scanner", "repeater", "intruder", "sequencer", "extender"}

// Settings is Burp's document: tool → file path for requests and for responses. Absent or empty is off.
type Settings struct {
	Requests  map[string]string `json:"requests"`
	Responses map[string]string `json:"responses"`
}

// Normalised returns settings with both maps present and every tool key listed, empty when off.
func (s Settings) Normalised() Settings {
	out := Settings{Requests: map[string]string{}, Responses: map[string]string{}}
	for _, tool := range Tools {
		out.Requests[tool] = strings.TrimSpace(s.Requests[tool])
		out.Responses[tool] = strings.TrimSpace(s.Responses[tool])
	}
	return out
}

// Validate refuses an unknown tool key or a path that is not absolute, naming it.
func (s Settings) Validate() error {
	known := map[string]bool{}
	for _, tool := range Tools {
		known[tool] = true
	}
	for which, m := range map[string]map[string]string{"requests": s.Requests, "responses": s.Responses} {
		for tool, path := range m {
			if !known[tool] {
				return fmt.Errorf("%s.%s: unknown tool; the tools are %s", which, tool, strings.Join(Tools, ", "))
			}
			if p := strings.TrimSpace(path); p != "" && !filepath.IsAbs(p) {
				return fmt.Errorf("%s.%s: %q is not an absolute path; the log is written by the server process, "+
					"so a relative path would land wherever it happened to start", which, tool, p)
			}
		}
	}
	return nil
}

// toolOf maps an exchange's producer to Burp's tool key. The crawler is part of Burp's Scanner, and so
// is an isolated scan (13uw): its results stay out of the site map and All issues, but its requests
// went on the wire like any scan's, and a traffic log that dropped them would under-report what was sent.
// An import, or traffic nothing attributed, belongs to no tool and is logged only by all_tools
// when it came from a tool at all — which it did not, so it is not logged.
func toolOf(source core.Source) string {
	switch source {
	case core.SourceProxy:
		return "proxy"
	case core.SourceScanner, core.SourceCrawl, core.SourceIsolatedScan:
		return "scanner"
	case core.SourceRepeater:
		return "repeater"
	case core.SourceIntruder:
		return "intruder"
	}
	return ""
}

const queueLen = 4096

// Logger writes the configured logs. The zero value is not usable; use New.
type Logger struct {
	store *core.TrafficStore

	mu       sync.Mutex
	settings Settings
	files    map[string]*os.File

	queue   chan item
	dropped atomic.Uint64
	written atomic.Uint64
	errMu   sync.Mutex
	lastErr string
	done    chan struct{}
}

// New starts a logger over store with every log off. Attach it with Observe.
func New(store *core.TrafficStore) *Logger {
	l := &Logger{store: store, settings: Settings{}.Normalised(), files: map[string]*os.File{},
		queue: make(chan item, queueLen), done: make(chan struct{})}
	go l.run()
	return l
}

// Observe is the store observer: O(1), never blocks, never touches a file.
func (l *Logger) Observe(ex *core.Exchange) {
	if ex == nil || toolOf(ex.Source) == "" {
		return
	}
	select {
	case l.queue <- item{ex: ex}:
	default:
		l.dropped.Add(1)
	}
}

// Apply validates settings, opens every named file for appending (creating it), closes the files no
// longer named, and installs the settings. On a refusal nothing changes.
func (l *Logger) Apply(settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	next := settings.Normalised()
	l.mu.Lock()
	defer l.mu.Unlock()
	opened := map[string]*os.File{}
	want := map[string]bool{}
	for _, m := range []map[string]string{next.Requests, next.Responses} {
		for _, path := range m {
			if path == "" || want[path] {
				continue
			}
			want[path] = true
			if f, ok := l.files[path]; ok {
				opened[path] = f
				continue
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				for p, nf := range opened {
					if _, existed := l.files[p]; !existed {
						nf.Close()
					}
				}
				return fmt.Errorf("cannot open %s for appending: %w", path, err)
			}
			opened[path] = f
		}
	}
	for path, f := range l.files {
		if !want[path] {
			f.Close()
		}
	}
	l.files, l.settings = opened, next
	return nil
}

// Settings returns the settings in force, every tool key present.
func (l *Logger) Settings() Settings {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.settings.Normalised()
}

// Stats is what the logger has done since it started.
type Stats struct {
	Written   uint64 `json:"written"`
	Dropped   uint64 `json:"dropped"`
	LastError string `json:"last_error,omitempty"`
}

// Stats reports the entries written, the exchanges dropped because the queue was full, and the most
// recent write error.
func (l *Logger) Stats() Stats {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	return Stats{Written: l.written.Load(), Dropped: l.dropped.Load(), LastError: l.lastErr}
}

// Flush waits until everything queued so far has been written. For tests and shutdown.
func (l *Logger) Flush() {
	marker := make(chan struct{})
	l.queue <- item{flush: marker}
	<-marker
}

// item is one queued exchange, or a flush marker.
type item struct {
	ex    *core.Exchange
	flush chan struct{}
}

const rule = "======================================================"

func (l *Logger) run() {
	for it := range l.queue {
		if it.flush != nil {
			close(it.flush)
			continue
		}
		l.write(it.ex)
	}
}

// targets returns the files an exchange's request and response go to: the tool's own and all_tools,
// deduplicated so one file named under both gets the entry once.
func (l *Logger) targets(tool string) (requests, responses []*os.File) {
	l.mu.Lock()
	defer l.mu.Unlock()
	pick := func(m map[string]string) []*os.File {
		var out []*os.File
		seen := map[string]bool{}
		for _, key := range []string{tool, "all_tools"} {
			if path := m[key]; path != "" && !seen[path] {
				seen[path] = true
				if f := l.files[path]; f != nil {
					out = append(out, f)
				}
			}
		}
		return out
	}
	return pick(l.settings.Requests), pick(l.settings.Responses)
}

func (l *Logger) write(ex *core.Exchange) {
	reqFiles, respFiles := l.targets(toolOf(ex.Source))
	if len(reqFiles) == 0 && len(respFiles) == 0 {
		return
	}
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	when := time.Now()
	if ex.StartedMs > 0 {
		when = time.UnixMilli(int64(ex.StartedMs))
	}
	head := when.Format("15:04:05") + "  " + scheme + "://" + ex.Host + ":" + strconv.Itoa(int(ex.Port))
	if ex.ServerIP != "" {
		head += "  [" + ex.ServerIP + "]"
	}
	entry := func(raw []byte) []byte {
		var b strings.Builder
		b.WriteString(rule + "\n" + head + "\n" + rule + "\n")
		b.Write(raw)
		b.WriteString("\n" + rule + "\n\n\n")
		return []byte(b.String())
	}
	put := func(files []*os.File, id *core.MsgId) {
		if len(files) == 0 || id == nil {
			return
		}
		msg, err := l.store.Get(*id)
		if err != nil {
			l.fail(err)
			return
		}
		data := entry(msg.Raw())
		for _, f := range files {
			if _, err := f.Write(data); err != nil {
				l.fail(err)
				continue
			}
			l.written.Add(1)
		}
	}
	put(reqFiles, ex.Request)
	put(respFiles, ex.Response)
}

func (l *Logger) fail(err error) {
	l.errMu.Lock()
	defer l.errMu.Unlock()
	l.lastErr = err.Error()
}

// Close stops the writer and closes every file.
func (l *Logger) Close() error {
	l.Flush()
	l.mu.Lock()
	defer l.mu.Unlock()
	var errs []error
	paths := make([]string, 0, len(l.files))
	for p := range l.files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := l.files[p].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	l.files = map[string]*os.File{}
	return errors.Join(errs...)
}
