package web

// extension_services.go builds the extension.Services the composition root
// injects into the plugin host (burpsy-react-ui-wiwh, slice 6): the host
// methods W6 landed answered CodeNotWired until something real stood behind
// them, and this is that something. A plugin is an untrusted principal, so
// every implementation here routes through the same fences the operator's
// own tools use — never around them:
//
//   - Send goes out through an AuthorisedSender bound to the request's own
//     authority, the exact path a session macro step takes (see macroRunner,
//     HARD-03): the engagement scope judges the rendered bytes before the
//     dial, pacing applies, and a refusal is extension.ErrOutOfScope, not a
//     bypass.
//   - Prompt is deliberately NIL: no operator-configured AI endpoint exists
//     yet (that is W4's agent.LLM lane), and a plugin's ai.prompt answers
//     CodeNotWired until one does. xpuh closes then, not before.
//
// Storage is a JSON document beside the project database: per-plugin,
// per-scope, bounded by the protocol's key/value limits, written atomically
// so a crash mid-write cannot tear a plugin's saved state. Traffic is a
// read-only window over the same store the history page serves.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/extension"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ExtensionServices assembles the services from this server's parts. The
// composition root calls it once, after the server exists, and injects the
// result before any plugin loads (see extension.Host.SetServices).
func (s *Server) ExtensionServices() extension.Services {
	// The storage document lives beside the project database (<project>.db.extensions.json), one
	// per project. The path is resolved on every use from the project open NOW, because main.go
	// builds these services before WithPersist attaches the project and an in-console project
	// switch swaps the project afterwards. A server without a project (tests, no -db) resolves
	// "" and gets an in-memory store, the honest answer for a process with nothing to persist into.
	return extension.Services{
		RaiseEvent: s.extensionRaiseEvent,
		Storage:    newExtensionStorage(s.extensionStoragePath),
		Send:       s.extensionSend,
		Traffic:    extensionTraffic{srv: s},
	}
}

// extensionRaiseEvent is event.raise: one dashboard event per call, with the
// plugin named in the detail so the operator can always tell a plugin's row
// from the tool's own.
func (s *Server) extensionRaiseEvent(plugin string, level extension.EventLevel, message string) {
	sev := dash.SeverityInfo
	switch level {
	case extension.EventError, extension.EventCritical:
		sev = dash.SeverityError
	case extension.EventDebug:
		sev = dash.SeverityInfo
	}
	s.events.Record("extension", sev, plugin+": "+message)
}

// extensionSend is http.send: one request through the authorised sender, the
// egress fence a plugin can never talk its way past.
func (s *Server) extensionSend(ctx context.Context, plugin string, req extension.SessionRequest) (extension.SessionResponse, error) {
	host, port, tls, err := targetParts(req.URL)
	if err != nil {
		return extension.SessionResponse{}, err
	}
	// Fail closed on a missing part, the rule macroRunner states: treating a
	// missing scope as permission is the defect the gate exists to prevent.
	if s.sender == nil {
		return extension.SessionResponse{}, fmt.Errorf("no HTTP sender is wired, so plugin %q cannot send", plugin)
	}
	if s.scope == nil {
		return extension.SessionResponse{}, fmt.Errorf("no engagement scope is wired, so a request from plugin %q cannot be authorised", plugin)
	}
	path := req.URL
	if i := strings.Index(req.URL, "://"); i >= 0 {
		if j := strings.Index(req.URL[i+3:], "/"); j >= 0 {
			path = req.URL[i+3+j:]
		} else {
			path = "/"
		}
	}
	// The pre-check exists to answer with ErrOutOfScope, the contract the host
	// documents; the byte-level AuthoriseRaw inside SendRequest stays the real
	// gate, because only the rendered request can be trusted.
	if !s.scope.Contains(host, port, path, tls) {
		explain := s.scope.Explain(host, port, path, tls)
		// The attempt is logged even though nothing was dialled: the tool log is
		// where the operator reconciles what a plugin tried against what left.
		s.toolLog.Record(toollog.ToolExtension, host, port, tls, strings.ToUpper(req.Method), path, 0, nil, 0, "refused by engagement scope: "+explain, nil)
		return extension.SessionResponse{}, fmt.Errorf("%w: %s", extension.ErrOutOfScope, explain)
	}
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = "GET"
	}
	// Repeated header names collapse to the last value, the same shape a macro
	// step carries; the protocol's [][]string survives JSON, the sender's
	// Request does not, and the collapse is the honest statement of that.
	hdrs := map[string]string{"Host": host}
	for _, kv := range req.Headers {
		if len(kv) == 2 {
			hdrs[kv[0]] = kv[1]
		}
	}
	start := time.Now()
	resp, err := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls).SendRequest(ctx, &sender.Request{
		Method:  method,
		Host:    host,
		Port:    port,
		TLS:     tls,
		Path:    path,
		Headers: hdrs,
		Body:    []byte(req.Body),
	})
	if err != nil {
		s.toolLog.Record(toollog.ToolExtension, host, port, tls, method, path, 0, nil, elapsedMillis(start), err.Error(), nil)
		return extension.SessionResponse{}, err
	}
	respLen := len(resp.Body)
	s.toolLog.Record(toollog.ToolExtension, host, port, tls, method, path, resp.StatusCode, &respLen, elapsedMillis(start), "", nil)
	out := extension.SessionResponse{Status: resp.StatusCode, Body: string(resp.Body)}
	for k, v := range resp.Headers {
		out.Headers = append(out.Headers, []string{k, v})
	}
	return out, nil
}

// extensionTraffic is traffic.query and scope.check: a read-only window over
// the traffic store, paged and bounded. It must not mutate anything — the
// interface says so, and the implementation holds no write handle.
type extensionTraffic struct{ srv *Server }

func (t extensionTraffic) Query(_ context.Context, _ string, q extension.TrafficQuery) (extension.TrafficPage, error) {

	limit := q.Limit
	if limit <= 0 {
		limit = extension.DefaultTrafficPage
	}
	if limit > extension.MaxTrafficPage {
		limit = extension.MaxTrafficPage
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	page := extension.TrafficPage{Items: []extension.TrafficItem{}}
	if q.Source == extension.TrafficOrganizer {
		if t.srv.organizer == nil {
			return extension.TrafficPage{}, errors.New("no organizer is wired")
		}
		// The organizer's own order is preserved, the rule organizerView states:
		// it is a list the operator built. Unresolved items (an evicted exchange)
		// are skipped here rather than carried as empty rows: a plugin paged for
		// traffic, and a note-only row answers a question it did not ask.
		for _, item := range t.srv.organizer.List() {
			if item.Exchange < 0 {
				continue // not an id the store can hold; skipped like an evicted exchange
			}
			ex, err := t.srv.store.GetExchange(core.ExchangeID(item.Exchange))
			if err != nil || ex == nil {
				continue
			}
			t.addIfMatch(&page, ex, q, offset, limit)
		}
		return page, nil
	}
	for _, ex := range t.srv.store.Exchanges() {
		t.addIfMatch(&page, ex, q, offset, limit)
	}
	return page, nil
}

// addIfMatch applies the query's filters and paging to one exchange. Total is
// the count across EVERY match, paged or not — a page that reported only its
// own length would tell the plugin there is no more when there is.
func (t extensionTraffic) addIfMatch(page *extension.TrafficPage, ex *core.Exchange, q extension.TrafficQuery, offset, limit int) {
	{
		if q.Host != "" && !strings.EqualFold(ex.Host, q.Host) {
			return
		}
		if q.Method != "" && !strings.EqualFold(ex.Method, q.Method) {
			return
		}
		status := 0
		if ex.Status != nil {
			status = int(*ex.Status)
		}
		if q.Status != 0 && status != q.Status {
			return
		}
		url := fmt.Sprintf("%s:%d%s", ex.Host, ex.Port, ex.Path)
		if q.Contains != "" && !strings.Contains(url, q.Contains) {
			return
		}
		if uint64(ex.ID) > math.MaxInt {
			return // the protocol's id is an int; an id past it is left out, never wrapped negative
		}
		page.Total++
		if page.Total <= offset || len(page.Items) >= limit {
			return
		}
		item := extension.TrafficItem{ID: int(uint64(ex.ID) & math.MaxInt), Method: ex.Method, URL: url, Status: status}
		if q.IncludeBodies {
			if ex.Request != nil {
				if m, err := t.srv.store.Get(*ex.Request); err == nil {
					item.Request = string(m.Raw())
				}
			}
			if ex.Response != nil {
				if m, err := t.srv.store.Get(*ex.Response); err == nil {
					item.Response = string(m.Raw())
				}
			}
		}
		page.Items = append(page.Items, item)
	}
}

func (t extensionTraffic) InScope(_ context.Context, rawurl string) (bool, error) {
	host, port, tls, err := targetParts(rawurl)
	if err != nil {
		return false, err
	}
	path := rawurl
	if i := strings.Index(rawurl, "://"); i >= 0 {
		if j := strings.Index(rawurl[i+3:], "/"); j >= 0 {
			path = rawurl[i+3+j:]
		} else {
			path = "/"
		}
	}
	if t.srv.scope == nil {
		return false, errors.New("no engagement scope is wired")
	}
	return t.srv.scope.Contains(host, port, path, tls), nil
}

// elapsedMillis is the whole milliseconds since start, never negative: a clock that steps back
// must not turn a duration into a huge unsigned value in the tool log.
func elapsedMillis(start time.Time) uint64 {
	ms := time.Since(start).Milliseconds()
	if ms < 0 {
		return 0
	}
	return uint64(ms)
}

// extensionStoragePath is the storage document of the project open now, "" when none is.
// persist is a concrete *persist.Store: a nil receiver answers "" from Path, which is also the
// guard. A bare nil check on the interface would be true for a typed nil and would root the
// document at the process cwd. Callers hold the project-switch read lock.
func (s *Server) extensionStoragePath() string {
	if path := s.persist.Path(); path != "" {
		return path + ".extensions.json"
	}
	return ""
}

// extensionStorage is storage.get/set/delete over a JSON document. The map
// key is plugin NUL scope NUL key, so one plugin can never read another's
// rows and the two scopes stay distinct. Both scopes live in the project's
// document, so "preferences" is per project here, as it always was. Writes
// serialise on the mutex and land atomically (temp file + rename), and the
// protocol's byte bounds are enforced here so a plugin cannot grow the
// document without limit.
//
// The document follows the project: every operation resolves the path (under
// the project-switch read lock, so a switch cannot land mid-operation) and
// reloads when it differs from the path the rows in memory came from. Rows
// are never copied between projects.
type extensionStorage struct {
	mu         sync.Mutex
	resolve    func() string // the document path of the project open now; "" = in memory only
	loadedFrom string
	data       map[string]json.RawMessage // nil until the current path has been read
}

func newExtensionStorage(resolve func() string) *extensionStorage {
	return &extensionStorage{resolve: resolve}
}

func extensionStorageKey(plugin string, scope extension.StorageScope, key string) string {
	return plugin + "\x00" + string(scope) + "\x00" + key
}

func (st *extensionStorage) Get(plugin string, scope extension.StorageScope, key string) (json.RawMessage, bool, error) {
	unlock := lockProjectCapture()
	defer unlock()
	st.mu.Lock()
	defer st.mu.Unlock()
	path := st.resolve()
	if err := st.loadLocked(path); err != nil {
		return nil, false, err
	}
	v, ok := st.data[extensionStorageKey(plugin, scope, key)]
	return v, ok, nil
}

func (st *extensionStorage) Set(plugin string, scope extension.StorageScope, key string, value json.RawMessage) error {
	if len(key) > extension.MaxStorageKeyBytes {
		return fmt.Errorf("storage key is %d bytes; the bound is %d", len(key), extension.MaxStorageKeyBytes)
	}
	if len(value) > extension.MaxStorageValueBytes {
		return fmt.Errorf("storage value is %d bytes; the bound is %d", len(value), extension.MaxStorageValueBytes)
	}
	unlock := lockProjectCapture()
	defer unlock()
	st.mu.Lock()
	defer st.mu.Unlock()
	path := st.resolve()
	if err := st.loadLocked(path); err != nil {
		return err
	}
	st.data[extensionStorageKey(plugin, scope, key)] = append(json.RawMessage{}, value...)
	return st.saveLocked(path)
}

func (st *extensionStorage) Delete(plugin string, scope extension.StorageScope, key string) error {
	unlock := lockProjectCapture()
	defer unlock()
	st.mu.Lock()
	defer st.mu.Unlock()
	path := st.resolve()
	if err := st.loadLocked(path); err != nil {
		return err
	}
	delete(st.data, extensionStorageKey(plugin, scope, key))
	return st.saveLocked(path)
}

// loadLocked makes st.data the rows of the document at path. It is a no-op while the path is the
// one already loaded. A missing file is an empty store, not an error. A file that exists and cannot
// be read or parsed is an error on every call and leaves nothing loaded, so a write can never
// replace rows that were merely unreadable. With no path the store is in memory only.
func (st *extensionStorage) loadLocked(path string) error {
	if st.data != nil && st.loadedFrom == path {
		return nil
	}
	if path == "" {
		st.data, st.loadedFrom = map[string]json.RawMessage{}, ""
		return nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		st.data, st.loadedFrom = map[string]json.RawMessage{}, path
		return nil
	}
	if err != nil {
		st.data = nil
		return err
	}
	rows := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &rows); err != nil {
		st.data = nil
		return fmt.Errorf("extension storage %s is unreadable and was left untouched: %w", path, err)
	}
	st.data, st.loadedFrom = rows, path
	return nil
}

func (st *extensionStorage) saveLocked(path string) error {
	if path == "" {
		return nil
	}
	raw, err := json.Marshal(st.data)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
