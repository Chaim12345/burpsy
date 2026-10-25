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
	"os"
	"strings"
	"sync"

	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/extension"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// ExtensionServices assembles the services from this server's parts. The
// composition root calls it once, after the server exists, and injects the
// result before any plugin loads (see extension.Host.SetServices).
func (s *Server) ExtensionServices() extension.Services {
	// The storage document lives beside the project database; a server without
	// one (tests) gets an in-memory store, which is the honest answer for a
	// process that has no project to persist into.
	persister, ok := any(s.persist).(interface{ Path() string })
	var storagePath string
	if ok && persister != nil {
		storagePath = persister.Path() + ".extensions.json"
	}
	return extension.Services{
		RaiseEvent: s.extensionRaiseEvent,
		Storage:    newExtensionStorage(storagePath),
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
		return extension.SessionResponse{}, fmt.Errorf("%w: %s", extension.ErrOutOfScope, s.scope.Explain(host, port, path, tls))
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
		return extension.SessionResponse{}, err
	}
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
	// The organizer source is not wired in this slice: the organizer store
	// exposes no read API the host can page yet, and answering with the proxy
	// history instead would silently rename what the plugin asked for.
	if q.Source == extension.TrafficOrganizer {
		return extension.TrafficPage{}, errors.New("the organizer source is not wired yet")
	}
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
	for _, ex := range t.srv.store.Exchanges() {
		if q.Host != "" && !strings.EqualFold(ex.Host, q.Host) {
			continue
		}
		if q.Method != "" && !strings.EqualFold(ex.Method, q.Method) {
			continue
		}
		status := 0
		if ex.Status != nil {
			status = int(*ex.Status)
		}
		if q.Status != 0 && status != q.Status {
			continue
		}
		url := fmt.Sprintf("%s:%d%s", ex.Host, ex.Port, ex.Path)
		if q.Contains != "" && !strings.Contains(url, q.Contains) {
			continue
		}
		page.Total++
		if page.Total <= offset || len(page.Items) >= limit {
			continue
		}
		item := extension.TrafficItem{ID: int(ex.ID), Method: ex.Method, URL: url, Status: status}
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
	return page, nil
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

// extensionStorage is storage.get/set/delete over a JSON document. The map
// key is plugin NUL scope NUL key, so one plugin can never read another's
// rows and the two scopes stay distinct. Writes serialise on the mutex and
// land atomically (temp file + rename), and the protocol's byte bounds are
// enforced here so a plugin cannot grow the document without limit.
type extensionStorage struct {
	mu   sync.Mutex
	path string // empty: in-memory only (tests, a server without a project)
	data map[string]json.RawMessage
}

func newExtensionStorage(path string) *extensionStorage {
	return &extensionStorage{path: path, data: map[string]json.RawMessage{}}
}

func extensionStorageKey(plugin string, scope extension.StorageScope, key string) string {
	return plugin + "\x00" + string(scope) + "\x00" + key
}

func (st *extensionStorage) Get(plugin string, scope extension.StorageScope, key string) (json.RawMessage, bool, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := st.loadLocked(); err != nil {
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
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := st.loadLocked(); err != nil {
		return err
	}
	st.data[extensionStorageKey(plugin, scope, key)] = append(json.RawMessage{}, value...)
	return st.saveLocked()
}

func (st *extensionStorage) Delete(plugin string, scope extension.StorageScope, key string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := st.loadLocked(); err != nil {
		return err
	}
	delete(st.data, extensionStorageKey(plugin, scope, key))
	return st.saveLocked()
}

// loadLocked is idempotent: data non-nil means either the file was read or
// there is no file to read. A missing file is an empty store, not an error.
func (st *extensionStorage) loadLocked() error {
	if st.data != nil || st.path == "" {
		return nil
	}
	raw, err := os.ReadFile(st.path)
	if errors.Is(err, os.ErrNotExist) {
		st.data = map[string]json.RawMessage{}
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &st.data)
}

func (st *extensionStorage) saveLocked() error {
	if st.path == "" {
		return nil
	}
	raw, err := json.Marshal(st.data)
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}
