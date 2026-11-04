package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Repeater (HTTP) workspace ---------------------------------------------------------------
//
// Where tab state lives: server-side, in memory, one store per Server (the running project).
// Tabs, groups, notes, colours, per-tab send options and each tab's send history are kept here,
// keyed by integer tab id; the request/response bytes a send produced stay in the traffic store
// and are only referenced (message ids) when a history is exported. Every page is rendered from
// this store, so the browser keeps no tab state of its own and a reload shows the same tabs. The
// state is lost when the process restarts, as the React console's component state was.
//
// GET never writes: an empty store renders a virtual tab (the latest captured request as the
// draft), and the first POST (send, save, any tab action) is what creates it. Every tab action
// posts the editor along with it (hx-include), so switching or renaming a tab never drops an
// unsent edit.

const (
	ui2RepeaterMaxTabs    = 100
	ui2RepeaterMaxClosed  = 20
	ui2RepeaterMaxHistory = 50
)

// ui2RepeaterColours are the tab/group colours, the same names the history highlights use.
var ui2RepeaterColours = []string{"red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray"}

// ui2RepeaterOpts is one tab's send-option overrides. Override false is "restore global
// default": the options are kept but not sent, so the send follows the standing settings.
type ui2RepeaterOpts struct {
	Override         bool
	Redirect         string // "" standing policy, never, on_site, in_scope, always
	Protocol         string // auto, http1, http2
	ResponseTimeout  string // ms as typed; "" is the standing read timeout
	StreamingTimeout string // ms as typed; "" is the standing streaming window
	ProcessCookies   bool
	StripConnection  bool
	NormalizeCRLF    bool
	UpdateCL         bool
	H2Reuse          bool
	CrossDomainProto bool
	Unpack           bool
}

func ui2RepeaterDefaultOpts() ui2RepeaterOpts { return ui2RepeaterOpts{Protocol: "auto", Unpack: true} }

// payload renders the overrides as /api/repeater/send's options object, nil when the tab
// follows the global defaults.
func (o ui2RepeaterOpts) payload() (*repeaterSendOptions, error) {
	if !o.Override {
		return nil, nil
	}
	out := &repeaterSendOptions{
		RedirectMode: o.Redirect, ProcessCookies: o.ProcessCookies, StripConnection: o.StripConnection,
		NormalizeLineEndings: o.NormalizeCRLF, UpdateContentLength: o.UpdateCL,
		H2ConnectionReuse: o.H2Reuse, EnforceProtocolCrossDomain: o.CrossDomainProto,
	}
	if o.Protocol != "auto" {
		out.ProtocolPreference = o.Protocol
	}
	unpack := o.Unpack
	out.UnpackResponses = &unpack
	for _, f := range []struct {
		name, v string
		dst     **int64
	}{{"response timeout", o.ResponseTimeout, &out.ResponseTimeoutMS}, {"streaming timeout", o.StreamingTimeout, &out.StreamingTimeoutMS}} {
		if strings.TrimSpace(f.v) == "" {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(f.v), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s must be a whole number of milliseconds, not %q", f.name, f.v)
		}
		*f.dst = &n
	}
	return out, nil
}

// ui2RepeaterEntry is one send in a tab's history.
type ui2RepeaterEntry struct {
	SentAt  time.Time
	Request string         // the request text as sent (before the send's transforms)
	Result  map[string]any // /api/repeater/send's answer, decoded
	Group   string         // the group-send mode that produced it, "" for a single send
}

type ui2RepeaterTab struct {
	ID           int
	Name         string
	Color        string
	Note         string
	Group        int // 0 is no group
	Target       string
	SNI          string
	Raw          string
	FromExchange *uint64
	Opts         ui2RepeaterOpts
	History      []ui2RepeaterEntry
	LastError    string
	cancel       context.CancelFunc
}

type ui2RepeaterGroup struct {
	ID    int
	Name  string
	Color string
}

type ui2RepeaterStore struct {
	mu        sync.Mutex
	nextTab   int
	nextGroup int
	tabs      []*ui2RepeaterTab
	groups    []*ui2RepeaterGroup
	closed    []*ui2RepeaterTab
}

// ui2RepeaterStores holds one workspace per Server, kept off the Server struct so this console
// page carries its own state.
var ui2RepeaterStores sync.Map

func (s *Server) ui2Repeater() *ui2RepeaterStore {
	v, _ := ui2RepeaterStores.LoadOrStore(s, &ui2RepeaterStore{nextTab: 1, nextGroup: 1})
	return v.(*ui2RepeaterStore)
}

// The store's methods below expect st.mu held.

func (st *ui2RepeaterStore) find(id int) (*ui2RepeaterTab, int) {
	for i, t := range st.tabs {
		if t.ID == id {
			return t, i
		}
	}
	return nil, -1
}

func (st *ui2RepeaterStore) group(id int) *ui2RepeaterGroup {
	for _, g := range st.groups {
		if g.ID == id {
			return g
		}
	}
	return nil
}

func (st *ui2RepeaterStore) add(t *ui2RepeaterTab) (*ui2RepeaterTab, error) {
	if len(st.tabs) >= ui2RepeaterMaxTabs {
		return nil, fmt.Errorf("refused: Repeater holds at most %d tabs - close one first", ui2RepeaterMaxTabs)
	}
	t.ID = st.nextTab
	st.nextTab++
	if t.Name == "" {
		t.Name = strconv.Itoa(t.ID)
	}
	if t.Opts == (ui2RepeaterOpts{}) {
		t.Opts = ui2RepeaterDefaultOpts()
	}
	st.tabs = append(st.tabs, t)
	return t, nil
}

func (st *ui2RepeaterStore) close(ids map[int]bool) {
	kept := st.tabs[:0]
	for _, t := range st.tabs {
		if !ids[t.ID] {
			kept = append(kept, t)
			continue
		}
		if t.cancel != nil {
			t.cancel()
		}
		st.closed = append(st.closed, t)
	}
	st.tabs = kept
	if n := len(st.closed); n > ui2RepeaterMaxClosed {
		st.closed = append([]*ui2RepeaterTab(nil), st.closed[n-ui2RepeaterMaxClosed:]...)
	}
}

// ui2RepeaterTabFromForm resolves the tab a POST acts on and applies the editor's fields to it
// (when the editor rode along). A missing or unknown tab_id creates the tab from the posted
// request, which is how the virtual first tab, a Site map draft and a legacy raw/target post
// become a real tab.
func (st *ui2RepeaterStore) tabFromForm(f url.Values) (*ui2RepeaterTab, error) {
	id, _ := strconv.Atoi(f.Get("tab_id"))
	t, _ := st.find(id)
	if t == nil && f.Get("tab_id") != "" {
		return nil, errors.New("that tab has been closed - reopen it or pick another")
	}
	if t == nil {
		nt := &ui2RepeaterTab{Raw: f.Get("raw"), Target: strings.TrimSpace(f.Get("target"))}
		if fe, err := strconv.ParseUint(f.Get("from_exchange"), 10, 64); err == nil {
			nt.FromExchange = &fe
		}
		var err error
		if t, err = st.add(nt); err != nil {
			return nil, err
		}
	}
	if f.Get("editor") == "1" {
		// A request the textarea cannot carry renders no raw field; keep the stored one.
		if _, ok := f["raw"]; ok {
			t.Raw = f.Get("raw")
		}
		t.Target = strings.TrimSpace(f.Get("target"))
		t.SNI = strings.TrimSpace(f.Get("sni"))
		t.Note = f.Get("note")
		on := func(k string) bool { return f.Get(k) == "1" }
		t.Opts = ui2RepeaterOpts{
			Override: on("opt_override"), Redirect: f.Get("opt_redirect"), Protocol: f.Get("opt_protocol"),
			ResponseTimeout: f.Get("opt_resp_timeout"), StreamingTimeout: f.Get("opt_stream_timeout"),
			ProcessCookies: on("opt_cookies"), StripConnection: on("opt_strip_conn"), NormalizeCRLF: on("opt_crlf"),
			UpdateCL: on("opt_cl"), H2Reuse: on("opt_h2reuse"), CrossDomainProto: on("opt_xdomain"), Unpack: on("opt_unpack"),
		}
		if t.Opts.Protocol == "" {
			t.Opts.Protocol = "auto"
		}
	}
	return t, nil
}

func (t *ui2RepeaterTab) record(e ui2RepeaterEntry) {
	t.History = append(t.History, e)
	if n := len(t.History); n > ui2RepeaterMaxHistory {
		t.History = append([]ui2RepeaterEntry(nil), t.History[n-ui2RepeaterMaxHistory:]...)
	}
}

// ui2RepeaterSendPayload is one tab's /api/repeater/send body.
func ui2RepeaterSendPayload(t *ui2RepeaterTab) (map[string]any, error) {
	target := t.Target
	if target == "" {
		target = ui2HostFromRequest(t.Raw)
	}
	if target == "" {
		return nil, errors.New("no target: the request carries no Host header and no target was given")
	}
	opts, err := t.Opts.payload()
	if err != nil {
		return nil, err
	}
	p := map[string]any{
		"target": target, "request": ui2RestoreHeaderNewlines(t.Raw), "tab_id": "ui2-" + strconv.Itoa(t.ID),
	}
	if opts != nil {
		p["options"] = opts
	}
	if t.Note != "" {
		p["note"] = t.Note
	}
	if t.SNI != "" {
		p["sni"] = t.SNI
	}
	if t.FromExchange != nil {
		p["from_exchange"] = *t.FromExchange
	}
	return p, nil
}

// ui2RepeaterGated reports whether an API route now needs a confirmation the page cannot mint
// inline. /api/repeater/send and send-group are riskEgress (one click) today; if that changes,
// the page refuses instead of silently bypassing the review.
func ui2RepeaterGated(path string) bool {
	_, risk, ok := routeRiskFor(path)
	return ok && needsConfirmation(risk)
}

// ui2RepeaterCall runs one internal JSON API call under ctx and returns the status and body.
func (s *Server) ui2RepeaterCall(ctx context.Context, path string, payload any) (int, []byte, http.Header) {
	b, _ := json.Marshal(payload)
	req := newReq(http.MethodPost, path).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(b)))
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes(), rec.Header()
}

// ---- handlers --------------------------------------------------------------------------------

// handleUI2Repeater serves GET /ui2/repeater: the tab strip, the active tab's editor and its
// response pane. Query state (all read-only): tab, h (history index), hop (redirect hop to
// show), view_resp (raw|pretty), diff (1 highlights changes against the previous send), q (tab
// search). POST is the legacy single-form send.
func (s *Server) handleUI2Repeater(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.handleUI2RepeaterSend(w, r)
		return
	}
	q := r.URL.Query()
	tabID, _ := strconv.Atoi(q.Get("tab"))
	st := ui2RepeaterQuery{Hist: -1}
	if h, err := strconv.Atoi(q.Get("h")); err == nil {
		st.Hist = h
	}
	st.Hop, _ = strconv.Atoi(q.Get("hop"))
	st.Raw = q.Get("view_resp") == "raw"
	st.Diff = q.Get("diff") == "1"
	st.Search = q.Get("q")
	ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", s.renderUI2Repeater(tabID, st, "", nil))
}

// handleUI2RepeaterSend serves POST /ui2/repeater/send: saves the editor into its tab, sends it
// through /api/repeater/send under a cancellable context, and records the answer in the tab's
// history. A post without a tab_id (the Site map draft editor, older forms) opens a new tab.
func (s *Server) handleUI2RepeaterSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	st := s.ui2Repeater()
	st.mu.Lock()
	t, err := st.tabFromForm(r.PostForm)
	if err != nil {
		st.mu.Unlock()
		ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", s.renderUI2Repeater(0, ui2RepeaterQuery{Hist: -1}, err.Error(), nil))
		return
	}
	id := t.ID
	payload, perr := ui2RepeaterSendPayload(t)
	if perr == nil && ui2RepeaterGated("/api/repeater/send") {
		perr = errors.New("refused: /api/repeater/send now requires a confirmation this page cannot mint - send from the console")
	}
	if perr != nil {
		t.LastError = perr.Error()
		st.mu.Unlock()
		s.ui2RepeaterRespond(w, r, id, "")
		return
	}
	if t.cancel != nil {
		t.cancel()
	}
	ctx, cancel := context.WithCancel(r.Context())
	t.cancel = cancel
	sent := t.Raw
	st.mu.Unlock()

	code, body, _ := s.ui2RepeaterCall(ctx, "/api/repeater/send", payload)
	cancelled := ctx.Err() != nil
	cancel()

	st.mu.Lock()
	if t, _ = st.find(id); t != nil {
		t.cancel = nil
		t.LastError = ""
		var result map[string]any
		switch {
		case code == http.StatusOK && json.Unmarshal(body, &result) == nil:
			t.record(ui2RepeaterEntry{SentAt: time.Now(), Request: sent, Result: result})
		case cancelled:
			t.LastError = "send cancelled"
		default:
			t.LastError = ui2APIErrorText(strings.TrimSpace(string(body)))
		}
	}
	st.mu.Unlock()
	s.ui2RepeaterRespond(w, r, id, "")
}

// handleUI2RepeaterSendGroup serves POST /ui2/repeater/send-group: the active tab's group sent
// through /api/repeater/send-group in one of its three modes, each answer recorded in the tab it
// came from.
func (s *Server) handleUI2RepeaterSendGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	mode := r.PostFormValue("mode")
	switch mode {
	case repeaterGroupSequenceSingleConn, repeaterGroupSequenceSeparateConn, repeaterGroupParallel:
	default:
		s.ui2RepeaterRespond(w, r, 0, "unknown group send mode")
		return
	}
	st := s.ui2Repeater()
	st.mu.Lock()
	t, err := st.tabFromForm(r.PostForm)
	if err != nil {
		st.mu.Unlock()
		s.ui2RepeaterRespond(w, r, 0, err.Error())
		return
	}
	id := t.ID
	if t.Group == 0 || st.group(t.Group) == nil {
		st.mu.Unlock()
		s.ui2RepeaterRespond(w, r, id, "this tab is in no group - add it to a group to send the group")
		return
	}
	var items []map[string]any
	sentByTab := map[string]string{}
	for _, m := range st.tabs {
		if m.Group != t.Group {
			continue
		}
		p, perr := ui2RepeaterSendPayload(m)
		if perr != nil {
			st.mu.Unlock()
			s.ui2RepeaterRespond(w, r, id, fmt.Sprintf("tab %q: %v", m.Name, perr))
			return
		}
		items = append(items, p)
		sentByTab[p["tab_id"].(string)] = m.Raw
	}
	st.mu.Unlock()
	if ui2RepeaterGated("/api/repeater/send-group") {
		s.ui2RepeaterRespond(w, r, id, "refused: /api/repeater/send-group now requires a confirmation this page cannot mint - send from the console")
		return
	}
	code, body, _ := s.ui2RepeaterCall(r.Context(), "/api/repeater/send-group", map[string]any{"mode": mode, "items": items})
	if code != http.StatusOK {
		s.ui2RepeaterRespond(w, r, id, ui2APIErrorText(strings.TrimSpace(string(body))))
		return
	}
	var resp repeaterGroupSendResp
	if err := json.Unmarshal(body, &resp); err != nil {
		s.ui2RepeaterRespond(w, r, id, "unreadable group send answer: "+err.Error())
		return
	}
	gv := &ui2RepeaterGroupResult{Mode: resp.Mode, BatchMs: resp.BatchDurationMs, Shared: resp.SharedConnection, Followed: resp.FollowedRedirects}
	st.mu.Lock()
	for _, it := range resp.Items {
		row := ui2RepeaterGroupRow{Tab: it.TabID, Error: it.Error, Framing: it.Framing, Arrival: it.Arrival}
		tid, _ := strconv.Atoi(strings.TrimPrefix(it.TabID, "ui2-"))
		if m, _ := st.find(tid); m != nil {
			row.Tab = m.Name
			if it.Result != nil {
				var result map[string]any
				if b, err := json.Marshal(it.Result); err == nil && json.Unmarshal(b, &result) == nil {
					m.record(ui2RepeaterEntry{SentAt: time.Now(), Request: sentByTab[it.TabID], Result: result, Group: resp.Mode})
				}
			}
		}
		if it.Result != nil {
			row.Status = it.Result.Status
			row.Exchange = uint64(it.Result.ExchangeID)
			row.HasExchange = true
		}
		gv.Rows = append(gv.Rows, row)
	}
	st.mu.Unlock()
	ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", s.renderUI2Repeater(id, ui2RepeaterQuery{Hist: -1}, "", gv))
}

// handleUI2RepeaterTabs serves POST /ui2/repeater/tabs/{action}: every tab, group and option
// change. Each action first saves the editor that rode along, then acts, then renders the
// workspace with the resulting active tab.
func (s *Server) handleUI2RepeaterTabs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	action := r.PathValue("action")
	switch action {
	case "new", "paste", "select", "save", "rename", "color", "duplicate", "close", "close-others",
		"close-left", "close-right", "reopen", "group-new", "group-move", "group-remove",
		"opts-global", "opts-reset", "cancel", "export":
	default:
		http.Error(w, "unknown Repeater tab action", http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	f := r.PostForm
	st := s.ui2Repeater()
	st.mu.Lock()
	// cancel and export act on an existing tab only; they never create one.
	if action == "cancel" || action == "export" {
		id, _ := strconv.Atoi(f.Get("tab_id"))
		t, _ := st.find(id)
		if t == nil {
			st.mu.Unlock()
			http.Error(w, "no such Repeater tab", http.StatusNotFound)
			return
		}
		if action == "cancel" {
			if t.cancel != nil {
				t.cancel()
			}
			st.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		req := historyExportReq{Tab: t.Name, Target: t.Target, Note: t.Note, Entries: []historyExportEntryReq{}}
		for _, e := range t.History {
			req.Entries = append(req.Entries, ui2RepeaterExportEntry(e))
		}
		st.mu.Unlock()
		code, body, hdr := s.ui2RepeaterCall(r.Context(), "/api/repeater/history-export", req)
		if code != http.StatusOK {
			http.Error(w, strings.TrimSpace(string(body)), code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if cd := hdr.Get("Content-Disposition"); cd != "" {
			w.Header().Set("Content-Disposition", cd)
		} else {
			w.Header().Set("Content-Disposition", `attachment; filename="repeater-history.json"`)
		}
		_, _ = w.Write(body)
		return
	}
	var t *ui2RepeaterTab
	var err error
	// new and paste must not turn the posted editor into a second new tab when it has no id yet.
	if action != "new" && action != "paste" || f.Get("tab_id") != "" {
		t, err = st.tabFromForm(f)
	}
	note := ""
	if err != nil {
		note = err.Error()
	}
	active := 0
	if t != nil {
		active = t.ID
	}
	if err == nil {
		active, note = st.apply(action, t, f, active)
	}
	st.mu.Unlock()
	if action == "save" && r.Header.Get("HX-Request") == "true" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if active > 0 && r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Push-Url", "/ui2/repeater?tab="+strconv.Itoa(active))
	}
	s.ui2RepeaterRespond(w, r, active, note)
}

// apply runs one tab action with st.mu held and returns the tab to show and a refusal note.
func (st *ui2RepeaterStore) apply(action string, t *ui2RepeaterTab, f url.Values, active int) (int, string) {
	idx := -1
	if t != nil {
		_, idx = st.find(t.ID)
	}
	switch action {
	case "new":
		nt := &ui2RepeaterTab{}
		if raw := f.Get("raw"); raw != "" && f.Get("editor") != "1" {
			// A stand-alone draft (repeater.html) opened as a tab without sending.
			nt.Raw, nt.Target = raw, strings.TrimSpace(f.Get("target"))
		} else if t != nil {
			nt.Target = t.Target
			nt.Raw = "GET / HTTP/1.1\r\nHost: " + ui2RepeaterAuthority(t.Target, t.Raw) + "\r\nAccept: */*\r\n\r\n"
		}
		created, err := st.add(nt)
		if err != nil {
			return active, err.Error()
		}
		return created.ID, ""
	case "paste":
		target, raw, err := ui2RepeaterRequestFromURL(f.Get("url"), f.Get("scheme"))
		if err != nil {
			return active, err.Error()
		}
		created, aerr := st.add(&ui2RepeaterTab{Target: target, Raw: raw})
		if aerr != nil {
			return active, aerr.Error()
		}
		return created.ID, ""
	case "select":
		id, _ := strconv.Atoi(f.Get("select"))
		if sel, _ := st.find(id); sel != nil {
			return sel.ID, ""
		}
		return active, "that tab is closed"
	case "save":
		return active, ""
	case "rename":
		name := strings.TrimSpace(f.Get("name"))
		if name == "" {
			return active, "a tab name cannot be empty"
		}
		if len(name) > 120 {
			name = name[:120]
		}
		t.Name = name
	case "color":
		c := f.Get("color")
		if c != "" && !ui2RepeaterValidColour(c) {
			return active, "unknown colour"
		}
		if gid, _ := strconv.Atoi(f.Get("group")); gid > 0 {
			if g := st.group(gid); g != nil {
				g.Color = c
				return active, ""
			}
		}
		t.Color = c
	case "duplicate":
		cp := &ui2RepeaterTab{Name: t.Name + " (copy)", Color: t.Color, Note: t.Note, Group: t.Group,
			Target: t.Target, SNI: t.SNI, Raw: t.Raw, FromExchange: t.FromExchange, Opts: t.Opts}
		created, err := st.add(cp)
		if err != nil {
			return active, err.Error()
		}
		// Place the copy right after its original.
		st.tabs = append(st.tabs[:len(st.tabs)-1], nil)
		copy(st.tabs[idx+2:], st.tabs[idx+1:])
		st.tabs[idx+1] = created
		return created.ID, ""
	case "close", "close-others", "close-left", "close-right":
		ids := map[int]bool{}
		for i, x := range st.tabs {
			switch {
			case action == "close" && i == idx,
				action == "close-others" && i != idx,
				action == "close-left" && i < idx,
				action == "close-right" && i > idx:
				ids[x.ID] = true
			}
		}
		st.close(ids)
		if action == "close" {
			switch {
			case len(st.tabs) == 0:
				return 0, ""
			case idx < len(st.tabs):
				return st.tabs[idx].ID, ""
			default:
				return st.tabs[len(st.tabs)-1].ID, ""
			}
		}
	case "reopen":
		if len(st.closed) == 0 {
			return active, "no closed tab to reopen"
		}
		if len(st.tabs) >= ui2RepeaterMaxTabs {
			return active, fmt.Sprintf("refused: Repeater holds at most %d tabs - close one first", ui2RepeaterMaxTabs)
		}
		re := st.closed[len(st.closed)-1]
		st.closed = st.closed[:len(st.closed)-1]
		if st.group(re.Group) == nil {
			re.Group = 0
		}
		st.tabs = append(st.tabs, re)
		return re.ID, ""
	case "group-new":
		name := strings.TrimSpace(f.Get("group_name"))
		if name == "" {
			name = "Group " + strconv.Itoa(st.nextGroup)
		}
		c := f.Get("group_color")
		if c != "" && !ui2RepeaterValidColour(c) {
			c = ""
		}
		g := &ui2RepeaterGroup{ID: st.nextGroup, Name: name, Color: c}
		st.nextGroup++
		st.groups = append(st.groups, g)
		t.Group = g.ID
	case "group-move":
		gid, _ := strconv.Atoi(f.Get("group"))
		if st.group(gid) == nil {
			return active, "that group no longer exists"
		}
		t.Group = gid
	case "group-remove":
		gid := t.Group
		t.Group = 0
		st.dropEmptyGroup(gid)
	case "opts-global":
		t.Opts.Override = false
	case "opts-reset":
		t.Opts = ui2RepeaterDefaultOpts()
		t.Opts.Override = true
	}
	return active, ""
}

func (st *ui2RepeaterStore) dropEmptyGroup(gid int) {
	for _, t := range st.tabs {
		if t.Group == gid {
			return
		}
	}
	kept := st.groups[:0]
	for _, g := range st.groups {
		if g.ID != gid {
			kept = append(kept, g)
		}
	}
	st.groups = kept
}

func ui2RepeaterValidColour(c string) bool {
	for _, x := range ui2RepeaterColours {
		if x == c {
			return true
		}
	}
	return false
}

// ui2RepeaterExportEntry maps one history entry onto the export API's id-based entry.
func ui2RepeaterExportEntry(e ui2RepeaterEntry) historyExportEntryReq {
	id := func(k string) *uint64 {
		f, ok := e.Result[k].(float64)
		if !ok || f < 0 {
			return nil
		}
		v := uint64(f)
		return &v
	}
	out := historyExportEntryReq{RequestMsgID: id("request_msg_id"), ResponseMsgID: id("response_msg_id"), Kind: "http",
		SentAt: e.SentAt.UTC().Format(time.RFC3339)}
	if ex := id("exchange_id"); ex != nil {
		v := core.ExchangeID(*ex)
		out.ExchangeID = &v
	}
	return out
}

// ui2RepeaterAuthority is the Host a fresh request for a tab names: the target's authority, or
// the request's own Host.
func ui2RepeaterAuthority(target, raw string) string {
	a := target
	if a == "" {
		a = ui2HostFromRequest(raw)
	}
	if i := strings.Index(a, "://"); i >= 0 {
		a = a[i+3:]
	}
	if a == "" {
		return "example.com"
	}
	return a
}

// ui2RepeaterRequestFromURL is "Paste host / URL as request": a host, host:port or http(s) URL
// becomes a target and a minimal GET. scheme picks http or https for a bare host.
func ui2RepeaterRequestFromURL(input, scheme string) (string, string, error) {
	in := strings.TrimSpace(input)
	if in == "" {
		return "", "", errors.New("paste a host or URL first")
	}
	proto := "https"
	if scheme == "http" {
		proto = "http"
	}
	if i := strings.Index(in, "://"); i >= 0 {
		switch strings.ToLower(in[:i]) {
		case "http":
			proto = "http"
		case "https":
			proto = "https"
		default:
			return "", "", fmt.Errorf("refused: %q is not an http or https URL", in[:i]+"://")
		}
		in = in[i+3:]
	}
	hostPort, path := in, "/"
	if j := strings.IndexAny(in, "/?"); j >= 0 {
		hostPort, path = in[:j], in[j:]
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}
	if hostPort == "" || strings.ContainsAny(hostPort, " \t\r\n@") {
		return "", "", fmt.Errorf("refused: %q does not name a host", input)
	}
	if strings.ContainsAny(path, " \r\n") {
		return "", "", errors.New("refused: the URL path contains whitespace")
	}
	raw := "GET " + path + " HTTP/1.1\r\nHost: " + hostPort + "\r\nAccept: */*\r\n\r\n"
	return proto + "://" + hostPort, raw, nil
}

// ui2RepeaterRespond renders the workspace with tab id active, answering an htmx swap with the
// fragment.
func (s *Server) ui2RepeaterRespond(w http.ResponseWriter, r *http.Request, id int, note string) {
	ui2Fragment(w, r, "burpsy /ui2/ — Repeater", "repeater", s.renderUI2Repeater(id, ui2RepeaterQuery{Hist: -1}, note, nil))
}

// ---- rendering -------------------------------------------------------------------------------

// ui2RepeaterQuery is the GET view state: which history entry and redirect hop to show, raw or
// pretty, and whether to highlight changes against the previous send.
type ui2RepeaterQuery struct {
	Hist   int // -1 is the latest send
	Hop    int // 0 is the response to the request as written; n is followed hop n
	Raw    bool
	Diff   bool
	Search string
}

type ui2RepeaterTabLink struct {
	ID      int
	Name    string
	Color   string
	Target  string
	Active  bool
	HistLen int
}

type ui2RepeaterGroupView struct {
	ID    int
	Name  string
	Color string
	Tabs  []ui2RepeaterTabLink
}

type ui2RepeaterGroupRow struct {
	Tab         string
	Status      int
	Exchange    uint64
	HasExchange bool
	Error       string
	Framing     string
	Arrival     int
}

type ui2RepeaterGroupResult struct {
	Mode     string
	BatchMs  uint64
	Shared   string
	Followed bool
	Rows     []ui2RepeaterGroupRow
}

type ui2RepeaterHopView struct {
	N        int
	From     string
	Status   int
	Location string
	To       string
	Followed bool
	Reason   string
	Protocol string
	Bytes    int
	Selected bool
}

type ui2RepeaterRedirectView struct {
	Mode        string
	Sent        int
	Complete    bool
	FinalStatus int
	Error       string
	Hops        []ui2RepeaterHopView
}

type ui2RepeaterDiffSeg struct {
	Kind string // same | add | del
	Text string
}

type ui2RepInspectorRow struct{ Name, Value string }

type ui2RepInspectorSection struct {
	Title string
	Rows  []ui2RepInspectorRow
	More  int // rows over the display bound
}

type ui2RepeaterRespView struct {
	TabID         int
	Hist          int
	Status        int
	DurationMs    int64
	ExchangeID    uint64
	HasExchange   bool
	H2Conn        string
	Unpacked      string
	UnpackError   string
	Binary        bool
	GroupMode     string
	SentAt        string
	Raw           bool
	Pane          ui2PaneView
	Redirects     *ui2RepeaterRedirectView
	Hop           int
	HopRequest    *ui2PaneView
	Diff          bool
	DiffAvailable bool
	DiffIdentical bool
	DiffNote      string
	DiffSegs      []ui2RepeaterDiffSeg
	ReqInspector  []ui2RepInspectorSection
	RespInspector []ui2RepInspectorSection
}

type ui2RepeaterTabView struct {
	ID         int
	Virtual    bool
	Name       string
	Color      string
	OwnColor   string
	Note       string
	Target     string
	SNI        string
	Raw        string
	EditorSafe bool
	FromEx     string
	GroupID    int
	GroupName  string
	GroupSize  int
	Opts       ui2RepeaterOpts
	LastError  string
	Sending    bool
	HistLen    int
	HistPos    int // 1-based position of the shown entry, 0 with no history
	Prev       int // history index of the previous entry, -1 none
	Next       int
	Index      int // position in the strip
	Last       bool
	TabCount   int
	Resp       *ui2RepeaterRespView
}

type ui2RepeaterView struct {
	Groups      []ui2RepeaterGroupView
	Ungrouped   []ui2RepeaterTabLink
	AllGroups   []ui2RepeaterGroup
	Colours     []string
	Search      string
	TabCount    int
	Shown       int
	Closed      int
	Tab         ui2RepeaterTabView
	Note        string
	GroupResult *ui2RepeaterGroupResult
	Protocols   [][2]string
	Redirects   [][2]string
	GroupModes  [][2]string
}

func ui2RepeaterTabColour(t *ui2RepeaterTab, st *ui2RepeaterStore) string {
	if t.Color != "" {
		return t.Color
	}
	if g := st.group(t.Group); g != nil {
		return g.Color
	}
	return ""
}

// ui2RepeaterMatches is tab search: every word of q in the tab's name or target.
func ui2RepeaterMatches(t *ui2RepeaterTab, q string) bool {
	hay := strings.ToLower(t.Name + "\n" + t.Target)
	for _, w := range strings.Fields(strings.ToLower(q)) {
		if !strings.Contains(hay, w) {
			return false
		}
	}
	return true
}

// renderUI2Repeater builds the workspace with tab id active (the first tab when id is unknown).
func (s *Server) renderUI2Repeater(id int, q ui2RepeaterQuery, note string, gr *ui2RepeaterGroupResult) templateHTML {
	st := s.ui2Repeater()
	st.mu.Lock()
	v := ui2RepeaterView{Search: q.Search, Note: note, GroupResult: gr, Colours: ui2RepeaterColours,
		TabCount: len(st.tabs), Closed: len(st.closed),
		Protocols:  [][2]string{{"auto", "Auto (ALPN)"}, {"http1", "HTTP/1.1"}, {"http2", "HTTP/2"}},
		Redirects:  [][2]string{{"", "Standing policy"}, {"never", "Never"}, {"on_site", "On-site only"}, {"in_scope", "In-scope only"}, {"always", "Always"}},
		GroupModes: [][2]string{{repeaterGroupSequenceSingleConn, "Send group in sequence (single connection)"}, {repeaterGroupSequenceSeparateConn, "Send group in sequence (separate connections)"}, {repeaterGroupParallel, "Send group in parallel"}},
	}
	t, idx := st.find(id)
	if t == nil && len(st.tabs) > 0 {
		t, idx = st.tabs[0], 0
	}
	for _, g := range st.groups {
		v.AllGroups = append(v.AllGroups, *g)
		v.Groups = append(v.Groups, ui2RepeaterGroupView{ID: g.ID, Name: g.Name, Color: g.Color})
	}
	for _, x := range st.tabs {
		if !ui2RepeaterMatches(x, q.Search) {
			continue
		}
		v.Shown++
		link := ui2RepeaterTabLink{ID: x.ID, Name: x.Name, Color: ui2RepeaterTabColour(x, st), Target: x.Target,
			Active: t != nil && x.ID == t.ID, HistLen: len(x.History)}
		placed := false
		for i := range v.Groups {
			if v.Groups[i].ID == x.Group {
				v.Groups[i].Tabs = append(v.Groups[i].Tabs, link)
				placed = true
			}
		}
		if !placed {
			v.Ungrouped = append(v.Ungrouped, link)
		}
	}
	var hist []ui2RepeaterEntry
	if t == nil {
		v.Tab = ui2RepeaterTabView{Virtual: true, Name: "1", Opts: ui2RepeaterDefaultOpts(), Prev: -1, Next: -1, Last: true}
		v.Tab.Raw, v.Tab.FromEx = s.ui2RepeaterLatestDraft()
	} else {
		v.Tab = ui2RepeaterTabView{ID: t.ID, Name: t.Name, Color: ui2RepeaterTabColour(t, st), OwnColor: t.Color,
			Note: t.Note, Target: t.Target, SNI: t.SNI, Raw: t.Raw, GroupID: t.Group, Opts: t.Opts,
			LastError: t.LastError, Sending: t.cancel != nil, HistLen: len(t.History), Prev: -1, Next: -1,
			Index: idx, Last: idx == len(st.tabs)-1, TabCount: len(st.tabs)}
		if t.FromExchange != nil {
			v.Tab.FromEx = strconv.FormatUint(*t.FromExchange, 10)
		}
		if g := st.group(t.Group); g != nil {
			v.Tab.GroupName = g.Name
			for _, x := range st.tabs {
				if x.Group == g.ID {
					v.Tab.GroupSize++
				}
			}
		}
		hist = append(hist, t.History...)
	}
	st.mu.Unlock()

	if n := len(hist); n > 0 {
		h := q.Hist
		if h < 0 || h >= n {
			h = n - 1
		}
		v.Tab.HistPos = h + 1
		if h > 0 {
			v.Tab.Prev = h - 1
		}
		if h < n-1 {
			v.Tab.Next = h + 1
			// An older entry is shown: its request is what the editor holds (Burp's back/forward).
			v.Tab.Raw = hist[h].Request
		}
		var prev *ui2RepeaterEntry
		if h > 0 {
			prev = &hist[h-1]
		}
		v.Tab.Resp = s.ui2RepeaterResp(v.Tab.ID, h, hist[h], prev, q)
	}
	v.Tab.EditorSafe = ui2TextareaSafe([]byte(v.Tab.Raw))
	return ui2Exec("repeater_workspace.html", v)
}

// ui2RepeaterLatestDraft is the virtual first tab's draft: the latest captured request.
func (s *Server) ui2RepeaterLatestDraft() (string, string) {
	exs := s.store.Exchanges()
	if len(exs) == 0 {
		return "", ""
	}
	ex := exs[len(exs)-1]
	if ex.Request == nil {
		return "", ""
	}
	msg, err := s.store.Get(*ex.Request)
	if err != nil || !ui2TextareaSafe(msg.Raw()) {
		return "", ""
	}
	return string(msg.Raw()), strconv.FormatUint(uint64(ex.ID), 10)
}

func ui2RepeaterString(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func ui2RepeaterNum(m map[string]any, k string) (float64, bool) {
	f, ok := m[k].(float64)
	return f, ok
}

func (s *Server) ui2RepeaterResp(tabID, h int, e ui2RepeaterEntry, prev *ui2RepeaterEntry, q ui2RepeaterQuery) *ui2RepeaterRespView {
	res := e.Result
	rv := &ui2RepeaterRespView{TabID: tabID, Hist: h, Raw: q.Raw, GroupMode: e.Group,
		SentAt: e.SentAt.Format("15:04:05"), H2Conn: ui2RepeaterString(res, "h2_connection"),
		UnpackError: ui2RepeaterString(res, "unpack_error"), Binary: ui2RepeaterString(res, "response_body_base64") != ""}
	if f, ok := ui2RepeaterNum(res, "status"); ok {
		rv.Status = int(f)
	}
	if f, ok := ui2RepeaterNum(res, "duration_ms"); ok {
		rv.DurationMs = int64(f)
	}
	if f, ok := ui2RepeaterNum(res, "exchange_id"); ok && f >= 0 {
		rv.ExchangeID, rv.HasExchange = uint64(f), true
	}
	response := ui2RepeaterResponseText(res)
	if ui2RepeaterString(res, "response_unpacked") != "" {
		rv.Unpacked = ui2RepeaterString(res, "unpacked_from")
		if rv.Unpacked == "" {
			rv.Unpacked = "compressed"
		}
	}
	shown := response
	if red, ok := res["redirects"].(map[string]any); ok {
		rv.Redirects = &ui2RepeaterRedirectView{Mode: ui2RepeaterString(red, "mode"), Error: ui2RepeaterString(red, "error")}
		if f, ok := ui2RepeaterNum(red, "sent"); ok {
			rv.Redirects.Sent = int(f)
		}
		if f, ok := ui2RepeaterNum(red, "final_status"); ok {
			rv.Redirects.FinalStatus = int(f)
		}
		rv.Redirects.Complete, _ = red["complete"].(bool)
		hops, _ := red["hops"].([]any)
		for i, raw := range hops {
			hm, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			hv := ui2RepeaterHopView{N: i + 1, From: ui2RepeaterString(hm, "from"), Location: ui2RepeaterString(hm, "location"),
				To: ui2RepeaterString(hm, "to"), Reason: ui2RepeaterString(hm, "reason"), Protocol: ui2RepeaterString(hm, "protocol")}
			hv.Followed, _ = hm["followed"].(bool)
			if f, ok := ui2RepeaterNum(hm, "status"); ok {
				hv.Status = int(f)
			}
			hopResp := ui2RepeaterString(hm, "response")
			hv.Bytes = len(hopResp)
			if q.Hop == hv.N && hv.Followed && hopResp != "" {
				hv.Selected = true
				shown = hopResp
				pane := renderMessagePane(ui2RepeaterString(hm, "request"), true, !q.Raw)
				rv.HopRequest = &pane
				rv.Hop = hv.N
			}
			rv.Redirects.Hops = append(rv.Redirects.Hops, hv)
		}
	}
	rv.Pane = renderMessagePane(shown, false, !q.Raw)
	rv.ReqInspector = ui2RepeaterInspect(e.Request, true)
	rv.RespInspector = ui2RepeaterInspect(shown, false)
	if prev != nil {
		rv.DiffAvailable = true
		if q.Diff && rv.HopRequest == nil {
			rv.Diff = true
			s.ui2RepeaterDiff(rv, ui2RepeaterResponseText(prev.Result), response)
		}
	}
	return rv
}

// ui2RepeaterResponseText is the response as the pane shows it: unpacked when the send
// unpacked it (display only - the stored bytes are what arrived).
func ui2RepeaterResponseText(res map[string]any) string {
	if u := ui2RepeaterString(res, "response_unpacked"); u != "" {
		return u
	}
	return ui2RepeaterString(res, "response")
}

// ui2RepeaterDiff highlights what changed against the previous send, through /api/tools/compare.
func (s *Server) ui2RepeaterDiff(rv *ui2RepeaterRespView, prev, cur string) {
	a, b := strings.ToValidUTF8(prev, "�"), strings.ToValidUTF8(cur, "�")
	result, errText := s.ui2APIResult(http.MethodPost, "/api/tools/compare", map[string]string{"a": a, "b": b})
	if errText != "" {
		rv.DiffNote = "change highlighting unavailable: " + ui2APIErrorText(errText)
		return
	}
	m, _ := result.(map[string]any)
	if id, _ := m["identical"].(bool); id {
		rv.DiffIdentical = true
		return
	}
	ops, _ := m["ops"].([]any)
	segs, repaired := ui2CompareSegs(a, b, ops)
	for _, sg := range segs {
		kind := "same"
		switch sg.prefix {
		case "- ":
			kind = "del"
		case "+ ":
			kind = "add"
		}
		rv.DiffSegs = append(rv.DiffSegs, ui2RepeaterDiffSeg{Kind: kind, Text: sg.text})
	}
	if t, _ := m["truncated"].(bool); t {
		rv.DiffNote = "the diff engine hit its limit - a coarse replace is shown, not a full alignment"
	}
	if repaired {
		rv.DiffNote = strings.TrimSpace(rv.DiffNote + " corrupt diff ops were repaired for display")
	}
}

const ui2InspectorMaxRows = 200

// ui2RepeaterInspect is the Inspector: a message broken into its request/status line, query
// and body parameters, cookies and headers. Display only, read from the text the pane shows.
func ui2RepeaterInspect(raw string, isRequest bool) []ui2RepInspectorSection {
	if raw == "" {
		return nil
	}
	head, _, body := splitHTTPMessage(raw)
	lines := strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n")
	var out []ui2RepInspectorSection
	add := func(sec *ui2RepInspectorSection, name, value string) {
		if len(sec.Rows) >= ui2InspectorMaxRows {
			sec.More++
			return
		}
		sec.Rows = append(sec.Rows, ui2RepInspectorRow{Name: name, Value: value})
	}
	params := func(title, s string) {
		sec := ui2RepInspectorSection{Title: title}
		for _, kv := range strings.Split(s, "&") {
			if kv == "" {
				continue
			}
			k, val, _ := strings.Cut(kv, "=")
			if dk, err := url.QueryUnescape(k); err == nil {
				k = dk
			}
			if dv, err := url.QueryUnescape(val); err == nil {
				val = dv
			}
			add(&sec, k, val)
		}
		if len(sec.Rows) > 0 {
			out = append(out, sec)
		}
	}
	first := strings.Fields(lines[0])
	line := ui2RepInspectorSection{Title: "Request line"}
	labels := []string{"Method", "Path", "Version"}
	if !isRequest {
		line.Title = "Status line"
		labels = []string{"Version", "Status", "Reason"}
	}
	for i, l := range labels {
		val := ""
		switch {
		case !isRequest && i == 2 && len(first) > 2:
			val = strings.Join(first[2:], " ")
		case i < len(first):
			val = first[i]
		}
		add(&line, l, val)
	}
	out = append(out, line)
	if isRequest && len(first) > 1 {
		if _, qs, ok := strings.Cut(first[1], "?"); ok {
			params("Query parameters", qs)
		}
	}
	hdrs := ui2RepInspectorSection{Title: "Headers"}
	cookies := ui2RepInspectorSection{Title: "Cookies"}
	if !isRequest {
		cookies.Title = "Set-Cookie"
	}
	form := false
	for _, l := range lines[1:] {
		name, val, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		add(&hdrs, name, val)
		switch {
		case isRequest && strings.EqualFold(name, "cookie"):
			for _, c := range strings.Split(val, ";") {
				ck, cv, _ := strings.Cut(strings.TrimSpace(c), "=")
				if ck != "" {
					add(&cookies, ck, cv)
				}
			}
		case !isRequest && strings.EqualFold(name, "set-cookie"):
			ck, cv, _ := strings.Cut(val, "=")
			add(&cookies, strings.TrimSpace(ck), cv)
		case isRequest && strings.EqualFold(name, "content-type"):
			form = strings.Contains(strings.ToLower(val), "application/x-www-form-urlencoded")
		}
	}
	if len(cookies.Rows) > 0 {
		out = append(out, cookies)
	}
	if form {
		params("Body parameters", strings.TrimSpace(body))
	}
	return append(out, hdrs)
}
