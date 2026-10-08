package web

// Recorded login sequences (burpsy-react-ui-xhtk): the /api/crawl/logins library, Burp's "Replay"
// at /api/crawl/logins/replay, and the BrowserLogin a crawl replays them through.
//
// # The one rule this file keeps
//
// No secret comes back out. A typed password and a TOTP secret live on session.LoginStep, which this
// file stores and persists; everything it SERIALISES is a session.RecordedLoginView, which has no
// field a secret could land in. The replay's own result carries step descriptions that were redacted
// before the browser saw them, cookie NAMES and never values, and a screenshot of the final page.
//
// # Scope
//
// A replay is a browser following whatever the login page tells it to — SSO redirects included — so
// it runs in a domexec.Session gated by this engagement's scope on every request it sends, and it is
// refused outright while the scope is empty: in this build an empty scope means "everything", and a
// browser told "everything" by default is the one thing the guardrail forbids.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- store --------------------------------------------------------------------------------------

type recordedLoginStore struct {
	mu     sync.Mutex
	logins []*session.RecordedLogin
	// restoreNote is why the persisted library could not be read back, reported by the GET.
	restoreNote string
}

func (s *Server) recordedLoginStore() *recordedLoginStore {
	s.recordedLoginsOnce.Do(func() { s.recordedLogins = &recordedLoginStore{} })
	return s.recordedLogins
}

// restoreRecordedLogins REPLACES the library with the project's own, on startup and on every
// in-console project switch (WithPersist runs for both). Replace, not merge: a switch that kept the
// outgoing library would put one client's passwords and TOTP secrets in front of the next client's
// engagement, and the next save would write them into that client's project file.
func (s *Server) restoreRecordedLogins(p *persist.Store) {
	st := s.recordedLoginStore()
	var logins []*session.RecordedLogin
	note := ""
	raw, err := p.LoadRecordedLogins()
	switch {
	case err != nil:
		note = "the saved recorded logins could not be read: " + err.Error()
	case raw != nil:
		if err := json.Unmarshal(raw, &logins); err != nil {
			logins = nil
			note = "the saved recorded logins could not be decoded: " + err.Error()
		}
	}
	st.mu.Lock()
	st.logins = logins
	st.restoreNote = note
	st.mu.Unlock()
}

// get returns a deep-enough copy of one sequence: its own Steps slice and TOTP configs, so a replay
// running from it cannot see an edit made while it runs.
func (st *recordedLoginStore) get(id string) (*session.RecordedLogin, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, l := range st.logins {
		if l.ID == id {
			return cloneLogin(l), true
		}
	}
	return nil, false
}

func cloneLogin(l *session.RecordedLogin) *session.RecordedLogin {
	c := *l
	c.Steps = make([]session.LoginStep, len(l.Steps))
	for i, s := range l.Steps {
		c.Steps[i] = s
		if s.TOTP != nil {
			t := *s.TOTP
			c.Steps[i].TOTP = &t
		}
	}
	if l.StatusCheck != nil {
		sc := *l.StatusCheck
		c.StatusCheck = &sc
	}
	return &c
}

func (st *recordedLoginStore) views() []session.RecordedLoginView {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]session.RecordedLoginView, 0, len(st.logins))
	for _, l := range st.logins {
		out = append(out, l.View())
	}
	return out
}

// put adds or replaces by id.
func (st *recordedLoginStore) put(l *session.RecordedLogin) (replaced bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, have := range st.logins {
		if have.ID == l.ID {
			st.logins[i] = l
			return true
		}
	}
	st.logins = append(st.logins, l)
	return false
}

func (st *recordedLoginStore) remove(id string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i, l := range st.logins {
		if l.ID == id {
			st.logins = append(st.logins[:i], st.logins[i+1:]...)
			return true
		}
	}
	return false
}

func (s *Server) persistRecordedLogins() error {
	if s.persist == nil {
		return nil
	}
	st := s.recordedLoginStore()
	st.mu.Lock()
	raw, err := json.Marshal(st.logins)
	st.mu.Unlock()
	if err != nil {
		return err
	}
	return s.persist.SaveRecordedLogins(raw)
}

// ---- GET / POST / DELETE /api/crawl/logins -----------------------------------------------------

type recordedLoginsResponse struct {
	Logins []session.RecordedLoginView `json:"logins"`
	Empty  bool                        `json:"empty"`
	// StepKinds and Keys are what the editor may offer, read from the engine.
	StepKinds []session.LoginStepKind `json:"step_kinds"`
	Keys      []string                `json:"keys"`
	// RestoreNote says the saved library could not be read back, rather than showing it as empty.
	RestoreNote string `json:"restore_note,omitempty"`
}

type recordedLoginSaveReq struct {
	// ID names an existing sequence to replace; empty creates one.
	ID    string `json:"id"`
	Label string `json:"label"`
	// Script is a pasted recorder script (Burp's Login Recorder, Chrome's Recorder, or burpsy's own
	// JSON). When set, Steps is ignored and the reply carries the import notes.
	Script      string                 `json:"script"`
	Steps       []session.IncomingStep `json:"steps"`
	StatusCheck *session.StatusCheck   `json:"status_check"`
}

type recordedLoginSaveResponse struct {
	Login    session.RecordedLoginView `json:"login"`
	Replaced bool                      `json:"replaced"`
	// Format is the script format an import read, "" for an edit.
	Format string `json:"format"`
	// Notes are the recorded events that did not become a step as recorded — never silently dropped.
	Notes []session.ImportNote `json:"notes"`
}

func (s *Server) handleRecordedLogins(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		st := s.recordedLoginStore()
		views := st.views()
		kinds := session.LoginStepKinds()
		writeJSON(w, http.StatusOK, recordedLoginsResponse{
			Logins: views, Empty: len(views) == 0, StepKinds: kinds, Keys: session.ReplayKeyNames(),
			RestoreNote: st.restoreNote,
		})
	case http.MethodPost:
		s.saveRecordedLogin(w, r)
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "an id is required", http.StatusBadRequest)
			return
		}
		if !s.recordedLoginStore().remove(id) {
			http.Error(w, "no recorded login with that id", http.StatusNotFound)
			return
		}
		if err := s.persistRecordedLogins(); err != nil {
			http.Error(w, "removed, but the project could not be saved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"removed": id})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) saveRecordedLogin(w http.ResponseWriter, r *http.Request) {
	var req recordedLoginSaveReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	st := s.recordedLoginStore()
	var existing *session.RecordedLogin
	if req.ID != "" {
		have, ok := st.get(req.ID)
		if !ok {
			http.Error(w, "no recorded login with that id", http.StatusNotFound)
			return
		}
		existing = have
	}
	now := time.Now().UTC()
	login := &session.RecordedLogin{
		ID: req.ID, Label: strings.TrimSpace(req.Label), StatusCheck: req.StatusCheck,
		Source: "burpsy", Created: now, Updated: now,
	}
	if existing != nil {
		login.Created = existing.Created
		login.Source = existing.Source
	} else {
		login.ID = session.NewRecordedLoginID()
	}
	resp := recordedLoginSaveResponse{Notes: []session.ImportNote{}}
	if strings.TrimSpace(req.Script) != "" {
		imp, err := session.ImportScript([]byte(req.Script))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		login.Steps = imp.Steps
		login.Source = imp.Format
		if login.Label == "" {
			login.Label = imp.Name
		}
		resp.Format, resp.Notes = imp.Format, imp.Notes
	} else {
		var stored []session.LoginStep
		if existing != nil {
			stored = existing.Steps
		}
		steps, err := session.MergeSecrets(req.Steps, stored)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		login.Steps = steps
	}
	for i := range login.Steps {
		if t := login.Steps[i].TOTP; t != nil && t.Algorithm == "" {
			t.Algorithm = session.TOTPSHA1
		}
	}
	if login.StatusCheck != nil && strings.TrimSpace(login.StatusCheck.URL) == "" && strings.TrimSpace(login.StatusCheck.Text) == "" {
		login.StatusCheck = nil
	}
	if err := login.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resp.Replaced = st.put(login)
	if err := s.persistRecordedLogins(); err != nil {
		http.Error(w, "saved for this session, but the project could not be written: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp.Login = login.View()
	writeJSON(w, http.StatusOK, resp)
}

// ---- the scope gate ----------------------------------------------------------------------------

// sessionScopeGate is the engagement scope as a domexec.ScopeGate.
type sessionScopeGate struct{ scope *core.Scope }

func defaultPort(u *url.URL) uint16 {
	if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 && p < 65536 {
		return uint16(p)
	}
	if u.Scheme == "https" {
		return 443
	}
	return 80
}

func (g sessionScopeGate) AllowURL(u *url.URL) error {
	tls := u.Scheme == "https"
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if g.scope.Contains(u.Hostname(), defaultPort(u), path, tls) {
		return nil
	}
	return errors.New("out of scope")
}

func (g sessionScopeGate) AllowAuthority(host string, port uint16, tls bool) error {
	if g.scope.MayContainHost(host, port, tls) {
		return nil
	}
	return errors.New("host out of scope")
}

// errLoginNeedsScope is the refusal for a replay with nothing declared.
var errLoginNeedsScope = errors.New("a recorded login replays in a browser that follows whatever the login page says, " +
	"so it needs a declared scope: add the application (and its identity provider, for SSO) to scope first")

// ---- the browser -------------------------------------------------------------------------------

// loginBrowserFor returns the browser a recorded login replays in: the -dom engine when one is
// configured (one process, one browser), otherwise a headless Chrome this server launches on first
// use and keeps.
func (s *Server) loginBrowserFor(ctx context.Context) (*domexec.Browser, error) {
	if s.scanner != nil && s.scanner.DOMCapabilityConfigured() {
		return s.scanner.BrowserForRender(ctx)
	}
	s.loginBrowserMu.Lock()
	if s.loginBrowser == nil {
		s.loginBrowser = scanner.NewLazyBrowserProvider(domexec.Options{})
	}
	p := s.loginBrowser
	s.loginBrowserMu.Unlock()
	b, err := p.Browser(ctx)
	if err != nil {
		return nil, fmt.Errorf("a recorded login replays in a headless browser and none could be started: %w", err)
	}
	return b, nil
}

// CloseLoginBrowser stops the browser loginBrowserFor launched, if it ever did. The -dom engine is
// not this file's to close.
func (s *Server) CloseLoginBrowser() {
	s.loginBrowserMu.Lock()
	p := s.loginBrowser
	s.loginBrowser = nil
	s.loginBrowserMu.Unlock()
	if p != nil {
		_ = p.Close()
	}
}

// openLoginSession is the scope check, the browser and the isolated session, in that order.
func (s *Server) openLoginSession(ctx context.Context) (*domexec.Session, error) {
	if s.scope == nil || (s.scope.Empty() && !s.scope.AllowAll()) {
		return nil, errLoginNeedsScope
	}
	b, err := s.loginBrowserFor(ctx)
	if err != nil {
		return nil, err
	}
	sess, err := b.NewSession(sessionScopeGate{scope: s.scope})
	if err != nil {
		return nil, err
	}
	// The operator's one TLS-verification setting (Settings → Network) governs this leg too: a
	// staging host the crawl's own sender may reach with verification off is one the login may reach.
	sess.IgnoreCertificateErrors(s.sender != nil && !s.sender.Network().TLS.Verify)
	return sess, nil
}

// ---- the replay, as a crawler.BrowserLogin -----------------------------------------------------

// browserLoginRunner replays one recorded login in one session. It is the crawl's BrowserLogin and
// the replay route's driver, so "Replay" in the console and a crawl's login are the same code.
type browserLoginRunner struct {
	login *session.RecordedLogin
	sess  *domexec.Session
	// lastCounter is the TOTP time step each TOTP step last typed. A re-login inside the same 30
	// seconds would type the same code, which most servers refuse once it has been accepted (RFC
	// 6238 §5.2); the step waits out the period instead — Burp's Zxf1.ZX.
	mu          sync.Mutex
	lastCounter map[int]uint64
	// last is the most recent replay, for the route's reply.
	last domexec.LoginReplay
}

func newBrowserLoginRunner(l *session.RecordedLogin, sess *domexec.Session) *browserLoginRunner {
	return &browserLoginRunner{login: l, sess: sess, lastCounter: map[int]uint64{}}
}

func (r *browserLoginRunner) Label() string { return r.login.Label }

func (r *browserLoginRunner) actions() []domexec.LoginAction {
	out := make([]domexec.LoginAction, 0, len(r.login.Steps))
	for i, st := range r.login.Steps {
		a := domexec.LoginAction{
			Kind: string(st.Kind), URL: st.URL, Selector: st.Selector, XPath: st.XPath,
			Text: st.Value, Key: st.Key, Wait: time.Duration(st.WaitMS) * time.Millisecond,
			Description: st.Describe(),
		}
		if st.Kind == session.StepTOTP && st.TOTP != nil {
			cfg := *st.TOTP
			idx := i
			a.Code = func(ctx context.Context) (string, error) { return r.totpCode(ctx, idx, cfg) }
		}
		out = append(out, a)
	}
	return out
}

func (r *browserLoginRunner) totpCode(ctx context.Context, idx int, cfg session.TOTPConfig) (string, error) {
	now := time.Now()
	r.mu.Lock()
	last, used := r.lastCounter[idx]
	r.mu.Unlock()
	if used && cfg.Counter(now) <= last {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(cfg.UntilNextPeriod(now) + 50*time.Millisecond):
		}
		now = time.Now()
	}
	code, err := cfg.CodeAt(now)
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	r.lastCounter[idx] = cfg.Counter(now)
	r.mu.Unlock()
	return code, nil
}

func (r *browserLoginRunner) replay(ctx context.Context) domexec.LoginReplay {
	var check *domexec.LoginCheck
	if sc := r.login.StatusCheck; sc != nil {
		check = &domexec.LoginCheck{URL: sc.URL, Text: sc.Text}
	}
	ctx, cancel := context.WithTimeout(ctx, domexec.ReplayTimeout)
	defer cancel()
	rep := r.sess.ReplayLogin(ctx, r.actions(), check)
	r.mu.Lock()
	r.last = rep
	r.mu.Unlock()
	return rep
}

// Login is crawler.BrowserLogin.
func (r *browserLoginRunner) Login(ctx context.Context) crawler.LoginAttempt {
	rep := r.replay(ctx)
	a := crawler.LoginAttempt{Succeeded: rep.Succeeded, Verified: rep.Verified, Reason: rep.Reason, FinalURL: rep.FinalURL, Blocked: rep.Blocked}
	for _, c := range rep.Cookies {
		a.Cookies = append(a.Cookies, crawler.LoginCookie{
			Name: c.Name, Value: c.Value, Domain: c.Domain, HostOnly: !strings.HasPrefix(c.Domain, "."),
			Path: c.Path, Secure: c.Secure, HTTPOnly: c.HTTPOnly,
		})
	}
	return a
}

// ---- POST /api/crawl/logins/replay -------------------------------------------------------------

type recordedLoginReplayResponse struct {
	ID     string              `json:"id"`
	Label  string              `json:"label"`
	Replay domexec.LoginReplay `json:"replay"`
	// CookieNames are the cookies the replay earned, by name only.
	CookieNames []string `json:"cookie_names"`
	// Screenshot is the final page as a data: URL, "" when none could be taken.
	Screenshot string `json:"screenshot"`
}

func (s *Server) handleRecordedLoginReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	login, ok := s.recordedLoginStore().get(strings.TrimSpace(req.ID))
	if !ok {
		http.Error(w, "no recorded login with that id", http.StatusNotFound)
		return
	}
	sess, err := s.openLoginSession(r.Context())
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, errLoginNeedsScope) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	defer sess.Close()
	rep := newBrowserLoginRunner(login, sess).replay(r.Context())
	names := make([]string, 0, len(rep.Cookies))
	for _, c := range rep.Cookies {
		names = append(names, c.Name)
	}
	sort.Strings(names)
	shot := ""
	if len(rep.Screenshot) > 0 {
		shot = "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(rep.Screenshot)
	}
	writeJSON(w, http.StatusOK, recordedLoginReplayResponse{
		ID: login.ID, Label: login.Label, Replay: rep, CookieNames: names, Screenshot: shot,
	})
}
