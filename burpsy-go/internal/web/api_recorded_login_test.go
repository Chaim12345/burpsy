package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/session"
)

// The script the operator pastes: Burp's Login Recorder shape (see internal/session's own sample),
// pointed at whatever app the test serves.
func burpScriptFor(base string) string {
	return `[
 {"name":"Login Recorder for Burp Suite","version":"2.4.1","eventType":"start","iframes":[],"windows":[],"tabs":[]},
 {"eventType":"goto","url":"` + base + `/login","fromAddressBar":true},
 {"eventType":"typing","tagName":"INPUT","id":"username","name":"user","elementType":"text","typedValue":"alice","xPath":"/html/body/form/input[1]","frameId":0},
 {"eventType":"typing","tagName":"INPUT","id":"password","name":"pass","elementType":"password","typedValue":"hunter2","xPath":"/html/body/form/input[2]","frameId":0},
 {"eventType":"keyboard","key":"Enter"},
 {"eventType":"typing","tagName":"INPUT","id":"otp","name":"otp","elementType":"text","typedValue":"492039","xPath":"/html/body/form/input","frameId":0},
 {"eventType":"scroll","scrollX":0,"scrollY":10},
 {"eventType":"click","tagName":"BUTTON","id":"verify","xPath":"/html/body/form/button","frameId":0}
]`
}

const testTOTPSecret = "JBSWY3DPEHPK3PXP"

func TestTheRecordedLoginLibraryImportsRedactsAndRoundTripsSecrets(t *testing.T) {
	s := newTestServer()

	// Empty is [] on the wire, never null.
	rec := get(t, s, "/api/crawl/logins")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"logins":[]`) || !strings.Contains(rec.Body.String(), `"empty":true`) {
		t.Fatalf("empty library: %d %s", rec.Code, rec.Body.String())
	}

	rec = postJSON(t, s, "/api/crawl/logins", map[string]any{"label": "alice", "script": burpScriptFor("https://app.example")})
	if rec.Code != 200 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "hunter2") {
		t.Fatalf("the import reply carries the password: %s", body)
	}
	var saved struct {
		Login  session.RecordedLoginView `json:"login"`
		Format string                    `json:"format"`
		Notes  []session.ImportNote      `json:"notes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Format != "burp-login-recorder" || len(saved.Login.Steps) != 6 || saved.Login.ID == "" {
		t.Fatalf("saved: %+v", saved)
	}
	var sawScrollNote, sawTOTPHint bool
	for _, n := range saved.Notes {
		sawScrollNote = sawScrollNote || (n.EventType == "scroll" && n.Outcome == "dropped")
		sawTOTPHint = sawTOTPHint || strings.Contains(n.Detail, "TOTP")
	}
	if !sawScrollNote || !sawTOTPHint {
		t.Fatalf("notes must name the dropped scroll and suggest the TOTP step: %+v", saved.Notes)
	}

	// The editor turns the recorded code into a TOTP step and adds the status check Burp requires
	// with one — sending the view straight back, password redacted, as "See as JSON" would.
	steps := saved.Login.Steps
	steps[4] = session.LoginStepView{Kind: session.StepTOTP, Selector: "#otp",
		TOTP: &session.TOTPView{Period: 30, Digits: 6}}
	raw, _ := json.Marshal(steps)
	var edited []map[string]any
	_ = json.Unmarshal(raw, &edited)
	edited[4]["totp"] = map[string]any{"secret": testTOTPSecret, "period": 30, "digits": 6}

	rec = postJSON(t, s, "/api/crawl/logins", map[string]any{"id": saved.Login.ID, "label": "alice", "steps": edited})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "status check is required") {
		t.Fatalf("a TOTP sequence without a status check must be refused: %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, s, "/api/crawl/logins", map[string]any{"id": saved.Login.ID, "label": "alice", "steps": edited,
		"status_check": map[string]any{"url": "https://app.example/home", "text": "Welcome alice"}})
	if rec.Code != 200 {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body.String())
	}
	for _, secret := range []string{"hunter2", testTOTPSecret} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the edit reply carries %q", secret)
		}
	}
	// The stored sequence kept the password it never sent back, and took the new TOTP secret.
	stored, _ := s.recordedLoginStore().get(saved.Login.ID)
	if stored.Steps[2].Value != "hunter2" || !stored.Steps[2].Secret || stored.Steps[4].TOTP.Secret != testTOTPSecret ||
		stored.Steps[4].TOTP.Algorithm != session.TOTPSHA1 {
		t.Fatalf("stored after the round trip: %+v / %+v", stored.Steps[2], stored.Steps[4].TOTP)
	}
	rec = get(t, s, "/api/crawl/logins")
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), testTOTPSecret) {
		t.Fatalf("the GET carries a secret: %s", rec.Body.String())
	}

	if rec := deleteReq(t, s, "/api/crawl/logins?id=nope"); rec.Code != 404 {
		t.Fatalf("delete unknown: %d", rec.Code)
	}
	if rec := deleteReq(t, s, "/api/crawl/logins?id="+saved.Login.ID); rec.Code != 200 {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTheReplayAndTheCrawlRefuseWhatTheyCannotRun(t *testing.T) {
	s := newTestServer()
	if rec := postJSON(t, s, "/api/crawl/logins/replay", map[string]any{"id": "nope"}); rec.Code != 404 {
		t.Fatalf("replay of an unknown id: %d", rec.Code)
	}
	rec := postJSON(t, s, "/api/crawl/logins", map[string]any{"label": "a", "script": burpScriptFor("https://app.example")})
	var saved struct {
		Login session.RecordedLoginView `json:"login"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &saved)
	// No scope declared: refused before any browser starts.
	rec = postJSON(t, s, "/api/crawl/logins/replay", map[string]any{"id": saved.Login.ID})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "declared scope") {
		t.Fatalf("replay with an empty scope: %d %s", rec.Code, rec.Body.String())
	}
	before := len(s.tasks.Snapshot())
	for _, body := range []map[string]any{
		{"seeds": []string{"https://app.example/"}, "recorded_login": "nope"},
		{"seeds": []string{"https://app.example/"}, "recorded_login": saved.Login.ID},
	} {
		rec = postJSON(t, s, "/api/crawl", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("crawl %v: %d %s", body, rec.Code, rec.Body.String())
		}
	}
	if after := len(s.tasks.Snapshot()); after != before {
		t.Fatalf("a refused crawl left %d task row(s)", after-before)
	}
	if s.loginBrowser != nil {
		t.Fatal("a browser was started for a request that was refused")
	}
}

// totpLoginApp is a username+password form, then a TOTP form checked against the real RFC 6238 code,
// then /home, which links to /account. Logged out, every page is the login form.
type totpLoginApp struct {
	srv      *httptest.Server
	mu       sync.Mutex
	sessions map[string]bool
	accounts int
}

func newTOTPLoginApp(t *testing.T) *totpLoginApp {
	app := &totpLoginApp{sessions: map[string]bool{}}
	cfg := session.TOTPConfig{Secret: testTOTPSecret, Period: 30, Digits: 6}
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>" + body + "</body></html>"))
	}
	login := `<form method="post" action="/login"><input id="username" name="user"><input id="password" type="password" name="pass"><button>Sign in</button></form>`
	app.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Method == http.MethodPost && r.FormValue("user") == "alice" && r.FormValue("pass") == "hunter2" {
				http.SetCookie(w, &http.Cookie{Name: "pre", Value: "1", Path: "/"})
				http.Redirect(w, r, "/mfa", http.StatusFound)
				return
			}
			page(w, login)
			return
		case "/mfa":
			if c, err := r.Cookie("pre"); err != nil || c.Value != "1" {
				page(w, login)
				return
			}
			if r.Method == http.MethodPost {
				now, _ := cfg.CodeAt(time.Now())
				prev, _ := cfg.CodeAt(time.Now().Add(-30 * time.Second))
				if code := r.FormValue("otp"); code == now || code == prev {
					tok := session.NewRecordedLoginID()
					app.mu.Lock()
					app.sessions[tok] = true
					app.mu.Unlock()
					http.SetCookie(w, &http.Cookie{Name: "sid", Value: tok, Path: "/", HttpOnly: true})
					http.Redirect(w, r, "/home", http.StatusFound)
					return
				}
				http.Error(w, "bad code", http.StatusForbidden)
				return
			}
			page(w, `<form method="post" action="/mfa"><input id="otp" name="otp"><button id="verify">Verify</button></form>`)
			return
		}
		c, err := r.Cookie("sid")
		app.mu.Lock()
		ok := err == nil && app.sessions[c.Value]
		app.mu.Unlock()
		if !ok {
			page(w, login)
			return
		}
		switch r.URL.Path {
		case "/home":
			page(w, `<h1>Welcome alice</h1><p>dashboard</p><a href="/account">Account</a>`)
		case "/account":
			app.mu.Lock()
			app.accounts++
			app.mu.Unlock()
			page(w, `<table><tr><td>account of alice</td></tr></table>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(app.srv.Close)
	return app
}

func chromeAvailable() bool {
	for _, name := range []string{"chromium", "google-chrome", "google-chrome-stable"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

// saveTOTPLogin imports the script against app and converts its recorded code into a TOTP step.
func saveTOTPLogin(t *testing.T, s *Server, app *totpLoginApp) string {
	t.Helper()
	rec := postJSON(t, s, "/api/crawl/logins", map[string]any{"label": "alice", "script": burpScriptFor(app.srv.URL)})
	var saved struct {
		Login session.RecordedLoginView `json:"login"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil || rec.Code != 200 {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	raw, _ := json.Marshal(saved.Login.Steps)
	var steps []map[string]any
	_ = json.Unmarshal(raw, &steps)
	steps[4] = map[string]any{"kind": "totp", "selector": "#otp", "totp": map[string]any{"secret": testTOTPSecret, "period": 30, "digits": 6}}
	rec = postJSON(t, s, "/api/crawl/logins", map[string]any{"id": saved.Login.ID, "label": "alice", "steps": steps,
		"status_check": map[string]any{"url": app.srv.URL + "/home", "text": "Welcome alice"}})
	if rec.Code != 200 {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body.String())
	}
	return saved.Login.ID
}

// The real thing, through the real routes: Replay logs in with the stored password and a live TOTP
// code, and a crawl launched with the sequence reaches the page only a logged-in user can see.
func TestARecordedTOTPLoginReplaysAndAuthenticatesACrawlThroughTheRoutes(t *testing.T) {
	if !chromeAvailable() {
		t.Skip("no Chrome on PATH")
	}
	app := newTOTPLoginApp(t)
	s := newTestServer()
	t.Cleanup(s.CloseLoginBrowser)
	u, _ := url.Parse(app.srv.URL)
	s.scope.AddInclude(u.Hostname())
	id := saveTOTPLogin(t, s, app)

	rec := postJSON(t, s, "/api/crawl/logins/replay", map[string]any{"id": id})
	if rec.Code != 200 {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), testTOTPSecret) {
		t.Fatal("the replay reply carries a secret")
	}
	var replay struct {
		Replay struct {
			Succeeded bool              `json:"succeeded"`
			Reason    string            `json:"reason"`
			Steps     []json.RawMessage `json:"steps"`
			Blocked   []string          `json:"blocked"`
			Check     *struct {
				Found bool `json:"found"`
			} `json:"status_check"`
		} `json:"replay"`
		CookieNames []string `json:"cookie_names"`
		Screenshot  string   `json:"screenshot"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &replay); err != nil {
		t.Fatal(err)
	}
	if !replay.Replay.Succeeded || replay.Replay.Check == nil || !replay.Replay.Check.Found || len(replay.Replay.Steps) != 6 {
		t.Fatalf("replay: %s", rec.Body.String())
	}
	if replay.Replay.Blocked == nil || !strings.HasPrefix(replay.Screenshot, "data:image/jpeg;base64,") {
		t.Fatalf("blocked must be [] and a screenshot present: %v %.40s", replay.Replay.Blocked, replay.Screenshot)
	}
	if strings.Join(replay.CookieNames, ",") != "pre,sid" {
		t.Fatalf("cookie names: %v", replay.CookieNames)
	}

	// The crawl, with its own runner: one login before the first fetch.
	rec = postJSON(t, s, "/api/crawl", map[string]any{"seeds": []string{app.srv.URL + "/home"}, "recorded_login": id,
		"max_requests": 20, "login_page_pattern": `type="password"`})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("crawl: %d %s", rec.Code, rec.Body.String())
	}
	var start crawlStartResp
	_ = json.Unmarshal(rec.Body.Bytes(), &start)
	// The live crawl view (burpsy-react-ui-1l3x) says the crawl is logging in while the replay runs,
	// and takes no frame of the login page.
	sawLoggingIn := false
	for i := 0; i < 400 && !sawLoggingIn; i++ {
		lv := get(t, s, "/api/crawl/live?task="+jsonNumber(start.TaskID))
		var view struct {
			Phase     string          `json:"phase"`
			Frame     json.RawMessage `json:"frame"`
			FrameNote string          `json:"frame_note"`
		}
		_ = json.Unmarshal(lv.Body.Bytes(), &view)
		if view.Phase == "logging-in" {
			sawLoggingIn = true
			if string(view.Frame) != "null" {
				t.Fatalf("a frame was taken while logging in: %s", lv.Body.String())
			}
		}
		if view.Phase == "fetching" || view.Phase == "finished" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawLoggingIn {
		t.Fatal("the live view never reported the crawl logging in")
	}
	deadline := time.Now().Add(90 * time.Second)
	var run map[string]any
	for time.Now().Before(deadline) {
		rec = get(t, s, "/api/crawl?task="+strings.TrimSpace(jsonNumber(start.TaskID)))
		_ = json.Unmarshal(rec.Body.Bytes(), &run)
		if run["state"] != "running" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	report, _ := run["report"].(map[string]any)
	login, _ := report["login"].(map[string]any)
	if login == nil || login["authenticated"] != true || login["method"] != "recorded" {
		t.Fatalf("login block: %v (state %v)", login, run["state"])
	}
	if n, _ := login["requests_with_session"].(float64); n < 2 {
		t.Fatalf("requests_with_session: %v", login["requests_with_session"])
	}
	app.mu.Lock()
	accounts := app.accounts
	app.mu.Unlock()
	if accounts == 0 {
		t.Fatal("the crawl never reached /account, which only a logged-in user is linked to")
	}
	// The rendered-DOM audit renders logged out; on an authenticated crawl it is declined, named.
	if ra, _ := report["rendered_audit"].(map[string]any); ra == nil || !strings.Contains(ra["declined"].(string), "recorded login") {
		t.Fatalf("rendered_audit on an authenticated crawl: %v", report["rendered_audit"])
	}
	stops, _ := report["limits"].(map[string]any)["stops"].([]any)
	for _, stop := range stops {
		if stop == "login-failed" {
			t.Fatal("an authenticated crawl carries login-failed")
		}
	}
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), testTOTPSecret) {
		t.Fatal("the crawl run carries a secret")
	}
}

func jsonNumber(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// A re-login inside one TOTP period would type the code the server just accepted; the runner waits
// for the next time step instead (RFC 6238 §5.2; Burp's Zxf1.ZX).
func TestASecondTOTPCodeInOneRunWaitsForTheNextTimeStep(t *testing.T) {
	r := newBrowserLoginRunner(&session.RecordedLogin{}, nil)
	cfg := session.TOTPConfig{Secret: testTOTPSecret, Period: 1, Digits: 6}
	ctx := t.Context()
	first, err := r.totpCode(ctx, 0, cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstCounter := r.lastCounter[0]
	second, err := r.totpCode(ctx, 0, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.lastCounter[0] <= firstCounter {
		t.Fatalf("the second code reused time step %d", firstCounter)
	}
	want, _ := cfg.CodeForCounter(r.lastCounter[0])
	if second != want || (first == second && r.lastCounter[0] == firstCounter) {
		t.Fatalf("second code %s, want %s for step %d", second, want, r.lastCounter[0])
	}
}
