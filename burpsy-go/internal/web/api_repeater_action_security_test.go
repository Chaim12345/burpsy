package web

// The 1944 remediation pins (integrator disposition 2026-10-25): a custom-action script is an
// untrusted principal, so (1) GET serves the DEFINITION only - never script-derived output or
// error text; script-derived output comes only from the gated POST run; (2) installs are bounded
// globally (count and persisted bytes); (3) VM inputs are capped pre-run and outputs pre-commit;
// (4) writes have one owner and runs never starve other tabs.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// secretTarget serves a response whose Set-Cookie carries the canary the pins look for.
func secretTarget(t *testing.T, secret string) (host string, port uint16, closeFn func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session="+secret)
		_, _ = fmt.Fprint(w, "hello")
	}))
	authority := strings.TrimPrefix(srv.URL, "http://")
	name, portStr, _ := strings.Cut(authority, ":")
	var p int
	_, _ = fmt.Sscanf(portStr, "%d", &p)
	return name, uint16(p), srv.Close
}

func sendFromTab(t *testing.T, s *Server, tabID, host string, port uint16) {
	t.Helper()
	raw := fmt.Sprintf("GET /form HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port)
	if _, err := s.sendOneRepeaterRequest(context.Background(), repeaterSendSpec{
		TabID: tabID, Host: host, Port: port, Raw: []byte(raw), AsWritten: raw,
	}); err != nil {
		t.Fatalf("repeater send: %v", err)
	}
}

// THE output-authority pin: a script copies the response's Set-Cookie into its log, its store and
// its rewritten draft, then throws it. GET must carry NONE of it - metadata only. The gated POST
// run response carries all of it (the negative control: the data exists and is served where the
// gate is). The MCP read path serves this same GET body, so pinning the HTTP body pins both.
func TestRepeaterActionGetNeverServesScriptDerivedOutput(t *testing.T) {
	const secret = "SESSION-CANARY-1944"
	host, port, closeFn := secretTarget(t, secret)
	defer closeFn()
	s := newTestServer()

	script := `var c = response.headers["Set-Cookie"] || response.headers["set-cookie"];
		log("cookie " + c);
		store.set("c", c);
		request.headers["X-Copied"] = c;
		throw new Error("leaked " + c);`
	rec := putJSON(t, s, "/api/repeater/tabs/tab-s/action", map[string]any{"script": script, "auto_run": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("install: %d %s", rec.Code, rec.Body)
	}
	sendFromTab(t, s, "tab-s", host, port)

	rec = get(t, s, "/api/repeater/tabs/tab-s/action")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Errorf("GET serves the secret the script derived: %s", body)
	}
	// (Field-name substring checks are meaningless here: the definition carries the script SOURCE,
	// which names log/store by nature. The pins are the secret's absence and no recorded run.)
	if strings.Contains(body, `"last_run":`) {
		t.Errorf("GET serves the recorded run; it must be the definition only: %s", body)
	}
	var def struct {
		Action struct {
			Script  string `json:"script"`
			AutoRun bool   `json:"auto_run"`
		} `json:"action"`
		Runs      uint64 `json:"runs"`
		HasError  bool   `json:"has_error"`
		ErrorKind string `json:"error_kind"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &def); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if def.Action.Script != script || !def.Action.AutoRun {
		t.Errorf("the definition did not round-trip: %+v", def.Action)
	}
	if def.Runs != 1 || !def.HasError || def.ErrorKind != "exception" {
		t.Errorf("metadata wrong: runs=%d has_error=%v error_kind=%q (want 1/true/exception)", def.Runs, def.HasError, def.ErrorKind)
	}

	// Negative control: the gated POST returns exactly what GET withholds.
	rec = postJSON(t, s, "/api/repeater/tabs/tab-s/action/run", map[string]any{"mode": "last"})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST run mode=last: %d %s", rec.Code, rec.Body)
	}
	gated := rec.Body.String()
	if !strings.Contains(gated, secret) {
		t.Errorf("the gated run response must carry the run's output; got %s", gated)
	}
	var run struct {
		Log   []string `json:"log"`
		Error string   `json:"error"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	// The script threw, so by the all-or-nothing store rule its store.set never committed; the
	// secret it copied is in the log and the error text, which the gated run serves.
	if !strings.Contains(run.Error, "leaked") || len(run.Log) == 0 || !strings.Contains(run.Log[0], secret) {
		t.Errorf("the gated run response is incomplete: %+v", run)
	}
}

// Installs are bounded globally: 32 actions at most, 1 MiB of persisted script at most. Over the
// count is 409; over the bytes is 413; each pinned at N and N+1. A gated installer can still squat
// IDs that are not live tabs - bounded, visible, deletable, and documented as a stated residual.
func TestRepeaterActionInstallCaps(t *testing.T) {
	s := newTestServer()
	for i := 0; i < 32; i++ {
		rec := putJSON(t, s, fmt.Sprintf("/api/repeater/tabs/cap-%d/action", i), map[string]any{"script": `log("x")`})
		if rec.Code != http.StatusOK {
			t.Fatalf("install %d of 32: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := putJSON(t, s, "/api/repeater/tabs/cap-32/action", map[string]any{"script": `log("x")`}); rec.Code != http.StatusConflict {
		t.Errorf("the 33rd action answered %d, want 409: %s", rec.Code, rec.Body)
	}
	// Replacing an existing action never trips the count.
	if rec := putJSON(t, s, "/api/repeater/tabs/cap-0/action", map[string]any{"script": `log("y")`}); rec.Code != http.StatusOK {
		t.Errorf("replacing within the cap answered %d", rec.Code)
	}

	// Bytes: a script is capped at 64 KiB, so sixteen maximal scripts are exactly 1 MiB; the
	// seventeenth is over.
	s2 := newTestServer()
	big := "//" + strings.Repeat("x", 65534)
	for i := 0; i < 16; i++ {
		rec := putJSON(t, s2, fmt.Sprintf("/api/repeater/tabs/big-%d/action", i), map[string]any{"script": big})
		if rec.Code != http.StatusOK {
			t.Fatalf("install big %d of 16: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := putJSON(t, s2, "/api/repeater/tabs/big-16/action", map[string]any{"script": big}); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("past 1 MiB of persisted script answered %d, want 413: %s", rec.Code, rec.Body)
	}
	// A same-size replacement is net-zero and fits.
	big2 := "//" + strings.Repeat("y", 65534)
	if rec := putJSON(t, s2, "/api/repeater/tabs/big-0/action", map[string]any{"script": big2}); rec.Code != http.StatusOK {
		t.Errorf("a net-zero replacement answered %d: %s", rec.Code, rec.Body)
	}
}

// What the VM sees is capped BEFORE the run: a body over 1 MiB arrives truncated and the run
// record says so.
func TestRepeaterActionInputCaps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("y", 2*1024*1024)))
	}))
	defer srv.Close()
	authority := strings.TrimPrefix(srv.URL, "http://")
	name, portStr, _ := strings.Cut(authority, ":")
	var p int
	_, _ = fmt.Sscanf(portStr, "%d", &p)

	s := newTestServer()
	rec := putJSON(t, s, "/api/repeater/tabs/tab-i/action", map[string]any{
		"script": `log("req=" + request.body.length + " resp=" + response.body.length)`, "auto_run": true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("install: %d %s", rec.Code, rec.Body)
	}
	bigBody := strings.Repeat("z", 2*1024*1024)
	raw := fmt.Sprintf("POST /up HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: %d\r\n\r\n%s", name, p, len(bigBody), bigBody)
	if _, err := s.sendOneRepeaterRequest(context.Background(), repeaterSendSpec{
		TabID: "tab-i", Host: name, Port: uint16(p), Raw: []byte(raw), AsWritten: raw,
	}); err != nil {
		t.Fatalf("send: %v", err)
	}
	rec = postJSON(t, s, "/api/repeater/tabs/tab-i/action/run", map[string]any{"mode": "last"})
	if rec.Code != http.StatusOK {
		t.Fatalf("read run: %d", rec.Code)
	}
	var run struct {
		Log            []string `json:"log"`
		InputTruncated []string `json:"input_truncated"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(run.Log) == 0 || run.Log[0] != "req=1048576 resp=1048576" {
		t.Errorf("the VM must see each body capped at 1 MiB: %v", run.Log)
	}
	if fmt.Sprint(run.InputTruncated) != "[request_body response_body]" {
		t.Errorf("the truncation flags must name both bodies: %v", run.InputTruncated)
	}
}

// The rendered draft is capped at COMMIT time: 1 MiB kept, flagged. This bounds what is stored and
// served - it is not and is never labelled an in-VM allocation bound.
func TestRepeaterActionDraftCap(t *testing.T) {
	host, port, closeFn := repeaterActionTarget(t, "hello")
	defer closeFn()
	s := newTestServer()
	rec := putJSON(t, s, "/api/repeater/tabs/tab-d/action", map[string]any{
		"script": `request.body = "x".repeat(2097152)`,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("install: %d %s", rec.Code, rec.Body)
	}
	sendFromTab(t, s, "tab-d", host, port)
	rec = postJSON(t, s, "/api/repeater/tabs/tab-d/action/run", map[string]any{})
	if rec.Code != http.StatusOK {
		t.Fatalf("run: %d", rec.Code)
	}
	var run struct {
		Request        string `json:"request"`
		DraftTruncated bool   `json:"draft_truncated"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(run.Request) > 1048576+256 {
		t.Errorf("the committed draft is %d bytes; the commit cap is 1 MiB", len(run.Request))
	}
	if !run.DraftTruncated {
		t.Error("a capped draft must be flagged draft_truncated")
	}
}

// The error kind is classified: exception, timeout, store_full. GET carries the kind, never the text.
func TestRepeaterActionErrorKinds(t *testing.T) {
	host, port, closeFn := repeaterActionTarget(t, "hello")
	defer closeFn()
	s := newTestServer()
	kinds := []struct {
		name   string
		script string
		want   string
	}{
		{"exception", `throw new Error("boom")`, "exception"},
		{"timeout", `while (true) {}`, "timeout"},
		{"store_full", `for (var i = 0; i < 200; i++) { store.set("k" + i, "v"); }`, "store_full"},
	}
	for _, tc := range kinds {
		t.Run(tc.name, func(t *testing.T) {
			rec := putJSON(t, s, "/api/repeater/tabs/ek-"+tc.name+"/action", map[string]any{"script": tc.script})
			if rec.Code != http.StatusOK {
				t.Fatalf("install: %d %s", rec.Code, rec.Body)
			}
			sendFromTab(t, s, "ek-"+tc.name, host, port)
			rec = postJSON(t, s, "/api/repeater/tabs/ek-"+tc.name+"/action/run", map[string]any{})
			if rec.Code != http.StatusOK {
				t.Fatalf("a failed run is still a run: %d", rec.Code)
			}
			var run struct {
				Error     string `json:"error"`
				ErrorKind string `json:"error_kind"`
			}
			if err := decodeJSON(rec.Body.Bytes(), &run); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if run.Error == "" || run.ErrorKind != tc.want {
				t.Errorf("run error_kind = %q (error %q), want %q", run.ErrorKind, run.Error, tc.want)
			}
			rec = get(t, s, "/api/repeater/tabs/ek-"+tc.name+"/action")
			var def struct {
				HasError  bool   `json:"has_error"`
				ErrorKind string `json:"error_kind"`
			}
			if err := decodeJSON(rec.Body.Bytes(), &def); err != nil {
				t.Fatalf("decode def: %v", err)
			}
			if !def.HasError || def.ErrorKind != tc.want {
				t.Errorf("GET error kind = %q/%v, want %q", def.ErrorKind, def.HasError, tc.want)
			}
			if strings.Contains(rec.Body.String(), run.Error) && run.Error != "" {
				t.Errorf("GET serves the error text %q; it serves the kind only", run.Error)
			}
		})
	}
}

// Run output comes only from the gated POST: mode "last" reads the recorded run (409 when there is
// none), the default executes fresh.
func TestRepeaterActionRunModes(t *testing.T) {
	host, port, closeFn := repeaterActionTarget(t, "hello")
	defer closeFn()
	s := newTestServer()
	if rec := putJSON(t, s, "/api/repeater/tabs/tab-m/action", map[string]any{
		"script": `store.set("n", (parseInt(store.get("n") || "0") + 1).toString()); log("n=" + store.get("n"))`,
	}); rec.Code != http.StatusOK {
		t.Fatalf("install: %d %s", rec.Code, rec.Body)
	}
	if rec := postJSON(t, s, "/api/repeater/tabs/tab-m/action/run", map[string]any{"mode": "last"}); rec.Code != http.StatusConflict {
		t.Errorf("mode=last before any run answered %d, want 409", rec.Code)
	}
	sendFromTab(t, s, "tab-m", host, port)
	rec := postJSON(t, s, "/api/repeater/tabs/tab-m/action/run", map[string]any{})
	var run struct {
		Log []string `json:"log"`
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("fresh run: %d", rec.Code)
	}
	_ = decodeJSON(rec.Body.Bytes(), &run)
	if len(run.Log) == 0 || run.Log[0] != "n=1" {
		t.Fatalf("the fresh run: %v", run.Log)
	}
	rec = postJSON(t, s, "/api/repeater/tabs/tab-m/action/run", map[string]any{"mode": "last"})
	if rec.Code != http.StatusOK {
		t.Fatalf("mode=last: %d", rec.Code)
	}
	var last struct {
		Log   []string          `json:"log"`
		Store map[string]string `json:"store"`
	}
	_ = decodeJSON(rec.Body.Bytes(), &last)
	if len(last.Log) == 0 || last.Log[0] != "n=1" || last.Store["n"] != "1" {
		t.Errorf("mode=last must replay the recorded run, got %v / %v", last.Log, last.Store)
	}
	if rec := postJSON(t, s, "/api/repeater/tabs/tab-m/action/run", map[string]any{"mode": "bogus"}); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown mode answered %d, want 400", rec.Code)
	}
}

// One owner for writes: concurrent PUTs leave memory and the DB holding the SAME script.
func TestRepeaterActionConcurrentWritesConverge(t *testing.T) {
	p, err := persist.Open(filepath.Join(t.TempDir(), "p.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer p.Close()
	s := newTestServer().WithPersist(p)

	const writers = 8
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				putJSON(t, s, "/api/repeater/tabs/tab-c/action", map[string]any{
					"script": fmt.Sprintf(`log("writer-%d-round-%d")`, i, j),
				})
			}
		}(i)
	}
	wg.Wait()
	rec := get(t, s, "/api/repeater/tabs/tab-c/action")
	var def struct {
		Action struct {
			Script string `json:"script"`
		} `json:"action"`
	}
	if err := decodeJSON(rec.Body.Bytes(), &def); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rows, err := p.LoadRepeaterActions()
	if err != nil || len(rows) != 1 {
		t.Fatalf("the DB holds %d rows (err %v); one tab, one row", len(rows), err)
	}
	if rows[0].Script != def.Action.Script {
		t.Errorf("memory and DB diverged: memory %q, DB %q", def.Action.Script, rows[0].Script)
	}
}

// No starvation: while one tab's run spins, another tab's reads and a DELETE of the running tab
// answer at once. A run whose action is deleted or replaced mid-flight is discarded, never committed.
func TestRepeaterActionNeverStarvesOtherTabs(t *testing.T) {
	host, port, closeFn := repeaterActionTarget(t, "hello")
	defer closeFn()
	s := newTestServer()
	spin := `var t0 = Date.now(); while (Date.now() - t0 < 450) {}`
	if rec := putJSON(t, s, "/api/repeater/tabs/tab-a/action", map[string]any{"script": spin}); rec.Code != http.StatusOK {
		t.Fatalf("install A: %d", rec.Code)
	}
	if rec := putJSON(t, s, "/api/repeater/tabs/tab-b/action", map[string]any{"script": `log("b")`}); rec.Code != http.StatusOK {
		t.Fatalf("install B: %d", rec.Code)
	}
	sendFromTab(t, s, "tab-a", host, port)
	sendFromTab(t, s, "tab-b", host, port)

	runDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		runDone <- postJSON(t, s, "/api/repeater/tabs/tab-a/action/run", map[string]any{})
	}()
	time.Sleep(80 * time.Millisecond) // the run is in flight

	start := time.Now()
	if rec := get(t, s, "/api/repeater/tabs/tab-b/action"); rec.Code != http.StatusOK {
		t.Errorf("tab B's GET during tab A's run: %d", rec.Code)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Errorf("tab B waited %v behind tab A's run; a run holds no lock another tab needs", d)
	}

	start = time.Now()
	if rec := deleteReq(t, s, "/api/repeater/tabs/tab-a/action"); rec.Code != http.StatusOK {
		t.Errorf("DELETE during the run: %d", rec.Code)
	}
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Errorf("the DELETE waited %v for the run; removal must not queue behind execution", d)
	}
	rec := <-runDone
	if rec.Code != http.StatusConflict {
		t.Errorf("a run whose action vanished mid-flight answered %d, want 409 (its result is discarded): %s", rec.Code, rec.Body)
	}
	if rec := get(t, s, "/api/repeater/tabs/tab-a/action"); rec.Code != http.StatusNotFound {
		t.Errorf("the deleted action is still there: %d", rec.Code)
	}
}

// Two runs on the SAME tab serialize: the store they race on ends at 2, and each run's log shows
// the count it actually committed - no lost update.
func TestRepeaterActionSameTabRunsSerialize(t *testing.T) {
	host, port, closeFn := repeaterActionTarget(t, "hello")
	defer closeFn()
	s := newTestServer()
	if rec := putJSON(t, s, "/api/repeater/tabs/tab-1/action", map[string]any{
		"script": `store.set("n", (parseInt(store.get("n") || "0") + 1).toString()); log("n=" + store.get("n"))`,
	}); rec.Code != http.StatusOK {
		t.Fatalf("install: %d", rec.Code)
	}
	sendFromTab(t, s, "tab-1", host, port)
	logs := make([]string, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := postJSON(t, s, "/api/repeater/tabs/tab-1/action/run", map[string]any{})
			var run struct {
				Log []string `json:"log"`
			}
			if rec.Code == http.StatusOK {
				_ = decodeJSON(rec.Body.Bytes(), &run)
				if len(run.Log) > 0 {
					logs[i] = run.Log[0]
				}
			}
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{logs[0]: true, logs[1]: true}
	if !seen["n=1"] || !seen["n=2"] {
		t.Errorf("two racing runs logged %v; serialized commits log n=1 and n=2", logs)
	}
}

// The confirmation gate: every mutating verb on the route refuses an unconfirmed call (428) and
// proceeds on a confirmed one. GET, a read, is ungated - and harmless because it is definition-only.
func TestRepeaterActionIsConfirmationGated(t *testing.T) {
	s := newTestServer()
	body := `{"script":"log(1)","auto_run":true}`
	if rec := guarded(t, s, http.MethodPut, "/api/repeater/tabs/tab-g/action", body); rec.Code != http.StatusPreconditionRequired {
		t.Errorf("unconfirmed PUT = %d, want 428", rec.Code)
	}
	if rec := guarded(t, s, http.MethodDelete, "/api/repeater/tabs/tab-g/action", ""); rec.Code != http.StatusPreconditionRequired {
		t.Errorf("unconfirmed DELETE = %d, want 428", rec.Code)
	}
	if rec := guarded(t, s, http.MethodPost, "/api/repeater/tabs/tab-g/action/run", `{}`); rec.Code != http.StatusPreconditionRequired {
		t.Errorf("unconfirmed POST run = %d, want 428", rec.Code)
	}
	if rec := guarded(t, s, http.MethodGet, "/api/repeater/tabs/tab-g/action", ""); rec.Code == http.StatusPreconditionRequired {
		t.Error("GET is a read; the gate must not hold it for confirmation")
	}
	// Confirmed, the install proceeds - the token is bound to this exact call.
	token := confirm(t, s, http.MethodPut, "/api/repeater/tabs/tab-g/action", body)
	if rec := spendOn(t, s, token, http.MethodPut, "/api/repeater/tabs/tab-g/action", body); rec.Code != http.StatusOK {
		t.Errorf("confirmed PUT = %d, want 200: %s", rec.Code, rec.Body)
	}
}

// The PUT body is capped BEFORE decode: over 128 KiB is 413 without the decoder or the script
// check running (a valid-JSON over-cap body would otherwise reach the 64 KiB script cap as a 400).
func TestRepeaterActionPutBodyIsCappedBeforeDecode(t *testing.T) {
	s := newTestServer()
	big := strings.Repeat("x", 200*1024)
	rec := putJSON(t, s, "/api/repeater/tabs/tab-p/action", map[string]any{"script": big})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a 200 KiB action body answered %d, want 413 before any decode: %s", rec.Code, rec.Body)
	}
	// N: at the cap the body decodes (and then fails on the script's own 64 KiB limit - a 400,
	// proving the decode ran).
	under := strings.Repeat("x", 120*1024)
	rec = putJSON(t, s, "/api/repeater/tabs/tab-p/action", map[string]any{"script": under})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a 120 KiB body holding an over-limit script answered %d, want the 400 script refusal", rec.Code)
	}
}

// A corrupt saved action never blocks the others: it is skipped at restore (logged and counted)
// while the valid rows come back.
func TestRepeaterActionRestoreSkipsACorruptRow(t *testing.T) {
	p, err := persist.Open(filepath.Join(t.TempDir(), "p.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer p.Close()
	if err := p.SaveRepeaterAction("good-tab", `log("x")`, true); err != nil {
		t.Fatalf("save good: %v", err)
	}
	if err := p.SaveRepeaterAction("bad-tab", `this is not javascript(`, false); err != nil {
		t.Fatalf("save bad: %v", err)
	}
	s := newTestServer().WithPersist(p)
	if rec := get(t, s, "/api/repeater/tabs/good-tab/action"); rec.Code != http.StatusOK {
		t.Errorf("the valid action did not restore: %d", rec.Code)
	}
	if rec := get(t, s, "/api/repeater/tabs/bad-tab/action"); rec.Code != http.StatusNotFound {
		t.Errorf("a script the sandbox refuses must not come back to life: %d", rec.Code)
	}
}
