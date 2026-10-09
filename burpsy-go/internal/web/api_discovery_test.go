package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/extscan"
)

// ---- The content-discovery endpoint --------------------------------------------------------------
//
// internal/extscan wraps ffuf, which is the only content-discovery capability in this tree, and only
// `burpsy extscan` on the command line could reach it. These pin the route behind Burp's "Discover
// content" menu entry, and specifically the three refusals: a target the engagement does not
// authorise, a tool the operator did not allowlist, and a request that names no wordlist. Each of
// those must be a stated refusal rather than a 200 carrying an empty discovery list, because the
// latter reads as "this host has nothing to find".
//
// # Capability skips are counted here too
//
// The live test below actually launches ffuf. A machine without it would otherwise report a green
// package having verified nothing about the tool this route delegates to — a skipped test and a
// passing test look identical in a `go test` summary. So the skip is recorded and
// TestDiscoveryCapabilityWasExercised fails the package unless BURPSY_ALLOW_UNVERIFIED_EXTSCAN=1 says
// the reduced environment is deliberate. Same env var as internal/extscan's own live suite, on
// purpose: "this machine has no external tools" is one fact, not two.

const allowUnverifiedExtscanEnv = "BURPSY_ALLOW_UNVERIFIED_EXTSCAN"

var (
	discoverySkipMu sync.Mutex
	discoverySkips  []string
)

func recordDiscoverySkip(t *testing.T, reason string) {
	t.Helper()
	discoverySkipMu.Lock()
	discoverySkips = append(discoverySkips, fmt.Sprintf("%s (%s)", t.Name(), reason))
	discoverySkipMu.Unlock()
	t.Skip(reason + ": this test is NOT exercised in this run")
}

// discoveryListResp is the GET /api/discovery listing.
type discoveryListResp struct {
	Tool struct {
		Name        string `json:"name"`
		Allowlisted bool   `json:"allowlisted"`
		Available   bool   `json:"available"`
		Reason      string `json:"reason"`
	} `json:"tool"`
	Runs []discoveryRunResp `json:"runs"`
}

// discoveryRunResp mirrors discoveryRun for decoding, with only the fields these tests assert on.
type discoveryRunResp struct {
	TaskID      uint64   `json:"task_id"`
	Target      string   `json:"target"`
	State       string   `json:"state"`
	Outcome     string   `json:"outcome"`
	Looked      bool     `json:"looked"`
	Error       string   `json:"error"`
	Command     []string `json:"command"`
	Discoveries []struct {
		Path   string `json:"path"`
		Status int    `json:"status"`
	} `json:"discoveries"`
	Counts struct {
		Discovered int `json:"discovered"`
		OutOfScope int `json:"out_of_scope"`
		ByStatus   []struct {
			Status int `json:"status"`
			Count  int `json:"count"`
		} `json:"by_status"`
	} `json:"counts"`
	Summary string `json:"summary"`
	// The session fields (burpsy-react-ui-dgbi): one entry per recursion depth
	// that ran, and the echo of what was asked for.
	Levels []struct {
		Level      int `json:"level"`
		Discovered int `json:"discovered"`
		OutOfScope int `json:"out_of_scope"`
		Skipped    int `json:"skipped"`
		Runs       int `json:"runs"`
	} `json:"levels"`
	RecurseDepth int `json:"recurse_depth"`
}

func discoveryList(t *testing.T, s *Server) discoveryListResp {
	t.Helper()
	rec := get(t, s, "/api/discovery")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/discovery: status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var body discoveryListResp
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode discovery listing %q: %v", rec.Body.String(), err)
	}
	return body
}

// waitForDiscovery polls until the run leaves the running state. The sweep is asynchronous by design —
// it outlives the request that started it — so reading the result immediately would assert on a race.
func waitForDiscovery(t *testing.T, s *Server, taskID uint64) discoveryRunResp {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		rec := get(t, s, "/api/discovery?task="+strconv.FormatUint(taskID, 10))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/discovery?task=%d: status = %d (%s)", taskID, rec.Code, rec.Body.String())
		}
		var run discoveryRunResp
		if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
			t.Fatalf("decode discovery run: %v", err)
		}
		if run.State != "running" {
			return run
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("discovery run %d did not finish within the deadline", taskID)
	return discoveryRunResp{}
}

// The refusal the unit exists for: with no -tools allowlist there is no ffuf, and the endpoint says
// which name is missing instead of answering 200 with nothing in it.
func TestDiscoveryWithoutAnAllowlistedFfufIsRefusedByName(t *testing.T) {
	s := newTestServer()
	s.scope.AddInclude("target.test")

	rec := postJSON(t, s, "/api/discovery", map[string]any{
		"target":   "https://target.test/app/",
		"wordlist": "/etc/hostname",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, extscan.ToolFFUF) {
		t.Errorf("the refusal does not name the missing tool: %q", body)
	}
	if !strings.Contains(body, "-tools") {
		t.Errorf("the refusal does not say how to allow it: %q", body)
	}
	// And nothing was registered: a configuration refusal must not leave a task on the dashboard that
	// exists only to fail.
	if runs := discoveryList(t, s).Runs; len(runs) != 0 {
		t.Errorf("a refused sweep registered %d run(s); it must register none", len(runs))
	}
	if n := len(s.tasks.Snapshot()); n != 0 {
		t.Errorf("a refused sweep registered %d task(s)", n)
	}
}

// The empty list must never be the whole answer. A GET with no runs still reports whether this server
// could run a sweep at all — otherwise "nothing found here" and "content discovery is switched off"
// are the same response.
func TestDiscoveryListingSaysWhetherTheToolCouldRunAtAll(t *testing.T) {
	body := discoveryList(t, newTestServer())

	if body.Tool.Name != extscan.ToolFFUF {
		t.Errorf("tool.name = %q, want %q", body.Tool.Name, extscan.ToolFFUF)
	}
	if body.Tool.Allowlisted || body.Tool.Available {
		t.Errorf("tool = %+v; a server with no -tools must claim neither", body.Tool)
	}
	if body.Tool.Reason == "" {
		t.Fatal("an unavailable tool carries no reason, so an empty run list is indistinguishable " +
			"from a target with nothing to discover")
	}
	if body.Runs == nil {
		t.Error("runs decoded as null; the field must serialise as [] so a client cannot confuse an " +
			"absent field with an empty one")
	}
}

// An external tool picks its own paths, so scope is the gate and it is checked before anything is
// launched. A target the engagement does not authorise is refused even though the tool is allowlisted.
func TestDiscoveryRefusesATargetOutsideTheScope(t *testing.T) {
	s := newTestServer().WithExternalTools(map[string]string{extscan.ToolFFUF: "ffuf"})
	s.scope.AddInclude("in-scope.test")

	rec := postJSON(t, s, "/api/discovery", map[string]any{
		"target":   "https://someone-else.test/",
		"wordlist": "/etc/hostname",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not authorised by scope") {
		t.Errorf("the refusal does not explain itself: %q", rec.Body.String())
	}
	if n := len(s.tasks.Snapshot()); n != 0 {
		t.Errorf("an out-of-scope sweep registered %d task(s)", n)
	}
}

// The gate that matters most, and the one a per-request check could not give: scope may authorise the
// base path while a path-scoped exclude carves a hole out of the subtree. ffuf will walk straight into
// it, so the whole run is refused rather than started and hoped about.
func TestDiscoveryRefusesAHostWhoseSubtreeIsOnlyPartlyInScope(t *testing.T) {
	s := newTestServer().WithExternalTools(map[string]string{extscan.ToolFFUF: "ffuf"})
	s.scope.AddInclude("target.test")
	// The exclude has to cover the path extscan invents to ask scope its second question — and not the
	// base path itself, or this would be the plain out-of-scope refusal the test above already covers.
	// core scope rules are path *prefixes*, and "/app/burpsy" is a prefix of the probe extscan appends
	// ("burpsy-extscan-scope-probe") while "/app/" stays authorised. Same construction as
	// extscan's own TestAuthoriseRefusesAPartiallyScopedHost, for the same reason.
	s.scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "target.test", "/app/burpsy"))

	rec := postJSON(t, s, "/api/discovery", map[string]any{
		"target":   "https://target.test/app/",
		"wordlist": "/etc/hostname",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not every path beneath it") {
		t.Errorf("the refusal does not explain why a partly-scoped host is refused outright: %q",
			rec.Body.String())
	}
}

// A request that cannot describe a sweep is a 400 the operator can fix, not a task that fails.
func TestDiscoveryNeedsATargetAndAWordlist(t *testing.T) {
	s := newTestServer().WithExternalTools(map[string]string{extscan.ToolFFUF: "ffuf"})
	s.scope.AddInclude("target.test")

	for _, body := range []map[string]any{
		{"wordlist": "/etc/hostname"},
		{"target": "   ", "wordlist": "/etc/hostname"},
		{"target": "https://target.test/"},
		{"target": "https://target.test/", "wordlist": "  "},
	} {
		rec := postJSON(t, s, "/api/discovery", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %v: status = %d, want 400 (%s)", body, rec.Code, rec.Body.String())
		}
	}
	if n := len(s.tasks.Snapshot()); n != 0 {
		t.Errorf("a malformed request registered %d task(s)", n)
	}
}

// The whole route, against real ffuf: it registers a dashboard task, sweeps the wordlist, reports the
// paths it matched, and — the assertion that carries the honest-counting requirement — counts the ones
// the engagement scope refused rather than letting them vanish into a smaller number.
func TestDiscoveryRunsFfufAndCountsWhatItFoundAndWhatItDropped(t *testing.T) {
	if _, err := exec.LookPath("ffuf"); err != nil {
		recordDiscoverySkip(t, "no ffuf on PATH")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/backup.zip":
			fmt.Fprint(w, "found")
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()
	host := mustHostname(t, target.URL)

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nbackup.zip\nnothing-is-here\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	s := newTestServer().WithExternalTools(map[string]string{extscan.ToolFFUF: "ffuf"})
	s.scope.AddInclude(host)

	rec := postJSON(t, s, "/api/discovery", map[string]any{
		"target":   target.URL + "/",
		"wordlist": wordlist,
		// Matching 200 only keeps the assertion about the two paths that exist. Threads: 1 for the
		// reason extscan's own live test states — ffuf's default of 40 overruns an httptest server's
		// accept backlog on a busy machine, and a refused connection is an error to ffuf rather than a
		// result, so a path that exists silently goes unreported.
		"match_codes": "200",
		"threads":     1,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/discovery: status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID uint64 `json:"task_id"`
		Target string `json:"target"`
		State  string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if start.TaskID == 0 || start.State != "running" {
		t.Fatalf("start response = %+v, want a task id and the running state", start)
	}

	// The sweep appears on the dashboard while it is still running, which is the reason it is registered
	// at all: a run in progress and a run that never started must not look the same.
	found := false
	for _, task := range s.tasks.Snapshot() {
		if task.ID == start.TaskID {
			found = true
			if task.Kind != dash.KindDiscovery {
				t.Errorf("task kind = %q, want %q", task.Kind, dash.KindDiscovery)
			}
		}
	}
	if !found {
		t.Errorf("task %d is not in the registry, so the sweep would never appear on the Dashboard",
			start.TaskID)
	}

	run := waitForDiscovery(t, s, start.TaskID)
	if run.State != "done" || run.Outcome != "completed" || !run.Looked {
		t.Fatalf("run state = %q, outcome = %q, looked = %v, error = %q; want a completed sweep",
			run.State, run.Outcome, run.Looked, run.Error)
	}
	paths := map[string]int{}
	for _, d := range run.Discoveries {
		paths[d.Path] = d.Status
	}
	for _, want := range []string{"/admin", "/backup.zip"} {
		if paths[want] != 200 {
			t.Errorf("ffuf did not report %s as 200 through the endpoint; got %v", want, paths)
		}
	}
	if _, unexpected := paths["/nothing-is-here"]; unexpected {
		t.Errorf("a path the target 404s was reported: %v", paths)
	}
	if run.Counts.Discovered != len(run.Discoveries) {
		t.Errorf("counts.discovered = %d for %d discoveries", run.Counts.Discovered, len(run.Discoveries))
	}
	if len(run.Command) == 0 {
		t.Error("the run carries no argv; a delegated result has to say what was executed")
	}
	if !strings.Contains(run.Summary, "absence of guesses") {
		t.Errorf("summary does not state what an empty result would and would not mean: %q", run.Summary)
	}
}

// The post-run scope re-check, through the endpoint: the requests are already sent by then, but a
// result outside the engagement must not enter the report — and the drop is counted, not silent.
func TestDiscoveryCountsResultsTheScopeRefusedRatherThanHidingThem(t *testing.T) {
	if _, err := exec.LookPath("ffuf"); err != nil {
		recordDiscoverySkip(t, "no ffuf on PATH")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/backup.zip":
			fmt.Fprint(w, "found")
		default:
			http.NotFound(w, r)
		}
	}))
	defer target.Close()
	host := mustHostname(t, target.URL)

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nbackup.zip\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	// The scope authorises the whole subtree — Authorise insists on that — and then a *separate*
	// exclude on the exact path ffuf will find is what the post-run filter catches. This is the shape of
	// an engagement narrowed after a target was chosen.
	s := newTestServer().WithExternalTools(map[string]string{extscan.ToolFFUF: "ffuf"})
	s.scope.AddInclude(host)

	rec := postJSON(t, s, "/api/discovery", map[string]any{
		"target":      target.URL + "/",
		"wordlist":    wordlist,
		"match_codes": "200",
		"threads":     1,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/discovery: status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID uint64 `json:"task_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &start)

	// Narrow the scope while the sweep is in flight. The filter runs after the tool returns, so this is
	// the state it will be evaluated against.
	s.scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, host, "/admin"))

	run := waitForDiscovery(t, s, start.TaskID)
	if run.Outcome != "completed" {
		t.Fatalf("outcome = %q, error = %q", run.Outcome, run.Error)
	}
	for _, d := range run.Discoveries {
		if d.Path == "/admin" {
			t.Errorf("an excluded path was reported: %+v", d)
		}
	}
	if run.Counts.OutOfScope == 0 {
		t.Fatalf("counts.out_of_scope = 0 after excluding a path ffuf found; a dropped result that is "+
			"not counted is indistinguishable from one that was never there (run: %+v)", run)
	}
	if !strings.Contains(run.Summary, "outside the engagement scope") {
		t.Errorf("summary does not state the drop: %q", run.Summary)
	}
	// The task's own breakdown has to agree: an out-of-scope drop is gated work, so the count is a
	// floor and Task.Complete() must be false for it.
	for _, task := range s.tasks.Snapshot() {
		if task.ID != start.TaskID {
			continue
		}
		if task.Result.Gated == 0 {
			t.Errorf("task result = %+v; a scope-refused result must land in the gated bucket", task.Result)
		}
		if task.Complete() {
			t.Error("a run whose count is a floor reported itself complete")
		}
	}
}

// ?task= for a run this server never held is a 404, not an empty run that reads as a finished sweep.
func TestDiscoveryAnUnknownTaskIsNotFound(t *testing.T) {
	rec := get(t, newTestServer(), "/api/discovery?task=4242")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
}

func mustHostname(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname()
}

// TestDiscoveryCapabilityWasExercised is the honest-skip enforcement, mirroring
// internal/extscan's TestExternalToolCapabilitiesWereExercised: a run that skipped the live test
// verified nothing about the tool this route delegates to, and a skip is as silent as a pass.
func TestDiscoveryCapabilityWasExercised(t *testing.T) {
	discoverySkipMu.Lock()
	skipped := append([]string(nil), discoverySkips...)
	discoverySkipMu.Unlock()

	if len(skipped) == 0 {
		return
	}
	msg := fmt.Sprintf("%d live discovery test(s) were skipped for a missing capability, so this run "+
		"verified nothing about the ffuf delegation /api/discovery is built on. Skipped: %v",
		len(skipped), skipped)
	if os.Getenv(allowUnverifiedExtscanEnv) == "1" {
		t.Logf("DISCOVERY UNVERIFIED (allowed by %s): %s", allowUnverifiedExtscanEnv, msg)
		return
	}
	t.Fatalf("%s\nInstall ffuf to exercise it, or set %s=1 to accept a run that does not check the claim.",
		msg, allowUnverifiedExtscanEnv)
}
