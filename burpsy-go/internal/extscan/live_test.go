package extscan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The live half of this package's tests: these actually launch ffuf and nuclei
// against a throwaway local server.
//
// # Capability skips are counted, and missing capabilities are fatal
//
// This mirrors the Chrome rule in scanner's runtime coverage suite, and for the
// same reason. A test skipped for a missing binary and a test that passed look
// identical in a `go test` summary — both are silent — so a machine without ffuf
// would report a green package having verified nothing about ffuf at all. That
// is "we did not look" reading as "we looked and found nothing", which is the
// one outcome this project's standard forbids.
//
// So each live test records its skip, and TestExternalToolCapabilitiesWereExercised
// fails the package if anything was skipped. BURPSY_ALLOW_UNVERIFIED_EXTSCAN=1
// accepts a deliberately reduced environment and is loud about what it cost.

const allowUnverifiedEnv = "BURPSY_ALLOW_UNVERIFIED_EXTSCAN"

var (
	skipMu          sync.Mutex
	capabilitySkips []string
)

func recordSkip(t *testing.T, reason string) {
	t.Helper()
	skipMu.Lock()
	capabilitySkips = append(capabilitySkips, fmt.Sprintf("%s (%s)", t.Name(), reason))
	skipMu.Unlock()
	t.Skip(reason + ": this test is NOT exercised in this run")
}

func toolOnPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// nucleiTemplatesPresent reports whether nuclei has a template corpus to run.
// The binary alone is not the capability: nuclei with no templates runs and
// matches nothing, which would let an empty result pass for a real scan.
func nucleiTemplatesPresent() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	info, err := os.Stat(filepath.Join(home, ".local", "nuclei-templates", "http"))
	return err == nil && info.IsDir()
}

// liveServer is the throwaway target. It answers a couple of guessable paths so
// ffuf has something real to find, and sets headers a nuclei technology
// template recognises so nuclei has something real to match.
func liveServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	handler := func(body string, status int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Apache/2.4.49")
			w.Header().Set("X-Powered-By", "PHP/7.4.3")
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		}
	}
	mux.HandleFunc("/admin", handler("admin area", http.StatusOK))
	mux.HandleFunc("/backup.zip", handler("PK\x03\x04 not really a zip", http.StatusOK))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.49")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "<html><body>index</body></html>")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestLiveFFUFDiscoversRealPaths(t *testing.T) {
	if !toolOnPath("ffuf") {
		recordSkip(t, "no ffuf on PATH")
	}
	srv := liveServer(t)

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nbackup.zip\nnothing-is-here\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	scope := core.NewScopeAllowEverything()
	target, err := Authorise(scope, srv.URL+"/")
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}

	// Threads: 1 is load-bearing for the test, not a performance choice. ffuf
	// defaults to 40 concurrent connections, and against an httptest server on a
	// machine already busy running the rest of this suite that overruns the
	// accept backlog: a refused connection is an error to ffuf, not a result, so
	// a path that exists silently goes unreported and the assertion below fails
	// for a reason unrelated to what it is testing. Seen exactly that way in a
	// concurrent full-suite run. Three words do not need concurrency anyway.
	res := RunFFUF(t.Context(), Config{Tools: map[string]string{ToolFFUF: "ffuf"}},
		scope, target, FFUFOptions{Wordlist: wordlist, MatchCodes: "200", Threads: 1})
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %v (%v); command was %v", res.Outcome, res.Err, res.Command)
	}
	found := map[string]int{}
	for _, d := range res.Discoveries {
		found[d.Path] = d.Status
	}
	for _, want := range []string{"/admin", "/backup.zip"} {
		if found[want] != 200 {
			t.Errorf("ffuf did not discover %s as 200; found %v", want, found)
		}
	}
	if _, unexpected := found["/nothing-is-here"]; unexpected {
		t.Errorf("ffuf reported a path the server 404s; found %v", found)
	}
	if len(res.Rows()) == 0 {
		t.Error("a completed run with discoveries produced no report rows")
	}
}

// The scope re-check is not decoration: a discovery outside the engagement must
// not enter a report even though the request was already made.
func TestLiveFFUFDropsOutOfScopeDiscoveries(t *testing.T) {
	if !toolOnPath("ffuf") {
		recordSkip(t, "no ffuf on PATH")
	}
	srv := liveServer(t)

	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\nbackup.zip\n"), 0o644); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	// Authorise against a permissive scope, then hand the runner a stricter one
	// that excludes /admin. This is the shape of an engagement whose scope is
	// narrowed after a target was chosen, and the reporting side must honour it.
	target, err := Authorise(core.NewScopeAllowEverything(), srv.URL+"/")
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	narrowed := core.NewScope()
	narrowed.AddInclude("127.0.0.1")
	narrowed.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "127.0.0.1", "/admin"))

	res := RunFFUF(t.Context(), Config{Tools: map[string]string{ToolFFUF: "ffuf"}},
		narrowed, target, FFUFOptions{Wordlist: wordlist, MatchCodes: "200", Threads: 1})
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %v (%v)", res.Outcome, res.Err)
	}
	for _, d := range res.Discoveries {
		if d.Path == "/admin" {
			t.Errorf("an excluded path was reported: %+v", d)
		}
	}
	if len(res.Discoveries) == 0 {
		t.Error("everything was filtered; the test can no longer tell filtering from a failed scan")
	}
}

func TestLiveNucleiMatchesRealTemplates(t *testing.T) {
	if !toolOnPath("nuclei") {
		recordSkip(t, "no nuclei on PATH")
	}
	if !nucleiTemplatesPresent() {
		recordSkip(t, "nuclei has no template corpus installed")
	}
	srv := liveServer(t)

	scope := core.NewScopeAllowEverything()
	target, err := Authorise(scope, srv.URL+"/")
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}

	home, _ := os.UserHomeDir()
	res := RunNuclei(t.Context(), Config{Tools: map[string]string{ToolNuclei: "nuclei"}},
		scope, target, NucleiOptions{
			Templates: []string{filepath.Join(home, ".local", "nuclei-templates", "http", "technologies", "tech-detect.yaml")},
		})
	if res.Outcome != OutcomeCompleted {
		t.Fatalf("outcome = %v (%v); command was %v", res.Outcome, res.Err, res.Command)
	}
	if len(res.Hits) == 0 {
		t.Fatalf("tech-detect matched nothing against a server announcing Apache and PHP; command was %v", res.Command)
	}
	for _, h := range res.Hits {
		if h.TemplateID != "tech-detect" {
			t.Errorf("unexpected template %q", h.TemplateID)
		}
		if h.MatchedAt == "" {
			t.Error("hit carries no matched-at location")
		}
	}
	rows := res.Rows()
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 for a single template", len(rows))
	}
	if rows[0].Severity != "Informational" {
		t.Errorf("severity = %q, want Informational (tech-detect is nuclei-severity info)", rows[0].Severity)
	}
	if rows[0].Occurrences != len(res.Hits) {
		t.Errorf("row claims %d occurrences for %d hits", rows[0].Occurrences, len(res.Hits))
	}
}

// TestExternalToolCapabilitiesWereExercised is the honest-skip enforcement. It
// must sort last, which it does because Go runs tests in source order within a
// file and this is the last one here — but it also re-reads the shared slice
// under its lock, so an out-of-order run only makes it more permissive, never
// silently wrong.
func TestExternalToolCapabilitiesWereExercised(t *testing.T) {
	skipMu.Lock()
	skipped := append([]string(nil), capabilitySkips...)
	skipMu.Unlock()

	if len(skipped) == 0 {
		return
	}
	msg := fmt.Sprintf("%d live test(s) were skipped for a missing capability, so this run verified "+
		"nothing about the external tools it claims to integrate. Skipped: %v", len(skipped), skipped)
	if os.Getenv(allowUnverifiedEnv) == "1" {
		t.Logf("EXTSCAN UNVERIFIED (allowed by %s): %s", allowUnverifiedEnv, msg)
		return
	}
	t.Fatalf("%s\nInstall ffuf and nuclei (with its template corpus) to exercise them, or set %s=1 "+
		"to accept a run that does not check the claim.", msg, allowUnverifiedEnv)
}
