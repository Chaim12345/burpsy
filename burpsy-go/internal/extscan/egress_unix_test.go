//go:build unix

package extscan

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// fakeProxiedTool writes a stand-in for nuclei or ffuf that does what the real tool does with its proxy
// flag: sends its requests through it. It curls inURL and outURL via the proxy named after flag, then
// prints stdout (a nuclei record, say). curl's empty --noproxy argument stops a NO_PROXY in the environment from
// sending loopback direct, which would test the environment instead of the wiring.
func fakeProxiedTool(t *testing.T, name, flag string, urls []string, stdout string) string {
	t.Helper()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("no curl: the fake tool cannot send through the proxy")
	}
	var b strings.Builder
	b.WriteString("#!/bin/sh\nproxy=\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"" + flag + "\" ]; then proxy=\"$2\"; fi\n  shift\ndone\n")
	b.WriteString("[ -n \"$proxy\" ] || { echo 'no proxy flag' >&2; exit 3; }\n")
	for _, u := range urls {
		b.WriteString("curl -s -o /dev/null --noproxy '' -x \"$proxy\" '" + u + "'\n")
	}
	if stdout != "" {
		b.WriteString("printf '%s\\n' '" + stdout + "'\n")
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(b.String()), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// End to end through RunNuclei: a template's out-of-scope request never connects, the in-scope one is
// forwarded, and the run says it was partial because the gate refused something.
func TestRunNucleiSendsThroughTheGateAndReportsRefusals(t *testing.T) {
	var insideHits atomic.Int64
	inside, _ := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { insideHits.Add(1) }))
	outside, outsideAccepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	host, port := authority(t, inside.URL)
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPort(core.ScopeInclude, host, port))
	target, err := Authorise(scope, inside.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	record := `{"template-id":"tpl","info":{"name":"T","severity":"info"},"type":"http","host":"` + host + `","matched-at":"` + inside.URL + `/a"}`
	bin := fakeProxiedTool(t, "nuclei", "-proxy", []string{inside.URL + "/a", outside.URL + "/b"}, record)
	cfg := Config{Tools: map[string]string{ToolNuclei: bin}, Timeout: 30 * time.Second}

	res := RunNuclei(context.Background(), cfg, scope, target, NucleiOptions{})
	if insideHits.Load() != 1 {
		t.Fatalf("the in-scope request reached the origin %d time(s), want 1 (err %v)", insideHits.Load(), res.Err)
	}
	if n := outsideAccepts.Load(); n != 0 {
		t.Fatalf("the out-of-scope host accepted %d connection(s) during a gated nuclei run", n)
	}
	if res.GateRefused != 1 || len(res.GateRefusals) != 1 || !strings.Contains(res.GateRefusals[0], strings.TrimPrefix(outside.URL, "http://")) {
		t.Errorf("refusals = %d %v, want the one out-of-scope request named", res.GateRefused, res.GateRefusals)
	}
	if res.Outcome != OutcomePartial || res.Incomplete != IncompleteScopeRefused {
		t.Errorf("outcome %v / %q, want partial for refused requests", res.Outcome, res.Incomplete)
	}
	if len(res.Hits) != 1 {
		t.Errorf("hits = %+v, want the in-scope record", res.Hits)
	}
	if res.EgressGate != EgressGatePerRequest {
		t.Errorf("EgressGate = %q", res.EgressGate)
	}
}

// And through RunFFUF, whose flag is -x.
func TestRunFFUFSendsThroughTheGate(t *testing.T) {
	var insideHits atomic.Int64
	inside, _ := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { insideHits.Add(1) }))
	outside, outsideAccepts := countingServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	host, port := authority(t, inside.URL)
	scope := core.NewScope()
	scope.Add(core.NewScopeRuleWithPort(core.ScopeInclude, host, port))
	target, err := Authorise(scope, inside.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	bin := fakeProxiedTool(t, "ffuf", "-x", []string{inside.URL + "/w", outside.URL + "/w"}, "")
	// The fake writes no -o file, so the run fails at parsing — after the requests, which is all this
	// test is about.
	wl := filepath.Join(t.TempDir(), "w.txt")
	if err := os.WriteFile(wl, []byte("w\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Tools: map[string]string{ToolFFUF: bin}, Timeout: 30 * time.Second}
	res := RunFFUF(context.Background(), cfg, scope, target, FFUFOptions{Wordlist: wl})
	if insideHits.Load() != 1 {
		t.Fatalf("the in-scope request reached the origin %d time(s), want 1 (err %v)", insideHits.Load(), res.Err)
	}
	if n := outsideAccepts.Load(); n != 0 {
		t.Fatalf("the out-of-scope host accepted %d connection(s) during a gated ffuf run", n)
	}
	if res.GateRefused != 1 {
		t.Errorf("GateRefused = %d, want 1", res.GateRefused)
	}
}
