package filelog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func addExchange(t *testing.T, store *core.TrafficStore, source core.Source, path string) {
	t.Helper()
	req, _ := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: app.test\r\n\r\n"), core.DirectionRequest)
	resp, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"+path), core.DirectionResponse)
	store.AddExchange(&core.Exchange{Request: core.MsgPtr(req), Response: &resp, Host: "app.test", Port: 443, TLS: true,
		Method: "GET", Path: path, Source: source, ServerIP: "10.0.0.9"})
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEachToolsTrafficGoesToItsOwnFileAndAllToolsGetsEverything(t *testing.T) {
	dir := t.TempDir()
	proxyReqs, all, scannerResps := filepath.Join(dir, "proxy.log"), filepath.Join(dir, "all.log"), filepath.Join(dir, "scanner.log")
	store := core.NewTrafficStore()
	l := New(store)
	defer l.Close()
	store.ObserveExchanges(l.Observe)
	if err := l.Apply(Settings{
		Requests:  map[string]string{"proxy": proxyReqs, "all_tools": all},
		Responses: map[string]string{"scanner": scannerResps, "all_tools": all},
	}); err != nil {
		t.Fatal(err)
	}
	addExchange(t, store, core.SourceProxy, "/p")
	addExchange(t, store, core.SourceRepeater, "/r")
	addExchange(t, store, core.SourceCrawl, "/c")
	addExchange(t, store, core.SourceImport, "/i")
	l.Flush()

	p := read(t, proxyReqs)
	if !strings.Contains(p, "GET /p HTTP/1.1") || strings.Contains(p, "/r") || strings.Contains(p, "HTTP/1.1 200") {
		t.Errorf("proxy requests log = %q, want only the proxy request", p)
	}
	if !strings.HasPrefix(p, rule+"\n") || !strings.Contains(p, "  https://app.test:443  [10.0.0.9]\n"+rule+"\n") {
		t.Errorf("entry is not in Burp's shape: %q", p)
	}
	s := read(t, scannerResps)
	if !strings.Contains(s, "body/c") || strings.Contains(s, "GET ") || strings.Contains(s, "body/p") {
		t.Errorf("scanner responses log = %q, want only the crawler's response", s)
	}
	a := read(t, all)
	for _, want := range []string{"GET /p ", "GET /r ", "GET /c ", "body/p", "body/r", "body/c"} {
		if !strings.Contains(a, want) {
			t.Errorf("all_tools log lacks %q", want)
		}
	}
	if strings.Contains(a, "/i") {
		t.Error("an imported exchange came from no tool and must not be logged")
	}
	if strings.Count(a, "GET /p ") != 1 {
		t.Error("a file named under a tool and all_tools got the entry twice")
	}
	if st := l.Stats(); st.Written == 0 || st.Dropped != 0 || st.LastError != "" {
		t.Errorf("stats = %+v", st)
	}
}

func TestApplyRefusesBadSettingsAndChangesNothing(t *testing.T) {
	dir := t.TempDir()
	l := New(core.NewTrafficStore())
	defer l.Close()
	good := filepath.Join(dir, "ok.log")
	if err := l.Apply(Settings{Requests: map[string]string{"repeater": good}}); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Settings{
		"unknown tool":  {Requests: map[string]string{"comparer": filepath.Join(dir, "x.log")}},
		"relative path": {Responses: map[string]string{"proxy": "logs/proxy.log"}},
		"unopenable":    {Requests: map[string]string{"proxy": filepath.Join(dir, "no", "such", "dir", "x.log")}},
	} {
		if err := l.Apply(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if got := l.Settings().Requests["repeater"]; got != good {
		t.Errorf("a refused Apply changed the settings: repeater = %q", got)
	}
	if got := l.Settings().Requests; len(got) != len(Tools) {
		t.Errorf("settings do not list every tool: %v", got)
	}
}

// One file named under a tool and under all_tools receives each entry once.
func TestAFileNamedTwiceGetsEachEntryOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "both.log")
	store := core.NewTrafficStore()
	l := New(store)
	defer l.Close()
	store.ObserveExchanges(l.Observe)
	if err := l.Apply(Settings{Requests: map[string]string{"proxy": path, "all_tools": path}}); err != nil {
		t.Fatal(err)
	}
	addExchange(t, store, core.SourceProxy, "/once")
	l.Flush()
	if n := strings.Count(read(t, path), "GET /once "); n != 1 {
		t.Errorf("the entry was written %d times, want 1", n)
	}
}
