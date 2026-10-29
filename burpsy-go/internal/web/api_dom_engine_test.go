package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

type stubEngine struct{ closed bool }

func (e *stubEngine) Browser(context.Context) (*domexec.Browser, error) {
	return nil, errors.New("stub")
}
func (e *stubEngine) Close() error { e.closed = true; return nil }

func decodeDOM(t *testing.T, code int, body []byte) domEngineView {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	var v domEngineView
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return v
}

// PUT /api/scanner/dom sets, replaces and removes the DOM engine of a running process: the scanner
// that already holds the switch sees it, the DOM families are switched on with it, /api/stats reports
// it, and a value the builder refuses changes nothing.
func TestDOMEngineIsSetReplacedAndRemovedAtRuntime(t *testing.T) {
	sw := scanner.NewSwitchableBrowsers()
	built := map[string]*stubEngine{}
	build := func(v string) (scanner.BrowserProvider, error) {
		if v == "/no/such/browser" {
			return nil, errors.New(`-dom "/no/such/browser" names neither a ws:// CDP endpoint nor a runnable browser`)
		}
		e := &stubEngine{}
		built[v] = e
		return e, nil
	}
	active := scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithBrowserProvider(sw)
	s := NewServer(core.NewTrafficStore(), core.NewScope()).WithScanner(active).WithDOMSwitch(sw, build)

	rec := getJSON(t, s, "/api/scanner/dom")
	if v := decodeDOM(t, rec.Code, rec.Body.Bytes()); v.Engine != "off" || v.Configured || v.DOMChecks {
		t.Fatalf("a process started without -dom reports %+v", v)
	}

	rec = putJSON(t, s, "/api/scanner/dom", map[string]string{"engine": "chrome"})
	if v := decodeDOM(t, rec.Code, rec.Body.Bytes()); v.Engine != "chrome" || !v.Configured || !v.DOMChecks {
		t.Fatalf("after setting chrome: %+v", v)
	}
	if !active.DOMCapabilityConfigured() {
		t.Fatal("the running scanner does not see the engine that was set")
	}
	rec = getJSON(t, s, "/api/stats")
	var stats struct {
		DOMEngine string `json:"dom_engine"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &stats)
	if stats.DOMEngine != "chrome" {
		t.Fatalf("/api/stats reports dom engine %q, want chrome (%s)", stats.DOMEngine, rec.Body.Bytes())
	}

	rec = putJSON(t, s, "/api/scanner/dom", map[string]string{"engine": "/no/such/browser"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a refused value: status %d, want 400", rec.Code)
	}
	if sw.Label() != "chrome" || built["chrome"].closed {
		t.Fatal("a refused value must leave the engine in force untouched")
	}

	rec = putJSON(t, s, "/api/scanner/dom", map[string]string{"engine": ""})
	if v := decodeDOM(t, rec.Code, rec.Body.Bytes()); v.Engine != "off" || v.Configured {
		t.Fatalf("after removing: %+v", v)
	}
	if !built["chrome"].closed || active.DOMCapabilityConfigured() {
		t.Fatal("removing the engine must close it and leave the scanner without one")
	}
}

func TestDOMEngineRefusesABadBodyAndAProcessWithoutASwitch(t *testing.T) {
	s := NewServer(core.NewTrafficStore(), core.NewScope())
	if rec := getJSON(t, s, "/api/scanner/dom"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no switch: status %d, want 503", rec.Code)
	}
	sw := scanner.NewSwitchableBrowsers()
	s = s.WithDOMSwitch(sw, func(string) (scanner.BrowserProvider, error) { return &stubEngine{}, nil })
	if rec := putJSON(t, s, "/api/scanner/dom", map[string]bool{"engine": true}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body: status %d, want 400", rec.Code)
	}
}
