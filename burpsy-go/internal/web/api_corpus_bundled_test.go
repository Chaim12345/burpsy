package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// The compiled-in BCheck corpus runs in every audit, so the console lists it: each bundled check is
// a row the operator can see, switch off, and open read-only (burpsy-react-ui-0vzb.27).
func TestTheBundledCorpusIsListedSwitchableAndViewable(t *testing.T) {
	bundledChecks, err := scanner.BundledCorpus(nil)
	if err != nil || len(bundledChecks) == 0 {
		t.Fatalf("bundled corpus: %d checks, %v", len(bundledChecks), err)
	}
	store := core.NewTrafficStore()
	scope := core.NewScope()
	ps, err := scanner.LoadDir(t.TempDir(), store, scope, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	active := scanner.NewActiveScanner(store, zap.NewNop()).WithScope(scope).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).WithBundledCorpus(bundledChecks)
	s := newTestServer().WithScanner(active).WithPassiveScanner(ps)

	var res struct {
		Enabled     bool `json:"enabled"`
		ActiveCount int  `json:"active_count"`
		Checks      []struct {
			Name   string `json:"name"`
			Origin string `json:"origin"`
		} `json:"checks"`
	}
	rec := get(t, s, "/api/scanner/checks")
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v; %s", err, rec.Body.String())
	}
	n := 0
	for _, c := range res.Checks {
		if c.Origin == "bundled" {
			n++
		}
	}
	if !res.Enabled || n != len(bundledChecks) || res.ActiveCount != len(bundledChecks) {
		t.Fatalf("enabled=%v bundled rows=%d active_count=%d, want %d bundled checks listed",
			res.Enabled, n, res.ActiveCount, len(bundledChecks))
	}

	name := bundledChecks[0].Name
	if rec := putJSON(t, s, "/api/scanner/checks/enable", map[string]any{"name": name, "enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("disabling a bundled check = %d (%s)", rec.Code, rec.Body.String())
	}
	if !active.DisabledChecks()[name] {
		t.Error("the bundled check's switch did not reach the set the engine filters by")
	}

	src := decodeMap(t, get(t, s, "/api/scanner/checks/source?name="+url.QueryEscape(name)))
	if src["origin"] != "bundled" || src["source"] == "" || src["file"] == "" {
		t.Errorf("the bundled check's source view = %v", src)
	}
}
