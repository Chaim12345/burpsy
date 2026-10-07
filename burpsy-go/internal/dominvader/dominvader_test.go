package dominvader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Materialise writes a loadable extension: the embedded files plus a generated config.js carrying the
// canary, the switch and the report URL, so the browser can --load-extension it directly.
func TestMaterialiseWritesALoadableExtensionWithTheConfig(t *testing.T) {
	dir, err := Materialise(t.TempDir(), Config{Canary: "burpsyDIabc", Enabled: true, Report: "http://127.0.0.1:9/api/dominvader/hit"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"manifest.json", "instrument.js", "relay.js", "sw.js", "config.js"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
	cfg, err := os.ReadFile(filepath.Join(dir, "config.js"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"burpsyDIabc", `"enabled":true`, "api/dominvader/hit", "self.__burpsyDI_config"} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("config.js lacks %q: %s", want, cfg)
		}
	}
	// The MAIN-world instrumentation and the worker both read self.__burpsyDI_config.
	man, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if !strings.Contains(string(man), `"world": "MAIN"`) {
		t.Errorf("manifest does not inject a MAIN-world script: %s", man)
	}
}

// A repeat hit (same dedupe key) bumps the existing row rather than growing the list; distinct hits
// each get a row and a rising id.
func TestStoreCollapsesRepeatsAndKeepsDistinctHits(t *testing.T) {
	s := NewStore()
	if !strings.HasPrefix(s.Canary(), "burpsyDI") || s.Enabled() {
		t.Fatalf("fresh store: canary %q enabled %v", s.Canary(), s.Enabled())
	}
	a := s.Add(&Hit{Kind: "sink", Sink: "innerHTML", Dedupe: "k1"})
	again := s.Add(&Hit{Kind: "sink", Sink: "innerHTML", Dedupe: "k1"})
	b := s.Add(&Hit{Kind: "sink", Sink: "eval", Dedupe: "k2"})
	if again.ID != a.ID {
		t.Errorf("a repeat got a new id %d, want %d", again.ID, a.ID)
	}
	if b.ID == a.ID {
		t.Errorf("a distinct hit reused the id")
	}
	if got := s.Hits(); len(got) != 2 {
		t.Errorf("hits = %d, want 2", len(got))
	}
}

func TestStoreRefusesAnEmptyCanaryAndTogglesEnabled(t *testing.T) {
	s := NewStore()
	if err := s.SetCanary("  "); err == nil {
		t.Error("an empty canary was accepted")
	}
	if err := s.SetCanary("myCanary"); err != nil || s.Canary() != "myCanary" {
		t.Errorf("SetCanary: %v / %q", err, s.Canary())
	}
	s.SetEnabled(true)
	if cfg := s.Config("http://x/hit"); !cfg.Enabled || cfg.Canary != "myCanary" || cfg.Report != "http://x/hit" {
		t.Errorf("config = %+v", cfg)
	}
	s.Clear()
	if len(s.Hits()) != 0 {
		t.Error("Clear left hits")
	}
}
