package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/domexec"
	"go.uber.org/zap"
)

type fakeBrowsers struct{ closed int }

func (f *fakeBrowsers) Browser(context.Context) (*domexec.Browser, error) {
	return nil, errors.New("fake engine")
}
func (f *fakeBrowsers) Close() error { f.closed++; return nil }

// The DOM engine as a runtime setting: an empty switch reads as no engine everywhere (a DOM check
// is skipped as capability-missing, not failed), and setting or replacing the engine takes effect
// on the scanner that already holds the switch, closing the engine it replaces.
func TestSwitchableBrowsersSetsAndReplacesTheEngineOnALiveScanner(t *testing.T) {
	sw := NewSwitchableBrowsers()
	s := NewActiveScanner(core.NewTrafficStore(), zap.NewNop()).WithBrowserProvider(sw)
	if s.DOMCapabilityConfigured() {
		t.Fatal("an empty switch must read as no DOM engine")
	}
	if s.ConfigSnapshot().CheckDOM {
		t.Fatal("wiring an empty switch must not switch the DOM families on")
	}
	cc := &CheckContext{Scanner: s}
	if _, err := cc.Browser(context.Background()); !errors.Is(err, errCapabilityMissing) {
		t.Fatalf("a DOM check on an empty switch must be capability-missing (skipped), got %v", err)
	}

	first := &fakeBrowsers{}
	if err := sw.Set(first, "chrome"); err != nil {
		t.Fatal(err)
	}
	s.EnableDOMChecks()
	if !s.DOMCapabilityConfigured() || sw.Label() != "chrome" || !s.ConfigSnapshot().CheckDOM {
		t.Fatalf("after setting an engine: configured=%v label=%q checkDOM=%v", s.DOMCapabilityConfigured(), sw.Label(), s.ConfigSnapshot().CheckDOM)
	}
	if _, err := cc.Browser(context.Background()); err == nil || err.Error() != "fake engine" {
		t.Fatalf("the check must reach the engine that was set, got %v", err)
	}

	second := &fakeBrowsers{}
	_ = sw.Set(second, "ws://127.0.0.1:9222")
	if first.closed != 1 || second.closed != 0 {
		t.Fatalf("replacing the engine must close the old one once and leave the new one: %d %d", first.closed, second.closed)
	}
	_ = sw.Set(nil, "ignored")
	if second.closed != 1 || s.DOMCapabilityConfigured() || sw.Label() != "" {
		t.Fatalf("removing the engine: closed=%d configured=%v label=%q", second.closed, s.DOMCapabilityConfigured(), sw.Label())
	}
	if err := s.CloseCapabilities(); err != nil {
		t.Fatalf("closing an empty switch: %v", err)
	}
}
