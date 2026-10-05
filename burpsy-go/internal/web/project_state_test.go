package web

import (
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// burpsy-react-ui-z4ml: project-level scan state follows the project. Project A saved a scan override
// and has an audit ledger; switching to B (which saved neither) must give B the LAUNCH defaults and an
// empty ledger — not A's override and A's "already audited" set — and switching back restores A's.
func TestProjectLevelScanStateFollowsAProjectSwitch(t *testing.T) {
	dir := t.TempDir()
	open := func(name string) *persist.Store {
		st, err := persist.Open(filepath.Join(dir, name), zap.NewNop())
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		t.Cleanup(func() { _ = st.Close() })
		return st
	}
	scan := scanner.NewActiveScanner(core.NewTrafficStore(), zap.NewNop())
	launched := scan.UpdateScanConfig(func(*scanner.ScanConfig) {}).CheckXXE

	a := open("a.db")
	override := scan.UpdateScanConfig(func(*scanner.ScanConfig) {})
	override.CheckXXE = !launched
	if err := a.SaveScanConfig(override); err != nil {
		t.Fatal(err)
	}
	if err := a.SaveLiveSeenLedger([]byte("host-a#fp1\nhost-a#fp2")); err != nil {
		t.Fatal(err)
	}
	b := open("b.db")

	s := newTestServer().WithScanner(scan).WithPersist(a)
	current := func() bool { return scan.UpdateScanConfig(func(*scanner.ScanConfig) {}).CheckXXE }
	if current() != !launched {
		t.Fatal("project A's saved scan override was not applied at startup")
	}
	if s.liveAudit == nil || s.liveAudit.SeenCount() != 2 {
		t.Fatalf("project A's seen ledger was not loaded")
	}

	s.WithPersist(b) // what an in-console switch does
	if current() != launched {
		t.Error("after switching to B, the scan config still carries A's override — B saved none, so it must get the launch defaults")
	}
	if n := s.liveAudit.SeenCount(); n != 0 {
		t.Errorf("after switching to B the sweep still remembers %d of A's exchanges as already audited", n)
	}

	s.WithPersist(a)
	if current() != !launched {
		t.Error("switching back to A did not restore A's override")
	}
}
