package scanner

import (
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// TestTheLevelIsTakenFromTheExchangePathWhenTheRouteNamesNone is the regression guard for the
// reflected-XSS browser confirmation's silent per-level miss. VulnerableApp serves
// .../XSSWithHtmlTagInjection/LEVEL_2 through one template per level, and the confirmation reaches
// the view by clicking the level's entry in the SPA tree. A built-in route that names no level must
// therefore take the level from the exchange it is confirming; a fixed level (the shipped default
// was LEVEL_1) drives LEVEL_1's field for every level, so the sink never carries the payload of the
// point under test except on LEVEL_1 — measured as LEVEL_1 confirmed and LEVEL_2..5 missed with
// byte-identical wire responses.
func TestTheLevelIsTakenFromTheExchangePathWhenTheRouteNamesNone(t *testing.T) {
	sc := &ActiveScanner{config: &ScanConfig{XSSBrowserTargets: BuiltinXSSBrowserTargets()}}
	for _, level := range []string{"LEVEL_1", "LEVEL_2", "LEVEL_3"} {
		cc := &CheckContext{
			Scanner: sc,
			Exchange: &core.Exchange{
				Host: "127.0.0.1",
				Path: "/VulnerableApp/XSSWithHtmlTagInjection/" + level + "?value=1",
			},
		}
		got, ok := xssBrowserTargetFor(cc)
		if !ok {
			t.Fatalf("no route matched %s, so the browser confirmation was declined", level)
		}
		if got.LevelText != level {
			t.Errorf("confirming %s drove %q: a level taken from anywhere but the exchange's own path "+
				"points the browser at another level's field, and the confirmation then misses for a "+
				"reason that reads like the target is clean", level, got.LevelText)
		}
	}
}

// TestAnExplicitlyNamedLevelIsNotOverridden pins that a caller who states the level keeps it: the
// derivation exists for a route generic over levels, not to second-guess a specific one.
func TestAnExplicitlyNamedLevelIsNotOverridden(t *testing.T) {
	sc := &ActiveScanner{config: &ScanConfig{XSSBrowserTargets: []XSSBrowserTarget{{
		Match: "example.test", MasterText: "Fam", LevelText: "PINNED",
	}}}}
	cc := &CheckContext{Scanner: sc, Exchange: &core.Exchange{
		Host: "example.test", Path: "/Fam/OTHER_LEVEL",
	}}
	got, ok := xssBrowserTargetFor(cc)
	if !ok || got.LevelText != "PINNED" {
		t.Fatalf("a stated LevelText was rewritten to %q (matched=%v)", got.LevelText, ok)
	}
}

// TestTheBrowserConfirmLadderEvadesTheNaiveFiltersThatStripTheFirstSpelling is the regression guard for
// the per-level miss on a filter that deletes a tag by name. The confirmation is a substring test on a
// sink's argument, so every rung must keep the canary literal while surviving the filter; a spelling that
// hides the canary in an encoded blob would decode to an exploit yet never match, reading as clean.
func TestTheBrowserConfirmLadderEvadesTheNaiveFiltersThatStripTheFirstSpelling(t *testing.T) {
	// LEVEL_2 deletes any tag whose name starts with one of s,c,r,i,p,t,m,g,a (measured against a live
	// VulnerableApp: `<svg` and `<img` are stripped, `<details` and `<object` survive).
	level2 := func(p string) bool {
		for _, bad := range []string{"<script", "<svg", "<img", "<iframe", "<input", "<meta", "<a "} {
			if strings.Contains(strings.ToLower(p), bad) {
				return false
			}
		}
		return true
	}
	// LEVEL_3 adds only the literal keyword rejections `alert` and `javascript`; it does NOT block
	// onerror/onload, which is precisely why a confirmation-handler spelling is the rung that survives it.
	level3 := func(p string) bool {
		if !level2(p) {
			return false
		}
		low := strings.ToLower(p)
		return !strings.Contains(low, "alert") && !strings.Contains(low, "javascript")
	}

	ladder := xssBrowserConfirmLadder(genericXSSPayloads(), maxXSSBrowserConfirmAttempts)
	if len(ladder) == 0 {
		t.Fatal("the ladder is empty, so the confirmation would send nothing")
	}
	if got := ladder[0].note; got != genericXSSPayloads()[0].note {
		t.Errorf("the ladder does not lead with the context-specific payload: first note %q", got)
	}
	if len(ladder) != maxXSSBrowserConfirmAttempts {
		t.Errorf("the ladder has %d rungs, want the bounded %d", len(ladder), maxXSSBrowserConfirmAttempts)
	}
	for _, filter := range []struct {
		name string
		pass func(string) bool
	}{{"LEVEL_2 tag-name filter", level2}, {"LEVEL_3 tag-name + keyword filter", level3}} {
		found := false
		for _, p := range ladder {
			payload := p.build("CANARY")
			if !strings.Contains(payload, "CANARY") {
				t.Errorf("%s: rung %q does not keep the canary literal, so a sink carrying it could never "+
					"match and the page would read as clean", filter.name, p.note)
				continue
			}
			if filter.pass(payload) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: no rung survives, so every level behind that filter is reported clean", filter.name)
		}
	}
}
