package persist

import (
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/burpsy-go/burpsy/internal/matchreplace"
)

// burpsy-react-ui-wtm2: NewRule now refuses a blank match outside the header targets, and a
// project saved before that may hold one. Restoring it must not fail the whole project, must not
// install the rule (it corrupted every message it touched), and must say so rather than drop it
// in silence. The rules around it come back as saved.
func TestRestoreSkipsAndReportsASavedBlankMatchRule(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	p, err := Open(filepath.Join(t.TempDir(), "test.db"), zap.New(core))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { p.Close() })

	before, err := matchreplace.NewRule(matchreplace.TargetResponseBody, matchreplace.CategoryLiteral, "a", "b", "before")
	if err != nil {
		t.Fatal(err)
	}
	header, err := matchreplace.NewRule(matchreplace.TargetRequestHeader, matchreplace.CategoryLiteral, "", "X-A: 1", "add header")
	if err != nil {
		t.Fatal(err)
	}
	// What an older build saved: a blank literal body rule, which NewRule now refuses.
	legacy := &matchreplace.Rule{Enabled: true, Target: matchreplace.TargetRequestBody, Category: matchreplace.CategoryLiteral, StringReplace: "x", Comment: "legacy blank"}
	p.SaveMatchRules([]*matchreplace.Rule{before, legacy, header}, MatchRuleSettings{})

	mr := matchreplace.NewRuleSet()
	if err := p.Restore(nil, nil, nil, mr, nil, nil, nil); err != nil {
		t.Fatalf("Restore failed over one refused rule: %v", err)
	}
	rules := mr.Rules()
	if len(rules) != 2 || rules[0].Comment != "before" || rules[1].Comment != "add header" {
		t.Fatalf("restored rules = %+v, want the two valid rules in order", rules)
	}
	var named, counted bool
	for _, e := range logs.All() {
		msg := e.ContextMap()["error"]
		s, _ := msg.(string)
		if strings.Contains(s, "legacy blank") {
			named = true
		}
		if strings.Contains(s, "1 of 3 saved match & replace rule(s)") {
			counted = true
		}
	}
	if !named || !counted {
		t.Fatalf("refusal not reported (named=%v counted=%v): %+v", named, counted, logs.All())
	}
}
