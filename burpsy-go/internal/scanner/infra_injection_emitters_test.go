package scanner

import (
	"strings"
	"testing"
)

func TestEveryEmitterCarriesTheRecoveredArithmetic(t *testing.T) {
	for _, e := range CodeInjectionEmitters() {
		for _, ctx := range AllQuotingContexts {
			got := RenderCodeInjection(e, ctx)
			if !strings.Contains(got, "7*6") {
				t.Errorf("%s/%s payload %q lost the recovered arithmetic", e.Language, ctx.Label(), got)
			}
			if strings.Contains(got, "%s") {
				t.Errorf("%s payload %q kept its verb", e.Language, got)
			}
		}
	}
}

// The PHP emitters are the only ones the evidence actually contains; the rest must not
// claim recovery, because presenting an invented payload as recovered is the one thing this
// project forbids outright.
func TestOnlyPHPEmittersClaimRecovery(t *testing.T) {
	for _, e := range CodeInjectionEmitters() {
		if e.Recovered && e.Language != "php" {
			t.Errorf("%s emitter %q claims recovery, but only burp.Zxvv's PHP forms are in the evidence",
				e.Language, e.Template)
		}
	}
	var phpRecovered int
	for _, e := range CodeInjectionEmitters() {
		if e.Language == "php" && e.Recovered {
			phpRecovered++
		}
	}
	if phpRecovered != 2 {
		t.Errorf("got %d recovered PHP emitters, want the 2 from burp.Zxvv", phpRecovered)
	}
}

func TestProbeSetWalksEveryContextPerEmitter(t *testing.T) {
	got := CodeInjectionProbeSet("python")
	if len(got) != 2*len(AllQuotingContexts) {
		t.Fatalf("got %d probes for python, want 2 emitters x 3 contexts", len(got))
	}
	seen := map[QuotingContext]int{}
	for _, p := range got {
		if p.Detail != "python" {
			t.Errorf("probe %+v leaked from another language", p)
		}
		seen[p.Context]++
	}
	for _, ctx := range AllQuotingContexts {
		if seen[ctx] != 2 {
			t.Errorf("context %s covered %d times, want 2", ctx.Label(), seen[ctx])
		}
	}
}

func TestProbeSetWithNoLanguageCoversAll(t *testing.T) {
	all := CodeInjectionProbeSet("")
	if len(all) != len(CodeInjectionEmitters())*len(AllQuotingContexts) {
		t.Fatalf("got %d probes, want every emitter in every context", len(all))
	}
	langs := map[string]bool{}
	for _, p := range all {
		langs[p.Detail] = true
	}
	for _, want := range []string{"php", "perl", "ruby", "python", "javascript"} {
		if !langs[want] {
			t.Errorf("no probe generated for %s", want)
		}
	}
}

// A payload that already escapes its own quoting must not be double-wrapped, or it becomes
// syntactically inert and the probe silently tests nothing.
func TestSelfEscapingEmittersAreNotDoubleWrapped(t *testing.T) {
	for _, e := range CodeInjectionEmitters() {
		if !strings.HasPrefix(e.Template, `"`) {
			continue
		}
		for _, ctx := range AllQuotingContexts {
			got := RenderCodeInjection(e, ctx)
			if strings.HasPrefix(got, `""`) || strings.HasPrefix(got, `'"`) {
				t.Errorf("%s payload %q was double-wrapped for %s", e.Language, got, ctx.Label())
			}
		}
	}
}
