package jsexec

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A deliberately vulnerable recursive merge, the shape every real prototype-pollution
// advisory is about.
const unsafeMerge = `function(target, source) {
	for (var key in source) {
		if (typeof source[key] === "object" && source[key] !== null) {
			if (!target[key]) { target[key] = {}; }
			arguments.callee(target[key], source[key]);
		} else {
			target[key] = source[key];
		}
	}
	return target;
}`

// The same merge with the documented guard: skip the three dangerous keys.
const safeMerge = `function(target, source) {
	for (var key in source) {
		if (key === "__proto__" || key === "constructor" || key === "prototype") { continue; }
		if (typeof source[key] === "object" && source[key] !== null) {
			if (!target[key]) { target[key] = {}; }
			arguments.callee(target[key], source[key]);
		} else {
			target[key] = source[key];
		}
	}
	return target;
}`

func TestAnUnsafeMergeIsReportedAsPollutingObjectPrototypeViaProtoKey(t *testing.T) {
	payload := PollutionPayloads("canary123")[0]
	got, err := TestPrototypePollution(unsafeMerge, payload, 0)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if !got.Polluted {
		t.Fatal("a recursive merge with no __proto__ guard must be reported as polluting Object.prototype; a clean result here would let a real prototype-pollution bug ship undetected")
	}
	if got.Value != "canary123" {
		t.Errorf("polluted value = %q, want the canary; evidence must show the attacker-controlled value that landed", got.Value)
	}
	if got.ReachedVia != "__proto__" {
		t.Errorf("ReachedVia = %q, want __proto__ so a report can say how pollution was achieved", got.ReachedVia)
	}
}

func TestAGuardedMergeIsNotReportedAsPolluting(t *testing.T) {
	for _, payload := range PollutionPayloads("canary123") {
		got, err := TestPrototypePollution(safeMerge, payload, 0)
		if err != nil {
			t.Fatalf("evaluation failed for payload %q: %v", payload.Name, err)
		}
		if got.Polluted {
			t.Errorf("payload %q polluted a merge that explicitly skips __proto__/constructor/prototype; this is the false positive the engine exists to avoid", payload.Name)
		}
	}
}

func TestTheConstructorPrototypePayloadIsADistinctBypassShape(t *testing.T) {
	payloads := PollutionPayloads("canary123")
	if len(payloads) != 2 {
		t.Fatalf("got %d payloads, want 2", len(payloads))
	}
	if payloads[0].JSON == payloads[1].JSON {
		t.Fatal("the two payload shapes are identical, so the constructor.prototype bypass is not actually being tested")
	}
	if !strings.Contains(payloads[1].JSON, "constructor") {
		t.Errorf("second payload %q is not the constructor.prototype shape", payloads[1].JSON)
	}
}

func TestPollutionIsRefusedWhenThePropertyAlreadyExistsSoItCannotBeMisattributed(t *testing.T) {
	// A merge that itself defines the property before we look would otherwise be reported
	// as polluted by our payload. The harness must refuse rather than claim a false cause.
	preloaded := `function(target, source) { return target; }`
	payload := PollutionPayloads("canary123")[0]
	payload.Property = "toString" // already present on Object.prototype
	_, err := TestPrototypePollution(preloaded, payload, 0)
	if err == nil {
		t.Fatal("probing a property that already exists on Object.prototype must be refused, not reported as clean or as polluted")
	}
}

func TestANonTerminatingSnippetIsInterruptedRatherThanHangingTheScan(t *testing.T) {
	start := time.Now()
	_, err := EvaluateSnippet("while(true){}", "canary123", nil, 300*time.Millisecond)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got err %v, want ErrTimeout; an uninterruptible snippet would wedge the whole scan", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("interrupt took %s; the budget is not actually bounding execution", elapsed)
	}
}

func TestASnippetPassingASourceIntoEvalIsObservedAtTheEvalSink(t *testing.T) {
	obs, err := EvaluateSnippet(`eval(hash);`, "canary123", map[string]string{"hash": "alert('canary123')"}, 0)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if len(ObservationsForSink(obs, SnippetSinkEval)) != 1 {
		t.Fatalf("got %d eval observations, want 1: a source flowing into eval is the flow this tier exists to catch", len(obs))
	}
}

func TestASnippetThatNeverTouchesASourceYieldsNoObservations(t *testing.T) {
	obs, err := EvaluateSnippet(`var x = 1 + 1; eval("harmless");`, "canary123", map[string]string{"hash": "canary123"}, 0)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	if len(obs) != 0 {
		t.Fatalf("got %d observations, want 0; a sink called with unrelated data must not be reported as a flow", len(obs))
	}
}

func TestASnippetThatThrowsStillKeepsObservationsMadeBeforeTheThrow(t *testing.T) {
	// Without a DOM, snippets throw constantly. Discarding pre-throw observations would
	// lose exactly the evidence this tier is for.
	obs, err := EvaluateSnippet(`eval(hash); document.body.innerHTML = "x";`, "canary123",
		map[string]string{"hash": "canary123"}, 0)
	if err != nil {
		t.Fatalf("a throwing snippet must not be reported as an evaluation error: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("got %d observations, want 1 recorded before the DOM access threw", len(obs))
	}
}

func TestTheVMExposesNoHostCapabilities(t *testing.T) {
	// Attacker-influenced script runs here, so the absence of host bindings is a security
	// property worth asserting rather than assuming.
	for _, global := range []string{"require", "process", "os", "fs", "Deno"} {
		obs, err := EvaluateSnippet(`eval(String(typeof `+global+`));`, "function", nil, 0)
		if err != nil {
			t.Fatalf("probing %q failed: %v", global, err)
		}
		if len(obs) != 0 {
			t.Errorf("global %q is callable inside the VM; a snippet must not be able to reach the host", global)
		}
	}
}
