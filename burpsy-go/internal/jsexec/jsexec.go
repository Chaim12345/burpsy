// Package jsexec is a DOM-less JavaScript execution tier built on goja (pure Go, no cgo,
// no external binary).
//
// # What this is NOT
//
// This is not a browser and cannot replace one. goja implements ECMAScript, not the DOM:
// there is no `document`, no `Element`, no `innerHTML` setter, no layout, no CSS, no event
// loop, no fetch/XHR. The ~40 DOM-based declined catalog rows are blocked on observing
// *runtime DOM sinks and sources*, which is the DOM, not the language, so those rows are
// served by internal/domexec (chromedp over real Chrome) and NOT by this package.
//
// Building a DOM over this engine was considered and rejected: every unimplemented corner
// of a hand-rolled DOM is a silent false negative, and real DOM XSS routinely flows through
// jQuery or React, which need a DOM faithful enough to actually boot. A half-DOM that
// reports "no findings" is worse than no DOM at all, because the first is mistaken for
// evidence.
//
// # What this IS for
//
// Two jobs a real browser is the wrong tool for:
//
//  1. Prototype pollution. `Client-side prototype pollution` is decided by evaluating a
//     merge/extend snippet and then inspecting `Object.prototype` — no DOM required. Doing
//     it in-process is deterministic and far cheaper than a browser launch, and it cannot
//     be confounded by unrelated page script.
//
//  2. Graceful degradation when Chrome is absent. internal/domexec honestly refuses when it
//     cannot find a browser. On a minimal container that means zero DOM capability; this
//     package lets a caller still evaluate an *extracted* script snippet for a
//     source-to-sink flow. Its answers are strictly weaker than a browser's and callers MUST
//     label them as such — see EvaluateSnippet's doc comment.
//
// # Bounded by construction
//
// Hostile script is expected input here, so every entry point takes a timeout and runs the
// program on a goroutine with an interrupt: goja is single-threaded and a `while(true){}` in
// a snippet would otherwise hang the scan forever. There is no host binding of any kind — no
// filesystem, no network, no os — so a snippet cannot reach anything outside the VM.
package jsexec

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dop251/goja"
)

// DefaultTimeout bounds a single snippet evaluation. Chosen small deliberately: this tier
// exists for short extracted snippets, and anything slower is better served by the browser
// tier than by waiting.
const DefaultTimeout = 2 * time.Second

// ErrTimeout is returned when a snippet did not finish inside its budget. It is a distinct
// error because "the script never terminated" is a real observation about the target's code,
// not merely a failure of ours — a caller may legitimately report it (it is what the
// `Denial of service (DOM-based)` family is about) rather than discarding it.
var ErrTimeout = errors.New("script evaluation exceeded its time budget")

// run executes fn on a fresh VM under a hard interrupt, so a non-terminating snippet cannot
// wedge the caller.
func run(timeout time.Duration, fn func(vm *goja.Runtime) error) error {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	vm := goja.New()
	// No host objects are bound: the VM has no way to reach the filesystem, the network or
	// the process. That is what makes running attacker-influenced script here acceptable.
	done := make(chan error, 1)
	go func() { done <- fn(vm) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		vm.Interrupt(ErrTimeout)
		// Wait for the interrupted goroutine so the VM is not still running when we return.
		<-done
		return ErrTimeout
	}
}

// ---------------------------------------------------------------------------
// Prototype pollution
// ---------------------------------------------------------------------------

// PollutionEvidence describes what a snippet did to the object prototype chain.
type PollutionEvidence struct {
	// Polluted is true when a property that did not exist on Object.prototype before the
	// snippet ran exists after it.
	Polluted bool
	// Property is the polluted property name, empty when Polluted is false.
	Property string
	// Value is the polluted value rendered as a string, for evidence display.
	Value string
	// ReachedVia names which payload shape produced the pollution, so a report can say
	// how rather than only that.
	ReachedVia string
}

// PollutionPayload is one prototype-pollution probe: a JSON document to feed the target's
// merge function, and the property it should end up defining on Object.prototype.
type PollutionPayload struct {
	// Name identifies the payload shape.
	Name string
	// JSON is the attacker-controlled document.
	JSON string
	// Property is the property that lands on Object.prototype if the merge is unsafe.
	Property string
	// Value is what Property should equal.
	Value string
}

// PollutionPayloads returns the two documented prototype-pollution shapes.
//
// These are the publicly documented forms (`__proto__` and the
// `constructor.prototype` bypass used when a merge blocklists `__proto__` by name), not
// recovered Burp literals: burp.Zi2p's own payload table decodes to ZKM ciphertext residue
// like the other static payload arrays in that jar, so there was nothing to recover. The
// canary value is caller-supplied so two concurrent probes cannot be confused.
func PollutionPayloads(canary string) []PollutionPayload {
	if canary == "" {
		canary = "burpsyPolluted"
	}
	return []PollutionPayload{
		{
			Name:     "__proto__",
			JSON:     `{"__proto__":{"burpsyPolluted":"` + canary + `"}}`,
			Property: "burpsyPolluted",
			Value:    canary,
		},
		{
			Name:     "constructor.prototype",
			JSON:     `{"constructor":{"prototype":{"burpsyPolluted":"` + canary + `"}}}`,
			Property: "burpsyPolluted",
			Value:    canary,
		},
	}
}

// TestPrototypePollution runs mergeSource — the target's own merge/extend/clone function,
// as extracted from its JavaScript — against a pollution payload and reports whether
// Object.prototype was modified.
//
// mergeSource must evaluate to a function of two arguments (target, source); that is the
// shape every vulnerable merge helper in the wild has. The check is a genuine
// before/after comparison of Object.prototype rather than a source-text pattern match,
// which is the whole reason to have an engine here: a merge that *looks* unsafe but guards
// correctly reports clean, and one that looks safe but is not reports polluted.
func TestPrototypePollution(mergeSource string, payload PollutionPayload, timeout time.Duration) (PollutionEvidence, error) {
	var ev PollutionEvidence
	err := run(timeout, func(vm *goja.Runtime) error {
		mergeVal, err := vm.RunString("(" + mergeSource + ")")
		if err != nil {
			return fmt.Errorf("merge function did not evaluate: %w", err)
		}
		merge, ok := goja.AssertFunction(mergeVal)
		if !ok {
			return errors.New("merge source did not evaluate to a callable function")
		}
		// Prove the property is absent first. Without this a target whose prototype
		// already carried the name would be reported as freshly polluted.
		before, err := vm.RunString(`Object.prototype[` + quote(payload.Property) + `] === undefined`)
		if err != nil {
			return err
		}
		if !before.ToBoolean() {
			return fmt.Errorf("property %q already exists on Object.prototype before the probe; this VM cannot attribute pollution to the payload", payload.Property)
		}
		srcVal, err := vm.RunString("JSON.parse(" + quote(payload.JSON) + ")")
		if err != nil {
			return err
		}
		if _, err := merge(goja.Undefined(), vm.NewObject(), srcVal); err != nil {
			// A merge that throws on the payload has not polluted anything; that is a
			// clean result about this payload, not an error in our harness.
			return nil
		}
		after, err := vm.RunString(`(function(){var v = ({})[` + quote(payload.Property) + `]; return v === undefined ? null : String(v); })()`)
		if err != nil {
			return err
		}
		if goja.IsNull(after) || goja.IsUndefined(after) {
			return nil
		}
		ev.Polluted = true
		ev.Property = payload.Property
		ev.Value = after.String()
		ev.ReachedVia = payload.Name
		return nil
	})
	return ev, err
}

// ---------------------------------------------------------------------------
// Snippet source-to-sink evaluation (the weaker, no-Chrome tier)
// ---------------------------------------------------------------------------

// SnippetSink names a sink this tier can observe. It is deliberately a much shorter list
// than internal/domexec's: without a DOM, only sinks that are plain global functions can be
// shimmed honestly.
type SnippetSink string

const (
	SnippetSinkEval             SnippetSink = "eval"
	SnippetSinkFunctionCtor     SnippetSink = "Function"
	SnippetSinkSetTimeoutString SnippetSink = "setTimeout(string)"
	SnippetSinkJSONParse        SnippetSink = "JSON.parse"
)

// SnippetObservation records one sink reached with the canary.
type SnippetObservation struct {
	Sink     SnippetSink
	Argument string
}

// EvaluateSnippet runs an extracted script snippet with `location`-like source values
// supplied as a plain object, and reports which shimmable sinks received the canary.
//
// # This is strictly weaker than the browser tier, and must be reported as such
//
// There is no DOM here, so a snippet touching `document`, `innerHTML`, `location.assign`,
// storage or `postMessage` will throw or no-op rather than being observed. A caller MUST
// present a clean result from this function as "no flow observed by the DOM-less tier",
// never as "no DOM vulnerability" — the correct instrument for that claim is
// internal/domexec against real Chrome. This function exists so that a scan on a host with
// no browser degrades to a partial answer instead of no answer.
//
// sources are exposed to the snippet as globals (e.g. {"hash": "#<canary>"} becomes a
// `hash` global), which lets a caller rewrite `location.hash` to `hash` in the extracted
// text and evaluate the flow without a DOM.
func EvaluateSnippet(snippet, canary string, sources map[string]string, timeout time.Duration) ([]SnippetObservation, error) {
	var obs []SnippetObservation
	err := run(timeout, func(vm *goja.Runtime) error {
		for name, val := range sources {
			if err := vm.Set(name, val); err != nil {
				return err
			}
		}
		record := func(sink SnippetSink, arg string) {
			if canary != "" && strings.Contains(arg, canary) {
				obs = append(obs, SnippetObservation{Sink: sink, Argument: arg})
			}
		}
		// Shim each observable sink. Each returns undefined rather than executing: this
		// tier observes reachability, and actually evaluating attacker text inside the
		// same VM would let a snippet rewrite the shims and hide later flows.
		shims := map[string]SnippetSink{
			"eval":       SnippetSinkEval,
			"Function":   SnippetSinkFunctionCtor,
			"setTimeout": SnippetSinkSetTimeoutString,
		}
		for global, sink := range shims {
			s := sink
			if err := vm.Set(global, func(call goja.FunctionCall) goja.Value {
				if len(call.Arguments) > 0 {
					record(s, call.Arguments[0].String())
				}
				return goja.Undefined()
			}); err != nil {
				return err
			}
		}
		jsonObj := vm.NewObject()
		if err := jsonObj.Set("parse", func(call goja.FunctionCall) goja.Value {
			if len(call.Arguments) > 0 {
				record(SnippetSinkJSONParse, call.Arguments[0].String())
			}
			return goja.Undefined()
		}); err != nil {
			return err
		}
		if err := jsonObj.Set("stringify", func(call goja.FunctionCall) goja.Value { return goja.Undefined() }); err != nil {
			return err
		}
		if err := vm.Set("JSON", jsonObj); err != nil {
			return err
		}
		if _, err := vm.RunString(snippet); err != nil {
			// A snippet that throws — very common without a DOM — may still have reached a
			// sink before throwing, so whatever was recorded is kept and the throw is not
			// an error. Reporting it as one would discard real observations.
			return nil
		}
		return nil
	})
	return obs, err
}

// ObservationsForSink filters observations to one sink.
func ObservationsForSink(obs []SnippetObservation, sink SnippetSink) []SnippetObservation {
	var out []SnippetObservation
	for _, o := range obs {
		if o.Sink == sink {
			out = append(out, o)
		}
	}
	return out
}

// quote renders s as a JavaScript string literal via encoding/json, which is a correct
// JS-string escaper for this purpose and avoids hand-rolling one.
func quote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}
