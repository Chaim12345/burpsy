package toollog

import "testing"

// The proxy listener is a tool in this log (burpsy-react-ui-6dt), and membership is what the
// derived surfaces read: the Logger page's tool filter, its per-tool capture checkboxes and the
// histogram's seed are all built from ToolAll, so a tool that is recorded but absent from
// ToolAll is a tool the operator can neither filter to nor switch off. That is the failure the
// ToolAll seed exists to prevent — the hard-coded four-key list it replaced reported nothing at
// all for session, sequencer and comparer activity.
func TestTheProxyListenerIsAToolInTheLog(t *testing.T) {
	found := false
	for _, tool := range ToolAll {
		if tool == ToolProxy {
			found = true
		}
	}
	if !found {
		t.Fatal("ToolProxy is missing from ToolAll; the wire's tool list is seeded from it, so proxy traffic would be recorded and then unfilterable")
	}
	if ToolProxy.String() != "proxy" {
		t.Errorf("ToolProxy.String() = %q, want %q — the wire and the API's tool parameter both speak names, not ordinals", ToolProxy.String(), "proxy")
	}
	if got, ok := ToolFromName("proxy"); !ok || got != ToolProxy {
		t.Errorf("ToolFromName(%q) = %v, %v; want ToolProxy, true — the capture toggle addresses tools by name", "proxy", got, ok)
	}
	if !New().Capturing(ToolProxy) {
		t.Error("a fresh log does not capture proxy traffic; every tool captures by default, and the seed is derived from ToolAll's length")
	}
}

// captureAll is 1<<len(ToolAll)-1, so a tool appended to ToolAll without the mask following
// would be captured by the default seed and then silently missed by "capture all"/"capture
// none" — a switch that reports a state it does not reach.
func TestTheAllToolsMaskCoversTheProxyTool(t *testing.T) {
	l := New()
	l.SetAllCapturing(false)
	if l.Capturing(ToolProxy) {
		t.Error("SetAllCapturing(false) left proxy capture on")
	}
	l.SetAllCapturing(true)
	if !l.Capturing(ToolProxy) {
		t.Error("SetAllCapturing(true) did not restore proxy capture — the all-tools mask is one bit short of the tool list")
	}
}
