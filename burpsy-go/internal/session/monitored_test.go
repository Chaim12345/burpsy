package session

// The monitored-tool set (burpsy-react-ui-sn3j) — Burp's "configure the cookie jar to monitor
// any of the following tools: Proxy, Intruder, Scanner, Sequencer, Repeater, Extensions".
//
// The three-state honesty this file holds the coordinator to:
//
//   - by default every source monitors: the switch must not reproduce the
//     "a jar the UI says X fills and X does not fill" state AbsorbResponseCookies was written
//     to end;
//   - a source switched off still counts as OBSERVED — the wiring is real either way, and an
//     operator debugging an empty jar must be able to tell "the Repeater is attached and
//     traffic flows" from "the Repeater never registered";
//   - an empty set is not "monitor nothing": it is the zero value of a missed wire field, and
//     reading it as a real request would silently stop the jar filling.
import (
	"sort"
	"testing"
)

func TestDefaultIsEverySourceMonitors(t *testing.T) {
	c := NewCoordinator(nil)
	resp := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc\r\n\r\n")
	// A source that never existed before this change — no SetMonitoredSources call — absorbs.
	if n := c.AbsorbResponseCookies(SourceProxy, "app.test", 443, true, resp); n != 1 {
		t.Fatalf("proxy absorbed %d with the default set, want 1 — the switch must default to on or it reproduces the state AbsorbResponseCookies exists to end", n)
	}
	if n := c.AbsorbResponseCookies(SourceRepeater, "app.test", 443, true, resp); n != 1 {
		t.Errorf("repeater absorbed %d with the default set, want 1", n)
	}
}

func TestASwitchedOffSourceObservesButDoesNotAbsorb(t *testing.T) {
	c := NewCoordinator(nil)
	c.AttachAbsorptionSource(SourceRepeater)
	c.SetMonitoredSources([]string{"proxy"})

	resp := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc\r\n\r\n")
	if n := c.AbsorbResponseCookies(SourceRepeater, "app.test", 443, true, resp); n != 0 {
		t.Fatalf("the switched-off repeater absorbed %d, want 0", n)
	}
	if h := c.CookieHeader("app.test", 443, true, "/"); h != "" {
		t.Errorf("cookie header = %q after a switched-off source, want empty: the cookie must not be in the jar", h)
	}
	// But the response was OBSERVED — the wiring is real, and the observation must say so.
	if obs := c.Observation(); obs.ResponsesObserved != 1 {
		t.Errorf("responses observed = %d, want 1 — a switched-off source still counts its traffic or an empty jar cannot be debugged", obs.ResponsesObserved)
	}
	// And the proxy, still monitored, absorbs the same response.
	if n := c.AbsorbResponseCookies(SourceProxy, "app.test", 443, true, resp); n != 1 {
		t.Errorf("the monitored proxy absorbed %d, want 1", n)
	}
}

func TestTheEmptySetIsRefusedNotHonoured(t *testing.T) {
	c := NewCoordinator(nil)
	resp := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc\r\n\r\n")
	c.SetMonitoredSources([]string{"  "}) // trims to nothing — the zero value a missed field sends
	if n := c.AbsorbResponseCookies(SourceProxy, "app.test", 443, true, resp); n != 1 {
		t.Fatalf("an empty monitored request absorbed %d, want 1 — empty is a missed wire field, not an operator asking to monitor nothing", n)
	}
}

func TestMonitoredSourcesReportsTheSetInForce(t *testing.T) {
	c := NewCoordinator(nil)
	c.AttachAbsorptionSource(SourceProxy)
	c.AttachAbsorptionSource(SourceRepeater)

	// Default: every attached source.
	got := c.MonitoredSources()
	sort.Strings(got)
	if len(got) != 2 || got[0] != "proxy" || got[1] != "repeater" {
		t.Errorf("default monitored = %v, want [proxy repeater]", got)
	}

	// Configured: the subset, sorted.
	c.SetMonitoredSources([]string{"repeater", "proxy", "repeater"})
	got = c.MonitoredSources()
	if len(got) != 2 || got[0] != "proxy" || got[1] != "repeater" {
		t.Errorf("configured monitored = %v, want [proxy repeater] sorted and deduped", got)
	}

	// A name no surface attaches yet is kept — monitored for the day it attaches, the same
	// registered-when-wired rule AttachAbsorptionSource holds.
	c.SetMonitoredSources([]string{"intruder"})
	if got := c.MonitoredSources(); len(got) != 1 || got[0] != "intruder" {
		t.Errorf("monitored after naming an unattached source = %v, want [intruder] kept", got)
	}
}
