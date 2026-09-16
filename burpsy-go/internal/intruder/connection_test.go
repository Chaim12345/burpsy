package intruder

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// Burp's "Set Connection header" and "Store full payloads" attack settings
// (burpsy-react-ui-fmxv). Every test here asks the same question in a different place: does the
// setting change what actually goes on the wire, or what the report actually says. A setting that
// only changes a struct field is the defect this repo calls a no-op control.

// captureAttack runs a small sniper attack and hands back every request the sender was given, in
// send order, plus the report. The sender answers identically every time, so nothing in the
// assertions can depend on response content.
func captureAttack(t *testing.T, tmpl string, build func(*Attack) *Attack) ([][]byte, *AttackReport) {
	t.Helper()
	base, pts := basePoints(t, tmpl)
	if len(pts) == 0 {
		t.Fatalf("the template %q produced no insertion points; the fixture cannot test a splice", tmpl)
	}
	payloads := sets([]string{"alpha", "beta", "gamma"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{3}, 100)
	a := NewAttack(base, pts[:1], payloads, plan)
	a.Limits = Unthrottled(1)
	if build != nil {
		a = build(a)
	}

	var mu sync.Mutex
	var seen [][]byte
	send := func(raw []byte) (Sent, error) {
		mu.Lock()
		seen = append(seen, append([]byte(nil), raw...))
		mu.Unlock()
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), Status: intPtrHelper(200)}, nil
	}
	r := Run(a, send, nil)
	mu.Lock()
	defer mu.Unlock()
	return seen, r
}

func countHeader(raw []byte, name string) int {
	n := 0
	for _, line := range bytes.Split(raw, []byte("\r\n")) {
		if i := bytes.IndexByte(line, ':'); i > 0 &&
			strings.EqualFold(string(line[:i]), name) {
			n++
		}
	}
	return n
}

// The setting is off by default, and off means the template's own bytes reach the wire. Without
// this the other tests could all pass against an engine that sets the header unconditionally.
func TestConnectionHeaderIsUntouchedWhenTheSettingIsOff(t *testing.T) {
	seen, _ := captureAttack(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n", nil)
	if len(seen) != 3 {
		t.Fatalf("expected the 3 planned requests, got %d", len(seen))
	}
	for i, raw := range seen {
		if bytes.Contains(bytes.ToLower(raw), []byte("connection:")) {
			t.Errorf("request %d carries a Connection header the template never had and the attack never asked for:\n%q", i, raw)
		}
	}
}

// Burp: "Add or update the Connection header with the value close." The add half, on every
// request the attack sends rather than on the first.
func TestSetConnectionCloseAddsTheHeaderToEveryRequest(t *testing.T) {
	seen, _ := captureAttack(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n", func(a *Attack) *Attack {
		return a.WithSetConnectionClose(true)
	})
	if len(seen) != 3 {
		t.Fatalf("expected the 3 planned requests, got %d", len(seen))
	}
	for i, raw := range seen {
		if !bytes.Contains(raw, []byte("\r\nConnection: close\r\n")) {
			t.Errorf("request %d went out without Connection: close, so the setting changed nothing on the wire:\n%q", i, raw)
		}
		if n := countHeader(raw, "connection"); n != 1 {
			t.Errorf("request %d carries %d Connection headers; a duplicated header is a framing disagreement, not a setting:\n%q", i, n, raw)
		}
	}
}

// The update half. An existing header keeps its own name spelling and its own position; only the
// value changes. A setting that rewrote the whole line would silently normalise a template the
// operator wrote deliberately.
func TestSetConnectionCloseReplacesOnlyTheValueOfAnExistingHeader(t *testing.T) {
	tmpl := "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\nCONNECTION:   keep-alive\r\nX-Tail: end\r\n\r\n"
	seen, _ := captureAttack(t, tmpl, func(a *Attack) *Attack {
		return a.WithSetConnectionClose(true)
	})
	if len(seen) == 0 {
		t.Fatal("no requests were sent")
	}
	raw := seen[0]
	if !bytes.Contains(raw, []byte("CONNECTION:   close\r\n")) {
		t.Errorf("the existing header was not updated in place — its name casing or its separator was rewritten:\n%q", raw)
	}
	if n := countHeader(raw, "connection"); n != 1 {
		t.Errorf("updating produced %d Connection headers instead of 1:\n%q", n, raw)
	}
	if !bytes.Contains(raw, []byte("X-Tail: end\r\n")) {
		t.Errorf("a header after the Connection header was lost or moved:\n%q", raw)
	}
	if bytes.Contains(raw, []byte("keep-alive")) {
		t.Errorf("the old Connection value survived the update:\n%q", raw)
	}
}

// The setting runs AFTER the splice. This is the test that would catch the ordering mistake: an
// insertion point is a byte offset into the base request, so a header added before the splice
// moves every span after it and the payload lands in the wrong bytes. The Host header sits before
// the query here and the payload sits in the query, so an inserted header that shifted spans would
// corrupt exactly this request.
func TestSetConnectionCloseDoesNotShiftTheInsertionPoints(t *testing.T) {
	tmpl := "GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n"
	withHeader, _ := captureAttack(t, tmpl, func(a *Attack) *Attack {
		return a.WithSetConnectionClose(true)
	})
	without, _ := captureAttack(t, tmpl, nil)
	if len(withHeader) != len(without) || len(without) == 0 {
		t.Fatalf("the two runs sent different numbers of requests (%d vs %d)", len(withHeader), len(without))
	}
	for i := range without {
		want := setConnectionClose(without[i])
		if !bytes.Equal(withHeader[i], want) {
			t.Errorf("request %d differs from the same request with only the header added:\n with setting: %q\n expected:     %q\nthe payload splice moved when the header did", i, withHeader[i], want)
		}
		if !bytes.Contains(withHeader[i], []byte("?a=alpha&b=2")) &&
			!bytes.Contains(withHeader[i], []byte("?a=beta&b=2")) &&
			!bytes.Contains(withHeader[i], []byte("?a=gamma&b=2")) {
			t.Errorf("request %d has no payload in the first query parameter; the splice landed somewhere else:\n%q", i, withHeader[i])
		}
	}
}

// Burp's baseline request (v34) is "the template request with all payload positions set to their
// base values", and it exists to be compared against the attack rows. A baseline sent without the
// header every attack row carries would be the one row that is not comparable.
func TestSetConnectionCloseAlsoAppliesToTheBaselineRequest(t *testing.T) {
	seen, _ := captureAttack(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n", func(a *Attack) *Attack {
		return a.WithSetConnectionClose(true).WithBaseline(true)
	})
	if len(seen) != 4 {
		t.Fatalf("expected the baseline plus 3 attack requests, got %d", len(seen))
	}
	for i, raw := range seen {
		if !bytes.Contains(raw, []byte("Connection: close")) {
			t.Errorf("request %d (the baseline is one of these) went out without the header the rest carry:\n%q", i, raw)
		}
	}
}

// A template that already says close is left byte-identical, so an attack cannot be told apart
// from the same attack with the box ticked.
func TestSetConnectionCloseLeavesAnAlreadyClosingTemplateAlone(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: t.test\r\nConnection: Close\r\n\r\n")
	out := setConnectionClose(raw)
	if !bytes.Equal(raw, out) {
		t.Errorf("a template already carrying Connection: Close was rewritten:\n in:  %q\n out: %q", raw, out)
	}
}

// A bare-LF template stays bare LF. The attack template is the operator's bytes; this setting is a
// licence to set one header, not to reframe a request somebody wrote on purpose.
func TestSetConnectionCloseKeepsTheTemplatesOwnLineEnding(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\nHost: t.test\n\n")
	out := setConnectionClose(raw)
	if bytes.Contains(out, []byte("\r\n")) {
		t.Errorf("a bare-LF request was reframed with CRLF:\n%q", out)
	}
	if !bytes.Contains(out, []byte("\nConnection: close\n")) {
		t.Errorf("the header was not added to a bare-LF request:\n%q", out)
	}
}

// A request with no header terminator has nowhere honest to put a header, so it goes out as
// written rather than with a guessed one bolted on.
func TestSetConnectionCloseRefusesAnUnparseableRequest(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: t.test")
	if out := setConnectionClose(raw); !bytes.Equal(raw, out) {
		t.Errorf("a request with no header terminator was rewritten on a guess:\n in:  %q\n out: %q", raw, out)
	}
}

// ---- Store full payloads -----------------------------------------------------------------

// The assertion is on the MARSHALLED JSON, not the struct: the wire contract is what a reader
// sees, and a Go nil slice and an empty one are the same struct field and different JSON.
func attemptJSON(t *testing.T, r *AttackReport, ordinal int) map[string]any {
	t.Helper()
	for _, a := range r.Attempts {
		if a.Ordinal != ordinal {
			continue
		}
		b, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	t.Fatalf("the report has no attempt row for ordinal %d", ordinal)
	return nil
}

// Off is Burp's default and burpsy's: the field is ABSENT, not an empty array. Absent says "this
// attack did not store payload values"; an empty array would say "this attempt had no payloads",
// which is a real and different state (the baseline row).
func TestStorePayloadsOmitsThePayloadFieldWhenNotAsked(t *testing.T) {
	_, r := captureAttack(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n", nil)
	m := attemptJSON(t, r, 0)
	if v, ok := m["payloads"]; ok {
		t.Errorf("an attack that did not ask to store payloads emitted payloads=%v; absent is what tells a reader the values were not kept", v)
	}
}

// On: every kept row names the payload that produced it, in position order.
func TestStorePayloadsNamesThePayloadBehindEveryRow(t *testing.T) {
	_, r := captureAttack(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n", func(a *Attack) *Attack {
		return a.WithStorePayloads(true)
	})
	want := []string{"alpha", "beta", "gamma"}
	if len(r.Attempts) != 3 {
		t.Fatalf("expected 3 attempt rows, got %d", len(r.Attempts))
	}
	for i, a := range r.Attempts {
		if len(a.Payloads) != 1 || a.Payloads[0] != want[a.Ordinal] {
			t.Errorf("row %d (ordinal %d) reports payloads %v; the plan sent %q, so the report cannot name what it did", i, a.Ordinal, a.Payloads, want[a.Ordinal])
		}
		m := attemptJSON(t, r, a.Ordinal)
		if _, ok := m["payloads"]; !ok {
			t.Errorf("ordinal %d stored a payload in the struct but omitted it from the JSON; the wire is what a reader gets", a.Ordinal)
		}
	}
}

// The baseline row is the honest empty case: it is a request with no payloads at all, and with
// storing ON it must say so rather than borrowing the first attack payload's name.
func TestStorePayloadsLeavesTheBaselineRowWithoutPayloads(t *testing.T) {
	_, r := captureAttack(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n", func(a *Attack) *Attack {
		return a.WithStorePayloads(true).WithBaseline(true)
	})
	for _, a := range r.Attempts {
		if a.Ordinal != 0 {
			continue
		}
		if len(a.Payloads) != 0 {
			t.Errorf("the baseline row (ordinal 0) names payloads %v; Burp's baseline is the template with no payloads at all", a.Payloads)
		}
		return
	}
	t.Fatal("the report has no baseline row")
}
