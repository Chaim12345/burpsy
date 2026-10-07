package web

import (
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// 2cvk: Burp's auto-pause. The engine, the wire field and the report counter all shipped with 8f2,
// and no control anywhere in the console could set them — so the only way to halt a spray was the
// manual pause, which requires watching the attack. These tests pin the wire contract the console's
// new controls now send, and the refusal the console shows beside the field.

type autoPauseView struct {
	Report struct {
		Sent       int `json:"sent"`
		Planned    int `json:"planned"`
		AutoPaused int `json:"auto_paused"`
	} `json:"report"`
}

// queryPoints discovers the insertion points for a stored request, failing the test if the request
// has none. Every test below needs at least one position, and a silent zero would make an attack
// that sends nothing look like an attack that was paused.
func queryPoints(t *testing.T, srv *Server, id uint64) []wirePoint {
	t.Helper()
	var points []wirePoint
	code := postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "all": false}, &points)
	if code != http.StatusOK {
		t.Fatalf("points status = %d", code)
	}
	return points
}

// The console sends this block only when the operator has turned the switch on AND typed at least
// one expression. Every key here is one the console can produce, and the test fails if the server
// stops accepting one of them — a rename on either side that leaves the control silently inert.
func TestTheConsoleAutoPauseBlockIsAccepted(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())
	id := requestMessage(t, store, "GET /?q=alpha HTTP/1.1\r\nHost: t.test\r\n\r\n")

	points := queryPoints(t, srv, id)
	if len(points) == 0 {
		t.Fatalf("no insertion points for the request")
	}
	target := "http://" + echoServer(t)
	body := map[string]any{
		"msg_id":       id,
		"target":       target,
		"mode":         "sniper",
		"points":       []int{points[0].Index},
		"max_requests": 20,
		"payload_sources": []map[string]any{
			{"type": "list", "items": []string{"one", "two", "three", "four", "five", "six"}},
		},
		"auto_pause": map[string]any{
			"expressions":    []string{"zebra-never-appears"},
			"missing":        false,
			"simple":         true,
			"case_sensitive": true,
		},
	}

	var out autoPauseView
	if code := postJSONInto(t, srv, "/api/intruder/run", body, &out); code != http.StatusOK {
		t.Fatalf("run status = %d, want 200; the console's block is the shape api_tools.go's autoPauseReq decodes", code)
	}
	// Every payload is served by the echo target and none contains the expression, so an
	// auto-pause that fired here would have paused on the very first response.
	if out.Report.AutoPaused != 0 {
		t.Errorf("auto_paused = %d, want 0 — no response contains %q", out.Report.AutoPaused, "zebra-never-appears")
	}
	if out.Report.Sent == 0 {
		t.Errorf("sent = 0; an unconfigured-looking block was read as \"pause immediately\" and stopped the attack")
	}
}

// The control that matters: "missing" INVERTS the test, so an attack pauses on the response that
// STOPS carrying the signal. This is the pause an operator cannot perform by watching — the spray
// goes quiet and nothing on screen changes — which is the whole reason the feature exists, and it
// has no equivalent in the appears-mode test above.
//
// One payload, so the pause fires on the last request and the run ends rather than holding on a
// live attack: Control.Pause blocks until resumed, so a fire mid-run leaves the handler waiting and
// the assertions below would never run. The inversion is proved by the fired count being non-zero
// for a signal that is ABSENT from every response — which appears-mode, given the same payload,
// would not produce.
func TestAutoPauseFiresInMissingModeOnASignalThatNeverAppears(t *testing.T) {
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /?q=alpha HTTP/1.1\r\nHost: t.test\r\n\r\n")

	points := queryPoints(t, srv, id)
	var out autoPauseView
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + echoServer(t),
		"mode":         "sniper",
		"points":       []int{points[0].Index},
		"max_requests": 10,
		"payload_sources": []map[string]any{
			{"type": "list", "items": []string{"payload-with-no-such-text"}},
		},
		"auto_pause": map[string]any{
			"expressions": []string{"lockout-banner-text"},
			"missing":     true,
			"simple":      true,
		},
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d", code)
	}
	if out.Report.AutoPaused == 0 {
		t.Fatalf("auto_paused = 0: the signal %q is absent from every response, so missing mode must "+
			"fire. This is the pause an operator cannot perform by watching.", "lockout-banner-text")
	}
}

// And the inversion is real rather than a missing flag being ignored: the SAME expression in
// appears mode, against the same responses, must NOT pause. Without this, a server that treated
// `missing` as always-true would pass the test above.
func TestTheSameSignalDoesNotPauseInAppearsMode(t *testing.T) {
	store := core.NewTrafficStore()
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	srv := NewServer(store, scope)
	id := requestMessage(t, store, "GET /?q=alpha HTTP/1.1\r\nHost: t.test\r\n\r\n")

	points := queryPoints(t, srv, id)
	var out autoPauseView
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + echoServer(t),
		"mode":         "sniper",
		"points":       []int{points[0].Index},
		"max_requests": 10,
		"payload_sources": []map[string]any{
			{"type": "list", "items": []string{"payload-with-no-such-text"}},
		},
		"auto_pause": map[string]any{
			"expressions": []string{"lockout-banner-text"},
			"missing":     false,
			"simple":      true,
		},
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d", code)
	}
	if out.Report.AutoPaused != 0 {
		t.Errorf("auto_paused = %d in appears mode for a signal no response carries; the two modes are "+
			"inverted, and a server treating `missing` as always-true would pass the test above", out.Report.AutoPaused)
	}
}

// An uncompilable expression is a 400, and it is the one the console re-homes to the field: the
// operator's next action is to edit the expression, not to read a report for an attack that visibly
// did nothing. A 200 here would mean the console's field error can never fire.
func TestAnUncompilableAutoPauseExpressionIsRefusedRatherThanIgnored(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())
	id := requestMessage(t, store, "GET /?q=alpha HTTP/1.1\r\nHost: t.test\r\n\r\n")
	points := queryPoints(t, srv, id)

	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":       id,
		"target":       "http://" + echoServer(t),
		"mode":         "sniper",
		"points":       []int{points[0].Index},
		"max_requests": 5,
		"payload_sources": []map[string]any{
			{"type": "list", "items": []string{"a"}},
		},
		"auto_pause": map[string]any{
			"expressions": []string{"([unclosed"},
			"missing":     false,
			"simple":      false, // regex, so the expression is compiled
		},
	}, &autoPauseView{})
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; an auto-pause that silently never fires is a control that "+
			"lies by omission, so it must be refused here rather than at the target", code)
	}
}

// The wire contract the console depends on: the block is all-or-nothing. A request carrying
// auto_pause with no expressions is the shape the console deliberately never sends — an absent
// field and an empty list must not both mean "I did not choose" — and the server reads it as
// unconfigured, which is what makes that omission honest.
func TestAnAutoPauseWithNoExpressionsIsUnconfiguredRatherThanAPauseOnNothing(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())
	id := requestMessage(t, store, "GET /?q=alpha HTTP/1.1\r\nHost: t.test\r\n\r\n")
	points := queryPoints(t, srv, id)
	target := "http://" + echoServer(t)

	base := func() map[string]any {
		return map[string]any{
			"msg_id":       id,
			"target":       target,
			"mode":         "sniper",
			"points":       []int{points[0].Index},
			"max_requests": 6,
			"payload_sources": []map[string]any{
				{"type": "list", "items": []string{"p1", "p2", "p3", "p4", "p5", "p6"}},
			},
		}
	}

	// Two attacks that differ ONLY in whether the block is present at all, so a difference in what
	// the server did could only have come from the block.
	withBlock := base()
	withBlock["auto_pause"] = map[string]any{"expressions": []string{}, "missing": false, "simple": true}
	without := base()

	var a, b autoPauseView
	if code := postJSONInto(t, srv, "/api/intruder/run", withBlock, &a); code != http.StatusOK {
		t.Fatalf("with an empty expression list: status = %d", code)
	}
	if code := postJSONInto(t, srv, "/api/intruder/run", without, &b); code != http.StatusOK {
		t.Fatalf("with no block at all: status = %d", code)
	}
	if a.Report.AutoPaused != b.Report.AutoPaused {
		t.Errorf("auto_paused = %d with an empty list and %d with no block; the two must agree, or "+
			"the console's omission of the field changes what the server does",
			a.Report.AutoPaused, b.Report.AutoPaused)
	}
	if b.Report.AutoPaused != 0 {
		t.Errorf("auto_paused = %d with no block at all; an unconfigured auto-pause must not pause "+
			"anything, and a test with no block would otherwise pass for the wrong reason", b.Report.AutoPaused)
	}
}
