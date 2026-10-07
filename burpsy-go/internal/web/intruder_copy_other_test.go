package web

import (
	"net/http"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// 2g13: Burp's Copy other payload — a position's payload, on every request, is whichever
// payload a named earlier position received for that same request. See CopyOtherSource's own
// doc in internal/intruder/payload.go for why this is resolved at the caller (here) rather
// than as an ordinary generator, and why it is refused outside pitchfork.

type copyOtherRunView struct {
	Report struct {
		Sent int `json:"sent"`
	} `json:"report"`
	Examples []struct {
		FirstOrdinal int      `json:"first_ordinal"`
		Payloads     []string `json:"payloads"`
	} `json:"examples"`
}

func TestCopyOtherMirrorsAnEarlierPositionInPitchfork(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())
	// Two query params, both discoverable insertion points, so a pitchfork attack has two
	// positions to work with: "user" gets its own list, "confirm" copies position 0.
	id := requestMessage(t, store, "GET /?user=a&confirm=b HTTP/1.1\r\nHost: t.test\r\n\r\n")

	var points []wirePoint
	if code := postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "all": false}, &points); code != http.StatusOK {
		t.Fatalf("points status = %d", code)
	}
	var userIdx, confirmIdx = -1, -1
	for _, p := range points {
		if p.Kind == "url_param_value" && p.Label == "user" {
			userIdx = p.Index
		}
		if p.Kind == "url_param_value" && p.Label == "confirm" {
			confirmIdx = p.Index
		}
	}
	if userIdx < 0 || confirmIdx < 0 {
		t.Fatalf("expected both url_param_value points, got %+v", points)
	}

	var out copyOtherRunView
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id": id,
		"target": "http://" + echoServer(t),
		"mode":   "pitchfork",
		"points": []int{userIdx, confirmIdx},
		"payload_sources": []map[string]any{
			{"type": "list", "items": []string{"alice", "bob"}},
			{"type": "copy_other", "position": 0},
		},
		"max_requests": 10,
	}, &out)
	if code != http.StatusOK {
		t.Fatalf("run status = %d", code)
	}
	if out.Report.Sent != 2 {
		t.Fatalf("sent = %d, want 2 (one per pitchfork row)", out.Report.Sent)
	}
	if len(out.Examples) == 0 {
		t.Fatalf("no examples returned")
	}
	for _, ex := range out.Examples {
		if len(ex.Payloads) != 2 {
			t.Fatalf("ordinal %d: payloads = %v, want one per position", ex.FirstOrdinal, ex.Payloads)
		}
		if ex.Payloads[0] != ex.Payloads[1] {
			t.Fatalf("ordinal %d: position 0 = %q, position 1 (copy_other) = %q — must match",
				ex.FirstOrdinal, ex.Payloads[0], ex.Payloads[1])
		}
	}
}

func TestCopyOtherIsRefusedOutsidePitchfork(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())
	id := requestMessage(t, store, "GET /?user=a&confirm=b HTTP/1.1\r\nHost: t.test\r\n\r\n")

	var points []wirePoint
	postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "all": false}, &points)
	var userIdx, confirmIdx = -1, -1
	for _, p := range points {
		if p.Label == "user" {
			userIdx = p.Index
		}
		if p.Label == "confirm" {
			confirmIdx = p.Index
		}
	}

	body := httpBody(t, srv, map[string]any{
		"msg_id": id,
		"target": "http://" + echoServer(t),
		"mode":   "cluster_bomb",
		"points": []int{userIdx, confirmIdx},
		"payload_sources": []map[string]any{
			{"type": "list", "items": []string{"alice", "bob"}},
			{"type": "copy_other", "position": 0},
		},
		"max_requests": 10,
	})
	if body == "" {
		t.Fatal("expected a 400 body explaining copy_other is pitchfork-only")
	}
}

func TestCopyOtherRefusesAForwardOrSelfReference(t *testing.T) {
	store := core.NewTrafficStore()
	srv := NewServer(store, core.NewScope())
	id := requestMessage(t, store, "GET /?user=a&confirm=b HTTP/1.1\r\nHost: t.test\r\n\r\n")

	var points []wirePoint
	postJSONInto(t, srv, "/api/intruder/points", map[string]any{"msg_id": id, "all": false}, &points)
	var userIdx, confirmIdx = -1, -1
	for _, p := range points {
		if p.Label == "user" {
			userIdx = p.Index
		}
		if p.Label == "confirm" {
			confirmIdx = p.Index
		}
	}

	// position 0 (user) tries to copy position 1 (confirm) — a forward reference, not yet
	// resolved when position 0 itself is being resolved.
	body := httpBody(t, srv, map[string]any{
		"msg_id": id,
		"target": "http://" + echoServer(t),
		"mode":   "pitchfork",
		"points": []int{userIdx, confirmIdx},
		"payload_sources": []map[string]any{
			{"type": "copy_other", "position": 1},
			{"type": "list", "items": []string{"alice", "bob"}},
		},
		"max_requests": 10,
	})
	if body == "" {
		t.Fatal("expected a 400 body explaining the forward reference")
	}
}
