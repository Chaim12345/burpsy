package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Every field the browser declares as an array must reach it as one (burpsy-react-ui-9pxd).
//
// This is a wire test and not a struct test because Go cannot see the defect: a nil slice and an
// empty slice have the same len, range identically, and every other test in this package passed
// against either. The difference exists only in JSON, where nil becomes `null` — and
// internal/web/ui/src/lib/types.tools.ts declares these fields non-nullable, so the page reads
// `.length` on them without a guard. It was right to; the server was wrong.
//
// The cost of getting it wrong was the whole Results tab: a completed attack whose sends all
// succeeded has no error groups and no dropped payloads, so `report.errors` and
// `payload_sets[].dropped` both went out as `null`, `AttackResult` threw on the first one it read,
// and the operator got "This view failed to render" in place of their attack. It survived because
// nothing in this tree had ever rendered a real report — the browser suite covers the 17 routes and
// their empty states, and never launches an attack.
//
// The clean-run case is the one that mattered, so it is the case this pins.
func TestACleanIntruderRunSendsArraysNotNullsForEveryRowField(t *testing.T) {
	addr := echoServer(t)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")

	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, store, raw)

	// Deliberately the happiest path there is: a reachable target, no processing rules to drop a
	// payload, no bound to truncate a set. Every one of the fields below is therefore empty, which
	// is exactly the state that used to marshal as null.
	// One position, marked the way TestIntruderRunAcceptsAManualPoint marks it, so this test's
	// subject is the response shape and not the request form.
	start := strings.Index(raw, "pha")
	var body json.RawMessage
	code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
		"msg_id":        id,
		"target":        "http://" + addr,
		"mode":          "sniper",
		"manual_points": []map[string]int{{"start": start, "end": start + 3}},
		"payload_sets":  [][]string{{"xyz", "wxyz"}},
		"max_requests":  100,
		"rps":           1000,
	}, &body)
	if code != http.StatusOK {
		t.Fatalf("run status = %d, want 200: %s", code, body)
	}

	// Decoded as raw fields rather than into the real view types: the point is what the bytes say,
	// and unmarshalling into []DropReason would turn the null this is hunting back into a nil slice
	// and report success.
	var view struct {
		Report struct {
			Failed   int             `json:"failed"`
			Buckets  json.RawMessage `json:"buckets"`
			Errors   json.RawMessage `json:"errors"`
			Attempts json.RawMessage `json:"attempts"`
		} `json:"report"`
		Examples []struct {
			Payloads json.RawMessage `json:"payloads"`
		} `json:"examples"`
		PayloadSets []struct {
			Dropped json.RawMessage `json:"dropped"`
		} `json:"payload_sets"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("unmarshal run view: %v\n%s", err, body)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("unmarshal top level: %v\n%s", err, body)
	}
	if view.Report.Failed != 0 {
		t.Fatalf("this fixture is meant to have nothing fail (%d did), or it is not testing the clean path: %s",
			view.Report.Failed, body)
	}

	array := func(name string, raw json.RawMessage) {
		t.Helper()
		if len(raw) == 0 {
			t.Fatalf("%s is absent from the response: %s", name, body)
		}
		if string(raw) == "null" {
			t.Fatalf("%s went out as null; types.tools.ts declares it an array and the page reads .length on it", name)
		}
		if raw[0] != '[' {
			t.Fatalf("%s is not a JSON array: %s", name, raw)
		}
	}
	array("report.buckets", view.Report.Buckets)
	array("report.errors", view.Report.Errors)
	array("report.attempts", view.Report.Attempts)
	array("examples", top["examples"])
	array("payload_sets", top["payload_sets"])
	if len(view.PayloadSets) == 0 {
		t.Fatalf("no payload sets in the response, so its dropped field was never checked: %s", body)
	}
	for i, set := range view.PayloadSets {
		array("payload_sets["+strconv.Itoa(i)+"].dropped", set.Dropped)
	}
	if len(view.Examples) == 0 {
		t.Fatalf("no examples in the response, so their payloads field was never checked: %s", body)
	}
	for i, example := range view.Examples {
		array("examples["+strconv.Itoa(i)+"].payloads", example.Payloads)
	}
	// Not asserted: "the response contains no null anywhere". Pointer fields marshal as null
	// legitimately and by design — status on a send that got no response, grep_extract, pool,
	// request_id on a row with nothing stored — so only the fields named above are contractual
	// arrays, and naming them is what makes this a check rather than a grep.
}

// The send-settings fields the Results tab reads (burpsy-react-ui-xixe.1, Phase 1) are always present
// in the marshalled report, and each has the JSON type types.tools.ts declares. None of them is an
// array, so the hazard is different from the one above: an absent key, or a null where the page does
// arithmetic. connections_* are null BY DESIGN when reuse is off — "not counted" — and a number when
// it is on, and the two runs below pin both.
func TestIntruderSendSettingsFieldsAreOnTheWireWithTheirTypes(t *testing.T) {
	addr := echoServer(t)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, store, raw)
	start := strings.Index(raw, "pha")

	for _, reuse := range []bool{false, true} {
		var body json.RawMessage
		code := postJSONInto(t, srv, "/api/intruder/run", map[string]any{
			"msg_id":                 id,
			"target":                 "http://" + addr,
			"mode":                   "sniper",
			"manual_points":          []map[string]int{{"start": start, "end": start + 3}},
			"payload_sets":           [][]string{{"xyz", "wxyz"}},
			"rps":                    1000,
			"http1_connection_reuse": reuse,
			"update_host_header":     true,
		}, &body)
		if code != http.StatusOK {
			t.Fatalf("reuse=%v: run status = %d: %s", reuse, code, body)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(body, &top); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		kind := func(name string) string {
			t.Helper()
			raw, ok := top[name]
			if !ok {
				t.Fatalf("reuse=%v: %s is absent from the response: %s", reuse, name, body)
			}
			switch {
			case string(raw) == "null":
				return "null"
			case string(raw) == "true" || string(raw) == "false":
				return "bool"
			case raw[0] == '"':
				return "string"
			case raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9'):
				return "number"
			}
			return "other:" + string(raw)
		}
		wantCount := "null"
		if reuse {
			wantCount = "number"
		}
		for name, want := range map[string]string{
			"connections_opened":    wantCount,
			"connections_reused":    wantCount,
			"host_header_updated":   "bool",
			"host_header_skipped":   "string",
			"host_header_untouched": "number",
		} {
			if got := kind(name); got != want {
				t.Fatalf("reuse=%v: %s is %s on the wire, want %s: %s", reuse, name, got, want, top[name])
			}
		}
		if string(top["host_header_updated"]) != "true" {
			t.Fatalf("update_host_header was asked for and the report says %s", top["host_header_updated"])
		}
	}
}

// Grep - Payloads' count arrays (burpsy-react-ui-7qc3) are arrays on every row the page reads —
// attempts and buckets, with the setting on, off, and on a row whose send failed — and the report
// carries the settings it ran with as an object. types.tools.ts declares the arrays non-nullable.
func TestGrepPayloadsCountArraysAreArraysOnEveryRow(t *testing.T) {
	addr := echoServer(t)
	scope := core.NewScope()
	scope.AddInclude("127.0.0.1")
	store := core.NewTrafficStore()
	srv := NewServer(store, scope)
	raw := "GET /search?q=alpha HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	id := requestMessage(t, store, raw)
	start := strings.Index(raw, "pha")

	type row struct {
		Error           *string         `json:"error"`
		ReflectedCounts json.RawMessage `json:"reflected_counts"`
	}
	type bucket struct {
		ReflectedCountTotals json.RawMessage `json:"reflected_count_totals"`
	}
	for _, tc := range []struct {
		name   string
		target string
		grep   any
		want   string // the attempt rows' reflected_counts
	}{
		{"absent (legacy, on)", "http://" + addr, nil, "[1]"},
		{"off", "http://" + addr, map[string]any{"enabled": false}, "[]"},
		{"on, send failed", "http://127.0.0.1:1", map[string]any{"enabled": true}, "[]"},
	} {
		body := map[string]any{
			"msg_id": id, "target": tc.target, "mode": "sniper",
			"manual_points": []map[string]int{{"start": start, "end": start + 3}},
			"payload_sets":  [][]string{{"xyz", "wxyz"}}, "rps": 1000, "retries": 0,
		}
		if tc.grep != nil {
			body["grep_payloads"] = tc.grep
		}
		var out json.RawMessage
		if code := postJSONInto(t, srv, "/api/intruder/run", body, &out); code != http.StatusOK {
			t.Fatalf("%s: run = %d: %s", tc.name, code, out)
		}
		var view struct {
			Report struct {
				Attempts     []row           `json:"attempts"`
				Buckets      []bucket        `json:"buckets"`
				GrepPayloads json.RawMessage `json:"grep_payloads"`
			} `json:"report"`
		}
		if err := json.Unmarshal(out, &view); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(view.Report.Attempts) != 2 {
			t.Fatalf("%s: %d attempt rows, want 2: %s", tc.name, len(view.Report.Attempts), out)
		}
		for i, a := range view.Report.Attempts {
			if string(a.ReflectedCounts) != tc.want {
				t.Fatalf("%s: attempts[%d].reflected_counts = %s, want %s", tc.name, i, a.ReflectedCounts, tc.want)
			}
		}
		for i, b := range view.Report.Buckets {
			if len(b.ReflectedCountTotals) == 0 || b.ReflectedCountTotals[0] != '[' {
				t.Fatalf("%s: buckets[%d].reflected_count_totals = %s, want an array", tc.name, i, b.ReflectedCountTotals)
			}
		}
		if len(view.Report.GrepPayloads) == 0 || view.Report.GrepPayloads[0] != '{' {
			t.Fatalf("%s: report.grep_payloads = %s, want the settings object", tc.name, view.Report.GrepPayloads)
		}
	}
}
