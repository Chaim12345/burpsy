package extension

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// gqvg hardening: the exact 100-row boundary, every forwarded id and raw, and the shapes that
// must not reach a plugin (a row with no exchange id, a negative id, an Editor with nothing in it).

func hotkeyParams(t *testing.T, out string) (sel []map[string]any, editor map[string]any, raw string) {
	t.Helper()
	raw = out[strings.Index(out, "params=")+len("params="):]
	var wire struct {
		Selected []map[string]any `json:"selected"`
		Editor   map[string]any   `json:"editor"`
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		t.Fatalf("params are not JSON: %v: %s", err, raw)
	}
	return wire.Selected, wire.Editor, raw
}

func Test_exactly_the_cap_is_allowed_and_every_row_arrives_with_its_id_and_raw(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	rows := make([]SelectedExchange, MaxHotkeySelection)
	for i := range rows {
		id := i
		rows[i] = SelectedExchange{Exchange: &id}
	}
	rows[0].Raw = "GET /first HTTP/1.1\r\n\r\n"
	three := 3
	rows[1] = SelectedExchange{Exchange: &three, Raw: "GET /second HTTP/1.1\r\n\r\n"}
	res, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "key", Selected: rows})
	if err != nil {
		t.Fatalf("a selection of exactly %d rows was refused: %v", MaxHotkeySelection, err)
	}
	sel, _, raw := hotkeyParams(t, res.Output)
	if len(sel) != MaxHotkeySelection {
		t.Fatalf("plugin saw %d rows, want %d", len(sel), MaxHotkeySelection)
	}
	if sel[0]["exchange"] != float64(0) || sel[0]["raw"] != "GET /first HTTP/1.1\r\n\r\n" {
		t.Errorf("first row = %v, want id 0 with its raw: %s", sel[0], raw[:200])
	}
	if sel[1]["exchange"] != float64(3) || sel[1]["raw"] != "GET /second HTTP/1.1\r\n\r\n" {
		t.Errorf("second row = %v, want id 3 with its raw", sel[1])
	}
	if sel[99]["exchange"] != float64(99) {
		t.Errorf("last row = %v, want id 99", sel[99])
	}
}

func Test_a_selection_row_without_a_valid_exchange_id_is_refused_not_sent_as_null(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	neg := -1
	for name, rows := range map[string][]SelectedExchange{
		"nil id":      {{Raw: "x"}},
		"negative id": {{Exchange: &neg}},
	} {
		_, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "key", Selected: rows})
		if !errors.Is(err, ErrInvalidSelection) {
			t.Errorf("%s: error = %v, want ErrInvalidSelection", name, err)
		}
	}
	if v := h.List().Extensions[0]; v.Invocations != 0 || v.InvocationFailures != 0 {
		t.Errorf("a refused selection counted as %d invocations / %d failures", v.Invocations, v.InvocationFailures)
	}
}

func Test_an_editor_with_nothing_in_it_is_refused_and_a_raw_only_editor_is_a_draft(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	neg := -2
	for name, ed := range map[string]*EditorMessage{
		"empty":            {},
		"negative message": {Message: &neg, Raw: "x"},
	} {
		_, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "key", Editor: ed})
		if !errors.Is(err, ErrInvalidSelection) {
			t.Errorf("%s editor: error = %v, want ErrInvalidSelection", name, err)
		}
	}
	// A draft in the editor has text and no stored message id; that is a real shape (the Repeater).
	res, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "key", Editor: &EditorMessage{Raw: "GET / HTTP/1.1\r\n\r\n"}})
	if err != nil {
		t.Fatalf("raw-only editor refused: %v", err)
	}
	_, ed, raw := hotkeyParams(t, res.Output)
	if _, has := ed["message"]; has || ed["raw"] != "GET / HTTP/1.1\r\n\r\n" {
		t.Errorf("editor = %v, want raw and no message key: %s", ed, raw)
	}
}
