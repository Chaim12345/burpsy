package extension

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// gqvg: Burp's HotKeyEvent hands the plugin the selected rows and the open editor
// message. hotkey.invoke carries both, so a plugin hotkey can act on what the
// operator highlighted.
func Test_hotkey_invoke_carries_the_selection_and_the_open_editor_message(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	zero, three := 0, 3
	result, err := h.Invoke(context.Background(), "probe", InvokeParams{
		Registration: "key",
		Selected: []SelectedExchange{
			{Exchange: &zero, Raw: "GET /a HTTP/1.1\r\n\r\n"},
			{Exchange: &three},
		},
		Editor: &EditorMessage{Message: &zero, Raw: "GET /e HTTP/1.1\r\n\r\n"},
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	raw := strings.TrimPrefix(result.Output[strings.Index(result.Output, "params=")+len("params="):], "")
	var wire struct {
		Selected []map[string]any `json:"selected"`
		Editor   map[string]any   `json:"editor"`
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		t.Fatalf("params are not JSON: %v: %s", err, raw)
	}
	if len(wire.Selected) != 2 {
		t.Fatalf("selected = %v, want 2 rows: %s", wire.Selected, raw)
	}
	// Exchange 0 is a real id and must be present, not omitted as a zero value.
	if v, ok := wire.Selected[0]["exchange"]; !ok || v != float64(0) {
		t.Errorf("selected[0].exchange = %v (present=%v), want 0: %s", v, ok, raw)
	}
	if _, ok := wire.Selected[1]["raw"]; ok {
		t.Errorf("selected[1] carried raw though none was supplied: %s", raw)
	}
	if wire.Editor["message"] != float64(0) || wire.Editor["raw"] != "GET /e HTTP/1.1\r\n\r\n" {
		t.Errorf("editor = %v, want message 0 and its raw: %s", wire.Editor, raw)
	}
}

// With no selection the wire shape is the old one: neither key appears, so an
// existing plugin sees nothing new.
func Test_hotkey_invoke_without_a_selection_keeps_the_old_wire_shape(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	result, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "key"})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if strings.Contains(result.Output, `"selected"`) || strings.Contains(result.Output, `"editor"`) {
		t.Errorf("empty selection leaked keys: %s", result.Output)
	}
}

// Only hotkey.invoke carries a selection. A context-menu call that arrives with one
// must not forward it: that method's documented params do not include it.
func Test_a_selection_is_not_forwarded_to_other_invocation_kinds(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	one := 1
	result, err := h.Invoke(context.Background(), "probe", InvokeParams{
		Registration: "act", Selected: []SelectedExchange{{Exchange: &one}},
		Editor: &EditorMessage{Message: &one},
	})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if strings.Contains(result.Output, `"selected"`) || strings.Contains(result.Output, `"editor"`) {
		t.Errorf("menu.invoke received a hotkey selection: %s", result.Output)
	}
}

// A runaway selection is refused before it reaches the plugin, and is not counted
// as an invocation the plugin failed.
func Test_an_oversized_selection_is_refused_before_the_plugin_sees_it(t *testing.T) {
	h := testHost(t, "good")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	one := 1
	rows := make([]SelectedExchange, MaxHotkeySelection+1)
	for i := range rows {
		rows[i] = SelectedExchange{Exchange: &one}
	}
	_, err := h.Invoke(context.Background(), "probe", InvokeParams{Registration: "key", Selected: rows})
	if !errors.Is(err, ErrSelectionTooLarge) {
		t.Fatalf("error = %v, want ErrSelectionTooLarge", err)
	}
	if v := h.List().Extensions[0]; v.Invocations != 0 || v.InvocationFailures != 0 {
		t.Errorf("counters = %d/%d, want 0/0 for a refused call", v.Invocations, v.InvocationFailures)
	}
}

// The documented method table says what hotkey.invoke now carries.
func Test_the_hotkey_method_spec_documents_the_selection(t *testing.T) {
	for _, m := range MethodSpecs {
		if m.Name == "hotkey.invoke" {
			if !strings.Contains(m.Params, "selected") || !strings.Contains(m.Params, "editor") {
				t.Errorf("hotkey.invoke Params = %s, want selected and editor documented", m.Params)
			}
			return
		}
	}
	t.Fatal("hotkey.invoke missing from MethodSpecs")
}
