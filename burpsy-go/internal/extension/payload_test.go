package extension

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// 0qwh: registerPayloadGeneratorProvider / registerPayloadProcessor. The host half is
// Host.GeneratePayload and Host.ProcessPayload, which the Intruder engine calls.
func Test_a_plugin_can_register_a_payload_generator_and_processor(t *testing.T) {
	h := testHost(t, "payloads")
	view, err := h.Load("probe")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	kinds := map[Kind]bool{}
	for _, r := range view.Registrations {
		kinds[r.Kind] = true
	}
	if !kinds[KindPayloadGenerator] || !kinds[KindPayloadProcessor] || view.RegistrationsRefused != 0 {
		t.Errorf("registrations = %+v, refused %d", view.Registrations, view.RegistrationsRefused)
	}
}

func Test_GeneratePayload_pulls_the_next_payload_until_the_plugin_says_done(t *testing.T) {
	h := testHost(t, "payloads")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ctx := context.Background()
	got, done, err := h.GeneratePayload(ctx, "probe", "tokens", 0)
	if err != nil || done || string(got) != "tok-0" {
		t.Fatalf("position 0 = %q done=%v err=%v", got, done, err)
	}
	// A payload that is not text round-trips as base64 and comes back as the same bytes.
	got, done, err = h.GeneratePayload(ctx, "probe", "tokens", 1)
	if err != nil || done || !bytes.Equal(got, []byte{0xff, 0x00, 0x80}) {
		t.Fatalf("position 1 = %x done=%v err=%v", got, done, err)
	}
	if _, done, err = h.GeneratePayload(ctx, "probe", "tokens", 3); err != nil || !done {
		t.Fatalf("position 3 done=%v err=%v, want done", done, err)
	}
	// Only the generator registration may be asked to generate.
	if _, _, err = h.GeneratePayload(ctx, "probe", "upper", 0); !errors.Is(err, ErrWrongKind) {
		t.Errorf("generating from a processor error = %v, want ErrWrongKind", err)
	}
	if _, _, err = h.GeneratePayload(ctx, "probe", "nope", 0); !errors.Is(err, ErrUnknownRegistration) {
		t.Errorf("unknown registration error = %v", err)
	}
}

func Test_ProcessPayload_returns_the_rewritten_payload_skip_or_a_failure(t *testing.T) {
	h := testHost(t, "payloads")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ctx := context.Background()
	out, skip, err := h.ProcessPayload(ctx, "probe", "upper", []byte("abc"), []byte("base"))
	if err != nil || skip || string(out) != "ABC|base" {
		t.Fatalf("process = %q skip=%v err=%v", out, skip, err)
	}
	if _, skip, err = h.ProcessPayload(ctx, "probe", "upper", []byte("drop"), nil); err != nil || !skip {
		t.Errorf("drop: skip=%v err=%v, want skip", skip, err)
	}
	// A failing processor is an error the caller must handle by keeping the original payload;
	// the host never returns a half-processed value alongside it.
	out, _, err = h.ProcessPayload(ctx, "probe", "upper", []byte("boom"), nil)
	if err == nil || out != nil || !strings.Contains(err.Error(), "processor failed") {
		t.Errorf("failing processor = %q err=%v", out, err)
	}
	if v := h.List().Extensions[0]; v.InvocationFailures != 1 {
		t.Errorf("failures = %d, want 1", v.InvocationFailures)
	}
	if _, _, err = h.ProcessPayload(ctx, "probe", "tokens", []byte("x"), nil); !errors.Is(err, ErrWrongKind) {
		t.Errorf("processing with a generator error = %v, want ErrWrongKind", err)
	}
}

func Test_the_payload_wire_shapes_marshal_as_documented(t *testing.T) {
	h := testHost(t, "payloads")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// What the plugin received, via the helper echoing nothing: assert the params type directly.
	enc, _ := json.Marshal(InvokeParams{Registration: "tokens", Position: intp(0)})
	if !strings.Contains(string(enc), `"position":0`) {
		t.Errorf("position 0 omitted from the wire: %s", enc)
	}
	var generate, process bool
	for _, m := range MethodSpecs {
		switch m.Name {
		case "payload.generate":
			generate = m.Kind == KindPayloadGenerator
		case "payload.process":
			process = m.Kind == KindPayloadProcessor
		}
	}
	if !generate || !process {
		t.Errorf("MethodSpecs missing the payload methods (generate=%v process=%v)", generate, process)
	}
}

func intp(i int) *int { return &i }
