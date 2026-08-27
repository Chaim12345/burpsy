package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/tools"
)

// ---- the Decoder's "guess alphabets" checkbox must do something --------------------------
//
// BURP_PARITY_GAP_ANALYSIS.md §5.1 swept 24 pages and ~80 controls looking for a *decorative*
// control — one that renders, accepts input, returns 200, and whose value the backend never
// reads. It found exactly one, and this was it: `guess_alphabets` travelled from
// decoder.tsx through data.workbench.ts into `req.Guess` and reached `smartDecode`, which
// took the parameter and never referenced it. Four decode layers ran in the same fixed order
// either way.
//
// On a security-analysis toggle that is the worst place for it. The operator reads decoder
// output as evidence about a payload, and the control silently claimed to influence how that
// evidence was produced.
//
// These tests pin both halves: off must behave exactly as before, and on must accept the
// alphabets the strict decoders reject.

// The defect. Off and on must not produce identical results for input that only a relaxed
// alphabet can read — if they do, the checkbox is decorative again.
func TestGuessOffAndOnDifferForUnpaddedBase64(t *testing.T) {
	dec := tools.NewDecoder()
	// Unpadded base64 whose length is NOT a multiple of 4, so StdEncoding rejects it and only
	// the Raw* encodings can read it. The first draft of this test used a 20-character JWT
	// header, which IS a multiple of 4 and therefore decodes strictly — the test failed and was
	// right to: my premise about the input was wrong, not the code.
	const in = "eyJhIjoxfQ"

	offOut, offLayers := smartDecode(dec, in, false)
	onOut, onLayers := smartDecode(dec, in, true)

	if onOut == offOut && len(onLayers) == len(offLayers) {
		t.Fatalf("guess made no difference: off=%q%v on=%q%v — the checkbox is decorative",
			offOut, offLayers, onOut, onLayers)
	}
	if !strings.Contains(onOut, `"a":1`) {
		t.Errorf("guess=on did not decode the unpadded segment: %q (layers %v)", onOut, onLayers)
	}
}

// Separator-delimited hex: fingerprints, MAC addresses, certificate dumps. DecodeHex strips
// spaces and one leading 0x, and rejects colons.
func TestGuessReadsSeparatorDelimitedHex(t *testing.T) {
	dec := tools.NewDecoder()
	const in = "48:65:6c:6c:6f"

	_, offLayers := smartDecode(dec, in, false)
	onOut, onLayers := smartDecode(dec, in, true)

	if len(offLayers) != 0 {
		t.Logf("strict path already read %q as %v; the assertion below still holds", in, offLayers)
	}
	if !strings.Contains(onOut, "Hello") {
		t.Fatalf("guess=on did not read colon-delimited hex: %q (layers %v)", onOut, onLayers)
	}
}

// Off must be byte-identical to the old behaviour. This is the compatibility guard: the fix is
// only safe because turning the checkbox off changes nothing, and without this test "always
// guess" would satisfy both assertions above while altering results for every operator who
// left the box unticked.
func TestGuessOffKeepsTheStrictBehaviour(t *testing.T) {
	dec := tools.NewDecoder()
	cases := []string{
		"eyJhIjoxfQ",         // unpadded — strict must NOT read it
		"48:65:6c:6c:6f",     // colon hex — strict must NOT read it
		"SGVsbG8=",           // padded base64 — strict reads it
		"%48%65%6c%6c%6f",    // url — strict reads it
		"&lt;script&gt;",     // html — strict reads it
		"not encoded at all", // nothing to do
	}
	for _, in := range cases {
		out, layers := smartDecode(dec, in, false)
		switch in {
		case "eyJhIjoxfQ", "48:65:6c:6c:6f":
			if len(layers) != 0 {
				t.Errorf("strict path decoded %q as %v; guessing must be the only way in", in, layers)
			}
			if out != in {
				t.Errorf("strict path altered %q to %q", in, out)
			}
		default:
			// The remaining inputs are what the strict decoder always handled; asserting only
			// that it still does, not how, because their exact layering is pinned elsewhere.
			if out == "" {
				t.Errorf("strict path returned empty for %q", in)
			}
		}
	}
}

// A guessed layer must be labelled as guessed. "This decoded cleanly" and "this decoded once I
// relaxed the alphabet" are different facts about a payload, and on this tool the difference
// can matter to a conclusion.
func TestAGuessedLayerSaysSoInTheLayerList(t *testing.T) {
	dec := tools.NewDecoder()
	_, layers := smartDecode(dec, "eyJhIjoxfQ", true)
	if len(layers) == 0 {
		t.Fatal("nothing decoded, so there is no layer label to check")
	}
	var labelled bool
	for _, l := range layers {
		if strings.Contains(l, "guessed alphabet") {
			labelled = true
		}
	}
	if !labelled {
		t.Errorf("layers = %v; a layer that needed a relaxed alphabet must say so, or the "+
			"operator cannot tell a clean decode from a coaxed one", layers)
	}
}

// And the whole way through the real endpoint, since the audit's finding was about the control
// the operator actually clicks rather than about the helper.
func TestTheDecodeEndpointHonoursGuessAlphabets(t *testing.T) {
	ts := newTestServer()

	decode := func(guess bool) (string, []string) {
		body := `{"input":"eyJhIjoxfQ","guess_alphabets":` + map[bool]string{true: "true", false: "false"}[guess] + `}`
		req := httptest.NewRequest(http.MethodPost, "/api/tools/decode", strings.NewReader(body))
		rec := httptest.NewRecorder()
		ts.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("guess=%v: POST /api/tools/decode = %d: %s", guess, rec.Code, rec.Body.String())
		}
		// output is an object, not a string: {text,len,utf8,truncated}. Decoding it as a string
		// is how the first draft of this test failed; the shape is spelled out so the next
		// reader does not repeat it.
		var out struct {
			Output struct {
				Text string `json:"text"`
			} `json:"output"`
			Layers []string `json:"layers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode response: %v (body %s)", err, rec.Body.String())
		}
		return out.Output.Text, out.Layers
	}

	offOut, offLayers := decode(false)
	onOut, onLayers := decode(true)

	if offOut == onOut && len(offLayers) == len(onLayers) {
		t.Fatalf("the endpoint ignores guess_alphabets: off=%q%v on=%q%v",
			offOut, offLayers, onOut, onLayers)
	}
	if !strings.Contains(onOut, `"a":1`) {
		t.Errorf("guess=true through the endpoint did not decode: %q", onOut)
	}
}
