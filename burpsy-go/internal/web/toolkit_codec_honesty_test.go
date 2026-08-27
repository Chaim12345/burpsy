package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// The encode, hash and ws-filter routes shared one failure shape: a request naming something the
// handler could not do was answered with a plausible-looking success instead of a refusal. Each test
// below pins the specific claim the old code made falsely.

// decodeOutputText pulls the `output.text` field every tools route wraps its result in.
func decodeOutputText(t *testing.T, raw []byte) string {
	t.Helper()
	var body struct {
		Output struct {
			Text string `json:"text"`
		} `json:"output"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode response %s: %v", raw, err)
	}
	return body.Output.Text
}

// base64url must use the URL-safe alphabet, which is the entire reason it is a separate encoding.
//
// The handler used to map it onto tools.Decoder.EncodeBase64 — the standard-alphabet encoder — so the
// one encoding named for URLs emitted the two characters (`+` and `/`) that are unsafe in them. The
// input is chosen so the standard and URL-safe encodings actually differ: bytes that produce a `/`
// under the standard alphabet and a `_` under the URL-safe one. An input whose encoding is identical
// in both alphabets would let the bug pass.
//
// The output is unpadded, which is deliberate rather than incidental: tools.LayerBase64URL is
// documented as the alphabet "as used by JWT", and RFC 7515 §2 strips the padding. tools.Base64Decode
// breaks on `=` regardless, so both paddings decode — the round-trip below is what pins the property
// that actually matters, and the alphabet assertion pins the bug.
func Test_tools_encode_base64url_uses_the_url_safe_alphabet(t *testing.T) {
	s := newTestServer()
	input := "ÿþ" // UTF-8: c3 bf c3 be -> "w7/Dvg==" standard, "w7_Dvg" URL-safe unpadded

	standard := base64.StdEncoding.EncodeToString([]byte(input))
	want := base64.RawURLEncoding.EncodeToString([]byte(input))
	if want == standard {
		t.Fatalf("input %q encodes identically in both alphabets, so it cannot detect the bug", input)
	}

	rec := postJSON(t, s, "/api/tools/encode", map[string]string{"input": input, "encoding": "base64url"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	got := decodeOutputText(t, rec.Body.Bytes())
	if got != want {
		t.Errorf("base64url encode = %q, want %q (standard alphabet would give %q)", got, want, standard)
	}
	if strings.ContainsAny(got, "+/") {
		t.Errorf("base64url encode = %q, which contains a character the URL-safe alphabet exists to avoid", got)
	}

	// Round-trip through the matching decoder, so encode and decode cannot drift apart on the alphabet
	// again — which is exactly how they came to disagree in the first place.
	back := postJSON(t, s, "/api/tools/decode", map[string]string{"input": got, "encoding": "base64url"})
	if back.Code != http.StatusOK {
		t.Fatalf("decode round-trip: status = %d; body %s", back.Code, back.Body.String())
	}
	if round := decodeOutputText(t, back.Body.Bytes()); round != input {
		t.Errorf("base64url round-trip = %q, want %q", round, input)
	}
}

// An encoding this endpoint cannot perform is refused, never echoed back over unchanged input.
//
// The old default branch returned the input verbatim while the reply still reported the requested
// encoding, so a caller storing {encoding, output} recorded a transformation that never ran. JWT is
// included because it parses as a codec layer but has no inverse without the signing key — it must
// fail loudly rather than emit something token-shaped.
func Test_tools_encode_refuses_an_encoding_it_cannot_perform(t *testing.T) {
	s := newTestServer()
	for _, encoding := range []string{"bogus", "sha256", "jwt"} {
		rec := postJSON(t, s, "/api/tools/encode",
			map[string]string{"input": "hello", "encoding": encoding})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("encoding %q: status = %d, want 400; body %s",
				encoding, rec.Code, rec.Body.String())
		}
		if rec.Body.Len() > 0 && decodeOutputTextIfAny(rec.Body.Bytes()) == "hello" {
			t.Errorf("encoding %q returned the input unchanged as a success", encoding)
		}
	}
}

// decodeOutputTextIfAny is decodeOutputText for a body that is expected not to be JSON at all.
func decodeOutputTextIfAny(raw []byte) string {
	var body struct {
		Output struct {
			Text string `json:"text"`
		} `json:"output"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	return body.Output.Text
}

// A stated algorithm the hasher does not implement is refused, rather than silently answered with
// SHA-256 under the requested name.
//
// The pairing matters: the old default branch meant {"algorithm":"crc32"} came back as
// {"algorithm":"crc32", output: <sha256 digest>} — a response asserting a digest it had not computed,
// and a typo like "sha265" returning a plausible hash instead of a complaint.
func Test_tools_hash_refuses_an_algorithm_it_does_not_implement(t *testing.T) {
	s := newTestServer()
	for _, algorithm := range []string{"crc32", "sha265", "sha-256", "bcrypt"} {
		rec := postJSON(t, s, "/api/tools/hash",
			map[string]string{"input": "abc", "algorithm": algorithm})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("algorithm %q: status = %d, want 400; body %s",
				algorithm, rec.Code, rec.Body.String())
		}
	}
}

// The four implemented algorithms still answer, and an omitted algorithm still means SHA-256 — the
// documented default every caller that leaves the field out relies on. Refusing unknown names must
// not narrow the accepted set.
func Test_tools_hash_still_serves_its_implemented_algorithms(t *testing.T) {
	s := newTestServer()
	// Known-answer digests of "abc".
	want := map[string]string{
		"md5":    "900150983cd24fb0d6963f7d28e17f72",
		"sha1":   "a9993e364706816aba3e25717850c26c9cd0d89d",
		"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"":       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	for algorithm, digest := range want {
		rec := postJSON(t, s, "/api/tools/hash",
			map[string]string{"input": "abc", "algorithm": algorithm})
		if rec.Code != http.StatusOK {
			t.Fatalf("algorithm %q: status = %d, want 200; body %s",
				algorithm, rec.Code, rec.Body.String())
		}
		if got := decodeOutputText(t, rec.Body.Bytes()); got != digest {
			t.Errorf("algorithm %q: digest = %q, want %q", algorithm, got, digest)
		}
	}
}

// codecListFromUI extracts one `as const` string array out of ui/src/lib/data.workbench.ts.
//
// # Why this reads the TypeScript instead of restating it
//
// The two tests below used to carry a hard-coded list while their comments claimed they covered
// ENCODE_ENCODINGS and the decode layers "in ui/src/lib/data.workbench.ts". They did not read that
// file at all, so the guarantee was fictional: adding an encoding to the dropdown that the backend
// cannot perform left the suite green. Proven by mutation — offering "brainfuck" passed.
//
// That is the same failure that had been written into reference.ts's header (a test that did not
// exist), which suggests the pattern rather than the instance is the problem: a comment naming a file
// it does not open. These now open it.
func codecListFromUI(t *testing.T, name string) []string {
	t.Helper()
	const path = "ui/src/lib/data.workbench.ts"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	src := string(data)
	// The declaration, matched up to and including the "=", so a RENAMED array cannot satisfy it by
	// prefix. Searching for "export const DECODE_LAYERS" alone also matched DECODE_LAYERS_RENAMED,
	// which made the rename mutation pass — my own bug, caught by mutating the name.
	at := strings.Index(src, "export const "+name+" =")
	if at < 0 {
		t.Fatalf("%s does not declare %s — this test cannot check what it cannot find", path, name)
	}
	open, close := strings.Index(src[at:], "["), strings.Index(src[at:], "]")
	if open < 0 || close < open {
		t.Fatalf("could not find %s's array literal in %s", name, path)
	}
	var out []string
	for _, part := range strings.Split(src[at+open+1:at+close], ",") {
		if v := strings.Trim(strings.TrimSpace(part), `"'`); v != "" {
			out = append(out, v)
		}
	}
	// The floor: an extractor that silently matched nothing would make this pass by checking nothing,
	// which is exactly how the guarantee was lost the first time.
	if len(out) < 5 {
		t.Fatalf("extracted only %d entries from %s in %s; the extractor is not reading the array",
			len(out), name, path)
	}
	return out
}

// Every encoding the dropdown offers must actually encode. Read from the UI's own array, so adding
// one the backend cannot perform fails here rather than 500-ing in front of an operator.
func Test_tools_encode_serves_every_encoding_the_ui_offers(t *testing.T) {
	s := newTestServer()
	for _, encoding := range codecListFromUI(t, "ENCODE_ENCODINGS") {
		rec := postJSON(t, s, "/api/tools/encode",
			map[string]string{"input": "abc", "encoding": encoding})
		if rec.Code != http.StatusOK {
			t.Errorf("the Decoder offers encoding %q and the backend refuses it: status = %d, body %s",
				encoding, rec.Code, rec.Body.String())
		}
	}
}

// And the decode direction, which had no such test at all. gzip and deflate were in the engine and
// missing from the dropdown (burpsy-react-ui-37b); with them added, this is what stops the reverse —
// a layer offered that cannot decode.
func Test_tools_decode_serves_every_layer_the_ui_offers(t *testing.T) {
	s := newTestServer()
	for _, layer := range codecListFromUI(t, "DECODE_LAYERS") {
		// What is asserted is that the layer is RECOGNISED, not that the input decodes: "YWJj" is not
		// valid gzip, deflate or a JWT, and a known layer handed undecodable input reporting that
		// failure is correct behaviour. The signal is decodeLayer's vocabulary error, "unknown
		// encoding %q: expected one of ...".
		//
		// The body shape is FLAT — {input, encoding} — which is what lib/data.workbench.ts's runStep
		// posts. Sending {input, steps:[...]} instead, as I first did, is silently ignored by the
		// handler: nothing is decoded, no error is produced, and the test passes for every layer
		// including nonsense ones. Two mutations were needed to find that (a bogus layer, and a
		// renamed array), and both passed against the earlier version.
		rec := postJSON(t, s, "/api/tools/decode",
			map[string]any{"input": "YWJj", "encoding": layer})
		if strings.Contains(rec.Body.String(), "unknown encoding") {
			t.Errorf("the Decoder offers layer %q and the backend does not recognise it: %s",
				layer, rec.Body.String())
		}
	}
}

// An `exchange` filter that will not parse is refused rather than dropped.
//
// The parse error used to be discarded and the handler then fell through to the unfiltered index, so
// `?exchange=abc` answered with every message on the server while the caller believed it was reading
// one connection. Every row was real, which is what made it undetectable from the response alone.
func Test_ws_history_refuses_an_unparseable_exchange_filter(t *testing.T) {
	s := newTestServer()
	for _, raw := range []string{"abc", "1.5", "-3", ""} {
		if raw == "" {
			continue // an absent filter is the unfiltered case, tested below
		}
		rec := get(t, s, "/api/ws/history?exchange="+raw)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("exchange=%q: status = %d, want 400; body %s",
				raw, rec.Code, rec.Body.String())
		}
	}
	// No filter at all is still the whole index, and still a 200.
	if rec := get(t, s, "/api/ws/history"); rec.Code != http.StatusOK {
		t.Errorf("unfiltered: status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

// url encode and url decode must round-trip, which before this they did not.
//
// Routing encode through the codec table changed `url` from url.QueryEscape (form semantics: a space
// becomes `+`) to tools.URLEncode (RFC 3986 percent-encoding: a space becomes `%20`). That was not
// the bug being fixed, but it fixed one: the explicit `url` decode layer is tools.URLDecode, which
// passes `+` through as a literal plus, so encode("a b") produced "a+b" and decoding it returned
// "a+b" — the space silently became a plus sign on the way back.
//
// The pairing is what this pins. Either encoder is defensible alone; only one of them agrees with the
// decoder this endpoint actually ships.
func Test_tools_url_encode_and_decode_round_trip(t *testing.T) {
	s := newTestServer()
	for _, input := range []string{"a b&c", "a b", "x=1&y=2", "/path with spaces/", "ü ö"} {
		rec := postJSON(t, s, "/api/tools/encode", map[string]string{"input": input, "encoding": "url"})
		if rec.Code != http.StatusOK {
			t.Fatalf("encode %q: status = %d; body %s", input, rec.Code, rec.Body.String())
		}
		encoded := decodeOutputText(t, rec.Body.Bytes())
		if strings.Contains(encoded, "+") {
			t.Errorf("encode %q = %q: a `+` here decodes back as a literal plus, not a space",
				input, encoded)
		}
		back := postJSON(t, s, "/api/tools/decode", map[string]string{"input": encoded, "encoding": "url"})
		if back.Code != http.StatusOK {
			t.Fatalf("decode %q: status = %d; body %s", encoded, back.Code, back.Body.String())
		}
		if got := decodeOutputText(t, back.Body.Bytes()); got != input {
			t.Errorf("url round-trip of %q = %q via %q", input, got, encoded)
		}
	}
}
