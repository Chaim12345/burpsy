package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/tools"
)

// The Decoder's hash step through the real route (burpsy-react-ui-wi55, burpsy-react-ui-7tgt).

type hashReply struct {
	Algorithm string `json:"algorithm"`
	Output    struct {
		Text string `json:"text"`
		Len  int    `json:"len"`
		UTF8 bool   `json:"utf8"`
	} `json:"output"`
}

func postHash(t *testing.T, body map[string]string) (int, hashReply, string) {
	t.Helper()
	rec := postJSON(t, newTestServer(), "/api/tools/hash", body)
	var out hashReply
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("reply is not the documented JSON shape: %v — %s", err, rec.Body.String())
		}
	}
	return rec.Code, out, rec.Body.String()
}

// The UI's HASH_ALGORITHMS is read from data.workbench.ts and must equal the server's table exactly,
// in order — a name offered in the dropdown that the route refuses is a 400 in front of an operator,
// and a name the route accepts that the dropdown hides is a capability nobody can reach.
func Test_the_ui_hash_list_is_the_servers_algorithm_table(t *testing.T) {
	ui := codecListFromUI(t, "HASH_ALGORITHMS")
	if want := tools.DigestAlgorithmNames(); !reflect.DeepEqual(ui, want) {
		t.Fatalf("HASH_ALGORITHMS in the UI = %v\nserver table              = %v", ui, want)
	}
}

func Test_tools_hash_serves_every_algorithm_the_ui_offers(t *testing.T) {
	for _, name := range codecListFromUI(t, "HASH_ALGORITHMS") {
		body := map[string]string{"input": "abc", "algorithm": name}
		if strings.HasPrefix(name, "hmac-") {
			body["key"] = "secret"
		}
		code, out, raw := postHash(t, body)
		if code != http.StatusOK || out.Output.Text == "" {
			t.Errorf("the Decoder offers %q and the route answered %d: %s", name, code, raw)
		}
	}
}

// RFC 7515 Appendix A.1 through the route: the JWK key arrives as unpadded base64url, the signature
// must come back as unpadded base64url and equal the RFC's own value.
func Test_tools_hash_recomputes_the_rfc7515_hs256_signature(t *testing.T) {
	code, out, raw := postHash(t, map[string]string{
		"input":        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
		"algorithm":    "hmac-sha256",
		"key":          "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
		"key_encoding": "base64",
		"output":       "base64url",
	})
	if code != http.StatusOK || out.Output.Text != "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" {
		t.Fatalf("HS256 signature = %d %q (%s), want RFC 7515 A.1's dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", code, out.Output.Text, raw)
	}
}

// The pre-existing request shape — {input, algorithm} with hex output — must answer exactly as it
// did, because the CLI, saved Decoder chains and scripts already send it.
func Test_tools_hash_keeps_the_legacy_request_shape(t *testing.T) {
	for alg, want := range map[string]string{
		"md5": "900150983cd24fb0d6963f7d28e17f72",
		"":    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	} {
		code, out, raw := postHash(t, map[string]string{"input": "abc", "algorithm": alg})
		if code != http.StatusOK || out.Output.Text != want {
			t.Errorf("algorithm %q = %d %q (%s), want %s", alg, code, out.Output.Text, raw, want)
		}
	}
}

func Test_tools_hash_refuses_what_it_cannot_honour(t *testing.T) {
	cases := []struct {
		name string
		body map[string]string
		says string
	}{
		{"hmac without a key", map[string]string{"input": "x", "algorithm": "hmac-sha256"}, "needs a key"},
		{"a key on an unkeyed digest", map[string]string{"input": "x", "algorithm": "sha256", "key": "k"}, "not keyed"},
		{"an algorithm not in the table", map[string]string{"input": "x", "algorithm": "blake3"}, "hmac-sha256"},
		{"an input that is not hex", map[string]string{"input": "zz", "input_encoding": "hex", "algorithm": "md5"}, "input:"},
		{"an output it cannot write", map[string]string{"input": "x", "algorithm": "md5", "output": "base32"}, "unknown output"},
	}
	for _, c := range cases {
		code, _, raw := postHash(t, c.body)
		if code != http.StatusBadRequest || !strings.Contains(raw, c.says) {
			t.Errorf("%s: got %d %q, want 400 containing %q", c.name, code, strings.TrimSpace(raw), c.says)
		}
	}
}

// Hex input reaches the hash as bytes, not as the hex text: MD4 of the bytes 0x61 0x62 0x63 is
// MD4("abc"), the NTLM-style case where the operator has the raw bytes in hex.
func Test_tools_hash_reads_hex_input_as_bytes(t *testing.T) {
	code, out, raw := postHash(t, map[string]string{"input": "616263", "input_encoding": "hex", "algorithm": "md4"})
	if code != http.StatusOK || out.Output.Text != "a448017aaf21d8525fc10ae87aa6729d" {
		t.Fatalf("md4(hex 616263) = %d %q (%s), want md4(abc)", code, out.Output.Text, raw)
	}
}
