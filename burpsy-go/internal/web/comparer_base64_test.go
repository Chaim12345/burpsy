package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// A side loaded from a file travels as base64 (burpsy-react-ui-ppqw), so binary content is compared
// byte-for-byte rather than after a JSON string turned every invalid byte into U+FFFD.
func Test_compare_takes_a_binary_side_as_base64_and_diffs_the_real_bytes(t *testing.T) {
	a := []byte{0x00, 0xff, 0xfe, 'x', 0x80}
	b := []byte{0x00, 0xff, 0xfd, 'x', 0x80}
	rec := postJSON(t, newTestServer(), "/api/tools/compare", map[string]string{
		"a_base64": base64.StdEncoding.EncodeToString(a),
		"b_base64": base64.StdEncoding.EncodeToString(b),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Identical bool `json:"identical"`
		Ops       []struct {
			Kind    string `json:"kind"`
			AOffset int    `json:"a_offset"`
			ALen    int    `json:"a_len"`
		} `json:"ops"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Identical {
		t.Fatal("0xfe vs 0xfd reported identical — the bytes were mangled before the diff")
	}
	// Exactly one changed byte, at offset 2. Sent as JSON text, 0xfe and 0xfd would both have become
	// U+FFFD and compared equal; this pins that they did not.
	changed := 0
	for _, op := range out.Ops {
		if op.Kind != "equal" {
			changed += op.ALen
			if op.AOffset != 2 {
				t.Errorf("difference at offset %d, want 2", op.AOffset)
			}
		}
	}
	if changed != 1 {
		t.Errorf("changed bytes on side A = %d, want exactly 1 (ops %+v)", changed, out.Ops)
	}

	// Identical binary sides are identical.
	rec = postJSON(t, newTestServer(), "/api/tools/compare", map[string]string{
		"a_base64": base64.StdEncoding.EncodeToString(a),
		"b_base64": base64.StdEncoding.EncodeToString(a),
	})
	if !strings.Contains(rec.Body.String(), `"identical":true`) {
		t.Errorf("identical binary sides not reported identical: %s", rec.Body.String())
	}
}

func Test_compare_refuses_a_side_sent_both_ways_or_as_bad_base64(t *testing.T) {
	rec := postJSON(t, newTestServer(), "/api/tools/compare", map[string]string{"a": "x", "a_base64": "eA==", "b": "y"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "send one") {
		t.Errorf("a side sent as text and base64: %d %q", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, newTestServer(), "/api/tools/compare", map[string]string{"a_base64": "not base64!", "b": "y"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "a_base64") {
		t.Errorf("bad base64: %d %q", rec.Code, rec.Body.String())
	}
	// The text form still works on its own, unchanged.
	rec = postJSON(t, newTestServer(), "/api/tools/compare", map[string]string{"a": "abc", "b": "abd"})
	if rec.Code != http.StatusOK {
		t.Errorf("plain text compare: %d %s", rec.Code, rec.Body.String())
	}
}
