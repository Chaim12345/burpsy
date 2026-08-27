package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- the Comparer's diff (CMP-ALIGN) --------------------------------------------------------
//
// The old compareOps walked a[i] against b[i] positionally, so any length-changing edit
// desynchronised everything after it. The regression test for that is
// TestOneInsertedByteIsOneSmallOp, and it is the reason this file exists.
//
// The other load-bearing test is TestEveryDiffReconstructsBothInputs: an op list that does not
// reconstruct the inputs is worse than a bad diff, because the console renders by slicing at these
// offsets and would show the operator bytes that are not in either message.

// applyOps rebuilds (a, b) from the op list, the way the console does: A-side text comes from
// equal/replace/delete ops, B-side from equal/replace/insert.
func applyOps(t *testing.T, ops []compareOp, a, b []byte) (gotA, gotB []byte) {
	t.Helper()
	for _, op := range ops {
		switch op.Kind {
		case "equal":
			gotA = append(gotA, a[op.AOffset:op.AOffset+op.ALen]...)
			gotB = append(gotB, b[op.BOffset:op.BOffset+op.BLen]...)
		case "replace":
			gotA = append(gotA, a[op.AOffset:op.AOffset+op.ALen]...)
			gotB = append(gotB, b[op.BOffset:op.BOffset+op.BLen]...)
		case "delete":
			gotA = append(gotA, a[op.AOffset:op.AOffset+op.ALen]...)
		case "insert":
			gotB = append(gotB, b[op.BOffset:op.BOffset+op.BLen]...)
		default:
			t.Fatalf("unknown op kind %q", op.Kind)
		}
	}
	return gotA, gotB
}

// changedBytes is what the operator sees as "different".
func changedBytes(ops []compareOp) int {
	n := 0
	for _, op := range ops {
		if op.Kind != "equal" {
			if op.ALen > op.BLen {
				n += op.ALen
			} else {
				n += op.BLen
			}
		}
	}
	return n
}

// THE regression test. The old implementation reported 39 of 43 bytes changed for this input.
func TestOneInsertedByteIsOneSmallOp(t *testing.T) {
	a := []byte("the quick brown fox jumps over the lazy dog")
	b := []byte("the XQuick brown fox jumps over the lazy dog")

	got := diffBytes(a, b)
	if got.Truncated {
		t.Fatal("a 43-byte input hit the edit-distance bound")
	}

	changed := changedBytes(got.Ops)
	// One inserted char plus the q→Q case change: a handful of bytes, not the whole message.
	if changed > 6 {
		t.Errorf("%d bytes reported as changed for a one-character insertion (ops: %s) — this is the "+
			"positional-walk regression; the old code reported 39 of 43", changed, describeOps(got.Ops))
	}

	gotA, gotB := applyOps(t, got.Ops, a, b)
	if !bytes.Equal(gotA, a) || !bytes.Equal(gotB, b) {
		t.Errorf("ops do not reconstruct the inputs:\n A: %q\n B: %q", gotA, gotB)
	}
}

func describeOps(ops []compareOp) string {
	parts := make([]string, 0, len(ops))
	for _, op := range ops {
		parts = append(parts, fmt.Sprintf("%s(a=%d,b=%d)", op.Kind, op.ALen, op.BLen))
	}
	return strings.Join(parts, " ")
}

// The property that keeps the console honest: whatever the diff says, slicing the inputs at those
// offsets must give back exactly the inputs.
func TestEveryDiffReconstructsBothInputs(t *testing.T) {
	cases := []struct{ name, a, b string }{
		{"identical", "hello world", "hello world"},
		{"both empty", "", ""},
		{"a empty", "", "inserted"},
		{"b empty", "deleted", ""},
		{"prefix only", "same tail", "different tail"},
		{"suffix only", "head same", "head other"},
		{"insertion at start", "abc", "Xabc"},
		{"insertion at end", "abc", "abcX"},
		{"deletion in middle", "abcdef", "abef"},
		{"complete replacement", "aaaa", "bbbb"},
		{"repeated bytes", "aaaaaaaa", "aaaXaaaa"},
		{"http responses", "HTTP/1.1 200 OK\r\nDate: A\r\nContent-Length: 2\r\n\r\nhi",
			"HTTP/1.1 200 OK\r\nDate: BB\r\nContent-Length: 2\r\n\r\nhi"},
		{"one byte each", "a", "b"},
		{"newlines", "a\nb\nc\n", "a\nB\nc\n"},
		{"binary-ish", "\x00\x01\x02\x03", "\x00\x02\x03"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := []byte(tc.a), []byte(tc.b)
			got := diffBytes(a, b)
			if len(got.Ops) == 0 {
				t.Fatal("no ops at all; the console would render nothing")
			}
			gotA, gotB := applyOps(t, got.Ops, a, b)
			if !bytes.Equal(gotA, a) {
				t.Errorf("A reconstructs as %q, want %q", gotA, a)
			}
			if !bytes.Equal(gotB, b) {
				t.Errorf("B reconstructs as %q, want %q", gotB, b)
			}
			// Offsets must be inside their inputs, or the console slices out of range.
			for _, op := range got.Ops {
				if op.AOffset < 0 || op.AOffset+op.ALen > len(a) {
					t.Errorf("op %s A range [%d,%d) outside a (len %d)", op.Kind, op.AOffset, op.AOffset+op.ALen, len(a))
				}
				if op.BOffset < 0 || op.BOffset+op.BLen > len(b) {
					t.Errorf("op %s B range [%d,%d) outside b (len %d)", op.Kind, op.BOffset, op.BOffset+op.BLen, len(b))
				}
			}
		})
	}
}

// Identical inputs must produce exactly one equal op, because that is what the endpoint's
// `identical` check looks for.
func TestIdenticalInputsProduceOneEqualOp(t *testing.T) {
	for _, in := range []string{"", "x", "hello world", strings.Repeat("abc", 500)} {
		got := diffBytes([]byte(in), []byte(in))
		if len(got.Ops) != 1 || got.Ops[0].Kind != "equal" {
			t.Errorf("input len %d: ops = %s, want exactly one equal", len(in), describeOps(got.Ops))
		}
	}
}

// A minimal diff: changing one byte in the middle of a large identical body must not report more
// than that byte. This is the case the prefix/suffix trim exists for, and the one an operator hits
// constantly — two responses differing in a single field.
func TestASingleByteChangeInALargeBodyIsMinimal(t *testing.T) {
	body := strings.Repeat("0123456789", 5_000) // 50 KB
	a := []byte(body)
	b := []byte(body[:25_000] + "X" + body[25_001:])

	got := diffBytes(a, b)
	if got.Truncated {
		t.Fatal("a single-byte change hit the edit-distance bound")
	}
	if changed := changedBytes(got.Ops); changed != 1 {
		t.Errorf("%d bytes reported as changed for a one-byte edit in 50 KB (ops: %s)",
			changed, describeOps(got.Ops))
	}
}

// Adjacent single-element steps must be merged. Myers emits per-byte decisions; an operator reading
// hundreds of one-byte hunks for one changed word is being shown noise.
func TestAdjacentStepsAreMergedIntoHunks(t *testing.T) {
	a := []byte("the quick brown fox")
	b := []byte("the slow   brown fox")

	got := diffBytes(a, b)
	if len(got.Ops) > 5 {
		t.Errorf("%d ops for one changed word: %s — adjacent steps are not being merged",
			len(got.Ops), describeOps(got.Ops))
	}
}

// A delete adjacent to an insert is a replacement, and the console draws replacements side by side.
func TestAdjacentDeleteAndInsertFoldIntoReplace(t *testing.T) {
	got := diffBytes([]byte("aaaXbbb"), []byte("aaaYbbb"))
	var kinds []string
	for _, op := range got.Ops {
		kinds = append(kinds, op.Kind)
	}
	joined := strings.Join(kinds, ",")
	if !strings.Contains(joined, "replace") {
		t.Errorf("ops = %s; a one-byte substitution should read as a replace", joined)
	}
	for i := 0; i+1 < len(got.Ops); i++ {
		if (got.Ops[i].Kind == "delete" && got.Ops[i+1].Kind == "insert") ||
			(got.Ops[i].Kind == "insert" && got.Ops[i+1].Kind == "delete") {
			t.Errorf("ops = %s; an adjacent delete/insert pair survived folding", joined)
		}
	}
}

// Two unrelated large blobs must not hang the request. They must come back promptly, marked
// truncated, and still reconstruct — the honest degradation rather than a silent bad diff.
func TestUnrelatedLargeInputsDegradeHonestly(t *testing.T) {
	a := bytes.Repeat([]byte("a"), 200_000)
	b := bytes.Repeat([]byte("b"), 200_000)

	got := diffBytes(a, b)
	if !got.Truncated {
		// Not a failure in itself if it genuinely aligned them, but it must then still be correct.
		t.Log("the bound was not hit; checking correctness anyway")
	}
	gotA, gotB := applyOps(t, got.Ops, a, b)
	if !bytes.Equal(gotA, a) || !bytes.Equal(gotB, b) {
		t.Error("a truncated diff must still reconstruct both inputs")
	}
}

// The truncation flag must reach the operator, since an unaligned diff presented as aligned is the
// defect this work removes.
func TestTruncationIsReportedThroughTheEndpoint(t *testing.T) {
	ts := newTestServer()
	a := strings.Repeat("a", 200_000)
	b := strings.Repeat("b", 200_000)
	body, _ := json.Marshal(map[string]any{"a": a, "b": b})

	req := httptest.NewRequest(http.MethodPost, "/api/tools/compare", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d", rec.Code)
	}
	var out struct {
		Identical bool `json:"identical"`
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Identical {
		t.Error("identical=true for two entirely different inputs")
	}
	if !out.Truncated {
		t.Error("truncated=false after the bound was hit; the console cannot tell the operator that " +
			"the diff was not aligned")
	}
}

// End to end through the endpoint, on the exact input that exposed the original defect.
func TestTheEndpointReportsASmallDiffForASmallEdit(t *testing.T) {
	ts := newTestServer()
	a := "the quick brown fox jumps over the lazy dog"
	b := "the XQuick brown fox jumps over the lazy dog"
	body, _ := json.Marshal(map[string]any{"a": a, "b": b})

	req := httptest.NewRequest(http.MethodPost, "/api/tools/compare", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	ts.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Identical bool          `json:"identical"`
		Truncated bool          `json:"truncated"`
		Ops       []compareOpJS `json:"ops"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Identical || out.Truncated {
		t.Errorf("identical=%v truncated=%v, want both false", out.Identical, out.Truncated)
	}
	changed := 0
	for _, op := range out.Ops {
		if op.Kind != "equal" {
			if op.ALen > op.BLen {
				changed += op.ALen
			} else {
				changed += op.BLen
			}
		}
	}
	if changed > 6 {
		t.Errorf("the endpoint reports %d bytes changed for a one-character insertion", changed)
	}
}

// compareOpJS mirrors the wire shape, so the endpoint test asserts what a client really receives
// rather than reaching into the Go struct.
type compareOpJS struct {
	Kind string `json:"kind"`
	ALen int    `json:"a_len"`
	BLen int    `json:"b_len"`
}
