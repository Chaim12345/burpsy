package tools_test

import (
	"bytes"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/tools"
)

// rebuild replays the ops against a and b; the result must reconstruct b.
// Any span error shows up here. Ported from comparer.rs's rebuild helper.
func rebuild(t *testing.T, a, b []byte, d *tools.DiffResult) []byte {
	t.Helper()
	var out []byte
	for _, op := range d.Ops {
		switch op.Kind {
		case tools.OpEqual:
			out = append(out, b[op.B.Offset:op.B.End()]...)
		case tools.OpInsert:
			out = append(out, b[op.B.Offset:op.B.End()]...)
		case tools.OpDelete:
			if op.A.End() > len(a) {
				t.Fatalf("delete span past the end of a: %+v", op.A)
			}
		default:
			t.Fatalf("unknown op kind %v", op.Kind)
		}
	}
	return out
}

// check diffs with the default budget and asserts the ops reconstruct b.
func check(t *testing.T, a, b []byte, g tools.Granularity) *tools.DiffResult {
	t.Helper()
	d := tools.Diff(a, b, g)
	if got := rebuild(t, a, b, d); !bytes.Equal(got, b) {
		t.Fatalf("ops must reconstruct b: got %q want %q", got, b)
	}
	return d
}

// The headline case from comparer.rs: a one-byte difference in a 200 KB body.
// Budget of 4 proves the prefix/suffix trim did the work — without it Myers
// would need D in the hundreds of thousands and this would truncate.
func TestOneByteDifferingInA200kResponseIsFoundWithATinyEditScript(t *testing.T) {
	a := make([]byte, 200_000)
	for i := range a {
		a[i] = "abcdefghij"[i%10]
	}
	b := bytes.Clone(a)
	b[123_456] = 'Z'

	d := tools.DiffWithBudget(a, b, tools.GranularityByte, 4)
	if d.Truncated {
		t.Error("a one-byte change must not exhaust a budget of 4: diff truncated")
	}
	if d.DeletedTokens != 1 {
		t.Errorf("deleted_tokens = %d, want 1", d.DeletedTokens)
	}
	if d.InsertedTokens != 1 {
		t.Errorf("inserted_tokens = %d, want 1", d.InsertedTokens)
	}
	if d.EqualTokens != 199_999 {
		t.Errorf("equal_tokens = %d, want 199999", d.EqualTokens)
	}
	var changed []*tools.Op
	for i := range d.Ops {
		if d.Ops[i].Kind != tools.OpEqual {
			changed = append(changed, &d.Ops[i])
		}
	}
	if len(changed) != 2 {
		t.Fatalf("expected one delete and one insert, got %d changed ops", len(changed))
	}
	if changed[0].Kind != tools.OpDelete {
		t.Fatalf("first changed op = %v, want a delete", changed[0].Kind)
	}
	if changed[0].A.Offset != 123_456 || changed[0].A.Len != 1 {
		t.Errorf("delete span = %+v, want {Offset:123456 Len:1}", changed[0].A)
	}
	if got := rebuild(t, a, b, d); !bytes.Equal(got, b) {
		t.Errorf("ops must reconstruct b, got a %d-byte buffer", len(got))
	}
}

func TestIdenticalInputsProduceASingleEqualOp(t *testing.T) {
	a := []byte("HTTP/1.1 200 OK\r\nX: 1\r\n\r\nbody")
	d := check(t, a, a, tools.GranularityByte)
	if !d.IsIdentical() {
		t.Error("identical inputs must report identical")
	}
	if len(d.Ops) != 1 {
		t.Errorf("ops = %d, want a single equal op", len(d.Ops))
	}
	if d.Changes() != 0 {
		t.Errorf("changes = %d, want 0", d.Changes())
	}
}

func TestWordGranularityReportsOneChangedWordWhereBytesReportACharacter(t *testing.T) {
	a := []byte("the quick brown fox")
	b := []byte("the quick brawn fox")

	w := check(t, a, b, tools.GranularityWord)
	if w.DeletedTokens != 1 || w.InsertedTokens != 1 {
		t.Errorf("word: deleted/inserted = %d/%d, want 1/1", w.DeletedTokens, w.InsertedTokens)
	}
	by := check(t, a, b, tools.GranularityByte)
	if by.DeletedTokens != 1 || by.InsertedTokens != 1 {
		t.Errorf("byte: deleted/inserted = %d/%d, want 1/1", by.DeletedTokens, by.InsertedTokens)
	}

	// The word diff points at the whole word; the byte diff at the single character.
	var wDel core.Span
	found := false
	for i := range w.Ops {
		if w.Ops[i].Kind == tools.OpDelete {
			wDel = w.Ops[i].A
			found = true
		}
	}
	if !found {
		t.Fatal("word diff has no delete op")
	}
	if wDel.Offset != 10 || wDel.Len != 5 {
		t.Errorf("word delete span = %+v, want {Offset:10 Len:5} covering \"brown\"", wDel)
	}
}

func TestAPureInsertionIsReportedAsAnInsertWithNoDeletes(t *testing.T) {
	a := []byte("Host: x\r\n")
	b := []byte("Host: x\r\nCookie: s=1\r\n")
	d := check(t, a, b, tools.GranularityByte)
	if d.DeletedTokens != 0 {
		t.Errorf("deleted_tokens = %d, want 0", d.DeletedTokens)
	}
	if d.InsertedTokens != 13 {
		t.Errorf("inserted_tokens = %d, want 13 (Cookie: s=1 plus CRLF)", d.InsertedTokens)
	}
	if len(d.Ops) != 2 {
		t.Errorf("ops = %d, want one equal prefix then one insert", len(d.Ops))
	}
}

func TestAPureDeletionIsReportedAsADeleteWithNoInserts(t *testing.T) {
	d := check(t, []byte("abcdefXYZghij"), []byte("abcdefghij"), tools.GranularityByte)
	if d.InsertedTokens != 0 {
		t.Errorf("inserted_tokens = %d, want 0", d.InsertedTokens)
	}
	if d.DeletedTokens != 3 {
		t.Errorf("deleted_tokens = %d, want 3", d.DeletedTokens)
	}
}

func TestAnEmptySideIsAllInsertOrAllDelete(t *testing.T) {
	d := check(t, []byte(""), []byte("hello"), tools.GranularityByte)
	if d.InsertedTokens != 5 || d.DeletedTokens != 0 {
		t.Errorf("empty a: inserted/deleted = %d/%d, want 5/0", d.InsertedTokens, d.DeletedTokens)
	}
	d = check(t, []byte("hello"), []byte(""), tools.GranularityByte)
	if d.DeletedTokens != 5 || d.InsertedTokens != 0 {
		t.Errorf("empty b: deleted/inserted = %d/%d, want 5/0", d.DeletedTokens, d.InsertedTokens)
	}
	d = check(t, []byte(""), []byte(""), tools.GranularityByte)
	if len(d.Ops) != 0 {
		t.Errorf("empty/empty: ops = %d, want none", len(d.Ops))
	}
}

func TestInterleavedEditsAreAlignedRatherThanLumpedTogether(t *testing.T) {
	d := check(t, []byte("aXbXcXd"), []byte("aYbYcYd"), tools.GranularityByte)
	if d.Truncated {
		t.Error("three aligned substitutions must not truncate")
	}
	if d.DeletedTokens != 3 {
		t.Errorf("deleted_tokens = %d, want 3", d.DeletedTokens)
	}
	if d.InsertedTokens != 3 {
		t.Errorf("inserted_tokens = %d, want 3", d.InsertedTokens)
	}
	if d.EqualTokens != 4 {
		t.Errorf("equal_tokens = %d, want 4 (the surrounding letters stay aligned)", d.EqualTokens)
	}
}

// A single substitution with a long common prefix/suffix is unambiguous: the ops
// must come out in alignment order with exact spans. Mirrors comparer.rs's
// word-granularity vector and pins the op ordering the task asks about.
func TestOpsAreEmittedInOrderForASingleSubstitution(t *testing.T) {
	a := []byte("the quick brown fox")
	b := []byte("the quick brawn fox")

	d := check(t, a, b, tools.GranularityByte)
	want := []tools.OpKind{
		tools.OpEqual, tools.OpDelete, tools.OpInsert, tools.OpEqual,
	}
	if len(d.Ops) != len(want) {
		t.Fatalf("byte: got %d ops %v, want %d", len(d.Ops), kinds(d.Ops), len(want))
	}
	for i, k := range want {
		if d.Ops[i].Kind != k {
			t.Errorf("byte: op %d kind = %v, want %v (sequence %v)", i, d.Ops[i].Kind, k, kinds(d.Ops))
		}
	}
	if d.Ops[1].A.Offset != 12 || d.Ops[1].A.Len != 1 {
		t.Errorf("byte delete span = %+v, want the \"o\" at {Offset:12 Len:1}", d.Ops[1].A)
	}
	if d.Ops[2].B.Offset != 12 || d.Ops[2].B.Len != 1 {
		t.Errorf("byte insert span = %+v, want the \"a\" at {Offset:12 Len:1}", d.Ops[2].B)
	}

	wd := check(t, a, b, tools.GranularityWord)
	if len(wd.Ops) != len(want) {
		t.Fatalf("word: got %d ops %v, want %d", len(wd.Ops), kinds(wd.Ops), len(want))
	}
	for i, k := range want {
		if wd.Ops[i].Kind != k {
			t.Errorf("word: op %d kind = %v, want %v (sequence %v)", i, wd.Ops[i].Kind, k, kinds(wd.Ops))
		}
	}
	if wd.Ops[1].A.Offset != 10 || wd.Ops[1].A.Len != 5 {
		t.Errorf("word delete span = %+v, want \"brown\" at {Offset:10 Len:5}", wd.Ops[1].A)
	}
}

func kinds(ops []tools.Op) []tools.OpKind {
	out := make([]tools.OpKind, len(ops))
	for i := range ops {
		out[i] = ops[i].Kind
	}
	return out
}

func TestExhaustingTheBudgetFallsBackToAWholeRegionReplacementAndSaysSo(t *testing.T) {
	a := make([]byte, 2000)
	for i := range a {
		a[i] = byte(i % 251)
	}
	b := make([]byte, 2000)
	for i := range b {
		b[i] = byte(i%241 + 3)
	}
	d := tools.DiffWithBudget(a, b, tools.GranularityByte, 2)
	if !d.Truncated {
		t.Error("two unrelated buffers cannot align within D=2; must be truncated")
	}
	if got := rebuild(t, a, b, d); !bytes.Equal(got, b) {
		t.Error("a truncated diff is still a correct one: ops must reconstruct b")
	}
	del := 0
	for i := range d.Ops {
		if d.Ops[i].Kind == tools.OpDelete {
			del++
		}
	}
	if del != 1 {
		t.Errorf("delete ops = %d, want exactly one whole-region delete", del)
	}
}

// The default budget is derived from input size; on two large unrelated bodies
// it must bound the work and report truncation honestly instead of hanging.
func TestTheDefaultBudgetBoundsALargeDiffAndReportsTruncation(t *testing.T) {
	a := make([]byte, 200_000)
	b := make([]byte, 200_000)
	for i := range a {
		a[i] = "abcdefghij"[i%10]
		b[i] = "ABCDEFGHIJ"[i%10]
	}
	d := tools.Diff(a, b, tools.GranularityByte)
	if !d.Truncated {
		t.Error("two 200 KB unrelated bodies must exceed the size-derived budget and report it")
	}
	if got := rebuild(t, a, b, d); !bytes.Equal(got, b) {
		t.Error("a truncated diff is still a correct one: ops must reconstruct b")
	}
	if d.DeletedTokens != 200_000 || d.InsertedTokens != 200_000 {
		t.Errorf("deleted/inserted = %d/%d, want 200000/200000", d.DeletedTokens, d.InsertedTokens)
	}
}

// Spans index the original buffers, so nothing is copied. Ported from
// comparer.rs's spans_index_the_original_buffers_so_nothing_is_copied.
func TestSpansIndexTheOriginalBuffersSoNothingIsCopied(t *testing.T) {
	a := []byte("GET /a HTTP/1.1")
	b := []byte("GET /b HTTP/1.1")
	d := check(t, a, b, tools.GranularityWord)
	for _, op := range d.Ops {
		switch op.Kind {
		case tools.OpEqual:
			sa, sb := op.A, op.B
			if !bytes.Equal(a[sa.Offset:sa.End()], b[sb.Offset:sb.End()]) {
				t.Errorf("equal spans differ: a[%d:%d]=%q b[%d:%d]=%q",
					sa.Offset, sa.End(), a[sa.Offset:sa.End()],
					sb.Offset, sb.End(), b[sb.Offset:sb.End()])
			}
		case tools.OpDelete:
			s := op.A
			if !bytes.Equal(a[s.Offset:s.End()], []byte("/a")) {
				t.Errorf("delete span = %q, want %q", a[s.Offset:s.End()], "/a")
			}
		case tools.OpInsert:
			s := op.B
			if !bytes.Equal(b[s.Offset:s.End()], []byte("/b")) {
				t.Errorf("insert span = %q, want %q", b[s.Offset:s.End()], "/b")
			}
		}
	}
}

func TestTwoRealisticResponsesDifferingInOneHeaderAlignOnThatHeader(t *testing.T) {
	a := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: id=aaa\r\nX-Frame: DENY\r\n\r\n{}")
	b := []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nSet-Cookie: id=bbb\r\nX-Frame: DENY\r\n\r\n{}")
	d := check(t, a, b, tools.GranularityWord)
	if d.Changes() != 2 {
		t.Errorf("changes = %d, want 2 (one token out, one token in)", d.Changes())
	}
	var del core.Span
	found := false
	for i := range d.Ops {
		if d.Ops[i].Kind == tools.OpDelete {
			del = d.Ops[i].A
			found = true
		}
	}
	if !found {
		t.Fatal("no delete op in the header diff")
	}
	if s := string(a[del.Offset:del.End()]); s != "id=aaa" {
		t.Errorf("delete span content = %q, want %q", s, "id=aaa")
	}
}
