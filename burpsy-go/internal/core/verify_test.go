package core

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

var (
	verifyReqMsg  = []byte("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
	verifyRespMsg = []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nhi!")
)

func putVerifyMessage(t *testing.T, ts *TrafficStore, raw []byte) MsgId {
	t.Helper()
	id, err := ts.Put(raw, DirectionRequest)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return id
}

func TestVerifyIndexCleanDiskBacked(t *testing.T) {
	dir := t.TempDir()
	ts, err := NewTrafficStoreWithCaptureDir(dir, 1<<30)
	if err != nil {
		t.Fatalf("NewTrafficStoreWithCaptureDir: %v", err)
	}
	req := putVerifyMessage(t, ts, verifyReqMsg)
	resp := putVerifyMessage(t, ts, verifyRespMsg)
	putVerifyMessage(t, ts, []byte("GET /b HTTP/1.1\r\nHost: b.test\r\n\r\nbody"))
	ts.AddExchange(&Exchange{Request: MsgPtr(req), Response: &resp, Host: "a.test"})
	// First exchange, so position-is-the-id gives it id 0.
	ts.AddWsMessage(&WsMessage{Exchange: 0, FromClient: true, AtMs: 1}, []byte("ping"))

	if err := ts.VerifyIndex(); err != nil {
		t.Fatalf("VerifyIndex on a coherent disk-backed store: %v", err)
	}
}

func TestVerifyIndexCleanInMemory(t *testing.T) {
	ts := NewTrafficStore()
	putVerifyMessage(t, ts, verifyReqMsg)
	putVerifyMessage(t, ts, verifyRespMsg)
	if err := ts.VerifyIndex(); err != nil {
		t.Fatalf("VerifyIndex on a coherent in-memory store: %v", err)
	}
}

func TestVerifyIndexNamesDesyncedMessageID(t *testing.T) {
	ts := NewTrafficStore()
	putVerifyMessage(t, ts, verifyReqMsg)
	putVerifyMessage(t, ts, verifyRespMsg)

	ts.messages[1].ID = MsgId(7)

	err := ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "position 1") || !strings.Contains(err.Error(), "id 7") {
		t.Errorf("error %q does not name position 1 carrying id 7", err)
	}
}

func TestVerifyIndexDetectsByteTotalDrift(t *testing.T) {
	ts := NewTrafficStore()
	putVerifyMessage(t, ts, verifyReqMsg)

	atomic.AddInt64(&ts.bytes, 1)

	err := ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a byte-total disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "byte total drifted") {
		t.Errorf("error %q does not name the byte-total drift", err)
	}
}

func TestVerifyIndexDetectsTruncatedSegment(t *testing.T) {
	dir := t.TempDir()
	ts, err := NewTrafficStoreWithCaptureDir(dir, 1<<30)
	if err != nil {
		t.Fatalf("NewTrafficStoreWithCaptureDir: %v", err)
	}
	raws := [][]byte{
		verifyReqMsg,
		verifyRespMsg,
		[]byte("GET /b HTTP/1.1\r\nHost: b.test\r\n\r\nbody!!!"),
	}
	for _, r := range raws {
		putVerifyMessage(t, ts, r)
	}

	seg := filepath.Join(dir, "segment_0.dat")
	info, err := os.Stat(seg)
	if err != nil {
		t.Fatalf("stat segment: %v", err)
	}
	// Cut exactly one byte off the end of the only segment. The last message's
	// byte range runs to the end of the file, so the first disagreement must be
	// that message's id.
	if err := os.Truncate(seg, info.Size()-1); err != nil {
		t.Fatalf("truncate segment: %v", err)
	}

	err = ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a segment disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "message 2") {
		t.Errorf("error %q does not name message 2", err)
	}
}

func TestVerifyIndexNamesDesyncedExchangeID(t *testing.T) {
	ts := NewTrafficStore()
	putVerifyMessage(t, ts, verifyReqMsg)
	ts.AddExchange(&Exchange{Request: MsgPtr(MsgId(0)), Host: "a.test"})

	ts.exchanges[0].ID = 5

	err := ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "position 0") || !strings.Contains(err.Error(), "id 5") {
		t.Errorf("error %q does not name exchange position 0 carrying id 5", err)
	}
}

func TestVerifyIndexNamesMissingChildReference(t *testing.T) {
	ts := NewTrafficStore()
	putVerifyMessage(t, ts, verifyReqMsg)
	ts.AddExchange(&Exchange{
		Request: MsgPtr(MsgId(0)),
		Host:    "a.test",
		Related: []ChildRef{{Type: ChildWsFrame, ID: MsgId(99)}},
	})

	err := ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "exchange 0") || !strings.Contains(err.Error(), "child message 99") {
		t.Errorf("error %q does not name exchange 0's dangling child 99", err)
	}
}

func TestVerifyIndexNamesOutOfRangeResponse(t *testing.T) {
	ts := NewTrafficStore()
	putVerifyMessage(t, ts, verifyReqMsg)
	resp := MsgId(99)
	ts.AddExchange(&Exchange{Request: MsgPtr(MsgId(0)), Response: &resp, Host: "a.test"})

	err := ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "exchange 0") || !strings.Contains(err.Error(), "response message 99") {
		t.Errorf("error %q does not name exchange 0's dangling response 99", err)
	}
}

func TestVerifyIndexNamesDesyncedWsID(t *testing.T) {
	ts := NewTrafficStore()
	ts.AddExchange(&Exchange{Request: MsgPtr(MsgId(0)), Host: "a.test"})
	ts.AddWsMessage(&WsMessage{Exchange: 0, AtMs: 1}, []byte("hi"))

	ts.wsMessages[0].ID = MsgId(3)

	err := ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "ws message at position 0") || !strings.Contains(err.Error(), "id 3") {
		t.Errorf("error %q does not name ws position 0 carrying id 3", err)
	}
}

func TestVerifyIndexNamesOutOfRangeWsPayload(t *testing.T) {
	ts := NewTrafficStore()
	ts.AddExchange(&Exchange{Request: MsgPtr(MsgId(0)), Host: "a.test"})
	ts.AddWsMessage(&WsMessage{Exchange: 0, AtMs: 1}, []byte("hi"))

	ts.wsMessages[0].Payload = MsgId(50)

	err := ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "ws message 0") || !strings.Contains(err.Error(), "payload 50") {
		t.Errorf("error %q does not name ws message 0's dangling payload 50", err)
	}
}

func TestVerifyIndexNamesUnknownWsExchange(t *testing.T) {
	ts := NewTrafficStore()
	ts.AddWsMessage(&WsMessage{Exchange: 99, AtMs: 1}, []byte("hi"))

	err := ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "ws message 0") || !strings.Contains(err.Error(), "exchange 99") {
		t.Errorf("error %q does not name ws message 0's unknown exchange 99", err)
	}
}

func TestVerifyIndexFreshOpenStoreVerifiesClean(t *testing.T) {
	dir := t.TempDir()

	first, err := NewTrafficStoreWithCaptureDir(dir, 1<<30)
	if err != nil {
		t.Fatalf("NewTrafficStoreWithCaptureDir: %v", err)
	}
	putVerifyMessage(t, first, verifyReqMsg)
	putVerifyMessage(t, first, verifyRespMsg)
	if err := first.VerifyIndex(); err != nil {
		t.Fatalf("first store after writing: %v", err)
	}
	if err := first.segmentLog.Close(); err != nil {
		t.Fatalf("close segment log: %v", err)
	}

	// A store opened on a directory that already holds segments must not false
	// positive on the previous capture: its own index is empty, so it has
	// nothing to resolve, and nothing it claims to have fails to read back.
	reopened, err := NewTrafficStoreWithCaptureDir(dir, 1<<30)
	if err != nil {
		t.Fatalf("reopen capture dir: %v", err)
	}
	if err := reopened.VerifyIndex(); err != nil {
		t.Fatalf("fresh-open store with an empty index must verify clean, got %v", err)
	}

	// A message appended after reopening resolves at the resumed offset, not at
	// position zero of a previous life.
	putVerifyMessage(t, reopened, []byte("GET /c HTTP/1.1\r\nHost: c.test\r\n\r\nresumed"))
	if err := reopened.VerifyIndex(); err != nil {
		t.Fatalf("resumed store after writing: %v", err)
	}
}

func TestVerifyIndexNamesTamperedLocation(t *testing.T) {
	dir := t.TempDir()
	ts, err := NewTrafficStoreWithCaptureDir(dir, 1<<30)
	if err != nil {
		t.Fatalf("NewTrafficStoreWithCaptureDir: %v", err)
	}
	putVerifyMessage(t, ts, verifyReqMsg)

	// Shrink the recorded on-disk length of message 0 so it still resolves (the
	// bytes are there) but disagrees with both the location and the resident
	// bytes the index believes it holds.
	ts.locations[0].Length--

	err = ts.VerifyIndex()
	if err == nil {
		t.Fatal("expected a disagreement, got nil")
	}
	if !strings.Contains(err.Error(), "message 0") || !strings.Contains(err.Error(), "drifted apart") {
		t.Errorf("error %q does not name message 0's drifted location", err)
	}
}
