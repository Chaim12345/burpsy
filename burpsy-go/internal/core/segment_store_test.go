package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func req(host, path string, bodyLen int) []byte {
	body := make([]byte, bodyLen)
	for i := range body {
		body[i] = 'a' + byte(i%26)
	}
	return []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nX-Trace: t-%s\r\n\r\n%s",
		path, host, bodyLen, path, body))
}

// A disk-backed store must not hold the payload. This is the whole memory
// thesis in one assertion: the previous implementation appended the bytes to a
// segment and then kept them anyway ("also keep in memory for simplicity"), so
// a capture directory bought disk cost and nothing else.
func TestASegmentBackedMessageKeepsNoBytesOnTheHeap(t *testing.T) {
	dir := t.TempDir()
	ts, err := NewTrafficStoreWithCaptureDir(dir, 64<<20)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ts.segmentLog.Close()

	raw := req("a.test", "/one", 4096)
	id, err := ts.Put(raw, DirectionRequest)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	msg, err := ts.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !ts.segmentLog.Mappable() {
		t.Skip("platform cannot map segments, so the store keeps bytes resident by design")
	}
	if msg.resident != nil {
		t.Errorf("message holds %d resident bytes, want none — the segment already has them",
			len(msg.resident))
	}
	if msg.Location().Segment == "" {
		t.Error("message carries no location, so nothing could resolve its bytes later")
	}
	if msg.Len() != len(raw) {
		t.Errorf("Len() = %d, want %d — length must be readable without materialising the message",
			msg.Len(), len(raw))
	}
}

// Holding no bytes is only useful if the bytes are still readable. Mutating the
// caller's buffer after the Put must not change what the store returns, because
// segment mode used to alias it rather than copy it.
func TestASegmentBackedMessageStillServesItsBytesAndSpans(t *testing.T) {
	dir := t.TempDir()
	ts, err := NewTrafficStoreWithCaptureDir(dir, 64<<20)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ts.segmentLog.Close()

	raw := req("a.test", "/two", 2048)
	want := string(raw)
	id, err := ts.Put(raw, DirectionRequest)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	for i := range raw {
		raw[i] = 0 // the caller reuses its buffer; the store must not have aliased it
	}

	msg, err := ts.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got := string(msg.Raw()); got != want {
		t.Errorf("Raw() returned %d bytes that do not match what was stored (want %d) — "+
			"the store aliased the caller's buffer instead of reading its own copy",
			len(got), len(want))
	}
	// Header slices once per header, so this is the path that would collapse if
	// every span cost a fresh read of the whole message.
	if got := string(msg.Header("x-trace")); got != "t-/two" {
		t.Errorf("Header(x-trace) = %q, want %q — spans must resolve against the segment", got, "t-/two")
	}
	if got := len(msg.Body()); got != 2048 {
		t.Errorf("Body() = %d bytes, want 2048", got)
	}
}

// Rotation is the seal point: a segment stops growing, gets synced, and only
// then becomes safe to map. Messages written either side of a rotation must
// both still resolve.
func TestMessagesResolveAcrossASegmentRotation(t *testing.T) {
	dir := t.TempDir()
	// A tiny target forces a rotation every few messages.
	ts, err := NewTrafficStoreWithCaptureDir(dir, 4096)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ts.segmentLog.Close()

	var ids []MsgId
	var wants []string
	for i := 0; i < 12; i++ {
		raw := req("a.test", fmt.Sprintf("/r%d", i), 1024)
		wants = append(wants, string(raw))
		id, err := ts.Put(raw, DirectionRequest)
		if err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read capture dir: %v", err)
	}
	if len(entries) < 2 {
		t.Fatalf("capture dir holds %d segments, want at least 2 — the rotation this test exercises never happened",
			len(entries))
	}

	for i, id := range ids {
		msg, err := ts.Get(id)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if got := string(msg.Raw()); got != wants[i] {
			t.Errorf("message %d did not round-trip through its segment: got %d bytes, want %d",
				i, len(got), len(wants[i]))
		}
	}
	if err := ts.VerifyIndex(); err != nil {
		t.Errorf("VerifyIndex: %v — the index and the segment log disagree after rotation", err)
	}
}

// Without a capture directory SQLite (or nothing) is the only durable home for
// the bytes, so the store must still keep them.
func TestAStoreWithNoCaptureDirKeepsItsBytesResident(t *testing.T) {
	ts := NewTrafficStore()
	raw := req("a.test", "/mem", 512)
	id, err := ts.Put(raw, DirectionRequest)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	msg, err := ts.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if msg.resident == nil {
		t.Fatal("in-memory store dropped the payload, and there is no segment to recover it from")
	}
	if msg.Location().Segment != "" {
		t.Errorf("resident message claims location %q — it has no disk record to point at",
			msg.Location().Segment)
	}
	if got := string(msg.Raw()); got != string(raw) {
		t.Error("Raw() did not return the stored bytes")
	}
}

// A location that no longer resolves must be reported, not silently served as a
// short buffer: callers slice spans off Raw, and a truncated buffer would turn
// into plausible-looking nonsense.
func TestALocationOutsideItsSegmentIsRefusedRatherThanTruncated(t *testing.T) {
	dir := t.TempDir()
	sl, err := NewSegmentLog(dir, 4096)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer sl.Close()

	loc, err := sl.Append(MsgId(0), DirectionRequest, []byte("hello"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	beyond := Location{Segment: loc.Segment, Offset: loc.Offset, Length: 5000}
	if _, err := sl.ReadAt(beyond); err == nil {
		t.Error("ReadAt accepted a length past the end of the segment, so a caller would slice spans out of a short buffer")
	}
	if _, err := sl.ReadAt(Location{}); err == nil {
		t.Error("ReadAt accepted a location naming no segment")
	}
}

// The active segment is deliberately not mapped, because a mapping is fixed at
// the length the file had when it was made and reading past that is a SIGBUS
// rather than an error. It must still be readable.
func TestTheActiveSegmentIsReadableWithoutBeingMapped(t *testing.T) {
	dir := t.TempDir()
	sl, err := NewSegmentLog(dir, 1<<20)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer sl.Close()

	loc, err := sl.Append(MsgId(0), DirectionRequest, []byte("active-segment-bytes"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, mapped := sl.mapping(loc.Segment); mapped {
		t.Error("the segment still being appended to was mapped, which is the SIGBUS-on-growth case")
	}
	got, err := sl.ReadAt(loc)
	if err != nil {
		t.Fatalf("ReadAt on the active segment: %v", err)
	}
	if string(got) != "active-segment-bytes" {
		t.Errorf("ReadAt = %q, want the appended bytes", got)
	}
	if filepath.Dir(loc.Segment) != dir {
		t.Errorf("segment %q was not written under the capture dir %q", loc.Segment, dir)
	}
}

// VerifyCaptureDir used to look for "segment-*.log" while the writer produced
// "segment_%d.dat", so it matched nothing and returned a clean report having
// examined no files at all. For a project whose value is honest counting, a
// verifier that passes by looking at nothing is the worst possible failure.
func TestVerifyCaptureDirActuallyFindsTheSegmentsThatWereWritten(t *testing.T) {
	dir := t.TempDir()
	ts, err := NewTrafficStoreWithCaptureDir(dir, 4096)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	var written int64
	for i := 0; i < 10; i++ {
		raw := req("a.test", fmt.Sprintf("/v%d", i), 1024)
		if _, err := ts.Put(raw, DirectionRequest); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
		written += int64(len(raw))
	}
	if err := ts.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	verdicts := VerifyCaptureDir(dir)
	if len(verdicts) == 0 {
		t.Fatal("VerifyCaptureDir examined no segments at all, yet the store just wrote several")
	}
	var records int
	var payload int64
	for _, v := range verdicts {
		if v.Fault != nil {
			t.Errorf("segment %s reported a fault: %s", v.Path, *v.Fault)
		}
		records += v.Records
		payload += v.PayloadBytes
	}
	if records != 10 {
		t.Errorf("verified %d records across %d segments but 10 messages were stored — every "+
			"record written must be walked, not just every byte", records, len(verdicts))
	}
	if payload != written {
		t.Errorf("verified %d payload bytes across %d segments but %d were written — PayloadBytes "+
			"must count the message bytes actually checksummed", payload, len(verdicts), written)
	}
}

// An unreadable directory is a fault to report, not an empty pass.
func TestVerifyCaptureDirReportsADirectoryItCannotRead(t *testing.T) {
	verdicts := VerifyCaptureDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(verdicts) != 1 || verdicts[0].Fault == nil {
		t.Fatalf("verdicts = %+v, want a single verdict naming the fault", verdicts)
	}
}
