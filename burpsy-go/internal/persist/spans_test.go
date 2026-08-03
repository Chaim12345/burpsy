package persist

import (
	"path/filepath"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// diskBackedStore opens a store whose bytes live in segment files, mirrored by a
// real database, and returns both plus the capture directory.
func diskBackedStore(t *testing.T) (*core.TrafficStore, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	captureDir := filepath.Join(dir, "capture")
	store, err := core.NewTrafficStoreWithCaptureDir(captureDir, 64<<20)
	if err != nil {
		t.Fatalf("open traffic store: %v", err)
	}
	p, err := Open(filepath.Join(dir, "state.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open persist store: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)
	return store, p, captureDir
}

// The mirror must record a span, not the bytes, whenever the bytes are already
// durable in a segment file. Mirroring them as well stored every byte three
// times over — heap, segment, blob — and was worth 436 MB against 8 MB on a
// 419 MB capture.
func TestAMirroredMessageStoresItsSpanRatherThanItsBytes(t *testing.T) {
	store, p, _ := diskBackedStore(t)

	raw := []byte("GET /spans HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\nhello")
	if _, err := store.Put(raw, core.DirectionRequest); err != nil {
		t.Fatalf("put: %v", err)
	}

	var segment string
	var offset, length int64
	var blobLen int
	err := p.db.QueryRow(`SELECT segment, offset, length, length(raw) FROM messages WHERE id = 0`).
		Scan(&segment, &offset, &length, &blobLen)
	if err != nil {
		t.Fatalf("read back row: %v", err)
	}
	if segment == "" {
		t.Error("row carries no segment, so the mirror kept no way to find the bytes")
	}
	if length != int64(len(raw)) {
		t.Errorf("row length = %d, want %d", length, len(raw))
	}
	if blobLen != 0 {
		t.Errorf("row still carries %d bytes of payload — the bytes are in the segment already, "+
			"and storing them twice is what this change removes", blobLen)
	}
}

// Without a capture directory SQLite is the only durable copy, so it must still
// take the bytes. Dropping them here would lose traffic outright.
func TestAMirroredMessageStoresItsBytesWhenThereIsNoSegment(t *testing.T) {
	p := newTestStore(t)
	store := core.NewTrafficStore()
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)

	raw := []byte("GET /mem HTTP/1.1\r\nHost: a.test\r\n\r\n")
	if _, err := store.Put(raw, core.DirectionRequest); err != nil {
		t.Fatalf("put: %v", err)
	}

	var segment any
	var blobLen int
	if err := p.db.QueryRow(`SELECT segment, length(raw) FROM messages WHERE id = 0`).
		Scan(&segment, &blobLen); err != nil {
		t.Fatalf("read back row: %v", err)
	}
	if segment != nil {
		t.Errorf("row claims segment %v, but this store has no capture directory to point at", segment)
	}
	if blobLen != len(raw) {
		t.Errorf("row holds %d bytes, want %d — with no segment file, SQLite is the only durable copy",
			blobLen, len(raw))
	}
}

// The round trip that matters: restore an entire disk-backed store and get the
// same bytes back, without any message holding them.
func TestRestoreRebuildsDiskBackedMessagesFromSpans(t *testing.T) {
	store, p, captureDir := diskBackedStore(t)

	bodies := []string{"alpha", "beta-body-somewhat-longer", "gamma"}
	var wants []string
	for i, body := range bodies {
		raw := []byte("POST /r HTTP/1.1\r\nHost: a.test\r\nX-Case: " +
			body + "\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body)
		wants = append(wants, string(raw))
		if _, err := store.Put(raw, core.DirectionRequest); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}

	// A fresh store over the same capture directory, restored from the mirror.
	restored, err := core.NewTrafficStoreWithCaptureDir(captureDir, 64<<20)
	if err != nil {
		t.Fatalf("reopen traffic store: %v", err)
	}
	if err := p.Restore(restored, nil, nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	msgs, _ := restored.Count()
	if msgs != len(bodies) {
		t.Fatalf("restored %d messages, want %d", msgs, len(bodies))
	}
	for i := range bodies {
		m, err := restored.Get(core.MsgId(i))
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if got := string(m.Raw()); got != wants[i] {
			t.Errorf("message %d came back as %q, want %q", i, got, wants[i])
		}
		if got := string(m.Header("x-case")); got != bodies[i] {
			t.Errorf("message %d header = %q, want %q — the shape must survive the restore",
				i, got, bodies[i])
		}
		if m.Location().Segment == "" {
			t.Errorf("message %d came back resident, so restoring a capture still costs its size in memory", i)
		}
	}
	if err := restored.VerifyIndex(); err != nil {
		t.Errorf("VerifyIndex after restore: %v — the rebuilt index disagrees with the log", err)
	}
}

// A database written by an older build has bytes and no span. It must still
// load, as a resident message, or upgrading would lose every capture recorded
// so far.
func TestARowWrittenBeforeSpansExistedStillLoads(t *testing.T) {
	p := newTestStore(t)
	raw := []byte("GET /legacy HTTP/1.1\r\nHost: old.test\r\n\r\n")
	// Exactly what the previous schema wrote: three columns, no span.
	if _, err := p.db.Exec(`INSERT INTO messages (id, direction, raw) VALUES (0, 0, ?)`, raw); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	msgs, err := p.LoadMessages(nil)
	if err != nil {
		t.Fatalf("LoadMessages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("loaded %d messages, want 1", len(msgs))
	}
	if got := string(msgs[0].Raw()); got != string(raw) {
		t.Errorf("legacy row loaded as %q, want %q", got, raw)
	}
	if msgs[0].Location().Segment != "" {
		t.Error("legacy row claims a segment location it never had")
	}
}

// A span with no log to resolve it against must be reported. Returning a
// message whose bytes silently read as empty would turn a misconfigured capture
// directory into findings that quietly saw nothing.
func TestASpanWithNoSegmentLogIsRefusedRatherThanReadAsEmpty(t *testing.T) {
	p := newTestStore(t)
	if _, err := p.db.Exec(
		`INSERT INTO messages (id, direction, raw, segment, offset, length)
		 VALUES (0, 0, X'', '/nonexistent/segment_0.dat', 0, 40)`); err != nil {
		t.Fatalf("insert span row: %v", err)
	}

	if _, err := p.LoadMessages(nil); err == nil {
		t.Error("LoadMessages accepted a span with no segment log, so the message would read as empty")
	}
}

// migrate runs on every Open, so it has to be idempotent: the second Open must
// not fail trying to add columns that are already there.
func TestOpeningAnExistingDatabaseTwiceDoesNotReMigrate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "twice.db")
	first, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	raw := []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
	shape, err := core.Parse(raw, core.DirectionRequest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	first.SaveMessage(core.NewResidentMessage(0, raw, shape))
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := Open(path, zap.NewNop())
	if err != nil {
		t.Fatalf("second Open: %v — migrate is not idempotent", err)
	}
	defer second.Close()
	msgs, err := second.LoadMessages(nil)
	if err != nil {
		t.Fatalf("LoadMessages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("loaded %d messages after reopen, want 1", len(msgs))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
