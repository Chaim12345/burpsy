package persist

import (
	"runtime"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Loading a segment-backed history must not read the raw column.
//
// SaveMessage stores X” for a row whose bytes already live in a segment file, so selecting raw for
// those rows makes SQLite hand back a blob handle per row and database/sql copy it through
// convertAssignRows. Measured against a 23,556-message history that path allocated 2.4 GB (787 MB of
// columnBlob plus 782 MB of bytes.Clone) before the first byte was ever used ? a restart cost the
// whole capture again. The reader asks for length(raw) instead, and fetches bytes only for a row that
// is genuinely resident. This pins the shape and the span across that change.
func TestLoadMessagesReadsNoRawBytesForSegmentRows(t *testing.T) {
	store, p, captureDir := diskBackedStore(t)

	raw := []byte("GET /span HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\n\r\nhello")
	if _, err := store.Put(raw, core.DirectionRequest); err != nil {
		t.Fatalf("put: %v", err)
	}

	src, err := core.NewSegmentLog(captureDir, 64<<20)
	if err != nil {
		t.Fatalf("segment log: %v", err)
	}
	t.Cleanup(func() { src.Close() })

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	msgs, err := p.LoadMessages(src)
	if err != nil {
		t.Fatalf("LoadMessages: %v", err)
	}
	runtime.ReadMemStats(&after)

	if len(msgs) != 1 {
		t.Fatalf("loaded %d messages, want 1", len(msgs))
	}
	m := msgs[0]
	if m.Location().Segment == "" {
		t.Error("message lost its segment location, so it would read as empty")
	}
	if got := string(m.Raw()); got != string(raw) {
		t.Errorf("message bytes = %q, want %q", got, raw)
	}

	// One small row can never cost much; the bound is what separates "read the span" from "read the
	// blob" ? the blob path copies the payload through database/sql even for X'' rows.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
		t.Errorf("LoadMessages allocated %d bytes for one segment row; the raw column should not be read", allocated)
	}
}
