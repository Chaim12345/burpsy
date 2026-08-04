package core

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The framing these tests pin is the difference between a capture that can be
// checked and one that can only be re-read. Every assertion below exists
// because the previous format — a bare concatenation of payloads — made the
// corresponding question unanswerable from the file alone.

func firstRecordPayloadOffset() int64 { return SegmentFileHeaderLen + RecordHeaderLen }

// nthRecordHeaderOffset returns where the header of the record after the given
// payload lengths starts, so a test can aim at a specific record's bytes
// without re-deriving the arithmetic each time.
func nthRecordHeaderOffset(payloadLens ...int) int64 {
	at := int64(SegmentFileHeaderLen)
	for _, n := range payloadLens {
		at += RecordHeaderLen + int64(n)
	}
	return at
}

func TestARecordHeaderRoundTripsEveryField(t *testing.T) {
	for _, h := range []RecordHeader{
		{Len: 0, MsgID: 0, Direction: DirectionRequest, CRC32: 0},
		{Len: 1, MsgID: 1, Direction: DirectionResponse, CRC32: 0xFFFFFFFF},
		{Len: ^uint32(0), MsgID: 0xDEADBEEFCAFEF00D, Direction: DirectionRequest, CRC32: 0x12345678},
		{Len: 4096, MsgID: 42, Direction: DirectionResponse, CRC32: 0x9ABCDEF0},
	} {
		raw, ok := h.encode()
		if !ok {
			t.Fatalf("encode(%+v) refused a direction it must accept", h)
		}
		if len(raw) != RecordHeaderLen {
			t.Fatalf("encoded header is %d bytes, want %d", len(raw), RecordHeaderLen)
		}
		got, fault := decodeRecordHeader(0, raw[:])
		if fault != nil {
			t.Fatalf("decode of a header we just wrote reported %v", fault)
		}
		if got != h {
			t.Errorf("header did not survive an encode/decode round trip: got %+v, want %+v", got, h)
		}
	}
}

// A header read from a file that ended early must say what was missing, not
// silently read the bytes that happen to follow it.
func TestAHeaderDecodedFromTooFewBytesNamesWhatWasMissing(t *testing.T) {
	for have := 0; have < RecordHeaderLen; have++ {
		_, fault := decodeRecordHeader(64, make([]byte, have))
		if fault == nil {
			t.Fatalf("decode accepted %d bytes as a %d-byte header", have, RecordHeaderLen)
		}
		if fault.Kind != CorruptShortHeader || fault.At != 64 ||
			fault.Need != RecordHeaderLen || fault.Have != int64(have) {
			t.Errorf("fault %+v does not name %d of %d bytes at offset 64", fault, have, RecordHeaderLen)
		}
		if !strings.Contains(fault.Error(), "byte 64") {
			t.Errorf("fault text %q does not say where it was found", fault.Error())
		}
	}
}

// Defaulting an unrecognised direction to request would turn a damaged file
// into a plausible-looking one, so it is corruption on the way in and refused
// on the way out.
func TestADirectionByteOutsideTheEncodedSetIsCorruptionNotADefault(t *testing.T) {
	raw, ok := RecordHeader{Len: 3, MsgID: 7, Direction: DirectionRequest}.encode()
	if !ok {
		t.Fatal("encode refused a request direction")
	}
	raw[12] = 2
	_, fault := decodeRecordHeader(99, raw[:])
	if fault == nil {
		t.Fatal("decode accepted direction byte 2 as a real direction")
	}
	if fault.Kind != CorruptUnknownDirection || fault.At != 99 || fault.DirectionByte != 2 {
		t.Errorf("fault %+v does not name direction byte 2 at offset 99", fault)
	}
}

func TestAnUnencodableDirectionIsRefusedRatherThanRecordedAsARequest(t *testing.T) {
	dir := t.TempDir()
	sl, err := NewSegmentLog(dir, 1<<20)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer sl.Close()

	if _, err := sl.Append(MsgId(0), Direction(7), []byte("payload")); err == nil {
		t.Fatal("Append recorded a message whose direction it could not encode, so the file now " +
			"claims a direction the caller never asked for")
	}
}

func TestAFreshSegmentFileStartsWithTheMagicAndVersion(t *testing.T) {
	dir := t.TempDir()
	sl, err := NewSegmentLog(dir, 1<<20)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer sl.Close()

	loc, err := sl.Append(MsgId(0), DirectionRequest, []byte("hi"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	raw, err := os.ReadFile(loc.Segment)
	if err != nil {
		t.Fatalf("read segment: %v", err)
	}
	if string(raw[:8]) != segmentMagic {
		t.Errorf("segment starts with %q, want the magic %q", raw[:8], segmentMagic)
	}
	if raw[8] != SegmentFormatVersion {
		t.Errorf("segment declares format version %d, want %d", raw[8], SegmentFormatVersion)
	}
	for i := 9; i < SegmentFileHeaderLen; i++ {
		if raw[i] != 0 {
			t.Errorf("reserved byte %d is %d, want 0 — a later field cannot claim a byte that is "+
				"already carrying something", i, raw[i])
		}
	}
	// The location must point past the framing at the payload itself, which is
	// what keeps every read path free of any knowledge that framing exists.
	if loc.Offset != firstRecordPayloadOffset() {
		t.Errorf("first payload is at offset %d, want %d (file header + record header)",
			loc.Offset, firstRecordPayloadOffset())
	}
	if loc.Length != 2 {
		t.Errorf("location length %d describes something other than the 2-byte payload", loc.Length)
	}
}

// The fault the whole format exists for: a payload byte rewritten in place. The
// file is exactly as long as it was, so the old read-to-EOF check passed it,
// and every span still resolved to a plausible-looking message.
func TestAFlippedPayloadByteIsCaughtEvenThoughTheLengthIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	sl, err := NewSegmentLog(dir, 1<<20)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	first, second := []byte("first-record"), []byte("second-record")
	if _, err := sl.Append(MsgId(0), DirectionRequest, first); err != nil {
		t.Fatalf("append first: %v", err)
	}
	loc, err := sl.Append(MsgId(41), DirectionResponse, second)
	if err != nil {
		t.Fatalf("append second: %v", err)
	}
	if err := sl.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}

	before, err := os.Stat(loc.Segment)
	if err != nil {
		t.Fatalf("stat segment: %v", err)
	}
	// Flip one byte inside the *second* record's payload: same length, and the
	// first record must still read back cleanly.
	file, err := os.OpenFile(loc.Segment, os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open segment for writing: %v", err)
	}
	if _, err := file.WriteAt([]byte("X"), loc.Offset); err != nil {
		t.Fatalf("flip byte: %v", err)
	}
	file.Close()
	after, err := os.Stat(loc.Segment)
	if err != nil {
		t.Fatalf("re-stat segment: %v", err)
	}
	if before.Size() != after.Size() {
		t.Fatalf("the flip changed the file size (%d -> %d), so this test is not exercising the "+
			"same-length case it exists for", before.Size(), after.Size())
	}

	scan, err := ScanSegmentFile(loc.Segment)
	if err != nil {
		t.Fatalf("scan: %v — a flipped payload is a per-record fault, not a whole-file one", err)
	}
	if scan.Corrupt == nil {
		t.Fatal("the scan reported no corruption for a payload that was rewritten after it was written")
	}
	if scan.Corrupt.Kind != CorruptChecksumMismatch {
		t.Fatalf("fault %+v is not a checksum mismatch", scan.Corrupt)
	}
	if scan.Corrupt.ID != MsgId(41) {
		t.Errorf("the verdict blames message %d, but message 41 is the one that changed", scan.Corrupt.ID)
	}
	if scan.Corrupt.Stored == scan.Corrupt.Recomputed {
		t.Error("the verdict reports matching checksums yet still calls it a mismatch")
	}
	if scan.Corrupt.At != nthRecordHeaderOffset(len(first)) {
		t.Errorf("the verdict points at byte %d, want the second record's header at %d",
			scan.Corrupt.At, nthRecordHeaderOffset(len(first)))
	}
	if len(scan.Records) != 1 {
		t.Errorf("the scan kept %d records read before the fault, want 1 — a fault must not "+
			"discard what was already verified", len(scan.Records))
	}
	// The same fault must reach an operator through the verdict, not only
	// through the typed scan.
	verdicts := VerifyCaptureDir(dir)
	if len(verdicts) != 1 || verdicts[0].Fault == nil {
		t.Fatalf("VerifyCaptureDir returned %+v for a directory holding a corrupt segment", verdicts)
	}
	if verdicts[0].Corrupt == nil || verdicts[0].Corrupt.Kind != CorruptChecksumMismatch {
		t.Errorf("verdict carries %+v, want the typed checksum mismatch", verdicts[0].Corrupt)
	}
	if !strings.Contains(*verdicts[0].Fault, "message 41") {
		t.Errorf("verdict text %q does not name the failing message", *verdicts[0].Fault)
	}
}

// A write that was cut off — the process died mid-record, or the file was
// truncated — must be reported as corruption. The old check read to EOF, so a
// file that simply stopped early was indistinguishable from a complete one.
func TestATruncatedFinalRecordIsReportedAsCorruptionNotAcceptedSilently(t *testing.T) {
	for _, tc := range []struct {
		name string
		// cut is how many bytes to remove from the end.
		cut  int64
		want CorruptKind
	}{
		// The payload is cut short but its header survives, so the header
		// declares more than the file holds.
		{name: "payload cut short", cut: 100, want: CorruptLengthOverrunsSegment},
		// The file ends inside the record header itself.
		{name: "header cut short", cut: 300 + 5, want: CorruptShortHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sl, err := NewSegmentLog(dir, 1<<20)
			if err != nil {
				t.Fatalf("open log: %v", err)
			}
			loc, err := sl.Append(MsgId(3), DirectionRequest, bytes.Repeat([]byte("q"), 300))
			if err != nil {
				t.Fatalf("append: %v", err)
			}
			if err := sl.Close(); err != nil {
				t.Fatalf("close log: %v", err)
			}

			info, err := os.Stat(loc.Segment)
			if err != nil {
				t.Fatalf("stat segment: %v", err)
			}
			if err := os.Truncate(loc.Segment, info.Size()-tc.cut); err != nil {
				t.Fatalf("truncate segment: %v", err)
			}

			scan, err := ScanSegmentFile(loc.Segment)
			if err != nil {
				t.Fatalf("scan: %v — a torn record is a per-record fault, not a whole-file one", err)
			}
			if scan.Corrupt == nil {
				t.Fatal("a segment missing the end of its last record was accepted as clean")
			}
			if scan.Corrupt.Kind != tc.want {
				t.Errorf("fault %+v (%s) is not the expected kind %d", scan.Corrupt, scan.Corrupt.Error(), tc.want)
			}
			if scan.Corrupt.At != SegmentFileHeaderLen {
				t.Errorf("the verdict points at byte %d, want the only record's header at %d",
					scan.Corrupt.At, SegmentFileHeaderLen)
			}
			if len(scan.Records) != 0 {
				t.Errorf("the scan claims %d complete records in a file holding one torn one",
					len(scan.Records))
			}
			if verdicts := VerifyCaptureDir(dir); len(verdicts) != 1 || verdicts[0].Fault == nil {
				t.Errorf("VerifyCaptureDir returned %+v for a truncated segment", verdicts)
			}
		})
	}
}

// End to end: several records, more than one segment, every payload readable
// back through the ordinary read path, and every file verifying clean.
func TestRecordsRoundTripAcrossSegmentsAndEverySegmentVerifiesClean(t *testing.T) {
	dir := t.TempDir()
	// Small enough that ~400-byte records rotate every few appends.
	sl, err := NewSegmentLog(dir, 2048)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer sl.Close()

	type written struct {
		loc  Location
		body []byte
	}
	var records []written
	for i := 0; i < 20; i++ {
		body := []byte(fmt.Sprintf("record-%02d:%s", i, strings.Repeat("z", 400)))
		direction := DirectionRequest
		if i%2 == 1 {
			direction = DirectionResponse
		}
		loc, err := sl.Append(MsgId(i), direction, body)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		records = append(records, written{loc: loc, body: body})
	}
	if err := sl.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	segments := map[string]bool{}
	for i, r := range records {
		segments[r.loc.Segment] = true
		got, err := sl.Read(r.loc)
		if err != nil {
			t.Fatalf("read record %d back: %v", i, err)
		}
		if !bytes.Equal(got, r.body) {
			t.Errorf("record %d read back as %d bytes that are not what was written (%d bytes)",
				i, len(got), len(r.body))
		}
	}
	if len(segments) < 2 {
		t.Fatalf("all %d records landed in one segment, so this test never exercised a rotation",
			len(records))
	}

	verdicts := VerifyCaptureDir(dir)
	if len(verdicts) != len(segments) {
		t.Errorf("VerifyCaptureDir examined %d segments but the records live in %d",
			len(verdicts), len(segments))
	}
	total := 0
	for _, v := range verdicts {
		if v.Fault != nil {
			t.Errorf("segment %s reported a fault on a capture nothing has touched: %s", v.Path, *v.Fault)
		}
		if v.Corrupt != nil {
			t.Errorf("segment %s reported corruption %+v on a clean capture", v.Path, v.Corrupt)
		}
		total += v.Records
	}
	if total != len(records) {
		t.Errorf("the verify pass walked %d records but %d were written", total, len(records))
	}

	// Every scanned record must agree with the location its append handed out,
	// which is what makes a scan usable to rebuild an index rather than only to
	// pass or fail a file.
	for path := range segments {
		scan, err := ScanSegmentFile(path)
		if err != nil {
			t.Fatalf("scan %s: %v", path, err)
		}
		for _, sr := range scan.Records {
			var match *written
			for i := range records {
				if records[i].loc == sr.Loc {
					match = &records[i]
					break
				}
			}
			if match == nil {
				t.Errorf("scan of %s reports a record at %+v that no append ever returned", path, sr.Loc)
				continue
			}
			if sr.Header.Len != uint32(len(match.body)) {
				t.Errorf("record %d declares %d bytes, want %d", sr.Header.MsgID, sr.Header.Len, len(match.body))
			}
			if sr.Header.CRC32 != crc32.ChecksumIEEE(match.body) {
				t.Errorf("record %d carries a checksum that does not match its payload", sr.Header.MsgID)
			}
			wantDir := DirectionRequest
			if uint64(sr.Header.MsgID)%2 == 1 {
				wantDir = DirectionResponse
			}
			if sr.Header.Direction != wantDir {
				t.Errorf("record %d came back as direction %d, want %d — the direction a message "+
					"was captured in must survive the round trip", sr.Header.MsgID, sr.Header.Direction, wantDir)
			}
		}
	}
}

// A clean disk-backed store must verify clean through the store's own API, not
// only through a hand-built log.
func TestVerifyCaptureDirOnACleanStoreReportsNoCorruption(t *testing.T) {
	dir := t.TempDir()
	ts, err := NewTrafficStoreWithCaptureDir(dir, 4096)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer ts.Close()

	for i := 0; i < 8; i++ {
		if _, err := ts.Put(req("a.test", fmt.Sprintf("/clean%d", i), 512), DirectionRequest); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if err := ts.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	verdicts := VerifyCaptureDir(dir)
	if len(verdicts) == 0 {
		t.Fatal("VerifyCaptureDir examined nothing, yet the store just wrote a capture")
	}
	records := 0
	for _, v := range verdicts {
		if v.Fault != nil || v.Corrupt != nil {
			t.Errorf("segment %s: fault %v, corrupt %+v — nothing has touched this capture",
				v.Path, v.Fault, v.Corrupt)
		}
		records += v.Records
	}
	if records != 8 {
		t.Errorf("the verify pass walked %d records but 8 messages were stored", records)
	}
	if err := ts.VerifyIndex(); err != nil {
		t.Errorf("VerifyIndex on a clean disk-backed store: %v", err)
	}
}

// A file that is not one of ours is refused as what it is. Reading it as a
// damaged segment would produce a record verdict about a file that never had
// records in it.
func TestAFileThatIsNotASegmentIsRefusedByNameRatherThanMisread(t *testing.T) {
	for _, tc := range []struct {
		name       string
		content    []byte
		wantInText string
	}{
		{name: "foreign file", content: []byte("NOTBURPSY and then some padding bytes"), wantInText: "bad magic"},
		{name: "too short", content: []byte("tiny"), wantInText: "too short"},
		{name: "future version", content: func() []byte {
			head := segmentFileHeader()
			head[8] = SegmentFormatVersion + 9
			return head[:]
		}(), wantInText: "format version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, fmt.Sprintf(segmentNameFormat, 0))
			if err := os.WriteFile(path, tc.content, 0644); err != nil {
				t.Fatalf("write file: %v", err)
			}

			if _, err := ScanSegmentFile(path); err == nil {
				t.Error("the scan accepted a file that is not a segment of ours")
			} else if !strings.Contains(err.Error(), tc.wantInText) {
				t.Errorf("refusal %q does not say %q", err, tc.wantInText)
			}

			verdicts := VerifyCaptureDir(dir)
			if len(verdicts) != 1 || verdicts[0].Fault == nil {
				t.Fatalf("VerifyCaptureDir returned %+v, want one verdict naming the fault", verdicts)
			}
			if !strings.Contains(*verdicts[0].Fault, tc.wantInText) {
				t.Errorf("verdict %q does not say %q", *verdicts[0].Fault, tc.wantInText)
			}
			if verdicts[0].Records != 0 {
				t.Errorf("verdict claims %d records checked in a file that was never readable",
					verdicts[0].Records)
			}

			// Appending to it would write records after bytes we cannot read
			// back, so opening the directory is refused too.
			if _, err := NewSegmentLog(dir, 1<<20); err == nil {
				t.Error("NewSegmentLog resumed a file it cannot read, so the next record would " +
					"land after bytes no scan can walk")
			}
		})
	}
}

// Resuming must not write a second file header: one in the middle of a file
// would be walked as a record header declaring a nonsense length.
func TestResumingASegmentDoesNotWriteASecondFileHeader(t *testing.T) {
	dir := t.TempDir()
	first, err := NewSegmentLog(dir, 1<<20)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	if _, err := first.Append(MsgId(0), DirectionRequest, []byte("before-restart")); err != nil {
		t.Fatalf("append before restart: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}

	resumed, err := NewSegmentLog(dir, 1<<20)
	if err != nil {
		t.Fatalf("resume log: %v", err)
	}
	loc, err := resumed.Append(MsgId(1), DirectionResponse, []byte("after-restart"))
	if err != nil {
		t.Fatalf("append after restart: %v", err)
	}
	if err := resumed.Close(); err != nil {
		t.Fatalf("close resumed log: %v", err)
	}

	raw, err := os.ReadFile(loc.Segment)
	if err != nil {
		t.Fatalf("read segment: %v", err)
	}
	if n := bytes.Count(raw, []byte(segmentMagic)); n != 1 {
		t.Errorf("the segment carries the magic %d times, want exactly 1 — a resumed segment must "+
			"not be re-headered", n)
	}
	scan, err := ScanSegmentFile(loc.Segment)
	if err != nil {
		t.Fatalf("scan a resumed segment: %v", err)
	}
	if scan.Corrupt != nil {
		t.Fatalf("a segment written across a restart reports %s", scan.Corrupt.Error())
	}
	if len(scan.Records) != 2 {
		t.Fatalf("scan found %d records, want the one from each life of the log", len(scan.Records))
	}
	if scan.Records[1].Loc != loc {
		t.Errorf("the resumed record scans at %+v but its append returned %+v — currentOffset did "+
			"not pick up where the file actually ended", scan.Records[1].Loc, loc)
	}
}

// A zero-length segment is one rotate created before the process died. It holds
// no records, so adopting it loses nothing, where refusing would cost a restart
// over an empty file.
func TestAnEmptySegmentLeftByACrashIsAdoptedAndGetsItsHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fmt.Sprintf(segmentNameFormat, 0))
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatalf("write empty segment: %v", err)
	}

	sl, err := NewSegmentLog(dir, 1<<20)
	if err != nil {
		t.Fatalf("open a log over an empty segment: %v", err)
	}
	loc, err := sl.Append(MsgId(0), DirectionRequest, []byte("adopted"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := sl.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if loc.Segment != path {
		t.Errorf("the record landed in %s, want the adopted %s", loc.Segment, path)
	}
	if loc.Offset != firstRecordPayloadOffset() {
		t.Errorf("payload is at %d, want %d — the adopted file did not get its header",
			loc.Offset, firstRecordPayloadOffset())
	}
	scan, err := ScanSegmentFile(path)
	if err != nil {
		t.Fatalf("scan an adopted segment: %v", err)
	}
	if scan.Corrupt != nil || len(scan.Records) != 1 {
		t.Errorf("adopted segment scans as %d records / %v, want one clean record",
			len(scan.Records), scan.Corrupt)
	}
}

// The rotation target is a target, not a cap: a message larger than the whole
// target gets a segment to itself rather than being refused, split, or made to
// rotate an empty file away first.
func TestAMessageLargerThanTheTargetGetsItsOwnSegmentRatherThanBeingRefused(t *testing.T) {
	dir := t.TempDir()
	sl, err := NewSegmentLog(dir, 256)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer sl.Close()

	small, err := sl.Append(MsgId(0), DirectionRequest, []byte("first"))
	if err != nil {
		t.Fatalf("append small: %v", err)
	}
	huge := bytes.Repeat([]byte("h"), 256*5)
	hugeLoc, err := sl.Append(MsgId(1), DirectionResponse, huge)
	if err != nil {
		t.Fatalf("append oversized: %v", err)
	}
	if hugeLoc.Segment == small.Segment {
		t.Error("an oversized record shares a segment with the record before it")
	}
	if hugeLoc.Offset != firstRecordPayloadOffset() {
		t.Errorf("the oversized record is at offset %d, want %d — it should be the only record in "+
			"a fresh segment, not preceded by an empty rotation", hugeLoc.Offset, firstRecordPayloadOffset())
	}
	got, err := sl.Read(hugeLoc)
	if err != nil {
		t.Fatalf("read the oversized record back: %v", err)
	}
	if !bytes.Equal(got, huge) {
		t.Error("an oversized payload did not survive whole")
	}
	for _, v := range VerifyCaptureDir(dir) {
		if v.Fault != nil {
			t.Errorf("segment %s: %s", v.Path, *v.Fault)
		}
	}
}
