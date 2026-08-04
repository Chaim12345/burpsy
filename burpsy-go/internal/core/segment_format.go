package core

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

// The on-disk segment format: what a segment file says about itself, and what
// re-reading one can actually prove.
//
// A segment used to be a bare concatenation of payloads. Nothing in the file
// said where a record started, how long it was, or which message it belonged
// to — every one of those facts lived only in the in-memory index, so the file
// could only be checked by reading it to EOF and counting bytes. That check
// passes on a file whose bytes have been rewritten in place, which is the one
// fault a capture store most needs to notice: a byte flip that keeps the length
// turns a recorded request into a different request that still resolves, still
// parses, and is still believed.
//
// So each file now opens with a 16-byte header (magic + format version +
// reserved zeros) and each record with a 17-byte header (payload length, the
// message id, the direction, and a CRC32 over the payload). Those two headers
// are what make a segment self-describing: ScanSegmentFile can walk a file it
// has never seen before, recover every record boundary from the file itself,
// and say per record whether the bytes are the bytes that were written.
//
// # The checksum is not a security control
//
// The CRC catches torn writes, bit rot, and truncation — accidental corruption.
// It is not a cryptographic integrity or tamper-evidence guarantee and must
// never be described as one in a doc comment, an error string, or any
// operator-facing text: anyone with write access to the capture directory can
// recompute a CRC exactly as easily as we can. What it proves is "these bytes
// did not rot", never "these bytes were not replaced".
//
// # Divergences from crates/core/src/segment.rs, which is the format's spec
//
// The byte layout is the Rust one, number for number: SEGMENT_MAGIC,
// SEGMENT_FORMAT_VERSION = 1, SEGMENT_FILE_HEADER_LEN = 16, RECORD_HEADER_LEN =
// 17, every multi-byte field little-endian. Three things differ, all named:
//
//   - Rust models a fault as an enum with per-variant fields; Go has no such
//     thing, so CorruptRecord is one struct with a Kind and the union of the
//     fields, and only the fields its Kind names are populated.
//   - Rust's scan_segment_file reads the whole file into memory. This one
//     streams: a 100 MB segment is verified in a 64 KB buffer, because the Go
//     store's default segment target is 100 MB where Rust's is 64 MB and
//     verifying a capture should not need the capture's worth of RAM.
//   - Rust names segments segment-000000.log and seals by rename; Go names them
//     segment_%d.dat and seals in place (see rotate). Nothing in this file
//     depends on which of the two it is looking at beyond the magic.
const (
	// SegmentFileHeaderLen is magic(8) + version(1) + reserved(7), the reserved
	// bytes written as zero. Written once when a segment file is created, never
	// per record: it is the cheapest possible insurance against the one thing
	// that is genuinely expensive to retrofit, which is knowing what format a
	// file already on disk is in.
	SegmentFileHeaderLen = 16

	// RecordHeaderLen is len(4) + msgID(8) + direction(1) + crc32(4), written
	// immediately before every record's payload.
	RecordHeaderLen = 17

	// SegmentFormatVersion is the format this build writes and the only one it
	// reads. There is deliberately no migration story: a file whose version is
	// not this one is refused by name rather than guessed at.
	SegmentFormatVersion byte = 1

	// segmentMagic opens every segment file, so a file that is not one of ours
	// is refused as a foreign file instead of being parsed as a damaged one.
	segmentMagic = "BURPSYSG"
)

// segmentFileHeader is the block that opens a segment file. The reserved bytes
// are left zero, which is what a later field within this same format version
// gets to claim.
func segmentFileHeader() [SegmentFileHeaderLen]byte {
	var head [SegmentFileHeaderLen]byte
	copy(head[:len(segmentMagic)], segmentMagic)
	head[8] = SegmentFormatVersion
	return head
}

// validateSegmentFileHeader checks the block that opens a segment file, naming
// the file in every refusal so an operator learns which one to look at.
//
// Both callers — the verify pass and the append path resuming a segment — treat
// a failure here as fatal for that file rather than as something to work
// around. There is no legacy on-disk format to tolerate, so a file that does
// not open with our magic is either not ours or is damaged badly enough that
// nothing after byte 16 can be trusted either.
func validateSegmentFileHeader(path string, head []byte) error {
	if len(head) < SegmentFileHeaderLen {
		return fmt.Errorf("%s is %d bytes, too short to hold a %d-byte segment header",
			path, len(head), SegmentFileHeaderLen)
	}
	if string(head[:len(segmentMagic)]) != segmentMagic {
		return fmt.Errorf("%s is not a burpsy segment file (bad magic)", path)
	}
	if head[8] != SegmentFormatVersion {
		return fmt.Errorf("%s is segment format version %d, but this build understands version %d",
			path, head[8], SegmentFormatVersion)
	}
	// The seven reserved bytes are deliberately not checked. They are reserved
	// for a later field within this same version, so refusing a file that uses
	// one would make the reservation useless.
	return nil
}

// directionByte encodes a direction for the record header, reporting false for
// a value that is neither request nor response.
//
// Refusing rather than defaulting is the same reason decode refuses an
// unrecognised byte on the way back in: writing 0 for a direction we do not
// recognise would put a plausible-looking lie in a file that is supposed to be
// the record of what actually happened.
func directionByte(d Direction) (byte, bool) {
	switch d {
	case DirectionRequest:
		return 0, true
	case DirectionResponse:
		return 1, true
	default:
		return 0, false
	}
}

// RecordHeader is one record's on-disk header. Every field is written
// little-endian, in the order the fields are declared.
type RecordHeader struct {
	Len       uint32
	MsgID     MsgId
	Direction Direction
	CRC32     uint32
}

// encode lays the header out for the wire. It reports false for a direction it
// cannot encode; see directionByte.
func (h RecordHeader) encode() ([RecordHeaderLen]byte, bool) {
	var out [RecordHeaderLen]byte
	dir, ok := directionByte(h.Direction)
	if !ok {
		return out, false
	}
	binary.LittleEndian.PutUint32(out[0:4], h.Len)
	binary.LittleEndian.PutUint64(out[4:12], uint64(h.MsgID))
	out[12] = dir
	binary.LittleEndian.PutUint32(out[13:17], h.CRC32)
	return out, true
}

// decodeRecordHeader reads a header out of b. `at` is the byte offset b was
// read from, carried so every failure can name *where* it was found rather than
// only what was wrong with it.
func decodeRecordHeader(at int64, b []byte) (RecordHeader, *CorruptRecord) {
	if len(b) < RecordHeaderLen {
		return RecordHeader{}, &CorruptRecord{
			Kind: CorruptShortHeader,
			At:   at,
			Need: RecordHeaderLen,
			Have: int64(len(b)),
		}
	}
	var dir Direction
	switch b[12] {
	case 0:
		dir = DirectionRequest
	case 1:
		dir = DirectionResponse
	default:
		// An unrecognised direction byte is corruption, not something to
		// default. Defaulting to request would turn a damaged file into a
		// plausible-looking one.
		return RecordHeader{}, &CorruptRecord{
			Kind:          CorruptUnknownDirection,
			At:            at,
			DirectionByte: b[12],
		}
	}
	return RecordHeader{
		Len:       binary.LittleEndian.Uint32(b[0:4]),
		MsgID:     MsgId(binary.LittleEndian.Uint64(b[4:12])),
		Direction: dir,
		CRC32:     binary.LittleEndian.Uint32(b[13:17]),
	}, nil
}

// CorruptKind names what is wrong with a record, so a caller can branch on the
// fault rather than matching on message text.
type CorruptKind int

const (
	// CorruptShortHeader means the file ended part-way through a record header:
	// the record was being written when the process died, or the file was cut.
	CorruptShortHeader CorruptKind = iota
	// CorruptUnknownDirection means the direction byte is neither 0 nor 1, so
	// the header itself is damaged.
	CorruptUnknownDirection
	// CorruptLengthOverrunsSegment means the header declares more payload than
	// the file holds: a damaged length field, or a truncated file.
	CorruptLengthOverrunsSegment
	// CorruptChecksumMismatch means the payload is the declared length but not
	// the declared bytes — the same-length byte flip that a read-to-EOF check
	// cannot see.
	CorruptChecksumMismatch
)

// CorruptRecord is a fault found while walking a segment file, always carrying
// the byte offset it was found at.
//
// Only the fields its Kind names are populated; the rest are zero. This is the
// Go shape of Rust's `CorruptRecord` enum, which carries its fields per variant
// — see the divergence note at the top of this file.
type CorruptRecord struct {
	Kind CorruptKind
	// At is the offset of the record header the fault was found in or at, not
	// of the payload: it is the position to start looking at the file from.
	At int64

	// Need and Have are set for CorruptShortHeader.
	Need, Have int64
	// DirectionByte is set for CorruptUnknownDirection.
	DirectionByte byte
	// Declared and SegmentBytes are set for CorruptLengthOverrunsSegment.
	Declared, SegmentBytes int64
	// ID, Stored, and Recomputed are set for CorruptChecksumMismatch.
	ID                 MsgId
	Stored, Recomputed uint32
}

// Error says what the failure means for an operator, not which field
// disagreed.
func (c *CorruptRecord) Error() string {
	switch c.Kind {
	case CorruptShortHeader:
		return fmt.Sprintf("record header at byte %d needs %d bytes but only %d remain — "+
			"the segment ends mid-header, so it was truncated", c.At, c.Need, c.Have)
	case CorruptUnknownDirection:
		return fmt.Sprintf("record header at byte %d carries direction byte %d, which is neither "+
			"request (0) nor response (1) — the header is corrupt", c.At, c.DirectionByte)
	case CorruptLengthOverrunsSegment:
		return fmt.Sprintf("record header at byte %d declares %d bytes of payload but the segment "+
			"is only %d long — the header is corrupt or the file was truncated",
			c.At, c.Declared, c.SegmentBytes)
	case CorruptChecksumMismatch:
		// Written as 0x%08x rather than %#010x: Go counts a width against the
		// digits and not the "0x", so the Rust spelling would print a 32-bit
		// checksum as ten hex digits — a number that cannot be a CRC32 at all.
		return fmt.Sprintf("message %d at byte %d does not match the checksum written with it "+
			"(stored 0x%08x, recomputed 0x%08x) — its bytes changed after they were written",
			uint64(c.ID), c.At, c.Stored, c.Recomputed)
	default:
		return fmt.Sprintf("record at byte %d is corrupt in an unrecognised way (kind %d)", c.At, c.Kind)
	}
}

// ScannedRecord is one record a scan read and checked: its header as written,
// and where its payload lives — the same Location the append that wrote it
// returned, so a scan can be cross-checked against the in-memory index.
type ScannedRecord struct {
	Header RecordHeader
	Loc    Location
}

// SegmentScan is the result of walking one segment file end to end.
//
// Corrupt is the *first* fault found and Records still carries everything read
// before it, because "42 records were fine and then byte 91,120 was not" is
// actionable where a bare pass/fail is not.
type SegmentScan struct {
	Path    string
	Records []ScannedRecord
	Corrupt *CorruptRecord
}

// PayloadBytes is the total payload covered by the records that checked out —
// message bytes only, excluding the file header and the per-record framing.
func (s *SegmentScan) PayloadBytes() int64 {
	var total int64
	for _, r := range s.Records {
		total += r.Loc.Length
	}
	return total
}

// ScanSegmentFile walks a segment file, checking every record against its own
// header and recomputing its CRC32.
//
// The two failure classes are deliberately not the same return value. A file
// that is not a segment of ours — wrong magic, unreadable, a version this build
// does not write, too short to hold its own header — is an error: it is a fault
// in the file as a whole, and there is no per-record verdict to give about it.
// A bad record sets Corrupt and stops the walk, returning the records already
// read. Reporting rather than erroring out is what lets a verify pass emit a
// per-record verdict instead of a bare pass/fail.
//
// Scanning the segment that is still being appended to is allowed and will
// report a record caught mid-write as truncation — which it is, at the instant
// it was looked at. Sync the store first if that distinction matters.
func ScanSegmentFile(path string) (*SegmentScan, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening segment %s: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat of segment %s: %w", path, err)
	}
	size := info.Size()
	if size < SegmentFileHeaderLen {
		return nil, fmt.Errorf("%s is %d bytes, too short to hold a %d-byte segment header",
			path, size, SegmentFileHeaderLen)
	}

	reader := bufio.NewReaderSize(file, 1<<16)
	var head [SegmentFileHeaderLen]byte
	if _, err := io.ReadFull(reader, head[:]); err != nil {
		return nil, fmt.Errorf("reading the segment header of %s: %w", path, err)
	}
	if err := validateSegmentFileHeader(path, head[:]); err != nil {
		return nil, err
	}

	scan := &SegmentScan{Path: path}
	at := int64(SegmentFileHeaderLen)
	var raw [RecordHeaderLen]byte
	for at < size {
		n, err := io.ReadFull(reader, raw[:])
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			scan.Corrupt = &CorruptRecord{
				Kind: CorruptShortHeader, At: at, Need: RecordHeaderLen, Have: int64(n),
			}
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the record header at byte %d of %s: %w", at, path, err)
		}
		header, fault := decodeRecordHeader(at, raw[:])
		if fault != nil {
			scan.Corrupt = fault
			break
		}

		payloadAt := at + RecordHeaderLen
		declared := int64(header.Len)
		// Bounds-check against the file's real length before reading, so a
		// damaged length field is reported as what it is rather than as a read
		// error thirty seconds later.
		if payloadAt+declared > size {
			scan.Corrupt = &CorruptRecord{
				Kind: CorruptLengthOverrunsSegment, At: at, Declared: declared, SegmentBytes: size,
			}
			break
		}
		sum := crc32.NewIEEE()
		if copied, err := io.CopyN(sum, reader, declared); err != nil {
			// The bounds check above said these bytes were there, so a short
			// read here means the file shrank while it was being verified —
			// a whole-file fault, not something wrong with this record.
			return nil, fmt.Errorf("%s: the record at byte %d declares %d payload bytes but the file "+
				"ended after %d — it is being truncated while it is read", path, at, declared, copied)
		}
		if recomputed := sum.Sum32(); recomputed != header.CRC32 {
			scan.Corrupt = &CorruptRecord{
				Kind: CorruptChecksumMismatch, At: at,
				ID: header.MsgID, Stored: header.CRC32, Recomputed: recomputed,
			}
			break
		}

		scan.Records = append(scan.Records, ScannedRecord{
			Header: header,
			Loc:    Location{Segment: path, Offset: payloadAt, Length: declared},
		})
		at = payloadAt + declared
	}
	return scan, nil
}
