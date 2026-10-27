package core

import (
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
)

// segmentNameFormat is the one place the on-disk segment filename is spelled.
// It is shared with VerifyCaptureDir, which used to carry its own, different
// spelling and so matched no files at all.
const segmentNameFormat = "segment_%d.dat"

// Location represents a location in a segment file.
//
// Offset and Length describe the *payload* span and nothing else: the record's
// RecordHeaderLen-byte header sits in the bytes immediately before Offset. That
// is what lets ReadAt slice a location straight out of a mapping without
// knowing the framing exists, and what kept every read path unchanged when the
// framing was added.
type Location struct {
	Segment string
	Offset  int64
	Length  int64
}

// SegmentLog manages append-only segment files.
type SegmentLog struct {
	mu            sync.Mutex
	dir           string
	targetBytes   uint64
	currentFile   *os.File
	currentName   string
	currentOffset int64
	totalWritten  int64
	// mappings holds one read-only mapping per sealed segment, created on first
	// read and kept until Close. They are never evicted while the log is open,
	// which is what lets ReadAt hand out slices that stay valid after the lock
	// is dropped. The pages are file-backed and clean, so the kernel can
	// reclaim them under pressure without any of them being written to swap —
	// unlike the same bytes held on the Go heap.
	mappings map[string][]byte
}

// NewSegmentLog creates a new segment log in the given directory.
func NewSegmentLog(dir string, targetBytes uint64) (*SegmentLog, error) {
	// Owner-only (burpsy-react-ui-data-at-rest-perms): segments are captured traffic, cookies and
	// tokens included. MkdirAll applies the mode only to directories it creates; an existing
	// directory the operator named is left as they set it, because chmod-ing a directory burpsy did
	// not create (a shared capture root, /tmp) is not this package's decision.
	if err := os.MkdirAll(dir, segmentDirMode); err != nil {
		return nil, fmt.Errorf("failed to create segment directory: %w", err)
	}

	sl := &SegmentLog{
		dir:         dir,
		targetBytes: targetBytes,
	}

	// Find existing segments and determine current offset
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read segment directory: %w", err)
	}

	maxSeg := -1
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		var segNum int
		if _, err := fmt.Sscanf(name, segmentNameFormat, &segNum); err == nil {
			if segNum > maxSeg {
				maxSeg = segNum
			}
			info, err := entry.Info()
			if err == nil {
				sl.totalWritten += info.Size()
			}
		}
	}

	if maxSeg >= 0 {
		sl.currentName = filepath.Join(dir, fmt.Sprintf(segmentNameFormat, maxSeg))
		if err := sl.resume(); err != nil {
			return nil, err
		}
	}

	return sl, nil
}

// resume reopens the highest-numbered existing segment for appending, after
// checking that it really is one of ours.
//
// The file header is written when a segment is created, so resuming must not
// write it again — a second header in the middle of a file would be read back
// as a record header with a nonsense length. What resume does instead is verify
// the one that is already there, and pick up currentOffset from the file's real
// size so the rotation arithmetic still describes the file rather than the
// records.
//
// Only the segment being appended to is checked, not every file in the
// directory. This is a deliberate divergence from the Rust SegmentLog::open,
// which refuses the whole directory if any segment fails its header check: the
// Go store resumes captures rather than demanding an empty directory, and a
// stale file from some other tool is a thing for VerifyCaptureDir to name
// per-file, not a reason the proxy cannot start.
func (sl *SegmentLog) resume() error {
	info, err := os.Stat(sl.currentName)
	if err != nil {
		return fmt.Errorf("failed to stat current segment: %w", err)
	}

	if info.Size() == 0 {
		// A zero-length segment is one rotate created and was killed before it
		// could write the header. It holds no records, so adopting it destroys
		// nothing, where refusing would cost a restart over a file that has
		// nothing in it to lose.
		file, err := openSegmentForAppend(sl.currentName)
		if err != nil {
			return fmt.Errorf("failed to open current segment: %w", err)
		}
		if err := sl.writeFileHeader(file); err != nil {
			file.Close()
			return err
		}
		sl.currentFile = file
		sl.currentOffset = SegmentFileHeaderLen
		sl.totalWritten += SegmentFileHeaderLen
		return nil
	}

	head := make([]byte, SegmentFileHeaderLen)
	existing, err := os.Open(sl.currentName)
	if err != nil {
		return fmt.Errorf("failed to open current segment: %w", err)
	}
	_, readErr := io.ReadFull(existing, head)
	existing.Close()
	if readErr != nil {
		return fmt.Errorf("%s is %d bytes, too short to hold the %d-byte segment header — "+
			"refusing to append to it", sl.currentName, info.Size(), SegmentFileHeaderLen)
	}
	if err := validateSegmentFileHeader(sl.currentName, head); err != nil {
		return fmt.Errorf("%w — refusing to append to it", err)
	}

	file, err := openSegmentForAppend(sl.currentName)
	if err != nil {
		return fmt.Errorf("failed to open current segment: %w", err)
	}
	sl.currentFile = file
	sl.currentOffset = info.Size()
	return nil
}

// segmentDirMode and segmentFileMode are owner-only: a capture directory holds every request and
// response the proxy recorded, and 0755/0644 handed it to every other account on the machine.
const (
	segmentDirMode  os.FileMode = 0o700
	segmentFileMode os.FileMode = 0o600
)

// openSegmentForAppend reopens an existing segment for appending and tightens it to owner-only.
//
// The mode argument of OpenFile only applies to a file it creates, so a segment written by an
// earlier build keeps its 0644 unless it is changed here. The file has just been verified as one of
// ours (resume checks the header), so tightening it is not touching someone else's file. A failed
// chmod is not fatal — a filesystem without modes still records traffic — and leaves the mode as it
// was.
func openSegmentForAppend(name string) (*os.File, error) {
	file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY, segmentFileMode)
	if err != nil {
		return nil, err
	}
	if info, serr := file.Stat(); serr == nil && info.Mode().Perm()&0o077 != 0 {
		_ = file.Chmod(info.Mode().Perm() & 0o700)
	}
	return file, nil
}

// writeFileHeader puts the magic and format version at the start of a segment
// file that has just been created. Called exactly once per file, by rotate or
// by resume adopting an empty one — never on a file that already holds records.
func (sl *SegmentLog) writeFileHeader(file *os.File) error {
	head := segmentFileHeader()
	if _, err := file.Write(head[:]); err != nil {
		return fmt.Errorf("failed to write the segment header to %s: %w", sl.currentName, err)
	}
	return nil
}

// Append writes one record — a RecordHeaderLen-byte header, then the payload —
// and returns where the *payload* lives.
//
// The id and direction are parameters rather than something the log invents
// because they are what makes a segment self-describing: without them a file
// can be read back as bytes but not as messages, so a recovery pass would have
// to trust an index it was supposed to be checking. The caller (TrafficStore.Put)
// has both at hand, which is why they are passed rather than recovered later.
//
// The returned Location points past the header at the payload alone, so nothing
// on the read side has to know the framing exists.
func (sl *SegmentLog) Append(id MsgId, direction Direction, data []byte) (Location, error) {
	if int64(len(data)) > math.MaxUint32 {
		return Location{}, fmt.Errorf("message %d is %d bytes, which does not fit the record "+
			"header's 32-bit length", uint64(id), len(data))
	}
	header, ok := RecordHeader{
		Len:       uint32(len(data)),
		MsgID:     id,
		Direction: direction,
		CRC32:     crc32.ChecksumIEEE(data),
	}.encode()
	if !ok {
		// Refused rather than written as a request: see directionByte.
		return Location{}, fmt.Errorf("message %d carries direction %d, which is neither request "+
			"(%d) nor response (%d) — refusing to record it as either",
			uint64(id), int(direction), int(DirectionRequest), int(DirectionResponse))
	}

	sl.mu.Lock()
	defer sl.mu.Unlock()

	if sl.currentFile == nil {
		if err := sl.rotate(); err != nil {
			return Location{}, fmt.Errorf("failed to rotate segment: %w", err)
		}
	}
	// Rotation happens only at a completed-record boundary, and only when the
	// segment already holds a record: a message larger than the whole target
	// would otherwise rotate an empty segment away and immediately overshoot the
	// fresh one, leaving a header-only file behind for nothing. The target is a
	// target, not a cap — an oversized message gets a segment to itself rather
	// than being refused or split across two files.
	record := int64(RecordHeaderLen) + int64(len(data))
	if sl.currentOffset > SegmentFileHeaderLen && uint64(sl.currentOffset)+uint64(record) > sl.targetBytes {
		if err := sl.rotate(); err != nil {
			return Location{}, fmt.Errorf("failed to rotate segment: %w", err)
		}
	}

	if n, err := sl.currentFile.Write(header[:]); err != nil {
		sl.currentOffset += int64(n)
		sl.totalWritten += int64(n)
		return Location{}, sl.abandonAfterTornWrite("record header", err)
	}
	sl.currentOffset += RecordHeaderLen
	sl.totalWritten += RecordHeaderLen

	offset := sl.currentOffset
	n, err := sl.currentFile.Write(data)
	sl.currentOffset += int64(n)
	sl.totalWritten += int64(n)
	if err != nil {
		return Location{}, sl.abandonAfterTornWrite("record payload", err)
	}

	return Location{
		Segment: sl.currentName,
		Offset:  offset,
		Length:  int64(n),
	}, nil
}

// abandonAfterTornWrite rotates away from a segment whose last record was only
// partly written, and returns the error to report for the append that failed.
//
// A failed write (a full disk, most likely) leaves a header with no payload, or
// a payload shorter than its header declares. That record is lost either way —
// but every record after it would be lost too if the next append simply carried
// on into the same file, because a scan stops at the first fault. Sealing the
// damage into the tail of one segment costs a file and bounds the loss to the
// one record that actually failed.
func (sl *SegmentLog) abandonAfterTornWrite(what string, cause error) error {
	if err := sl.rotate(); err != nil {
		return fmt.Errorf("failed to write %s: %w (and the torn segment could not be rotated "+
			"away from, so the next append would land after it: %v)", what, cause, err)
	}
	return fmt.Errorf("failed to write %s: %w (its segment was rotated away from, so the records "+
		"after it are in a new file)", what, cause)
}

// rotate seals the current segment and creates a new one. Sealing means the
// bytes are on the platter and the file will never be appended to again, which
// is precisely the precondition ReadAt needs before it will map a segment.
func (sl *SegmentLog) rotate() error {
	if sl.currentFile != nil {
		if err := sl.currentFile.Sync(); err != nil {
			return fmt.Errorf("failed to seal segment %s: %w", sl.currentName, err)
		}
		sl.currentFile.Close()
	}

	// Find next segment number
	segNum := 0
	if sl.currentName != "" {
		var oldNum int
		if _, err := fmt.Sscanf(filepath.Base(sl.currentName), segmentNameFormat, &oldNum); err == nil {
			segNum = oldNum + 1
		}
	}

	// From here until the new file is ready there is no segment to append to,
	// and saying so is what lets a later Append retry the rotation instead of
	// writing into the handle that was just closed.
	sl.currentFile = nil
	sl.currentName = filepath.Join(sl.dir, fmt.Sprintf(segmentNameFormat, segNum))
	// os.Create would make it 0666 less the umask — 0644 in practice. Same flags, owner-only mode.
	file, err := os.OpenFile(sl.currentName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, segmentFileMode)
	if err != nil {
		return fmt.Errorf("failed to create new segment: %w", err)
	}
	// The magic and version go in here, on a brand new file and nowhere else.
	// Resuming an existing segment must not write them again — see resume.
	if err := sl.writeFileHeader(file); err != nil {
		file.Close()
		return err
	}

	sl.currentFile = file
	sl.currentOffset = SegmentFileHeaderLen
	sl.totalWritten += SegmentFileHeaderLen
	return nil
}

// Mappable reports whether this log can serve reads out of mappings. The store
// only stops retaining payload bytes when this is true, because a span has to
// be free to slice: Header slices once per header, and a copying read path
// would re-read the entire message for each one.
func (sl *SegmentLog) Mappable() bool { return segmentMappingSupported }

// ReadAt returns the bytes at loc without copying them where it can. For a
// sealed segment the result is a view into a read-only mapping that stays valid
// until Close, and must not be mutated.
//
// The segment currently being appended to is deliberately not mapped. A mapping
// has the length the file had when it was made, and touching a page beyond the
// end of the file raises SIGBUS rather than returning an error — so the active
// segment is read with pread, costing one allocation per read until rotation
// seals it. Sealing before mapping is the whole reason rotation syncs.
func (sl *SegmentLog) ReadAt(loc Location) ([]byte, error) {
	if loc.Segment == "" {
		return nil, fmt.Errorf("location carries no segment: nothing to read")
	}
	if mapped, ok := sl.mapping(loc.Segment); ok {
		end := loc.Offset + loc.Length
		if loc.Offset < 0 || loc.Length < 0 || end > int64(len(mapped)) {
			return nil, fmt.Errorf("location %s offset %d len %d falls outside the %d-byte segment",
				loc.Segment, loc.Offset, loc.Length, len(mapped))
		}
		return mapped[loc.Offset:end], nil
	}
	return sl.pread(loc)
}

// mapping returns a mapping of a sealed segment, creating it on first use. It
// reports false for the active segment, and for any failure to map: every such
// case has a working pread fallback, so a mapping that cannot be made is a
// performance question rather than a correctness one.
func (sl *SegmentLog) mapping(name string) ([]byte, bool) {
	if !segmentMappingSupported {
		return nil, false
	}
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if name == sl.currentName {
		return nil, false
	}
	if m, ok := sl.mappings[name]; ok {
		return m, true
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() == 0 {
		return nil, false
	}
	m, err := mapSegment(int(file.Fd()), info.Size())
	if err != nil {
		return nil, false
	}
	if sl.mappings == nil {
		sl.mappings = make(map[string][]byte)
	}
	sl.mappings[name] = m
	return m, true
}

// pread reads a location into a fresh buffer the caller owns.
func (sl *SegmentLog) pread(loc Location) ([]byte, error) {
	file, err := os.Open(loc.Segment)
	if err != nil {
		return nil, fmt.Errorf("failed to open segment: %w", err)
	}
	defer file.Close()

	data := make([]byte, loc.Length)
	n, err := file.ReadAt(data, loc.Offset)
	if err != nil {
		return nil, fmt.Errorf("failed to read from segment: %w", err)
	}
	if int64(n) != loc.Length {
		return nil, fmt.Errorf("short read: expected %d, got %d", loc.Length, n)
	}

	return data, nil
}

// Read returns a private copy of the bytes at loc. Prefer ReadAt, which avoids
// the copy for sealed segments; Read is for callers that need to own the buffer
// and outlive the log.
func (sl *SegmentLog) Read(loc Location) ([]byte, error) {
	b, err := sl.ReadAt(loc)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// TotalWritten returns the total bytes written across all segments — what the
// capture directory costs, so it counts the framing (a file header per segment,
// a record header per message) as well as the payloads.
func (sl *SegmentLog) TotalWritten() int64 {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	return sl.totalWritten
}

// Sync seals the active segment without dropping any mapping, so it is safe to
// call while readers are still working. This — not Close — is the shutdown call:
// at exit the kernel releases mappings anyway, so unmapping buys nothing, while
// getting the tail of the capture onto the platter buys everything.
func (sl *SegmentLog) Sync() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if sl.currentFile == nil {
		return nil
	}
	if err := sl.currentFile.Sync(); err != nil {
		return fmt.Errorf("failed to seal segment %s: %w", sl.currentName, err)
	}
	return nil
}

// Close drops every mapping and closes the current segment file. Any slice
// handed out by ReadAt is invalid afterwards — reading one is a segmentation
// fault, not an error return — so Close belongs at process shutdown, once
// nothing can still be holding a message.
func (sl *SegmentLog) Close() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	var firstErr error
	for name, m := range sl.mappings {
		if err := unmapSegment(m); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to unmap segment %s: %w", name, err)
		}
		delete(sl.mappings, name)
	}

	if sl.currentFile != nil {
		// Seal on the way out as well as on rotation: without this the last
		// segment's tail is only in the page cache, so a capture that was never
		// large enough to rotate is the one most at risk of losing its end.
		if err := sl.currentFile.Sync(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to seal segment %s: %w", sl.currentName, err)
		}
		if err := sl.currentFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		sl.currentFile = nil
	}
	return firstErr
}
